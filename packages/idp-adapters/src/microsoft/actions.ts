/**
 * Microsoft provider-confirmed response actions (design note D9, §3.3, ADR-0085) over Graph v1.0.
 *
 * Every action: linked-domain guard on the directory user (invariant 4), pre-state captured once
 * before the first write and saved through `ActionStateStore`, idempotent re-execution (a saved
 * `written` phase only confirms), read-back confirmation for state changes, rollback only of what
 * the gateway changed (`restored_previous_state_noop` otherwise). Provider errors become `failed`
 * results with classified codes; nothing is claimed without a provider 2xx and, for state changes,
 * a read-back showing the requested state (invariant 5).
 */
import { randomUUID } from 'node:crypto';
import {
  ActionFailure,
  ActionStateWriter,
  actionRequestId,
  confirmed,
  failed,
  isValidActionPublicId,
  parseProviderReference,
  pending,
  providerReference,
  refinePermissionFailure,
  runAction,
  type PreValues,
} from '../core/actions';
import { toProviderCallError } from '../core/errors';
import { appIdHash, domainOf, identityHash } from '../core/hash';
import { verifiedLinkedDomains } from '../core/session';
import type {
  ProviderActionResult,
  ProviderActionType,
  ProviderIdentityRef,
} from '../port/ato-port';
import type { MailboxItemRow, ProviderActionState } from '../port/state-ports';
import { MICROSOFT_PROFILES } from '../requirements';
import { MAX_FORWARDING_ITEMS, MICROSOFT_PROVIDER, MICROSOFT_REFERENCE_PREFIX } from './constants';
import type { MicrosoftCalls, MicrosoftContext } from './context';
import type { GraphUser } from './schemas';

export interface ExecuteRequest {
  actionPublicId: string;
  idempotencyKey: string;
  type: ProviderActionType;
  identity: ProviderIdentityRef;
  params: Record<string, string | number | boolean>;
}

export interface RollbackRequest {
  actionPublicId: string;
  idempotencyKey: string;
  type: ProviderActionType;
  identity: ProviderIdentityRef;
  providerReference: string;
}

/**
 * Gate checked before an action's first step: `null` = go, otherwise the result code stored with
 * an `unsupported` answer (`action_disabled`, `not_configured`, `capability_unavailable`).
 */
export type ActionGate = (type: ProviderActionType, signal: AbortSignal) => Promise<string | null>;

/** Profile and permission each write needs (D5). */
const ACTION_PERMISSION: Readonly<
  Record<ProviderActionType, { profile: string; permission: string }>
> = {
  revoke_sessions: { profile: MICROSOFT_PROFILES.response, permission: 'User.RevokeSessions.All' },
  require_password_reset: {
    profile: MICROSOFT_PROFILES.response,
    permission: 'User-PasswordProfile.ReadWrite.All',
  },
  suspend_account: {
    profile: MICROSOFT_PROFILES.response,
    permission: 'User.EnableDisableAccount.All',
  },
  remove_forwarding_rule: {
    profile: MICROSOFT_PROFILES.response,
    permission: 'MailboxSettings.ReadWrite',
  },
  require_mfa: {
    profile: MICROSOFT_PROFILES.responseExtended,
    permission: 'GroupMember.ReadWrite.All',
  },
  revoke_oauth_grant: {
    profile: MICROSOFT_PROFILES.responseExtended,
    permission: 'DelegatedPermissionGrant.ReadWrite.All',
  },
};

const ROLLBACK_TYPES: ReadonlySet<ProviderActionType> = new Set([
  'suspend_account',
  'require_mfa',
  'remove_forwarding_rule',
]);

interface Op {
  ctx: MicrosoftContext;
  calls: MicrosoftCalls;
  writer: ActionStateWriter;
  type: ProviderActionType;
  reference: string;
  requestId: string;
  profile: string;
  permission: string;
  integrationId: string;
}

type Outcome = { result: ProviderActionResult; resultCode?: string };

function asString(value: PreValues[string] | undefined): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function makeOp(
  ctx: MicrosoftContext,
  calls: MicrosoftCalls,
  type: ProviderActionType,
  actionPublicId: string,
): Op {
  const { profile, permission } = ACTION_PERMISSION[type];
  return {
    ctx,
    calls,
    writer: new ActionStateWriter(ctx.deps.actionState, actionPublicId, ctx.deps.clock),
    type,
    reference: providerReference(MICROSOFT_REFERENCE_PREFIX, type, actionPublicId),
    requestId: actionRequestId(actionPublicId) ?? randomUUID(),
    profile,
    permission,
    integrationId: ctx.deps.integration.id,
  };
}

/** Whether the grant demonstrably holds the permission (observed list known and containing it). */
function permissionObserved(op: Op): boolean {
  const grant = op.calls.session.grant(op.profile);
  return grant?.status === 'active' && grant.observedPermissions?.includes(op.permission) === true;
}

/** Runs a write, refining a 403 on a held permission into `missing_privileged_role`. */
async function write<T>(op: Op, call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw refinePermissionFailure(error, permissionObserved(op));
  }
}

/** The directory user behind the identity, with the linked-domain guard (invariant 4). */
async function targetUser(op: Op, externalId: string): Promise<GraphUser> {
  const user = await op.calls.graph.getUser(externalId, op.profile);
  if (!user) throw new ActionFailure('identity_not_found');
  const domain = domainOf(user.mail) ?? domainOf(user.userPrincipalName);
  if (!domain || !verifiedLinkedDomains(op.calls.session.view).has(domain)) {
    throw new ActionFailure('domain_not_linked');
  }
  return user;
}

async function unsupportedWith(op: Op, code: string): Promise<Outcome> {
  await op.writer.save({ phase: 'pre', pre: { unsupported: true }, resultCode: code });
  return { result: { status: 'unsupported' }, resultCode: code };
}

/** A read-back that has not converged: count the check and ask to poll later. */
async function notYet(op: Op, state: ProviderActionState): Promise<Outcome> {
  const checks = state.checks ?? 0;
  await op.writer.save({ ...state, checks: checks + 1, at: state.at });
  return { result: pending(op.reference, checks) };
}

function done(op: Op, state: ProviderActionState): Promise<Outcome> {
  const resultCode = state.resultCode;
  return Promise.resolve({
    result: confirmed(op.reference, op.ctx.deps.clock),
    ...(resultCode ? { resultCode } : {}),
  });
}

// ---------------------------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------------------------

export function executeAction(
  ctx: MicrosoftContext,
  request: ExecuteRequest,
  signal: AbortSignal,
  gate: ActionGate,
): Promise<ProviderActionResult> {
  return runAction(
    { provider: MICROSOFT_PROVIDER, action: request.type, metrics: ctx.deps.metrics },
    async () => {
      if (!isValidActionPublicId(request.actionPublicId) || !request.identity.externalId) {
        return { result: failed('invalid_request', false) };
      }
      const writer = new ActionStateWriter(
        ctx.deps.actionState,
        request.actionPublicId,
        ctx.deps.clock,
      );
      const existing = await writer.load();
      if (existing?.pre.unsupported === true) {
        return {
          result: { status: 'unsupported' },
          ...(existing.resultCode ? { resultCode: existing.resultCode } : {}),
        };
      }
      if (existing === null) {
        const blocked = await gate(request.type, signal);
        if (blocked !== null) {
          await writer.save({ phase: 'pre', pre: { unsupported: true }, resultCode: blocked });
          return { result: { status: 'unsupported' }, resultCode: blocked };
        }
      }
      const calls = await ctx.open(signal);
      const op = makeOp(ctx, calls, request.type, request.actionPublicId);
      const uid = request.identity.externalId;
      switch (request.type) {
        case 'revoke_sessions':
          return revokeSessions(op, existing, uid);
        case 'require_password_reset':
          return requirePasswordReset(op, existing, uid);
        case 'suspend_account':
          return suspendAccount(op, existing, uid);
        case 'require_mfa':
          return requireMfa(op, existing, uid);
        case 'remove_forwarding_rule':
          return removeForwarding(op, existing, uid, request.params);
        case 'revoke_oauth_grant':
          return revokeOauthGrant(op, existing, uid, request.params);
      }
    },
  );
}

async function revokeSessions(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') return done(op, existing);
  await targetUser(op, uid);
  const state = existing ?? (await op.writer.save({ phase: 'pre', pre: { uid } }));
  await write(op, () => op.calls.graph.revokeSessions(uid, op.profile, op.requestId));
  // Synchronous confirmation: the 2xx answer is the effect (D9.4).
  return done(op, await op.writer.save({ ...state, phase: 'written' }));
}

async function requirePasswordReset(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') return done(op, existing);
  const user = await targetUser(op, uid);
  if (user.onPremisesSyncEnabled === true) throw new ActionFailure('on_premises_managed');
  const state = existing ?? (await op.writer.save({ phase: 'pre', pre: { uid } }));
  await write(op, () =>
    op.calls.graph.patchUser(
      uid,
      { passwordProfile: { forceChangePasswordNextSignIn: true } },
      op.profile,
      op.requestId,
    ),
  );
  // The flag is not readable through Graph: confirmed by the 2xx answer (§3.3).
  return done(op, await op.writer.save({ ...state, phase: 'written' }));
}

async function readBackSuspended(op: Op, state: ProviderActionState): Promise<Outcome> {
  const uid = asString(state.pre.uid);
  if (!uid) throw new ActionFailure('unknown_reference');
  const user = await op.calls.graph.getUser(uid, op.profile);
  if (!user) throw new ActionFailure('identity_not_found');
  return user.accountEnabled === false ? done(op, state) : notYet(op, state);
}

async function suspendAccount(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') return readBackSuspended(op, existing);
  const user = await targetUser(op, uid);
  let state = existing;
  if (state === null) {
    const enabled = user.accountEnabled !== false;
    state = await op.writer.save({ phase: 'pre', pre: { uid, enabled } });
    if (!enabled) {
      return done(
        op,
        await op.writer.save({ ...state, phase: 'written', resultCode: 'already_in_state' }),
      );
    }
  }
  await write(op, () =>
    op.calls.graph.patchUser(uid, { accountEnabled: false }, op.profile, op.requestId),
  );
  state = await op.writer.save({ ...state, phase: 'written' });
  return readBackSuspended(op, state);
}

async function readBackMember(
  op: Op,
  state: ProviderActionState,
  wanted: boolean,
): Promise<Outcome> {
  const uid = asString(state.pre.uid);
  const gid = asString(state.pre.gid);
  if (!uid || !gid) throw new ActionFailure('unknown_reference');
  const member = await op.calls.graph.isMember(gid, uid, op.profile);
  return member === wanted ? done(op, state) : notYet(op, state);
}

async function requireMfa(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') return readBackMember(op, existing, true);
  let state = existing;
  if (state === null) {
    const groupId = op.ctx.deps.integration.settings.mfaEnforcement.groupId;
    if (!groupId) return unsupportedWith(op, 'not_configured');
    await targetUser(op, uid);
    const member = await op.calls.graph.isMember(groupId, uid, op.profile);
    state = await op.writer.save({ phase: 'pre', pre: { uid, gid: groupId, member } });
    if (member) {
      return done(
        op,
        await op.writer.save({ ...state, phase: 'written', resultCode: 'already_in_state' }),
      );
    }
  } else {
    await targetUser(op, uid);
  }
  const gid = asString(state.pre.gid);
  if (!gid) throw new ActionFailure('unknown_reference');
  await write(op, () => op.calls.graph.addMember(gid, uid, op.profile, op.requestId));
  state = await op.writer.save({ ...state, phase: 'written' });
  return readBackMember(op, state, true);
}

// remove_forwarding_rule -------------------------------------------------------------------------

type ItemState = NonNullable<ProviderActionState['items']>[number];

async function itemRef(op: Op, item: ItemState): Promise<string | null> {
  const row = await op.ctx.deps.mailboxState.itemByPublicId(op.integrationId, item.id);
  return row?.providerItemRef ?? null;
}

function initialItem(row: MailboxItemRow): ItemState {
  const base = { id: row.publicId, ref: null };
  if (row.state === 'removed') return { ...base, outcome: 'already_in_state' };
  if (row.kind === 'forwarding') {
    // Mailbox-level forwarding: no Graph API (PQ3), manual step in Exchange admin.
    return { ...base, outcome: 'unsupported', code: 'requires_exchange_admin' };
  }
  if (row.kind !== 'inbox_rule') return { ...base, outcome: 'unsupported', code: 'not_forwarding' };
  if (!row.providerItemRef) return { ...base, outcome: 'unsupported', code: 'rule_id_unknown' };
  return { ...base, outcome: 'pending' };
}

async function forwardingRows(
  op: Op,
  uid: string,
  params: ExecuteRequest['params'],
): Promise<{ rows: MailboxItemRow[]; more: boolean }> {
  const store = op.ctx.deps.mailboxState;
  const owner = identityHash(MICROSOFT_PROVIDER, uid);
  if (typeof params.itemId === 'string' && params.itemId.length > 0) {
    if (params.scope !== undefined) throw new ActionFailure('invalid_request');
    const row = await store.itemByPublicId(op.integrationId, params.itemId);
    if (!row || row.identityHash !== owner) throw new ActionFailure('item_not_found');
    return { rows: [row], more: false };
  }
  if (params.scope !== 'all_external') throw new ActionFailure('invalid_request');
  const external = (await store.load(op.integrationId, owner)).filter(
    (row) => row.state === 'present' && row.traits.includes('forwards_external'),
  );
  return {
    rows: external.slice(0, MAX_FORWARDING_ITEMS),
    more: external.length > MAX_FORWARDING_ITEMS,
  };
}

/** Aggregates per-item outcomes into the action's result (D9.7). */
async function aggregateForwarding(op: Op, state: ProviderActionState): Promise<Outcome> {
  const items = state.items ?? [];
  const outcomes = items.map((item) => item.outcome);
  if (outcomes.some((o) => o === 'pending' || o === 'written')) return notYet(op, state);
  const doneItems = outcomes.filter((o) => o === 'confirmed' || o === 'already_in_state').length;
  if (doneItems === items.length && state.pre.more !== true) {
    const resultCode =
      items.length === 0 || outcomes.every((o) => o === 'already_in_state')
        ? 'already_in_state'
        : undefined;
    const saved = await op.writer.save({
      ...state,
      ...(resultCode ? { resultCode } : {}),
      at: state.at,
    });
    return done(op, saved);
  }
  if (doneItems === 0 && outcomes.every((o) => o === 'unsupported') && state.pre.more !== true) {
    const code = items[0]?.code ?? 'requires_exchange_admin';
    await op.writer.save({ ...state, resultCode: code, at: state.at });
    return { result: { status: 'unsupported' }, resultCode: code };
  }
  if (items.length === 1 && items[0]?.outcome === 'failed') {
    return { result: failed(items[0].code ?? 'provider_unavailable', false) };
  }
  await op.writer.save({ ...state, resultCode: 'partial', at: state.at });
  return { result: failed('partial', false), resultCode: 'partial' };
}

async function readBackForwarding(op: Op, state: ProviderActionState, uid: string) {
  const mode = state.pre.mode === 'delete' ? 'delete' : 'disable';
  const items: ItemState[] = [];
  for (const item of state.items ?? []) {
    if (item.outcome !== 'written') {
      items.push(item);
      continue;
    }
    const ref = await itemRef(op, item);
    const rule = ref ? await op.calls.graph.getRule(uid, ref, op.profile) : null;
    const gone = rule === null || (mode === 'disable' && !rule.isEnabled);
    items.push(gone ? { ...item, outcome: 'confirmed' } : item);
  }
  return { ...state, items };
}

async function removeForwarding(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
  params: ExecuteRequest['params'],
): Promise<Outcome> {
  await targetUser(op, uid);
  let state = existing;
  if (state === null) {
    const mode = op.ctx.deps.integration.settings.forwardingRemoval.mode;
    const { rows, more } = await forwardingRows(op, uid, params);
    const items: ItemState[] = [];
    for (const row of rows) {
      const item = initialItem(row);
      if (item.outcome === 'pending' && row.providerItemRef) {
        const rule = await op.calls.graph.getRule(uid, row.providerItemRef, op.profile);
        if (rule === null || (mode === 'disable' && !rule.isEnabled)) {
          items.push({ ...item, outcome: 'already_in_state' });
          continue;
        }
        items.push({ ...item, enabled: rule.isEnabled });
        continue;
      }
      items.push(item);
    }
    state = await op.writer.save({ phase: 'pre', pre: { uid, mode, more }, items });
  }
  const mode = state.pre.mode === 'delete' ? 'delete' : 'disable';
  const items = [...(state.items ?? [])];
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i] as ItemState;
    if (item.outcome !== 'pending') continue;
    const ref = await itemRef(op, item);
    if (!ref) {
      items[i] = { ...item, outcome: 'failed', code: 'item_not_found' };
      continue;
    }
    try {
      await write<unknown>(op, () =>
        mode === 'delete'
          ? op.calls.graph.deleteRule(uid, ref, op.profile, op.requestId)
          : op.calls.graph.setRuleEnabled(uid, ref, false, op.profile, op.requestId),
      );
      items[i] = { ...item, outcome: 'written' };
    } catch (error) {
      const failure = toProviderCallError(error);
      if (failure.code === 'not_found') {
        items[i] = { ...item, outcome: 'already_in_state' };
      } else if (failure.retryable) {
        // Progress so far is kept; the queue retry continues with the remaining items.
        await op.writer.save({ ...state, phase: 'written', items });
        throw failure;
      } else {
        items[i] = { ...item, outcome: 'failed', code: failure.code };
      }
    }
    state = await op.writer.save({ ...state, phase: 'written', items: [...items] });
  }
  if (state.phase !== 'written') state = await op.writer.save({ ...state, phase: 'written' });
  return aggregateForwarding(op, await readBackForwarding(op, state, uid));
}

// revoke_oauth_grant ----------------------------------------------------------------------------

const APP_ID_HASH = /^[0-9a-f]{64}$/;

async function matchingGrants(op: Op, uid: string, app: string) {
  const grants = await op.calls.graph.listGrants(uid, op.profile);
  return grants.filter((grant) => appIdHash(grant.clientId) === app);
}

async function revokeOauthGrant(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
  params: ExecuteRequest['params'],
): Promise<Outcome> {
  const app = typeof params.appIdHash === 'string' ? params.appIdHash.toLowerCase() : '';
  if (!APP_ID_HASH.test(app)) throw new ActionFailure('invalid_request');
  if (existing?.phase === 'written') {
    return (await matchingGrants(op, uid, app)).length === 0
      ? done(op, existing)
      : notYet(op, existing);
  }
  await targetUser(op, uid);
  const matching = await matchingGrants(op, uid, app);
  let state =
    existing ?? (await op.writer.save({ phase: 'pre', pre: { uid, app, count: matching.length } }));
  if (matching.length === 0) {
    const resultCode = existing === null ? 'already_in_state' : undefined;
    return done(
      op,
      await op.writer.save({ ...state, phase: 'written', ...(resultCode ? { resultCode } : {}) }),
    );
  }
  for (const grant of matching) {
    await write(op, () => op.calls.graph.deleteGrant(grant.id, op.profile, op.requestId));
  }
  state = await op.writer.save({ ...state, phase: 'written' });
  // Confirmed by a re-list showing no grant of the application (D9.8).
  return (await matchingGrants(op, uid, app)).length === 0 ? done(op, state) : notYet(op, state);
}

// ---------------------------------------------------------------------------------------------
// confirm
// ---------------------------------------------------------------------------------------------

export function confirmAction(
  ctx: MicrosoftContext,
  ref: { type: ProviderActionType; providerReference: string },
  signal: AbortSignal,
): Promise<ProviderActionResult> {
  return runAction(
    { provider: MICROSOFT_PROVIDER, action: ref.type, metrics: ctx.deps.metrics },
    async () => {
      const parsed = parseProviderReference(MICROSOFT_REFERENCE_PREFIX, ref.providerReference);
      if (!parsed || parsed.type !== ref.type)
        return { result: failed('unknown_reference', false) };
      const writer = new ActionStateWriter(
        ctx.deps.actionState,
        parsed.actionPublicId,
        ctx.deps.clock,
      );
      const state = await writer.load();
      if (!state) return { result: failed('unknown_reference', false) };
      if (state.pre.unsupported === true) {
        return {
          result: { status: 'unsupported' },
          ...(state.resultCode ? { resultCode: state.resultCode } : {}),
        };
      }
      if (state.phase === 'pre' || state.phase === 'rollback_pre') {
        return { result: failed('action_not_written', false) };
      }
      const calls = await ctx.open(signal);
      const op = makeOp(ctx, calls, ref.type, parsed.actionPublicId);
      if (state.phase === 'rollback_written') return readBackRollback(op, state);
      const uid = asString(state.pre.uid);
      if (!uid) return { result: failed('unknown_reference', false) };
      switch (ref.type) {
        case 'revoke_sessions':
        case 'require_password_reset':
          return done(op, state);
        case 'suspend_account':
          return readBackSuspended(op, state);
        case 'require_mfa':
          return readBackMember(op, state, true);
        case 'remove_forwarding_rule':
          return aggregateForwarding(op, await readBackForwarding(op, state, uid));
        case 'revoke_oauth_grant': {
          const app = asString(state.pre.app);
          if (!app) return { result: failed('unknown_reference', false) };
          return (await matchingGrants(op, uid, app)).length === 0
            ? done(op, state)
            : notYet(op, state);
        }
      }
    },
  );
}

// ---------------------------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------------------------

async function noopRollback(op: Op, state: ProviderActionState | null): Promise<Outcome> {
  const saved = await op.writer.save({
    phase: 'rollback_written',
    pre: state?.pre ?? {},
    ...(state?.items ? { items: state.items } : {}),
    resultCode: 'restored_previous_state_noop',
  });
  return done(op, saved);
}

async function readBackRollback(op: Op, state: ProviderActionState): Promise<Outcome> {
  if (state.resultCode === 'restored_previous_state_noop') return done(op, state);
  const uid = asString(state.pre.uid);
  if (!uid) throw new ActionFailure('unknown_reference');
  switch (op.type) {
    case 'suspend_account': {
      const user = await op.calls.graph.getUser(uid, op.profile);
      if (!user) throw new ActionFailure('identity_not_found');
      return user.accountEnabled === true ? done(op, state) : notYet(op, state);
    }
    case 'require_mfa':
      return readBackMember(op, state, false);
    case 'remove_forwarding_rule': {
      for (const item of state.items ?? []) {
        if (item.outcome !== 'confirmed' || item.enabled !== true) continue;
        const ref = await itemRef(op, item);
        const rule = ref ? await op.calls.graph.getRule(uid, ref, op.profile) : null;
        if (rule === null) throw new ActionFailure('item_not_found');
        if (!rule.isEnabled) return notYet(op, state);
      }
      return done(op, state);
    }
    default:
      return { result: { status: 'unsupported' }, resultCode: 'rollback_not_available' };
  }
}

export function rollbackAction(
  ctx: MicrosoftContext,
  request: RollbackRequest,
  signal: AbortSignal,
): Promise<ProviderActionResult> {
  return runAction(
    { provider: MICROSOFT_PROVIDER, action: request.type, metrics: ctx.deps.metrics },
    async () => {
      if (!isValidActionPublicId(request.actionPublicId)) {
        return { result: failed('invalid_request', false) };
      }
      if (!ROLLBACK_TYPES.has(request.type)) {
        return { result: { status: 'unsupported' }, resultCode: 'rollback_not_available' };
      }
      const writer = new ActionStateWriter(
        ctx.deps.actionState,
        request.actionPublicId,
        ctx.deps.clock,
      );
      const state = await writer.load();
      const calls = await ctx.open(signal);
      const op = makeOp(ctx, calls, request.type, request.actionPublicId);
      // Nothing was ever done by the gateway (no state, an unsupported answer, or the target was
      // already in the requested state): rollback changes nothing (D9.3).
      if (
        state === null ||
        state.pre.unsupported === true ||
        state.resultCode === 'already_in_state'
      ) {
        return noopRollback(op, state);
      }
      if (state.phase === 'rollback_written') return readBackRollback(op, state);
      const uid = asString(state.pre.uid);
      if (!uid) return { result: failed('unknown_reference', false) };
      await targetUser(op, uid);
      switch (request.type) {
        case 'suspend_account': {
          if (state.pre.enabled !== true) return noopRollback(op, state);
          const next = await op.writer.save({ ...state, phase: 'rollback_pre', checks: 0 });
          await write(op, () =>
            op.calls.graph.patchUser(uid, { accountEnabled: true }, op.profile, op.requestId),
          );
          return readBackRollback(op, await op.writer.save({ ...next, phase: 'rollback_written' }));
        }
        case 'require_mfa': {
          const gid = asString(state.pre.gid);
          if (state.pre.member !== false || !gid) return noopRollback(op, state);
          const next = await op.writer.save({ ...state, phase: 'rollback_pre', checks: 0 });
          await write(op, () => op.calls.graph.removeMember(gid, uid, op.profile, op.requestId));
          return readBackRollback(op, await op.writer.save({ ...next, phase: 'rollback_written' }));
        }
        case 'remove_forwarding_rule': {
          if (state.pre.mode === 'delete') {
            return { result: { status: 'unsupported' }, resultCode: 'rollback_not_available' };
          }
          const restore = (state.items ?? []).filter(
            (item) => item.outcome === 'confirmed' && item.enabled === true,
          );
          if (restore.length === 0) return noopRollback(op, state);
          const next = await op.writer.save({ ...state, phase: 'rollback_pre', checks: 0 });
          for (const item of restore) {
            const ref = await itemRef(op, item);
            if (!ref) throw new ActionFailure('item_not_found');
            await write(op, () =>
              op.calls.graph.setRuleEnabled(uid, ref, true, op.profile, op.requestId),
            );
          }
          return readBackRollback(op, await op.writer.save({ ...next, phase: 'rollback_written' }));
        }
        default:
          return { result: { status: 'unsupported' }, resultCode: 'rollback_not_available' };
      }
    },
  );
}
