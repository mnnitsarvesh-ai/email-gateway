/**
 * Google Workspace provider-confirmed response actions (design note D9, §3.3, ADR-0085) over the
 * Admin SDK Directory (as the grant's delegated administrator) and Gmail settings (impersonating
 * the mailbox owner).
 *
 * Every action: linked-domain guard on the directory user (invariant 4), pre-state captured once
 * before the first write and saved through `ActionStateStore`, idempotent re-execution (a saved
 * `written` phase only confirms), read-back confirmation for state changes, rollback only of what
 * the gateway changed (`restored_previous_state_noop` otherwise). Nothing is claimed without a
 * provider 2xx and, for state changes, a read-back showing the requested state (invariant 5).
 *
 * | Action                   | Write                                                         | Confirmation              | Rollback            |
 * | ------------------------ | ------------------------------------------------------------- | ------------------------- | ------------------- |
 * | `revoke_sessions`        | `users.signOut`, then `tokens.delete` of every OAuth token    | re-list (no token left)   | –                   |
 * | `require_password_reset` | `users.update` `changePasswordAtNextLogin = true`             | read-back                 | –                   |
 * | `suspend_account`        | `users.update` `suspended = true`                             | read-back                 | only if pre not suspended |
 * | `require_mfa`            | `users.update` `orgUnitPath = settings.mfaEnforcement.orgUnitPath` | read-back            | restore `pre.ou`    |
 * | `remove_forwarding_rule` | auto-forwarding `enabled = false`; filter `DELETE`            | read-back                 | – (not offered)     |
 * | `revoke_oauth_grant`     | `tokens.delete` of the tokens whose client id hashes to `appIdHash` | re-list (absent)    | –                   |
 */
import {
  ActionFailure,
  ActionStateWriter,
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
import { GOOGLE_PROFILES, GOOGLE_SCOPES } from '../requirements';
import { GOOGLE_PROVIDER, GOOGLE_REFERENCE_PREFIX, MAX_FORWARDING_ITEMS } from './constants';
import type { GoogleCalls, GoogleContext } from './context';
import type { DirectoryClient } from './directory-client';
import type { GmailClient } from './gmail-client';
import type { DirectoryUser } from './schemas';

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

/** `null` = go; otherwise the result code stored with an `unsupported` answer. */
export type ActionGate = (type: ProviderActionType, signal: AbortSignal) => Promise<string | null>;

/** Profile and scope of each action's Directory write (D5). */
const ACTION_PERMISSION: Readonly<
  Record<ProviderActionType, { profile: string; permission: string }>
> = {
  revoke_sessions: {
    profile: GOOGLE_PROFILES.response,
    permission: GOOGLE_SCOPES.directoryUserSecurity,
  },
  require_password_reset: {
    profile: GOOGLE_PROFILES.response,
    permission: GOOGLE_SCOPES.directoryUser,
  },
  suspend_account: { profile: GOOGLE_PROFILES.response, permission: GOOGLE_SCOPES.directoryUser },
  remove_forwarding_rule: {
    profile: GOOGLE_PROFILES.response,
    permission: GOOGLE_SCOPES.gmailSettingsSharing,
  },
  require_mfa: {
    profile: GOOGLE_PROFILES.responseExtended,
    permission: GOOGLE_SCOPES.directoryUser,
  },
  revoke_oauth_grant: {
    profile: GOOGLE_PROFILES.response,
    permission: GOOGLE_SCOPES.directoryUserSecurity,
  },
};

const ROLLBACK_TYPES: ReadonlySet<ProviderActionType> = new Set(['suspend_account', 'require_mfa']);

interface Op {
  ctx: GoogleContext;
  calls: GoogleCalls;
  writer: ActionStateWriter;
  type: ProviderActionType;
  reference: string;
  profile: string;
  permission: string;
  integrationId: string;
  directory: DirectoryClient;
  gmail: GmailClient;
}

type Outcome = { result: ProviderActionResult; resultCode?: string };

function asString(value: PreValues[string] | undefined): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function makeOp(
  ctx: GoogleContext,
  calls: GoogleCalls,
  type: ProviderActionType,
  actionPublicId: string,
): Op {
  const { profile, permission } = ACTION_PERMISSION[type];
  return {
    ctx,
    calls,
    writer: new ActionStateWriter(ctx.deps.actionState, actionPublicId, ctx.deps.clock),
    type,
    reference: providerReference(GOOGLE_REFERENCE_PREFIX, type, actionPublicId),
    profile,
    permission,
    integrationId: ctx.deps.integration.id,
    directory: calls.directory(profile),
    gmail: calls.gmail(GOOGLE_PROFILES.response),
  };
}

/** Whether the grant demonstrably holds the scope (observed list known and containing it). */
function permissionObserved(op: Op): boolean {
  const grant = op.calls.session.grant(op.profile);
  return grant?.status === 'active' && grant.observedPermissions?.includes(op.permission) === true;
}

/**
 * Runs a Directory write; a 403 on a held scope means the delegated administrator lacks the admin
 * role for this user (e.g. a super administrator): `missing_privileged_role`, never success.
 */
async function directoryWrite<T>(op: Op, call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw refinePermissionFailure(error, permissionObserved(op));
  }
}

/** The directory user behind the identity, with the linked-domain guard (invariant 4). */
async function targetUser(op: Op, externalId: string): Promise<DirectoryUser> {
  const user = await op.directory.getUser(externalId);
  if (!user) throw new ActionFailure('identity_not_found');
  const domain = domainOf(user.primaryEmail);
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

async function alreadyInState(op: Op, state: ProviderActionState): Promise<Outcome> {
  return done(
    op,
    await op.writer.save({ ...state, phase: 'written', resultCode: 'already_in_state' }),
  );
}

// ---------------------------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------------------------

export function executeAction(
  ctx: GoogleContext,
  request: ExecuteRequest,
  signal: AbortSignal,
  gate: ActionGate,
): Promise<ProviderActionResult> {
  return runAction(
    { provider: GOOGLE_PROVIDER, action: request.type, metrics: ctx.deps.metrics },
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

// revoke_sessions ---------------------------------------------------------------------------------

async function readBackNoTokens(op: Op, state: ProviderActionState): Promise<Outcome> {
  const uid = asString(state.pre.uid);
  if (!uid) throw new ActionFailure('unknown_reference');
  return (await op.directory.listTokens(uid)).length === 0 ? done(op, state) : notYet(op, state);
}

/**
 * Signs the user out of every web and device session, then revokes every OAuth token of the user
 * (deviation WP2-3: Microsoft's `revokeSignInSessions` also invalidates refresh tokens, so both
 * providers end every session and token). Confirmed when a re-list shows no token left.
 */
async function revokeSessions(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') return readBackNoTokens(op, existing);
  await targetUser(op, uid);
  let state = existing ?? (await op.writer.save({ phase: 'pre', pre: { uid, so: false } }));
  if (state.pre.so !== true) {
    await directoryWrite(op, () => op.directory.signOut(uid));
    state = await op.writer.save({ ...state, pre: { ...state.pre, so: true } });
  }
  for (const token of await op.directory.listTokens(uid)) {
    await directoryWrite(op, () => op.directory.deleteToken(uid, token.clientId));
  }
  state = await op.writer.save({ ...state, phase: 'written' });
  return readBackNoTokens(op, state);
}

// require_password_reset ---------------------------------------------------------------------------

async function readBackUser(
  op: Op,
  state: ProviderActionState,
  matches: (user: DirectoryUser) => boolean,
): Promise<Outcome> {
  const uid = asString(state.pre.uid);
  if (!uid) throw new ActionFailure('unknown_reference');
  const user = await op.directory.getUser(uid);
  if (!user) throw new ActionFailure('identity_not_found');
  return matches(user) ? done(op, state) : notYet(op, state);
}

const passwordChangeRequired = (user: DirectoryUser) => user.changePasswordAtNextLogin === true;
const isSuspended = (user: DirectoryUser) => user.suspended === true;

async function requirePasswordReset(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') return readBackUser(op, existing, passwordChangeRequired);
  const user = await targetUser(op, uid);
  let state = existing;
  if (state === null) {
    const already = passwordChangeRequired(user);
    state = await op.writer.save({ phase: 'pre', pre: { uid, cp: already } });
    if (already) return alreadyInState(op, state);
  }
  await directoryWrite(op, () => op.directory.updateUser(uid, { changePasswordAtNextLogin: true }));
  state = await op.writer.save({ ...state, phase: 'written' });
  return readBackUser(op, state, passwordChangeRequired);
}

// suspend_account --------------------------------------------------------------------------------

async function suspendAccount(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') return readBackUser(op, existing, isSuspended);
  const user = await targetUser(op, uid);
  let state = existing;
  if (state === null) {
    const suspended = isSuspended(user);
    state = await op.writer.save({ phase: 'pre', pre: { uid, suspended } });
    if (suspended) return alreadyInState(op, state);
  }
  await directoryWrite(op, () => op.directory.updateUser(uid, { suspended: true }));
  state = await op.writer.save({ ...state, phase: 'written' });
  return readBackUser(op, state, isSuspended);
}

// require_mfa --------------------------------------------------------------------------------------

function inOrgUnit(path: string) {
  return (user: DirectoryUser) => (user.orgUnitPath ?? '/') === path;
}

/**
 * Moves the user to the tenant-designated organizational unit with 2-Step Verification enforced
 * (PQ2, impact high); never edits 2SV settings. `pre.ou` is restored on rollback.
 */
async function requireMfa(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
): Promise<Outcome> {
  if (existing?.phase === 'written') {
    const target = asString(existing.pre.target);
    if (!target) throw new ActionFailure('unknown_reference');
    return readBackUser(op, existing, inOrgUnit(target));
  }
  let state = existing;
  if (state === null) {
    const target = op.ctx.deps.integration.settings.mfaEnforcement.orgUnitPath;
    if (!target) return unsupportedWith(op, 'not_configured');
    const user = await targetUser(op, uid);
    const ou = user.orgUnitPath ?? '/';
    state = await op.writer.save({ phase: 'pre', pre: { uid, ou, target } });
    if (ou === target) return alreadyInState(op, state);
  } else {
    await targetUser(op, uid);
  }
  const target = asString(state.pre.target);
  if (!target) throw new ActionFailure('unknown_reference');
  await directoryWrite(op, () => op.directory.updateUser(uid, { orgUnitPath: target }));
  state = await op.writer.save({ ...state, phase: 'written' });
  return readBackUser(op, state, inOrgUnit(target));
}

// remove_forwarding_rule ---------------------------------------------------------------------------

type ItemState = NonNullable<ProviderActionState['items']>[number];

async function itemRow(op: Op, item: ItemState): Promise<MailboxItemRow | null> {
  return op.ctx.deps.mailboxState.itemByPublicId(op.integrationId, item.id);
}

function initialItem(row: MailboxItemRow): ItemState {
  const base = { id: row.publicId, ref: null };
  if (row.state === 'removed') return { ...base, outcome: 'already_in_state' };
  if (row.kind === 'forwarding') return { ...base, outcome: 'pending' };
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
  const owner = identityHash(GOOGLE_PROVIDER, uid);
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

/** Whether the item's effect is in place: auto-forwarding off, or the filter gone. */
async function itemRemoved(op: Op, mailbox: string, row: MailboxItemRow): Promise<boolean> {
  if (row.kind === 'forwarding') return !(await op.gmail.getAutoForwarding(mailbox)).enabled;
  if (!row.providerItemRef) return false;
  return (await op.gmail.getFilter(mailbox, row.providerItemRef)) === null;
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
    const code = items[0]?.code ?? 'not_forwarding';
    await op.writer.save({ ...state, resultCode: code, at: state.at });
    return { result: { status: 'unsupported' }, resultCode: code };
  }
  if (items.length === 1 && items[0]?.outcome === 'failed') {
    return { result: failed(items[0].code ?? 'provider_unavailable', false) };
  }
  await op.writer.save({ ...state, resultCode: 'partial', at: state.at });
  return { result: failed('partial', false), resultCode: 'partial' };
}

/** The mailbox address the Gmail calls impersonate (re-read: `provider_state` holds no address). */
async function mailboxOf(op: Op, uid: string): Promise<string> {
  const user = await op.directory.getUser(uid);
  if (!user) throw new ActionFailure('identity_not_found');
  return user.primaryEmail.toLowerCase();
}

async function readBackForwarding(
  op: Op,
  state: ProviderActionState,
  knownMailbox?: string,
): Promise<ProviderActionState> {
  const items: ItemState[] = [];
  let mailbox = knownMailbox ?? null;
  for (const item of state.items ?? []) {
    if (item.outcome !== 'written') {
      items.push(item);
      continue;
    }
    const uid = asString(state.pre.uid);
    if (!uid) throw new ActionFailure('unknown_reference');
    mailbox ??= await mailboxOf(op, uid);
    const row = await itemRow(op, item);
    const gone = row !== null && (await itemRemoved(op, mailbox, row));
    items.push(gone ? { ...item, outcome: 'confirmed' } : item);
  }
  return { ...state, items };
}

/**
 * Disables auto-forwarding (`gmail.settings.sharing`) or deletes forwarding filters
 * (`gmail.settings.basic`), impersonating the mailbox owner. Not reversible (the gateway keeps no
 * forwarding address or filter definition), so no rollback.
 */
async function removeForwarding(
  op: Op,
  existing: ProviderActionState | null,
  uid: string,
  params: ExecuteRequest['params'],
): Promise<Outcome> {
  const user = await targetUser(op, uid);
  const mailbox = user.primaryEmail.toLowerCase();
  let state = existing;
  if (state === null) {
    const { rows, more } = await forwardingRows(op, uid, params);
    const items: ItemState[] = [];
    for (const row of rows) {
      const item = initialItem(row);
      if (item.outcome === 'pending' && (await itemRemoved(op, mailbox, row))) {
        items.push({ ...item, outcome: 'already_in_state' });
        continue;
      }
      items.push(item);
    }
    state = await op.writer.save({ phase: 'pre', pre: { uid, more }, items });
  }
  const items = [...(state.items ?? [])];
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i] as ItemState;
    if (item.outcome !== 'pending') continue;
    const row = await itemRow(op, item);
    if (!row || (row.kind === 'inbox_rule' && !row.providerItemRef)) {
      items[i] = { ...item, outcome: 'failed', code: 'item_not_found' };
      continue;
    }
    try {
      if (row.kind === 'forwarding') await op.gmail.disableAutoForwarding(mailbox);
      else await op.gmail.deleteFilter(mailbox, row.providerItemRef as string);
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
  return aggregateForwarding(op, await readBackForwarding(op, state, mailbox));
}

// revoke_oauth_grant -------------------------------------------------------------------------------

const APP_ID_HASH = /^[0-9a-f]{64}$/;

async function matchingTokens(op: Op, uid: string, app: string) {
  const tokens = await op.directory.listTokens(uid);
  return tokens.filter((token) => appIdHash(token.clientId) === app);
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
    return (await matchingTokens(op, uid, app)).length === 0
      ? done(op, existing)
      : notYet(op, existing);
  }
  await targetUser(op, uid);
  const matching = await matchingTokens(op, uid, app);
  let state =
    existing ?? (await op.writer.save({ phase: 'pre', pre: { uid, app, count: matching.length } }));
  if (matching.length === 0) {
    const resultCode = existing === null ? 'already_in_state' : undefined;
    return done(
      op,
      await op.writer.save({ ...state, phase: 'written', ...(resultCode ? { resultCode } : {}) }),
    );
  }
  for (const token of matching) {
    await directoryWrite(op, () => op.directory.deleteToken(uid, token.clientId));
  }
  state = await op.writer.save({ ...state, phase: 'written' });
  // Confirmed by a re-list showing no token of the application (D9.8).
  return (await matchingTokens(op, uid, app)).length === 0 ? done(op, state) : notYet(op, state);
}

// ---------------------------------------------------------------------------------------------
// confirm
// ---------------------------------------------------------------------------------------------

export function confirmAction(
  ctx: GoogleContext,
  ref: { type: ProviderActionType; providerReference: string },
  signal: AbortSignal,
): Promise<ProviderActionResult> {
  return runAction(
    { provider: GOOGLE_PROVIDER, action: ref.type, metrics: ctx.deps.metrics },
    async () => {
      const parsed = parseProviderReference(GOOGLE_REFERENCE_PREFIX, ref.providerReference);
      if (!parsed || parsed.type !== ref.type) {
        return { result: failed('unknown_reference', false) };
      }
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
          return readBackNoTokens(op, state);
        case 'require_password_reset':
          return readBackUser(op, state, passwordChangeRequired);
        case 'suspend_account':
          return readBackUser(op, state, isSuspended);
        case 'require_mfa': {
          const target = asString(state.pre.target);
          if (!target) return { result: failed('unknown_reference', false) };
          return readBackUser(op, state, inOrgUnit(target));
        }
        case 'remove_forwarding_rule':
          return aggregateForwarding(op, await readBackForwarding(op, state));
        case 'revoke_oauth_grant': {
          const app = asString(state.pre.app);
          if (!app) return { result: failed('unknown_reference', false) };
          return (await matchingTokens(op, uid, app)).length === 0
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
  switch (op.type) {
    case 'suspend_account':
      return readBackUser(op, state, (user) => user.suspended !== true);
    case 'require_mfa': {
      const ou = asString(state.pre.ou);
      if (!ou) throw new ActionFailure('unknown_reference');
      return readBackUser(op, state, inOrgUnit(ou));
    }
    default:
      return { result: { status: 'unsupported' }, resultCode: 'rollback_not_available' };
  }
}

export function rollbackAction(
  ctx: GoogleContext,
  request: RollbackRequest,
  signal: AbortSignal,
): Promise<ProviderActionResult> {
  return runAction(
    { provider: GOOGLE_PROVIDER, action: request.type, metrics: ctx.deps.metrics },
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
      // `rollback_pre` is resumable: a retry after a throttled or unavailable rollback write (or a
      // crash between the write and the `rollback_written` save) repeats the idempotent write.
      const resuming = state.phase === 'rollback_pre';
      if (state.phase !== 'written' && !resuming) {
        return { result: failed('action_not_written', false) };
      }
      const uid = asString(state.pre.uid);
      if (!uid) return { result: failed('unknown_reference', false) };
      const user = await targetUser(op, uid);
      const begin = () =>
        resuming
          ? Promise.resolve(state)
          : op.writer.save({ ...state, phase: 'rollback_pre', checks: 0 });
      switch (request.type) {
        case 'suspend_account': {
          if (state.pre.suspended !== false) return noopRollback(op, state);
          const next = await begin();
          await directoryWrite(op, () => op.directory.updateUser(uid, { suspended: false }));
          return readBackRollback(op, await op.writer.save({ ...next, phase: 'rollback_written' }));
        }
        case 'require_mfa': {
          const ou = asString(state.pre.ou);
          const target = asString(state.pre.target);
          if (!ou || !target) return { result: failed('unknown_reference', false) };
          const current = user.orgUnitPath ?? '/';
          if (current === ou) {
            // An interrupted rollback whose write already landed is completed, not a no-op.
            return resuming
              ? readBackRollback(op, await op.writer.save({ ...state, phase: 'rollback_written' }))
              : noopRollback(op, state);
          }
          // Moved elsewhere since (by an administrator): the gateway does not override that.
          if (current !== target) return { result: failed('conflict', false) };
          const next = await begin();
          await directoryWrite(op, () => op.directory.updateUser(uid, { orgUnitPath: ou }));
          return readBackRollback(op, await op.writer.save({ ...next, phase: 'rollback_written' }));
        }
        default:
          return { result: { status: 'unsupported' }, resultCode: 'rollback_not_available' };
      }
    },
  );
}
