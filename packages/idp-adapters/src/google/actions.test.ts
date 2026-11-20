import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appIdHash } from '../core/hash';
import type { ProviderActionType, ProviderIdentityRef } from '../port/ato-port';
import type { MailboxItemRow } from '../port/state-ports';
import { GOOGLE_PROFILES, GOOGLE_SCOPES } from '../requirements';
import {
  GS_ADMIN_EMAIL,
  GS_CLIENTS,
  GS_MFA_OU,
  GS_USERS,
  googleCustomer,
  gsEmail,
  type GsUserKey,
} from '../testing/datasets/google';
import {
  createGoogleTestbed,
  defaultGoogleGrants,
  type GoogleTestbed,
  type GoogleTestbedOptions,
} from '../testing/google-harness';

const signal = () => new AbortController().signal;
let testbed: GoogleTestbed | null = null;

async function bed(options: GoogleTestbedOptions = {}, probe = true): Promise<GoogleTestbed> {
  testbed = await createGoogleTestbed(options);
  if (probe) await testbed.adapter.probe(signal());
  testbed.sims.script.clearCalls();
  return testbed;
}

afterEach(async () => {
  await testbed?.stop();
  testbed = null;
});

const identity = (key: GsUserKey): ProviderIdentityRef => ({
  provider: 'google_workspace',
  externalId: GS_USERS[key],
  primaryEmail: gsEmail(key),
});

function execute(
  tb: GoogleTestbed,
  type: ProviderActionType,
  options: {
    user?: GsUserKey;
    id?: string;
    params?: Record<string, string | number | boolean>;
    identity?: ProviderIdentityRef;
  } = {},
) {
  const actionPublicId = options.id ?? randomUUID();
  return tb.adapter
    .execute(
      {
        actionPublicId,
        idempotencyKey: actionPublicId,
        type,
        identity: options.identity ?? identity(options.user ?? 'alex'),
        params: options.params ?? {},
      },
      signal(),
    )
    .then((result) => ({ result, actionPublicId }));
}

const reference = (type: ProviderActionType, actionPublicId: string) =>
  `gws:${type}:${actionPublicId}`;

function rollback(
  tb: GoogleTestbed,
  type: ProviderActionType,
  actionPublicId: string,
  user: GsUserKey = 'alex',
) {
  return tb.adapter.rollback(
    {
      actionPublicId,
      idempotencyKey: `${actionPublicId}:rollback`,
      type,
      identity: identity(user),
      providerReference: reference(type, actionPublicId),
    },
    signal(),
  );
}

const confirm = (tb: GoogleTestbed, type: ProviderActionType, actionPublicId: string) =>
  tb.adapter.confirm({ type, providerReference: reference(type, actionPublicId) }, signal());

/** Successful writes (non-GET, 2xx) in the simulator call log. */
const effectiveWrites = (tb: GoogleTestbed) =>
  tb.sims.script.writes().filter((call) => call.status >= 200 && call.status < 300);

const user = (tb: GoogleTestbed, key: GsUserKey) => {
  const found = tb.customer.users.find((u) => u.id === GS_USERS[key]);
  if (!found) throw new Error('dataset');
  return found;
};

const NOW = '2026-11-10T12:00:00.000Z';

describe('revoke_sessions (sign-out plus OAuth token revocation)', () => {
  it('signs out, revokes every token, confirms by re-list and is idempotent', async () => {
    const tb = await bed();
    const { result, actionPublicId } = await execute(tb, 'revoke_sessions');
    expect(result).toEqual({
      status: 'confirmed',
      providerReference: `gws:revoke_sessions:${actionPublicId}`,
      confirmedAt: NOW,
    });
    expect(effectiveWrites(tb).map((c) => [c.method, c.path.replace(/\/[^/]+$/, '/…')])).toEqual([
      ['POST', `/admin/directory/v1/users/${GS_USERS.alex}/…`],
      ['DELETE', `/admin/directory/v1/users/${GS_USERS.alex}/tokens/…`],
      ['DELETE', `/admin/directory/v1/users/${GS_USERS.alex}/tokens/…`],
    ]);
    expect(effectiveWrites(tb).every((c) => c.subject === GS_ADMIN_EMAIL)).toBe(true);
    expect(tb.customer.tokens[GS_USERS.alex]).toEqual([]);
    const again = await execute(tb, 'revoke_sessions', { id: actionPublicId });
    expect(again.result.status).toBe('confirmed');
    expect(effectiveWrites(tb)).toHaveLength(3);
    expect(await confirm(tb, 'revoke_sessions', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(await rollback(tb, 'revoke_sessions', actionPublicId)).toEqual({
      status: 'unsupported',
    });
  });

  it('fails throttled (retryable); the retry neither signs out twice nor repeats deletions', async () => {
    const tb = await bed();
    tb.sims.script.inject({
      simulator: 'google-admin',
      method: 'DELETE',
      path: /\/tokens\//,
      status: 403,
      reason: 'userRateLimitExceeded',
    });
    const first = await execute(tb, 'revoke_sessions');
    expect(first.result).toEqual({ status: 'failed', code: 'throttled', retryable: true });
    const retry = await execute(tb, 'revoke_sessions', { id: first.actionPublicId });
    expect(retry.result.status).toBe('confirmed');
    const writes = effectiveWrites(tb);
    expect(writes.filter((c) => c.method === 'POST')).toHaveLength(1);
    expect(writes.filter((c) => c.method === 'DELETE')).toHaveLength(2);
  });

  it('stays pending while a re-list still shows tokens (confirmation never converging)', async () => {
    const tb = await bed();
    tb.sims.script.delayReadBack(100);
    const { result, actionPublicId } = await execute(tb, 'revoke_sessions');
    expect(result).toEqual({
      status: 'pending',
      providerReference: reference('revoke_sessions', actionPublicId),
      pollAfterMs: 10_000,
    });
    expect(await confirm(tb, 'revoke_sessions', actionPublicId)).toMatchObject({
      status: 'pending',
      pollAfterMs: 20_000,
    });
    expect(await confirm(tb, 'revoke_sessions', actionPublicId)).toMatchObject({
      pollAfterMs: 40_000,
    });
  });

  it('fails identity_not_found (404), domain_not_linked, missing_permission and missing_privileged_role', async () => {
    const tb = await bed();
    expect(
      (
        await execute(tb, 'revoke_sessions', {
          identity: { provider: 'google_workspace', externalId: '199999999999999999999' },
        })
      ).result,
    ).toEqual({ status: 'failed', code: 'identity_not_found', retryable: false });
    expect((await execute(tb, 'revoke_sessions', { user: 'frank' })).result).toEqual({
      status: 'failed',
      code: 'domain_not_linked',
      retryable: false,
    });
    // A super administrator cannot be signed out by the delegated administrator.
    expect((await execute(tb, 'revoke_sessions', { user: 'root' })).result).toEqual({
      status: 'failed',
      code: 'missing_privileged_role',
      retryable: false,
    });
    tb.sims.script.revokePermission(GOOGLE_SCOPES.directoryUserSecurity);
    expect((await execute(tb, 'revoke_sessions')).result).toEqual({
      status: 'failed',
      code: 'missing_permission',
      retryable: false,
    });
    expect(effectiveWrites(tb)).toHaveLength(0);
  });
});

describe('require_password_reset', () => {
  it('sets changePasswordAtNextLogin, confirms by read-back and is idempotent', async () => {
    const tb = await bed();
    const { result, actionPublicId } = await execute(tb, 'require_password_reset');
    expect(result.status).toBe('confirmed');
    expect(user(tb, 'alex').changePasswordAtNextLogin).toBe(true);
    await execute(tb, 'require_password_reset', { id: actionPublicId });
    expect(effectiveWrites(tb)).toHaveLength(1);
    expect(await rollback(tb, 'require_password_reset', actionPublicId)).toEqual({
      status: 'unsupported',
    });
  });

  it('answers already_in_state without a write when the flag is already set', async () => {
    const action = vi.fn();
    const tb = await bed({ metrics: { action } });
    const { result, actionPublicId } = await execute(tb, 'require_password_reset', {
      user: 'gale',
    });
    expect(result.status).toBe('confirmed');
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('already_in_state');
    expect(effectiveWrites(tb)).toHaveLength(0);
    expect(action).toHaveBeenCalledWith({
      provider: 'google_workspace',
      action: 'require_password_reset',
      outcome: 'already_in_state',
    });
  });

  it('goes pending → confirmed when the read-back lags', async () => {
    const tb = await bed();
    tb.sims.script.delayReadBack(1);
    const { result, actionPublicId } = await execute(tb, 'require_password_reset');
    expect(result).toMatchObject({ status: 'pending', pollAfterMs: 10_000 });
    expect(await confirm(tb, 'require_password_reset', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(effectiveWrites(tb)).toHaveLength(1);
  });
});

describe('suspend_account', () => {
  it('suspends with read-back and rolls back only what it changed', async () => {
    const tb = await bed();
    const { result, actionPublicId } = await execute(tb, 'suspend_account', { user: 'blake' });
    expect(result.status).toBe('confirmed');
    expect(user(tb, 'blake').suspended).toBe(true);
    expect(tb.actionState.peek(actionPublicId)?.pre).toEqual({
      uid: GS_USERS.blake,
      suspended: false,
    });
    expect(await rollback(tb, 'suspend_account', actionPublicId, 'blake')).toMatchObject({
      status: 'confirmed',
    });
    expect(user(tb, 'blake').suspended).toBe(false);
    // A repeated rollback only re-confirms.
    expect(await rollback(tb, 'suspend_account', actionPublicId, 'blake')).toMatchObject({
      status: 'confirmed',
    });
    expect(effectiveWrites(tb)).toHaveLength(2);
  });

  it('is already_in_state for a suspended user; rollback is a no-op that never unsuspends', async () => {
    const tb = await bed();
    const { result, actionPublicId } = await execute(tb, 'suspend_account', { user: 'casey' });
    expect(result.status).toBe('confirmed');
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('already_in_state');
    expect(await rollback(tb, 'suspend_account', actionPublicId, 'casey')).toMatchObject({
      status: 'confirmed',
    });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('restored_previous_state_noop');
    expect(user(tb, 'casey').suspended).toBe(true);
    expect(effectiveWrites(tb)).toHaveLength(0);
  });

  it('resumes a rollback whose write was throttled; the redelivered rollback confirms', async () => {
    const tb = await bed();
    const { actionPublicId } = await execute(tb, 'suspend_account', { user: 'blake' });
    tb.sims.script.inject({ method: 'PUT', path: /\/users\//, status: 429, retryAfter: '2' });
    expect(await rollback(tb, 'suspend_account', actionPublicId, 'blake')).toEqual({
      status: 'failed',
      code: 'throttled',
      retryable: true,
    });
    expect(tb.actionState.peek(actionPublicId)?.phase).toBe('rollback_pre');
    expect(user(tb, 'blake').suspended).toBe(true);
    expect(await rollback(tb, 'suspend_account', actionPublicId, 'blake')).toMatchObject({
      status: 'confirmed',
    });
    expect(user(tb, 'blake').suspended).toBe(false);
    expect(tb.actionState.peek(actionPublicId)?.phase).toBe('rollback_written');
    expect(effectiveWrites(tb)).toHaveLength(2);
  });

  it('rollback without any pre-state changes nothing', async () => {
    const tb = await bed();
    expect(await rollback(tb, 'suspend_account', randomUUID())).toMatchObject({
      status: 'confirmed',
    });
    expect(effectiveWrites(tb)).toHaveLength(0);
  });

  it('retries a throttled write with exactly one effective write; pending until the read-back converges', async () => {
    const tb = await bed();
    tb.sims.script.inject({ method: 'PUT', path: /\/users\//, status: 429, retryAfter: '2' });
    const first = await execute(tb, 'suspend_account');
    expect(first.result).toEqual({ status: 'failed', code: 'throttled', retryable: true });
    tb.sims.script.delayReadBack(2);
    const retry = await execute(tb, 'suspend_account', { id: first.actionPublicId });
    expect(retry.result).toMatchObject({ status: 'pending', pollAfterMs: 10_000 });
    expect(await confirm(tb, 'suspend_account', first.actionPublicId)).toMatchObject({
      status: 'pending',
      pollAfterMs: 20_000,
    });
    expect(await confirm(tb, 'suspend_account', first.actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(effectiveWrites(tb)).toHaveLength(1);
  });

  it('fails missing_privileged_role for a super administrator and missing_permission without the scope', async () => {
    const tb = await bed();
    expect((await execute(tb, 'suspend_account', { user: 'root' })).result).toEqual({
      status: 'failed',
      code: 'missing_privileged_role',
      retryable: false,
    });
    expect(user(tb, 'root').suspended).toBe(false);
    tb.sims.script.revokePermission(GOOGLE_SCOPES.directoryUser);
    expect((await execute(tb, 'suspend_account')).result).toEqual({
      status: 'failed',
      code: 'missing_permission',
      retryable: false,
    });
  });
});

describe('require_mfa (tenant-designated 2SV organizational unit, PQ2)', () => {
  it('moves the user to the OU, confirms by read-back and restores pre.ou on rollback', async () => {
    const tb = await bed();
    const { result, actionPublicId } = await execute(tb, 'require_mfa');
    expect(result.status).toBe('confirmed');
    expect(user(tb, 'alex').orgUnitPath).toBe(GS_MFA_OU);
    expect(tb.actionState.peek(actionPublicId)?.pre).toEqual({
      uid: GS_USERS.alex,
      ou: '/Staff',
      target: GS_MFA_OU,
    });
    // The extended profile is used (its own service account and delegated admin).
    expect(
      tb.connections.tokenRequests.some((r) => r.profile === GOOGLE_PROFILES.responseExtended),
    ).toBe(true);
    expect(await rollback(tb, 'require_mfa', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(user(tb, 'alex').orgUnitPath).toBe('/Staff');
    expect(effectiveWrites(tb)).toHaveLength(2);
  });

  it('is already_in_state for a user in the OU; rollback is a no-op', async () => {
    const tb = await bed();
    const { actionPublicId } = await execute(tb, 'require_mfa', { user: 'gale' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('already_in_state');
    await rollback(tb, 'require_mfa', actionPublicId, 'gale');
    expect(user(tb, 'gale').orgUnitPath).toBe(GS_MFA_OU);
    expect(effectiveWrites(tb)).toHaveLength(0);
  });

  it('resumes a throttled rollback and completes one whose write landed before a crash', async () => {
    const tb = await bed();
    const { actionPublicId } = await execute(tb, 'require_mfa');
    tb.sims.script.inject({ method: 'PUT', path: /\/users\//, status: 503 });
    expect(await rollback(tb, 'require_mfa', actionPublicId)).toMatchObject({
      status: 'failed',
      retryable: true,
    });
    expect(tb.actionState.peek(actionPublicId)?.phase).toBe('rollback_pre');
    expect(await rollback(tb, 'require_mfa', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(user(tb, 'alex').orgUnitPath).toBe('/Staff');

    // Crash between the rollback write and the `rollback_written` save: the state is still
    // `rollback_pre` but the user is already back in pre.ou; the retry completes, not no-ops.
    const second = await execute(tb, 'require_mfa');
    const saved = tb.actionState.peek(second.actionPublicId);
    if (!saved) throw new Error('state');
    await tb.actionState.save(second.actionPublicId, { ...saved, phase: 'rollback_pre' });
    user(tb, 'alex').orgUnitPath = '/Staff';
    expect(await rollback(tb, 'require_mfa', second.actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    const after = tb.actionState.peek(second.actionPublicId);
    expect(after?.phase).toBe('rollback_written');
    expect(after?.resultCode).toBeUndefined();
  });

  it('refuses to roll back over a later administrator move (conflict)', async () => {
    const tb = await bed();
    const { actionPublicId } = await execute(tb, 'require_mfa');
    user(tb, 'alex').orgUnitPath = '/IT';
    expect(await rollback(tb, 'require_mfa', actionPublicId)).toEqual({
      status: 'failed',
      code: 'conflict',
      retryable: false,
    });
    expect(user(tb, 'alex').orgUnitPath).toBe('/IT');
  });

  it('is unsupported (not_configured) without an OU and fails bad_request for a deleted OU', async () => {
    const tb = await bed({
      settings: (s) => ({ ...s, mfaEnforcement: { groupId: null, orgUnitPath: null } }),
    });
    const { result, actionPublicId } = await execute(tb, 'require_mfa');
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('not_configured');
    await tb.stop();
    const tb2 = await bed();
    tb2.customer.orgUnits = tb2.customer.orgUnits.filter((u) => u.orgUnitPath !== GS_MFA_OU);
    expect((await execute(tb2, 'require_mfa')).result).toEqual({
      status: 'failed',
      code: 'bad_request',
      retryable: false,
    });
  });
});

describe('remove_forwarding_rule (auto-forwarding and filters, no rollback)', () => {
  /** Runs the settings sweep so the mailbox items exist (as the worker would). */
  async function swept(options: GoogleTestbedOptions = {}) {
    const tb = await bed(options);
    let cursor: string | null = null;
    for (let i = 0; i < 10; i += 1) {
      const page = await tb.adapter.ingest('forwarding_changes', cursor, signal());
      cursor = page.cursor;
      if (!page.hasMore) break;
    }
    tb.sims.script.clearCalls();
    const rows = tb.mailboxState.all(tb.integration.id);
    const row = (predicate: (r: MailboxItemRow) => boolean) => {
      const found = rows.find(predicate);
      if (!found) throw new Error('item');
      return found;
    };
    return { tb, rows, row };
  }

  it('disables auto-forwarding impersonating the owner, with read-back; idempotent', async () => {
    const { tb, row } = await swept();
    const item = row((r) => r.kind === 'forwarding');
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      user: 'blake',
      params: { itemId: item.publicId },
    });
    expect(result.status).toBe('confirmed');
    expect(tb.customer.gmail[GS_USERS.blake]?.autoForwarding.enabled).toBe(false);
    const writes = effectiveWrites(tb);
    expect(writes.map((c) => [c.simulator, c.method, c.subject])).toEqual([
      ['gmail', 'PUT', 'blake@fabrikam-it.example'],
    ]);
    expect(
      tb.connections.tokenRequests.some(
        (r) => r.subject === 'blake@fabrikam-it.example' && r.profile === GOOGLE_PROFILES.response,
      ),
    ).toBe(true);
    // provider_state holds ids and flags only, never an address.
    expect(JSON.stringify(tb.actionState.peek(actionPublicId))).not.toContain('@');
    await execute(tb, 'remove_forwarding_rule', {
      user: 'blake',
      id: actionPublicId,
      params: { itemId: item.publicId },
    });
    expect(effectiveWrites(tb)).toHaveLength(1);
    expect(await rollback(tb, 'remove_forwarding_rule', actionPublicId, 'blake')).toEqual({
      status: 'unsupported',
    });
  });

  it('deletes a forwarding filter; an already deleted filter is already_in_state', async () => {
    const { tb, row } = await swept();
    const filter = row((r) => r.kind === 'inbox_rule' && r.traits.includes('forwards_external'));
    expect(filter.providerItemRef).toBe('ANe1BmgAlex0001');
    const { result } = await execute(tb, 'remove_forwarding_rule', {
      params: { itemId: filter.publicId },
    });
    expect(result.status).toBe('confirmed');
    expect(tb.customer.gmail[GS_USERS.alex]?.filters.map((f) => f.id)).toEqual(['ANe1BmgAlex0002']);
    const again = await execute(tb, 'remove_forwarding_rule', {
      params: { itemId: filter.publicId },
    });
    expect(again.result.status).toBe('confirmed');
    expect(tb.actionState.peek(again.actionPublicId)?.resultCode).toBe('already_in_state');
    expect(effectiveWrites(tb)).toHaveLength(1);
  });

  it('goes pending → confirmed when the read-back lags', async () => {
    const { tb, row } = await swept();
    const item = row((r) => r.kind === 'forwarding');
    tb.sims.script.delayReadBack(1);
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      user: 'blake',
      params: { itemId: item.publicId },
    });
    expect(result).toMatchObject({ status: 'pending', pollAfterMs: 10_000 });
    expect(await confirm(tb, 'remove_forwarding_rule', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
  });

  it('acts on every external item with all_external and reports partial removal', async () => {
    const { tb, rows } = await swept({
      customer: (now) => {
        // A second external forwarding filter for blake.
        const customer = googleCustomer(now);
        customer.gmail[GS_USERS.blake]?.filters.push({
          id: 'ANe1BmgBlake002',
          criteria: { from: 'ceo@fabrikam-it.example' },
          action: { forward: 'copy@exfil-mail.example' },
        });
        return customer;
      },
    });
    const external = rows.filter(
      (r) => r.state === 'present' && r.traits.includes('forwards_external'),
    );
    expect(external.map((r) => r.kind).sort()).toEqual(['forwarding', 'inbox_rule', 'inbox_rule']);
    tb.sims.script.inject({
      simulator: 'gmail',
      method: 'DELETE',
      path: /blake.*filters/,
      status: 403,
    });
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      user: 'blake',
      params: { scope: 'all_external' },
    });
    expect(result).toEqual({ status: 'failed', code: 'partial', retryable: false });
    const state = tb.actionState.peek(actionPublicId);
    expect(state?.resultCode).toBe('partial');
    expect(state?.items?.map((i) => [i.outcome, i.code])).toEqual(
      expect.arrayContaining([
        ['confirmed', undefined],
        ['failed', 'missing_permission'],
      ]),
    );
    expect(tb.customer.gmail[GS_USERS.blake]?.autoForwarding.enabled).toBe(false);
  });

  it('answers unsupported for a delegate, item_not_found for another user’s item, invalid_request otherwise', async () => {
    const { tb, row } = await swept();
    const delegate = row((r) => r.kind === 'delegate');
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      user: 'erin',
      params: { itemId: delegate.publicId },
    });
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('not_forwarding');
    expect(
      (await execute(tb, 'remove_forwarding_rule', { params: { itemId: delegate.publicId } }))
        .result,
    ).toEqual({ status: 'failed', code: 'item_not_found', retryable: false });
    expect((await execute(tb, 'remove_forwarding_rule', { params: {} })).result).toEqual({
      status: 'failed',
      code: 'invalid_request',
      retryable: false,
    });
    expect(effectiveWrites(tb)).toHaveLength(0);
  });

  it('fails missing_permission without gmail.settings.sharing', async () => {
    const { tb, row } = await swept();
    tb.sims.script.revokePermission(GOOGLE_SCOPES.gmailSettingsSharing);
    const item = row((r) => r.kind === 'forwarding');
    expect(
      (
        await execute(tb, 'remove_forwarding_rule', {
          user: 'blake',
          params: { itemId: item.publicId },
        })
      ).result,
    ).toEqual({ status: 'failed', code: 'missing_permission', retryable: false });
    expect(tb.customer.gmail[GS_USERS.blake]?.autoForwarding.enabled).toBe(true);
  });
});

describe('revoke_oauth_grant', () => {
  it('deletes the tokens of the application only and confirms by re-list; idempotent', async () => {
    const tb = await bed();
    const params = { appIdHash: appIdHash(GS_CLIENTS.mailSync) };
    const { result, actionPublicId } = await execute(tb, 'revoke_oauth_grant', { params });
    expect(result.status).toBe('confirmed');
    expect(tb.customer.tokens[GS_USERS.alex]?.map((t) => t.clientId)).toEqual([
      GS_CLIENTS.calendar,
    ]);
    await execute(tb, 'revoke_oauth_grant', { id: actionPublicId, params });
    expect(effectiveWrites(tb)).toHaveLength(1);
    const none = await execute(tb, 'revoke_oauth_grant', { params });
    expect(tb.actionState.peek(none.actionPublicId)?.resultCode).toBe('already_in_state');
    expect(
      (await execute(tb, 'revoke_oauth_grant', { params: { appIdHash: 'nope' } })).result,
    ).toEqual({
      status: 'failed',
      code: 'invalid_request',
      retryable: false,
    });
  });

  it('stays pending while the token is still listed', async () => {
    const tb = await bed();
    tb.sims.script.delayReadBack(1);
    const { result, actionPublicId } = await execute(tb, 'revoke_oauth_grant', {
      params: { appIdHash: appIdHash(GS_CLIENTS.mailSync) },
    });
    expect(result).toMatchObject({ status: 'pending' });
    expect(await confirm(tb, 'revoke_oauth_grant', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
  });
});

describe('action gate, references and probing', () => {
  it('answers unsupported (action_disabled) without any provider call', async () => {
    const tb = await bed({
      settings: (s) => ({ ...s, actions: { ...s.actions, suspend_account: { enabled: false } } }),
    });
    const { result, actionPublicId } = await execute(tb, 'suspend_account');
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('action_disabled');
    expect(tb.sims.script.calls()).toEqual([]);
    expect(await confirm(tb, 'suspend_account', actionPublicId)).toEqual({ status: 'unsupported' });
  });

  it('probes first when the report is stale and refuses an unavailable capability', async () => {
    const grants = defaultGoogleGrants().map((g) =>
      g.profile === GOOGLE_PROFILES.response ? { ...g, status: 'pending' as const } : g,
    );
    const tb = await bed({ grants }, false);
    const { result, actionPublicId } = await execute(tb, 'suspend_account');
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('capability_unavailable');
    expect(tb.sims.script.calls().length).toBeGreaterThan(0); // the probe's reads
    expect(tb.sims.script.writes()).toEqual([]);
  });

  it('refuses foreign or malformed references and never throws', async () => {
    const tb = await bed();
    const id = randomUUID();
    for (const providerReference of [
      `msgraph:suspend_account:${id}`,
      'garbage',
      `gws:suspend_account:${id}`,
    ]) {
      expect(
        await tb.adapter.confirm({ type: 'suspend_account', providerReference }, signal()),
      ).toEqual({
        status: 'failed',
        code: 'unknown_reference',
        retryable: false,
      });
    }
    expect(
      await tb.adapter.confirm(
        { type: 'revoke_sessions', providerReference: `gws:suspend_account:${id}` },
        signal(),
      ),
    ).toMatchObject({ status: 'failed', code: 'unknown_reference' });
  });
});
