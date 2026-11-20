import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appIdHash } from '../core/hash';
import type { ProviderActionType, ProviderIdentityRef } from '../port/ato-port';
import { MS_MFA_GROUP_ID, MS_SERVICE_PRINCIPALS, MS_USERS } from '../testing/datasets/microsoft';
import {
  createMicrosoftTestbed,
  type MicrosoftTestbed,
  type MicrosoftTestbedOptions,
} from '../testing/harness';

const signal = () => new AbortController().signal;
let testbed: MicrosoftTestbed | null = null;

async function bed(options: MicrosoftTestbedOptions = {}, probe = true): Promise<MicrosoftTestbed> {
  testbed = await createMicrosoftTestbed(options);
  if (probe) await testbed.adapter.probe(signal());
  testbed.sims.script.clearCalls();
  return testbed;
}

afterEach(async () => {
  await testbed?.stop();
  testbed = null;
});

const identity = (key: keyof typeof MS_USERS): ProviderIdentityRef => ({
  provider: 'microsoft_entra',
  externalId: MS_USERS[key],
  primaryEmail: `${key}@contoso-it.example`,
});

function execute(
  tb: MicrosoftTestbed,
  type: ProviderActionType,
  options: {
    user?: keyof typeof MS_USERS;
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

function rollback(
  tb: MicrosoftTestbed,
  type: ProviderActionType,
  actionPublicId: string,
  user: keyof typeof MS_USERS = 'alex',
) {
  return tb.adapter.rollback(
    {
      actionPublicId,
      idempotencyKey: `${actionPublicId}:rollback`,
      type,
      identity: identity(user),
      providerReference: `msgraph:${type}:${actionPublicId}`,
    },
    signal(),
  );
}

const confirm = (tb: MicrosoftTestbed, type: ProviderActionType, actionPublicId: string) =>
  tb.adapter.confirm({ type, providerReference: `msgraph:${type}:${actionPublicId}` }, signal());

/** Successful writes (non-GET, 2xx) in the simulator call log. */
const effectiveWrites = (tb: MicrosoftTestbed) =>
  tb.sims.script.writes('graph').filter((call) => call.status >= 200 && call.status < 300);

const user = (tb: MicrosoftTestbed, key: keyof typeof MS_USERS) =>
  tb.directory.users.find((u) => u.id === MS_USERS[key]);

describe('revoke_sessions', () => {
  it('is confirmed synchronously with an msgraph reference and is idempotent', async () => {
    const tb = await bed();
    const { result, actionPublicId } = await execute(tb, 'revoke_sessions');
    expect(result).toEqual({
      status: 'confirmed',
      providerReference: `msgraph:revoke_sessions:${actionPublicId}`,
      confirmedAt: '2026-11-10T12:00:00.000Z',
    });
    const again = await execute(tb, 'revoke_sessions', { id: actionPublicId });
    expect(again.result.status).toBe('confirmed');
    expect(effectiveWrites(tb)).toHaveLength(1);
    expect(await confirm(tb, 'revoke_sessions', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(await rollback(tb, 'revoke_sessions', actionPublicId)).toEqual({
      status: 'unsupported',
    });
  });

  it('fails missing_permission when the permission was revoked after the probe', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission('User.RevokeSessions.All');
    const { result } = await execute(tb, 'revoke_sessions');
    expect(result).toEqual({ status: 'failed', code: 'missing_permission', retryable: false });
  });

  it('fails throttled (retryable); the retry performs exactly one effective write', async () => {
    const tb = await bed();
    tb.sims.script.inject({
      simulator: 'graph',
      method: 'POST',
      path: /revokeSignInSessions$/,
      status: 429,
      retryAfter: '5',
    });
    const first = await execute(tb, 'revoke_sessions');
    expect(first.result).toEqual({ status: 'failed', code: 'throttled', retryable: true });
    const retry = await execute(tb, 'revoke_sessions', { id: first.actionPublicId });
    expect(retry.result.status).toBe('confirmed');
    expect(effectiveWrites(tb)).toHaveLength(1);
  });

  it('fails identity_not_found when the user is gone (404)', async () => {
    const tb = await bed();
    const { result } = await execute(tb, 'revoke_sessions', {
      identity: { provider: 'microsoft_entra', externalId: 'aaaaaaaa-0000-4000-8000-0000000000ff' },
    });
    expect(result).toEqual({ status: 'failed', code: 'identity_not_found', retryable: false });
    expect(effectiveWrites(tb)).toHaveLength(0);
  });

  it('refuses identities outside the provider-verified linked domains (invariant 4)', async () => {
    const tb = await bed();
    const { result } = await execute(tb, 'revoke_sessions', { user: 'frank' });
    expect(result).toEqual({ status: 'failed', code: 'domain_not_linked', retryable: false });
    tb.connections.update(tb.integration.organizationId, tb.integration.connectionPublicId, {
      linkedDomains: [{ name: 'contoso-it.example', providerVerified: false }],
    });
    expect((await execute(tb, 'revoke_sessions')).result).toMatchObject({
      code: 'domain_not_linked',
    });
    expect(effectiveWrites(tb)).toHaveLength(0);
  });
});

describe('require_password_reset', () => {
  it('sets forceChangePasswordNextSignIn and confirms on the 2xx', async () => {
    const tb = await bed();
    const { result } = await execute(tb, 'require_password_reset');
    expect(result.status).toBe('confirmed');
    expect(user(tb, 'alex')?.passwordProfile).toEqual({ forceChangePasswordNextSignIn: true });
  });

  it('fails on_premises_managed for synchronized users without writing', async () => {
    const tb = await bed();
    expect((await execute(tb, 'require_password_reset', { user: 'drew' })).result).toEqual({
      status: 'failed',
      code: 'on_premises_managed',
      retryable: false,
    });
    expect(tb.sims.script.writes()).toHaveLength(0);
  });

  it('fails missing_privileged_role for privileged users (403 with the permission granted)', async () => {
    const tb = await bed();
    expect((await execute(tb, 'require_password_reset', { user: 'casey' })).result).toEqual({
      status: 'failed',
      code: 'missing_privileged_role',
      retryable: false,
    });
  });
});

describe('suspend_account', () => {
  it('disables the account, confirms by read-back, re-executes without a second write and rolls back', async () => {
    const tb = await bed();
    const { result, actionPublicId } = await execute(tb, 'suspend_account');
    expect(result.status).toBe('confirmed');
    expect(user(tb, 'alex')?.accountEnabled).toBe(false);
    expect((await execute(tb, 'suspend_account', { id: actionPublicId })).result.status).toBe(
      'confirmed',
    );
    expect(effectiveWrites(tb)).toHaveLength(1);
    expect(tb.actionState.peek(actionPublicId)?.pre).toEqual({ uid: MS_USERS.alex, enabled: true });
    expect(await rollback(tb, 'suspend_account', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(user(tb, 'alex')?.accountEnabled).toBe(true);
    // Rollback is idempotent too.
    expect(await rollback(tb, 'suspend_account', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(effectiveWrites(tb)).toHaveLength(2);
  });

  it('answers already_in_state for a disabled account and its rollback is a no-op', async () => {
    const actions = vi.fn();
    const tb = await bed({ metrics: { action: actions } });
    const { result, actionPublicId } = await execute(tb, 'suspend_account', { user: 'gale' });
    expect(result.status).toBe('confirmed');
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('already_in_state');
    expect(actions).toHaveBeenLastCalledWith({
      provider: 'microsoft_entra',
      action: 'suspend_account',
      outcome: 'already_in_state',
    });
    expect(await rollback(tb, 'suspend_account', actionPublicId, 'gale')).toMatchObject({
      status: 'confirmed',
    });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('restored_previous_state_noop');
    expect(user(tb, 'gale')?.accountEnabled).toBe(false); // never re-enables what it did not disable
    expect(tb.sims.script.writes()).toHaveLength(0);
  });

  it('goes pending → confirmed when the read-back lags', async () => {
    const tb = await bed();
    tb.sims.script.delayReadBack(1);
    const { result, actionPublicId } = await execute(tb, 'suspend_account');
    expect(result).toEqual({
      status: 'pending',
      providerReference: `msgraph:suspend_account:${actionPublicId}`,
      pollAfterMs: 10_000,
    });
    expect(await confirm(tb, 'suspend_account', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
  });

  it('keeps answering pending with a growing interval (10 s → 5 min) when it never converges', async () => {
    const tb = await bed();
    tb.sims.script.delayReadBack(1_000);
    const { result, actionPublicId } = await execute(tb, 'suspend_account');
    expect(result).toMatchObject({ status: 'pending', pollAfterMs: 10_000 });
    const intervals: number[] = [];
    for (let i = 0; i < 8; i += 1) {
      const next = await confirm(tb, 'suspend_account', actionPublicId);
      expect(next.status).toBe('pending');
      if (next.status === 'pending') intervals.push(next.pollAfterMs);
    }
    expect(intervals).toEqual([
      20_000, 40_000, 80_000, 160_000, 300_000, 300_000, 300_000, 300_000,
    ]);
    expect(effectiveWrites(tb)).toHaveLength(1);
  });

  it('rolls back without pre-state as a no-op', async () => {
    const tb = await bed();
    const { actionPublicId } = await execute(tb, 'suspend_account');
    tb.actionState.delete(actionPublicId);
    expect(await rollback(tb, 'suspend_account', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(user(tb, 'alex')?.accountEnabled).toBe(false);
  });

  it('fails missing_privileged_role for privileged users', async () => {
    const tb = await bed();
    expect((await execute(tb, 'suspend_account', { user: 'casey' })).result).toMatchObject({
      code: 'missing_privileged_role',
    });
  });
});

describe('require_mfa', () => {
  it('adds the user to the tenant MFA group, confirms by membership and rolls back', async () => {
    const tb = await bed();
    const group = tb.directory.groups.find((g) => g.id === MS_MFA_GROUP_ID);
    const { result, actionPublicId } = await execute(tb, 'require_mfa');
    expect(result.status).toBe('confirmed');
    expect(group?.members).toEqual([MS_USERS.alex]);
    expect(await rollback(tb, 'require_mfa', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(group?.members).toEqual([]);
  });

  it('answers already_in_state for a member and never removes a membership it did not add', async () => {
    const tb = await bed();
    tb.directory.groups[0]?.members.push(MS_USERS.alex);
    const { actionPublicId } = await execute(tb, 'require_mfa');
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('already_in_state');
    expect(await rollback(tb, 'require_mfa', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(tb.directory.groups[0]?.members).toEqual([MS_USERS.alex]);
    expect(tb.sims.script.writes()).toHaveLength(0);
  });

  it('is unsupported (not_configured) without an MFA group', async () => {
    const tb = await bed({
      settings: (s) => ({ ...s, mfaEnforcement: { groupId: null, orgUnitPath: null } }),
    });
    const { result, actionPublicId } = await execute(tb, 'require_mfa');
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('not_configured');
    expect(tb.sims.script.writes()).toHaveLength(0);
  });
});

describe('remove_forwarding_rule', () => {
  async function withItems(options: MicrosoftTestbedOptions = {}) {
    const tb = await bed(options);
    let cursor: string | null = null;
    for (let i = 0; i < 5; i += 1) {
      const page = await tb.adapter.ingest('mailbox_audit', cursor, signal());
      cursor = page.cursor;
      if (!page.hasMore) break;
    }
    tb.sims.script.clearCalls();
    const items = tb.mailboxState.all(tb.integration.id);
    const rule = items.find((r) => r.providerItemRef === 'AQAAAJ5dZqA=');
    const forwarding = items.find((r) => r.kind === 'forwarding');
    if (!rule || !forwarding) throw new Error('items missing');
    return { tb, rule, forwarding };
  }
  const graphRule = (tb: MicrosoftTestbed) =>
    tb.directory.messageRules[MS_USERS.alex]?.find((r) => r.id === 'AQAAAJ5dZqA=');

  it('disables an inbox rule, confirms by read-back and re-enables on rollback', async () => {
    const { tb, rule } = await withItems();
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      params: { itemId: rule.publicId },
    });
    expect(result.status).toBe('confirmed');
    expect(graphRule(tb)?.isEnabled).toBe(false);
    expect(
      (
        await execute(tb, 'remove_forwarding_rule', {
          id: actionPublicId,
          params: { itemId: rule.publicId },
        })
      ).result.status,
    ).toBe('confirmed');
    expect(effectiveWrites(tb)).toHaveLength(1);
    expect(await rollback(tb, 'remove_forwarding_rule', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(graphRule(tb)?.isEnabled).toBe(true);
  });

  it('deletes in delete mode (absence read back in the same call) with no rollback', async () => {
    const { tb, rule } = await withItems({
      settings: (s) => ({ ...s, forwardingRemoval: { mode: 'delete' } }),
    });
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      params: { itemId: rule.publicId },
    });
    expect(result.status).toBe('confirmed');
    expect(graphRule(tb)).toBeUndefined();
    expect(await rollback(tb, 'remove_forwarding_rule', actionPublicId)).toEqual({
      status: 'unsupported',
    });
  });

  it('answers already_in_state for a rule that is already disabled', async () => {
    const { tb, rule } = await withItems();
    const live = graphRule(tb);
    if (live) live.isEnabled = false;
    const { actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      params: { itemId: rule.publicId },
    });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('already_in_state');
    expect(tb.sims.script.writes()).toHaveLength(0);
  });

  it('is unsupported for mailbox-level forwarding (requires_exchange_admin, PQ3)', async () => {
    const { tb, forwarding } = await withItems();
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      params: { itemId: forwarding.publicId },
    });
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('requires_exchange_admin');
    expect(tb.sims.script.writes()).toHaveLength(0);
  });

  it('acts on all external items and fails partial when one cannot be removed', async () => {
    const { tb } = await withItems();
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      params: { scope: 'all_external' },
    });
    expect(result).toEqual({ status: 'failed', code: 'partial', retryable: false });
    const state = tb.actionState.peek(actionPublicId);
    expect(state?.resultCode).toBe('partial');
    expect(state?.items?.map((i) => [i.outcome, i.code])).toEqual(
      expect.arrayContaining([
        ['confirmed', undefined],
        ['unsupported', 'requires_exchange_admin'],
      ]),
    );
    expect(graphRule(tb)?.isEnabled).toBe(false);
  });

  it('refuses an item of another identity and malformed parameters', async () => {
    const { tb, rule } = await withItems();
    expect(
      (
        await execute(tb, 'remove_forwarding_rule', {
          user: 'blake',
          params: { itemId: rule.publicId },
        })
      ).result,
    ).toEqual({
      status: 'failed',
      code: 'item_not_found',
      retryable: false,
    });
    expect((await execute(tb, 'remove_forwarding_rule', { params: {} })).result).toMatchObject({
      code: 'invalid_request',
    });
  });

  it('goes pending → confirmed when the rule read-back lags', async () => {
    const { tb, rule } = await withItems();
    tb.sims.script.delayReadBack(1);
    const { result, actionPublicId } = await execute(tb, 'remove_forwarding_rule', {
      params: { itemId: rule.publicId },
    });
    expect(result).toMatchObject({ status: 'pending', pollAfterMs: 10_000 });
    expect(await confirm(tb, 'remove_forwarding_rule', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
  });
});

describe('revoke_oauth_grant', () => {
  it("deletes the user's grants of the application and confirms by re-list", async () => {
    const tb = await bed();
    const app = appIdHash(MS_SERVICE_PRINCIPALS.unverified);
    const { result } = await execute(tb, 'revoke_oauth_grant', { params: { appIdHash: app } });
    expect(result.status).toBe('confirmed');
    expect(tb.directory.oauth2PermissionGrants.map((g) => g.id)).toEqual(['grant-alex-verified']);
  });

  it('answers already_in_state when no grant matches and refuses malformed hashes', async () => {
    const tb = await bed();
    const { actionPublicId } = await execute(tb, 'revoke_oauth_grant', {
      params: { appIdHash: 'f'.repeat(64) },
    });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('already_in_state');
    expect(tb.sims.script.writes()).toHaveLength(0);
    expect(
      (await execute(tb, 'revoke_oauth_grant', { params: { appIdHash: 'nope' } })).result,
    ).toMatchObject({ code: 'invalid_request' });
  });

  it('goes pending → confirmed while the grant list lags', async () => {
    const tb = await bed();
    tb.sims.script.delayReadBack(1);
    const { result, actionPublicId } = await execute(tb, 'revoke_oauth_grant', {
      params: { appIdHash: appIdHash(MS_SERVICE_PRINCIPALS.unverified) },
    });
    expect(result.status).toBe('pending');
    expect(await confirm(tb, 'revoke_oauth_grant', actionPublicId)).toMatchObject({
      status: 'confirmed',
    });
    expect(effectiveWrites(tb)).toHaveLength(1);
  });
});

describe('gates and references', () => {
  it('answers unsupported for an action disabled in the binding settings, without any call', async () => {
    const tb = await bed({
      settings: (s) => ({ ...s, actions: { ...s.actions, suspend_account: { enabled: false } } }),
    });
    const { result, actionPublicId } = await execute(tb, 'suspend_account');
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('action_disabled');
    expect(tb.sims.script.calls()).toHaveLength(0);
    // Re-executing keeps the answer (no flip once recorded).
    expect((await execute(tb, 'suspend_account', { id: actionPublicId })).result).toEqual({
      status: 'unsupported',
    });
  });

  it('answers unsupported when the response grant is missing (capability_unavailable)', async () => {
    const grants = (await import('../testing/harness'))
      .defaultMicrosoftGrants()
      .filter((g) => g.profile !== 'm365.ato_response');
    const tb = await bed({ grants });
    const { result, actionPublicId } = await execute(tb, 'revoke_sessions');
    expect(result).toEqual({ status: 'unsupported' });
    expect(tb.actionState.peek(actionPublicId)?.resultCode).toBe('capability_unavailable');
  });

  it('re-probes a stale report before the first action', async () => {
    const tb = await bed({}, false);
    const { result } = await execute(tb, 'revoke_sessions');
    expect(result.status).toBe('confirmed');
    expect(tb.sims.script.calls({ path: '/v1.0/auditLogs/signIns' })).toHaveLength(1);
  });

  it('fails unknown_reference for foreign or unknown references and invalid ids', async () => {
    const tb = await bed();
    expect(
      await tb.adapter.confirm(
        { type: 'suspend_account', providerReference: 'gws:suspend_account:x' },
        signal(),
      ),
    ).toEqual({
      status: 'failed',
      code: 'unknown_reference',
      retryable: false,
    });
    expect(await confirm(tb, 'suspend_account', randomUUID())).toMatchObject({
      code: 'unknown_reference',
    });
    expect(
      (await execute(tb, 'revoke_sessions', { id: 'bad id with spaces' })).result,
    ).toMatchObject({ code: 'invalid_request' });
  });

  it('keeps the provider state small and free of addresses', async () => {
    const tb = await bed();
    const { actionPublicId } = await execute(tb, 'require_mfa');
    const state = JSON.stringify(tb.actionState.peek(actionPublicId));
    expect(state.length).toBeLessThan(2048);
    expect(state).not.toContain('@');
  });
});
