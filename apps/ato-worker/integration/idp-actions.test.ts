import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AtoResponseAction } from '@email-gateway/database';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import { appIdHash } from '@email-gateway/idp-adapters';
import {
  googleCustomer,
  GS_DOMAIN,
  GS_USERS,
  microsoftDirectory,
  MS_DOMAIN,
  MS_MFA_GROUP_ID,
  MS_SERVICE_PRINCIPALS,
  MS_USERS,
} from '@email-gateway/idp-adapters/testing';
import { Fixtures } from './support/fixtures';
import { Clock } from './support/harness';
import { approvedAction, IdpWorld, MIN, msDirectoryAs } from './support/idp';
import { accountOf, configure } from './support/scenario';

/**
 * Step 8.5 §11.3 provider actions through `ato.responses` (respond role) and the maintenance
 * confirmations, on the in-process simulators: every action type on Microsoft and Google with
 * approval by a second user, read-back confirmation, confirmation timeout, already-in-state and
 * its no-op rollback, rollback with pre-state, the unsupported and refused paths (gateway user, no
 * integration, ambiguous integrations, Microsoft mailbox forwarding, disabled capability,
 * linked-domain guard) and idempotent redelivery (one write in the simulator log).
 */
const fx = new Fixtures();
const clock = new Clock(new Date(Math.floor(Date.now() / MIN) * MIN));
const w = new IdpWorld(fx, clock);
let org: { id: bigint; domain: string; domainId: bigint };
let msIntegration: bigint;
let gsIntegration: bigint;

const SECOND_TENANT = '33333333-4444-4555-8666-777777777777';

beforeAll(async () => {
  const now = clock.now();
  await w.start({
    microsoft: [microsoftDirectory(now), msDirectoryAs(now, SECOND_TENANT, MS_DOMAIN)],
    google: [googleCustomer(now)],
  });
  org = await fx.organization('idpact');
  await configure(w.h, org.id);
  const ms = await w.bind(w.connect(org.id, 'microsoft_entra'), {
    settings: (s) => ({
      ...s,
      actions: { ...s.actions, require_password_reset: { enabled: true } },
    }),
  });
  const gs = await w.bind(w.connect(org.id, 'google_workspace'), {
    settings: (s) => ({
      ...s,
      actions: { ...s.actions, require_password_reset: { enabled: false } },
    }),
  });
  msIntegration = ms.id;
  gsIntegration = gs.id;
  await w.probe();
  await w.poll();
});

afterAll(async () => {
  await w.stop();
  await fx.cleanup();
});

/** The `ato.response.requested.v1` envelope of an action from its outbox row. */
async function requested(actionId: bigint): Promise<EventEnvelope> {
  const rows = await fx.prisma.messageOutbox.findMany({
    where: {
      organizationId: org.id,
      eventType: EventTypes.AtoResponseRequested,
      aggregateId: actionId.toString(),
    },
    orderBy: { id: 'desc' },
    take: 1,
  });
  return fx.envelope(EventTypes.AtoResponseRequested, org.id, rows[0]!.payload, clock.now());
}

async function mailbox(address: string) {
  const existing = await accountOf(fx, org.id, 'mailbox', address);
  if (existing) return existing;
  return w.h.comps.db.transaction((tx) =>
    w.h.comps.store.ensureAccount(tx, {
      organizationId: org.id,
      subject: { kind: 'mailbox', address },
      at: clock.now(),
    }),
  );
}

async function run(
  address: string,
  type: Parameters<typeof approvedAction>[3],
  params: Record<string, string | number | boolean> = {},
  // As the api sets it (`providerKind`: the first active integration's provider, §6).
  providerKind: string = address.endsWith(`@${GS_DOMAIN}`) ? 'google_workspace' : 'microsoft_entra',
): Promise<AtoResponseAction> {
  const account = await mailbox(address);
  const action = await approvedAction(w, org, account.id, type, params, providerKind);
  await w.h.comps.respond.handle(await requested(action.id));
  return fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } });
}

async function confirmUntilSettled(actionId: bigint, maxPolls = 12): Promise<AtoResponseAction> {
  for (let i = 0; i < maxPolls; i++) {
    const row = await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: actionId } });
    if (row.status !== 'executing' && row.status !== 'rollback_requested') return row;
    clock.advance(Math.max(1000, (row.nextCheckAt?.getTime() ?? 0) - clock.now().getTime() + 1));
    await w.h.comps.maintenance.providerConfirmations();
  }
  return fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: actionId } });
}

describe('Microsoft Entra ID actions (§3.3)', () => {
  it('revoke_sessions: confirmed synchronously, provider reference, one write on redelivery', async () => {
    w.sims.script.clearCalls();
    const action = await run(`alex@${MS_DOMAIN}`, 'revoke_sessions');
    expect(action).toMatchObject({
      status: 'succeeded',
      providerStatus: 'confirmed',
      integrationId: msIntegration,
    });
    expect(action.providerReference).toBe(`msgraph:revoke_sessions:${action.publicId}`);
    const writes = () =>
      w.sims.script.calls({ method: 'POST', path: /revokeSignInSessions$/ }).length;
    expect(writes()).toBe(1);
    const event = await requested(action.id);
    await expect(
      w.h.comps.respond.handle({ ...event, eventId: fx.track(crypto.randomUUID()) }),
    ).resolves.toBe('duplicate');
    expect(writes()).toBe(1);
  });

  it('suspend_account: read-back confirmation, then rollback restores the pre-state', async () => {
    const action = await run(`blake@${MS_DOMAIN}`, 'suspend_account');
    const settled = await confirmUntilSettled(action.id);
    expect(settled).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
    const dir = w.sims.script.dataset.microsoft!.directories[0]!;
    expect(dir.users.find((u) => u.id === MS_USERS.blake)!.accountEnabled).toBe(false);
    const approver = await fx.user(org.id, `rb-${crypto.randomUUID().slice(0, 6)}`, org.domain);
    await w.h.comps.db.transaction((tx) =>
      w.h.comps.store.requestRollback(tx, {
        organizationId: org.id,
        actionId: action.id,
        actor: { type: 'user', id: approver.publicId, userId: approver.id },
        reason: 'false positive',
      }),
    );
    await w.h.comps.respond.handle(await requested(action.id));
    const rolled = await confirmUntilSettled(action.id);
    expect(rolled.status).toBe('rolled_back');
    expect(dir.users.find((u) => u.id === MS_USERS.blake)!.accountEnabled).toBe(true);
  });

  it('require_password_reset of a synced user fails on_premises_managed (never claimed)', async () => {
    const action = await run(`drew@${MS_DOMAIN}`, 'require_password_reset');
    expect(action).toMatchObject({ status: 'failed', resultCode: 'on_premises_managed' });
  });

  it('require_mfa adds the user to the tenant-designated group (confirmed by read-back)', async () => {
    const action = await confirmUntilSettled((await run(`alex@${MS_DOMAIN}`, 'require_mfa')).id);
    expect(action).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
    const group = w.sims.script.dataset.microsoft!.directories[0]!.groups.find(
      (g) => g.id === MS_MFA_GROUP_ID,
    )!;
    expect(group.members).toContain(MS_USERS.alex);
  });

  it('remove_forwarding_rule: inbox rule disabled; mailbox-level forwarding is unsupported', async () => {
    const alex = await accountOf(fx, org.id, 'mailbox', `alex@${MS_DOMAIN}`);
    const items = await fx.prisma.atoProviderMailboxItem.findMany({
      where: { integrationId: msIntegration, accountId: alex!.id, state: 'present' },
    });
    const rule = items.find((i) => i.itemKind === 'inbox_rule' && i.providerItemRef !== null);
    const forwarding = items.find((i) => i.itemKind === 'forwarding');
    expect(rule).toBeDefined();
    expect(forwarding).toBeDefined();
    const disabled = await confirmUntilSettled(
      (await run(`alex@${MS_DOMAIN}`, 'remove_forwarding_rule', { itemId: rule!.publicId })).id,
    );
    expect(disabled).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
    const rules = w.sims.script.dataset.microsoft!.directories[0]!.messageRules[MS_USERS.alex]!;
    expect(rules.find((r) => r.id === rule!.providerItemRef)?.isEnabled).toBe(false);
    const unsupported = await run(`alex@${MS_DOMAIN}`, 'remove_forwarding_rule', {
      itemId: forwarding!.publicId,
    });
    expect(unsupported).toMatchObject({
      status: 'unsupported',
      resultCode: 'requires_exchange_admin',
    });
  });

  it('revoke_oauth_grant removes the grants of the application (re-list confirms absence)', async () => {
    const action = await run(`alex@${MS_DOMAIN}`, 'revoke_oauth_grant', {
      appIdHash: appIdHash(MS_SERVICE_PRINCIPALS.unverified),
    });
    expect(action).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
    const grants = w.sims.script.dataset.microsoft!.directories[0]!.oauth2PermissionGrants;
    expect(grants.some((g) => g.clientId === MS_SERVICE_PRINCIPALS.unverified)).toBe(false);
    expect(grants.some((g) => g.clientId === MS_SERVICE_PRINCIPALS.verified)).toBe(true);
  });
});

describe('Google Workspace actions (§3.3)', () => {
  it('suspend_account of an already suspended user: already_in_state, rollback is a no-op', async () => {
    const action = await confirmUntilSettled(
      (await run(`casey@${GS_DOMAIN}`, 'suspend_account')).id,
    );
    expect(action).toMatchObject({
      status: 'succeeded',
      providerStatus: 'confirmed',
      resultCode: 'already_in_state',
      integrationId: gsIntegration,
    });
    expect(action.providerReference).toBe(`gws:suspend_account:${action.publicId}`);
    const approver = await fx.user(org.id, `rb-${crypto.randomUUID().slice(0, 6)}`, org.domain);
    await w.h.comps.db.transaction((tx) =>
      w.h.comps.store.requestRollback(tx, {
        organizationId: org.id,
        actionId: action.id,
        actor: { type: 'user', id: approver.publicId, userId: approver.id },
        reason: 'review',
      }),
    );
    await w.h.comps.respond.handle(await requested(action.id));
    const rolled = await confirmUntilSettled(action.id);
    expect(rolled).toMatchObject({
      status: 'rolled_back',
      resultCode: 'restored_previous_state_noop',
    });
    const casey = w.sims.script.dataset.google!.customers[0]!.users.find(
      (u) => u.id === GS_USERS.casey,
    );
    expect(casey?.suspended).toBe(true);
  });

  it('remove_forwarding_rule deletes the external forwarding filter', async () => {
    const alex = await accountOf(fx, org.id, 'mailbox', `alex@${GS_DOMAIN}`);
    const filter = (
      await fx.prisma.atoProviderMailboxItem.findMany({
        where: { integrationId: gsIntegration, accountId: alex!.id, itemKind: 'inbox_rule' },
      })
    ).find((i) => i.targetDomain !== null);
    expect(filter).toBeDefined();
    const action = await confirmUntilSettled(
      (await run(`alex@${GS_DOMAIN}`, 'remove_forwarding_rule', { itemId: filter!.publicId })).id,
    );
    expect(action).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
    const filters = w.sims.script.dataset.google!.customers[0]!.gmail[GS_USERS.alex]!.filters;
    expect(filters.some((f) => f.id === filter!.providerItemRef)).toBe(false);
  });

  it('a confirmation that never converges ends failed, unconfirmed, after the timeout', async () => {
    w.sims.script.delayReadBack(1000);
    const action = await run(`alex@${GS_DOMAIN}`, 'require_mfa');
    expect(action.status).toBe('executing');
    expect(action.providerStatus).toBe('pending');
    clock.advance(31 * MIN);
    await w.h.comps.maintenance.providerConfirmations();
    const timedOut = await fx.prisma.atoResponseAction.findUniqueOrThrow({
      where: { id: action.id },
    });
    expect(timedOut).toMatchObject({
      status: 'failed',
      providerStatus: 'unconfirmed',
      resultCode: 'confirmation_timeout',
    });
    expect(
      await w.h.metric('ato_idp_actions_total', { action: 'require_mfa', outcome: 'timeout' }),
    ).toBe(1);
    w.sims.script.delayReadBack(0);
  });

  it('an action disabled in the binding settings is unsupported (no provider call)', async () => {
    w.sims.script.clearCalls();
    const action = await run(`blake@${GS_DOMAIN}`, 'require_password_reset');
    expect(action.status).toBe('unsupported');
    expect(w.sims.script.writes()).toHaveLength(0);
  });
});

describe('selection, guard and unsupported paths (D9.2, inv. 4)', () => {
  it('a gateway user receives no provider action (not_a_mailbox_account)', async () => {
    const user = await fx.user(org.id, `gw-${crypto.randomUUID().slice(0, 6)}`, org.domain);
    const account = await w.h.comps.db.transaction((tx) =>
      w.h.comps.store.ensureAccount(tx, {
        organizationId: org.id,
        subject: { kind: 'gateway_user', userId: user.id, address: user.email },
        at: clock.now(),
      }),
    );
    const action = await approvedAction(
      w,
      org,
      account.id,
      'revoke_sessions',
      {},
      'microsoft_entra',
    );
    await w.h.comps.respond.handle(await requested(action.id));
    expect(
      await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } }),
    ).toMatchObject({ status: 'unsupported', resultCode: 'not_a_mailbox_account' });
  });

  it('a mailbox of a domain no integration covers: unsupported no_integration', async () => {
    const action = await run(`someone@${org.domain}`, 'revoke_sessions');
    expect(action).toMatchObject({ status: 'unsupported', resultCode: 'no_integration' });
  });

  it('linked-domain guard: an identity mapped to an integration outside its domains is refused', async () => {
    const outsider = await mailbox(`mallory@${org.domain}`);
    await fx.prisma.atoAccountIdentity.create({
      data: {
        organizationId: org.id,
        accountId: outsider.id,
        provider: 'microsoft_entra',
        externalId: 'aaaaaaaa-0000-4000-8000-0000000000ee',
        externalIdHash: 'e'.repeat(64),
        firstSeenAt: clock.now(),
        lastSeenAt: clock.now(),
        integrationId: msIntegration,
      },
    });
    w.sims.script.clearCalls();
    const action = await run(`mallory@${org.domain}`, 'suspend_account');
    expect(action).toMatchObject({ status: 'failed', resultCode: 'domain_not_linked' });
    expect(w.sims.script.writes()).toHaveLength(0);
  });

  it('two integrations covering the domain: failed ambiguous_integration, never retried', async () => {
    const second = await w.bind(
      w.connect(org.id, 'microsoft_entra', { tenantId: SECOND_TENANT, domain: MS_DOMAIN }),
    );
    await w.healthDue(second.id);
    await w.probe();
    w.sims.script.clearCalls();
    const action = await run(`newcomer@${MS_DOMAIN}`, 'revoke_sessions');
    expect(action).toMatchObject({ status: 'failed', resultCode: 'ambiguous_integration' });
    expect(w.sims.script.writes()).toHaveLength(0);
    await fx.prisma.atoProviderIntegration.update({
      where: { id: second.id },
      data: { status: 'disabled', disabledAt: clock.now(), disabledReason: 'test' },
    });
  });
});
