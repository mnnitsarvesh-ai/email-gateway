import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  atoMailboxSha256,
  sha256Hex,
  type ProviderEvent,
  type ResponseActionType,
} from '@email-gateway/ato-detection';
import { FakeIdentityProviderAdapter } from '@email-gateway/ato-detection/fake-provider';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import type { IncidentActor } from '@email-gateway/security-incidents';
import { ProviderRetryError } from '../src/respond/respond.consumer';
import { Fixtures, ips } from './support/fixtures';
import { Clock, harness, testConfig, type Harness } from './support/harness';
import { accountOf, codes, configure, deliver, deliverMail } from './support/scenario';

/**
 * Step 8.4 §10.3 response scenarios on a 2021 clock (the platform-wide expiry sweeps can only
 * match this suite's rows): (14) SMTP restriction by automation and by approval, rollback and
 * expiry; (13) session revocation and MFA through the fake adapter (confirmed, pending → confirmed,
 * retryable and final failures, unsupported); (9) forwarding rules and (10) OAuth consents through
 * the provider runner; (15) identity-provider failures (auth error, throttling, backoff, `error`).
 * No real identity provider is ever called.
 */
const fx = new Fixtures();
const MIN = 60_000;
const clock = new Clock(new Date('2021-04-01T09:00:00.000Z'));
const fake = new FakeIdentityProviderAdapter({ pollsUntilConfirmed: 2 });
let h: Harness;

beforeAll(async () => {
  h = await harness(fx, {
    clock,
    fakeAdapter: fake,
    config: testConfig({ ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES: '2' }),
  });
});

afterAll(async () => {
  await h?.close();
  await fx.cleanup();
});

const userActor = (u: { id: bigint; publicId: string }): IncidentActor => ({
  type: 'user',
  id: u.publicId,
  userId: u.id,
});

/** A compromised mailbox: a listed-IP login on its portal account (T1), then phishing sent (P1, X1). */
async function compromise(org: { id: bigint; domain: string; domainId: bigint }, label: string) {
  const user = await fx.user(org.id, label, org.domain);
  const ip = ips.saoPaulo();
  await fx.indicator('ip', ip, 'critical');
  clock.advance(MIN);
  await deliver(
    h,
    await fx.login({
      organizationId: org.id,
      userId: user.id,
      email: user.email,
      outcome: 'success',
      ip,
      at: clock.now(),
    }),
  );
  clock.advance(MIN);
  const [m] = await fx.messages(org.id, [
    {
      sender: user.email,
      receivedAt: clock.now(),
      recipients: ['victim@target.example'],
      verdict: 'malicious',
      reasonCodes: ['url.phishing_high_confidence'],
      domainId: org.domainId,
    },
  ]);
  await deliverMail(h, fx.scanned(m!));
  const mailbox = await accountOf(fx, org.id, 'mailbox', user.email);
  return {
    user,
    mailbox: await fx.prisma.atoAccount.findUniqueOrThrow({ where: { id: mailbox!.id } }),
  };
}

/** The `ato.response.requested.v1` envelope of an action from its outbox row. */
async function requested(orgId: bigint, actionId: bigint): Promise<EventEnvelope> {
  const rows = await fx.prisma.messageOutbox.findMany({
    where: {
      organizationId: orgId,
      eventType: EventTypes.AtoResponseRequested,
      aggregateId: actionId.toString(),
    },
    orderBy: { id: 'desc' },
    take: 1,
  });
  const row = rows[0]!;
  return fx.envelope(EventTypes.AtoResponseRequested, orgId, row.payload, clock.now());
}

async function providerIntegration(organizationId: bigint): Promise<bigint> {
  // The fake adapter serves one script to every integration: only the newest one is active.
  await fx.prisma.atoProviderIntegration.updateMany({
    where: { organizationId: { in: fx.organizationIds }, status: 'active' },
    data: { status: 'disabled' },
  });
  const row = await fx.prisma.atoProviderIntegration.create({
    data: {
      organizationId,
      provider: 'fake',
      bindingKey: sha256Hex('fake|-'),
      status: 'active',
      capabilities: {},
      cursors: {},
      nextPollAt: new Date(clock.now().getTime() - 1000),
    },
  });
  h.comps.providers.invalidate();
  return row.id;
}

describe('SMTP restrictions (scenario 14)', () => {
  it('automation in enforce mode applies a send_block (strong + two categories, level ≥ high)', async () => {
    const org = await fx.organization('auto');
    await configure(h, org.id, {
      mode: 'enforce',
      automation: {
        restrict_smtp_sending: { mode: 'automatic', minLevel: 'high', durationMinutes: 60 },
      },
    });
    const { mailbox } = await compromise(org, 'auto');
    expect(['high', 'critical']).toContain(mailbox.riskLevel);
    const actions = await fx.prisma.atoResponseAction.findMany({
      where: { organizationId: org.id, actionType: 'restrict_smtp_sending' },
    });
    expect(actions).toHaveLength(1);
    expect(actions[0]).toMatchObject({
      status: 'succeeded',
      providerStatus: 'applied',
      authorization: 'automation_policy',
      requestedByType: 'system',
    });
    const restriction = await fx.prisma.atoSmtpRestriction.findUniqueOrThrow({
      where: { id: actions[0]!.restrictionId! },
    });
    expect(restriction).toMatchObject({
      kind: 'send_block',
      scope: 'mailbox',
      status: 'active',
      mode: 'reject',
      mailboxSha256: atoMailboxSha256(mailbox.address!),
    });
    expect(
      await fx.prisma.messageOutbox.count({
        where: { organizationId: org.id, eventType: EventTypes.AtoRestrictionChanged },
      }),
    ).toBe(1);
    // Low-impact automatic defaults ran as well (alert the tenant administrators).
    const alert = await fx.prisma.atoResponseAction.findFirst({
      where: { organizationId: org.id, actionType: 'alert_tenant_admins' },
    });
    expect(alert).toMatchObject({
      status: 'succeeded',
      providerStatus: 'unconfirmed',
      resultCode: 'queued_for_delivery',
    });
  });

  it('monitor mode holds the action for approval (guard); approval applies, rollback lifts, expiry expires', async () => {
    const org = await fx.organization('approve');
    await configure(h, org.id, {
      mode: 'monitor',
      automation: {
        restrict_smtp_sending: { mode: 'automatic', minLevel: 'high', durationMinutes: 15 },
      },
    });
    const guardBefore = await h.metric('ato_automation_guard_total', {
      reason: 'tenant_monitor_mode',
    });
    const { mailbox } = await compromise(org, 'appr');
    expect(await h.metric('ato_automation_guard_total', { reason: 'tenant_monitor_mode' })).toBe(
      guardBefore + 1,
    );
    const pending = await fx.prisma.atoResponseAction.findFirstOrThrow({
      where: { organizationId: org.id, actionType: 'restrict_smtp_sending' },
    });
    expect(pending.status).toBe('pending_approval');
    expect(pending.requestReason).toContain('tenant_monitor_mode');
    const analyst1 = await fx.user(org.id, 'analyst1', org.domain);
    const analyst2 = await fx.user(org.id, 'analyst2', org.domain);
    const approved = await h.comps.db.transaction((tx) =>
      h.comps.store.decideResponse(tx, {
        organizationId: org.id,
        actionId: pending.id,
        decision: 'approve',
        actor: userActor(analyst1),
        reason: 'confirmed by phone',
      }),
    );
    expect(approved).toMatchObject({ status: 'succeeded', providerStatus: 'applied' });
    const rolled = await h.comps.db.transaction((tx) =>
      h.comps.store.requestRollback(tx, {
        organizationId: org.id,
        actionId: pending.id,
        actor: userActor(analyst2),
        reason: 'user re-secured',
      }),
    );
    expect(rolled.status).toBe('rolled_back');
    expect(
      (
        await fx.prisma.atoSmtpRestriction.findUniqueOrThrow({
          where: { id: approved.restrictionId! },
        })
      ).status,
    ).toBe('lifted');
    // A manual request by one analyst, approved by the other (four eyes), then expiry.
    const manual = await h.comps.db.transaction((tx) =>
      h.comps.store.requestResponse(tx, {
        organizationId: org.id,
        accountId: mailbox.id,
        incidentId: mailbox.activeIncidentId,
        actionType: 'restrict_smtp_sending',
        target: {
          scope: 'mailbox',
          accountPublicId: mailbox.publicId,
          mailboxSha256: atoMailboxSha256(mailbox.address!),
        },
        params: { durationMinutes: 15 },
        actor: userActor(analyst1),
        reason: 'again',
        authorization: 'manual',
      }),
    );
    const applied = await h.comps.db.transaction((tx) =>
      h.comps.store.decideResponse(tx, {
        organizationId: org.id,
        actionId: manual.id,
        decision: 'approve',
        actor: userActor(analyst2),
      }),
    );
    expect(applied.status).toBe('succeeded');
    clock.advance(16 * MIN);
    await h.comps.maintenance.expiry();
    const expired = await fx.prisma.atoSmtpRestriction.findUniqueOrThrow({
      where: { id: applied.restrictionId! },
    });
    expect(expired.status).toBe('expired');
    const changes = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: EventTypes.AtoRestrictionChanged },
      orderBy: { id: 'asc' },
    });
    expect(changes.map((c) => (c.payload as { status: string }).status)).toEqual([
      'active',
      'lifted',
      'active',
      'expired',
    ]);
  });

  it('approvals expire after ATO_APPROVAL_TTL_HOURS (maintenance)', async () => {
    const org = await fx.organization('ttl');
    await configure(h, org.id, {
      automation: { restrict_smtp_sending: { mode: 'automatic', minLevel: 'high' } },
    });
    await compromise(org, 'ttl');
    const pending = await fx.prisma.atoResponseAction.findFirstOrThrow({
      where: { organizationId: org.id, status: 'pending_approval' },
    });
    clock.advance(25 * 3_600_000);
    await h.comps.maintenance.expiry();
    expect(
      (await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: pending.id } })).status,
    ).toBe('expired');
  });
});

describe('provider actions through the fake adapter (scenario 13)', () => {
  async function providerAction(
    org: { id: bigint; domain: string; domainId: bigint },
    label: string,
    type: ResponseActionType,
  ) {
    const { mailbox } = await compromise(org, label);
    fake.addIdentity(mailbox.address!, {
      provider: 'fake',
      externalId: `ext-${label}-${fx.suffix}`,
      primaryEmail: mailbox.address!,
    });
    const a1 = await fx.user(org.id, `${label}-a1`, org.domain);
    const a2 = await fx.user(org.id, `${label}-a2`, org.domain);
    const action = await h.comps.db.transaction((tx) =>
      h.comps.store.requestResponse(tx, {
        organizationId: org.id,
        accountId: mailbox.id,
        incidentId: mailbox.activeIncidentId,
        actionType: type,
        target: { scope: 'account', accountPublicId: mailbox.publicId },
        actor: userActor(a1),
        reason: 'contain',
        authorization: 'manual',
        providerKind: 'fake',
      }),
    );
    const approved = await h.comps.db.transaction((tx) =>
      h.comps.store.decideResponse(tx, {
        organizationId: org.id,
        actionId: action.id,
        decision: 'approve',
        actor: userActor(a2),
      }),
    );
    return { mailbox, action: approved };
  }

  it('revoke_sessions: confirmed synchronously → succeeded with a provider reference (idempotent)', async () => {
    const org = await fx.organization('revoke');
    await configure(h, org.id);
    await providerIntegration(org.id);
    const { action } = await providerAction(org, 'rv', 'revoke_sessions');
    expect(action.status).toBe('approved');
    const event = await requested(org.id, action.id);
    await expect(h.comps.respond.handle(event)).resolves.toBe('handled');
    const done = await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } });
    expect(done).toMatchObject({
      status: 'succeeded',
      providerStatus: 'confirmed',
      resultCode: 'provider_confirmed',
    });
    expect(done.providerReference).toMatch(/^fake-/);
    // Redelivery: no second provider effect, no state change.
    const effects = fake.effects.revoke_sessions;
    await expect(
      h.comps.respond.handle({ ...event, eventId: fx.track(crypto.randomUUID()) }),
    ).resolves.toBe('duplicate');
    expect(fake.effects.revoke_sessions).toBe(effects);
    const identity = await fx.prisma.atoAccountIdentity.findFirst({
      where: { organizationId: org.id },
    });
    expect(identity).toMatchObject({
      provider: 'fake',
      externalIdHash: sha256Hex(`ext-rv-${fx.suffix}`),
    });
  });

  it('require_mfa: pending → executing → confirmed by the maintenance poll', async () => {
    const org = await fx.organization('mfa');
    await configure(h, org.id);
    await providerIntegration(org.id);
    const { action } = await providerAction(org, 'mf', 'require_mfa');
    await h.comps.respond.handle(await requested(org.id, action.id));
    const executing = await fx.prisma.atoResponseAction.findUniqueOrThrow({
      where: { id: action.id },
    });
    expect(executing).toMatchObject({ status: 'executing', providerStatus: 'pending' });
    clock.advance(2000);
    await h.comps.maintenance.providerConfirmations(); // first poll: still pending (2 polls needed)
    clock.advance(2000);
    await h.comps.maintenance.providerConfirmations();
    const final = await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } });
    expect(final).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
  });

  it('a retryable failure is retried by the queue, a final failure is failed (never claimed)', async () => {
    const org = await fx.organization('fail');
    await configure(h, org.id);
    await providerIntegration(org.id);
    const { action } = await providerAction(org, 'fl', 'revoke_sessions');
    fake.failNext('execute', { code: 'provider_unavailable', retryable: true });
    const event = await requested(org.id, action.id);
    await expect(h.comps.respond.handle(event)).rejects.toBeInstanceOf(ProviderRetryError);
    const retried = await fx.prisma.atoResponseAction.findUniqueOrThrow({
      where: { id: action.id },
    });
    expect(retried).toMatchObject({ status: 'approved', attempts: 1 });
    fake.failNext('execute', { code: 'identity_disabled', retryable: false });
    await h.comps.respond.handle(event);
    const failed = await fx.prisma.atoResponseAction.findUniqueOrThrow({
      where: { id: action.id },
    });
    expect(failed).toMatchObject({
      status: 'failed',
      providerStatus: 'failed',
      resultCode: 'identity_disabled',
    });
    expect(failed.providerReference).toBeNull();
    const logs = await fx.prisma.atoResponseActionLog.findMany({
      where: { actionId: action.id },
      orderBy: { id: 'asc' },
    });
    expect(logs.map((l) => l.outcome)).toEqual(
      expect.arrayContaining(['retry_scheduled', 'failed']),
    );
    const notification = await fx.prisma.messageOutbox.findFirst({
      where: { organizationId: org.id, eventType: EventTypes.AtoNotificationRequested },
      orderBy: { id: 'desc' },
    });
    expect((notification!.payload as { kind: string }).kind).toBe('response_failed');
  });

  it('an action left approved past the queue retry horizon is failed by the expiry job', async () => {
    const org = await fx.organization('stale');
    await configure(h, org.id);
    await providerIntegration(org.id);
    const { action } = await providerAction(org, 'st', 'revoke_sessions');
    expect(action.status).toBe('approved');
    // Its message was dead-lettered without the consumer's last attempt (e.g. a database error on
    // every delivery): nothing touched the action since. Only rows older than 25 h are swept.
    await h.comps.maintenance.expiry();
    expect(
      (await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } })).status,
    ).toBe('approved');
    await fx.prisma.$executeRaw`
      UPDATE ato_response_actions SET updated_at = ${new Date(clock.now().getTime() - 26 * 3_600_000)}
      WHERE id = ${action.id} AND organization_id = ${org.id}`;
    await h.comps.maintenance.expiry();
    const failed = await fx.prisma.atoResponseAction.findUniqueOrThrow({
      where: { id: action.id },
    });
    expect(failed).toMatchObject({
      status: 'failed',
      providerStatus: 'failed',
      resultCode: 'provider_retry_exhausted',
      activeMarker: null,
    });
    // A late redelivery of the original request is a duplicate, never a provider call.
    const effects = fake.effects.revoke_sessions;
    await expect(h.comps.respond.handle(await requested(org.id, action.id))).resolves.toBe(
      'duplicate',
    );
    expect(fake.effects.revoke_sessions).toBe(effects);
  });

  it('unsupported: an action the adapter does not support, and no integration at all', async () => {
    const org = await fx.organization('unsup');
    await configure(h, org.id);
    const integration = await providerIntegration(org.id);
    const { action } = await providerAction(org, 'us', 'require_password_reset');
    await h.comps.respond.handle(await requested(org.id, action.id));
    expect(
      (await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } })).status,
    ).toBe('unsupported');
    await fx.prisma.atoProviderIntegration.update({
      where: { id: integration },
      data: { status: 'disabled' },
    });
    const second = await providerAction(org, 'us2', 'revoke_sessions');
    await h.comps.respond.handle(await requested(org.id, second.action.id));
    expect(
      (await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: second.action.id } }))
        .status,
    ).toBe('unsupported');
  });
});

describe('provider ingestion runner (scenarios 9, 10, 15)', () => {
  const ev = (
    over: Partial<ProviderEvent> & Pick<ProviderEvent, 'stream'>,
    address: string,
  ): ProviderEvent => ({
    provider: 'fake',
    // Short ids: a 40+ character token-like run is refused as secret-shaped by the schema.
    eventId: `evt-${crypto.randomUUID().slice(0, 8)}`,
    occurredAt: clock.now().toISOString(),
    identity: {
      provider: 'fake',
      externalId: `ext-${address.split('@')[0]}`,
      primaryEmail: address,
    },
    ...over,
  });

  it('forwarding to a new external domain (M1), risky OAuth consent (Q1), X5 after a listed sign-in', async () => {
    const org = await fx.organization('runner');
    await configure(h, org.id);
    const integration = await providerIntegration(org.id);
    const address = `exec-${fx.suffix}@${org.domain}`;
    const ip = ips.london();
    await fx.indicator('ip', ip, 'high');
    fake
      .script('sign_ins', [ev({ stream: 'sign_ins', outcome: 'success', ip }, address)])
      .script('forwarding_changes', [
        ev(
          {
            stream: 'forwarding_changes',
            mailbox: { change: 'forwarding_added', targetDomain: 'exfil.example' },
          },
          address,
        ),
      ])
      .script('oauth_consents', [
        ev(
          {
            stream: 'oauth_consents',
            oauth: {
              appIdHash: 'a'.repeat(64),
              scopes: ['mail_read', 'offline_access'],
              consentType: 'user',
              publisherVerified: false,
            },
          },
          address,
        ),
      ]);
    clock.advance(1000);
    await h.comps.runner.runOnce();
    const account = await accountOf(fx, org.id, 'mailbox', address);
    const c = await codes(fx, org.id, account!.id);
    expect(c).toEqual(
      expect.arrayContaining([
        'ato.ti.malicious_ip_success',
        'ato.mailbox.external_forwarding',
        'ato.oauth.risky_consent',
        'ato.correlation.config_change_after_login',
      ]),
    );
    const q1 = await fx.prisma.atoRiskSignal.findFirst({
      where: { organizationId: org.id, ruleCode: 'ato.oauth.risky_consent' },
    });
    expect(q1!.strength).toBe('strong');
    const row = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
      where: { id: integration },
    });
    expect(row.cursors).toMatchObject({
      sign_ins: '1',
      forwarding_changes: '1',
      oauth_consents: '1',
    });
    expect(row.consecutiveFailures).toBe(0);
    const signIn = await fx.prisma.atoAuthEvent.findFirst({
      where: { organizationId: org.id, source: 'idp_sign_in' },
    });
    expect(signIn).toMatchObject({ channel: 'idp', outcome: 'success', countryCode: 'GB' });
    // A second pass sees no new events and processes nothing twice.
    const before = await fx.prisma.atoRiskSignal.count({ where: { organizationId: org.id } });
    await fx.prisma.atoProviderIntegration.update({
      where: { id: integration },
      data: { nextPollAt: new Date(clock.now().getTime() - 1) },
    });
    await h.comps.runner.runOnce();
    expect(await fx.prisma.atoRiskSignal.count({ where: { organizationId: org.id } })).toBe(before);
  });

  it('provider failures: auth error backs off, throttling honours retryAfter, then status error', async () => {
    const org = await fx.organization('idpfail');
    await configure(h, org.id);
    const integration = await providerIntegration(org.id);
    fake.throttleNext('sign_ins', 120_000);
    clock.advance(1000);
    await h.comps.runner.runOnce();
    let row = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
      where: { id: integration },
    });
    expect(row.nextPollAt.getTime()).toBeGreaterThanOrEqual(clock.now().getTime() + 119_000);
    expect(row.consecutiveFailures).toBe(0);
    const failuresBefore = await h.metric('ato_provider_operations_total', {
      operation: 'ingest',
      outcome: 'failed',
    });
    for (let i = 1; i <= 2; i++) {
      await fx.prisma.atoProviderIntegration.update({
        where: { id: integration },
        data: { nextPollAt: new Date(clock.now().getTime() - 1) },
      });
      fake.failNext('ingest', { code: 'auth_error', retryable: false });
      await h.comps.runner.runOnce();
      row = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
        where: { id: integration },
      });
      expect(row.consecutiveFailures).toBe(i);
      expect(row.lastErrorCode).toBe('auth_error');
      expect(row.nextPollAt.getTime()).toBeGreaterThan(clock.now().getTime() + 60_000);
    }
    expect(row.status).toBe('error');
    expect(
      await h.metric('ato_provider_operations_total', { operation: 'ingest', outcome: 'failed' }),
    ).toBe(failuresBefore + 2);
  });
});
