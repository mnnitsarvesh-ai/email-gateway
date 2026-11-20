import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EventTypes } from '@email-gateway/event-contracts';
import { microsoftDirectory, MS_DOMAIN, MS_TENANT_ID } from '@email-gateway/idp-adapters/testing';
import { Fixtures } from './support/fixtures';
import { Clock } from './support/harness';
import { approvedAction, IdpWorld, MIN, msDirectoryAs } from './support/idp';
import { configure } from './support/scenario';

/**
 * Step 8.5 §11.3 health probes and transitions (D6, D11): unhealthy ⇒ one `provider_unhealthy`
 * notification request per integration per 6 h in the transaction of the transition, recovery
 * without a notification; connection inactive ⇒ paused and resumed; connection removed ⇒ disabled
 * and in-flight provider actions failed `integration_disabled`; directory changed ⇒ paused; an
 * `error` integration recovers on a passing probe; a revoked permission ⇒ degraded and the action
 * capability gone; the D11 gauges.
 */
const fx = new Fixtures();
const clock = new Clock(new Date(Math.floor(Date.now() / MIN) * MIN));
const w = new IdpWorld(fx, clock);

const TENANTS = {
  a: '44444444-0000-4000-8000-00000000000a',
  b: '44444444-0000-4000-8000-00000000000b',
  c: '44444444-0000-4000-8000-00000000000c',
  d: '44444444-0000-4000-8000-00000000000d',
  e: '44444444-0000-4000-8000-00000000000e',
};
const domainOf = (k: keyof typeof TENANTS) => `health-${k}.example`;

beforeAll(async () => {
  const now = clock.now();
  await w.start({
    microsoft: [
      microsoftDirectory(now),
      ...Object.entries(TENANTS).map(([k, t]) =>
        msDirectoryAs(now, t, domainOf(k as keyof typeof TENANTS)),
      ),
    ],
  });
});

afterAll(async () => {
  await w.stop();
  await fx.cleanup();
});

async function setup(key: keyof typeof TENANTS) {
  const org = await fx.organization(`h${key}`);
  await configure(w.h, org.id);
  const connection = w.connect(org.id, 'microsoft_entra', {
    tenantId: TENANTS[key],
    domain: domainOf(key),
  });
  const integration = await w.bind(connection);
  await w.probe();
  return { org, connection, integration };
}

const row = (id: bigint) => fx.prisma.atoProviderIntegration.findUniqueOrThrow({ where: { id } });

async function notifications(orgId: bigint) {
  const rows = await fx.prisma.messageOutbox.findMany({
    where: { organizationId: orgId, eventType: EventTypes.AtoNotificationRequested },
  });
  return rows
    .map((r) => r.payload as { kind: string; refs: Record<string, string>; audience: string })
    .filter((p) => p.kind === 'provider_unhealthy');
}

describe('health transitions and the provider_unhealthy notification (D6, D11)', () => {
  it('unhealthy once ⇒ one notification; recovery silent; again within 6 h ⇒ counted only', async () => {
    const { org, connection, integration } = await setup('a');
    expect((await row(integration.id)).healthStatus).toBe('healthy');
    expect(await notifications(org.id)).toHaveLength(0);

    w.connections.failTokens('credentials_invalid', { times: 50 });
    await w.healthDue(integration.id);
    await w.probe();
    const unhealthy = await row(integration.id);
    expect(unhealthy.healthStatus).toBe('unhealthy');
    const sent = await notifications(org.id);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      audience: 'tenant',
      refs: { integrationPublicId: integration.publicId },
    });
    // The 8.2 view of the failing state: last probe stored with its code.
    expect(unhealthy.lastErrorCode).toBe('credentials_invalid');

    // Recovery (no notification), then unhealthy again 1 h later: suppressed, counted.
    w.clearTokenFailures();
    void connection;
    clock.advance(30 * MIN);
    await w.healthDue(integration.id);
    await w.probe();
    expect((await row(integration.id)).healthStatus).toBe('healthy');
    w.connections.failTokens('credentials_invalid', { times: 50 });
    clock.advance(30 * MIN);
    await w.healthDue(integration.id);
    await w.probe();
    expect((await row(integration.id)).healthStatus).toBe('unhealthy');
    expect(await notifications(org.id)).toHaveLength(1);
    const window = await fx.prisma.notificationAlertWindow.findFirstOrThrow({
      where: {
        organizationId: org.id,
        kind: 'ato_provider_health',
        scopeKey: integration.publicId,
      },
    });
    expect(window.eventCount).toBe(2);
    w.clearTokenFailures();
    // Gauges (no tenant labels).
    expect(
      await w.h.metric('ato_idp_integrations', {
        provider: 'microsoft_entra',
        health: 'unhealthy',
      }),
    ).toBeGreaterThanOrEqual(1);
  });

  it('connection inactive ⇒ paused connection_inactive; active again ⇒ resumed', async () => {
    const { org, connection, integration } = await setup('b');
    w.connections.update(org.id.toString(), connection.publicId, { status: 'configuring' });
    await w.healthDue(integration.id);
    await w.probe();
    expect(await row(integration.id)).toMatchObject({
      status: 'paused',
      pausedReason: 'connection_inactive',
      healthStatus: 'unhealthy',
    });
    expect(await notifications(org.id)).toHaveLength(1);
    // A paused integration is never polled.
    await w.due(integration.id);
    expect(await w.poll(2)).toBeGreaterThan(0);
    const streams = await fx.prisma.atoProviderStream.findMany({
      where: { integrationId: integration.id, role: 'primary' },
    });
    expect(streams.every((s) => s.pagesTotal === 0n)).toBe(true);
    w.connections.update(org.id.toString(), connection.publicId, { status: 'active' });
    await w.healthDue(integration.id);
    await w.probe();
    expect(await row(integration.id)).toMatchObject({
      status: 'active',
      pausedReason: null,
      healthStatus: 'healthy',
    });
  });

  it('telemetry grant inactive ⇒ paused telemetry_grant_inactive', async () => {
    const { org, connection, integration } = await setup('c');
    w.connections.setGrantStatus(
      org.id.toString(),
      connection.publicId,
      'm365.ato_telemetry',
      'revoked',
    );
    await w.healthDue(integration.id);
    await w.probe();
    expect(await row(integration.id)).toMatchObject({
      status: 'paused',
      pausedReason: 'telemetry_grant_inactive',
    });
  });

  it('connection removed ⇒ disabled; its in-flight provider actions fail integration_disabled', async () => {
    const { org, connection, integration } = await setup('d');
    await w.due(integration.id);
    await w.poll();
    const account = await fx.prisma.atoAccount.findFirstOrThrow({
      where: { organizationId: org.id, address: `alex@${domainOf('d')}` },
    });
    const action = await approvedAction(w, org, account.id, 'require_mfa', {}, 'microsoft_entra');
    // Executing on this integration (pending a read-back) when the connection disappears.
    await fx.prisma.atoResponseAction.update({
      where: { id: action.id },
      data: {
        status: 'executing',
        providerStatus: 'pending',
        integrationId: integration.id,
        providerReference: `msgraph:require_mfa:${action.publicId}`,
        nextCheckAt: new Date(clock.now().getTime() + 3_600_000),
      },
    });
    w.connections.remove(org.id.toString(), connection.publicId);
    await w.healthDue(integration.id);
    await w.probe();
    expect(await row(integration.id)).toMatchObject({
      status: 'disabled',
      disabledReason: 'connection_removed',
    });
    expect(
      await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } }),
    ).toMatchObject({ status: 'failed', resultCode: 'integration_disabled' });
  });

  it('another directory behind the connection ⇒ paused directory_changed; error recovers on a passing probe', async () => {
    const { org, connection, integration } = await setup('e');
    w.connections.update(org.id.toString(), connection.publicId, { externalTenantId: TENANTS.a });
    await w.healthDue(integration.id);
    await w.probe();
    expect(await row(integration.id)).toMatchObject({
      status: 'paused',
      pausedReason: 'directory_changed',
      healthStatus: 'unhealthy',
    });
    w.connections.update(org.id.toString(), connection.publicId, { externalTenantId: TENANTS.e });
    await w.healthDue(integration.id);
    await w.probe();
    expect((await row(integration.id)).status).toBe('active');
    // 8.4 `error` after repeated failures; a passing probe recovers it and resets the streams.
    await fx.prisma.atoProviderIntegration.update({
      where: { id: integration.id },
      data: { status: 'error', consecutiveFailures: 10 },
    });
    await fx.prisma.atoProviderStream.updateMany({
      where: { integrationId: integration.id },
      data: { consecutiveFailures: 10 },
    });
    await w.healthDue(integration.id);
    await w.probe();
    expect(await row(integration.id)).toMatchObject({ status: 'active', consecutiveFailures: 0 });
    const streams = await fx.prisma.atoProviderStream.findMany({
      where: { integrationId: integration.id },
    });
    expect(streams.every((s) => s.consecutiveFailures === 0)).toBe(true);
    void org;
  });

  it('a revoked permission ⇒ missing_permission, degraded health, the capability gone', async () => {
    const org = await fx.organization('hperm');
    await configure(w.h, org.id);
    const integration = await w.bind(w.connect(org.id, 'microsoft_entra'));
    await w.probe();
    expect((await row(integration.id)).healthStatus).toBe('healthy');
    w.sims.script.revokePermission('IdentityRiskEvent.Read.All', MS_TENANT_ID);
    w.sims.script.revokePermission('User.RevokeSessions.All', MS_TENANT_ID);
    await w.healthDue(integration.id);
    await w.probe();
    const after = await row(integration.id);
    expect(after.healthStatus).toBe('degraded');
    const risk = await fx.prisma.atoProviderStream.findFirstOrThrow({
      where: { integrationId: integration.id, stream: 'risk_events' },
    });
    expect(risk.availability).toBe('missing_permission');
    const caps = after.capabilities as {
      actions: Record<string, { supported: boolean }>;
      streams: Record<string, { supported: boolean }>;
    };
    expect(caps.streams.risk_events?.supported).toBe(false);
    expect(caps.actions.revoke_sessions?.supported).toBe(false);
    const account = await w.h.comps.db.transaction((tx) =>
      w.h.comps.store.ensureAccount(tx, {
        organizationId: org.id,
        subject: { kind: 'mailbox', address: `blake@${MS_DOMAIN}` },
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
    const rows = await fx.prisma.messageOutbox.findMany({
      where: {
        organizationId: org.id,
        eventType: EventTypes.AtoResponseRequested,
        aggregateId: action.id.toString(),
      },
    });
    await w.h.comps.respond.handle(
      fx.envelope(EventTypes.AtoResponseRequested, org.id, rows[0]!.payload, clock.now()),
    );
    expect(
      await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } }),
    ).toMatchObject({ status: 'unsupported', resultCode: 'capability_unavailable' });
    expect(
      await w.h.metric('ato_idp_probe_total', { provider: 'microsoft_entra', result: 'failed' }),
    ).toBeGreaterThan(0);
  });
});
