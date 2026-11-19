import { integrationHealthChangedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Harness, signal } from './support/harness';

/**
 * Periodic health (§10.3, D11, D15): schedule and claims, transitions writing the event, audit
 * and outbox rows in ONE transaction (rollback test), no transition on an equal status, critical
 * failures, the provider-error grace period and back-off, and loop detection.
 */
const h = new Harness();
let org: bigint;
// The seed's egress snapshot is published 2026-06-01; keep `egress.ranges_fresh` out of the way.
const config = { PROVIDER_EGRESS_MAX_AGE_DAYS: '365', INTEGRATION_HEALTH_INTERVAL_SECONDS: '900' };

beforeAll(async () => {
  await h.start();
  org = await h.organization('health');
});

afterAll(async () => {
  await h.cleanup();
});

async function healthyConnection(label: string) {
  const domainName = h.name(label);
  const tenant = h.m365Tenant({ domains: [{ name: domainName }] });
  const domain = await h.domain(org, domainName);
  const connection = await h.connection(org, 'microsoft_365', {
    status: 'active',
    externalTenantId: tenant.tenantId,
    tenantVerifiedAt: h.clock.now(),
    nextHealthCheckAt: h.clock.now(),
  });
  await h.grant(connection, {
    authMethod: 'customer_app_secret',
    status: 'active',
    clientId: tenant.clientId,
    claimedTenantId: tenant.tenantId,
    credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
  });
  await h.link(connection, domain.id);
  await h.dnsRecords(org, domain.id);
  return { connection, domain, tenant };
}

const events = (connectionId: bigint) =>
  h.prisma.providerHealthEvent.findMany({ where: { connectionId }, orderBy: { id: 'asc' } });
const outbox = (connectionId: bigint) =>
  h.prisma.messageOutbox.findMany({
    where: {
      organizationId: org,
      aggregateType: 'provider_connection',
      aggregateId: connectionId.toString(),
    },
    orderBy: { id: 'asc' },
  });

describe('connection health', () => {
  it('first check: unknown → healthy with event, audit and outbox rows; schedules the next check', async () => {
    const { connection } = await healthyConnection('first');
    const { components, metrics } = h.worker({ config });
    const claimed = await components.health.claim(10);
    expect(claimed).toContain(connection.id);
    const outcome = await components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({ previous: 'unknown', status: 'healthy', changed: true });
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn.healthStatus).toBe('healthy');
    expect(conn.healthClaimedUntil).toBeNull();
    expect(conn.nextHealthCheckAt!.getTime()).toBe(h.clock.now().getTime() + 900_000);
    const [event] = await events(connection.id);
    expect(event).toMatchObject({ fromStatus: 'unknown', toStatus: 'healthy', failingChecks: [] });
    const [row] = await outbox(connection.id);
    expect(row).toMatchObject({ eventType: 'integration.connection.health_changed.v1' });
    const payload = integrationHealthChangedV1.parse(row!.payload);
    expect(payload).toMatchObject({
      connectionId: connection.publicId,
      provider: 'microsoft_365',
      previousStatus: 'unknown',
      status: 'healthy',
    });
    const audit = await h.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: org,
        action: 'integration.health_changed',
        resourceId: connection.publicId,
      },
    });
    expect(audit.actorType).toBe('system');
    const checks = await h.prisma.providerHealthCheck.findMany({
      where: { connectionId: connection.id },
    });
    expect(new Set(checks.map((c) => c.checkCode))).toEqual(
      new Set([
        'credentials.token',
        'permissions.granted',
        'tenant.identity',
        'domains.provider_verified',
        'dns.mx_gateway',
        'inbound.recent_deliveries',
        'outbound.relay_activity',
        'routing.loops',
        'credential.expiry',
        'egress.ranges_fresh',
      ]),
    );
    // Not due again before the interval: not claimed.
    expect(await components.health.claim(10)).not.toContain(connection.id);
    const transitions = await metrics.healthTransitions.get();
    expect(transitions.values.some((v) => v.labels.to === 'healthy')).toBe(true);
  });

  it('no transition on an equal status', async () => {
    const { connection } = await healthyConnection('equal');
    const { components } = h.worker({ config });
    await components.health.check(connection.id, signal());
    h.clock.advance(900_000);
    const outcome = await components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({ status: 'healthy', changed: false });
    expect(await events(connection.id)).toHaveLength(1);
    expect(await outbox(connection.id)).toHaveLength(1);
    h.clock.set(new Date());
  });

  it('revoked consent: credentials.token fails and the connection turns critical', async () => {
    const { connection, tenant } = await healthyConnection('revoked');
    await h.worker({ config }).components.health.check(connection.id, signal());
    h.fake.revokeConsent(tenant.tenantId, tenant.clientId);
    // A fresh worker (empty token cache) sees the revocation.
    const outcome = await h.worker({ config }).components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({ previous: 'healthy', status: 'critical', changed: true });
    expect(outcome!.failingChecks).toContain('credentials.token');
    const rows = await events(connection.id);
    expect(rows.at(-1)).toMatchObject({ fromStatus: 'healthy', toStatus: 'critical' });
    const last = (await outbox(connection.id)).at(-1)!;
    expect(integrationHealthChangedV1.parse(last.payload).failingChecks).toContain(
      'credentials.token',
    );
    const check = await h.prisma.providerHealthCheck.findFirstOrThrow({
      where: { connectionId: connection.id, checkCode: 'credentials.token' },
    });
    expect(check).toMatchObject({ status: 'fail', severity: 'critical' });
    expect(check.firstFailedAt).not.toBeNull();
  });

  it('provider unavailable: error within the grace period, back-off ×2, critical after the grace', async () => {
    const { connection } = await healthyConnection('grace');
    const t0 = h.clock.now().getTime();
    await h.worker({ config }).components.health.check(connection.id, signal());
    h.fake.failNext({ endpoint: 'm365.token', status: 503, times: 100 });
    const tokenCheck = () =>
      h.prisma.providerHealthCheck.findFirstOrThrow({
        where: { connectionId: connection.id, checkCode: 'credentials.token' },
      });
    // Round 1: error, still healthy (grace), back-off 900 s.
    let outcome = await h.worker({ config }).components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({
      status: 'healthy',
      changed: false,
      providerChecksSkipped: false,
    });
    let check = await tokenCheck();
    expect(check).toMatchObject({
      status: 'error',
      evidence: { code: 'unavailable', backoffSeconds: 900 },
    });
    const firstFailedAt = check.firstFailedAt!.getTime();
    // Round 2 (+15 min): runs again, still in grace, back-off doubles.
    h.clock.set(new Date(t0 + 15 * 60_000));
    outcome = await h.worker({ config }).components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({ status: 'healthy', providerChecksSkipped: false });
    check = await tokenCheck();
    expect(check.evidence).toMatchObject({ backoffSeconds: 1800 });
    expect(check.firstFailedAt!.getTime()).toBe(firstFailedAt);
    // Round 3 (+30 min): provider checks backed off; mail-flow checks still run.
    h.clock.set(new Date(t0 + 30 * 60_000));
    outcome = await h.worker({ config }).components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({ status: 'healthy', providerChecksSkipped: true });
    // Round 4 (+61 min): back-off over, grace over: critical.
    h.clock.set(new Date(t0 + 61 * 60_000));
    outcome = await h.worker({ config }).components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({
      status: 'critical',
      changed: true,
      providerChecksSkipped: false,
    });
    h.fake.reset();
    h.clock.set(new Date());
  });

  it('a transition is atomic: a failure after the event row rolls back event, audit, outbox and checks', async () => {
    const { connection } = await healthyConnection('rollback');
    const { components } = h.worker({
      config,
      healthFaults: {
        afterEventInsert: () => {
          throw new Error('injected');
        },
      },
    });
    await expect(components.health.check(connection.id, signal())).rejects.toThrow('injected');
    expect(await events(connection.id)).toHaveLength(0);
    expect(await outbox(connection.id)).toHaveLength(0);
    expect(
      await h.prisma.auditLog.count({
        where: {
          organizationId: org,
          action: 'integration.health_changed',
          resourceId: connection.publicId,
        },
      }),
    ).toBe(0);
    expect(
      await h.prisma.providerHealthCheck.count({ where: { connectionId: connection.id } }),
    ).toBe(0);
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn.healthStatus).toBe('unknown');
  });

  it('loop deliveries to a linked domain turn routing.loops critical (D9)', async () => {
    const { connection, domain } = await healthyConnection('loops');
    await h.prisma.emailDelivery.create({
      data: {
        receivedAt: h.clock.now(),
        messageId: 1n,
        recipientId: BigInt(Date.now()),
        organizationId: org,
        status: 'failed',
        failureReason: 'loop_detected',
        direction: 'internal',
        destinationKey: `tenant:${domain.id.toString()}`,
      },
    });
    const outcome = await h.worker({ config }).components.health.check(connection.id, signal());
    expect(outcome).toMatchObject({ status: 'critical' });
    expect(outcome!.failingChecks).toContain('routing.loops');
  });
});
