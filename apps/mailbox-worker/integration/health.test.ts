import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startSimulators, type RunningSimulators } from '@email-gateway/idp-adapters/testing';
import { notificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import type { MailboxComponents } from '../src/components';
import { hourOf } from '../src/runtime/redis-stores';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';

/**
 * Design §9.3 (mailbox-worker health role, D11.2–D11.4): the leader lock, coverage states, every
 * health check, transitions with the system audit row and the throttled `api_mode_unhealthy`
 * alert outbox row (`notification_alert_windows`), and the maintenance (pruning, feed sweeps).
 */
const fx = new Fixtures();
const clock = new Clock();
const S = fx.suffix;
const API = `api-${S}.it-apimode.example`;
const DAY = 86_400_000;
let sims: RunningSimulators;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;

async function mailbox(
  address: string,
  input: {
    status?: 'active' | 'disabled' | 'deleted';
    journalSeen?: Date | null;
    deletedAt?: Date;
  } = {},
) {
  const row = await fx.prisma.apiMailbox.create({
    data: {
      publicId: crypto.randomUUID(),
      organizationId: org.id,
      apiConnectionId: conn.apiConnectionId,
      providerUserId: crypto.randomUUID(),
      primaryAddress: address,
      domainId: org.domains.get(API)!,
      status: input.status ?? 'active',
      journalLastSeenAt: input.journalSeen ?? null,
      deletedAt: input.deletedAt ?? null,
    },
  });
  await fx.prisma.apiMailboxAddress.create({
    data: { organizationId: org.id, mailboxId: row.id, address, kind: 'primary' },
  });
  return row;
}

const connectionRow = () =>
  fx.prisma.apiModeConnection.findUniqueOrThrow({ where: { id: conn.apiConnectionId } });
const alerts = () =>
  fx.prisma.messageOutbox.findMany({
    where: { organizationId: org.id, eventType: 'notification.alert_requested.v1' },
  });
const audits = () =>
  fx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action: 'api_mode.health_changed' },
    orderBy: { id: 'asc' },
  });
const checks = async () =>
  new Map(
    (
      (await connectionRow()).healthChecks as { checks: { code: string; status: string }[] }
    ).checks.map((c) => [c.code, c.status]),
  );

beforeAll(async () => {
  sims = await startSimulators({ dataset: {}, now: clock.ms });
  comps = fx.components(fx.config(sims), { clock, tokens: new SimAccessTokens(() => sims, clock) });
  org = await fx.organization('health');
  await fx.domain(org, API, 'api');
  conn = await fx.connection(org, 'microsoft_365', { tenantId: 'tenant-health', domains: [API] });
  await fx.journalSource(org, conn);
  await fx.prisma.apiModeConnection.update({
    where: { id: conn.apiConnectionId },
    data: { inventoryStatus: 'ok', mailboxesTotal: 2 },
  });
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('health role (D11.2, D11.3)', () => {
  it('runs on the leader only', async () => {
    const other = fx.components(fx.config(sims), {
      clock,
      tokens: new SimAccessTokens(() => sims, clock),
    });
    expect(await comps.healthLeader.runOnce()).not.toBe('not_leader');
    expect(await other.healthLeader.runOnce()).toBe('not_leader');
    await comps.healthLeader.stop();
  });

  it('stores coverage states and moves to degraded with an audit row and one alert', async () => {
    const covered = await mailbox(`covered@${API}`, { journalSeen: new Date(clock.ms() - DAY) });
    const gap = await mailbox(`gap@${API}`, { journalSeen: new Date(clock.ms() - 8 * DAY) });
    const disabled = await mailbox(`disabled@${API}`, { status: 'disabled' });
    // Reset to a known state after the leader test's evaluation.
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { healthStatus: 'unknown', healthAlertedAt: null },
    });
    await fx.prisma.auditLog.deleteMany({ where: { organizationId: org.id } });
    await fx.prisma.messageOutbox.deleteMany({ where: { organizationId: org.id } });
    await fx.prisma.notificationAlertWindow.deleteMany({ where: { organizationId: org.id } });

    const report = await comps.health.runOnce();
    expect(report).toMatchObject({ connections: 1, transitions: 1, alerts: 1, failed: 0 });
    const states = await fx.prisma.apiMailbox.findMany({
      where: { id: { in: [covered.id, gap.id, disabled.id] } },
      orderBy: { id: 'asc' },
    });
    expect(states.map((m) => m.coverageState)).toEqual(['covered', 'gap', 'out_of_scope']);
    // Only changed states are written (the disabled mailbox was already out_of_scope).
    expect(states.map((m) => m.coverageChangedAt !== null)).toEqual([true, true, false]);

    const row = await connectionRow();
    expect(row.healthStatus).toBe('degraded');
    expect(row.healthAlertedAt?.getTime()).toBe(clock.ms());
    const c = await checks();
    expect(c.get('coverage.percent')).toBe('warn');
    expect(c.get('connection.active')).toBe('pass');
    expect(c.get('intake.present')).toBe('pass');
    expect(c.get('mailbox_access.grant')).toBe('pass');

    const [audit] = await audits();
    expect(audit).toMatchObject({
      actorType: 'system',
      resourceType: 'api_mode_connection',
      resourceId: conn.apiConnectionPublicId,
    });
    expect(audit!.metadata).toEqual({
      connectionId: conn.apiConnectionPublicId,
      from: 'unknown',
      to: 'degraded',
      failingChecks: ['coverage.percent'],
    });
    const [alert] = await alerts();
    const payload = notificationAlertRequestedV1.parse(alert!.payload);
    expect(payload).toMatchObject({
      kind: 'api_mode_unhealthy',
      severity: 'medium',
      refs: { apiModeConnectionId: conn.apiConnectionPublicId },
    });
    expect(alert).toMatchObject({ aggregateType: 'organization', aggregateId: org.id.toString() });
    expect(JSON.stringify(alert!.payload)).not.toContain('@');

    // A second run without a change writes nothing new.
    expect(await comps.health.runOnce()).toMatchObject({ transitions: 0, alerts: 0 });
  });

  it('fails on revoked access with feeds enabled; the alert is throttled for 24 hours', async () => {
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { feedsEnabled: true },
    });
    await fx.prisma.providerConnectionGrant.update({
      where: { id: conn.grantId },
      data: { status: 'revoked' },
    });
    clock.advance(60_000);
    const report = await comps.health.runOnce();
    expect(report).toMatchObject({ transitions: 1, alerts: 0, throttled: 1 });
    expect((await connectionRow()).healthStatus).toBe('failing');
    expect((await checks()).get('mailbox_access.grant')).toBe('fail');
    expect(await alerts()).toHaveLength(1);
    expect((await audits()).map((a) => (a.metadata as { to: string }).to)).toEqual([
      'degraded',
      'failing',
    ]);
  });

  it('evaluates lag, throttling, feed errors and the MX of API-mode domains', async () => {
    await fx.prisma.providerConnectionGrant.update({
      where: { id: conn.grantId },
      data: { status: 'active' },
    });
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { feedsEnabled: false },
    });
    await fx.prisma.apiModeCounter.create({
      data: {
        organizationId: org.id,
        apiConnectionId: conn.apiConnectionId,
        hour: hourOf(clock.now()),
        lagCount: 10,
        lagGt3600s: 10,
        lagMaxMs: 7_200_000,
        throttled429: 25,
      },
    });
    await fx.prisma.domainMxRecord.create({
      data: {
        organizationId: org.id,
        domainId: org.domains.get(API)!,
        priority: 10,
        host: 'mx.gateway.local',
        pointsToGateway: true,
        lastSeenAt: clock.now(),
      },
    });
    await comps.health.runOnce();
    const c = await checks();
    expect(c.get('lag.p95_1h')).toBe('fail');
    expect(c.get('throttling.1h')).toBe('warn');
    expect(c.get('domains.api_mode_mx')).toBe('warn');
    expect((await connectionRow()).healthStatus).toBe('failing');
  });

  it('returns to healthy (audited, no alert)', async () => {
    await fx.prisma.apiModeCounter.deleteMany({ where: { apiConnectionId: conn.apiConnectionId } });
    await fx.prisma.domainMxRecord.deleteMany({ where: { organizationId: org.id } });
    await fx.prisma.apiMailbox.updateMany({
      where: { organizationId: org.id, status: 'active' },
      data: { journalLastSeenAt: clock.now() },
    });
    const before = (await alerts()).length;
    const report = await comps.health.runOnce();
    expect(report).toMatchObject({ transitions: 1, alerts: 0 });
    expect((await connectionRow()).healthStatus).toBe('healthy');
    expect(await alerts()).toHaveLength(before);
  });
});

describe('connection, intake and feed checks (D11.3)', () => {
  it('fails an unbound connection without intake; warns on feed errors and journal silence', async () => {
    const domain = `other-${S}.it-apimode.example`;
    await fx.domain(org, domain, 'api');
    const other = await fx.connection(org, 'microsoft_365', {
      tenantId: 'tenant-health-2',
      domains: [domain],
      feeds: { enabled: true },
    });
    await fx.prisma.providerConnection.update({
      where: { id: other.providerConnectionId },
      data: { status: 'configuring', activeTenantKey: null },
    });
    for (const [i, feedStatus] of (['error', 'error', 'active'] as const).entries()) {
      await fx.prisma.apiMailbox.create({
        data: {
          publicId: crypto.randomUUID(),
          organizationId: org.id,
          apiConnectionId: other.apiConnectionId,
          providerUserId: crypto.randomUUID(),
          primaryAddress: `feed${i}@${domain}`,
          domainId: org.domains.get(domain)!,
          status: 'active',
          feedStatus,
        },
      });
    }
    await comps.health.runOnce();
    const row = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: other.apiConnectionId },
    });
    const c = new Map(
      (row.healthChecks as { checks: { code: string; status: string }[] }).checks.map((x) => [
        x.code,
        x.status,
      ]),
    );
    expect(row.healthStatus).toBe('failing');
    expect(c.get('connection.active')).toBe('fail');
    expect(c.get('intake.present')).toBe('fail');
    expect(c.get('feeds.errors')).toBe('warn');
    expect(c.get('coverage.percent')).toBe('pass');

    // A silent provider journal source on the connection: intake present, journal health warns.
    await fx.prisma.providerConnection.update({
      where: { id: other.providerConnectionId },
      data: { status: 'active', activeTenantKey: `it-apimode:${crypto.randomUUID()}` },
    });
    const sourceId = await fx.journalSource(org, other);
    await fx.prisma.journalIntakeSource.update({
      where: { id: sourceId },
      data: { healthStatus: 'silent' },
    });
    await comps.health.runOnce();
    const after = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: other.apiConnectionId },
    });
    const c2 = new Map(
      (after.healthChecks as { checks: { code: string; status: string }[] }).checks.map((x) => [
        x.code,
        x.status,
      ]),
    );
    expect(c2.get('connection.active')).toBe('pass');
    expect(c2.get('intake.present')).toBe('pass');
    expect(c2.get('intake.journal_health')).toBe('warn');
    expect(after.healthStatus).toBe('degraded');
  });
});

describe('maintenance (D11.4)', () => {
  it('prunes old dedupe keys, expired claims, old counters and long-deleted mailboxes', async () => {
    const now = clock.ms();
    const keep = await mailbox(`keep@${API}`);
    const old = await fx.prisma.apiCopyDedupeKey.create({
      data: {
        organizationId: org.id,
        mailboxId: keep.id,
        messageIdHash: 'a'.repeat(64),
        claimedBy: 'journal',
        createdAt: new Date(now - 200 * 3_600_000),
      },
    });
    const expired = await fx.prisma.apiCopyDedupeKey.create({
      data: {
        organizationId: org.id,
        mailboxId: keep.id,
        messageIdHash: 'b'.repeat(64),
        claimedBy: 'graph',
        claimExpiresAt: new Date(now - 60_000),
        createdAt: new Date(now),
      },
    });
    const fresh = await fx.prisma.apiCopyDedupeKey.create({
      data: {
        organizationId: org.id,
        mailboxId: keep.id,
        messageIdHash: 'c'.repeat(64),
        claimedBy: 'graph',
        claimExpiresAt: new Date(now + 600_000),
        createdAt: new Date(now),
      },
    });
    await fx.prisma.apiModeCounter.create({
      data: {
        organizationId: org.id,
        apiConnectionId: conn.apiConnectionId,
        hour: hourOf(new Date(now - 401 * DAY)),
      },
    });
    const gone = await mailbox(`gone@${API}`, {
      status: 'deleted',
      deletedAt: new Date(now - 31 * DAY),
    });
    const recent = await mailbox(`recent@${API}`, {
      status: 'deleted',
      deletedAt: new Date(now - DAY),
    });

    const report = await comps.maintenance.runOnce();
    expect(report.dedupeKeys).toBeGreaterThanOrEqual(1);
    expect(report.expiredClaims).toBeGreaterThanOrEqual(1);
    expect(report.counters).toBe(1);
    expect(report.deletedMailboxes).toBe(1);
    const left = await fx.prisma.apiCopyDedupeKey.findMany({
      where: { id: { in: [old.id, expired.id, fresh.id] } },
    });
    expect(left.map((k) => k.id)).toEqual([fresh.id]);
    expect(await fx.prisma.apiMailbox.count({ where: { id: gone.id } })).toBe(0);
    expect(await fx.prisma.apiMailboxAddress.count({ where: { mailboxId: gone.id } })).toBe(0);
    expect(await fx.prisma.apiMailbox.count({ where: { id: recent.id } })).toBe(1);
  });

  it('stops feeds of disabled connections and starts feeds of in-scope mailboxes', async () => {
    const m = await mailbox(`feed@${API}`);
    await fx.prisma.apiMailbox.update({
      where: { id: m.id },
      data: { feedStatus: 'active', feedCursor: 'opaque-cursor', subscriptionId: `sub-${S}` },
    });
    expect((await comps.maintenance.runOnce()).feedsStopped).toBeGreaterThanOrEqual(1);
    expect(await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: m.id } })).toMatchObject({
      feedStatus: 'off',
      feedCursor: null,
      subscriptionId: null,
    });
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { feedsEnabled: true },
    });
    expect((await comps.maintenance.runOnce()).feedsActivated).toBeGreaterThanOrEqual(1);
    const after = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: m.id } });
    expect(after.feedStatus).toBe('pending');
    expect(after.nextSyncAt?.getTime()).toBe(clock.ms());
  });
});
