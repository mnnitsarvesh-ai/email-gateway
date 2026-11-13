/**
 * Tenant isolation of the step 6.1 WP3 insight routes (docs/plan/steps/18-rest-api.md D7, §9
 * "Cross-tenant"), real sessions, MySQL writer + replica and Redis: organizations A and B have
 * fixtures of identical shapes and different volumes. A's members and API keys never see B's
 * audit rows, report counts, usage or billing numbers; A's cursor is refused for B; A's report
 * cache is never served to B; the platform audit route refuses organization administrators, API
 * keys, override sessions and platform users without MFA, and serves (and audits) an MFA
 * platform user. Step 7.1 (docs/plan/steps/20-admin-portal.md §9): the delivery, processing and
 * top-domains reports and the threats outcomes count only the caller's organization (A never sees
 * B's counts or domain names) and their cache entries are never shared.
 */
// @covers get /api/v1/audit/logs
// @covers get /api/v1/platform/audit/logs
// @covers get /api/v1/reports/traffic
// @covers get /api/v1/reports/threats
// @covers get /api/v1/reports/url-clicks
// @covers get /api/v1/reports/delivery
// @covers get /api/v1/reports/processing
// @covers get /api/v1/reports/top-domains
// @covers get /api/v1/usage
// @covers get /api/v1/billing/plan
// @covers get /api/v1/billing/usage
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { KeyValueStore } from '../src/kv/key-value-store';
import { reportCacheKey } from '../src/modules/reports/domain/report-cache-key';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, login, loginWithMfa } from './support/http';
import {
  type AuditSpec,
  DAY_MS,
  deleteInsightFixtures,
  HOUR_MS,
  insertAuditRows,
  insertClicks,
  insertDeliveries,
  insertDomain,
  insertMessages,
  insertQuarantineEntries,
  insertScanRounds,
  type MessageSpec,
  POLL,
  reader,
  utcDay,
  waitFor,
} from './support/insights';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let tokenA: string;
let tokenB: string;
let keyA: string;
const marker = randomUUID();
/** Volumes: A has `n`, B has `3n` of every fixture kind (identical shapes). */
const VOLUME = { A: 4, B: 12 };
const from = utcDay(2);
const to = utcDay(0);
const auditWindow = {
  from: new Date(from.getTime() - HOUR_MS),
  to: new Date(to.getTime() - HOUR_MS),
};
const ALL = ['audit:read', 'report:read', 'organization:read', 'billing:read', 'threat_intel:read'];

/** Step 7.1: each organization's own domain (top-domains report). */
const domains = new Map<bigint, { publicId: string; name: string }>();

async function seed(org: FixtureOrganization, n: number): Promise<void> {
  const domain = await insertDomain(ctx, org, `isolation-${org.slug}.example.test`);
  domains.set(org.id, domain);
  const messages: MessageSpec[] = [];
  for (let i = 0; i < n; i += 1) {
    messages.push({
      receivedAt: new Date(from.getTime() + (i % 2) * DAY_MS + i * 60_000),
      direction: i % 2 === 0 ? 'inbound' : 'outbound',
      verdict: i % 3 === 0 ? 'phishing' : 'clean',
      action: 'deliver',
      domainId: domain.id,
    });
  }
  const inserted = await insertMessages(ctx, org, messages);
  // Step 7.1: one delivered delivery and one completed initial scan round per message.
  await insertDeliveries(
    ctx,
    org,
    inserted.map((message) => ({ message, status: 'delivered', deliveredAfterMs: 2000 })),
  );
  await insertScanRounds(
    ctx,
    org,
    inserted.map((message) => ({ message, status: 'completed', completedAfterMs: 400 })),
  );
  await insertQuarantineEntries(
    ctx,
    org,
    Array.from({ length: n }, (_, i) => ({
      quarantinedAt: new Date(from.getTime() + i * 60_000),
      reason: 'phishing' as const,
      primaryEngine: 'url' as const,
    })),
  );
  await insertClicks(
    ctx,
    org,
    Array.from({ length: n }, (_, i) => ({
      clickedAt: new Date(from.getTime() + i * 60_000),
      decision: 'blocked' as const,
    })),
  );
  const audit: AuditSpec[] = Array.from({ length: n }, (_, i) => ({
    organizationId: org.id,
    createdAt: new Date(from.getTime() + i * 60_000),
    action: 'domain.created',
    resourceId: `${marker}-${org.slug}-${i}`,
  }));
  await insertAuditRows(ctx, audit);
  await waitFor(
    async () =>
      (await reader(ctx).emailMessage.count({ where: { organizationId: org.id } })) +
      (await reader(ctx).quarantineMessage.count({ where: { organizationId: org.id } })) +
      (await reader(ctx).urlClickEvent.count({ where: { organizationId: org.id } })) +
      (await reader(ctx).emailDelivery.count({ where: { organizationId: org.id } })) +
      (await reader(ctx).emailScan.count({ where: { organizationId: org.id } })) +
      (await reader(ctx).auditLog.count({
        where: { resourceId: { startsWith: `${marker}-${org.slug}` } },
      })),
    6 * n,
  );
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteInsightFixtures(ctx, [orgA.id, orgB.id]));
  const adminA = await fx.createUser(orgA, { roles: ['organization_admin'] });
  const adminB = await fx.createUser(orgB, { roles: ['organization_admin'] });
  tokenA = (
    await login(ctx, { email: adminA.email, password: adminA.password, organization: orgA.slug })
  ).body.accessToken as string;
  tokenB = (
    await login(ctx, { email: adminB.email, password: adminB.password, organization: orgB.slug })
  ).body.accessToken as string;
  keyA = await fx.createApiKey(orgA, ALL);
  await seed(orgA, VOLUME.A);
  await seed(orgB, VOLUME.B);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const get = (path: string, headers: Record<string, string>, params: Record<string, string> = {}) =>
  ctx.http.get(`${path}?${new URLSearchParams(params).toString()}`).set(headers);
const range = { from: from.toISOString(), to: to.toISOString() };
const auditRange = { from: auditWindow.from.toISOString(), to: auditWindow.to.toISOString() };

describe('audit logs', () => {
  it('lists only the own organization’s rows for members and API keys', async () => {
    for (const headers of [bearer(tokenA), apiKeyHeader(keyA)]) {
      const res = await get('/api/v1/audit/logs', headers, { ...auditRange, limit: '100' }).expect(
        200,
      );
      const ids = (res.body.data as Array<{ resourceId: string | null }>).map(
        (r) => r.resourceId ?? '',
      );
      expect(ids.filter((id) => id.startsWith(marker))).toHaveLength(VOLUME.A);
      expect(ids.some((id) => id.includes(orgB.slug))).toBe(false);
    }
    const b = await get('/api/v1/audit/logs', bearer(tokenB), {
      ...auditRange,
      limit: '100',
    }).expect(200);
    expect(
      (b.body.data as Array<{ resourceId: string | null }>).filter((r) =>
        r.resourceId?.startsWith(marker),
      ),
    ).toHaveLength(VOLUME.B);
  });

  it('refuses a cursor of organization A presented by organization B', async () => {
    const page = await get('/api/v1/audit/logs', bearer(tokenA), {
      ...auditRange,
      limit: '1',
    }).expect(200);
    const cursor = page.body.nextCursor as string;
    expect(cursor).toEqual(expect.any(String));
    const res = await get('/api/v1/audit/logs', bearer(tokenB), {
      ...auditRange,
      limit: '1',
      cursor,
    }).expect(400);
    expect(res.body.code).toBe('cursor_invalid');
    // A's own API key shares the organization binding: the cursor is A's.
    await get('/api/v1/audit/logs', apiKeyHeader(keyA), {
      ...auditRange,
      limit: '1',
      cursor,
    }).expect(200);
  });
});

describe('reports', () => {
  it('count only the own organization (same window, different volumes)', async () => {
    const a = await get('/api/v1/reports/traffic', bearer(tokenA), range).expect(200);
    const b = await get('/api/v1/reports/traffic', bearer(tokenB), range).expect(200);
    expect(a.body.totals.total).toBe(VOLUME.A);
    expect(b.body.totals.total).toBe(VOLUME.B);
    const threatsA = await get('/api/v1/reports/threats', apiKeyHeader(keyA), range).expect(200);
    expect(threatsA.body.quarantine.total).toBe(VOLUME.A);
    expect(threatsA.body.messages.total).toBe(VOLUME.A);
    const threatsB = await get('/api/v1/reports/threats', bearer(tokenB), range).expect(200);
    expect(threatsB.body.quarantine.total).toBe(VOLUME.B);
    const clicksA = await get('/api/v1/reports/url-clicks', bearer(tokenA), range).expect(200);
    const clicksB = await get('/api/v1/reports/url-clicks', bearer(tokenB), range).expect(200);
    expect(clicksA.body.totals.decisions.blocked).toBe(VOLUME.A);
    expect(clicksB.body.totals.decisions.blocked).toBe(VOLUME.B);
  });

  it('step 7.1 reports count only the own organization’s deliveries, rounds and domains', async () => {
    for (const [org, headers, n] of [
      [orgA, bearer(tokenA), VOLUME.A],
      [orgA, apiKeyHeader(keyA), VOLUME.A],
      [orgB, bearer(tokenB), VOLUME.B],
    ] as const) {
      const delivery = await get('/api/v1/reports/delivery', headers, range).expect(200);
      expect(delivery.body.totals.total).toBe(n);
      expect(delivery.body.latency.delivered).toBe(n);
      const processing = await get('/api/v1/reports/processing', headers, range).expect(200);
      expect(processing.body.totals.rounds).toBe(n);
      const top = await get('/api/v1/reports/top-domains', headers, range).expect(200);
      const own = domains.get(org.id)!;
      const other = domains.get(org.id === orgA.id ? orgB.id : orgA.id)!;
      expect(top.body.domains.map((d: { domainId: string }) => d.domainId)).toEqual([own.publicId]);
      // Inbound = even i; phishing = i % 3 === 0 among them.
      const inbound = Array.from({ length: n }, (_, i) => i).filter((i) => i % 2 === 0);
      expect(top.body.domains[0]).toMatchObject({
        inbound: inbound.length,
        threats: inbound.filter((i) => i % 3 === 0).length,
      });
      expect(JSON.stringify(top.body)).not.toContain(other.name);
      expect(JSON.stringify(top.body)).not.toContain(other.publicId);
      const threats = await get('/api/v1/reports/threats', headers, range).expect(200);
      expect(
        (threats.body.outcomes as Array<{ count: number }>).reduce((a, o) => a + o.count, 0),
      ).toBe(n);
    }
  });

  it('never serves organization A’s cached step 7.1 reports to organization B', async () => {
    const params = { from: new Date(from.getTime() + HOUR_MS).toISOString(), to: to.toISOString() };
    for (const report of ['delivery', 'processing', 'top-domains'] as const) {
      const a1 = await get(`/api/v1/reports/${report}`, bearer(tokenA), params).expect(200);
      const a2 = await get(`/api/v1/reports/${report}`, bearer(tokenA), params).expect(200);
      expect(a2.body.generatedAt, report).toBe(a1.body.generatedAt);
      const b1 = await get(`/api/v1/reports/${report}`, bearer(tokenB), params).expect(200);
      expect(JSON.stringify(b1.body), report).not.toBe(JSON.stringify(a1.body));
      // The cache key holds the normalized window (day-aligned for delivery and processing).
      const window = { from: a1.body.from as string, to: a1.body.to as string };
      const key =
        report === 'top-domains' ? { ...window, limit: 10 } : { ...window, granularity: 'day' };
      const kv = ctx.get(KeyValueStore);
      for (const org of [orgA, orgB]) {
        const entry = JSON.parse((await kv.get(reportCacheKey(org.id, report, key)))!) as {
          organizationId: string;
          report: string;
        };
        expect(entry, report).toMatchObject({ organizationId: org.id.toString(), report });
      }
    }
  });

  it('never serves organization A’s cached report to organization B', async () => {
    const params = {
      from: new Date(from.getTime() + HOUR_MS).toISOString(),
      to: to.toISOString(),
      granularity: 'hour',
    };
    const a1 = await get('/api/v1/reports/traffic', bearer(tokenA), params).expect(200);
    const a2 = await get('/api/v1/reports/traffic', bearer(tokenA), params).expect(200);
    expect(a2.body.generatedAt).toBe(a1.body.generatedAt);
    const b1 = await get('/api/v1/reports/traffic', bearer(tokenB), params).expect(200);
    expect(b1.body.totals.total).not.toBe(a1.body.totals.total);
    const window = { from: params.from, to: params.to, granularity: 'hour', direction: null };
    const kv = ctx.get(KeyValueStore);
    const entryA = JSON.parse((await kv.get(reportCacheKey(orgA.id, 'traffic', window)))!) as {
      organizationId: string;
    };
    const entryB = JSON.parse((await kv.get(reportCacheKey(orgB.id, 'traffic', window)))!) as {
      organizationId: string;
    };
    expect(entryA.organizationId).toBe(orgA.id.toString());
    expect(entryB.organizationId).toBe(orgB.id.toString());
  });
});

describe('usage and billing', () => {
  it('report only the own organization’s numbers', async () => {
    const usageA = await get('/api/v1/usage', bearer(tokenA), range).expect(200);
    const usageB = await get('/api/v1/usage', bearer(tokenB), range).expect(200);
    expect(usageA.body.organizationId).toBe(orgA.publicId);
    expect(usageA.body.messages.total).toBe(VOLUME.A);
    expect(usageB.body.messages.total).toBe(VOLUME.B);
    expect(usageA.body.quarantine.active).toBe(VOLUME.A);

    const planA = await get('/api/v1/billing/plan', apiKeyHeader(keyA)).expect(200);
    expect(planA.body.organizationId).toBe(orgA.publicId);
    const month = from.toISOString().slice(0, 7);
    const billingA = await get('/api/v1/billing/usage', bearer(tokenA), { month }).expect(200);
    const billingB = await get('/api/v1/billing/usage', bearer(tokenB), { month }).expect(200);
    expect(billingA.body.organizationId).toBe(orgA.publicId);
    expect(billingB.body.organizationId).toBe(orgB.publicId);
    // Both months contain every fixture message only if the window is inside the month.
    if (from.getUTCMonth() === to.getUTCMonth()) {
      expect(billingA.body.messages.total).toBe(VOLUME.A);
      expect(billingB.body.messages.total).toBe(VOLUME.B);
    }
    expect(billingA.body.users).toBe(1);
  });
});

describe('platform audit route', () => {
  const target = () => ({ organizationId: orgA.publicId, ...auditRange });

  it('refuses organization administrators and API keys (403)', async () => {
    await get('/api/v1/platform/audit/logs', bearer(tokenA), target()).expect(403);
    await get('/api/v1/platform/audit/logs', apiKeyHeader(keyA), target()).expect(403);
  });

  it('refuses override sessions and platform users without MFA (403)', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .send({
        organizationId: orgA.publicId,
        reason: 'Insights isolation 6.1',
        durationMinutes: 15,
      })
      .expect(201);
    const overrideToken = (started.body as { accessToken: string }).accessToken;
    await get('/api/v1/platform/audit/logs', bearer(overrideToken), target()).expect(403);
    // The override reads A's tenant audit log like a member of A (its own scope), not B's.
    const asA = await get('/api/v1/audit/logs', bearer(overrideToken), {
      ...auditRange,
      limit: '100',
    }).expect(200);
    expect(
      (asA.body.data as Array<{ resourceId: string | null }>).some((r) =>
        r.resourceId?.includes(orgB.slug),
      ),
    ).toBe(false);

    const noMfa = await fx.createPlatformUser(['platform_admin'], { mfa: false });
    const res = await login(ctx, {
      email: noMfa.email,
      password: noMfa.password,
      organization: noMfa.organization.slug,
    });
    expect(res.status).toBe(200);
    const denied = await get(
      '/api/v1/platform/audit/logs',
      bearer(res.body.accessToken as string),
      target(),
    ).expect(403);
    expect(['mfa_required', 'mfa_enrollment_required']).toContain(denied.body.code);
  });

  it('serves an MFA platform user the requested organization and audits the search', async () => {
    const operator = await fx.createPlatformUser(['platform_admin']);
    const session = await loginWithMfa(ctx, fx, operator);
    const before = new Date();
    const res = await get('/api/v1/platform/audit/logs', bearer(session.accessToken), {
      ...target(),
      limit: '100',
    }).expect(200);
    const ids = (res.body.data as Array<{ resourceId: string | null }>).map(
      (r) => r.resourceId ?? '',
    );
    expect(ids.filter((id) => id.startsWith(`${marker}-${orgA.slug}`))).toHaveLength(VOLUME.A);
    expect(ids.some((id) => id.includes(orgB.slug))).toBe(false);
    await expect
      .poll(
        () =>
          ctx.prisma.auditLog.count({
            where: {
              organizationId: orgA.id,
              action: 'platform.audit_searched',
              actorId: operator.publicId,
              createdAt: { gte: before },
            },
          }),
        POLL,
      )
      .toBe(1);
  });
});
