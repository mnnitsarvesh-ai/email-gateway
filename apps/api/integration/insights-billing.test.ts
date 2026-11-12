/**
 * Step 6.1 WP3 integration (real MySQL writer + replica, Redis): `GET /usage`, `GET /billing/plan`
 * and `GET /billing/usage` (docs/plan/steps/18-rest-api.md §3.3, D12) against seeded messages,
 * users, domains, API keys, limits and features: `/usage` equals `/organizations/{id}/usage`,
 * the plan and entitlements equal the catalogue rows, the monthly message counts equal SQL ground
 * truth, the cache, and the month rules.
 */
// @covers get /api/v1/usage
// @covers get /api/v1/billing/plan
// @covers get /api/v1/billing/usage
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BILLING_PRICING_NOTE } from '../src/modules/billing/billing.schemas';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, login } from './support/http';
import {
  DAY_MS,
  deleteInsightFixtures,
  HOUR_MS,
  insertMessages,
  type MessageSpec,
  reader,
  waitFor,
} from './support/insights';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let token: string;
let key: string;

const now = new Date();
const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
const prevStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
const month = monthStart.toISOString().slice(0, 7);
const prevMonth = prevStart.toISOString().slice(0, 7);

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization({ planCode: 'standard' });
  fx.registerCleanup(() => deleteInsightFixtures(ctx, [org.id]));
  const admin = await fx.createUser(org, { roles: ['organization_admin'] });
  await fx.createUser(org, { roles: ['read_only_user'], status: 'invited' });
  token = (
    await login(ctx, { email: admin.email, password: admin.password, organization: org.slug })
  ).body.accessToken as string;
  key = await fx.createApiKey(org, ['billing:read', 'organization:read']);
  // A platform override of one limit (source override).
  await ctx.prisma.organizationLimit.update({
    where: { organizationId_limitKey: { organizationId: org.id, limitKey: 'max_users' } },
    data: { limitValue: 777n, source: 'override' },
  });
  const specs: MessageSpec[] = [];
  const inMonth = (i: number) => new Date(monthStart.getTime() + (i % 3) * HOUR_MS + i * 1000);
  for (let i = 0; i < 12; i += 1) {
    specs.push({
      receivedAt: inMonth(i),
      direction: (['inbound', 'outbound', 'internal'] as const)[i % 3]!,
      verdict: 'clean',
    });
  }
  for (let i = 0; i < 5; i += 1) {
    specs.push({
      receivedAt: new Date(prevStart.getTime() + i * DAY_MS),
      direction: 'inbound',
      verdict: null,
    });
  }
  await insertMessages(ctx, org, specs);
  await waitFor(
    () => reader(ctx).emailMessage.count({ where: { organizationId: org.id } }),
    specs.length,
  );
  await waitFor(
    async () =>
      (
        await reader(ctx).organizationLimit.findFirst({
          where: { organizationId: org.id, limitKey: 'max_users' },
          select: { limitValue: true },
        })
      )?.limitValue === 777n,
    true,
  );
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('GET /usage', () => {
  it('equals GET /organizations/{id}/usage for the caller’s organization', async () => {
    const period = `from=${monthStart.toISOString()}&to=${new Date(monthStart.getTime() + 20 * DAY_MS).toISOString()}`;
    const own = await ctx.http.get(`/api/v1/usage?${period}`).set(bearer(token)).expect(200);
    const viaId = await ctx.http
      .get(`/api/v1/organizations/${org.publicId}/usage?${period}`)
      .set(bearer(token))
      .expect(200);
    expect(own.body).toEqual(viaId.body);
    expect(own.body.organizationId).toBe(org.publicId);
    expect(own.body.users).toMatchObject({ total: 2, active: 1, invited: 1 });
    expect(own.body.messages).toMatchObject({ total: 12, inbound: 4, outbound: 4, internal: 4 });
    const byKey = await ctx.http.get(`/api/v1/usage?${period}`).set(apiKeyHeader(key)).expect(200);
    expect(byKey.body).toEqual(own.body);
  });
});

describe('GET /billing/plan', () => {
  it('returns the catalogue plan and the effective entitlements with their source', async () => {
    const res = await ctx.http.get('/api/v1/billing/plan').set(bearer(token)).expect(200);
    const plan = await ctx.prisma.organizationPlan.findUniqueOrThrow({
      where: { code: 'standard' },
      select: { code: true, name: true, description: true },
    });
    expect(res.body.plan).toEqual(plan);
    const limits = await ctx.prisma.organizationLimit.findMany({
      where: { organizationId: org.id },
      orderBy: { limitKey: 'asc' },
    });
    expect(res.body.limits).toEqual(
      limits.map((l) => ({ key: l.limitKey, value: Number(l.limitValue), source: l.source })),
    );
    expect(res.body.limits).toContainEqual({ key: 'max_users', value: 777, source: 'override' });
    const features = await ctx.prisma.organizationFeature.findMany({
      where: { organizationId: org.id },
      orderBy: { featureKey: 'asc' },
    });
    expect(res.body.features).toEqual(
      features.map((f) => ({ key: f.featureKey, enabled: f.enabled, source: f.source })),
    );
    expect(res.body.pricing).toBeNull();
    expect(res.body.note).toBe(BILLING_PRICING_NOTE);
  });
});

describe('GET /billing/usage', () => {
  it('meters the current month (default) equal to SQL ground truth, and is cached', async () => {
    const res = await ctx.http.get('/api/v1/billing/usage').set(bearer(token)).expect(200);
    const rows = await ctx.prisma.$queryRaw<Array<{ direction: string; n: bigint }>>`
      SELECT direction, COUNT(*) AS n FROM email_messages WHERE organization_id = ${org.id}
        AND received_at >= ${monthStart} AND received_at < ${new Date()} GROUP BY direction`;
    const truth = Object.fromEntries(rows.map((r) => [r.direction, Number(r.n)]));
    expect(res.body).toMatchObject({
      organizationId: org.publicId,
      month,
      from: monthStart.toISOString(),
      messages: {
        total: 12,
        inbound: truth.inbound ?? 0,
        outbound: truth.outbound ?? 0,
        internal: truth.internal ?? 0,
      },
      users: 2,
      domains: 0,
      apiKeys: 1,
    });
    expect(res.body.limits).toContainEqual({
      key: 'max_users',
      value: 777,
      source: 'override',
      used: 2,
    });
    const again = await ctx.http
      .get(`/api/v1/billing/usage?month=${month}`)
      .set(apiKeyHeader(key))
      .expect(200);
    expect(again.body.generatedAt).toBe(res.body.generatedAt);
  });

  it('meters a whole past month and refuses future and expired months', async () => {
    const res = await ctx.http
      .get(`/api/v1/billing/usage?month=${prevMonth}`)
      .set(bearer(token))
      .expect(200);
    expect(res.body).toMatchObject({
      month: prevMonth,
      from: prevStart.toISOString(),
      to: monthStart.toISOString(),
      messages: { total: 5, inbound: 5, outbound: 0, internal: 0 },
    });
    const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1))
      .toISOString()
      .slice(0, 7);
    const old = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 7, 1))
      .toISOString()
      .slice(0, 7);
    for (const m of [next, old]) {
      const bad = await ctx.http
        .get(`/api/v1/billing/usage?month=${m}`)
        .set(bearer(token))
        .expect(400);
      expect(bad.body.code).toBe('usage_period_unavailable');
    }
  });
});
