/**
 * Step 6.1 WP3 e2e (stubbed infrastructure): `GET /usage` (OrganizationUsageService for the
 * caller's organization) and `/billing/plan`, `/billing/usage` (docs/plan/steps/18-rest-api.md
 * §3.3, D12): shapes, strict queries, month rules, RBAC, the expensive class, the cache,
 * `503 report_timeout` and the OpenAPI operations.
 */
// @covers get /api/v1/usage
// @covers get /api/v1/billing/plan
// @covers get /api/v1/billing/usage
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import { BILLING_PRICING_NOTE } from '../src/modules/billing/billing.schemas';
import { ReportQueryTimeoutError } from '../src/modules/reports/domain/report-errors';
import {
  createInsightApp,
  expectCoded,
  INSIGHT_PERMISSIONS,
  type InsightApp,
  USAGE_COUNTS,
} from './insights-support';

let t: InsightApp;

beforeAll(async () => {
  t = await createInsightApp();
});
afterAll(async () => {
  await t?.close();
});
beforeEach(() => {
  t.principals.user([...INSIGHT_PERMISSIONS]);
  t.principals.apiKeyWith([...INSIGHT_PERMISSIONS]);
  t.kv.entries.clear();
  t.doubles.reports.directions = () =>
    Promise.resolve([
      { direction: 'inbound', count: 11 },
      { direction: 'internal', count: 2 },
    ]);
});

const get = async (path: string, auth?: Record<string, string>) =>
  t
    .http()
    .get(path)
    .set(auth ?? (await t.principals.bearer()));

const currentMonth = () => new Date().toISOString().slice(0, 7);

describe('GET /usage', () => {
  it('is the organization usage of the caller (same service as /organizations/{id}/usage)', async () => {
    let seen: unknown[] = [];
    t.doubles.usageCounts = (...args: unknown[]) => {
      seen = args;
      return Promise.resolve(USAGE_COUNTS);
    };
    const res = await get('/api/v1/usage?from=2026-11-01T00:00:00Z&to=2026-11-12T00:00:00Z');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      organizationId: t.principals.ids.org,
      period: { from: '2026-11-01T00:00:00.000Z', to: '2026-11-12T00:00:00.000Z' },
      users: { total: 9, active: 7, invited: 2 },
      domains: { total: 2, active: 2 },
      messages: { total: 42, inbound: 30, outbound: 12, internal: 0, today: 4 },
      quarantine: { active: 3 },
      apiKeys: { active: 1 },
    });
    expect(res.body.limits).toContainEqual({
      key: 'max_users',
      value: 500,
      source: 'override',
      used: 9,
    });
    expect((seen[0] as { id: bigint }).id).toBe(1n);

    const viaKey = await get('/api/v1/usage', t.principals.apiKeyHeaders);
    expect(viaKey.status).toBe(200);
    expect(viaKey.body.organizationId).toBe(t.principals.ids.org);
  });

  it('refuses unknown parameters, ranges over 31 days and callers without organization:read', async () => {
    expectCoded((await get('/api/v1/usage?organizationId=x')).body, 'validation_failed');
    const long = await get('/api/v1/usage?from=2026-09-01T00:00:00Z&to=2026-11-01T00:00:00Z');
    expect(long.status).toBe(400);
    t.principals.user(['billing:read']);
    t.principals.apiKeyWith(['billing:read']);
    expectCoded((await get('/api/v1/usage')).body, 'forbidden');
    expect((await get('/api/v1/usage', t.principals.apiKeyHeaders)).status).toBe(403);
    expect((await t.http().get('/api/v1/usage')).status).toBe(401);
  });
});

describe('GET /billing/plan', () => {
  it('returns the plan, effective limits and features with their source, pricing null', async () => {
    const res = await get('/api/v1/billing/plan');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      organizationId: t.principals.ids.org,
      plan: {
        code: 'standard',
        name: 'Standard',
        description: 'Inbound and outbound filtering for small and medium organizations',
      },
      limits: [
        { key: 'max_domains', value: 10, source: 'plan' },
        { key: 'max_users', value: 500, source: 'override' },
        { key: 'messages_per_day', value: 100_000, source: 'plan' },
      ],
      features: [
        { key: 'dlp', enabled: false, source: 'plan' },
        { key: 'inbound_filtering', enabled: true, source: 'plan' },
      ],
      pricing: null,
      note: BILLING_PRICING_NOTE,
    });
    expect((await get('/api/v1/billing/plan', t.principals.apiKeyHeaders)).status).toBe(200);
    expectCoded((await get('/api/v1/billing/plan?x=1')).body, 'validation_failed');
  });

  it('requires billing:read', async () => {
    t.principals.user(['organization:read', 'report:read']);
    expectCoded((await get('/api/v1/billing/plan')).body, 'forbidden');
  });
});

describe('GET /billing/usage', () => {
  it('meters the current month by default and a given retained month', async () => {
    const res = await get('/api/v1/billing/usage');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      organizationId: t.principals.ids.org,
      month: currentMonth(),
      from: `${currentMonth()}-01T00:00:00.000Z`,
      messages: { total: 13, inbound: 11, outbound: 0, internal: 2 },
      users: 9,
      domains: 2,
      apiKeys: 1,
    });
    expect(res.body.limits).toContainEqual({
      key: 'max_domains',
      value: 10,
      source: 'plan',
      used: 2,
    });
    expect(res.body.limits).toContainEqual({
      key: 'messages_per_day',
      value: 100_000,
      source: 'plan',
      used: null,
    });
    expect(res.body).not.toHaveProperty('pricing');

    const last = new Date();
    last.setUTCDate(1);
    last.setUTCMonth(last.getUTCMonth() - 1);
    const month = last.toISOString().slice(0, 7);
    const past = await get(`/api/v1/billing/usage?month=${month}`);
    expect(past.status).toBe(200);
    expect(past.body.month).toBe(month);
    const end = new Date(Date.UTC(last.getUTCFullYear(), last.getUTCMonth() + 1, 1));
    expect(past.body.to).toBe(end.toISOString());
  });

  it('refuses malformed months (validation_failed) and unavailable months (usage_period_unavailable)', async () => {
    expectCoded((await get('/api/v1/billing/usage?month=2026-13')).body, 'validation_failed');
    expectCoded((await get('/api/v1/billing/usage?month=11-2026')).body, 'validation_failed');
    expectCoded((await get('/api/v1/billing/usage?year=2026')).body, 'validation_failed');
    const future = new Date();
    future.setUTCDate(1);
    future.setUTCMonth(future.getUTCMonth() + 1);
    expectCoded(
      (await get(`/api/v1/billing/usage?month=${future.toISOString().slice(0, 7)}`)).body,
      'usage_period_unavailable',
    );
    const old = new Date();
    old.setUTCDate(1);
    old.setUTCMonth(old.getUTCMonth() - 7);
    expectCoded(
      (await get(`/api/v1/billing/usage?month=${old.toISOString().slice(0, 7)}`)).body,
      'usage_period_unavailable',
    );
  });

  it('is cached per organization and month, and maps a timeout to 503 report_timeout', async () => {
    let calls = 0;
    t.doubles.reports.directions = () => {
      calls += 1;
      return Promise.resolve([]);
    };
    const a = await get('/api/v1/billing/usage');
    const b = await get('/api/v1/billing/usage');
    expect(b.body).toEqual(a.body);
    expect(calls).toBe(1);
    t.kv.entries.clear();
    t.doubles.reports.directions = () => Promise.reject(new ReportQueryTimeoutError('directions'));
    const timeout = await get('/api/v1/billing/usage');
    expect(timeout.status).toBe(503);
    expectCoded(timeout.body, 'report_timeout');
  });

  it('requires billing:read', async () => {
    t.principals.apiKeyWith(['report:read']);
    expect((await get('/api/v1/billing/usage', t.principals.apiKeyHeaders)).status).toBe(403);
  });

  it('is in the expensive rate class (429 with headers)', async () => {
    const limited = await createInsightApp({ API_RATE_EXPENSIVE_PER_MINUTE: '1' });
    try {
      limited.principals.apiKeyWith(['billing:read']);
      const h = limited.principals.apiKeyHeaders;
      expect((await limited.http().get('/api/v1/billing/usage').set(h)).status).toBe(200);
      const res = await limited.http().get('/api/v1/billing/usage').set(h);
      expect(res.status).toBe(429);
      expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'expensive' });
      expect(res.headers['retry-after']).toBeDefined();
      expect(res.headers['ratelimit-limit']).toBe('1');
      // The plan route is not in the class.
      expect((await limited.http().get('/api/v1/billing/plan').set(h)).status).toBe(200);
    } finally {
      await limited.close();
    }
  });
});

describe('usage and billing OpenAPI operations', () => {
  it('documents tags, permissions, examples, the rate class and the specific codes', () => {
    const doc = buildOpenApiDocument(t.app);
    const op = (path: string) =>
      doc.paths[path]!.get as unknown as Record<string, unknown> & {
        responses: Record<string, { content?: Record<string, { example?: unknown }> }>;
      };
    expect(op('/api/v1/usage').tags).toEqual(['usage']);
    expect(op('/api/v1/usage')['x-eg-permissions']).toEqual({
      mode: 'all',
      permissions: ['organization:read'],
    });
    expect(op('/api/v1/billing/plan').tags).toEqual(['billing']);
    expect(op('/api/v1/billing/plan')['x-eg-rate-class']).toBeUndefined();
    expect(op('/api/v1/billing/usage')['x-eg-rate-class']).toBe('expensive');
    expect(JSON.stringify(op('/api/v1/billing/usage').responses['400'])).toContain(
      'usage_period_unavailable',
    );
    expect(JSON.stringify(op('/api/v1/billing/usage').responses['503'])).toContain(
      'report_timeout',
    );
    for (const path of ['/api/v1/usage', '/api/v1/billing/plan', '/api/v1/billing/usage']) {
      expect(op(path).summary).toEqual(expect.any(String));
      expect(op(path).description).toEqual(expect.any(String));
      expect(op(path).responses['200']!.content!['application/json']!.example).toBeDefined();
    }
  });
});
