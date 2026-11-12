/**
 * Step 6.1 WP3 e2e (stubbed infrastructure): the reports (docs/plan/steps/18-rest-api.md §3.3,
 * D12): success shapes, strict queries and range/granularity limits, RBAC, the `expensive` rate
 * class (429 with RateLimit headers), the cache, `503 report_timeout`, and the OpenAPI operations.
 */
// @covers get /api/v1/reports/traffic
// @covers get /api/v1/reports/threats
// @covers get /api/v1/reports/url-clicks
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import { ReportQueryTimeoutError } from '../src/modules/reports/domain/report-errors';
import {
  createInsightApp,
  expectCoded,
  INSIGHT_PERMISSIONS,
  type InsightApp,
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
  t.doubles.reports.traffic = () => Promise.resolve([]);
  t.doubles.reports.outcomes = () => Promise.resolve([]);
  t.doubles.reports.quarantine = () => Promise.resolve([]);
  t.doubles.reports.clicks = () => Promise.resolve([]);
});

const get = async (path: string, auth?: Record<string, string>) =>
  t
    .http()
    .get(path)
    .set(auth ?? (await t.principals.bearer()));

describe('GET /reports/traffic', () => {
  it('returns aligned, zero-filled buckets with direction and verdict counts', async () => {
    t.doubles.reports.traffic = () =>
      Promise.resolve([
        {
          bucket: new Date('2026-11-10T00:00:00.000Z'),
          direction: 'inbound',
          verdict: 'spam',
          count: 4,
        },
        {
          bucket: new Date('2026-11-11T00:00:00.000Z'),
          direction: 'outbound',
          verdict: null,
          count: 1,
        },
      ]);
    const res = await get(
      '/api/v1/reports/traffic?from=2026-11-10T05:00:00Z&to=2026-11-11T05:00:00Z&granularity=day',
    );
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      from: '2026-11-10T00:00:00.000Z',
      to: '2026-11-12T00:00:00.000Z',
      granularity: 'day',
      direction: null,
      totals: { total: 5, inbound: 4, outbound: 1, internal: 0 },
    });
    expect(res.body.buckets).toHaveLength(2);
    expect(res.body.buckets[0].verdicts).toMatchObject({ spam: 4, none: 0, clean: 0 });
    expect(res.body.buckets[1].verdicts).toMatchObject({ none: 1 });
    expect(res.headers['ratelimit-limit']).toBeDefined();
  });

  it('accepts API keys with report:read', async () => {
    const res = await get('/api/v1/reports/traffic', t.principals.apiKeyHeaders);
    expect(res.status).toBe(200);
    expect(res.body.granularity).toBe('day');
  });

  it('refuses unknown parameters, bad values and ranges over the granularity limit', async () => {
    for (const query of [
      'foo=1',
      'granularity=week',
      'direction=sideways',
      'from=yesterday',
      'from=2026-11-01T00:00:00Z&to=2026-11-09T00:00:00Z&granularity=hour',
      'from=2026-10-01T00:00:00Z&to=2026-11-09T00:00:00Z&granularity=day',
      'from=2026-11-09T00:00:00Z&to=2026-11-09T00:00:00Z',
    ]) {
      const res = await get(`/api/v1/reports/traffic?${query}`);
      expect(res.status, query).toBe(400);
      expectCoded(res.body, 'validation_failed');
    }
    const ok = await get(
      '/api/v1/reports/traffic?from=2026-11-02T00:00:00Z&to=2026-11-09T00:00:00Z&granularity=hour',
    );
    expect(ok.status).toBe(200);
    expect(ok.body.buckets).toHaveLength(7 * 24);
  });

  it('serves the second identical request from the cache', async () => {
    let calls = 0;
    t.doubles.reports.traffic = () => {
      calls += 1;
      return Promise.resolve([]);
    };
    const first = await get('/api/v1/reports/traffic?granularity=hour');
    const second = await get('/api/v1/reports/traffic?granularity=hour');
    expect(second.body).toEqual(first.body);
    expect(calls).toBe(1);
    expect([...t.kv.entries.keys()].some((k) => /^rpt:v1:1:traffic:[0-9a-f]{64}$/.test(k))).toBe(
      true,
    );
  });

  it('maps a query timeout to 503 report_timeout', async () => {
    t.doubles.reports.traffic = () => Promise.reject(new ReportQueryTimeoutError('traffic'));
    const res = await get('/api/v1/reports/traffic');
    expect(res.status).toBe(503);
    expectCoded(res.body, 'report_timeout');
  });
});

describe('GET /reports/threats', () => {
  it('counts verdicts, actions, quarantine reasons and engines', async () => {
    t.doubles.reports.outcomes = () =>
      Promise.resolve([{ verdict: 'phishing', action: 'quarantine', count: 2 }]);
    t.doubles.reports.quarantine = () =>
      Promise.resolve([{ reason: 'phishing', primaryEngine: 'url', count: 2 }]);
    const res = await get('/api/v1/reports/threats');
    expect(res.status).toBe(200);
    expect(res.body.messages).toMatchObject({
      total: 2,
      verdicts: { phishing: 2 },
      actions: { quarantine: 2 },
    });
    expect(res.body.quarantine).toMatchObject({
      total: 2,
      reasons: { phishing: 2 },
      primaryEngines: { url: 2 },
    });
    const bad = await get('/api/v1/reports/threats?granularity=hour');
    expect(bad.status).toBe(400);
  });

  it('maps a timeout of either query to 503 report_timeout', async () => {
    t.doubles.reports.quarantine = () => Promise.reject(new ReportQueryTimeoutError('quarantine'));
    const res = await get('/api/v1/reports/threats');
    expect(res.status).toBe(503);
    expectCoded(res.body, 'report_timeout');
  });
});

describe('GET /reports/url-clicks', () => {
  it('buckets clicks by decision', async () => {
    t.doubles.reports.clicks = () =>
      Promise.resolve([
        { bucket: new Date('2026-11-12T08:00:00.000Z'), decision: 'blocked', count: 3 },
      ]);
    const res = await get(
      '/api/v1/reports/url-clicks?from=2026-11-12T08:00:00Z&to=2026-11-12T10:00:00Z&granularity=hour',
    );
    expect(res.status).toBe(200);
    expect(res.body.buckets).toHaveLength(2);
    expect(res.body.totals).toEqual({
      total: 3,
      decisions: { allowed: 0, warned: 0, blocked: 3, continued: 0, expired: 0, not_found: 0 },
    });
    expect((await get('/api/v1/reports/url-clicks?decision=blocked')).status).toBe(400);
  });

  it('maps a timeout to 503 report_timeout', async () => {
    t.doubles.reports.clicks = () => Promise.reject(new ReportQueryTimeoutError('clicks'));
    expectCoded((await get('/api/v1/reports/url-clicks')).body, 'report_timeout');
  });
});

describe('report RBAC', () => {
  it('refuses users and API keys without report:read (403) and anonymous callers (401)', async () => {
    t.principals.user(['audit:read', 'organization:read']);
    t.principals.apiKeyWith(['audit:read']);
    for (const path of ['traffic', 'threats', 'url-clicks']) {
      const user = await get(`/api/v1/reports/${path}`);
      expect(user.status).toBe(403);
      expectCoded(user.body, 'forbidden');
      expect((await get(`/api/v1/reports/${path}`, t.principals.apiKeyHeaders)).status).toBe(403);
      expect((await t.http().get(`/api/v1/reports/${path}`)).status).toBe(401);
    }
  });
});

describe('report rate class', () => {
  it('limits the expensive class per principal with RateLimit headers and 429 rate_limited', async () => {
    const limited = await createInsightApp({ API_RATE_EXPENSIVE_PER_MINUTE: '2' });
    try {
      limited.principals.user(['report:read']);
      const auth = await limited.principals.bearer();
      const first = await limited.http().get('/api/v1/reports/traffic').set(auth);
      expect(first.status).toBe(200);
      expect(first.headers['ratelimit-limit']).toBe('2');
      expect(first.headers['ratelimit-remaining']).toBe('1');
      expect((await limited.http().get('/api/v1/reports/threats').set(auth)).status).toBe(200);
      const third = await limited.http().get('/api/v1/reports/url-clicks').set(auth);
      expect(third.status).toBe(429);
      expect(third.body).toMatchObject({ code: 'rate_limited', scope: 'expensive' });
      expect(third.headers['retry-after']).toBeDefined();
      expect(third.headers['ratelimit-remaining']).toBe('0');
    } finally {
      await limited.close();
    }
  });
});

describe('report OpenAPI operations', () => {
  it('documents tag, summary, description, permission, rate class, example and report_timeout', () => {
    const doc = buildOpenApiDocument(t.app);
    for (const path of ['traffic', 'threats', 'url-clicks']) {
      const op = doc.paths[`/api/v1/reports/${path}`]!.get as unknown as Record<string, unknown> & {
        responses: Record<
          string,
          { content?: Record<string, { example?: unknown; schema?: unknown }> }
        >;
      };
      expect(op.tags).toEqual(['reports']);
      expect(op.summary).toEqual(expect.any(String));
      expect(op.description).toEqual(expect.stringContaining('report_timeout'));
      expect(op['x-eg-permissions']).toEqual({ mode: 'all', permissions: ['report:read'] });
      expect(op['x-eg-rate-class']).toBe('expensive');
      expect(op.responses['200']!.content!['application/json']!.example).toBeDefined();
      expect(JSON.stringify(op.responses['503'])).toContain('report_timeout');
      expect(JSON.stringify(op.responses['400'])).toContain('validation_failed');
      expect(op.responses['429']).toBeDefined();
    }
  });
});
