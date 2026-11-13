/**
 * Step 6.1 WP3 e2e (stubbed infrastructure): the reports (docs/plan/steps/18-rest-api.md §3.3,
 * D12; the step 7.1 delivery, processing and top-domains reports and the threats `outcomes`,
 * docs/plan/steps/20-admin-portal.md §3.3): success shapes, strict queries and range/granularity limits, RBAC, the `expensive` rate
 * class (429 with RateLimit headers), the cache, `503 report_timeout`, and the OpenAPI operations.
 */
// @covers get /api/v1/reports/traffic
// @covers get /api/v1/reports/threats
// @covers get /api/v1/reports/url-clicks
// @covers get /api/v1/reports/delivery
// @covers get /api/v1/reports/processing
// @covers get /api/v1/reports/top-domains
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import { InconsistentReadError } from '../src/http/listing/echo-check';
import {
  DELIVERY_LATENCY_BOUNDS_MS,
  PROCESSING_LATENCY_BOUNDS_MS,
} from '../src/modules/reports/domain/latency-histogram';
import { ReportQueryTimeoutError } from '../src/modules/reports/domain/report-errors';
import {
  DELIVERY_REPORT_EXAMPLE,
  DeliveryReportSchema,
  PROCESSING_REPORT_EXAMPLE,
  ProcessingReportSchema,
  THREATS_REPORT_EXAMPLE,
  ThreatsReportSchema,
  TOP_DOMAINS_REPORT_EXAMPLE,
  TopDomainsReportSchema,
} from '../src/modules/reports/reports.schemas';
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
  t.doubles.reports.deliveries = () => Promise.resolve([]);
  t.doubles.reports.scanRounds = () => Promise.resolve([]);
  t.doubles.reports.domainVerdicts = () => Promise.resolve([]);
  t.doubles.reports.domains = () => Promise.resolve(new Map());
});

const ALL_REPORTS = ['traffic', 'threats', 'url-clicks', 'delivery', 'processing', 'top-domains'];

/** Latency samples (cumulative per bound) of the given values in ms. */
const latency = (bounds: readonly number[], valuesMs: number[]) => ({
  samples: valuesMs.length,
  sumUs: valuesMs.reduce((a, v) => a + v * 1000, 0),
  cumulative: bounds.map((b) => valuesMs.filter((v) => v <= b).length),
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
    expect(res.body.outcomes).toEqual([{ verdict: 'phishing', action: 'quarantine', count: 2 }]);
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

describe('GET /reports/threats outcomes (step 7.1 P15)', () => {
  it('lists the verdict × action pairs by count, then verdict and action', async () => {
    t.doubles.reports.outcomes = () =>
      Promise.resolve([
        { verdict: 'spam', action: 'tag', count: 2 },
        { verdict: 'clean', action: 'deliver', count: 9 },
        { verdict: null, action: null, count: 2 },
        { verdict: 'bulk', action: 'quarantine', count: 2 },
      ]);
    const res = await get('/api/v1/reports/threats');
    expect(res.status).toBe(200);
    expect(res.body.outcomes).toEqual([
      { verdict: 'clean', action: 'deliver', count: 9 },
      { verdict: 'bulk', action: 'quarantine', count: 2 },
      { verdict: 'none', action: 'none', count: 2 },
      { verdict: 'spam', action: 'tag', count: 2 },
    ]);
    expect(ThreatsReportSchema.safeParse(res.body).success).toBe(true);
  });
});

describe('GET /reports/delivery (step 7.1 §3.3)', () => {
  it('returns zero-filled buckets with statuses, success rates and the latency histogram', async () => {
    t.doubles.reports.deliveries = () =>
      Promise.resolve([
        {
          bucket: new Date('2026-11-10T00:00:00.000Z'),
          status: 'delivered',
          count: 3,
          latency: latency(DELIVERY_LATENCY_BOUNDS_MS, [800, 800, 40_000]),
        },
        {
          bucket: new Date('2026-11-10T00:00:00.000Z'),
          status: 'failed',
          count: 1,
          latency: latency(DELIVERY_LATENCY_BOUNDS_MS, []),
        },
      ]);
    const res = await get(
      '/api/v1/reports/delivery?from=2026-11-10T05:00:00Z&to=2026-11-11T05:00:00Z&granularity=day',
    );
    expect(res.status).toBe(200);
    expect(DeliveryReportSchema.safeParse(res.body).success).toBe(true);
    expect(res.body).toMatchObject({
      from: '2026-11-10T00:00:00.000Z',
      to: '2026-11-12T00:00:00.000Z',
      granularity: 'day',
      totals: { total: 4, successRate: 0.75 },
      latency: { delivered: 3, averageMs: 13_867, p50UpperBoundMs: 1000, p95UpperBoundMs: 60_000 },
    });
    expect(res.body.buckets).toHaveLength(2);
    expect(res.body.buckets[0].statuses).toMatchObject({ delivered: 3, failed: 1, bounced: 0 });
    expect(res.body.buckets[1]).toMatchObject({ total: 0, successRate: null });
    expect(res.body.latency.histogram).toHaveLength(DELIVERY_LATENCY_BOUNDS_MS.length + 1);
  });

  it('accepts API keys with report:read', async () => {
    const res = await get('/api/v1/reports/delivery', t.principals.apiKeyHeaders);
    expect(res.status).toBe(200);
    expect(res.body.totals.successRate).toBeNull();
    expect(res.body.latency.averageMs).toBeNull();
  });

  it('maps a query timeout to 503 report_timeout and caches per organization', async () => {
    let calls = 0;
    t.doubles.reports.deliveries = () => {
      calls += 1;
      return Promise.resolve([]);
    };
    await get('/api/v1/reports/delivery?granularity=hour');
    await get('/api/v1/reports/delivery?granularity=hour');
    expect(calls).toBe(1);
    expect([...t.kv.entries.keys()].some((k) => /^rpt:v1:1:delivery:[0-9a-f]{64}$/.test(k))).toBe(
      true,
    );
    t.kv.entries.clear();
    t.doubles.reports.deliveries = () => Promise.reject(new ReportQueryTimeoutError('deliveries'));
    expectCoded((await get('/api/v1/reports/delivery')).body, 'report_timeout');
  });
});

describe('GET /reports/processing (step 7.1 §3.3)', () => {
  it('returns rounds by status and the time to verdict per bucket and in total', async () => {
    t.doubles.reports.scanRounds = () =>
      Promise.resolve([
        {
          bucket: new Date('2026-11-12T08:00:00.000Z'),
          status: 'completed',
          count: 2,
          latency: latency(PROCESSING_LATENCY_BOUNDS_MS, [200, 1_000_000]),
        },
        {
          bucket: new Date('2026-11-12T09:00:00.000Z'),
          status: 'timed_out',
          count: 1,
          latency: latency(PROCESSING_LATENCY_BOUNDS_MS, []),
        },
      ]);
    const res = await get(
      '/api/v1/reports/processing?from=2026-11-12T08:00:00Z&to=2026-11-12T10:00:00Z&granularity=hour',
    );
    expect(res.status).toBe(200);
    expect(ProcessingReportSchema.safeParse(res.body).success).toBe(true);
    expect(res.body.buckets).toEqual([
      {
        start: '2026-11-12T08:00:00.000Z',
        rounds: 2,
        statuses: { pending: 0, running: 0, completed: 2, failed: 0, timed_out: 0 },
        averageMs: 500_100,
        p95UpperBoundMs: null,
      },
      {
        start: '2026-11-12T09:00:00.000Z',
        rounds: 1,
        statuses: { pending: 0, running: 0, completed: 0, failed: 0, timed_out: 1 },
        averageMs: null,
        p95UpperBoundMs: null,
      },
    ]);
    expect(res.body.totals).toMatchObject({ rounds: 3, p50UpperBoundMs: 250 });
    expect(res.body.totals.histogram.at(-1)).toEqual({ leMs: null, count: 1 });
    expect(res.body.definition).toContain('completed rounds only');
  });

  it('accepts API keys and maps a timeout to 503 report_timeout', async () => {
    expect((await get('/api/v1/reports/processing', t.principals.apiKeyHeaders)).status).toBe(200);
    t.kv.entries.clear();
    t.doubles.reports.scanRounds = () => Promise.reject(new ReportQueryTimeoutError('scan_rounds'));
    expectCoded((await get('/api/v1/reports/processing')).body, 'report_timeout');
  });
});

describe('GET /reports/top-domains (step 7.1 §3.3)', () => {
  const domain = (id: bigint, name: string, deleted = false) => ({
    id,
    publicId: `01930c2e-7d1a-7000-8000-${id.toString().padStart(12, '0')}`,
    name,
    status: deleted ? 'deleted' : 'active',
    deleted,
  });

  it('ranks domains with threats and counts unattributed messages', async () => {
    t.doubles.reports.domainVerdicts = () =>
      Promise.resolve([
        { domainId: 1n, verdict: 'phishing', count: 4 },
        { domainId: 1n, verdict: 'clean', count: 6 },
        { domainId: 2n, verdict: 'spam', count: 9 },
        { domainId: 3n, verdict: 'clean', count: 99 },
        { domainId: null, verdict: 'bec', count: 1 },
      ]);
    t.doubles.reports.domains = (_scope: unknown, ids: bigint[]) =>
      Promise.resolve(
        new Map(
          [domain(1n, 'alpha.example.test'), domain(2n, 'old.example.test', true)]
            .filter((d) => ids.includes(d.id))
            .map((d) => [d.id, d]),
        ),
      );
    const res = await get('/api/v1/reports/top-domains?limit=5');
    expect(res.status).toBe(200);
    expect(TopDomainsReportSchema.safeParse(res.body).success).toBe(true);
    expect(res.body.threatVerdicts).toEqual(['spam', 'phishing', 'malware', 'bec', 'suspicious']);
    expect(
      res.body.domains.map((d: Record<string, unknown>) => [
        d.name,
        d.threats,
        d.inbound,
        d.deleted,
      ]),
    ).toEqual([
      ['old.example.test', 9, 9, true],
      ['alpha.example.test', 4, 10, false],
    ]);
    expect(res.body.domains[0].domainId).toBe('01930c2e-7d1a-7000-8000-000000000002');
    expect(res.body.unattributed).toEqual({ inbound: 1, threats: 1 });
  });

  it('answers 503 inconsistent_read when a domain does not resolve in the tenant', async () => {
    t.doubles.reports.domainVerdicts = () =>
      Promise.resolve([{ domainId: 7n, verdict: 'spam', count: 1 }]);
    t.doubles.reports.domains = () => Promise.reject(new InconsistentReadError('report_domains'));
    const res = await get('/api/v1/reports/top-domains');
    expect(res.status).toBe(503);
    expectCoded(res.body, 'inconsistent_read');
  });

  it('accepts API keys and maps a timeout to 503 report_timeout', async () => {
    const ok = await get('/api/v1/reports/top-domains', t.principals.apiKeyHeaders);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ domains: [], unattributed: { inbound: 0, threats: 0 } });
    t.kv.entries.clear();
    t.doubles.reports.domainVerdicts = () =>
      Promise.reject(new ReportQueryTimeoutError('domain_verdicts'));
    expectCoded((await get('/api/v1/reports/top-domains')).body, 'report_timeout');
  });
});

describe('step 7.1 report queries are strict', () => {
  it('refuses unknown parameters, bad granularity, ranges over the limit and bad limits', async () => {
    const cases: Array<[string, string]> = [];
    for (const path of ['delivery', 'processing']) {
      for (const query of [
        'foo=1',
        'granularity=week',
        'limit=5',
        'from=yesterday',
        'from=2026-11-01T00:00:00Z&to=2026-11-09T00:00:00Z&granularity=hour',
        'from=2026-10-01T00:00:00Z&to=2026-11-09T00:00:00Z&granularity=day',
        'from=2026-11-09T00:00:00Z&to=2026-11-09T00:00:00Z',
      ]) {
        cases.push([path, query]);
      }
    }
    for (const query of [
      'foo=1',
      'granularity=hour',
      'limit=0',
      'limit=26',
      'limit=2.5',
      'limit=ten',
      'from=2026-10-01T00:00:00Z&to=2026-11-09T00:00:00Z',
    ]) {
      cases.push(['top-domains', query]);
    }
    for (const [path, query] of cases) {
      const res = await get(`/api/v1/reports/${path}?${query}`);
      expect(res.status, `${path}?${query}`).toBe(400);
      expectCoded(res.body, 'validation_failed');
    }
    for (const ok of [
      'delivery?from=2026-11-02T00:00:00Z&to=2026-11-09T00:00:00Z&granularity=hour',
      'processing?from=2026-10-09T00:00:00Z&to=2026-11-09T00:00:00Z&granularity=day',
      'top-domains?limit=1',
      'top-domains?limit=25',
    ]) {
      expect((await get(`/api/v1/reports/${ok}`)).status, ok).toBe(200);
    }
  });
});

describe('report RBAC', () => {
  it('refuses users and API keys without report:read (403) and anonymous callers (401)', async () => {
    t.principals.user(['audit:read', 'organization:read']);
    t.principals.apiKeyWith(['audit:read']);
    for (const path of ALL_REPORTS) {
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

  it('counts the step 7.1 reports against the same expensive budget', async () => {
    const limited = await createInsightApp({ API_RATE_EXPENSIVE_PER_MINUTE: '2' });
    try {
      limited.principals.user(['report:read']);
      const auth = await limited.principals.bearer();
      const first = await limited.http().get('/api/v1/reports/delivery').set(auth);
      expect(first.status).toBe(200);
      expect(first.headers['ratelimit-limit']).toBe('2');
      expect((await limited.http().get('/api/v1/reports/processing').set(auth)).status).toBe(200);
      const third = await limited.http().get('/api/v1/reports/top-domains').set(auth);
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
    for (const path of ALL_REPORTS) {
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

describe('report examples (D14)', () => {
  it('every step 7.1 example and the extended threats example match their response schema', () => {
    expect(ThreatsReportSchema.safeParse(THREATS_REPORT_EXAMPLE).success).toBe(true);
    expect(DeliveryReportSchema.safeParse(DELIVERY_REPORT_EXAMPLE).success).toBe(true);
    expect(ProcessingReportSchema.safeParse(PROCESSING_REPORT_EXAMPLE).success).toBe(true);
    expect(TopDomainsReportSchema.safeParse(TOP_DOMAINS_REPORT_EXAMPLE).success).toBe(true);
    // The outcomes example adds up to the verdict and action marginals.
    const m = THREATS_REPORT_EXAMPLE.messages;
    const sum = (key: 'verdict' | 'action', value: string) =>
      THREATS_REPORT_EXAMPLE.outcomes
        .filter((o) => o[key] === value)
        .reduce((a, o) => a + o.count, 0);
    for (const [verdict, n] of Object.entries(m.verdicts))
      expect(sum('verdict', verdict), verdict).toBe(n);
    for (const [action, n] of Object.entries(m.actions))
      expect(sum('action', action), action).toBe(n);
  });

  it('documents the examples on the operations', () => {
    const doc = buildOpenApiDocument(t.app);
    for (const [path, example] of [
      ['delivery', DELIVERY_REPORT_EXAMPLE],
      ['processing', PROCESSING_REPORT_EXAMPLE],
      ['top-domains', TOP_DOMAINS_REPORT_EXAMPLE],
    ] as const) {
      const op = doc.paths[`/api/v1/reports/${path}`]!.get as unknown as {
        responses: Record<string, { content?: Record<string, { example?: unknown }> }>;
      };
      expect(op.responses['200']!.content!['application/json']!.example).toEqual(example);
    }
  });
});
