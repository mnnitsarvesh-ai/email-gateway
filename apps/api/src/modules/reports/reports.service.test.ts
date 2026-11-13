import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { InMemoryKeyValueStore } from '../../../test/support/in-memory-key-value-store';
import { ReportExecutor } from './report-executor';
import type { ReportMetrics } from './report-metrics';
import type { ReportsRepository } from './reports.repository';
import { InconsistentReadError } from '../../http/listing/echo-check';
import {
  DELIVERY_LATENCY_BOUNDS_MS,
  PROCESSING_LATENCY_BOUNDS_MS,
} from './domain/latency-histogram';
import {
  DeliveryReportSchema,
  ProcessingReportSchema,
  ThreatsReportSchema,
  TopDomainsReportSchema,
} from './reports.schemas';
import { outcomePairs, ReportsService } from './reports.service';

const now = new Date('2026-11-12T10:30:00.000Z');
const scope = systemScope(7n);

function setup(repo: Partial<ReportsRepository>) {
  const metrics = {
    duration: { observe: vi.fn() },
    cache: { inc: vi.fn() },
    timeouts: { inc: vi.fn() },
  };
  const executor = new ReportExecutor(
    new InMemoryKeyValueStore(),
    metrics as unknown as ReportMetrics,
    {
      REPORTS_CACHE_TTL_SECONDS: 60,
    },
  );
  return new ReportsService(repo as ReportsRepository, executor, { REPORTS_MAX_RANGE_DAYS: 31 });
}

describe('ReportsService', () => {
  it('traffic: zero-filled aligned buckets, counts by direction and verdict (null → none)', async () => {
    const traffic = vi.fn(() =>
      Promise.resolve([
        {
          bucket: new Date('2026-11-12T08:00:00.000Z'),
          direction: 'inbound' as const,
          verdict: 'clean' as const,
          count: 3,
        },
        {
          bucket: new Date('2026-11-12T08:00:00.000Z'),
          direction: 'outbound' as const,
          verdict: null,
          count: 2,
        },
        {
          bucket: new Date('2026-11-12T10:00:00.000Z'),
          direction: 'internal' as const,
          verdict: 'spam' as const,
          count: 1,
        },
      ]),
    );
    const service = setup({ traffic });
    const report = await service.traffic(
      scope,
      {
        from: new Date('2026-11-12T07:59:00.000Z'),
        to: new Date('2026-11-12T10:01:00.000Z'),
        granularity: 'hour',
      },
      now,
    );
    expect(report.from).toBe('2026-11-12T07:00:00.000Z');
    expect(report.to).toBe('2026-11-12T11:00:00.000Z');
    expect(report.buckets.map((b) => [b.start, b.total])).toEqual([
      ['2026-11-12T07:00:00.000Z', 0],
      ['2026-11-12T08:00:00.000Z', 5],
      ['2026-11-12T09:00:00.000Z', 0],
      ['2026-11-12T10:00:00.000Z', 1],
    ]);
    expect(report.buckets[1]).toMatchObject({ inbound: 3, outbound: 2, internal: 0 });
    expect(report.buckets[1]!.verdicts).toMatchObject({ clean: 3, none: 2, spam: 0 });
    expect(report.totals).toMatchObject({ total: 6, inbound: 3, outbound: 2, internal: 1 });
    expect(report.totals.verdicts).toMatchObject({ clean: 3, spam: 1, none: 2, phishing: 0 });
    expect(traffic).toHaveBeenCalledWith(
      scope,
      expect.objectContaining({ from: new Date('2026-11-12T07:00:00.000Z') }),
      'hour',
      undefined,
    );
  });

  it('threats: verdict, action, reason and engine counts', async () => {
    const service = setup({
      outcomes: () =>
        Promise.resolve([
          { verdict: 'phishing', action: 'quarantine', count: 4 },
          { verdict: null, action: null, count: 1 },
        ]),
      quarantine: () =>
        Promise.resolve([
          { reason: 'phishing', primaryEngine: 'url', count: 3 },
          { reason: 'manual', primaryEngine: 'none', count: 1 },
        ]),
    });
    const report = await service.threats(scope, {}, now);
    expect(report.from).toBe('2026-11-05T10:00:00.000Z');
    expect(report.to).toBe('2026-11-12T11:00:00.000Z');
    expect(report.messages.total).toBe(5);
    expect(report.messages.verdicts).toMatchObject({ phishing: 4, none: 1, clean: 0 });
    expect(report.messages.actions).toMatchObject({ quarantine: 4, none: 1, deliver: 0 });
    expect(report.quarantine).toMatchObject({ total: 4 });
    expect(report.quarantine.reasons).toMatchObject({ phishing: 3, manual: 1, spam: 0 });
    expect(report.quarantine.primaryEngines).toMatchObject({ url: 3, none: 1, rspamd: 0 });
  });

  it('url clicks: buckets by decision; a second identical call is served from the cache', async () => {
    const clicks = vi.fn(() =>
      Promise.resolve([
        { bucket: new Date('2026-11-11T00:00:00.000Z'), decision: 'blocked' as const, count: 2 },
        { bucket: new Date('2026-11-12T00:00:00.000Z'), decision: 'allowed' as const, count: 5 },
      ]),
    );
    const service = setup({ clicks });
    const first = await service.urlClicks(scope, { granularity: 'day' }, now);
    expect(first.buckets).toHaveLength(8);
    expect(first.totals).toEqual({
      total: 7,
      decisions: { allowed: 5, warned: 0, blocked: 2, continued: 0, expired: 0, not_found: 0 },
    });
    const second = await service.urlClicks(
      scope,
      { granularity: 'day' },
      new Date(now.getTime() + 60_000),
    );
    expect(second).toEqual(first);
    expect(clicks).toHaveBeenCalledTimes(1);
  });
});

/** Latency samples whose values (ms) fall at the given bounds. */
function latency(bounds: readonly number[], valuesMs: number[]) {
  return {
    samples: valuesMs.length,
    sumUs: valuesMs.reduce((a, v) => a + v * 1000, 0),
    cumulative: bounds.map((b) => valuesMs.filter((v) => v <= b).length),
  };
}
const noLatency = (bounds: readonly number[]) => latency(bounds, []);

describe('threats outcomes (step 7.1 P15)', () => {
  it('lists non-zero verdict × action pairs by count desc, then verdict and action', () => {
    expect(
      outcomePairs([
        { verdict: 'spam', action: 'tag', count: 3 },
        { verdict: null, action: null, count: 3 },
        { verdict: 'clean', action: 'deliver', count: 10 },
        { verdict: 'bulk', action: 'tag', count: 3 },
        { verdict: 'spam', action: 'quarantine', count: 3 },
        { verdict: 'phishing', action: 'reject', count: 0 },
      ]),
    ).toEqual([
      { verdict: 'clean', action: 'deliver', count: 10 },
      { verdict: 'bulk', action: 'tag', count: 3 },
      { verdict: 'none', action: 'none', count: 3 },
      { verdict: 'spam', action: 'quarantine', count: 3 },
      { verdict: 'spam', action: 'tag', count: 3 },
    ]);
  });

  it('is part of the threats report and matches its schema', async () => {
    const service = setup({
      outcomes: () =>
        Promise.resolve([
          { verdict: 'phishing', action: 'quarantine', count: 4 },
          { verdict: null, action: 'deliver', count: 1 },
        ]),
      quarantine: () => Promise.resolve([]),
    });
    const report = await service.threats(scope, {}, now);
    expect(report.outcomes).toEqual([
      { verdict: 'phishing', action: 'quarantine', count: 4 },
      { verdict: 'none', action: 'deliver', count: 1 },
    ]);
    expect(ThreatsReportSchema.safeParse(report).success).toBe(true);
  });
});

describe('delivery report (step 7.1 §3.3)', () => {
  it('counts statuses per bucket, success rates and the latency histogram', async () => {
    const deliveries = vi.fn(() =>
      Promise.resolve([
        {
          bucket: new Date('2026-11-11T00:00:00.000Z'),
          status: 'delivered' as const,
          count: 3,
          latency: latency(DELIVERY_LATENCY_BOUNDS_MS, [500, 2000, 7_200_000]),
        },
        {
          bucket: new Date('2026-11-11T00:00:00.000Z'),
          status: 'bounced' as const,
          count: 1,
          latency: noLatency(DELIVERY_LATENCY_BOUNDS_MS),
        },
        {
          bucket: new Date('2026-11-12T00:00:00.000Z'),
          status: 'deferred' as const,
          count: 2,
          latency: noLatency(DELIVERY_LATENCY_BOUNDS_MS),
        },
        {
          bucket: new Date('2026-11-12T00:00:00.000Z'),
          status: 'delivered' as const,
          count: 1,
          latency: latency(DELIVERY_LATENCY_BOUNDS_MS, [100_000_000]),
        },
      ]),
    );
    const service = setup({ deliveries });
    const report = await service.delivery(
      scope,
      { from: new Date('2026-11-11T03:00:00Z'), to: new Date('2026-11-12T03:00:00Z') },
      now,
    );
    expect(DeliveryReportSchema.safeParse(report).success).toBe(true);
    expect(report.granularity).toBe('day');
    expect(report.buckets.map((b) => [b.start, b.total, b.successRate])).toEqual([
      ['2026-11-11T00:00:00.000Z', 4, 0.75],
      ['2026-11-12T00:00:00.000Z', 3, 1],
    ]);
    expect(report.totals).toMatchObject({ total: 7, successRate: 0.8 });
    expect(report.totals.statuses).toMatchObject({
      delivered: 4,
      bounced: 1,
      deferred: 2,
      failed: 0,
    });
    expect(report.latency).toMatchObject({
      delivered: 4,
      averageMs: Math.round((500 + 2000 + 7_200_000 + 100_000_000) / 4),
      p50UpperBoundMs: 5000,
      p95UpperBoundMs: null,
    });
    expect(report.latency.histogram).toHaveLength(DELIVERY_LATENCY_BOUNDS_MS.length + 1);
    expect(report.latency.histogram.filter((b) => b.count > 0)).toEqual([
      { leMs: 1000, count: 1 },
      { leMs: 5000, count: 1 },
      { leMs: 14_400_000, count: 1 },
      { leMs: null, count: 1 },
    ]);
  });

  it('is zero-filled with null rates and latency when nothing was delivered', async () => {
    const service = setup({ deliveries: () => Promise.resolve([]) });
    const report = await service.delivery(scope, { granularity: 'hour' }, now);
    expect(report.buckets).toHaveLength(25);
    expect(report.buckets.every((b) => b.total === 0 && b.successRate === null)).toBe(true);
    expect(report.latency).toMatchObject({
      delivered: 0,
      averageMs: null,
      p50UpperBoundMs: null,
      p95UpperBoundMs: null,
    });
    expect(DeliveryReportSchema.safeParse(report).success).toBe(true);
  });
});

describe('processing report (step 7.1 §3.3)', () => {
  it('counts rounds by status and the time to verdict per bucket and in total', async () => {
    const scanRounds = vi.fn(() =>
      Promise.resolve([
        {
          bucket: new Date('2026-11-12T08:00:00.000Z'),
          status: 'completed' as const,
          count: 4,
          latency: latency(PROCESSING_LATENCY_BOUNDS_MS, [100, 300, 300, 4000]),
        },
        {
          bucket: new Date('2026-11-12T08:00:00.000Z'),
          status: 'running' as const,
          count: 1,
          latency: noLatency(PROCESSING_LATENCY_BOUNDS_MS),
        },
        {
          bucket: new Date('2026-11-12T09:00:00.000Z'),
          status: 'timed_out' as const,
          count: 2,
          latency: noLatency(PROCESSING_LATENCY_BOUNDS_MS),
        },
      ]),
    );
    const service = setup({ scanRounds });
    const report = await service.processing(
      scope,
      {
        from: new Date('2026-11-12T08:00:00Z'),
        to: new Date('2026-11-12T10:00:00Z'),
        granularity: 'hour',
      },
      now,
    );
    expect(ProcessingReportSchema.safeParse(report).success).toBe(true);
    expect(report.buckets).toEqual([
      {
        start: '2026-11-12T08:00:00.000Z',
        rounds: 5,
        statuses: { pending: 0, running: 1, completed: 4, failed: 0, timed_out: 0 },
        averageMs: 1175,
        p95UpperBoundMs: 5000,
      },
      {
        start: '2026-11-12T09:00:00.000Z',
        rounds: 2,
        statuses: { pending: 0, running: 0, completed: 0, failed: 0, timed_out: 2 },
        averageMs: null,
        p95UpperBoundMs: null,
      },
    ]);
    expect(report.totals).toMatchObject({
      rounds: 7,
      averageMs: 1175,
      p50UpperBoundMs: 500,
      p95UpperBoundMs: 5000,
    });
    expect(report.totals.histogram.slice(0, 5)).toEqual([
      { leMs: 250, count: 1 },
      { leMs: 500, count: 2 },
      { leMs: 1000, count: 0 },
      { leMs: 2000, count: 0 },
      { leMs: 5000, count: 1 },
    ]);
    expect(report.definition).toContain('initial scan round');
  });
});

describe('top-domains report (step 7.1 §3.3)', () => {
  const domain = (id: bigint, name: string, deleted = false) => ({
    id,
    publicId: `01930c2e-7d1a-7000-8000-${id.toString().padStart(12, '0')}`,
    name,
    status: deleted ? ('deleted' as const) : ('active' as const),
    deleted,
  });

  it('ranks domains with threats, resolves names in the tenant and counts unattributed mail', async () => {
    const domains = vi.fn((_scope: unknown, ids: readonly bigint[]) =>
      Promise.resolve(
        new Map(
          [domain(1n, 'b.example.test'), domain(2n, 'a.example.test', true), domain(3n, 'c.test')]
            .filter((d) => ids.includes(d.id))
            .map((d) => [d.id, d]),
        ),
      ),
    );
    const service = setup({
      domainVerdicts: () =>
        Promise.resolve([
          { domainId: 1n, verdict: 'spam', count: 2 },
          { domainId: 1n, verdict: 'clean', count: 5 },
          { domainId: 2n, verdict: 'phishing', count: 2 },
          { domainId: 2n, verdict: 'clean', count: 5 },
          { domainId: 3n, verdict: 'clean', count: 50 },
          { domainId: null, verdict: 'malware', count: 1 },
          { domainId: null, verdict: null, count: 2 },
        ]),
      domains,
    });
    const report = await service.topDomains(scope, { limit: 5 }, now);
    expect(TopDomainsReportSchema.safeParse(report).success).toBe(true);
    expect(report.from).toBe('2026-11-05T10:00:00.000Z');
    // Tie on threats and inbound: name decides (a before b). Domain 3 has no threats.
    expect(report.domains.map((d) => [d.name, d.deleted, d.threats, d.inbound])).toEqual([
      ['a.example.test', true, 2, 7],
      ['b.example.test', false, 2, 7],
    ]);
    expect(report.domains[0]!.verdicts).toEqual({
      spam: 0,
      phishing: 2,
      malware: 0,
      bec: 0,
      suspicious: 0,
    });
    expect(report.domains[0]!.domainId).toMatch(/^01930c2e-/);
    expect(report.unattributed).toEqual({ inbound: 3, threats: 1 });
    expect(domains).toHaveBeenCalledWith(scope, [1n, 2n]);
  });

  it('applies the limit after the name tie-break', async () => {
    const service = setup({
      domainVerdicts: () =>
        Promise.resolve([
          { domainId: 1n, verdict: 'spam', count: 1 },
          { domainId: 2n, verdict: 'spam', count: 1 },
        ]),
      domains: () =>
        Promise.resolve(
          new Map([
            [1n, domain(1n, 'z.test')],
            [2n, domain(2n, 'y.test')],
          ]),
        ),
    });
    const report = await service.topDomains(scope, { limit: 1 }, now);
    expect(report.domains.map((d) => d.name)).toEqual(['y.test']);
  });

  it('never shows a domain that does not resolve in the tenant (503 inconsistent_read)', async () => {
    const service = setup({
      domainVerdicts: () => Promise.resolve([{ domainId: 9n, verdict: 'spam', count: 1 }]),
      domains: () => Promise.reject(new InconsistentReadError('report_domains')),
    });
    await expect(service.topDomains(scope, {}, now)).rejects.toBeInstanceOf(InconsistentReadError);
  });

  it('caches per limit and window', async () => {
    const domainVerdicts = vi.fn(() => Promise.resolve([]));
    const service = setup({ domainVerdicts, domains: () => Promise.resolve(new Map()) });
    await service.topDomains(scope, {}, now);
    await service.topDomains(scope, { limit: 10 }, now);
    expect(domainVerdicts).toHaveBeenCalledTimes(1);
    await service.topDomains(scope, { limit: 3 }, now);
    expect(domainVerdicts).toHaveBeenCalledTimes(2);
  });
});
