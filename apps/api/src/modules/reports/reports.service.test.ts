import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { InMemoryKeyValueStore } from '../../../test/support/in-memory-key-value-store';
import { ReportExecutor } from './report-executor';
import type { ReportMetrics } from './report-metrics';
import type { ReportsRepository } from './reports.repository';
import { ReportsService } from './reports.service';

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
