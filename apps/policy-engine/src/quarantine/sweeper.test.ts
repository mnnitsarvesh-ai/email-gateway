import { MetricsService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { QuarantineMetrics } from '../metrics/quarantine-metrics';
import { InconsistentQuarantineReadError } from './errors';
import { isOrganizationKey, messageObjectPrefixes } from './disposal';
import { QUARANTINE_SWEEPER_LOCK, QuarantineSweeper } from './sweeper';

/** A writer client whose every read is empty (no work due) unless a test overrides a model. */
function emptyPrisma(over: Record<string, Record<string, unknown>> = {}) {
  const model = (name: string) =>
    new Proxy(
      {},
      {
        get(_t, op: string) {
          const custom = over[name]?.[op];
          if (custom !== undefined) return custom;
          if (op === 'findMany' || op === 'groupBy') return () => Promise.resolve([]);
          if (op === 'count') return () => Promise.resolve(0);
          if (op === 'deleteMany' || op === 'updateMany')
            return () => Promise.resolve({ count: 0 });
          return () => Promise.resolve(null);
        },
      },
    );
  return new Proxy(
    {},
    {
      get(_t, prop: string) {
        if (prop === '$queryRaw') return () => Promise.resolve([]);
        if (prop === '$transaction') return (fn: (tx: unknown) => unknown) => fn({});
        return model(prop);
      },
    },
  );
}

function sweeper(options: {
  ensure?: () => Promise<boolean>;
  prisma?: unknown;
  digests?: () => Promise<{ runs: number; digests: number; alerts: number }>;
}) {
  const service = new MetricsService({ service: 't' });
  const metrics = new QuarantineMetrics(service);
  const locks = {
    ensure: vi.fn(options.ensure ?? (() => Promise.resolve(true))),
    release: vi.fn(() => Promise.resolve()),
  };
  const s = new QuarantineSweeper({
    prisma: (options.prisma ?? emptyPrisma()) as never,
    locks,
    objects: { exists: vi.fn(), purgeKey: vi.fn(), purgePrefix: vi.fn() },
    store: { casEntry: vi.fn(), cancelPendingRequests: vi.fn(), createEntries: vi.fn() },
    settings: { resolve: vi.fn() },
    disposal: { read: vi.fn() },
    digests: {
      run: vi.fn(options.digests ?? (() => Promise.resolve({ runs: 0, digests: 0, alerts: 0 }))),
    },
    metrics,
    lifecycleMetrics: {
      transition: vi.fn(),
      ignored: vi.fn(),
      versionConflict: vi.fn(),
      derivedSkipped: vi.fn(),
    },
    sink: vi.fn(),
    logger: createLogger({ service: 't', level: 'silent' }),
    intervalMs: 60_000,
    txTimeoutMs: 120_000,
    batchSize: 10,
    retentionDays: 186,
    bounds: { maxHoldDays: 60, maxReviewDays: 13 },
    now: () => new Date('2026-11-12T08:00:00.000Z'),
  });
  return { s, locks, service };
}

describe('QuarantineSweeper (Q19): leader election and pass isolation', () => {
  it('does nothing without the lock; reports a lock failure as a database error', async () => {
    const off = sweeper({ ensure: () => Promise.resolve(false) });
    expect((await off.s.sweepOnce()).outcome).toBe('not_leader');
    expect(off.locks.ensure).toHaveBeenCalledWith(QUARANTINE_SWEEPER_LOCK);
    expect(off.s.isLeader).toBe(false);
    expect(await off.service.metrics()).toContain('quarantine_sweeper_leader{service="t"} 0');
    const down = sweeper({ ensure: () => Promise.reject(new Error('mysql down')) });
    expect((await down.s.sweepOnce()).outcome).toBe('database_error');
  });

  it('a quiet pass as leader: swept, gauges at zero, last success stamped', async () => {
    const { s, service } = sweeper({});
    expect(await s.sweepOnce()).toMatchObject({ outcome: 'swept', failedSteps: [] });
    expect(s.isLeader).toBe(true);
    const text = await service.metrics();
    expect(text).toContain('quarantine_sweeper_leader{service="t"} 1');
    expect(text).toContain(
      'quarantine_sweep_last_success_timestamp_seconds{service="t"} 1794470400',
    );
    for (const state of ['held', 'pending_approval', 'releasing']) {
      expect(text).toContain(`quarantine_entries{state="${state}",service="t"} 0`);
    }
    expect(text).toContain('quarantine_pending_approvals{service="t"} 0');
  });

  it('a failing step does not stop the others; the pass is partial and not stamped', async () => {
    const digests = vi.fn(() => Promise.reject(new Error('digest failure')));
    const { s, service } = sweeper({ digests });
    const report = await s.sweepOnce();
    expect(report).toMatchObject({ outcome: 'partial', failedSteps: ['digests'] });
    const text = await service.metrics();
    // Gauges (after the failing step) still ran.
    expect(text).toContain('quarantine_pending_approvals{service="t"} 0');
    expect(text).toContain('quarantine_sweep_last_success_timestamp_seconds{service="t"} 0');
  });

  it('an expiry candidate that does not echo its filter is an inconsistent read (step fails)', async () => {
    const prisma = emptyPrisma({
      quarantineMessage: {
        findMany: () =>
          Promise.resolve([
            {
              messageId: 1n,
              messageReceivedAt: new Date(),
              organizationId: 7n,
              status: 'released',
              expiresAt: new Date('2020-01-01T00:00:00.000Z'),
            },
          ]),
      },
    });
    const { s } = sweeper({ prisma });
    const report = await s.sweepOnce();
    expect(report.failedSteps).toContain('expiry');
    expect(new InconsistentQuarantineReadError('entries', 'x').name).toBe(
      'InconsistentQuarantineReadError',
    );
  });
});

describe('object purge scope (Q17)', () => {
  it('purges only the message prefixes of its organization, by the UTC received date', () => {
    expect(
      messageObjectPrefixes({
        messageId: 42n,
        receivedAt: new Date('2026-01-02T23:30:00.000Z'),
        organizationId: 7n,
      }),
    ).toEqual([
      'org/7/part/2026/01/02/42/',
      'org/7/rewrite/2026/01/02/42/',
      'org/7/policy/2026/01/02/42/',
    ]);
    expect(isOrganizationKey('org/7/eml/a.eml', 7n)).toBe(true);
    expect(isOrganizationKey('org/70/eml/a.eml', 7n)).toBe(false);
    expect(isOrganizationKey('org/7/../8/eml/a.eml', 7n)).toBe(false);
    expect(isOrganizationKey('org/7//a.eml', 7n)).toBe(false);
  });
});
