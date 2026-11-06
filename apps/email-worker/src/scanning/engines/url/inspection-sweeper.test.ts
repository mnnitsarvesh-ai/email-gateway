import { MetricsService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { InspectionSweeper, URL_INSPECTION_LOCK } from './inspection-sweeper';
import { UrlMetrics } from './url-metrics';

const NOW = new Date('2026-11-06T10:00:00Z');
const OLD = new Date(NOW.getTime() - 2 * 3_600_000);

interface Row {
  id: bigint;
  receivedAt: Date;
  status: string;
  createdAt: Date;
}

function setup(
  rows: Row[],
  options: { leader?: boolean; lockError?: boolean; batchSize?: number } = {},
) {
  const finds: unknown[] = [];
  const updates: unknown[] = [];
  const tx = {
    urlDynamicInspection: {
      findMany: (args: { take: number }) => {
        finds.push(args);
        return Promise.resolve(rows.filter((r) => r.status === 'pending').slice(0, args.take));
      },
      updateMany: (args: { where: { OR: Array<{ id: bigint }> } }) => {
        updates.push(args);
        let count = 0;
        for (const ref of args.where.OR) {
          const row = rows.find((r) => r.id === ref.id && r.status === 'pending');
          if (row) {
            row.status = 'expired';
            count += 1;
          }
        }
        return Promise.resolve({ count });
      },
    },
  };
  const prisma = {
    $transaction: (fn: (t: typeof tx) => Promise<unknown>) => fn(tx),
  } as unknown as PrismaClient;
  const registry = new MetricsService({ service: 'url-sweeper-test' });
  const locks = {
    names: [] as string[],
    ensure: (name: string) => {
      locks.names.push(name);
      return options.lockError
        ? Promise.reject(new Error('db'))
        : Promise.resolve(options.leader ?? true);
    },
    release: () => Promise.resolve(),
  };
  const sweeper = new InspectionSweeper({
    prisma,
    locks,
    metrics: UrlMetrics.for(registry),
    logger: createLogger({ service: 'url-sweeper-test', level: 'silent' }),
    intervalMs: 60_000,
    pendingTtlSeconds: 3_600,
    txTimeoutMs: 120_000,
    now: () => NOW,
    ...(options.batchSize ? { batchSize: options.batchSize } : {}),
  });
  return { sweeper, finds, updates, registry, locks };
}

const pending = (id: number, createdAt = OLD): Row => ({
  id: BigInt(id),
  receivedAt: new Date('2026-11-05T00:00:00Z'),
  status: 'pending',
  createdAt,
});

describe('pending-inspection sweeper (U15)', () => {
  it('expires pending rows older than the TTL in batches, as the leader of scan:url-inspections', async () => {
    const rows = [pending(1), pending(2), pending(3), pending(4), pending(5)];
    const s = setup(rows, { batchSize: 2 });
    expect(await s.sweeper.sweepOnce()).toEqual({ outcome: 'swept', expired: 5 });
    expect(s.locks.names).toEqual([URL_INSPECTION_LOCK]);
    expect(rows.every((r) => r.status === 'expired')).toBe(true);
    expect(s.finds[0]).toMatchObject({
      where: { status: 'pending', createdAt: { lt: new Date(NOW.getTime() - 3_600_000) } },
      orderBy: { createdAt: 'asc' },
      take: 2,
    });
    expect(s.updates[0]).toMatchObject({
      where: { status: 'pending', createdAt: { lt: new Date(NOW.getTime() - 3_600_000) } },
      data: { status: 'expired' },
    });
    expect(await s.registry.metrics()).toMatch(
      /scan_url_dynamic_inspections_total\{[^}]*status="expired"[^}]*\} 5/,
    );
  });

  it('does nothing without the lock, and reports a lock error', async () => {
    const rows = [pending(1)];
    expect(await setup(rows, { leader: false }).sweeper.sweepOnce()).toEqual({
      outcome: 'not_leader',
      expired: 0,
    });
    expect(await setup(rows, { lockError: true }).sweeper.sweepOnce()).toEqual({
      outcome: 'database_error',
      expired: 0,
    });
    expect(rows[0]!.status).toBe('pending');
  });

  it('refuses a read that returned rows outside the request (wrong read)', async () => {
    const rows = [pending(1, new Date(NOW.getTime() - 60_000))];
    const s = setup(rows);
    expect(await s.sweeper.sweepOnce()).toEqual({ outcome: 'database_error', expired: 0 });
    expect(rows[0]!.status).toBe('pending');
    expect(await s.registry.metrics()).toMatch(
      /scan_url_inconsistent_reads_total\{[^}]*read="inspection"[^}]*\} 1/,
    );
  });

  it('starts and stops its loop', async () => {
    const s = setup([]);
    s.sweeper.start();
    expect(s.sweeper.running).toBe(true);
    await s.sweeper.stop();
    expect(s.sweeper.running).toBe(false);
  });
});
