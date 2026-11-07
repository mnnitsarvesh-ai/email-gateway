import { MetricsService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { BEC_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { BecMetrics } from './bec-metrics';
import { BEC_HISTORY_LOCK, BecHistorySweeper } from './history-sweeper';

const NOW = new Date('2026-11-06T10:00:00Z');
const daysAgo = (d: number) => new Date(NOW.getTime() - d * 86_400_000);

interface Row {
  id: bigint;
  organizationId: bigint;
  lastSeenAt: Date;
}

function setup(
  rows: Row[],
  settings: Record<string, unknown> = {},
  options: { leader?: boolean; lockError?: boolean; batchSize?: number; forgeRead?: boolean } = {},
) {
  const deletes: unknown[] = [];
  const history = {
    groupBy: () =>
      Promise.resolve(
        [...new Set(rows.map((r) => r.organizationId))]
          .sort()
          .map((organizationId) => ({ organizationId })),
      ),
    findMany: (args: {
      where: { organizationId: bigint; lastSeenAt: { lt: Date } };
      take: number;
    }) => {
      const found = rows
        .filter(
          (r) =>
            r.organizationId === args.where.organizationId &&
            r.lastSeenAt < args.where.lastSeenAt.lt,
        )
        .slice(0, args.take);
      return Promise.resolve(
        options.forgeRead ? found.map((r) => ({ ...r, organizationId: 999n })) : found,
      );
    },
    deleteMany: (args: {
      where: { id: { in: bigint[] }; organizationId: bigint; lastSeenAt: { lt: Date } };
    }) => {
      deletes.push(args);
      let count = 0;
      for (const id of args.where.id.in) {
        const index = rows.findIndex(
          (r) =>
            r.id === id &&
            r.organizationId === args.where.organizationId &&
            r.lastSeenAt < args.where.lastSeenAt.lt,
        );
        if (index >= 0) {
          rows.splice(index, 1);
          count += 1;
        }
      }
      return Promise.resolve({ count });
    },
  };
  const prisma = {
    becContactHistory: history,
    scanEngineSetting: {
      findUnique: (args: { where: { organizationId_engine: { organizationId: bigint } } }) => {
        const org = args.where.organizationId_engine.organizationId;
        const value = settings[org.toString()];
        return Promise.resolve(
          value === undefined ? null : { organizationId: org, engine: 'bec', settings: value },
        );
      },
    },
    $transaction: (fn: (tx: unknown) => Promise<unknown>) => fn({ becContactHistory: history }),
  } as unknown as PrismaClient;
  const registry = new MetricsService({ service: 'bec-sweeper-test' });
  const locks = {
    ensure: (name: string) => {
      expect(name).toBe(BEC_HISTORY_LOCK);
      return options.lockError
        ? Promise.reject(new Error('lock'))
        : Promise.resolve(options.leader ?? true);
    },
    release: () => Promise.resolve(),
  };
  const sweeper = new BecHistorySweeper({
    prisma,
    locks,
    metrics: BecMetrics.for(registry),
    logger: createLogger({ service: 'test', level: 'silent' }),
    platform: BEC_PLATFORM_DEFAULTS,
    intervalMs: 3_600_000,
    txTimeoutMs: 1_000,
    now: () => NOW,
    ...(options.batchSize ? { batchSize: options.batchSize } : {}),
  });
  return { sweeper, rows, deletes, registry };
}

describe('BecHistorySweeper (B12 retention)', () => {
  it('deletes rows older than the tenant retention (settings row, else the default 365 days)', async () => {
    const rows: Row[] = [
      { id: 1n, organizationId: 1n, lastSeenAt: daysAgo(400) },
      { id: 2n, organizationId: 1n, lastSeenAt: daysAgo(100) },
      { id: 3n, organizationId: 2n, lastSeenAt: daysAgo(100) },
      { id: 4n, organizationId: 2n, lastSeenAt: daysAgo(10) },
      { id: 5n, organizationId: 3n, lastSeenAt: daysAgo(500) },
    ];
    // Org 2 keeps 30 days (history may be on or off: the rule is the same); org 3 has an
    // invalid row (above the platform maximum) → the default 365 days applies.
    const t = setup(rows, {
      '2': { history: { enabled: false, retentionDays: 30 } },
      '3': { history: { retentionDays: 9999 } },
    });
    expect(await t.sweeper.sweepOnce()).toEqual({ outcome: 'swept', organizations: 3, deleted: 3 });
    expect(t.rows.map((r) => r.id)).toEqual([2n, 4n]);
    expect(await t.registry.metrics()).toMatch(/bec_history_rows_deleted_total(\{[^}]*\})? 3/);
  });

  it('works in bounded batches, each delete repeating the organization and age conditions', async () => {
    const rows: Row[] = Array.from({ length: 5 }, (_, i) => ({
      id: BigInt(i + 1),
      organizationId: 1n,
      lastSeenAt: daysAgo(400),
    }));
    const t = setup(rows, {}, { batchSize: 2 });
    expect((await t.sweeper.sweepOnce()).deleted).toBe(5);
    expect(t.deletes).toHaveLength(3);
    expect(t.deletes[0]).toMatchObject({
      where: { organizationId: 1n, lastSeenAt: { lt: daysAgo(365) } },
    });
  });

  it('only the leader sweeps; lock errors and forged reads are database errors (nothing deleted)', async () => {
    const rows = (): Row[] => [{ id: 1n, organizationId: 1n, lastSeenAt: daysAgo(400) }];
    expect((await setup(rows(), {}, { leader: false }).sweeper.sweepOnce()).outcome).toBe(
      'not_leader',
    );
    expect((await setup(rows(), {}, { lockError: true }).sweeper.sweepOnce()).outcome).toBe(
      'database_error',
    );
    const forged = setup(rows(), {}, { forgeRead: true });
    expect(await forged.sweeper.sweepOnce()).toMatchObject({
      outcome: 'database_error',
      deleted: 0,
    });
    expect(forged.rows).toHaveLength(1);
    expect(await forged.registry.metrics()).toMatch(
      /scan_bec_inconsistent_reads_total\{read="history"[^}]*\} 1/,
    );
  });
});
