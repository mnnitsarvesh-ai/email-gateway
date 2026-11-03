import {
  PARTITION_REGISTRY,
  PrismaClient,
  type PartitionSpec,
  createMaintenanceClientUrl,
  parsePartitionName,
  periodStart,
  runPartitionMaintenance,
} from '@email-gateway/database';
import { createConnection, type RowDataPacket } from 'mysql2/promise';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * Partition maintenance (D3) against the dev schema, as the migrator account: after an apply,
 * every registered table has partitions ahead of today plus pmax, and a second apply is a
 * no-op. Retention purges are left to the CLI and unit tests so this suite never deletes dev
 * data. A scratch table checks exact names, splits and drops at fixed dates.
 */
// One connection, as in the CLI: the advisory lock and lock_wait_timeout are per-connection.
const prisma = new PrismaClient({
  datasourceUrl: createMaintenanceClientUrl(stack.migrationDatabaseUrl()),
});
const silent = { info: () => {}, warn: () => {}, error: () => {} };
const PROBE = 'it_partition_probe';

afterAll(async () => {
  await prisma.$executeRawUnsafe(`DROP TABLE IF EXISTS \`${PROBE}\``);
  await prisma.$disconnect();
});

async function partitionNames(table: string): Promise<string[]> {
  const rows = await prisma.$queryRawUnsafe<{ name: string }[]>(
    `SELECT PARTITION_NAME AS name FROM information_schema.PARTITIONS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND PARTITION_NAME IS NOT NULL
      ORDER BY PARTITION_ORDINAL_POSITION`,
    table,
  );
  return rows.map((r) => r.name);
}

describe('partition maintenance', () => {
  it('manages the 19 partitioned tables, including the step 2.3 and 3.1 tables', () => {
    expect(PARTITION_REGISTRY).toHaveLength(19);
    expect(PARTITION_REGISTRY.map((s) => s.table)).toEqual(
      expect.arrayContaining([
        'delivery_reinjections',
        'delivery_status_events',
        'email_message_parses',
      ]),
    );
  });

  it('creates partitions ahead for every registered table, and a second apply is a no-op', async () => {
    const now = new Date();
    const first = await runPartitionMaintenance({
      client: prisma,
      logger: silent,
      mode: 'apply',
      now,
      purge: false,
    });
    expect(first.errors).toEqual([]);
    expect(first.ok).toBe(true);

    for (const spec of PARTITION_REGISTRY) {
      const names = await partitionNames(spec.table);
      expect(names.at(-1), spec.table).toBe('pmax');
      const current = periodStart(now, spec.granularity);
      const future = names
        .map((n) => parsePartitionName(n, spec.granularity))
        .filter((d): d is Date => d !== null && d.getTime() > current.getTime());
      expect(future.length, spec.table).toBeGreaterThanOrEqual(
        spec.granularity === 'month' ? 3 : 7,
      );
      expect(names, spec.table).toContain(
        spec.granularity === 'month'
          ? `p${current.getUTCFullYear()}${String(current.getUTCMonth() + 1).padStart(2, '0')}`
          : `p${current.toISOString().slice(0, 10).replaceAll('-', '')}`,
      );
    }

    const second = await runPartitionMaintenance({
      client: prisma,
      logger: silent,
      mode: 'apply',
      now,
      purge: false,
    });
    expect(second).toMatchObject({ ok: true, actions: [], statements: [] });
  });

  it('splits and drops a scratch table at fixed dates', async () => {
    await prisma.$executeRawUnsafe(`DROP TABLE IF EXISTS \`${PROBE}\``);
    await prisma.$executeRawUnsafe(
      `CREATE TABLE \`${PROBE}\` (
         id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
         created_at DATETIME(3) NOT NULL,
         PRIMARY KEY (id, created_at)
       ) PARTITION BY RANGE COLUMNS(created_at) (PARTITION pmax VALUES LESS THAN (MAXVALUE))`,
    );
    const spec: PartitionSpec = {
      table: PROBE,
      column: 'created_at',
      granularity: 'month',
      retention: 2,
      drop: true,
      tier: 'operational',
    };
    const run = (now: string, bootstrapFrom?: Date) =>
      runPartitionMaintenance({
        client: prisma,
        logger: silent,
        mode: 'apply',
        now: new Date(now),
        specs: [spec],
        plan: bootstrapFrom ? { bootstrapFrom } : {},
        purge: false,
      });

    // A stray row in pmax is copied by the split (warned, not fatal).
    await prisma.$executeRawUnsafe(
      `INSERT INTO \`${PROBE}\` (created_at) VALUES ('2025-12-20 10:00:00.000')`,
    );
    const bootstrap = await run('2026-03-15T12:00:00Z', new Date('2026-01-01T00:00:00Z'));
    expect(bootstrap.ok).toBe(true);
    expect(await partitionNames(PROBE)).toEqual([
      'p202601',
      'p202602',
      'p202603',
      'p202604',
      'p202605',
      'p202606',
      'pmax',
    ]);
    const [stray] = await prisma.$queryRawUnsafe<{ n: bigint }[]>(
      `SELECT COUNT(*) AS n FROM \`${PROBE}\` PARTITION (p202601)`,
    );
    expect(Number(stray?.n)).toBe(1);

    // Two months later: cutoff 2026-03-01 drops January and February; two more months ahead.
    const later = await run('2026-05-10T00:00:00Z');
    expect(later.ok).toBe(true);
    expect(await partitionNames(PROBE)).toEqual([
      'p202603',
      'p202604',
      'p202605',
      'p202606',
      'p202607',
      'p202608',
      'pmax',
    ]);
    expect((await run('2026-05-31T23:59:59Z')).actions).toEqual([]);
  });

  it('skips a run while another session holds the per-schema maintenance lock', async () => {
    const other = await createConnection(stack.migrationDatabaseUrl());
    try {
      const [[held]] = await other.query<RowDataPacket[]>(
        "SELECT GET_LOCK(LEFT(CONCAT('partition_maintenance:', DATABASE()), 64), 0) AS acquired",
      );
      expect(Number(held?.acquired)).toBe(1);
      const result = await runPartitionMaintenance({
        client: prisma,
        logger: silent,
        mode: 'apply',
        purge: false,
      });
      expect(result).toMatchObject({ ok: true, skippedLockHeld: true, actions: [] });
    } finally {
      await other.end();
    }
    // Released on disconnect (asynchronously, once the server ends the session): wait for it,
    // then the next run takes the lock again.
    const deadline = Date.now() + 5_000;
    for (;;) {
      const [free] = await prisma.$queryRawUnsafe<{ free: bigint | number | null }[]>(
        "SELECT IS_FREE_LOCK(LEFT(CONCAT('partition_maintenance:', DATABASE()), 64)) AS free",
      );
      if (Number(free?.free) === 1) break;
      if (Date.now() > deadline) throw new Error('maintenance lock not released after disconnect');
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const after = await runPartitionMaintenance({
      client: prisma,
      logger: silent,
      mode: 'apply',
      purge: false,
    });
    expect(after.skippedLockHeld).toBe(false);
  });

  it('gives up partition DDL after lock_wait_timeout instead of stalling the table', async () => {
    const table = `${PROBE}_mdl`;
    await prisma.$executeRawUnsafe(`DROP TABLE IF EXISTS \`${table}\``);
    await prisma.$executeRawUnsafe(
      `CREATE TABLE \`${table}\` (
         id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
         created_at DATETIME(3) NOT NULL,
         PRIMARY KEY (id, created_at)
       ) PARTITION BY RANGE COLUMNS(created_at) (PARTITION pmax VALUES LESS THAN (MAXVALUE))`,
    );
    const spec: PartitionSpec = {
      table,
      column: 'created_at',
      granularity: 'month',
      retention: null,
      drop: false,
      tier: 'operational',
    };
    // An open transaction that has read the table holds a shared metadata lock until it ends.
    const holder = await createConnection(stack.migrationDatabaseUrl());
    try {
      await holder.query('START TRANSACTION');
      await holder.query(`SELECT COUNT(*) FROM \`${table}\``);
      const started = Date.now();
      const blocked = await runPartitionMaintenance({
        client: prisma,
        logger: silent,
        mode: 'apply',
        specs: [spec],
        purge: false,
        lockWaitTimeoutSeconds: 1,
      });
      expect(Date.now() - started).toBeLessThan(10_000);
      expect(blocked.ok).toBe(false);
      expect(blocked.errors).toEqual([
        { table, message: expect.stringMatching(/lock wait timeout/i) as unknown },
      ]);
      await holder.query('ROLLBACK');

      // Retried on the next run once the transaction has ended.
      const retried = await runPartitionMaintenance({
        client: prisma,
        logger: silent,
        mode: 'apply',
        specs: [spec],
        purge: false,
        lockWaitTimeoutSeconds: 1,
      });
      expect(retried.ok).toBe(true);
      expect((await partitionNames(table)).length).toBeGreaterThan(1);
    } finally {
      await holder.end();
      await prisma.$executeRawUnsafe(`DROP TABLE IF EXISTS \`${table}\``);
    }
  });
});
