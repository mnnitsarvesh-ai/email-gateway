import { describe, expect, it, vi } from 'vitest';
import {
  REGISTRY_PURGE_SQL,
  REGISTRY_WATERMARK,
  buildDropSql,
  buildSplitSql,
  createMaintenanceClientUrl,
  runPartitionMaintenance,
  type SqlClient,
} from './executor';
import { type PartitionSpec } from './registry';

interface FakeOptions {
  partitions: { tableName: string; partitionName: string; description: string }[];
  /** Partitions (as `table.partition`) that contain rows with a NULL guard column. */
  guarded?: string[];
  /** Tables whose pmax contains rows. */
  pmaxRows?: string[];
  minMessageId?: bigint | null;
  /** MIN(id) of message_identities. */
  minRegistryId?: bigint | null;
  /** Stored registry purge watermark. */
  watermark?: bigint | null;
  /** GET_LOCK result (default 1: acquired). */
  lockAcquired?: number;
  /** IS_USED_LOCK(...) = CONNECTION_ID() result (default 1: this connection). */
  lockMine?: number;
  /** Rows deleted per purge statement, in order; 0 afterwards. */
  deletes?: Record<string, number[]>;
}

function fakeClient(options: FakeOptions) {
  /** DDL and purge DELETEs, in order. */
  const executed: string[] = [];
  /** Every statement (queries included), in order. */
  const all: string[] = [];
  /** Watermark upserts as [name, value]. */
  const watermarks: [unknown, unknown][] = [];
  const deletes = Object.fromEntries(
    Object.entries(options.deletes ?? {}).map(([k, v]) => [k, [...v]]),
  );
  const answer = (sql: string): unknown => {
    if (sql.includes('GET_LOCK(')) return [{ acquired: BigInt(options.lockAcquired ?? 1) }];
    if (sql.includes('IS_USED_LOCK(')) return [{ mine: BigInt(options.lockMine ?? 1) }];
    if (sql.includes('RELEASE_LOCK(')) return [{ released: 1n }];
    if (sql.includes('FROM `maintenance_watermarks`')) {
      return options.watermark == null ? [] : [{ value: options.watermark }];
    }
    if (sql.includes('FROM `message_identities`') && sql.includes('MIN(`id`)')) {
      return [{ minId: options.minRegistryId ?? null }];
    }
    if (sql.includes('information_schema.PARTITIONS')) {
      return options.partitions.map((p) => ({ ...p, tableRows: 0n }));
    }
    const guard = /FROM `(\w+)` PARTITION \(`(\w+)`\) WHERE `\w+` IS NULL/.exec(sql);
    if (guard) return options.guarded?.includes(`${guard[1]}.${guard[2]}`) ? [{ 1: 1 }] : [];
    const stray = /FROM `(\w+)` PARTITION \(`pmax`\) LIMIT 1/.exec(sql);
    if (stray) return options.pmaxRows?.includes(stray[1]!) ? [{ 1: 1 }] : [];
    if (sql.includes('MIN(`id`)')) return [{ minId: options.minMessageId ?? null }];
    throw new Error(`unexpected query ${sql}`);
  };
  const execute = (sql: string, values: unknown[]): number => {
    if (sql.startsWith('SET SESSION')) return 0;
    if (sql.startsWith('INSERT INTO `maintenance_watermarks`')) {
      watermarks.push([values[0], values[1]]);
      return 1;
    }
    executed.push(sql);
    const purge = /DELETE FROM `(\w+)`/.exec(sql);
    if (purge) return deletes[purge[1]!]?.shift() ?? 0;
    return 0;
  };
  const client = {
    $queryRawUnsafe: vi.fn((sql: string) => {
      all.push(sql);
      try {
        return Promise.resolve(answer(sql));
      } catch (err) {
        return Promise.reject(err instanceof Error ? err : new Error(String(err)));
      }
    }),
    $executeRawUnsafe: vi.fn((sql: string, ...values: unknown[]) => {
      all.push(sql);
      return Promise.resolve(execute(sql, values));
    }),
  } as unknown as SqlClient;
  return { client, executed, all, watermarks };
}

const logger = () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() });
const outbox: PartitionSpec = {
  table: 'message_outbox',
  column: 'created_at',
  granularity: 'day',
  retention: 7,
  drop: true,
  guard: { kind: 'no-null-rows', column: 'published_at', description: 'no unpublished rows' },
  tier: 'operational',
};
const day = (d: number) => `p202611${String(d).padStart(2, '0')}`;
const dayBound = (d: number) => `'2026-11-${String(d + 1).padStart(2, '0')} 00:00:00'`;
const outboxPartitions = (from: number, to: number) => [
  ...Array.from({ length: to - from + 1 }, (_, i) => ({
    tableName: 'message_outbox',
    partitionName: day(from + i),
    description: dayBound(from + i),
  })),
  { tableName: 'message_outbox', partitionName: 'pmax', description: 'MAXVALUE' },
];
const NOW = new Date('2026-11-10T06:00:00Z'); // cutoff 2026-11-03: p20261101 and p20261102 expire

describe('SQL builders', () => {
  it('builds REORGANIZE and DROP statements with quoted identifiers', () => {
    expect(
      buildSplitSql('email_messages', [{ name: 'p202612', lessThan: '2027-01-01 00:00:00' }]),
    ).toBe(
      "ALTER TABLE `email_messages` REORGANIZE PARTITION `pmax` INTO (PARTITION `p202612` VALUES LESS THAN ('2027-01-01 00:00:00'), PARTITION `pmax` VALUES LESS THAN (MAXVALUE))",
    );
    expect(buildDropSql('email_messages', ['p202601', 'p202602'])).toBe(
      'ALTER TABLE `email_messages` DROP PARTITION `p202601`, `p202602`',
    );
  });

  it('refuses unexpected identifiers and pmax drops', () => {
    expect(() => buildDropSql('t', ['pmax'])).toThrow(/pmax/);
    expect(() => buildDropSql('t', ['p1; DROP TABLE x'])).toThrow(/unexpected partition name/);
    expect(() => buildSplitSql('t', [{ name: 'p202601', lessThan: "x') --" }])).toThrow(/bound/);
  });
});

describe('runPartitionMaintenance', () => {
  it('drops expired outbox partitions, skips guarded ones and fails the run', async () => {
    const { client, executed } = fakeClient({
      partitions: outboxPartitions(1, 17),
      guarded: ['message_outbox.p20261101'],
    });
    const log = logger();
    const result = await runPartitionMaintenance({
      client,
      logger: log,
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(executed).toEqual(['ALTER TABLE `message_outbox` DROP PARTITION `p20261102`']);
    expect(result.ok).toBe(false);
    expect(result.skippedDrops).toEqual([
      { table: 'message_outbox', partition: 'p20261101', reason: 'no unpublished rows' },
    ]);
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ partition: 'p20261101' }),
      'expired partition not dropped: guard failed',
    );
  });

  it('drops everything expired when the guard passes, and is a no-op afterwards', async () => {
    const first = fakeClient({ partitions: outboxPartitions(1, 17) });
    const result = await runPartitionMaintenance({
      client: first.client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(result.ok).toBe(true);
    expect(first.executed).toEqual([
      'ALTER TABLE `message_outbox` DROP PARTITION `p20261101`, `p20261102`',
    ]);

    const second = fakeClient({ partitions: outboxPartitions(3, 17) });
    const again = await runPartitionMaintenance({
      client: second.client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(again).toMatchObject({ ok: true, actions: [], statements: [] });
    expect(second.executed).toEqual([]);
  });

  it('plan mode records SQL without executing it', async () => {
    const { client, executed } = fakeClient({
      partitions: [{ tableName: 'message_outbox', partitionName: 'pmax', description: 'MAXVALUE' }],
    });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'plan',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(executed).toEqual([]);
    expect(result.statements).toHaveLength(1);
    expect(result.statements[0]).toMatchObject({ kind: 'split-pmax', applied: false });
    expect(result.statements[0]!.sql).toContain('PARTITION `p20261110`');
    expect(result.statements[0]!.sql).toContain('PARTITION `p20261117`');
  });

  it('warns when pmax already holds rows but still splits', async () => {
    const { client, executed } = fakeClient({
      partitions: [{ tableName: 'message_outbox', partitionName: 'pmax', description: 'MAXVALUE' }],
      pmaxRows: ['message_outbox'],
    });
    const log = logger();
    const result = await runPartitionMaintenance({
      client,
      logger: log,
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(result.ok).toBe(true);
    expect(executed).toHaveLength(1);
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ table: 'message_outbox' }),
      'pmax already contains rows; the split copies them',
    );
  });

  it('records a missing or non-conforming table as an error and continues', async () => {
    const other: PartitionSpec = {
      ...outbox,
      table: 'webhook_deliveries',
      granularity: 'month',
      guard: undefined,
    };
    const { client } = fakeClient({ partitions: outboxPartitions(3, 17) });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [other, outbox],
      purge: false,
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([
      { table: 'webhook_deliveries', message: expect.stringContaining('missing') as unknown },
    ]);
  });

  it('purges idempotency rows in batches until a short batch, with sleeps', async () => {
    const { client, executed } = fakeClient({
      partitions: [],
      minMessageId: null,
      deletes: { message_idempotency: [10, 10, 3] },
    });
    const sleep = vi.fn(async () => {});
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [],
      purgeOptions: { batchSize: 10, maxBatches: 3, sleepMs: 1 },
      sleep,
    });
    expect(result.purged).toEqual([
      { table: 'message_idempotency', rows: 23, batches: 3, capped: false },
    ]);
    expect(executed.filter((s) => s.includes('message_idempotency'))).toHaveLength(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    const idempotencyCall = vi
      .mocked(client.$executeRawUnsafe)
      .mock.calls.find(([sql]) => sql.includes('message_idempotency'))!;
    expect(idempotencyCall[1]).toBe('2026-10-11 06:00:00');
  });

  it('purges the registry in id ranges from MIN(id), keeping referenced rows, with a cap', async () => {
    const { client, executed, watermarks } = fakeClient({
      partitions: [],
      minMessageId: 1000n,
      minRegistryId: 1n,
      deletes: { message_identities: [10, 4, 10, 10] },
    });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [],
      purgeOptions: { batchSize: 10, maxBatches: 3, sleepMs: 1 },
      sleep: async () => {},
    });
    expect(result.purged).toContainEqual({
      table: 'message_identities',
      rows: 24,
      batches: 3,
      capped: true,
    });
    const calls = vi
      .mocked(client.$executeRawUnsafe)
      .mock.calls.filter(([sql]) => sql === REGISTRY_PURGE_SQL)
      .map(([, from, to]) => [from, to]);
    expect(calls).toEqual([
      [1n, 11n],
      [11n, 21n],
      [21n, 31n],
    ]);
    expect(watermarks).toEqual([
      [REGISTRY_WATERMARK, 11n],
      [REGISTRY_WATERMARK, 21n],
      [REGISTRY_WATERMARK, 31n],
    ]);
    // The anti-joins keep rows referenced by a live archive or by quarantine.
    expect(REGISTRY_PURGE_SQL).toContain('NOT EXISTS (SELECT 1 FROM `email_archives` a');
    expect(REGISTRY_PURGE_SQL).toContain('a.`deleted_at` IS NULL');
    expect(REGISTRY_PURGE_SQL).toContain('NOT EXISTS (SELECT 1 FROM `quarantine_messages` qm');
    expect(executed.filter((s) => s.includes('message_identities'))).toHaveLength(3);
  });

  it('resumes the registry purge from the watermark and stops at MIN(email_messages.id)', async () => {
    const { client, watermarks } = fakeClient({
      partitions: [],
      minMessageId: 125n,
      minRegistryId: 1n,
      watermark: 100n,
    });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [],
      purgeOptions: { batchSize: 20, maxBatches: 10, sleepMs: 0 },
      sleep: async () => {},
    });
    const calls = vi
      .mocked(client.$executeRawUnsafe)
      .mock.calls.filter(([sql]) => sql === REGISTRY_PURGE_SQL)
      .map(([, from, to]) => [from, to]);
    expect(calls).toEqual([
      [100n, 120n],
      [120n, 125n],
    ]);
    expect(watermarks.at(-1)).toEqual([REGISTRY_WATERMARK, 125n]);
    expect(result.purged).toContainEqual({
      table: 'message_identities',
      rows: 0,
      batches: 2,
      capped: false,
    });
  });

  it('does nothing to the registry when the watermark already reached the cutoff', async () => {
    const { client, executed, watermarks } = fakeClient({
      partitions: [],
      minMessageId: 50n,
      watermark: 50n,
    });
    await runPartitionMaintenance({ client, logger: logger(), mode: 'apply', now: NOW, specs: [] });
    expect(executed.some((s) => s.includes('message_identities'))).toBe(false);
    expect(watermarks).toEqual([]);
  });

  it('skips the registry purge when there are no messages', async () => {
    const { client, executed } = fakeClient({ partitions: [], minMessageId: null });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [],
    });
    expect(result.purged.map((p) => p.table)).toEqual(['message_idempotency']);
    expect(executed.some((s) => s.includes('message_identities'))).toBe(false);
  });
});

describe('runPartitionMaintenance locking and metadata-lock bound', () => {
  const pmaxOnly = [
    { tableName: 'message_outbox', partitionName: 'pmax', description: 'MAXVALUE' },
  ];

  it('takes the advisory lock, bounds lock_wait_timeout before DDL and releases the lock', async () => {
    const { client, all } = fakeClient({ partitions: pmaxOnly });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(result.ok).toBe(true);
    const lock = all.findIndex((s) => s.includes('GET_LOCK('));
    const timeout = all.indexOf('SET SESSION lock_wait_timeout = 5');
    const check = all.findIndex((s) => s.includes('IS_USED_LOCK('));
    const ddl = all.findIndex((s) => s.startsWith('ALTER TABLE `message_outbox` REORGANIZE'));
    const release = all.findIndex((s) => s.includes('RELEASE_LOCK('));
    expect(lock).toBe(0);
    expect(all[lock]).toContain("CONCAT('partition_maintenance:', DATABASE())");
    expect(timeout).toBeGreaterThan(lock);
    expect(check).toBeGreaterThan(timeout);
    expect(ddl).toBeGreaterThan(check);
    expect(release).toBe(all.length - 1);
  });

  it('uses the configured lock wait timeout and rejects invalid values', async () => {
    const { client, all } = fakeClient({ partitions: pmaxOnly });
    await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
      lockWaitTimeoutSeconds: 12,
    });
    expect(all).toContain('SET SESSION lock_wait_timeout = 12');
    await expect(
      runPartitionMaintenance({
        client,
        logger: logger(),
        mode: 'apply',
        specs: [],
        lockWaitTimeoutSeconds: 0,
      }),
    ).rejects.toThrow(/lock wait timeout/);
  });

  it('skips the whole run when another run holds the lock', async () => {
    const { client, all, executed } = fakeClient({ partitions: pmaxOnly, lockAcquired: 0 });
    const log = logger();
    const result = await runPartitionMaintenance({
      client,
      logger: log,
      mode: 'apply',
      now: NOW,
      specs: [outbox],
    });
    expect(result).toMatchObject({ ok: true, skippedLockHeld: true, actions: [], statements: [] });
    expect(executed).toEqual([]);
    expect(all).toHaveLength(1);
    expect(log.warn).toHaveBeenCalledWith(
      {},
      'another partition maintenance run holds the lock; skipping this run',
    );
  });

  it('refuses DDL when the lock is not held by the executing connection', async () => {
    const { client, executed, all } = fakeClient({ partitions: pmaxOnly, lockMine: 0 });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([
      { table: 'message_outbox', message: expect.stringContaining('single-connection') as unknown },
    ]);
    expect(executed).toEqual([]);
    expect(all.at(-1)).toContain('RELEASE_LOCK(');
  });

  it('records a metadata-lock timeout as a per-table failure and releases the lock', async () => {
    const { client, all } = fakeClient({ partitions: pmaxOnly });
    vi.mocked(client.$executeRawUnsafe).mockImplementation((sql: string) => {
      all.push(sql);
      return sql.startsWith('ALTER TABLE')
        ? Promise.reject(new Error('Lock wait timeout exceeded; try restarting transaction'))
        : Promise.resolve(0);
    });
    const result = await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'apply',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(result.ok).toBe(false);
    expect(result.errors[0]).toMatchObject({ table: 'message_outbox' });
    expect(result.errors[0]!.message).toMatch(/Lock wait timeout/);
    expect(all.at(-1)).toContain('RELEASE_LOCK(');
  });

  it('plan mode neither locks nor changes session settings', async () => {
    const { client, all } = fakeClient({ partitions: pmaxOnly });
    await runPartitionMaintenance({
      client,
      logger: logger(),
      mode: 'plan',
      now: NOW,
      specs: [outbox],
      purge: false,
    });
    expect(all.some((s) => s.includes('GET_LOCK(') || s.startsWith('SET SESSION'))).toBe(false);
  });

  it('builds a single-connection client URL', () => {
    const url = createMaintenanceClientUrl('mysql://u:p@db:3306/email_gateway?connect_timeout=5');
    expect(new URL(url).searchParams.get('connection_limit')).toBe('1');
    expect(new URL(url).searchParams.get('connect_timeout')).toBe('5');
    expect(new URL(url).pathname).toBe('/email_gateway');
  });
});
