#!/usr/bin/env node
/**
 * Database performance test (D8).
 *
 *   node dist/perf/cli.js [--messages 200000] [--organizations 20] [--runs 20] [--keep]
 *                         [--out ../../docs/database/performance-report.md] [--seed 42]
 *
 * Creates the throwaway schema `<db>_perf` (e.g. `email_gateway_perf`) with the migrator
 * account, which holds ALL on exactly that schema (infrastructure/mysql/init), applies every
 * migration to it, bootstraps partitions 4 months back, loads synthetic data, runs ANALYZE
 * TABLE and Q1–Q18 (EXPLAIN, EXPLAIN FORMAT=TREE, EXPLAIN ANALYZE, timings), samples replica
 * lag through DATABASE_READ_URL, writes the report and drops the schema unless --keep.
 * Never run it against production: it drops and recreates `<db>_perf` and generates heavy load.
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { cpus, platform, release, totalmem } from 'node:os';
import { resolve } from 'node:path';
import { loadConfig } from '@email-gateway/config';
import { createLogger } from '@email-gateway/logger';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { maintenanceConfigSchema, parseArgs } from '../partitioning/config';
import { runPartitionMaintenance } from '../partitioning/executor';
import { addPeriods, periodStart } from '../partitioning/planner';
import { PARTITION_REGISTRY } from '../partitioning/registry';
import { loadSyntheticData } from './load';
import { buildQueries } from './queries';
import { renderReport } from './report';
import { readLag, runQuery, startLagSampler } from './run';
import {
  PACKAGE_ROOT,
  applyMigrations,
  dropSchema,
  perfSchemaName,
  recreateSchema,
  withSchema,
} from './schema';

const DAYS = 120;
const USAGE =
  'usage: perf [--messages N] [--organizations N] [--runs N] [--seed N] [--out FILE] [--keep]';

const perfConfigSchema = maintenanceConfigSchema.extend({
  DATABASE_READ_URL: z.string().startsWith('mysql://').optional(),
});

function positiveInt(value: string | undefined, fallback: number, flag: string): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) throw new Error(`${flag} must be a positive integer`);
  return n;
}

function dockerMemory(): number | null {
  try {
    const out = spawnSync('docker', ['info', '--format', '{{.MemTotal}}'], {
      encoding: 'utf8',
      timeout: 5000,
    });
    const n = Number(out.stdout.trim());
    return out.status === 0 && Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

function formatWithPrettier(file: string): boolean {
  try {
    const bin = require.resolve('prettier/bin/prettier.cjs', {
      paths: [resolve(PACKAGE_ROOT, '..', '..')],
    });
    return spawnSync(process.execPath, [bin, '--write', file], { stdio: 'ignore' }).status === 0;
  } catch {
    return false;
  }
}

async function main(): Promise<number> {
  const args = parseArgs(
    process.argv.slice(2),
    ['messages', 'organizations', 'runs', 'seed', 'out'],
    ['keep', 'help'],
  );
  if (args.flags.has('help')) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  const messages = positiveInt(args.values.messages, 200_000, '--messages');
  const organizations = positiveInt(args.values.organizations, 20, '--organizations');
  const runs = positiveInt(args.values.runs, 20, '--runs');
  const seed = positiveInt(args.values.seed, 42, '--seed');
  const out = resolve(
    args.values.out ??
      resolve(PACKAGE_ROOT, '..', '..', 'docs', 'database', 'performance-report.md'),
  );

  const config = loadConfig(perfConfigSchema);
  if (
    config.APP_ENV === 'staging' ||
    config.APP_ENV === 'production' ||
    config.NODE_ENV === 'production'
  ) {
    process.stderr.write('refusing to run the performance test outside local/CI environments\n');
    return 1;
  }
  const logger = createLogger({ service: 'db-perf', level: config.LOG_LEVEL });
  const admin = new PrismaClient({ datasourceUrl: config.MIGRATION_DATABASE_URL });
  const PERF_SCHEMA = perfSchemaName(config.MIGRATION_DATABASE_URL);
  const perfUrl = withSchema(config.MIGRATION_DATABASE_URL, PERF_SCHEMA);
  // One connection: LAST_INSERT_ID() must be read on the connection that inserted.
  const perf = new PrismaClient({
    datasourceUrl: withSchema(config.MIGRATION_DATABASE_URL, PERF_SCHEMA, {
      connection_limit: '1',
    }),
  });
  const reader = config.DATABASE_READ_URL
    ? new PrismaClient({ datasourceUrl: config.DATABASE_READ_URL })
    : null;
  const now = new Date();
  let keep = args.flags.has('keep');

  try {
    logger.info({ schema: PERF_SCHEMA, messages, organizations }, 'creating perf schema');
    await recreateSchema(admin, PERF_SCHEMA);

    let t = performance.now();
    await applyMigrations(perfUrl);
    const migrateMs = performance.now() - t;

    t = performance.now();
    const bootstrapFrom = addPeriods(periodStart(now, 'month'), 'month', -4);
    const maintenance = await runPartitionMaintenance({
      client: perf,
      logger,
      mode: 'apply',
      now,
      plan: { bootstrapFrom },
      purge: false,
    });
    if (!maintenance.ok) throw new Error('partition maintenance failed on the perf schema');
    const maintenanceMs = performance.now() - t;

    const sampler = startLagSampler(reader);
    let lastLogged = 0;
    const load = await loadSyntheticData(perf, {
      messages,
      organizations,
      days: DAYS,
      now,
      seed,
      onProgress: (done, total) => {
        if (done - lastLogged >= total / 10 || done === total) {
          lastLogged = done;
          logger.info({ done, total }, 'loading messages');
        }
      },
    });
    const lag = await sampler.stop();

    let catchUpSeconds: number | null = null;
    if (reader) {
      const waitStart = performance.now();
      while (performance.now() - waitStart < 15 * 60 * 1000) {
        const current = await readLag(reader).catch(() => null);
        if (current === 0) {
          catchUpSeconds = (performance.now() - waitStart) / 1000;
          break;
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
    }

    t = performance.now();
    const tableNames = (
      await perf.$queryRawUnsafe<{ name: string }[]>(
        `SELECT TABLE_NAME AS name FROM information_schema.TABLES
          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' AND TABLE_NAME <> '_prisma_migrations'
          ORDER BY TABLE_NAME`,
      )
    ).map((r) => r.name);
    for (const name of tableNames) {
      if (!/^[a-z_]+$/.test(name)) continue;
      await perf.$queryRawUnsafe(`ANALYZE TABLE \`${name}\``);
    }
    const analyzeMs = performance.now() - t;

    const partitions = new Map(
      (
        await perf.$queryRawUnsafe<{ name: string; n: bigint }[]>(
          `SELECT TABLE_NAME AS name, COUNT(*) AS n FROM information_schema.PARTITIONS
            WHERE TABLE_SCHEMA = DATABASE() AND PARTITION_NAME IS NOT NULL GROUP BY TABLE_NAME`,
        )
      ).map((r) => [r.name, Number(r.n)]),
    );
    const loaded = new Set(load.stats.map((s) => s.table));
    const reported = [...new Set([...PARTITION_REGISTRY.map((s) => s.table), ...loaded])].sort();
    const tables: { table: string; rows: number; partitions: number }[] = [];
    for (const table of reported) {
      const [row] = await perf.$queryRawUnsafe<{ n: bigint }[]>(
        `SELECT COUNT(*) AS n FROM \`${table}\``,
      );
      tables.push({ table, rows: Number(row?.n ?? 0), partitions: partitions.get(table) ?? 1 });
    }

    const queries = await buildQueries(perf, load.sample, now);
    const results = [];
    for (const query of queries) {
      logger.info({ query: query.id }, 'running query');
      results.push(await runQuery(perf, query, runs));
    }

    const [version] = await perf.$queryRawUnsafe<{ v: string; bp: bigint }[]>(
      'SELECT VERSION() AS v, @@innodb_buffer_pool_size AS bp',
    );
    const report = renderReport({
      generatedAt: now,
      schema: PERF_SCHEMA,
      command: `pnpm db:perf${messages !== 200_000 ? ` -- --messages ${messages}` : ''}`,
      messages,
      organizations,
      days: DAYS,
      runs,
      environment: {
        mysqlVersion: version?.v ?? 'unknown',
        bufferPoolBytes: Number(version?.bp ?? 0),
        dockerMemoryBytes: dockerMemory(),
        host: `${platform()} ${release()}, ${cpus().length} CPUs (${cpus()[0]?.model ?? 'unknown'}), ${Math.round(totalmem() / 1024 ** 3)} GiB RAM`,
        node: process.version,
      },
      migrateMs,
      maintenanceMs,
      loadMs: load.totalMs,
      analyzeMs,
      loadStats: load.stats,
      tables,
      replica: {
        measured: reader !== null,
        maxLagSeconds: lag.maxLagSeconds,
        samples: lag.samples,
        unavailable: lag.unavailable,
        catchUpSeconds,
      },
      results,
    });
    writeFileSync(out, report);
    const formatted = formatWithPrettier(out);
    logger.info({ out, formatted }, 'performance report written');
    return 0;
  } catch (err) {
    keep = keep || process.env.PERF_KEEP_ON_ERROR === '1';
    logger.error(
      { err: err instanceof Error ? err.message : String(err) },
      'performance test failed',
    );
    return 1;
  } finally {
    if (!keep) {
      await dropSchema(admin, PERF_SCHEMA).catch((err: unknown) =>
        logger.error({ err: String(err) }, 'could not drop the perf schema'),
      );
    }
    await Promise.all([admin.$disconnect(), perf.$disconnect(), reader?.$disconnect()]);
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  },
);
