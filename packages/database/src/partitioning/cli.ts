#!/usr/bin/env node
/**
 * Partition maintenance CLI (D3). Runs after `prisma migrate deploy` (Compose db-migrate),
 * daily as a Kubernetes CronJob, and in CI.
 *
 *   node dist/partitioning/cli.js plan  [--now <ISO>] [--bootstrap-from <YYYY-MM-DD>]
 *   node dist/partitioning/cli.js apply [--now <ISO>] [--bootstrap-from <YYYY-MM-DD>]
 *                                       [--lock-wait-timeout <seconds, default 5>]
 *
 * `plan` prints the SQL it would run and changes nothing. `apply` runs it under a per-schema
 * advisory lock; when another run holds the lock it logs a warning and exits 0 without doing
 * anything. Exit code 1 on any failure, including an expired outbox partition kept back by its
 * guard and a partition DDL that timed out waiting for a metadata lock (retried next run).
 */
import { loadConfig } from '@email-gateway/config';
import { createLogger } from '@email-gateway/logger';
import { PrismaClient } from '@prisma/client';
import { maintenanceConfigSchema, parseArgs, parseDay, parseInstant } from './config';
import {
  DEFAULT_LOCK_WAIT_TIMEOUT_SECONDS,
  type MaintenanceMode,
  createMaintenanceClientUrl,
  runPartitionMaintenance,
} from './executor';

const USAGE =
  'usage: partitions <plan|apply> [--now <ISO-8601>] [--bootstrap-from <YYYY-MM-DD>]' +
  ' [--lock-wait-timeout <seconds>] [--no-purge]';

async function main(): Promise<number> {
  const args = parseArgs(
    process.argv.slice(2),
    ['now', 'bootstrap-from', 'lock-wait-timeout'],
    ['no-purge', 'help'],
  );
  if (args.flags.has('help')) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  const [command, ...rest] = args.positionals;
  if ((command !== 'plan' && command !== 'apply') || rest.length > 0) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const mode: MaintenanceMode = command;
  const now = args.values.now ? parseInstant(args.values.now, '--now') : new Date();
  const bootstrapFrom = args.values['bootstrap-from']
    ? parseDay(args.values['bootstrap-from'], '--bootstrap-from')
    : undefined;
  const lockWaitRaw = args.values['lock-wait-timeout'];
  const lockWaitTimeoutSeconds =
    lockWaitRaw === undefined ? DEFAULT_LOCK_WAIT_TIMEOUT_SECONDS : Number(lockWaitRaw);
  if (!Number.isInteger(lockWaitTimeoutSeconds) || lockWaitTimeoutSeconds < 1) {
    process.stderr.write('--lock-wait-timeout must be a positive integer (seconds)\n');
    return 2;
  }

  const config = loadConfig(maintenanceConfigSchema);
  const logger = createLogger({
    service: 'db-maintenance',
    level: config.LOG_LEVEL,
    version: config.SERVICE_VERSION,
  });
  // One connection: the advisory lock and lock_wait_timeout are per-connection.
  const prisma = new PrismaClient({
    datasourceUrl: createMaintenanceClientUrl(config.MIGRATION_DATABASE_URL),
  });
  try {
    logger.info({ mode, now: now.toISOString(), bootstrapFrom }, 'partition maintenance started');
    const result = await runPartitionMaintenance({
      client: prisma,
      logger,
      mode,
      now,
      plan: bootstrapFrom ? { bootstrapFrom } : {},
      purge: !args.flags.has('no-purge'),
      lockWaitTimeoutSeconds,
    });
    if (result.skippedLockHeld) return 0;
    if (mode === 'plan') {
      const ddl = result.statements.filter((s) => s.kind !== 'purge').map((s) => `${s.sql};`);
      const purges = result.statements
        .filter((s) => s.kind === 'purge')
        .map((s) => `-- batched retention purge, repeated until done: ${s.sql};`);
      const lines = [...(ddl.length > 0 ? ddl : ['-- partitions: nothing to do']), ...purges];
      process.stdout.write(`${lines.join('\n')}\n`);
    }
    logger.info(
      {
        ok: result.ok,
        partitionActions: result.actions.length,
        skippedDrops: result.skippedDrops.length,
        purged: result.purged,
        errors: result.errors.length,
      },
      'partition maintenance finished',
    );
    return result.ok ? 0 : 1;
  } catch (err) {
    logger.error(
      { err: err instanceof Error ? err.message : String(err) },
      'partition maintenance aborted',
    );
    return 1;
  } finally {
    await prisma.$disconnect();
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
