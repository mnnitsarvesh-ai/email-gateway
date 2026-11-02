#!/usr/bin/env node
/**
 * Migration helpers that run around the Prisma CLI.
 *
 *   node dist/migrations/cli.js check         preflight before `prisma migrate deploy`
 *   node dist/migrations/cli.js assert-local  exit 1 unless APP_ENV/NODE_ENV are local-like
 *
 * `check` reads `_prisma_migrations` with MIGRATION_DATABASE_URL and fails (exit 1) with an
 * explanation when the database records a retired migration (see history.ts). An empty
 * database passes. `assert-local` guards `pnpm db:reset:local`.
 */
import { readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadConfig } from '@email-gateway/config';
import { createLogger } from '@email-gateway/logger';
import { PrismaClient } from '@prisma/client';
import { maintenanceConfigSchema } from '../partitioning/config';
import { isProductionLike } from '../seed/guard';
import { checkMigrationHistory } from './history';

const MIGRATIONS_DIR = resolve(__dirname, '..', '..', 'prisma', 'migrations');
const USAGE = 'usage: migrations <check|assert-local>';

function localMigrations(): string[] {
  return readdirSync(MIGRATIONS_DIR).filter((name) =>
    statSync(resolve(MIGRATIONS_DIR, name)).isDirectory(),
  );
}

async function check(): Promise<number> {
  const config = loadConfig(maintenanceConfigSchema);
  const logger = createLogger({ service: 'db-migrate', level: config.LOG_LEVEL });
  const prisma = new PrismaClient({ datasourceUrl: config.MIGRATION_DATABASE_URL });
  try {
    const [table] = await prisma.$queryRawUnsafe<{ n: bigint | number }[]>(
      `SELECT COUNT(*) AS n FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '_prisma_migrations'`,
    );
    const applied =
      Number(table?.n ?? 0) === 0
        ? []
        : (
            await prisma.$queryRawUnsafe<{ name: string }[]>(
              'SELECT migration_name AS name FROM `_prisma_migrations` WHERE rolled_back_at IS NULL',
            )
          ).map((r) => r.name);
    const result = checkMigrationHistory(applied, localMigrations());
    if (!result.ok) {
      logger.error({ retired: result.retired }, result.message);
      return 1;
    }
    if (result.unknown.length > 0) logger.warn({ unknown: result.unknown }, result.message);
    else logger.info({ applied: applied.length }, result.message);
    return 0;
  } finally {
    await prisma.$disconnect();
  }
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2).filter((a) => a !== '--');
  if (rest.length > 0) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  if (command === 'check') return check();
  if (command === 'assert-local') {
    if (isProductionLike(process.env.APP_ENV, process.env.NODE_ENV)) {
      process.stderr.write('refusing to reset a staging/production database\n');
      return 1;
    }
    return 0;
  }
  process.stderr.write(`${USAGE}\n`);
  return 2;
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
