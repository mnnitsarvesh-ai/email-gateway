#!/usr/bin/env node
/**
 * Migration helpers that run around the Prisma CLI.
 *
 *   node dist/migrations/cli.js check         preflight before `prisma migrate deploy`
 *   node dist/migrations/cli.js assert-local  exit 1 unless APP_ENV/NODE_ENV are local-like
 *   node dist/migrations/cli.js effective-permissions export <file>
 *   node dist/migrations/cli.js effective-permissions compare <file>
 *
 * `check` reads `_prisma_migrations` with MIGRATION_DATABASE_URL and fails (exit 1) with an
 * explanation when the database records a retired migration (see history.ts). An empty
 * database passes. `assert-local` guards `pnpm db:reset:local`. `effective-permissions` (step 8.6
 * §9.6) writes every user's effective permission set (public ids only) to a JSON file before an
 * RBAC data migration, and compares the current sets with it afterwards: it prints the counts and
 * exits 1 when any user lost a permission.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadConfig } from '@email-gateway/config';
import { createLogger } from '@email-gateway/logger';
import { PrismaClient } from '@prisma/client';
import { maintenanceConfigSchema } from '../partitioning/config';
import { isProductionLike } from '../seed/guard';
import {
  compareEffectivePermissions,
  parseEffectivePermissionSnapshot,
  snapshotEffectivePermissions,
} from './effective-permissions';
import { checkMigrationHistory } from './history';

const MIGRATIONS_DIR = resolve(__dirname, '..', '..', 'prisma', 'migrations');
const USAGE =
  'usage: migrations <check|assert-local|effective-permissions <export|compare> <file>>';

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

async function effectivePermissions(mode: string | undefined, file: string): Promise<number> {
  if (mode !== 'export' && mode !== 'compare') {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const config = loadConfig(maintenanceConfigSchema);
  const logger = createLogger({ service: 'db-migrate', level: config.LOG_LEVEL });
  const prisma = new PrismaClient({ datasourceUrl: config.MIGRATION_DATABASE_URL });
  try {
    const current = await snapshotEffectivePermissions(prisma);
    if (mode === 'export') {
      writeFileSync(file, `${JSON.stringify(current, null, 2)}\n`, { mode: 0o600 });
      logger.info({ users: current.users.length, file }, 'effective permissions exported');
      return 0;
    }
    const before = parseEffectivePermissionSnapshot(JSON.parse(readFileSync(file, 'utf8')));
    const { ok, changes, ...counts } = compareEffectivePermissions(before, current);
    if (ok) logger.info({ ...counts, changed: changes.length }, 'no user lost a permission');
    else logger.error({ ...counts, changes }, 'users lost permissions');
    return ok ? 0 : 1;
  } finally {
    await prisma.$disconnect();
  }
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2).filter((a) => a !== '--');
  if (command === 'effective-permissions' && rest.length === 2) {
    return effectivePermissions(rest[0], rest[1]!);
  }
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
