import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { type SqlClient } from '../partitioning/executor';

/** Root of the @email-gateway/database package (dist/perf → package root). */
export const PACKAGE_ROOT = resolve(__dirname, '..', '..');

const SCHEMA_NAME = /^[a-z][a-z0-9_]{0,63}$/;

export function assertSchemaName(name: string): void {
  if (!SCHEMA_NAME.test(name)) throw new Error(`Invalid schema name ${JSON.stringify(name)}`);
}

/** Returns `url` pointing at another schema, with optional extra query parameters. */
export function withSchema(url: string, schema: string, params: Record<string, string> = {}) {
  assertSchemaName(schema);
  const parsed = new URL(url);
  parsed.pathname = `/${schema}`;
  for (const [key, value] of Object.entries(params)) parsed.searchParams.set(key, value);
  return parsed.toString();
}

/**
 * The perf schema for the database in `url`: `<db>_perf`. The migrator account holds ALL on
 * exactly this schema and no global privileges (infrastructure/mysql/init/01-users.sh).
 */
export function perfSchemaName(url: string): string {
  const db = decodeURIComponent(new URL(url).pathname.replace(/^\//, ''));
  const name = `${db}_perf`;
  assertSchemaName(name);
  return name;
}

/** Drops and recreates `schema` (the account needs CREATE and DROP on that schema). */
export async function recreateSchema(client: SqlClient, schema: string): Promise<void> {
  assertSchemaName(schema);
  await client.$executeRawUnsafe(`DROP DATABASE IF EXISTS \`${schema}\``);
  await client.$executeRawUnsafe(
    `CREATE DATABASE \`${schema}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
  );
}

export async function dropSchema(client: SqlClient, schema: string): Promise<void> {
  assertSchemaName(schema);
  await client.$executeRawUnsafe(`DROP DATABASE IF EXISTS \`${schema}\``);
}

/**
 * Applies every migration to the database in `url` with the Prisma CLI (`migrate deploy`).
 * Both datasource variables point at that database, so nothing else is touched. Output is
 * captured and returned only on failure, with connection strings masked.
 */
export function applyMigrations(url: string): Promise<void> {
  const cli = require.resolve('prisma/build/index.js', { paths: [PACKAGE_ROOT] });
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [cli, 'migrate', 'deploy'], {
      cwd: PACKAGE_ROOT,
      env: { ...process.env, DATABASE_URL: url, MIGRATION_DATABASE_URL: url },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) return resolvePromise();
      const masked = output.replace(/mysql:\/\/[^\s"']+/g, 'mysql://***');
      reject(new Error(`prisma migrate deploy exited with ${code}:\n${masked}`));
    });
  });
}
