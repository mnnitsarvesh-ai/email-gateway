import { createConnection, type Connection, type RowDataPacket } from 'mysql2/promise';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * The migrator account (MIGRATION_DATABASE_URL) has ALL on the gateway schema and on two
 * throwaway schemas (<db>_shadow, <db>_perf) only: no privilege on *.*, so it cannot read or
 * rewrite the grant tables in `mysql.*` (infrastructure/mysql/init/01-users.sh).
 */
const PRIVILEGE_ERRNOS = [1142, 1044, 1227];

async function errno(work: Promise<unknown>): Promise<number | undefined> {
  const err = (await work.then(
    () => undefined,
    (e: unknown) => e,
  )) as { errno?: number } | undefined;
  return err?.errno;
}

let migrator: Connection;
let schema: string;

beforeAll(async () => {
  migrator = await createConnection(stack.migrationDatabaseUrl());
  const [[row]] = await migrator.query<RowDataPacket[]>('SELECT DATABASE() AS db');
  schema = String(row?.db);
});

afterAll(async () => {
  await migrator?.end();
});

describe('migrator account privileges', () => {
  it('holds no global privileges, only schema-level grants on the three schemas', async () => {
    const [rows] = await migrator.query<RowDataPacket[]>('SHOW GRANTS');
    const grants = rows.map((r) => String(Object.values(r)[0]));
    const global = grants.filter((g) => g.includes(' ON *.* '));
    expect(global).toHaveLength(1);
    expect(global[0]).toMatch(/^GRANT USAGE ON \*\.\* TO /);
    const escaped = schema.replaceAll('_', '\\_');
    const scoped = grants.filter((g) => !g.includes(' ON *.* '));
    expect(scoped).toHaveLength(3);
    for (const g of scoped) expect(g).toMatch(/^GRANT ALL PRIVILEGES ON `/);
    const targets = scoped.map((g) => /ON `([^`]+)`\.\*/.exec(g)?.[1]).sort();
    expect(targets).toEqual([schema, `${escaped}\\_perf`, `${escaped}\\_shadow`].sort());
  });

  it('cannot read or write the mysql system schema', async () => {
    expect(PRIVILEGE_ERRNOS).toContain(await errno(migrator.query('SELECT 1 FROM mysql.user')));
    expect(PRIVILEGE_ERRNOS).toContain(
      await errno(migrator.query('UPDATE mysql.user SET max_connections = 0 WHERE 1 = 0')),
    );
    expect(PRIVILEGE_ERRNOS).toContain(
      await errno(migrator.query('INSERT INTO mysql.db (Host, Db, User) VALUES ("%", "x", "y")')),
    );
    expect(PRIVILEGE_ERRNOS).toContain(
      await errno(migrator.query("CREATE USER 'it_should_not_exist'@'%'")),
    );
  });

  it('cannot create schemas other than its throwaway ones', async () => {
    expect(PRIVILEGE_ERRNOS).toContain(
      await errno(migrator.query(`CREATE DATABASE \`${schema}_it_other\``)),
    );
    // `_` must not act as a wildcard in the throwaway grants.
    const lookalike = `${schema.slice(0, -1)}X_shadow`;
    expect(PRIVILEGE_ERRNOS).toContain(
      await errno(migrator.query(`CREATE DATABASE \`${lookalike}\``)),
    );
  });
});
