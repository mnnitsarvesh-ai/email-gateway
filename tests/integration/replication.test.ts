import { randomUUID } from 'node:crypto';
import { createConnection, type Connection, type RowDataPacket } from 'mysql2/promise';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

// The primary (`mysql`, via DATABASE_URL) replicates to `mysql-replica`, which the reader account
// reaches via DATABASE_READ_URL. See docs/database/replication.md.

const REPLICATION_TIMEOUT_MS = 10_000;
const POLL_MS = 200;

/** A privilege error, not a read-only error (ER_OPTION_PREVENTS_STATEMENT, 1290). */
const PRIVILEGE_ERRNOS = [1142, 1044];

interface MysqlError {
  errno?: number;
  message: string;
}

async function expectPrivilegeDenied(work: Promise<unknown>): Promise<void> {
  const err = (await work.then(
    () => undefined,
    (e: unknown) => e,
  )) as MysqlError | undefined;
  expect(err, 'statement unexpectedly succeeded').toBeDefined();
  expect(PRIVILEGE_ERRNOS).toContain(err?.errno);
  expect(err?.message).toMatch(/denied/i);
}

/** The reader's credentials, pointed at the primary instead of the replica. */
function readerOnPrimaryUrl(): string {
  const url = new URL(stack.databaseReadUrl());
  url.hostname = stack.host;
  url.port = String(stack.ports.mysql);
  return url.toString();
}

let writer: Connection;
let reader: Connection;

beforeAll(async () => {
  writer = await createConnection(stack.databaseUrl());
  reader = await createConnection(stack.databaseReadUrl());
});

afterAll(async () => {
  await Promise.all([writer?.end(), reader?.end()]);
});

describe('MySQL replication', () => {
  it('the replica runs MySQL 8.4 with GTID, read_only and super_read_only', async () => {
    const [[row]] = await reader.query<RowDataPacket[]>(
      `SELECT VERSION() AS version, @@global.gtid_mode AS gtidMode,
              @@global.read_only AS readOnly, @@global.super_read_only AS superReadOnly,
              @@global.server_id AS serverId`,
    );
    expect(row?.version).toMatch(/^8\.4\./);
    expect(row?.gtidMode).toBe('ON');
    expect(Number(row?.readOnly)).toBe(1);
    expect(Number(row?.superReadOnly)).toBe(1);

    const [[primary]] = await writer.query<RowDataPacket[]>(
      'SELECT @@global.gtid_mode AS gtidMode, @@global.server_id AS serverId',
    );
    expect(primary?.gtidMode).toBe('ON');
    expect(Number(primary?.serverId)).not.toBe(Number(row?.serverId));
  });

  it('the reader can run SHOW REPLICA STATUS, and both replication threads are running', async () => {
    const [rows] = await reader.query<RowDataPacket[]>('SHOW REPLICA STATUS');
    expect(rows).toHaveLength(1);
    const status = rows[0]!;
    expect(status.Replica_IO_Running).toBe('Yes');
    expect(status.Replica_SQL_Running).toBe('Yes');
    expect(Number(status.Auto_Position)).toBe(1);
    expect(status.Seconds_Behind_Source).not.toBeNull();
    expect(Number.isFinite(Number(status.Seconds_Behind_Source))).toBe(true);
  });

  it('a row written on the primary becomes visible on the replica, with its GTID', async () => {
    const key = `it-repl-${randomUUID()}`;
    try {
      await writer.execute(
        'INSERT INTO system_settings (`key`, value, updated_at) VALUES (?, JSON_OBJECT(?, ?), NOW(3))',
        [key, 'source', 'replication.test'],
      );
      const [[gtid]] = await writer.query<RowDataPacket[]>(
        'SELECT @@global.gtid_executed AS executed',
      );
      const primaryExecuted = String(gtid?.executed ?? '');
      expect(primaryExecuted).not.toBe('');

      const deadline = Date.now() + REPLICATION_TIMEOUT_MS;
      let replicated: RowDataPacket | undefined;
      while (!replicated && Date.now() < deadline) {
        const [rows] = await reader.execute<RowDataPacket[]>(
          'SELECT value FROM system_settings WHERE `key` = ?',
          [key],
        );
        replicated = rows[0];
        if (!replicated) await new Promise((r) => setTimeout(r, POLL_MS));
      }
      expect(replicated, `row not replicated within ${REPLICATION_TIMEOUT_MS} ms`).toBeDefined();
      expect(replicated?.value).toEqual({ source: 'replication.test' });

      // Everything the primary had executed by the insert has been applied on the replica.
      const [[subset]] = await reader.query<RowDataPacket[]>(
        'SELECT GTID_SUBSET(?, @@global.gtid_executed) AS contained',
        [primaryExecuted],
      );
      expect(Number(subset?.contained)).toBe(1);
    } finally {
      await writer.execute('DELETE FROM system_settings WHERE `key` = ?', [key]);
    }
  });

  describe('the reader account cannot change data (privilege errors, not just read-only)', () => {
    const key = `it-repl-denied-${randomUUID()}`;

    it.each([
      [
        'INSERT',
        'INSERT INTO system_settings (`key`, value, updated_at) VALUES (?, JSON_OBJECT(), NOW(3))',
      ],
      ['UPDATE', 'UPDATE system_settings SET description = ? WHERE `key` = ?'],
      ['DELETE', 'DELETE FROM system_settings WHERE `key` = ?'],
    ])('on the replica: %s is denied', async (_name, sql) => {
      const params = sql.startsWith('UPDATE') ? ['x', key] : [key];
      await expectPrivilegeDenied(reader.execute(sql, params));
    });

    it('on the replica: CREATE TABLE is rejected, and the grants hold no write privilege', async () => {
      // For DDL the replica checks super_read_only (1290) before privileges, so this alone does
      // not prove the account lacks CREATE. The grants below and the primary test below do.
      const err = (await reader
        .query('CREATE TABLE it_reader_should_not_exist (id INT PRIMARY KEY)')
        .then(
          () => undefined,
          (e: unknown) => e,
        )) as MysqlError | undefined;
      expect([...PRIVILEGE_ERRNOS, 1290]).toContain(err?.errno);

      const [rows] = await reader.query<RowDataPacket[]>('SHOW GRANTS');
      const grants = rows.map((row) => String(Object.values(row)[0]));
      const database = new URL(stack.databaseReadUrl()).pathname.slice(1);
      expect(grants).toHaveLength(2);
      expect(grants.some((g) => /^GRANT REPLICATION CLIENT ON \*\.\* TO /.test(g))).toBe(true);
      expect(grants.some((g) => g.startsWith(`GRANT SELECT ON \`${database}\`.* TO `))).toBe(true);
    });

    it('on the primary: INSERT and CREATE TABLE are denied too', async () => {
      const onPrimary = await createConnection(readerOnPrimaryUrl());
      try {
        await expectPrivilegeDenied(
          onPrimary.execute(
            'INSERT INTO system_settings (`key`, value, updated_at) VALUES (?, JSON_OBJECT(), NOW(3))',
            [key],
          ),
        );
        await expectPrivilegeDenied(
          onPrimary.query('CREATE TABLE it_reader_should_not_exist (id INT PRIMARY KEY)'),
        );
        const [[readOnly]] = await onPrimary.query<RowDataPacket[]>(
          'SELECT @@global.read_only AS readOnly',
        );
        // The primary is writable, so the denial above is purely the account's privileges.
        expect(Number(readOnly?.readOnly)).toBe(0);
      } finally {
        await onPrimary.end();
      }
    });
  });
});
