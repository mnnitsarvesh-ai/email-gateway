# 007: packages/db — writer pool, control-plane reader routing, writer-only enforcement

Owner agent: backend-engineer
Depends on: 003, 005, 006
Status: draft
Branch: feat/007-packages-db
Phase: 0

## User story

Story: _to be written by product-owner_

As a service author, I want a MySQL client that gives data-plane services the writer only and gives the control-plane API replica reads with an explicit read-your-writes escape hatch so that replica lag can never influence a mail decision.

## Acceptance criteria

AC-1 Given a data-plane service config built from `@esg/config` root fragments, when its schema is inspected, then it cannot express a reader DSN: `MYSQL_READER_URL` is absent from the schema and from the parsed result; importing `@esg/config/control-plane` from a non-`services/api` fixture fails lint with `no-restricted-imports`.
AC-2 Given `@esg/db`, when `import '@esg/db'` (root) or a deep path outside `exports` is attempted, then Node resolution fails with `ERR_PACKAGE_PATH_NOT_EXPORTED`; only `/writer`, `/control-plane` and `/uuid` resolve.
AC-3 Given a fixture importing `@esg/db/control-plane` outside `services/api`, when ESLint runs, then it fails with the restricted-import rule id.
AC-4 Given `createWriterDb` with the writer DSN, when `SELECT @@server_id` runs through it, then the result is 1.
AC-5 Given `createWriterDb` pointed at the replica DSN (`@@read_only = 1`), when it starts, then it rejects with a clear error mentioning read-only, emits a fatal log, and no connection stays in the pool.
AC-6 Given `createControlPlaneDb`, when `read()` runs `SELECT @@server_id`, then the result is 2; `read({ fresh: true })` and `write()` return 1.
AC-7 Given `scripts/replica-lag.sh pause`, when `write()` inserts a row and then `read()` selects it, then the row is not found; `read({ fresh: true })` finds it; after `resume`, `read()` finds it within 10 s.
AC-8 Given `read()`, when the callback runs an `INSERT`/`UPDATE`/`DELETE`, then it fails with a read-only error (`START TRANSACTION READ ONLY` and `esg_reader` SELECT-only), and no row changes on either server.
AC-9 Given `transaction()`, when the callback inserts into two tables then throws, then the original error is rethrown unchanged, and zero rows remain in both tables.
AC-10 Given `transaction()`, when COMMIT fails (for example the connection is killed before commit), then the promise rejects with the commit error and does not resolve.
AC-11 Given the writer container stopped, when `transaction()` or `query()` is called, then it rejects within the configured connect/query timeout (test sets 2 s and asserts rejection under 5 s) and does not hang.
AC-12 Given a pool configured with `connectionLimit = N`, when N+1 concurrent long transactions start, then the extra one fails or waits no longer than the checkout timeout and rejects with a timeout error.
AC-13 Given a data-plane transaction, when `SELECT @@transaction_isolation` runs inside it, then it is `READ-COMMITTED` by default and `REPEATABLE-READ` when requested via `opts.isolation`.
AC-14 Given `uuidToBin` and `binToUuid`, when 1,000 random UUIDv7 values round-trip, then each is identical; stored in `BINARY(16)`, `ORDER BY` returns ids in creation-time order.
AC-15 Given a logged pool error that includes SQL with bound values, when output is captured, then the DSN password and bound values are `[redacted]`.

## Out of scope

- A query builder or ORM. Use parameterised SQL through mysql2, with zod parsing of rows at the boundary where useful.
- Tenant-scoped query helpers and `packages/tenancy` (tenant resolution). Those are Phase 1, with `policy-adapter` and `ingest-service`.
- Lag-aware automatic routing, such as falling back to the writer when the replica lags by more than N seconds. Callers decide explicitly with `fresh`.
- The idempotency-store helper (Phase 1).
- Deadlock or serialization retry loops. Callers own failure handling. In ingest, any DB error means `4xx`.

## Design notes

### Entry points

These are enforced through the `exports` map of `@esg/db`. There is **no root export**.

```ts
// @esg/db/writer — for every service, including data plane
export function createWriterDb(cfg: WriterDbConfig, log: Logger): Promise<WriterDb>;
interface WriterDb {
  transaction<T>(fn: (tx: Tx) => Promise<T>, opts?: { isolation?: 'READ COMMITTED' | 'REPEATABLE READ' }): Promise<T>;
  query<R>(sql: string, params: readonly unknown[]): Promise<R[]>;   // single statement, autocommit
  close(): Promise<void>;
}

// @esg/db/control-plane — only services/api (lint rule from 001)
export function createControlPlaneDb(cfg: { writer: WriterDbConfig; reader: ReaderDbConfig }, log: Logger): Promise<ControlPlaneDb>;
interface ControlPlaneDb {
  read<T>(fn: (q: ReadOnlyQuery) => Promise<T>, opts?: { fresh?: boolean }): Promise<T>;
  //   fresh: false (default) → reader pool (replica);  fresh: true → writer pool (read-your-writes)
  write<T>(fn: (tx: Tx) => Promise<T>): Promise<T>;                  // always writer, in a transaction
  close(): Promise<void>;
}

// @esg/db/uuid — helpers shared by both
export const uuidToBin: (u: string) => Buffer;  export const binToUuid: (b: Buffer) => string;  // UUIDv7, no byte swap
```

- `ReadOnlyQuery` only exposes `query()`. Calls through `read()` run in a `START TRANSACTION READ ONLY` block. On the reader, the `esg_reader` user is SELECT-only and the replica is `super_read_only`.
- Data-plane code uses the writer default isolation of `READ COMMITTED`, set per session. This reduces gap locking on the outbox and identity inserts. Callers can choose `REPEATABLE READ` per transaction.
- Pools use mysql2/promise with bounded `connectionLimit`, `connectTimeout`, a per-query `timeout` and `enableKeepAlive`, all from config. `transaction()` always rolls back on throw and rethrows the original error.
- The connection-checkout and query timeouts are bounded and configurable, so `ingest-service` can stay inside Postfix's LMTP timeout and return `4xx`.

### How "data-plane services get the writer only" (ADR-019) is enforced

There are five layers. Any one of them failing is caught by another.

1. **Lint (001).** Importing `@esg/db/control-plane` or `@esg/config/control-plane` outside `services/api` is an ESLint error. Fixture tests prove it.
2. **Config (006).** Data-plane config schemas can't express a reader DSN. The fragment lives only in the control-plane subpath, and unknown env keys are stripped.
3. **Runtime guard.** On startup, `createWriterDb` runs `SELECT @@global.read_only, @@global.super_read_only`. If either is `1`, it **refuses to start** with a fatal log. A writer DSN pointed at a replica by mistake fails fast instead of quietly reading stale data.
4. **Credentials.** In AWS, data-plane pods only get the writer secret (devops-engineer, Helm and Terraform outputs from 010 split the writer and reader secret ARNs). Locally, data-plane `.env` files only carry `MYSQL_WRITER_URL` (003).
5. **Review.** code-reviewer treats any data-plane read from a replica as BLOCKING.

### Tests

These are integration tests against `deploy/local`.
- `read()` runs on the replica: `@@server_id = 2`.
- `read({ fresh: true })` and `write()` run on the writer: `@@server_id = 1`.
- **Read-your-writes.** With `scripts/replica-lag.sh pause`:
  - `write()` inserts a row;
  - `read()` doesn't see it (stale);
  - `read({ fresh: true })` does see it.

  Then `resume`.
- `createWriterDb` pointed at the replica DSN rejects with a clear error.
- A writing statement through `read()` fails (read-only transaction).
- `transaction()` rolls back fully when the callback throws. No partial rows remain in a two-table insert.
- With the writer stopped, `transaction()` rejects within the configured timeout, and doesn't hang.
- `uuidToBin` and `binToUuid` round-trip, and `ORDER BY` on `BINARY(16)` v7 ids follows creation time.

## Hard rules at risk

- **2 (writer-only data plane).** This task is the mechanism; see the five enforcement layers.
- **1 (250 after persist).** `transaction()` must surface every failure, including commit failure and timeouts, so ingest can reply `4xx`. It never swallows errors.
- **7.** This package doesn't scope tenants automatically. That stays the caller's job, checked in review. A helper may come in Phase 1.
- **9.** DSNs are `Secret` values (006). Pool errors are logged through the redacting serializer.

## NEEDS SARVESH

None.
