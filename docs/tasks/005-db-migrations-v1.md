# 005: DB migrations v1 (dbmate) — tenancy, message identity, partitioned message tables

Owner agent: backend-engineer
Depends on: 001, 003
Status: draft
Branch: feat/005-db-migrations-v1
Phase: 0

**Contracts-first task.** This DDL is the shared contract for `ingest-service`, the workers, `aggregator`, `policy-engine`, `delivery-service` and `api`.

## User story

Story: _to be written by product-owner_

As a pipeline service author, I want the v1 MySQL schema with tenant scoping, global message identity and LMTP-retry dedupe built in so that ingest can commit message + recipients + outbox in one writer transaction and every later query is tenant-scoped.

## Acceptance criteria

AC-1 Given an empty MySQL writer, when `pnpm dbmate up` runs, then it exits 0 and all tables listed in the task exist (`organizations, domains, mail_servers, users, message_identity, email_messages, message_recipients, scans, deliveries, outbox, quarantine, audit_logs, idempotency_keys`) (assumes default for NEEDS SARVESH #1: `email_messages`).
AC-2 Given a migrated database, when `pnpm dbmate up` runs again, then it exits 0 and applies nothing; `dbmate status` shows no pending migrations.
AC-3 Given each migration file, when inspected, then it is named `YYYYMMDDHHMMSS_create_<table>.sql`, contains one logical change, and `-- migrate:down` is empty and commented as intentional; `db/schema.sql` is committed and matches `dbmate dump` (a diff is empty).
AC-4 Given `information_schema`, when queried, then every table except `organizations` has `organization_id BINARY(16) NOT NULL` and an index whose first column is `organization_id`.
AC-5 Given any tenant table, when an `INSERT` omits `organization_id`, or sets it NULL, then MySQL returns an error (1364 or 1048) and no row is stored; one test per tenant table.
AC-6 Given `information_schema.COLUMNS`, when queried, then no column default equals `'clean'`, and `scans.state` and every state column are `NOT NULL` with no default.
AC-7 Given `scans`, when inserting `state='clean'` with a `reason_code`, or `state` in `timeout|error|not_scanned` with NULL `reason_code`, then the CHECK constraint rejects it (error 3819); `clean` with NULL reason and `timeout` with a reason succeed.
AC-8 Given `email_messages`, `message_recipients`, `scans` and `deliveries`, when `information_schema.PARTITIONS` is queried, then each is partitioned by RANGE COLUMNS on `received_at` with partitions `p202611` through `p202812` plus `pmax`; an insert with `received_at` in 2030 succeeds into `pmax`.
AC-9 Given `message_identity`, when inserting a second row with the same (`organization_id`, `dedupe_key`), then it fails with duplicate-key error 1062; the same `dedupe_key` under another organization succeeds.
AC-10 Given `message_recipients`, when inserting the same (`message_uuid`, `rcpt_hash`, `received_at`) twice, then the second fails with 1062.
AC-11 Given `scans`, when `INSERT ... ON DUPLICATE KEY UPDATE message_uuid = message_uuid` is run twice with the same (`message_uuid`, `stage`, `stage_version`, `received_at`), then one row exists and the first row's values are unchanged.
AC-12 Given `deliveries`, when inserting a second row for the same (`message_uuid`, `stage_version`, `received_at`), then it fails with 1062.
AC-13 Given `domains`, when organization A and B both hold `unverified.test` as `pending`, then both rows exist; when A is set `verified`, then B's attempt to set `verified` for the same name fails with 1062 on `verified_name`.
AC-14 Given `organizations`, when a row is inserted without `archiving_enabled`, then it is `0`/FALSE (never archive by default).
AC-15 Given `outbox`, when inserting a `payload` over 16 KiB, then the CHECK rejects it, or if MySQL refuses that CHECK expression the limit is documented in the task and enforced in `@esg/mq` (008 AC for size guard covers it).
AC-16 Given `quarantine`, when inserting a row whose `message_uuid` is not in `message_identity`, then the FK rejects it (error 1452); a second row for the same (`organization_id`, `message_uuid`) fails with 1062.
AC-17 Given the writer and `mysql-replica`, when `information_schema` is compared, then the table and column definitions are identical.
AC-18 Given the migrations, when applied to a MySQL 8.0 and a MySQL 8.4 container, then both succeed (no 8.4-only syntax).
AC-19 Given the repo, when `grep` runs over `db/migrations`, then no table named like an event or history table (`*_events`, `*_history`, `delivery_attempts`) exists (hard rule 11).
AC-20 Given `db/seeds/local/001_tenants.sql` applied, when queried, then `tenant-a` has `tenant-a.test` verified and a mail server `mailpit-tenant:1025`, `tenant-b` has `tenant-b.test` verified, `unverified.test` is `pending` for both, ids are fixed UUIDv7 values, and the file contains no credentials (gitleaks passes).

### Open questions for Sarvesh

- NEEDS SARVESH #2 (cross-tenant system queries versus hard rule 7): no AC is written for the outbox-poll, deadline-sweep or partition-maintenance queries; they need an ADR and a Phase 1 AC.
- NEEDS SARVESH #3 (retention defaults) is not tested here; no purge job exists in this task.
- NEEDS SARVESH #4: ADR-026 and ADR-027 must be Accepted before this task is `ready`.

## Out of scope

- Event or history tables. Per-stage events, verdict history and delivery attempts go to **ClickHouse** (hard rule 11, ADR-012) in Phase 1.
- The `connectors` table (outbound connectors) and the policy tables. Those come in Phase 3 and Phase 2.
- Partition maintenance automation (a job that adds future partitions, plus an alert). That is a Phase 1 task. This task creates the initial partitions only.
- Retention purge jobs, archive tables (Phase 5), and SSO/SCIM columns (Phase 5).
- Platform-operator (non-tenant) users and audit. A separate table comes later.

## Design notes

See **Proposed ADR-026** (partitioning and identity table) and **ADR-027** (UUIDv7, `BINARY(16)`).

### Conventions

- One logical change per migration, named `db/migrations/YYYYMMDDHHMMSS_create_<table>.sql`. Forward-only, so `-- migrate:down` is left empty and commented as intentional.
- All ids are `BINARY(16)` UUIDv7, except `outbox.id` and `audit_logs.id`, which are `BIGINT UNSIGNED AUTO_INCREMENT` (ordering, append-only).
- Timestamps are `DATETIME(6)` in UTC. The server runs with `default_time_zone='+00:00'`.
- `utf8mb4`, `utf8mb4_0900_ai_ci`. Email addresses are stored lowercased, with an extra `*_hash BINARY(32)` (SHA-256 of the normalised address) for indexed lookups.
- **`organization_id BINARY(16) NOT NULL`, with an index whose leftmost column is `organization_id`, on every tenant table** (hard rule 7). `organizations` is the tenant root: its `id` *is* the `organization_id`.
- **No `DEFAULT 'clean'`** on any state column. State columns are `NOT NULL` with no default.
- **DDL must work on MySQL 8.0 and 8.4** until ADR-025 is decided. Don't use 8.4-only syntax.
- `db/schema.sql` (from `dbmate dump`) is committed, so reviewers can see schema diffs.

### Workspace

`db/` is a workspace package, `@esg/db-migrations`, with `package.json`, `vitest.config.ts` and `test/`. Its tests run against the `deploy/local` writer and replica.

### Tables

**1. `organizations`**
- `id` PK, `slug` UNIQUE, `name`, `status ENUM('active','suspended','deleted')`.
- `archiving_enabled BOOLEAN NOT NULL DEFAULT FALSE`. Never archive by default.
- `created_at`, `updated_at`.

**2. `domains`**
- `id` PK, `organization_id` (FK → organizations), `name VARCHAR(253)` (lowercased A-label).
- `status ENUM('pending','verified','disabled')`, `verification_token_hash BINARY(32)`, `verified_at`.
- `verified_name VARCHAR(253) GENERATED ALWAYS AS (IF(status='verified', name, NULL)) STORED`, with **UNIQUE(`verified_name`)**. A domain can be *verified* by at most one organization, which tenant resolution (hard rule 4) depends on. Pending claims by several organizations are allowed.
- UNIQUE(`organization_id`, `name`).

**3. `mail_servers`** (tenant downstream delivery targets)
- `id`, `organization_id` (FK), `domain_id` NULL (FK; NULL means all of the organization's domains), `host`, `port`, `tls_policy ENUM('may','encrypt','verify')`, `priority`, `enabled`.
- INDEX(`organization_id`, `domain_id`).

**4. `users`**
- `id`, `organization_id` (FK), `email`, `email_hash`, `role ENUM('org_admin','org_auditor','end_user')`, `status`, timestamps.
- UNIQUE(`organization_id`, `email_hash`).
- No credential columns in v1. Portal auth arrives in Phase 3.

**5. `message_identity`** (non-partitioned; the global identity and FK anchor)
- `message_uuid BINARY(16)` PK, `organization_id`, `received_at DATETIME(6)`.
- `dedupe_key BINARY(32) NOT NULL`, with UNIQUE(`organization_id`, `dedupe_key`).
- INDEX(`organization_id`, `received_at`).
- `dedupe_key` = SHA-256 over (postfix instance id, long queue id, a fingerprint of the stored EML bytes). The exact recipe is fixed by the Phase 1 ingest task and documented in that task. It is **never** derived from header values alone (ADR-021).
- Why this table exists: partitioned tables can't have foreign keys, and every unique key on them must include the partition column. So global uniqueness of `message_uuid` and the LMTP-retry dedupe key live here. Ingest inserts this row first, inside the same writer transaction. A duplicate-key error on (`organization_id`, `dedupe_key`) means "already ingested". Ingest then accepts only the missing recipients and returns `250` without writing a second message.

**6. `email_messages`** (PARTITION BY RANGE COLUMNS(`received_at`), monthly)
- `message_uuid`, `received_at`, `organization_id`, `direction ENUM('inbound','outbound','internal')`.
- `source_type ENUM('mx_listener','connector')` and `source_id VARCHAR(64)`. These record what tenancy was resolved *from*.
- `envelope_from VARCHAR(320)` (sender-controlled; data only).
- `size_bytes`, `eml_bucket`, `eml_key VARCHAR(512)`, `eml_sha256 BINARY(32)`, `postfix_queue_id`.
- `status ENUM('received','scanning','decided','handed_off','quarantined','discarded')`.
- `decision ENUM('deliver','tag','quarantine','discard') NULL`, `policy_version`, `decided_at`, `created_at`, `updated_at`.
- **PRIMARY KEY (`message_uuid`, `received_at`)**.
- INDEX(`organization_id`, `received_at`), INDEX(`organization_id`, `status`, `received_at`).
- No FKs, because the table is partitioned. Integrity comes from `message_identity` and the single writer transaction.

**7. `message_recipients`** (partitioned the same way)
- `message_uuid`, `received_at`, `organization_id`, `rcpt_seq SMALLINT`, `rcpt_address`, `rcpt_hash`.
- `lmtp_status ENUM('accepted','tempfailed')`, `delivery_status` (current state only).
- PK(`message_uuid`, `rcpt_seq`, `received_at`).
- UNIQUE(`message_uuid`, `rcpt_hash`, `received_at`). Retry dedupe per recipient.
- INDEX(`organization_id`, `rcpt_hash`, `received_at`). End-user "my mail" lookups.

**8. `scans`** (partitioned; the current result per stage, not history)
- `message_uuid`, `received_at`, `organization_id`, `stage VARCHAR(32)`, `stage_version SMALLINT UNSIGNED`.
- `state ENUM('clean','suspicious','malicious','unknown','timeout','error','not_scanned') NOT NULL` (no default), `reason_code VARCHAR(32) NULL`.
- `engine_name`, `engine_version`, `signatures_version`, `score DECIMAL(8,3) NULL`.
- `findings JSON` (rule ids only, at most 50 entries; enforced by `@esg/schemas`).
- `started_at`, `finished_at`, `created_at`.
- **PK(`message_uuid`, `stage`, `stage_version`, `received_at`)**. This is the idempotency key's natural unique key, so a redelivered result does `INSERT … ON DUPLICATE KEY UPDATE message_uuid = message_uuid`, which is a no-op.
- INDEX(`organization_id`, `received_at`).
- Add a CHECK constraint `CHECK (state <> 'clean' OR reason_code IS NULL)`, plus `CHECK (state NOT IN ('timeout','error','not_scanned') OR reason_code IS NOT NULL)`. This is defence in depth for hard rule 5. MySQL 8.0.16+ enforces CHECK constraints.

**9. `deliveries`** (partitioned; the current handoff state)
- `message_uuid`, `received_at`, `organization_id`, `stage_version`, `mail_server_id NULL`.
- `handoff_status ENUM('pending','handed_off')`, `outbound_queue_id`, `handed_off_at`.
- PK(`message_uuid`, `stage_version`, `received_at`). One handoff per message per delivery stage version (idempotency, ADR-022).
- INDEX(`organization_id`, `received_at`).
- Postfix delivery outcomes such as deferred or delivered are ClickHouse events, not columns updated per attempt.

**10. `outbox`** (non-partitioned, short-lived rows)
- `id BIGINT AUTO_INCREMENT` PK, `organization_id`, `message_uuid NULL`, `event_type`, `routing_key`.
- `payload JSON NOT NULL` (an `EventEnvelope` from 002), with `CHECK (JSON_STORAGE_SIZE(payload) <= 16384)`. If MySQL refuses that CHECK expression, enforce the limit in `@esg/mq` and document it here.
- `created_at`, `published_at NULL`, `publish_attempts`.
- INDEX(`published_at`, `id`) for the publisher poll (`SELECT … WHERE published_at IS NULL ORDER BY id LIMIT n FOR UPDATE SKIP LOCKED`).
- INDEX(`organization_id`, `created_at`).
- Rows are deleted after publishing by a batched cleanup in Phase 1.

**11. `quarantine`** (non-partitioned, because volume is a fraction of all mail)
- `id` PK, `organization_id`, `message_uuid` (**FK → `message_identity`**), `received_at`.
- `reasons JSON` (engines, states, rule ids, policy rule id, so the portal always shows a block reason), `policy_rule_id`.
- `status ENUM('held','released','deleted','expired')`, `expires_at`, `released_by_user_id NULL`, `released_at NULL`.
- UNIQUE(`organization_id`, `message_uuid`), INDEX(`organization_id`, `status`, `created_at`).

**12. `audit_logs`** (control-plane actions by tenant users and the system)
- `id BIGINT AUTO_INCREMENT`, `organization_id`, `actor_type ENUM('user','system','api_key')`, `actor_id`, `action VARCHAR(64)`, `target_type`, `target_id`.
- `metadata JSON` (never message content), `client_ip VARBINARY(16) NULL`, `created_at`.
- INDEX(`organization_id`, `created_at`).
- Append-only. *Recommendation:* in production, `esg_writer` gets INSERT and SELECT only on this table. devops-engineer handles that in grants.
- Per-message pipeline events (including `discard`, ADR-020) go to ClickHouse, not here.

**13. `idempotency_keys`** (added by architect; generic store for side effects that have no natural unique key)
- `idem_key VARCHAR(128)` PK, `organization_id`, `created_at`.
- INDEX(`organization_id`, `created_at`).
- Consumers insert the key in the same writer transaction as their side effect.

### Partitions

- Initial partitions are monthly, from `p202611` (Nov 2026) through `p202812` (Dec 2028), plus a catch-all `pmax VALUES LESS THAN (MAXVALUE)`.
- The catch-all means an insert can never fail because a partition is missing. Such a failure would make ingest return `4xx` for all mail.
- The Phase 1 maintenance job splits `pmax` (`REORGANIZE PARTITION`) while it is still empty, and an alert fires if fewer than 3 future months exist or `pmax` holds any rows.
- `message_identity` isn't partitioned. Retention purges it in batches (Phase 1).

### Seeds

`db/seeds/local/001_tenants.sql`, applied only by the local `migrate` one-shot from 003:
- `tenant-a` with `tenant-a.test` verified and a mail server `mailpit-tenant:1025`.
- `tenant-b` with `tenant-b.test` verified.
- A pending `unverified.test` claimed by both tenants, used for negative tests.
- Fixed UUIDv7 ids, so tests can reference them. No credentials.

### Tests (`db/test/`)

- `dbmate up` on an empty writer succeeds, and running it again is a no-op.
- Schema invariants, checked through `information_schema`:
  - every table except `organizations` has `organization_id BINARY(16) NOT NULL`, and an index whose first column is `organization_id`;
  - no column default equals `'clean'`;
  - `email_messages`, `message_recipients`, `scans` and `deliveries` are partitioned on `received_at`.
- The replica has the identical schema (GTID replication of DDL).
- The `verified_name` uniqueness stops a second organization from verifying the same domain.
- CHECK constraints reject `clean` with a reason, and `timeout` without one.
- The `message_identity` dedupe unique key rejects a duplicate (`organization_id`, `dedupe_key`).

## Hard rules at risk

- **7 (`organization_id` everywhere).** Covered by the schema-invariant test. Queries are reviewed in each service task.
- **11 (event history in ClickHouse).** No history or event tables. `scans` and `deliveries` hold current state keyed by stage version.
- **5 (no clean on failure).** No `clean` defaults, plus CHECK constraints.
- **6 (idempotency).** Natural PKs on `scans` and `deliveries`, `idempotency_keys` for everything else, and the `message_identity` dedupe key for LMTP retries.
- **4 (tenant not from headers).** Unique `verified_name`, and `source_type`/`source_id` record where the tenant was resolved from.
- **1 (250 after persist).** The schema supports a single small transaction: identity, message, recipients, outbox. No history writes inside it (ADR-021).
- **9.** Seeds hold no secrets.

## NEEDS SARVESH

1. **Table name.** Your brief says `email_messages`. CLAUDE.md and ADR-021 say `messages`. *Recommendation:* use `email_messages` (more specific, and avoids clashing with a generic word), and update the CLAUDE.md wording in this task. The ADR's decision is unchanged.
2. **Cross-tenant system queries vs hard rule 7.** `outbox-publisher` (poll for unpublished rows), the aggregator's stage-deadline sweep, partition maintenance and retention purges all query **across tenants** by design, so they can't put `organization_id` in the `WHERE` clause. Options:
   - (a) a written exception: these specific queries are allowed, each marked `/* esg:cross-tenant: <reason> */` and listed in an allow-list that code-reviewer checks;
   - (b) a per-tenant poll loop, which costs a lot and adds complexity at 1M messages a day.

   *Recommendation:* (a), recorded as a new ADR. Without this decision, Phase 1's `outbox-publisher` can't be written without breaking a hard rule.
3. **Retention defaults.** These drive partition and purge design. *Recommendation:* message metadata 90 days, quarantine 30 days, EML in the mail bucket 30 days (longer only through archiving), audit logs 1 year. Also check CERT-In's 180-day log requirement (see `docs/human-tasks.md`).
4. **Proposed ADR-026 and ADR-027** must be Accepted before this task is `ready`.
