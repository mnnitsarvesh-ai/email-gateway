# Indexing

Every index in the schema exists for a documented query ([query-examples.md](query-examples.md)) or a constraint. Section 3 of [the step design](../plan/steps/01-database.md#3-data-model) lists the complete set per table. Do not add an index to a partitioned table without a documented query and a plan from `pnpm db:perf`.

## Rules

1. **Tenant-scoped indexes lead with `organization_id`.** Every tenant query filters by it, and putting it first keeps one tenant's rows together in the index, so the query never touches other tenants' entries.
2. **Write-heavy tables get the minimum.** Each secondary index costs a B-tree insert per row. On the message tables (about 1M messages and 15–20M child rows a day at target volume), every extra index is millions of random writes a day plus buffer-pool pressure. So the detail tables (`email_events`, `scan_engine_results`, `email_message_status_history`, `delivery_attempts`, `email_headers`, `policy_execution_logs`) have only their primary key and the unique key that makes writes idempotent. They are always read through their message (`message_id, received_at`).
3. **Unique keys double as lookup indexes.** `(message_id, rcpt_seq, received_at)` makes recipient inserts idempotent and also serves "recipients of a message" by its `message_id` prefix.
4. **Keyset pagination needs the sort columns in the index.** `(organization_id, received_at, id)` on `email_messages` serves `ORDER BY received_at DESC, id DESC` without a filesort.
5. **Purge and job queries get an index on their predicate** (`expires_at`, `processed_at`, `(status, next_attempt_at)`), so batched deletes and pollers never scan.

## Prefix indexes

Email addresses are `VARCHAR(320)` in `utf8mb4` (up to 1,280 bytes), which is long for an index key. Four indexes use a 100-character prefix:

| Index                                                                   | Query                               |
| ----------------------------------------------------------------------- | ----------------------------------- |
| `email_recipients (organization_id, address(100), received_at)`         | Messages for a recipient (tracking) |
| `bounce_events (organization_id, recipient_address(100), occurred_at)`  | Bounce history of an address        |
| `quarantine_messages (organization_id, recipient_address(100), status)` | Q6, end-user quarantine             |
| `policy_exceptions (organization_id, exception_type, match_value(100))` | Exception matching                  |

100 characters distinguishes practically every real address. A prefix index cannot be covering, so MySQL re-reads the row to compare the full value (the plan shows `Using where`), and columns after the prefix in the index are still used for range and equality. Unique keys never use a prefix: `delivery_suppressions (organization_id, address)` is a full-length unique key, because uniqueness on a prefix would be wrong.

## Partition pruning and secondary indexes

In a partitioned InnoDB table, **every secondary index is partitioned too** (local indexes). There is no global index. That has three consequences:

- With a predicate on the partition column, MySQL first prunes to the matching partitions and then uses the index inside each of them. Q1 reads 2 partitions out of 9, and Q2 reads 1.
- Without one, the same index is probed **in every partition**: one B-tree descent per partition. For selective predicates that return a few rows (Q7 stuck messages, Q10 hash hunt, Q8 outbox poll), this stays at well under 2 ms with 9 monthly partitions (see the [report](performance-report.md)). It grows linearly with the number of partitions, which retention keeps small.
- **Uniqueness is per partition.** That is why every unique key ends with the partition column: a unique key on `message_id` alone could not be enforced across partitions. Global uniqueness of message ids and ingestion keys is enforced by the non-partitioned registry `message_identities`.

Secondary indexes in InnoDB also carry the primary key. For partitioned tables that is `(id, received_at)`, 15 bytes. `BIGINT` keys instead of `CHAR(36)` UUIDs save about 30 bytes per entry in every secondary index ([ADR-0014](../architecture/adr/0014-mysql-data-model-partitioning-read-write-split.md)).

## Per-table rationale

Partitioned tables (all have `PRIMARY KEY (id, <partition column>)`):

| Table                          | Index                                                               | Why                                                                                          |
| ------------------------------ | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `email_messages`               | `(organization_id, received_at, id)`                                | Q1 tenant list with keyset pagination, Q11 driver                                            |
|                                | `(status, status_changed_at)`                                       | Q7 stuck-message reconciliation                                                              |
| `email_recipients`             | UQ `(message_id, rcpt_seq, received_at)`                            | Idempotent insert; recipients of a message (Q2)                                              |
|                                | `(organization_id, address(100), received_at)`                      | Message tracking by recipient                                                                |
| `email_headers`                | UQ `(message_id, seq, received_at)`                                 | Idempotent insert; headers of a message                                                      |
| `email_attachments`            | UQ `(message_id, part_index, received_at)`                          | Idempotent insert; attachments of a message                                                  |
|                                | `(organization_id, sha256)`                                         | Q10 hash hunt (incident response)                                                            |
| `email_events`                 | `(message_id, received_at)`                                         | Q4 timeline (no unique key: idempotency comes from `processOnce`)                            |
| `email_message_status_history` | UQ `(message_id, version, received_at)`                             | One row per version (optimistic concurrency); Q4                                             |
| `email_scans`                  | UQ `(message_id, scan_kind, attempt, received_at)`                  | Idempotent insert per scan attempt; Q3                                                       |
| `scan_engine_results`          | UQ `(scan_id, engine, received_at)`                                 | One result per engine per scan; Q3 join                                                      |
| `policy_execution_logs`        | UQ `(message_id, evaluation_seq, received_at)`                      | Idempotent insert per evaluation                                                             |
| `email_deliveries`             | UQ `(recipient_id, delivery_seq, received_at)`                      | One delivery per recipient and sequence (initial, release, redirect)                         |
|                                | `(message_id, received_at)`                                         | Deliveries of a message; Q11 join                                                            |
|                                | `(status, last_attempt_at)`                                         | Retry scheduler and stuck-delivery reconciliation                                            |
| `delivery_attempts`            | UQ `(delivery_id, attempt_no, received_at)`                         | Idempotent insert per attempt                                                                |
| `bounce_events`                | UQ `(organization_id, dedupe_key, occurred_at)`                     | Deduplicates DSNs (`occurred_at` is parsed from the DSN, so redelivery maps to the same key) |
|                                | `(organization_id, recipient_address(100), occurred_at)`            | Bounce history of an address                                                                 |
| `email_archives`               | UQ `(message_id, received_at)`                                      | One archive per message                                                                      |
|                                | `(organization_id, received_at)`, `(organization_id, retain_until)` | Archive search by date; expiry job                                                           |
| `message_outbox`               | `(published_at, id)`                                                | Q8 relay poll (`published_at IS NULL ORDER BY id`)                                           |
| `audit_logs`                   | `(organization_id, created_at)`                                     | Q12 audit trail per tenant                                                                   |
|                                | `(resource_type, resource_id)`                                      | History of one resource                                                                      |
| `webhook_deliveries`           | UQ `(subscription_id, event_id, event_occurred_at)`                 | One delivery per subscription and event                                                      |
|                                | `(status, next_attempt_at)`                                         | Retry scheduler                                                                              |

`email_deliveries` deliberately has no `organization_id` index: per-tenant delivery reports drive from `email_messages` (Q11) or come from ClickHouse.

Non-partitioned tables, the notable ones:

| Table                     | Index                                                                                                                                                     | Why                                                                                                                    |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `message_identities`      | UQ `public_id`, UQ `(organization_id, ingest_key)`                                                                                                        | Q2 entry point; ingestion idempotency                                                                                  |
| `message_idempotency`     | PK `(consumer, event_id)`, `(processed_at)`                                                                                                               | Q9; 30-day purge                                                                                                       |
| `quarantine_messages`     | `(organization_id, status, quarantined_at)`, `(organization_id, recipient_address(100), status)`, `(status, expires_at)`, UQ `(message_id, recipient_id)` | Q5, Q6, expiry job, one quarantine per recipient                                                                       |
| `domains`                 | UQ `verified_name` (generated), UQ `(organization_id, name)`, `(name)`, `(organization_id, status)`                                                       | Q13 tenant resolution (verified owner only); one claim per tenant; competing claims; domain list                       |
| `delivery_suppressions`   | UQ `(organization_id, address)`, `(expires_at)`                                                                                                           | Q14; expiry purge                                                                                                      |
| `users`                   | UQ `(organization_id, email)`, `(organization_id, status)`                                                                                                | Login and invite lookup; user list                                                                                     |
| `user_sessions`           | UQ `refresh_token_hash`, `(user_id, revoked_at)`, `(family_id, revoked_at)`, `(expires_at)`                                                               | Refresh, revoke-all, live row of a rotation family (`revoked_at IS NULL`) and family revoke, purge                     |
| `user_tokens`             | UQ `token_hash`, `(user_id, purpose, consumed_at)`, `(expires_at)`                                                                                        | Token redemption by hash; consume a user's earlier unconsumed tokens of a purpose; purge                               |
| `user_mfa_recovery_codes` | UQ `(user_id, code_hash)`                                                                                                                                 | Recovery-code redemption by HMAC within the user                                                                       |
| `organizations`           | `(status, purge_after)`                                                                                                                                   | Deferred purge job: deleted organizations past `purge_after`                                                           |
| `api_keys`                | UQ `key_prefix`, `(organization_id, revoked_at)`                                                                                                          | Key lookup by its shown prefix, then constant-time hash compare; key list                                              |
| `roles`                   | UQ `(organization_id, key)`, `(key)`                                                                                                                      | Role lookup; NULL `organization_id` does not collide, so the seed enforces system-role uniqueness                      |
| `threat_indicators`       | UQ `(org_scope, source, indicator_type, value_sha256)` (`org_scope` generated, 0 = platform), `(indicator_type, value_sha256)`                            | Tenant-scoped feed/analyst upsert (no cross-tenant collision); lookup by hashed value (values can be 2,048 characters) |
| `email_policies`          | `(organization_id, status, direction, priority)`                                                                                                          | Load the active policies of a tenant in evaluation order                                                               |
