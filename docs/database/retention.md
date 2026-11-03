# Data retention

Retention in MySQL is enforced in two ways ([ADR-0014](../architecture/adr/0014-mysql-data-model-partitioning-read-write-split.md) §7, design [D3/D9](../plan/steps/01-database.md#d9-retention-backup-and-restore-documentation-deliverables)):

- **Platform maximum: partition drops.** The maintenance job (`db:partitions`, see [partitioning.md](partitioning.md)) drops whole partitions once they pass the platform retention of their table. This is the upper bound for every tenant.
- **Shorter retention: batched deletes.** Anything shorter (per tenant or plan), and every non-partitioned table, is purged with indexed, batched `DELETE`s owned by the feature that writes the data.

Mail content (EML, attachments) lives in S3 and follows S3 lifecycle rules. MySQL holds only metadata and object keys.

## Platform tiers (partition drops)

"N months" keeps the current month plus N full months: a partition is dropped when its upper bound ≤ the first day of (current UTC month − N). "N days" drops when the upper bound ≤ today − N days.

| Tier        | Tables                                                                                                                                                         | Retention                                    |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| Core        | `email_messages`, `email_recipients`, `email_attachments`, `email_scans`, `email_deliveries`, `delivery_reinjections`, `bounce_events`                         | 6 months                                     |
| Detail      | `email_headers`, `email_events`, `email_message_status_history`, `scan_engine_results`, `policy_execution_logs`, `delivery_attempts`, `delivery_status_events` | 3 months                                     |
| Operational | `webhook_deliveries`                                                                                                                                           | 2 months                                     |
| Operational | `message_outbox`                                                                                                                                               | 7 days, and never while rows are unpublished |
| Compliance  | `email_archives`, `audit_logs`                                                                                                                                 | Never dropped automatically                  |

Step 2.3: `delivery_reinjections` lives as long as the deliveries it groups (core). The delivery audit trail `delivery_status_events` is detail data: after 3 months the delivery status itself remains on `email_deliveries` (final status, codes, error class) until the core tier drops it, and the per-signal history is gone. `stream_cursors` (one row per consumer) and `mail_destination_presets` (seeded configuration) are not purged.

`email_archives` is governed row by row by archive retention policies and legal holds (step 8.1). `audit_logs` is kept until an operator exports and drops old partitions as a deliberate, recorded operation.

## Purges run by the maintenance job

Both run in batches of 5,000 (rows for `message_idempotency`, an id range for `message_identities`), with a 50 ms pause between batches and at most 200 batches per table per run. The rest continues on the next daily run.

| Table                 | Rule                                                                                                                                                                    | Why                                                                                                                                                                                                             |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `message_idempotency` | `processed_at` older than **30 days**                                                                                                                                   | Redeliveries happen within minutes or hours. 30 days is far beyond any RabbitMQ redelivery or replay window. Indexed by `(processed_at)`                                                                        |
| `message_identities`  | `id < (SELECT MIN(id) FROM email_messages)`, **except** rows still referenced by a live `email_archives` row (`deleted_at IS NULL`) or by any `quarantine_messages` row | Registry ids are allocated in time order, so registry rows below the oldest remaining message belong to messages whose core partitions were dropped. If `email_messages` is empty, nothing is purged. See below |

### Registry rows that outlive the core tier

The registry maps a message's `public_id` to `(id, received_at)`, and that is the only way to reach a message's rows by public id ([partitioning.md](partitioning.md)). Archives are never dropped automatically and quarantine can be kept longer than the 6-month core tier, so a registry row is **kept** while an archive or quarantine row references it. Its `(organization_id, ingest_key)` duplicate protection stays in place for those messages too.

How the purge works (`packages/database/src/partitioning/executor.ts`, `REGISTRY_PURGE_SQL`):

- It walks registry ids in ranges of 5,000, from a watermark (`maintenance_watermarks.message_identities.purged_below`, or the smallest registry id on the first run) up to `MIN(email_messages.id)`, and deletes each range with `NOT EXISTS` anti-joins on `email_archives (message_id, …)` and `quarantine_messages (message_id, …)` (both indexed on `message_id`).
- After each range it advances the watermark, so the rows it keeps are examined once, not on every daily run.
- **Contract for later steps:** when step 8.1 (archive expiry) or step 5.3 (quarantine expiry) deletes the last reference to a message whose id is below `MIN(email_messages.id)`, it deletes that message's `message_identities` row in the same transaction. The maintenance job does not revisit ranges below its watermark.

Covered by unit tests (`executor.test.ts`: ranges, watermark, cap) and by an integration test that runs the exact statement against MySQL (`tests/integration/schema.test.ts`: archived and quarantined registry rows survive, unreferenced and soft-deleted-archive rows are deleted).

## Identity purges run by the api (step 1.3)

The api's `SessionPurgeService` (auth module, design [D5](../plan/steps/02-tenants-auth-rbac.md#d5-sessions-refresh-rotation-and-revocation)) runs hourly on a timer guarded by a KV lock (`jobs:auth-purge`, 55 minutes), so only one api replica purges at a time. It deletes in batches of 1,000 rows with indexed `DELETE … LIMIT`, and is disabled in tests (`AUTH_BACKGROUND_JOBS_ENABLED=false`).

| Table              | Rule                                                                                       | Index          |
| ------------------ | ------------------------------------------------------------------------------------------ | -------------- |
| `user_sessions`    | `expires_at` older than **1 day** (each refresh rotation leaves one revoked row per token) | `(expires_at)` |
| `user_tokens`      | `expires_at` older than **7 days** (consumed and unconsumed alike)                         | `(expires_at)` |
| `login_audit_logs` | `created_at` older than `AUTH_LOGIN_AUDIT_RETENTION_DAYS` (default **365 days**)           | `(created_at)` |

`user_mfa_recovery_codes` has no time-based purge: a user's codes are replaced when they are regenerated, cleared by an MFA reset, and removed with the user (`ON DELETE CASCADE`, like `user_tokens` and `user_sessions`).

## Organization deletion (deferred purge)

Deleting an organization ([D12](../plan/steps/02-tenants-auth-rbac.md#d12-organizations-wp5)) is a soft delete: `status = deleted`, `deleted_at`, and `purge_after = max(now + ORG_DELETION_RETENTION_DAYS, the latest email_archives.retain_until of the organization)`. The index `organizations (status, purge_after)` serves the purge job's scan. The **purge job itself is deferred** (not implemented in step 1.2): it will delete the tenant's rows and S3 objects only after `purge_after`, never while an `archive_legal_holds` row is `active`, and never archives still under retention. Its safeguards are documented in `docs/runbooks/organization-deletion.md`.

## Soft-deleted domains (step 2.1)

Deleting a domain ([D3](../plan/steps/03-domain-onboarding.md#d3-lifecycle-and-status-model)) is a soft delete: `status = deleted`, `deleted_at`, `next_check_at = NULL`. The row and its children (verification rows, DNS record rows, DKIM keys with their public keys and selectors, observed MX rows, settings) stay as history and keep the audit linkage. The generated columns free the name at once: `verified_name` becomes NULL (another organization may verify it) and `live_name` becomes NULL (the same organization may add it again as a new row). Key material does not outlive the domain: deleting it revokes every non-retired DKIM key and sets its `private_key_ciphertext` to NULL, and retired keys lose theirs at retirement ([ADR-0018](../architecture/adr/0018-dkim-key-custody.md)). There is no separate time-based purge for deleted domains: they are removed with the organization purge (below). Rows are a few per domain, so keeping them is cheap.

## Planned feature-owned purges

These are not implemented yet. Each belongs to the step that builds the feature, and uses an indexed, batched delete. (The `user_sessions`, `user_tokens` and `login_audit_logs` purges moved to the api in step 1.3, above.)

| Data                         | Rule                                                                                                                      | Status                                 |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Deleted organizations        | Purge tenant rows and S3 objects after `purge_after`, skipping active legal holds (see above)                             | Deferred (after 1.2)                   |
| Soft-deleted domains         | Delete `domains` rows with `status = deleted` (children cascade) together with the organization purge                     | Deferred (with the organization purge) |
| `quarantine_messages`        | Expire by `expires_at` (index `(status, expires_at)`), recording a `quarantine_actions` row, then delete the S3 object    | Planned, step 5.3                      |
| `delivery_suppressions`      | Delete after `expires_at` (index `(expires_at)`)                                                                          | Planned, step 6.x                      |
| Per-tenant message retention | Retention below the platform maximum: batched delete by `(organization_id, received_at)` on the message tables            | Planned, steps 1.2/8.1                 |
| Archive expiry               | Delete `email_archives` rows (and objects) past `retain_until`, skipping rows under an active legal hold                  | Planned, step 8.1                      |
| S3 lifecycle                 | Bucket lifecycle rules aligned with the MySQL tiers, so objects do not outlive their metadata by more than a grace period | Planned, step 8.1                      |

## Long-term history

ClickHouse ([ADR-0009](../architecture/adr/0009-search-and-analytics.md)) holds the long-term event and message history for reporting and analytics. Dropping MySQL detail partitions after 3 months does not lose reporting history, once the event pipeline to ClickHouse exists (a later phase).
