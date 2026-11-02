# Data ownership

Which deployable owns (writes) each table, bucket, queue and cache, and who may read from the MySQL replica. The table-level writers come from the step 1.1 design, [§3.11](../plan/steps/01-database.md#311-data-ownership-writers); this page expands them per table and adds the stores outside MySQL. Rules:

1. **One owner per write path.** A table may be read by many services but is written only by its owner (plus the cross-cutting outbox and idempotency tables). A service that needs another owner's data to change asks for it with an event or an API call; it does not write the other owner's table.
2. **The data plane uses the writer only.** `smtp-adapter`, `email-worker`, `policy-engine`, `delivery-worker` and `archive-worker` never register `PrismaReadService` (ESLint rule plus a DI assertion in each `app.module.test.ts`), so replica lag can never affect a mail decision.
3. **Schema changes are owned by migrations.** Only `db-migrate` and partition maintenance use the DDL account (`MIGRATION_DATABASE_URL`). Runtime services have DML only.
4. **Content is never in MySQL.** Bodies and attachments live in S3; MySQL holds keys, sizes and hashes.

Status: all 63 tables are IMPLEMENTED (step 1.1 schema plus the steps 1.2 + 1.3 migration `identity_tenancy`, `tests/integration/schema.test.ts`). Apart from `db:seed` (catalog, the platform organization and demo data), **no business code writes them yet**; the writing step is given for each group. The "Writer" column is ownership by design.

## MySQL tables by owner

### api (control plane)

| Tables                                                                                                                                     | Notes                                                                                                        | Writing step |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ------------ |
| `organizations`, `organization_settings`, `organization_limits`, `organization_features`, `organization_deployments`                       | Tenant management; deployments also by the deployment manager (in `api`)                                     | 1.2, 8.3     |
| `users`, `roles`, `role_permissions`, `user_roles`, `user_sessions`, `api_keys`, `login_audit_logs`                                        | Identity and access. Password and MFA secrets are hashes or app-encrypted ciphertext only                    | 1.3          |
| `user_tokens`, `user_mfa_recovery_codes`                                                                                                   | Auth module: single-use tokens (SHA-256 only) and MFA recovery codes (HMAC only); purged/replaced by the api | 1.3          |
| `domains`, `domain_verifications`, `domain_dns_records`, `domain_dkim_keys`, `domain_mx_records`, `domain_mail_servers`, `domain_settings` | Domain onboarding and its background DNS jobs. DKIM private keys are references, never key material          | 2.1          |
| `email_policies`, `policy_versions`, `policy_conditions`, `policy_actions`, `policy_exceptions`                                            | Everything in policy except execution logs                                                                   | 5.2          |
| `delivery_routes`; `delivery_suppressions` (manual entries)                                                                                |                                                                                                              | 2.3, 6.x     |
| `quarantine_actions`; `quarantine_release_logs` (created on release); `quarantine_messages` status changes caused by user actions          | Release and delete requests, approvals                                                                       | 5.3          |
| `archive_settings`, `archive_retention_policies`, `archive_legal_holds`                                                                    |                                                                                                              | 8.1          |
| `webhook_subscriptions`                                                                                                                    | HMAC secret stored as app-encrypted ciphertext                                                               | 6.2          |
| `audit_logs`                                                                                                                               | Append-only, partitioned monthly, never auto-dropped                                                         | 1.2 onwards  |
| `system_settings`, `yara_rules`, `threat_indicators` (analyst and organization entries)                                                    | Platform operators and tenant analysts                                                                       | 4.2, 6.1     |

### smtp-adapter (ingestion)

| Tables                                                                                                                       | Notes                                                                                        | Writing step |
| ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------ |
| `message_identities`, `email_messages` (insert, status `received`), `email_recipients`, `email_headers`, `email_attachments` | One transaction with the outbox row; the registry allocates the message id and `received_at` | 3.1          |

### email-worker (scanning)

| Tables                                                                                           | Notes                                                         | Writing step |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- | ------------ |
| `email_scans`, `scan_engine_results`                                                             | One scan row per scan kind and attempt; one result per engine | 4.1–4.6      |
| `email_messages` status `scanning` and `scanned`, `email_message_status_history`, `email_events` |                                                               | 3.3, 4.1     |
| `threat_indicators` sightings (`last_seen_at`)                                                   |                                                               | 4.x          |

### policy-engine (decisions)

| Tables                                                                                                                                                 | Notes                                       | Writing step |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- | ------------ |
| `policy_execution_logs`                                                                                                                                | Decision trace per evaluation               | 5.2          |
| `quarantine_messages` (insert)                                                                                                                         | One row per quarantined recipient           | 5.3          |
| `email_messages` status `policy_evaluated`, `quarantined`, `discarded`, `final_action`, `final_verdict`, `risk_score`; `email_recipients.final_action` | Status history rows for its own transitions | 3.3, 5.2     |

### delivery-worker (delivery)

| Tables                                                                | Notes                                             | Writing step |
| --------------------------------------------------------------------- | ------------------------------------------------- | ------------ |
| `email_deliveries`, `delivery_attempts`, `bounce_events`              | Postfix owns the retries; the worker records them | 2.3          |
| `delivery_suppressions` (automatic, from hard bounces and complaints) |                                                   | 6.x          |

### archive-worker and notification-worker

| Owner                 | Tables               | Writing step |
| --------------------- | -------------------- | ------------ |
| `archive-worker`      | `email_archives`     | 8.1          |
| `notification-worker` | `webhook_deliveries` | 6.2          |

### Cross-cutting

| Table                                                                                             | Writers                                                                                 | Notes                                                                                                                 |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `message_outbox`                                                                                  | Every producer, in the same transaction as the state change it announces                | Partitioned daily; the relay (PLANNED 3.2) sets `published_at`. Partition drops skip partitions with unpublished rows |
| `message_idempotency`                                                                             | Every consumer, through `processOnce` (IMPLEMENTED)                                     | Key `(consumer, event_id)`; purged after 30 days by the partition maintenance job (IMPLEMENTED, `db:partitions`)      |
| Catalog tables: `organization_plans`, `permissions`, `system_settings`, system `roles`            | `db:seed` (DML account, IMPLEMENTED in step 1.1), then platform operators through `api` | `db:seed` refuses to seed demo data in staging or production                                                          |
| Reputation catalogs: `ip_reputation`, `domain_reputation`, `url_reputation`, `malware_signatures` | **Unassigned**                                                                          | Written by feed ingestion, which has no execution-plan step yet (4.3 excludes external feeds)                         |

### Gaps in the ownership table (to resolve in the named step)

| Gap                                                                                                                                                                                                                                               | Step |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| Message statuses `delivery_queued`, `delivered` and `partially_delivered`, and `email_recipients.status`, have no writer in §3.11. `delivery-worker` is the natural owner                                                                         | 3.3  |
| `quarantine_release_logs` completion (`delivered`, `blocked_by_revalidation`) and `quarantine_messages.status = released` are written after the re-validation scan and the delivery, which run in `email-worker` and `delivery-worker`, not `api` | 5.3  |
| `email_message_status_history` and `email_events` are listed under `email-worker` only; every service that changes a status must append its own history row                                                                                       | 3.3  |
| `audit_logs` is listed under `api`; `discard` decisions in `policy-engine` must be audited too (ADR-0006)                                                                                                                                         | 5.2  |

## Read access and the replica

| Service               | MySQL connection                               | Typical reads (all on the writer unless stated)                                                                                                          |
| --------------------- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api`                 | Writer + **reader** (`PrismaReadService`)      | Lists, search, reports, dashboards and usage on the **reader**. Read-after-write paths, transactions and authorization right after a write on the writer |
| `smtp-adapter`        | Writer only                                    | `domains`, `domain_settings`, `domain_mail_servers`, `organizations` status, `organization_limits` (in-session, latency-critical)                        |
| `email-worker`        | Writer only                                    | `email_messages`, `email_attachments`, `organization_features`, `policy_exceptions` (`skip_engine`), `yara_rules`, threat and reputation tables          |
| `policy-engine`       | Writer only                                    | `email_scans`, `scan_engine_results`, `email_recipients`, policies and versions, `organization_settings`                                                 |
| `delivery-worker`     | Writer only                                    | `delivery_routes`, `domain_mail_servers`, `delivery_suppressions`, `quarantine_release_logs`                                                             |
| `archive-worker`      | Writer only                                    | `archive_settings`, `archive_retention_policies`, `archive_legal_holds`                                                                                  |
| `notification-worker` | Writer only (may adopt the reader in step 6.2) | `webhook_subscriptions`, `organization_settings`, `quarantine_messages` (digests)                                                                        |

The reader is IMPLEMENTED and registered only in `api` (`apps/api/src/app.module.ts`). No feature module uses it yet; feature steps adopt it. See [replication.md](../database/replication.md) for the modes and lag handling.

## Object storage

| Bucket (`env`)                | Prefix                          | Writer                      | Readers                                                                                               | Status                                 |
| ----------------------------- | ------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Mail (`S3_BUCKET_MAIL`)       | `org/{organizationId}/eml/`     | `smtp-adapter` (ingestion)  | `email-worker` (scan), `delivery-worker` (reinject), `api` (preview with `message:read_content`, 6.1) | Bucket IMPLEMENTED; writer PLANNED 3.1 |
| Mail (`S3_BUCKET_MAIL`)       | `org/{organizationId}/part/`    | Ingestion or `email-worker` | `email-worker`, `api`                                                                                 | PLANNED 3.1, 4.2                       |
| Archive (`S3_BUCKET_ARCHIVE`) | `org/{organizationId}/archive/` | `archive-worker`            | `api` (search, export, 8.1)                                                                           | Bucket IMPLEMENTED; writer PLANNED 8.1 |

Every key carries the organization prefix. Lifecycle: the Terraform module expires mail objects after 30 days by default, while message rows are kept 6 months; alignment is PLANNED 8.1.

## Queues

| Queue                            | Producer of the bound event    | Consumer (owner)       | Status                                                       |
| -------------------------------- | ------------------------------ | ---------------------- | ------------------------------------------------------------ |
| `email-worker.message-received`  | `smtp-adapter` via the outbox  | `email-worker`         | Topology IMPLEMENTED; producer and consumer PLANNED 3.1, 4.1 |
| `policy-engine.message-scanned`  | `email-worker` via the outbox  | `policy-engine`        | Topology IMPLEMENTED; PLANNED 4.1, 5.2                       |
| `delivery-worker.policy-decided` | `policy-engine` via the outbox | `delivery-worker`      | Topology IMPLEMENTED; PLANNED 5.2, 2.3                       |
| `archive-worker.policy-decided`  | `policy-engine` via the outbox | `archive-worker`       | Topology IMPLEMENTED; PLANNED 8.1                            |
| `notification-worker.events`     | `policy-engine` via the outbox | `notification-worker`  | Topology IMPLEMENTED; PLANNED 6.2                            |
| `<queue>.dlq` (each)             | RabbitMQ dead-lettering        | Operators, replay tool | IMPLEMENTED; replay PLANNED 3.2                              |

Each consumer owns its queue and its DLQ and asserts them at startup.

## Redis

Redis is never the source of truth (`noeviction`, AOF on locally, but anything in it must be rebuildable).

| User            | Use                                           | Status               |
| --------------- | --------------------------------------------- | -------------------- |
| Rspamd          | Its own statistics and module state           | IMPLEMENTED (config) |
| `smtp-adapter`  | Per-tenant and per-client rate-limit counters | PLANNED 2.2          |
| `email-worker`  | Engine result and hash caches                 | PLANNED 4.1, 4.2     |
| `api`           | API rate limits, short-lived locks            | PLANNED 6.1          |
| `policy-engine` | Compiled policy cache                         | PLANNED 5.2          |

Key prefixes per service and per organization will be fixed by the first step that writes keys.

## Search and analytics

| Store      | Writer                                           | Reader                      | Status                                         |
| ---------- | ------------------------------------------------ | --------------------------- | ---------------------------------------------- |
| OpenSearch | An indexer fed from RabbitMQ events              | `api`                       | PLANNED, no execution-plan step yet (ADR-0009) |
| ClickHouse | An event-history loader fed from RabbitMQ events | `api` (reports, dashboards) | PLANNED, no execution-plan step yet (ADR-0009) |
