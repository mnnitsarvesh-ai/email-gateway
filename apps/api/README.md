# api

The control-plane REST API (NestJS 11): authentication, sessions and RBAC, organizations, domains, SMTP connectors, destination servers, delivery status, dead letters, since step 3.3 the message lifecycle and since step 4.1 the security scan results, scan settings and the platform classifier training. Every endpoint, its permission and its error codes are listed in [docs/api/README.md](../../docs/api/README.md); the OpenAPI snapshot is [docs/api/openapi.json](../../docs/api/openapi.json) (Swagger UI at `/docs` outside production).

Business routes live under `/api/v1` ([ADR-0015](../../docs/architecture/adr/0015-api-base-path.md)); `GET /health/live`, `GET /health/ready` and `GET /metrics` (internal port only) are unprefixed. The tenant of a request always comes from the authenticated principal ([ADR-0016](../../docs/architecture/adr/0016-authentication-sessions-rbac.md)); a resource of another tenant is a `404`. Writes and authorization decisions use the MySQL writer; lists and status views read the replica (`PrismaReadService`, writer fallback above `DATABASE_READ_MAX_LAG_SECONDS`, [ADR-0014](../../docs/architecture/adr/0014-mysql-data-model-partitioning-read-write-split.md)).

## Run and test

```bash
pnpm --filter @email-gateway/api dev               # host run, reads ../../.env (port API_HOST_PORT)
pnpm --filter @email-gateway/api lint typecheck test test:e2e
pnpm --filter @email-gateway/api test:integration  # real MySQL writer + replica, Redis, MinIO, Postfix
UPDATE_OPENAPI=1 pnpm --filter @email-gateway/api test:e2e -- openapi   # after an intended API change
```

- `src/**/*.test.ts`: unit tests (services with fakes). `test/`: in-process HTTP tests with every dependency stubbed (guards, validation, route security, the OpenAPI contract). `integration/`: in-process app against the Compose infrastructure (`integration/support`: app harness, fixtures, HTTP helpers, SQL fixtures of messages in any lifecycle state).
- `integration/common.test.ts` sends one probe mail through the local Postfix when the smtp-adapter runs; `afterAll` removes what it left behind (step 3.3 L16): the run's message is found by its unique `Message-ID`, its postfix-outbound queue files are deleted one queue id at a time (`docker compose exec -T postfix-outbound postsuper -d <id>`, never `ALL`), and its EML and part objects and rows are deleted (`integration/support/probe-cleanup.ts`).

## Layout (`src/`)

| Path                    | What                                                                                                                                                       |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app.module.ts`         | Root module: database (writer + reader), Redis, S3, health, metrics, the shared building blocks, the feature modules                                       |
| `auth-contracts/`       | `Principal`, `TenantScope` + `tenantWhere`, `@RequirePermissions`, `@CurrentScope`, `@CurrentPrincipal`                                                    |
| `audit/`                | `AuditService`: `audit_logs` rows in the caller's transaction (metadata scrubbed of credentials)                                                           |
| `database/`             | `TransactionRunner`: interactive writer transactions owned by services                                                                                     |
| `http/`                 | prefix and proxy setup, OpenAPI document, pagination, `CodedHttpException` + `CodedExceptionFilter` (errors with a stable `code`), `idempotency/`          |
| `http/idempotency/`     | The Idempotency-Key store (step 3.3 L11): header validation, request fingerprint, `IdempotencyService` (`api_idempotency_keys`), `ApiIdempotencyKey()`     |
| `modules/<feature>/`    | Controller (translation only) → service (logic, transactions) → repositories (queries); `dto/` zod schemas (validation and OpenAPI), `api-docs.ts` helpers |
| `modules/messages/`     | Message lifecycle (step 3.3) and scan results (step 4.1): see below                                                                                        |
| `modules/scans/`        | Scan settings and platform training (step 4.1): see below                                                                                                  |
| `modules/risk-scoring/` | Risk scoring profiles and the dry-run (step 5.1): see below                                                                                                |

## Message lifecycle (step 3.3)

Design: [08-message-lifecycle.md](../../docs/plan/steps/08-message-lifecycle.md) L10–L12, [ADR-0025](../../docs/architecture/adr/0025-message-lifecycle-state-machine.md).

| Route                                                | Permission           | Store                   |
| ---------------------------------------------------- | -------------------- | ----------------------- |
| `GET /api/v1/messages/{messageId}/lifecycle`         | `message:read`       | replica                 |
| `GET /api/v1/messages/{messageId}/lifecycle/history` | `message:read`       | replica                 |
| `POST /api/v1/messages/{messageId}/rescan`           | `message:rescan`     | writer, Idempotency-Key |
| `POST /api/v1/messages/{messageId}/release`          | `quarantine:release` | writer, Idempotency-Key |

`message:rescan` is held by `organization_admin`, `security_analyst` and `super_admin` (and API keys with that scope); `quarantine:release` by `organization_admin`, `security_analyst`, `quarantine_reviewer` and `super_admin`. `message:read` is a read permission of every tenant role.

- `controllers/message-lifecycle.controller.ts`: translation only; sets `Idempotency-Replayed: true` on a replayed `202`. `CodedExceptionFilter` renders `{ statusCode, error, code, message, currentState?, currentVersion?, correlationId }`.
- `services/message-lifecycle.service.ts` (writes): validates the path, the `Idempotency-Key` header and the body, then one writer transaction: idempotency lookup (`SELECT … FOR UPDATE`) → registry lookup and message lock (`lockLifecycle`, another organization's row is `404`) → transition-key check (a concurrent winner → retry and replay) → state decision (`decideTransition`: stale version `409 message_version_conflict`, any other refusal `409 message_state_conflict`) → preconditions (EML key under `org/<id>/`; release: no `quarantine_messages` rows, at least one `pending`/`quarantined` recipient) → `transitionMessage` (`recordIgnored: false`, transition key `api:<organizationId>:<operation>:<key>`) → effects (rescan: `mail.message.rescan_requested.v1`, consumed by every registered scan engine since step 4.1, which scans the new round; release: the released `quarantined` recipients become `pending`, then `mail.delivery.approved.v1` per 1000 recipients with `source: quarantine_release`, `deliverySeq` = highest + 1 or 1, `lifecycleRound` = the new round, UUIDv7 event ids, and one `delivery.approved` timeline event each) → audit row (`message.rescan_requested` / `message.quarantine_released`, metadata without the key, only its SHA-256) → stored response.
- `services/lifecycle-gateway.ts`: the api's only door to `@email-gateway/message-lifecycle` (one-door rule); passes the api's `LifecycleMetrics` adapter and logger.
- `services/message-lifecycle-read.service.ts` (reads): state, reason, version, round, parse stage, recipient counts, highest `deliverySeq`, `actions` (from the transition table, not the caller's permissions); history ordered by version with a cursor, legacy rows as recorded.
- `repositories/`: `message-lifecycle.repository.ts` (writer, inside the operation's transaction) and `message-lifecycle-read.repository.ts` (`PrismaReadService`).
- `lifecycle-metrics.ts`: `api_message_lifecycle_operations_total{operation,outcome}` (`applied`, `replayed`, `conflict`, `not_found`, `invalid_request`) and the shared `lifecycle_transitions_total`, `lifecycle_transitions_ignored_total`, `lifecycle_version_conflicts_total`, `lifecycle_derived_skipped_total` with `service="api"`.

## Security scanning (step 4.1)

Design: [09-rspamd.md](../../docs/plan/steps/09-rspamd.md) S8, S13, S14, S16, [ADR-0026](../../docs/architecture/adr/0026-security-scan-pipeline.md).

| Route                                                                                     | Permission                          | Store                                                  |
| ----------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------ |
| `GET /api/v1/messages/{messageId}/scans`                                                  | `message:read`                      | replica                                                |
| `GET /api/v1/scan-settings`                                                               | `policy:read`                       | replica                                                |
| `PUT /api/v1/scan-settings/{engine}`                                                      | `scan:settings_manage`              | writer, version compare-and-set, audited               |
| `DELETE /api/v1/scan-settings/{engine}?expectedVersion=n`                                 | `scan:settings_manage`              | writer, version compare-and-set, audited               |
| `POST /api/v1/platform/organizations/{organizationId}/messages/{messageId}/scan-training` | `platform:scan_training`, user, MFA | writer lookups, S3 stream → Rspamd controller, audited |

- `modules/messages/`: `controllers/message-scans.controller.ts`, `services/message-scans-read.service.ts`, `repositories/message-scans-read.repository.ts` (`email_scans`, `scan_engine_results`, `email_auth_results` with the message's `(message_id, received_at)` and the scope's organization), `domain/message-scans.ts` (pure mapping: final row = result, every row = attempt, `evidence.signals` = symbols; round cursor).
- `modules/scans/`: `domain/engine-settings.ts` (per catalog engine: `resolveRspamdSettings` against the platform settings `SCAN_RSPAMD_*` of `config.ts`; a stored override that no longer fits is shown with its violations and not applied), `services/scan-settings.service.ts` (CAS on `scan_engine_settings.version`, `409 version_conflict`, `422 scan_settings_invalid`, audit `scan_settings.updated` / `scan_settings.reset` with before/after in the same transaction; a reset keeps the row with `{}` and a new version), `services/scan-training.service.ts` (organization by public id, message within it, EML key prefix, `@email-gateway/rspamd` learn/fuzzy with flags 11/12 and `SCAN_FUZZY_WEIGHT`, audit `scan_training.<operation>` for every call that found its message, `email_events` `scan.training` on success), `services/eml-store.ts` (S3 stream; the `GetObjectCommand` class is resolved from `@email-gateway/common`'s SDK), `services/rspamd-controller.ts` (`RSPAMD_CONTROLLER_URL`, `RSPAMD_CONTROLLER_ENABLE_PASSWORD`; without them training answers `503 rspamd_unavailable`).
- `scan:settings_manage` is held by `organization_admin` and `security_analyst` (and grantable to API keys); `platform:scan_training` by `platform_admin` (and `super_admin`); never by API keys or override sessions.

## Risk scoring (step 5.1)

Design: [15-risk-scoring.md](../../docs/plan/steps/15-risk-scoring.md) R10, R12, R15–R17, [ADR-0041](../../docs/architecture/adr/0041-risk-scoring-model.md), [ADR-0042](../../docs/architecture/adr/0042-risk-scoring-placement-and-policy-handoff.md). **5.1 recommends and never enforces** (policy 5.2 decides, quarantine 5.3 acts); the default weights and thresholds are engineering defaults calibrated on a synthetic dataset, **not validated detection accuracy**. Scores are computed by the email-worker at round completion (`message_risk_scores`); the api manages the tenant profile and reads scores.

| Route                                                             | Permission                         | Store                                                                          |
| ----------------------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------ |
| `GET /api/v1/risk-scoring/platform-profile`                       | `policy:read`                      | none (library data: profile, bounds, signal map, hard blocks)                  |
| `GET /api/v1/risk-scoring/profile`                                | `policy:read`                      | replica                                                                        |
| `GET /api/v1/risk-scoring/profile/versions[/{versionId}]`         | `policy:read`                      | replica                                                                        |
| `POST /api/v1/risk-scoring/profile/versions`                      | `policy:manage`                    | writer, organization lock, version cap, audited `risk_profile.draft_created`   |
| `PUT /api/v1/risk-scoring/profile/versions/{versionId}`           | `policy:manage`                    | writer, drafts only, `row_version` CAS, audited `risk_profile.draft_updated`   |
| `DELETE /api/v1/risk-scoring/profile/versions/{versionId}`        | `policy:manage`                    | writer, drafts only, audited `risk_profile.draft_deleted`                      |
| `POST /api/v1/risk-scoring/profile/versions/{versionId}/publish`  | `policy:publish`                   | writer, immutable afterwards, audited `risk_profile.published` (+ `activated`) |
| `POST /api/v1/risk-scoring/profile/versions/{versionId}/activate` | `policy:publish`                   | writer, pointer CAS, audited `risk_profile.activated`                          |
| `POST /api/v1/risk-scoring/profile/reset`                         | `policy:publish`                   | writer, pointer → NULL, audited `risk_profile.reset`                           |
| `POST /api/v1/messages/{messageId}/scans/{scanId}/risk/dry-run`   | `policy:manage` and `message:read` | replica, **writes nothing**                                                    |
| `GET /api/v1/messages/{messageId}/scans` (`risk` per round)       | `message:read`                     | replica                                                                        |

- `modules/risk-scoring/`: `domain/risk-profile.ts` (overrides validation through `validateOverrides`, changed override paths for audit metadata, the active-profile resolution the email-worker also applies, views), `domain/risk-dry-run.ts` (the round's rows → `RoundRows` exactly as the email-worker passes them, then `buildScoringInput` + `scoreRisk` with the worker's fail-safe error result), `services/risk-profiles.service.ts`, `services/risk-dry-run.service.ts` (no writer, audit or cache dependency), `services/risk-writer.ts` (120 s transactions, one retry on an echo-check mismatch, then `503 inconsistent_read`; `risk_profile_changes_total{operation}`, `risk_dry_runs_total{result}`), `repositories/risk-profiles.repository.ts` (drafts change only `WHERE status = 'draft'`), `repositories/risk-dry-run.repository.ts` (read only).
- Errors: `400 risk_profile_invalid` (`violations` by path), `404 risk_profile_version_not_found` / `message_not_found` / `scan_not_found`, `409 risk_profile_limit_reached` (`RISK_PROFILE_MAX_VERSIONS`, default 200, 10–1000), `409 risk_profile_version_conflict` (`currentRowVersion` / `currentProfileVersion`), `409 risk_profile_version_immutable`, `409 risk_profile_version_not_published`, `409 scan_round_not_complete`, `409 risk_revision_unavailable`, `503 inconsistent_read`.
- `RISK_PLATFORM_PROFILE` (default `rsk-default/1`, a key of `RISK_PLATFORM_PROFILES`) is the platform profile drafts are based on and resolved against. A profile change applies to the **next round only** (each round snapshots the active version when it opens).
- Organization purge: `modules/tenant-data/risk-tenant-data.repository.ts` deletes `message_risk_scores`, then `risk_scoring_profile_versions`, then `risk_scoring_profiles` in batches.

### Idempotency semantics (L11)

- `Idempotency-Key` is required on both writes: 1–128 characters of `[A-Za-z0-9._:-]` (`400 idempotency_key_required` / `idempotency_key_invalid`), case-sensitive (`utf8mb4_bin`), unique per organization.
- The record (`api_idempotency_keys`: principal `user:<publicId>` | `api_key:<publicId>`, operation, resource public id, SHA-256 of the canonical JSON `{ operation, resourceId, body }`, status and response) commits in the same writer transaction as the transition, its effects and the audit row, and answers for 24 hours (a constant).
- Same key, same request → the stored status and body, `Idempotency-Replayed: true`, nothing written. Same key, any difference (body, path, operation, caller) → `422 idempotency_key_reused`. `4xx` outcomes are never stored. An expired record is replaced.
- Concurrency: two requests with one key race on the record's unique key or on the message lock; the loser's transaction rolls back and is retried once, which replays the winner's response. A second race means the effect exists without a live record (a key reused on the same message after 24 hours) and is `422`.
- The read APIs lag the write by the replica delay; the `202` body carries the new `version` for the next operation.
