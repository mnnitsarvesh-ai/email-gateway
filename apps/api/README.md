# api

The control-plane REST API (NestJS 11): authentication, sessions and RBAC, organizations, domains, SMTP connectors, destination servers, delivery status, dead letters and, since step 3.3, the message lifecycle. Every endpoint, its permission and its error codes are listed in [docs/api/README.md](../../docs/api/README.md); the OpenAPI snapshot is [docs/api/openapi.json](../../docs/api/openapi.json) (Swagger UI at `/docs` outside production).

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

| Path                 | What                                                                                                                                                       |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app.module.ts`      | Root module: database (writer + reader), Redis, S3, health, metrics, the shared building blocks, the feature modules                                       |
| `auth-contracts/`    | `Principal`, `TenantScope` + `tenantWhere`, `@RequirePermissions`, `@CurrentScope`, `@CurrentPrincipal`                                                    |
| `audit/`             | `AuditService`: `audit_logs` rows in the caller's transaction (metadata scrubbed of credentials)                                                           |
| `database/`          | `TransactionRunner`: interactive writer transactions owned by services                                                                                     |
| `http/`              | prefix and proxy setup, OpenAPI document, pagination, `CodedHttpException` + `CodedExceptionFilter` (errors with a stable `code`), `idempotency/`          |
| `http/idempotency/`  | The Idempotency-Key store (step 3.3 L11): header validation, request fingerprint, `IdempotencyService` (`api_idempotency_keys`), `ApiIdempotencyKey()`     |
| `modules/<feature>/` | Controller (translation only) → service (logic, transactions) → repositories (queries); `dto/` zod schemas (validation and OpenAPI), `api-docs.ts` helpers |
| `modules/messages/`  | Message lifecycle (step 3.3): see below                                                                                                                    |

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
- `services/message-lifecycle.service.ts` (writes): validates the path, the `Idempotency-Key` header and the body, then one writer transaction: idempotency lookup (`SELECT … FOR UPDATE`) → registry lookup and message lock (`lockLifecycle`, another organization's row is `404`) → transition-key check (a concurrent winner → retry and replay) → state decision (`decideTransition`: stale version `409 message_version_conflict`, any other refusal `409 message_state_conflict`) → preconditions (EML key under `org/<id>/`; release: no `quarantine_messages` rows, at least one `pending`/`quarantined` recipient) → `transitionMessage` (`recordIgnored: false`, transition key `api:<organizationId>:<operation>:<key>`) → effects (rescan: `mail.message.rescan_requested.v1`, which nothing consumes before step 4.1, so rescan is a state transition plus the request contract until then; release: the released `quarantined` recipients become `pending`, then `mail.delivery.approved.v1` per 1000 recipients with `source: quarantine_release`, `deliverySeq` = highest + 1 or 1, `lifecycleRound` = the new round, UUIDv7 event ids, and one `delivery.approved` timeline event each) → audit row (`message.rescan_requested` / `message.quarantine_released`, metadata without the key, only its SHA-256) → stored response.
- `services/lifecycle-gateway.ts`: the api's only door to `@email-gateway/message-lifecycle` (one-door rule); passes the api's `LifecycleMetrics` adapter and logger.
- `services/message-lifecycle-read.service.ts` (reads): state, reason, version, round, parse stage, recipient counts, highest `deliverySeq`, `actions` (from the transition table, not the caller's permissions); history ordered by version with a cursor, legacy rows as recorded.
- `repositories/`: `message-lifecycle.repository.ts` (writer, inside the operation's transaction) and `message-lifecycle-read.repository.ts` (`PrismaReadService`).
- `lifecycle-metrics.ts`: `api_message_lifecycle_operations_total{operation,outcome}` (`applied`, `replayed`, `conflict`, `not_found`, `invalid_request`) and the shared `lifecycle_transitions_total`, `lifecycle_transitions_ignored_total`, `lifecycle_version_conflicts_total`, `lifecycle_derived_skipped_total` with `service="api"`.

### Idempotency semantics (L11)

- `Idempotency-Key` is required on both writes: 1–128 characters of `[A-Za-z0-9._:-]` (`400 idempotency_key_required` / `idempotency_key_invalid`), case-sensitive (`utf8mb4_bin`), unique per organization.
- The record (`api_idempotency_keys`: principal `user:<publicId>` | `api_key:<publicId>`, operation, resource public id, SHA-256 of the canonical JSON `{ operation, resourceId, body }`, status and response) commits in the same writer transaction as the transition, its effects and the audit row, and answers for 24 hours (a constant).
- Same key, same request → the stored status and body, `Idempotency-Replayed: true`, nothing written. Same key, any difference (body, path, operation, caller) → `422 idempotency_key_reused`. `4xx` outcomes are never stored. An expired record is replaced.
- Concurrency: two requests with one key race on the record's unique key or on the message lock; the loser's transaction rolls back and is retried once, which replays the winner's response. A second race means the effect exists without a live record (a key reused on the same message after 24 hours) and is `422`.
- The read APIs lag the write by the replica delay; the `202` body carries the new `version` for the next operation.
