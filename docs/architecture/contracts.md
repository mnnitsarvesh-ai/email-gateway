# Inter-service contracts

Every way two components of the gateway talk to each other, with the source of truth for each contract. A contract is **IMPLEMENTED** when the code and a test exist in this repository, and **PLANNED x.y** when it is designed but not built (the step is from [`docs/plan/execution-plan.md`](../plan/execution-plan.md)). Breaking a contract requires a new version (events: `.v2`; HTTP: `/v2`), with both versions served during the migration (ADR-0005).

| Contract                                                        | Between                                            | Source of truth                                                      | Status                        |
| --------------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------- |
| [Policy delegation](#1-postfix--smtp-adapter-policy-delegation) | Postfix → `smtp-adapter` :10040                    | `apps/smtp-adapter/src/policy/*`, `infrastructure/postfix/main.cf`   | IMPLEMENTED (answers `DUNNO`) |
| [Milter](#2-postfix--rspamd-milter)                             | Postfix → Rspamd :11332                            | `main.cf`, `infrastructure/rspamd/local.d/*`                         | IMPLEMENTED (config)          |
| [LMTP ingestion](#3-postfix--smtp-adapter-lmtp-ingestion)       | Postfix → `smtp-adapter` :24                       | ADR-0006                                                             | PLANNED 2.2, 3.1              |
| [RabbitMQ topology](#4-rabbitmq-topology)                       | Producers → `mail.events` → consumers              | `packages/event-contracts/src/topology.ts`                           | IMPLEMENTED (topology)        |
| [Event envelope](#5-event-envelope)                             | Every producer and consumer                        | `packages/event-contracts/src/envelope.ts`                           | IMPLEMENTED                   |
| [Event payloads](#6-event-payloads)                             | ingestion, email-worker, policy-engine → consumers | `packages/event-contracts/src/events.ts`                             | IMPLEMENTED (schemas)         |
| [Security engine](#7-security-engine-contract)                  | email-worker → engine adapters                     | `packages/security-contracts/src/index.ts`                           | IMPLEMENTED (types)           |
| [Engine wire protocols](#8-engine-wire-protocols)               | email-worker → Rspamd HTTP, ClamAV clamd           | ADR-0007                                                             | PLANNED 4.1, 4.2              |
| [HTTP health](#9-http-health-contract)                          | Docker, Kubernetes, admin-portal → every service   | `packages/common/src/health/*`, `packages/shared-types`              | IMPLEMENTED                   |
| [api ↔ admin-portal](#10-api--admin-portal)                     | Browser → admin-portal → api                       | `apps/admin-portal/src/lib/platform-health.ts`, `docs/api/README.md` | IMPLEMENTED (health, meta)    |
| [S3 key conventions](#11-s3-key-conventions)                    | ingestion, workers, api → S3                       | ADR-0008, `events.ts` (`s3Key`)                                      | IMPLEMENTED (prefix format)   |
| [Database access](#12-database-connections)                     | Every service → MySQL writer / reader              | ADR-0014, `packages/common/src/database/*`                           | IMPLEMENTED                   |

## 1. Postfix → smtp-adapter policy delegation

Postfix's [SMTP access policy delegation](http://www.postfix.org/SMTPD_POLICY_README.html) over TCP. Postfix calls it from `smtpd_recipient_restrictions` (`check_policy_service inet:smtp-adapter:10040`), so it is consulted once per `RCPT TO`, after `reject_unauth_destination`.

**Request.** `name=value` lines ending with an empty line. Postfix sends, among others: `request=smtpd_access_policy`, `protocol_state` (`RCPT`), `protocol_name`, `helo_name`, `queue_id`, `instance` (stable for one message across recipients), `sender`, `recipient`, `recipient_count`, `client_address`, `client_name`, `reverse_client_name`, `sasl_method`, `sasl_username`, `sasl_sender`, `size`, `ccert_subject`, `ccert_issuer`, `ccert_fingerprint`, `encryption_protocol`, `encryption_cipher`, `encryption_keysize`.

| Attribute                                              | Planned use                                                                                                                                                                     | Step     |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `recipient`                                            | Tenant resolution by recipient domain (`domains.verified_name`, i.e. verified owner only, and `inbound_enabled`), recipient validation (`domain_settings.recipient_validation`) | 2.2      |
| `client_address`, `sasl_username`, `ccert_fingerprint` | Outbound relay authorization (`domain_mail_servers` `outbound_source` `ip_cidr`, connectors)                                                                                    | 2.2, 8.2 |
| `sender`                                               | Outbound: the sender domain must belong to the authorized organization                                                                                                          | 2.2      |
| `client_address`, `instance`                           | Per-tenant and per-client rate limits in Redis                                                                                                                                  | 2.2      |

**Implemented behaviour** (`policy-protocol.ts`, `policy-server.service.ts`, `policy-decision.service.ts`):

| Aspect           | Contract                                                                                                                                                                          |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Parsing          | Requests may span TCP chunks and may be pipelined. Any attribute name is accepted; `=` inside values is kept. A request over **16 KiB** or a line without `=` is a protocol error |
| Ordering         | One connection serves many requests; replies are written strictly in request order                                                                                                |
| Response         | `action=<action>\n\n`. An action containing CR or LF is refused (no response splitting)                                                                                           |
| Current decision | `DUNNO` for `request=smtpd_access_policy` (hand the decision back to Postfix's own restrictions). Any other `request` gets `DEFER_IF_PERMIT Unsupported policy request`           |
| Errors           | If the decision throws: `DEFER_IF_PERMIT 4.3.5 Policy service temporarily unavailable`. If the request is malformed: the same tempfail, then the connection is closed             |
| Idle connections | Closed by the server after 60 s idle (Postfix reconnects; `smtpd_policy_service_max_idle = 300s`)                                                                                 |
| Health           | `policy-listener` readiness check: ok while the TCP listener accepts connections                                                                                                  |

**Postfix side** (`main.cf`): `smtpd_policy_service_timeout = 10s`, `smtpd_policy_service_default_action = DEFER_IF_PERMIT 4.3.5 Policy service unavailable`. Unreachable or slow means **4xx, never accept-all**. Tested by `tests/integration/mail-plane.test.ts`.

**Planned actions** (2.2): `DUNNO` (continue), `REJECT 5.1.1` (unknown recipient), `REJECT 5.7.1` (relay or sender not authorized), `DEFER_IF_PERMIT 4.7.x` (rate limited), `DEFER_IF_PERMIT 4.3.5` (any internal failure). The adapter never answers `OK` (that would skip later restrictions).

## 2. Postfix → Rspamd milter

| Aspect    | Contract                                                                                                                                                                                                                     |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Transport | Milter protocol 6 to `inet:rspamd:11332` (Rspamd proxy worker in milter mode, `self_scan = yes`)                                                                                                                             |
| Macros    | `i {mail_addr} {client_addr} {client_name} {auth_authen}`                                                                                                                                                                    |
| Timeouts  | Connect 10 s, content 60 s (Postfix); Rspamd proxy timeout 120 s                                                                                                                                                             |
| Actions   | Score ≥ 15 rejects in-session; ≥ 6 adds headers; greylisting is disabled. Everything else is decided post-queue                                                                                                              |
| Headers   | `X-Spamd-Result`, `X-Rspamd-Server`, `Authentication-Results` are added for downstream evaluation. Downstream code must treat them as **gateway-added**, and must strip or ignore any copies a sender supplied (PLANNED 3.1) |
| Failure   | `milter_default_action = tempfail`: Rspamd unreachable means 4xx                                                                                                                                                             |

## 3. Postfix → smtp-adapter LMTP ingestion

**PLANNED 2.2 (listener) and 3.1 (ingestion).** Postfix delivers queued mail with `relay_transport = lmtp:inet:smtp-adapter:24` (today `discard:`).

| Aspect      | Contract                                                                                                                                                                                       |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Replies     | LMTP replies per recipient after `DATA`. `250` only after the EML is in S3 **and** the ingestion transaction has committed                                                                     |
| Failures    | Any S3, MySQL or parsing failure answers `4xx`, so Postfix keeps the message in its spool and retries. Ingestion does not answer `5xx` for infrastructure faults                               |
| Idempotency | `message_identities` unique `(organization_id, ingest_key)`: a repeated delivery of the same message answers `250` without writing again. `ingest_key` is defined in step 3.1                  |
| Transaction | Registry row, `email_messages` (`id` = registry id, `received_at` = registry `received_at`), `email_recipients`, `email_headers`, `email_attachments`, `message_outbox` in **one** transaction |
| Bodies      | Streamed to S3, never buffered whole in memory, never written to MySQL                                                                                                                         |

## 4. RabbitMQ topology

Declared as data in `packages/event-contracts/src/topology.ts` and asserted idempotently by each consumer at startup (`RabbitMqService.assertTopology`). IMPLEMENTED and tested (`events.test.ts`, `rabbitmq-redis.test.ts`).

| Exchange      | Type   | Durable | Purpose                                                  |
| ------------- | ------ | ------- | -------------------------------------------------------- |
| `mail.events` | topic  | yes     | Every domain event; routing key = `eventType`            |
| `mail.dlx`    | direct | yes     | Dead letters; routing key = the dead-letter queue's name |

| Queue (quorum)                   | Consumer              | Binding (routing key on `mail.events`) | `x-delivery-limit` | Dead-letter queue                    |
| -------------------------------- | --------------------- | -------------------------------------- | ------------------ | ------------------------------------ |
| `email-worker.message-received`  | `email-worker`        | `mail.message.received.v1`             | 5                  | `email-worker.message-received.dlq`  |
| `policy-engine.message-scanned`  | `policy-engine`       | `mail.message.scanned.v1`              | 5                  | `policy-engine.message-scanned.dlq`  |
| `delivery-worker.policy-decided` | `delivery-worker`     | `mail.policy.decided.v1`               | 10                 | `delivery-worker.policy-decided.dlq` |
| `archive-worker.policy-decided`  | `archive-worker`      | `mail.policy.decided.v1`               | 10                 | `archive-worker.policy-decided.dlq`  |
| `notification-worker.events`     | `notification-worker` | `mail.policy.decided.v1`               | 5                  | `notification-worker.events.dlq`     |

Every work queue has these arguments: `x-queue-type: quorum`, `x-delivery-limit`, `x-dead-letter-exchange: mail.dlx`, `x-dead-letter-routing-key: <queue>.dlq`, `x-dead-letter-strategy: at-least-once`, `x-overflow: reject-publish`. Each DLQ is itself a durable quorum queue bound to `mail.dlx` with its own name.

| Rule            | Contract                                                                                                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Publishing      | Confirm channel only: an event counts as published when the broker confirms it. Producers publish **from the outbox** (relay PLANNED 3.2), never directly from a handler |
| Consuming       | Manual acks after the handler's MySQL transaction commits. Prefetch `RABBITMQ_PREFETCH` (default 20). Broker `consumer_timeout` 30 min                                   |
| Redelivery      | At-least-once. Every consumer wraps its effects in `processOnce(prisma, '<consumer>', eventId, handler)`                                                                 |
| Poison messages | After `x-delivery-limit` redeliveries a message moves to `<queue>.dlq`. Replay tooling is PLANNED 3.2                                                                    |
| Connection loss | The process exits and is restarted by Compose or Kubernetes (crash-only), so topology and consumers are re-established cleanly                                           |
| Bodies          | Never on the bus: payloads carry ids and S3 keys only                                                                                                                    |

## 5. Event envelope

`eventEnvelopeSchema` (zod), IMPLEMENTED:

| Field            | Type                                    | Contract                                                                                                                                    |
| ---------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `eventId`        | UUID (`z.uuid()`); producers use UUIDv7 | Idempotency key: consumers record `(consumer, eventId)` in `message_idempotency`                                                            |
| `eventType`      | `^[a-z]+(\.[a-z_]+)+\.v\d+$`            | Versioned, also the routing key, e.g. `mail.message.received.v1`                                                                            |
| `occurredAt`     | ISO 8601 date-time                      | When the state change happened                                                                                                              |
| `correlationId`  | string, 8–128 chars                     | Carried from the SMTP session or HTTP request (`x-correlation-id`) into every log line                                                      |
| `organizationId` | decimal string `^[1-9][0-9]{0,19}$`     | The tenant's `organizations.id` (BIGINT UNSIGNED) as a canonical decimal string. Set by the producer from trusted context, never from input |
| `payload`        | per event type                          | Parsed with the event's own schema by `parseEvent(raw, schema)`; any mismatch throws                                                        |

Ids inside the platform (events, S3 keys, logs) are decimal strings because JSON numbers cannot represent 64-bit integers. APIs expose `public_id` (UUIDv7) instead (ADR-0014).

## 6. Event payloads

Every message event carries `messageId` (the registry id, `message_identities.id`, decimal string) and `receivedAt` (the partition key of every message table), so a consumer reaches each partitioned table with `WHERE message_id = ? AND received_at = ?` and prunes to one partition.

| Event type                 | Producer                          | Consumers (queue)                                          | Payload fields                                                                                                                                                                               |
| -------------------------- | --------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mail.message.received.v1` | ingestion in `smtp-adapter` (3.1) | `email-worker`                                             | `messageId`, `receivedAt`, `direction` (`inbound`, `outbound`, `internal`), `emlS3Key` (`^org/[1-9][0-9]{0,19}/`), `sizeBytes` (int ≥ 0), `envelopeFrom` (≤ 320), `recipientCount` (int ≥ 1) |
| `mail.message.scanned.v1`  | `email-worker` (4.1)              | `policy-engine`                                            | `messageId`, `receivedAt`, `scanIds` (decimal ids of `email_scans`), `timedOutStages` (stage names)                                                                                          |
| `mail.policy.decided.v1`   | `policy-engine` (5.2)             | `delivery-worker`, `archive-worker`, `notification-worker` | `messageId`, `receivedAt`, `action` (`deliver`, `tag`, `quarantine`, `discard`), `matchedPolicyVersionIds` (decimal ids of `policy_versions`), `archive` (boolean)                           |

Schemas are IMPLEMENTED and tested (`events.test.ts`: valid events, UUID ids rejected, leading zeros rejected, non-prefixed S3 keys rejected, unversioned types rejected). No producer or consumer exists yet.

**Planned events** (names fixed by their steps): quarantine release request and approval (5.3), delivery status and bounces (2.3), webhook fan-out (6.2), domain verification results (2.1). `mail.policy.decided.v1` carries one action for the whole message; per-recipient decisions (design §3.4 `email_recipients.final_action`) will need either a payload extension in a `v2` or a lookup by consumers. That choice belongs to steps 3.3 and 5.2.

## 7. Security engine contract

`packages/security-contracts` (IMPLEMENTED as types and a zod schema; no engine implements it yet):

```ts
interface SecurityEngine {
  readonly stage: SecurityStage; // antispam | antivirus | yara | url | bec | dlp
  readonly name: string;
  scan(input: ScanInput, signal: AbortSignal): Promise<EngineVerdict>;
}
interface ScanInput {
  organizationId: string; // decimal id, from the envelope, never from message content
  messageId: string; // registry id, decimal string
  emlS3Key: string;
  sizeBytes: number;
}
```

`EngineVerdict`: `stage`, `engine`, `engineVersion`, `outcome` (`clean`, `suspicious`, `malicious`, `error`, `timeout`), `score` (normalised 0–100), `signals` (≤ 200 of `{ id, description ≤ 500 }`), `durationMs`, optional `details`.

Rules: engines read content from S3 and return a verdict; they never decide the final action. `error` and `timeout` are first-class outcomes so policy can fail safe. The caller enforces the timeout through `signal`.

Known gaps, to be closed in step 4.x: the database enum `scan_engine_results.outcome` also has `skipped`; the database `engine` column names `sandbox` and `reputation`, which have no `SecurityStage`; and the aggregated risk score in MySQL is 0–1000 while engine scores are 0–100 (mapping owned by 5.1).

## 8. Engine wire protocols

PLANNED 4.1 and 4.2 (the daemons are IMPLEMENTED and tested directly by `mail-plane.test.ts`).

| Engine | Endpoint (Compose)                       | Protocol                                                                                | Auth                                                                                                                      |
| ------ | ---------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Rspamd | `RSPAMD_URL=http://rspamd:11333`         | HTTP `POST /checkv2` with the raw message; JSON verdict (score, action, symbols)        | None; the normal worker is reachable only on the internal network. The controller (:11334) accepts only `127.0.0.1`/`::1` |
| ClamAV | `CLAMAV_HOST=clamav`, `CLAMAV_PORT=3310` | clamd `INSTREAM` (length-prefixed chunks), `PING`                                       | None; internal network only                                                                                               |
| YARA   | in-process in `email-worker`             | Rules versioned in the repo, loaded at startup (ADR-0007); tenant rules in `yara_rules` | n/a                                                                                                                       |

## 9. HTTP health contract

Every Nest service exposes the same unversioned endpoints (`HealthController`). IMPLEMENTED and tested (`health.service.test.ts`, per-app e2e and integration tests).

| Endpoint            | Checks                                                            | Status codes                           |
| ------------------- | ----------------------------------------------------------------- | -------------------------------------- |
| `GET /health/live`  | None: the process and event loop respond                          | `200` always                           |
| `GET /health/ready` | Every registered indicator, **2 s timeout each**, run in parallel | `200` when all are ok, `503` otherwise |

Response (`HealthReport`): `service`, `status` (`ok` or `error`), `version`, `uptimeSeconds`, `checks[]`. Each check (`DependencyHealth`): `name`, `status`, `latencyMs`, optional `error` (message), optional `details` (flat map of string, number, boolean or null).

| Service               | HTTP port | Readiness checks                                         |
| --------------------- | --------- | -------------------------------------------------------- |
| `api`                 | 3000      | `mysql`, `mysql-reader`, `redis`, `s3`                   |
| `smtp-adapter`        | 3010      | `mysql`, `redis`, `policy-listener`                      |
| `email-worker`        | 3020      | `mysql`, `rabbitmq`, `redis`, `s3`                       |
| `policy-engine`       | 3030      | `mysql`, `rabbitmq`, `redis`                             |
| `delivery-worker`     | 3040      | `mysql`, `rabbitmq`                                      |
| `notification-worker` | 3050      | `mysql`, `rabbitmq`                                      |
| `archive-worker`      | 3060      | `mysql`, `rabbitmq`, `s3`                                |
| `admin-portal`        | 3001      | `GET /api/health`: liveness only, independent of the API |

What each check does: `mysql` runs `SELECT 1` on the writer; `rabbitmq` passively declares `mail.events`; `redis` expects `PONG`; `s3` runs `HeadBucket` on the mail bucket; `policy-listener` checks that the TCP listener is accepting.

**`mysql-reader`** (api only) always resolves with `status: "ok"` and reports the read-replica state in `details`:

```json
{
  "name": "mysql-reader",
  "status": "ok",
  "latencyMs": 3,
  "details": {
    "mode": "writer-fallback",
    "lagSeconds": null,
    "maxLagSeconds": 10,
    "reason": "replication stopped"
  }
}
```

`mode` is `reader`, `writer-fallback` or `writer-only`; `reason` is present only in `writer-fallback`. Readiness does not fail on the replica by design, because the writer fallback keeps the api correct; alert on `details.mode != "reader"` instead (PLANNED 10.3). Details: [replication.md](../database/replication.md).

## 10. api ↔ admin-portal

| Aspect                               | Contract                                                                                                                                                                                                                                                                                                                                                                                                         | Status                                                                                                                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard health                     | The portal server (never the browser) calls `${API_INTERNAL_URL}/health/ready` with `cache: no-store` and a 2 s timeout, and shows `ok`, `degraded` or `unreachable`                                                                                                                                                                                                                                             | IMPLEMENTED (`platform-health.test.ts`, `services.test.ts`)                                                                                                            |
| Credentials                          | The portal holds no data-store credentials; its only backend is the api. `API_INTERNAL_URL` is server-side only                                                                                                                                                                                                                                                                                                  | IMPLEMENTED                                                                                                                                                            |
| Business API                         | REST under `/api/v1` (ADR-0015; probes stay at `/health/*`), OpenAPI at `/docs` outside production with the snapshot `docs/api/openapi.json`, one error shape `{ statusCode, error, message, correlationId }`, `x-correlation-id` echoed. Endpoints: [docs/api/README.md](../api/README.md)                                                                                                                      | IMPLEMENTED: meta, authentication, identity administration, organizations (`app.e2e.test.ts`, `openapi.test.ts`, `route-security.e2e.test.ts`, API integration suites) |
| Browser calls                        | CORS limited to `CORS_ORIGINS` with credentials                                                                                                                                                                                                                                                                                                                                                                  | IMPLEMENTED (config)                                                                                                                                                   |
| Authentication                       | First-party authentication (ADR-0016): email + Argon2id password, TOTP MFA, short-lived JWT bearer access tokens with rotating refresh tokens (JSON bodies; the portal BFF decides cookie handling in 7.x), `X-API-Key` for automation; tenant always from the principal; platform staff reach a tenant only through the audited override. External SSO (OIDC/SAML) and SCIM come later behind the `sso` feature | IMPLEMENTED 1.3 (`apps/api/integration/auth.test.ts`, tenant isolation suites); SSO PLANNED (later step)                                                               |
| Pagination, idempotency, rate limits | Cursor pagination `?limit&cursor` → `{ data, nextCursor }` ordered by id descending (message lists will page on `(received_at, id)`), `Idempotency-Key` on mutating calls, per-tenant request limits; per-IP limits on the authentication routes                                                                                                                                                                 | Cursor pagination and auth rate limits IMPLEMENTED 1.2/1.3; idempotency keys and per-tenant limits PLANNED 6.1                                                         |
| Identifiers                          | `public_id` (UUIDv7) for every exposed aggregate; numeric ids never leave the platform through the API; `bigint` is never serialized raw (explicit response mappers)                                                                                                                                                                                                                                             | IMPLEMENTED for organizations, users and API keys (1.2/1.3); later resources follow the same rule                                                                      |

## 11. S3 key conventions

Buckets come from configuration: `S3_BUCKET_MAIL` (EML and attachment parts) and `S3_BUCKET_ARCHIVE` (archive copies). Locally MinIO (path-style, `S3_ENDPOINT`); in AWS the Terraform `mail-storage` module (SSE-KMS, versioning, TLS-only, public access blocked).

| Object            | Bucket  | Key                                                                                                   | Writer                    | Status                                                             |
| ----------------- | ------- | ----------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------ |
| Raw message (EML) | mail    | `org/{organizationId}/eml/{yyyy}/{mm}/{dd}/{messageId}.eml`                                           | ingestion                 | Prefix IMPLEMENTED (schema, `storage.test.ts`); writer PLANNED 3.1 |
| Attachment part   | mail    | `org/{organizationId}/part/...` (layout fixed in 3.1)                                                 | ingestion or email-worker | PLANNED 3.1, 4.2                                                   |
| Archive copy      | archive | `org/{organizationId}/archive/...` (layout fixed in 8.1)                                              | archive-worker            | PLANNED 8.1                                                        |
| DSN copy          | mail    | `org/{organizationId}/dsn/...` (proposed; layout fixed in 2.3, column `bounce_events.dsn_object_key`) | delivery-worker           | PLANNED 2.3                                                        |

Rules: `{organizationId}` and `{messageId}` are decimal ids. Every key starts with `org/{organizationId}/` so per-tenant export, deletion and IAM conditions are prefix operations. The event schema enforces the **format** (`^org/[1-9][0-9]{0,19}/`); consumers must also check that the prefix **equals** the envelope's `organizationId` before reading (PLANNED 3.x). MySQL stores keys (`*_object_key VARCHAR(512)`), sizes and SHA-256 hashes, never content.

## 12. Database connections

| Variable                 | Account                    | Grants                                                        | Used by                             |
| ------------------------ | -------------------------- | ------------------------------------------------------------- | ----------------------------------- |
| `DATABASE_URL`           | `gateway_app` (writer)     | `SELECT, INSERT, UPDATE, DELETE` on the schema                | Every service                       |
| `DATABASE_READ_URL`      | `gateway_reader` (replica) | `SELECT` on the schema, `REPLICATION CLIENT` (lag probe only) | `api` only (`PrismaReadService`)    |
| `MIGRATION_DATABASE_URL` | `gateway_migrator`         | DDL on the schema                                             | `db-migrate`, partition maintenance |
| (replication)            | `gateway_repl`             | `REPLICATION SLAVE, BACKUP_ADMIN`                             | Replica I/O thread, CLONE           |

Data-plane services (`smtp-adapter`, `email-worker`, `policy-engine`, `delivery-worker`, `archive-worker`) use the writer only, so replica lag never affects a mail decision. `notification-worker` is writer-only until step 6.2. See [data ownership](data-ownership.md) and [replication.md](../database/replication.md).
