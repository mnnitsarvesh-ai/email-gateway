# @email-gateway/email-worker

Email Processing Service. Since step 3.1 it runs the **post-queue MIME ingestion stage**
(design [06-mime-ingestion.md](../../docs/plan/steps/06-mime-ingestion.md),
[ADR-0022](../../docs/architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md)). For each
`mail.message.received.v1` it streams the stored EML from S3 and parses it with
[`@email-gateway/mime-parser`](../../packages/mime-parser/README.md). Bodies and attachments
are streamed to S3, and one writer transaction records the parse metadata, an `email_events`
row and a `mail.message.parsed.v1` or `mail.message.parse_failed.v1` outbox event. Since step
3.2 ([07-rabbitmq.md](../../docs/plan/steps/07-rabbitmq.md) Q13,
[ADR-0024](../../docs/architecture/adr/0024-rabbitmq-topology-retry-dead-letter.md)) the
received events arrive over **RabbitMQ** (queue `email.received`), and the parse events are
published from the outbox by the `event-relay` (to `email.ingestion`, bound to the dormant
`scan.*` and `email.policy.evaluate` queues). Since step 4.1
([09-rspamd.md](../../docs/plan/steps/09-rspamd.md),
[ADR-0026](../../docs/architecture/adr/0026-security-scan-pipeline.md)) it also runs the
**security scan stage** (the scan role, below): one queue per engine, scan rounds, the engine
registry, standardized verdicts, with Rspamd as the first engine. Since step 4.2
([10-attachment-scanning.md](../../docs/plan/steps/10-attachment-scanning.md),
[ADR-0028](../../docs/architecture/adr/0028-attachment-scanning-engine.md)) the second required
engine is the **attachment engine** (queue `scan.attachment`): known-threat hashes, ClamAV over
clamd INSTREAM, YARA-X, true file types and archive limits in resource-limited inspector child
processes, a Redis content cache, sandbox submissions and signature-update rescans (below).
Since step 4.3 ([11-url-protection.md](../../docs/plan/steps/11-url-protection.md),
[ADR-0029](../../docs/architecture/adr/0029-url-security-engine.md),
[ADR-0030](../../docs/architecture/adr/0030-url-rewriting-and-click-tokens.md)) the third required
engine is the **url engine** (queue `scan.url`): URL extraction from the stored parts,
normalization, lookalikes, reputation providers with an authenticated Redis cache, SSRF-guarded
redirect-chain fetches, the verdict map `url-map/1`, URL rewriting into a new S3 object with
signed click tokens, dynamic-inspection requests, their results consumer (`scan.url.results`) and
the pending-inspection sweeper (below).

Data plane: the MySQL **writer** only (ADR-0014, no `PrismaReadService`), S3 (`S3_BUCKET_MAIL`)
and RabbitMQ with one least-privilege user per role: the MIME role uses `RABBITMQ_EMAIL_WORKER_URL`
(read `email.received`, write `email.ingestion` and `email.events` for retry and dead-letter
copies; it cannot configure anything or reach `email.delivery`), the scan role
`RABBITMQ_SCANNER_URL` (user `eg-scanner`: read `scan.spam`, `scan.attachment`, `scan.url`,
`scan.url.results`, write `email.security` and `email.events`). Redis holds the attachment
engine's content cache (`eg:scan:att:v2:*`, values authenticated with the worker-only
`ATTACHMENT_CACHE_HMAC_KEY`, A10) and the URL cache (`eg:url:*`, `URL_CACHE_HMAC_KEY`, U6;
Rspamd keeps its own state in Redis DB `RSPAMD_REDIS_DB`). Health is `GET /health/live` and
`GET /health/ready` (checks `mysql`, `rabbitmq` with the MIME role, `rabbitmq-scanner` with the
scan role, `clamav` and `attachment-inspector` where the attachment consumer runs, `url-engine`
(Redis of the URL cache; the DNS resolver's reachability as a detail) where the url consumer runs,
`redis`,
`s3`; a broker check = connected, not blocked by a resource alarm, the
exchanges and queues of the role verified passively). Metrics are on `GET /metrics`. The default
port is 3020.

## Roles (step 4.1 S1)

| Role | Flag                                    | Broker user (URL)                               | Consumes                                                                                                                         | Readiness                                                                                                       |
| ---- | --------------------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| MIME | `MIME_INGESTION_ENABLED` (default true) | `eg-email-worker` (`RABBITMQ_EMAIL_WORKER_URL`) | `email.received`                                                                                                                 | `rabbitmq`                                                                                                      |
| Scan | `SCAN_ENABLED` (default true)           | `eg-scanner` (`RABBITMQ_SCANNER_URL`)           | `scan.spam`, `scan.attachment`, `scan.url` + `scan.url.results`, `scan.bec`, `scan.dlp` (one queue per engine, `SCAN_CONSUMERS`) | `rabbitmq-scanner`, `clamav`, `attachment-inspector`, `url-engine`, `bec-engine`, `dlp-engine`, `dlp-extractor` |

Locally (Compose, host) one process runs both roles. Production runs two Deployments of the same
image (`infrastructure/kubernetes/base/email-worker.yaml`): `email-worker` (`SCAN_ENABLED=false`)
and `email-worker-scan` (`MIME_INGESTION_ENABLED=false`, `SCAN_CONSUMERS=rspamd`), plus
`email-worker-attachment` (`SCAN_CONSUMERS=attachment`, step 4.2) and `email-worker-url`
(`SCAN_CONSUMERS=url`, step 4.3, `infrastructure/kubernetes/base/email-worker-url.yaml`), scaled
independently. The global
`AmqpModule` is imported only with the MIME role; `ScanningModule` builds its own connection and
confirm publisher. At least one role must be enabled.

## Modules

| Path                                           | Responsibility                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/config.ts`                                | zod config, including every `MIME_*` key of design §5 and the M5 cross-field refusals (`validateMimeConfig`)                                                                                                                                                                                                               |
| `src/mime-ingestion/limits.ts`                 | config → `MimeLimits`                                                                                                                                                                                                                                                                                                      |
| `src/mime-ingestion/part-keys.ts`              | deterministic part keys `org/{org}/part/{yyyy}/{mm}/{dd}/{messageId}/{partIndex}.{text\|html\|att}` (UTC date of `received_at`) and the organization-prefix check                                                                                                                                                          |
| `src/mime-ingestion/s3-part-sink.ts`           | the parser's `PartSink`: one `@aws-sdk/lib-storage` `Upload` per part, ranged `GetObject` for the zip inspector, abort without an object, cleanup of this attempt's objects                                                                                                                                                |
| `src/mime-ingestion/eml-source.ts`             | streaming `GetObject` of `email_messages.eml_object_key`. `NoSuchKey` → `eml_missing`, anything else is an infrastructure error                                                                                                                                                                                            |
| `src/mime-ingestion/mime-repository.ts`        | writer persistence: ledger, message and parse row reads, `markParsing`, attempt decrement, and the finalize transaction                                                                                                                                                                                                    |
| `src/mime-ingestion/mime-ingestion.service.ts` | `MimeIngestionService.handle(event)`: the M3 flow                                                                                                                                                                                                                                                                          |
| `src/mime-ingestion/payloads.ts`               | the event payloads, validated with `messageParsedV1` and `messageParseFailedV1` before insert                                                                                                                                                                                                                              |
| `src/mime-ingestion/mime-metrics.ts`           | the M16 series                                                                                                                                                                                                                                                                                                             |
| `src/mime-ingestion/mime-ingestion.module.ts`  | `MimeIngestionModule.forRoot(config, logger)`: the `email.received` `QueueConsumer` (`createMimeConsumer`, `classifyMimeFailure`), the service and `MimeIngestionRuntime` (starts after bootstrap; stops the consumer, then the AMQP client, before the database closes). Imported only when `MIME_INGESTION_ENABLED=true` |
| `src/scanning/config.ts`                       | every `SCAN_*` key of step 4.1 §5 and the cross-field refusals (`validateScanConfig`)                                                                                                                                                                                                                                      |
| `src/scanning/engine.ts`                       | the adapter contract (`EngineScanContext`, `EngineScanOutcome`, `ScanEngineAdapter`), `EngineAttemptFailedError`, `EmlUnavailableError`, failure reason codes                                                                                                                                                              |
| `src/scanning/registry.ts`                     | `ENGINE_REGISTRY` (`[rspamdRegistration]`): catalog entry, ledger consumer, budgets, adapter factory, settings resolution. The orchestrator never names an engine                                                                                                                                                          |
| `src/scanning/round-service.ts`                | `ScanRoundService.handle(event)`: the per-delivery algorithm of S5 (generic over the registry)                                                                                                                                                                                                                             |
| `src/scanning/scan-repository.ts`              | writer persistence: round opening (E3, `email_scans`), attempt rows, the finalize transaction (final row, `email_auth_results`, completion, E6/E7, `scanned.v1`), the sweeper's queries                                                                                                                                    |
| `src/scanning/aggregate.ts`                    | `aggregateRound` (S6, pure)                                                                                                                                                                                                                                                                                                |
| `src/scanning/circuit-breaker.ts`              | the generic breaker (closed / open / half-open, consecutive and ratio thresholds, injected clock)                                                                                                                                                                                                                          |
| `src/scanning/settings-resolver.ts`            | tenant overrides from `scan_engine_settings`, re-validated at use, LRU cache with TTL                                                                                                                                                                                                                                      |
| `src/scanning/deadline-sweeper.ts`             | the round deadline sweeper (leader lock `scan:deadline`; window on `deadline_at`)                                                                                                                                                                                                                                          |
| `src/scanning/engine-consumer.ts`              | the engine `QueueConsumer` (`createEngineConsumer`, `classifyScanFailure`) and the S3 EML opener                                                                                                                                                                                                                           |
| `src/scanning/scan-metrics.ts`                 | the S17 series (and the transition service's `lifecycle_*` series)                                                                                                                                                                                                                                                         |
| `src/scanning/engines/rspamd/`                 | the Rspamd adapter (`rspamd.engine.ts`), the S7 mapping (`verdict-mapper.ts`, `RSPAMD_MAPPING_VERSION = 'rspamd-map/2'`), the symbol categories as data (`symbol-catalog.ts`) and the registration                                                                                                                         |
| `src/scanning/scanning.module.ts`              | `ScanningModule.forRoot(config, logger)`: the scanner broker connection and publisher, one consumer per enabled engine, the sweeper, `ScannerBrokerHealth` (`rabbitmq-scanner`) and `ScanningRuntime` (connects at init, starts after bootstrap, stops before the database closes). Imported only when `SCAN_ENABLED=true` |

The components are plain classes wired in the modules, so the integration tests build the same
graph without Nest (`createMimeIngestionService`, `createMimeConsumer`, `createScanInfrastructure`,
`createRoundService`, `createEngineConsumer`).

## Flow (design M3)

1. **Ledger pre-check.** If `message_idempotency (email-worker.mime-parser, eventId)` exists, the
   event is a `duplicate` and nothing happens.
2. **Load the message** from the writer by `(id, received_at, organization_id = envelope.organizationId)`.
   If the row is missing (unknown message, or a **cross-tenant envelope**), only the ledger row
   is written, a warning is logged and `message_missing` is counted.
3. **Load the parse row.** A final status means the event is a `duplicate`, and a ledger row is
   written. A different event for the same message never parses it twice.
4. **Mark parsing.** The row is inserted with `attempts = 1`, or `attempts + 1` is applied when it
   is already `parsing` (a P2002 race re-reads it). When `attempts > MIME_MAX_ATTEMPTS`, the result is
   `parse_failed / max_attempts_exceeded` (the poison guard). The guard counts crashes and every
   failed attempt that was not an outage (step 9).
5. **Pre-read checks.** A key outside `org/{organizationId}/` gives `eml_key_mismatch`. A key
   without any `org/<id>/` prefix is published with `emlS3Key: null` (the contract cannot carry
   it), so the verdict still commits.
   `size_bytes > MIME_MAX_MESSAGE_BYTES` gives `parse_limit_exceeded ['message_size']` without a
   download.
6. **Stream and parse** under a wall clock of `MIME_PARSE_TIMEOUT_MS`, and every part is streamed
   to its key. `MIME_S3_TIMEOUT_MS` bounds each single wait on S3: the GET until it answers, each
   body chunk the parser waits for, each part write waiting for upload capacity and each part
   finish (`S3Stalled` / `UploadTimedOut`, retried). Time the parser spends on the bytes is not S3
   time, so a large message is never cut by it. When the parse budget runs out, the result is
   `parse_timeout` only if the message itself was slow: if an S3 call had been pending for at
   least `min(1 s, budget / 4)`, or half the budget was spent waiting on S3, the attempt is an
   infrastructure retry (`S3Stalled`) instead.
7. **Integrity.** The SHA-256 and byte count of the bytes read are compared with `eml_sha256` and
   `size_bytes`. A mismatch gives `parse_failed / integrity_mismatch`. Nothing of the content is
   recorded, and this attempt's part objects are deleted (best effort).
8. **Finalize** in one writer transaction (`processOnce`, budget `MIME_DB_TIMEOUT_MS`):
   - a conditional `UPDATE email_message_parses … WHERE status = 'parsing'` (0 rows means the
     transaction rolls back and the event is a `duplicate`);
   - `email_headers` and `email_attachments` rows;
   - `email_messages.subject` (decoded) and `attachment_count` only, never `status`,
     `status_changed_at` or `version`;
   - one `email_events` row (`parsed` or `parse_failed`, `source_service = email-worker`);
   - one outbox row (`aggregate_type = message`, `correlation_id` from the received event).
9. **Failed attempts** are rethrown, and the feed retries them with backoff
   (`MIME_RETRY_BASE_MS`…`MIME_RETRY_MAX_MS`). A **transient** failure (`isTransientFailure`: any
   S3 service error, a network or timeout error, `S3Stalled`, a Prisma connection, pool,
   transaction-timeout or deadlock error) gives the attempt back (`attempts - 1`, best effort), so
   a message is never failed because of an outage. Any **other** exception (for example Prisma
   `P2000` "value too long", a contract violation, an unexpected `TypeError`) fails the same way
   on every attempt, so it keeps its attempt: after `MIME_MAX_ATTEMPTS` such attempts the message
   ends `parse_failed / max_attempts_exceeded` instead of freezing the cursor forever. The retry
   log line carries `transient: true|false`.

**Logs** carry ids, codes, counts, durations and `errName`/`errCode` only (M15). They never carry
the subject, filenames, addresses, header values, bodies, or error objects and messages from the
parser, S3 or decoders. `src/mime-ingestion/log-redaction.test.ts` proves this with marker
strings.

## Scan stage (step 4.1 S5, S6)

Every registered and enabled engine consumes its own queue (`scan.spam` for Rspamd, ledger
consumer `email-worker.scan.rspamd`) with both triggers: `mail.message.parsed.v1` (round 0) and
`mail.message.rescan_requested.v1` (round = `payload.lifecycleRound`, after the api applied
E19). Per delivery (`ScanRoundService`):

1. **Ledger check** (`duplicate`).
2. **Load** the writer row by `(id, received_at, organization_id = envelope.organizationId)`; a
   missing row (or another tenant's) writes only the ledger row (`message_not_found`). The EML key
   must lie under `org/<envelope org>/` and equal the row's key (else a final `error`
   `eml_key_mismatch`, no scan).
3. **Open the round** in a short writer transaction: lock the message (`lockLifecycle`); round 0
   of a `persisted` message → E3 `persisted → scanning` (`transitionKey scan-open:<id>:0`, shared
   by every engine); a `scanning` message of the same round joins; an older round, another state
   or an already finalized engine is skipped (`older_round`, `lifecycle_<state>`, `already_final`,
   ledger row only). The `email_scans` row of the round is created with `INSERT IGNORE`
   semantics (`status running`, `deadline_at = now + SCAN_ROUND_DEADLINE_SECONDS`,
   `required_engines` snapshot, `trigger_event_id`); this engine's rows give its attempt count.
4. **Scan outside any transaction**: tenant settings (S8), the engine's circuit breaker, a
   per-call `AbortSignal.timeout(SCAN_<ENGINE>_TIMEOUT_MS)`, the EML streamed from S3 (each wait
   bounded by `SCAN_S3_TIMEOUT_MS`; never buffered, never persisted).
5. **Record**: a retryable failure within `SCAN_<ENGINE>_MAX_ATTEMPTS` and the deadline → a
   non-final row (`timeout`/`error`, `engine.*` reason) and `EngineAttemptFailedError`
   (`retryable`, hold backoff `SCAN_RETRY_BASE_MS`..`SCAN_RETRY_MAX_MS`); otherwise **finalize**
   through `processOnce`: lock message → scan, the final row (at most one per engine, unique
   `final_engine` key), the `email_auth_results` row, and the completion check in the same
   transaction. An S3, MySQL or network outage is **transient**: thrown unchanged, no row, no
   attempt consumed.
6. **Completion** when every required engine has a final: `aggregateRound` (S6), the
   `email_scans` row completed (`status`, `scan_verdict`, `reason_codes`), E6 `scanned` or E7
   `scan_failed` (`scan-complete:<id>:<round>`, `expectedRound`), and one schema-validated
   `mail.message.scanned.v1` outbox row (ids, codes and counts only). A superseded round (a newer
   rescan, an expired message) completes its row but writes no event.

The stage never writes `email_messages.status` itself (one-door rule) and never rejects,
quarantines or delivers (engines classify, policy decides). **Never clean by accident:** a
timeout, error, open breaker, missing EML, unparseable reply or deadline is never `clean`; a
round whose required engine failed ends `scan_failed`.

**Rspamd engine** (`engines/rspamd`): the request carries the trusted envelope of the writer row
(`client_ip`, `client_helo`, `client_name`, `envelope_from`, recipients by `rcpt_seq`,
`mta_queue_id`; `User: org-<id>` only for outbound and internal mail), `Log-Tag m<id>r<round>`.
Messages above `SCAN_RSPAMD_MAX_BYTES` are not sent (`unknown`, `engine.too_large`). The reply is
normalized by `@email-gateway/rspamd` and mapped with rules R0–R10 (`verdict-mapper.ts`); the
result keeps at most 200 signals with at most 5 options of 200 characters (`evidence`), and the
SPF/DKIM/DMARC/ARC outcomes go to `email_auth_results`. The engine version comes from the reply's
`Server` header (controller `/stat` only when it is missing, cached `SCAN_ENGINE_VERSION_TTL_MS`).

**Resilience** (S10): one breaker per engine per worker (`SCAN_BREAKER_*`; only transport
failures count; open → immediate `circuit_open` attempt), in-flight HTTP calls limited to the
prefetch, and the **deadline sweeper**: one leader per cluster (`GET_LOCK('scan:deadline')`)
finalizes running rounds past `deadline_at` (final `timeout` rows `deadline_exceeded` for the
missing required engines) every `SCAN_SWEEP_INTERVAL_MS`.

**Tenant settings** (S8): `scan_engine_settings` rows (written by the api) are re-validated at
use with `resolveRspamdSettings`; an invalid row falls back to the platform settings (logged
once per row version, `scan_settings_invalid_total`). Cached per (organization, engine) for
`SCAN_SETTINGS_CACHE_TTL_MS` (10 000 entries, LRU): a change takes effect within the TTL. Every
result records `settings_version` (`rspamd-map/2;p=<platform hash>;t=<row version | none>`).

R6 trusts an ARC chain (DMARC failure becomes the reason `auth.dmarc_fail_arc_trusted` only) when
its latest sealer is on `RSPAMD_ARC_TRUSTED_SEALERS` (Rspamd `ARC_ALLOW_TRUSTED`); `ARC_ALLOW`
alone never does (`isTrustedArcChain` in `verdict-mapper.ts`). The deadline sweeper selects
`running` rounds by `deadline_at` within `SCAN_SWEEP_LOOKBACK_HOURS`, never by `received_at`.

Operations: [docs/runbooks/scan-pipeline.md](../../docs/runbooks/scan-pipeline.md).

## Attachment engine (step 4.2)

Design [10-attachment-scanning.md](../../docs/plan/steps/10-attachment-scanning.md) (decision ids
A*n*), [ADR-0028](../../docs/architecture/adr/0028-attachment-scanning-engine.md), runbook
[attachment-scanning.md](../../docs/runbooks/attachment-scanning.md), deployment
[attachment-scanning.md](../../docs/deployment/attachment-scanning.md). Code:
`src/scanning/engines/attachment/`.

| Module                                                                             | Role                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `registration.ts`                                                                  | `attachmentRegistration` (consumer `email-worker.scan.attachment`, budget `SCAN_ATTACHMENT_*`, `settingsFor` = `resolveAttachmentSettings`, an invalid tenant row falls back to the platform), `createAttachmentEngine`                                                                                                                                                                                                                                           |
| `attachment.engine.ts`                                                             | The adapter (A3): parse and attachment rows on the writer (row count checked against the parse row's `attachment_count`; a mismatch is the retryable `inconsistent_read`), A0/E1 (every parse limit but `body_size` is incomplete), known hashes (chunks of 500), per-attachment parallelism, byte budget, cache, S3 full read (size bound, SHA-256), clamd ∥ inspector, inner hashes, mapping, child rows, sandbox selection, readiness checks, signature source |
| `verdict-mapper.ts`                                                                | `attachment-map/1` (A6), pure: rules M1–C1, A0, E1, tenant rules (deny incl. extension type and entries, allow list, raise-only), reason-code ordering ≤ 32, signals, sandbox selection                                                                                                                                                                                                                                                                           |
| `inspector/pool.ts`                                                                | `InspectorPool` (A4): children with an empty environment, IPC (`advanced`), heap cap, `prlimit --cpu --core=0` (Linux, `required`), Node's permission model (compiled children), private 0700 cwd, recycling, bounded wait queue, CPU/RSS sampling every 100 ms, kill classification `cpu`/`memory`/`wall`/`crash`, bundle-id handshake                                                                                                                           |
| `inspector/child.ts`, `inspect.ts`, `file-type.ts`, `yara-scanner.ts`, `bundle.ts` | The child (no `child_process`, no fs writes: unit-tested module graph): true type (A5), archive walk (zip/gzip/tar, limits while inflating, encryption markers, malformed, traversal, overlap, index paths), YARA-X, bundle id (A9, equals `yara/bundle.mjs`)                                                                                                                                                                                                     |
| `content-cache.ts`, `clamav-versions.ts`                                           | Content cache `eg:scan:att:v2:<sha256>:<contentVersion>` (A10: `<HMAC-SHA256>.<json>` under `ATTACHMENT_CACHE_HMAC_KEY`, wrong MAC or shape → `rejected` and rescanned, strict `contentResultSchema` in `content-schema.ts`; TTL by content verdict, ≤ 128 KiB, Redis errors bypass), the ClamAV version provider                                                                                                                                                 |
| `attachment-store.ts`, `part-reader.ts`, `byte-budget.ts`                          | Writer reads with echo checks (`InconsistentAttachmentReadError`: identity, part order, requested hashes), bounded S3 part reads, the weighted byte semaphore                                                                                                                                                                                                                                                                                                     |
| `signature-watcher.ts`, `rescan-runner.ts`                                         | A13: version detector (`scan_signature_versions` and its job in one transaction, jobs per `ATTACHMENT_SIGNATURE_RESCAN`) and the job executor (E19 `scanner`/`signature_rescan` + `rescan_requested.v1`)                                                                                                                                                                                                                                                          |
| `attachment-metrics.ts`                                                            | The A19 series (bounded labels)                                                                                                                                                                                                                                                                                                                                                                                                                                   |

Generic changes of the 4.1 orchestrator (A12): `EngineDeps` carries the writer, S3, Redis, the
scan metrics and the registry; `EngineDefinite.childRows { attachments, sandbox }` travel in
`FinalRowInput` and `ScanRepository.insertFinal` writes `attachment_scan_results`,
`sandbox_submissions` and the `sandbox_requested.v1` outbox rows in the final row's transaction
only when the final row was inserted; a definite result may be `skipped` (rule A0); the failure
codes `inspector_timeout`, `inspector_crash`, `part_unavailable`, `part_integrity`,
`part_key_mismatch`, `parse_row_missing`, `inconsistent_read` (retryable, not the engine's fault); the round deadline validation is the maximum over the
enabled engines; `ScanningModule` builds consumers only for `SCAN_CONSUMERS` and starts/stops the
adapter (inspector pool), the watcher and the runner.

**Configuration** (`.env.example` section "Attachment scanning (step 4.2)"; every key validated by
`scanning/config.ts`): `SCAN_ENGINES` (default `rspamd,attachment`), `SCAN_CONSUMERS` (subset;
empty = all), `CLAMAV_HOST`/`_PORT`/`_TIMEOUT_MS`/`_MAX_CONNECTIONS`/`_CHUNK_BYTES`,
`SCAN_ATTACHMENT_CONCURRENCY`/`_TIMEOUT_MS`/`_MAX_ATTEMPTS` (< 10, the queue limit),
`ATTACHMENT_MAX_BYTES` (≤ `MIME_MAX_ATTACHMENT_BYTES`), the archive limits, `ATTACHMENT_DENIED_TYPES`
and the three rule verdicts (validated with `attachmentPlatformSettingsSchema`),
`ATTACHMENT_MAX_PER_MESSAGE`, `ATTACHMENT_PER_MESSAGE_PARALLELISM`,
`ATTACHMENT_MEMORY_BUDGET_BYTES` (≥ `ATTACHMENT_MAX_BYTES`), `ATTACHMENT_INSPECTOR_*` and
`ATTACHMENT_INSPECT_*` (CPU ≤ wall timeout, YARA ≤ wall timeout, RSS > heap; `best_effort`
rlimits and `EG_INSPECTOR_SELFTEST` refused with `NODE_ENV=production`),
`ATTACHMENT_YARA_RULES_DIR`, `ATTACHMENT_CACHE_*`, `ATTACHMENT_SANDBOX_*`,
`ATTACHMENT_SIGNATURE_*`, `ATTACHMENT_RESCAN_*`, `REDIS_URL`.

**Scaling:** see the deployment doc (`CLAMAV_MAX_CONNECTIONS × replicas ≤ clamd MaxThreads × clamd
replicas`, `concurrency × parallelism ≥ pool size`, memory budget + pool × RSS within the pod
limit).

**Benchmark:** `pnpm --filter @email-gateway/email-worker bench:attachments -- --duration=10`
(`bench/attachment-bench.ts`; real pool + ClamdClient, cache off/on; results in
[docs/performance/attachment-scanning.md](../../docs/performance/attachment-scanning.md)). The
compiled child (`dist/`) is used when built (`pnpm --filter @email-gateway/email-worker build`).

## URL engine (step 4.3)

Design [11-url-protection.md](../../docs/plan/steps/11-url-protection.md) (decision ids U*n*),
runbook [url-scanning.md](../../docs/runbooks/url-scanning.md). The URL primitives live in
[`@email-gateway/url-security`](../../packages/url-security/README.md); this worker wires them.
Code: `src/scanning/engines/url/`, `src/scanning/url-config.ts`, `src/scanning/parts/`.

| File                         | Content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `registration.ts`            | `urlRegistration` (consumer `email-worker.scan.url`, budget `SCAN_URL_*`, `settingsFor` = `resolveUrlSettings`, an invalid tenant row falls back to the platform, `settingsVersion` with `url-map/1`), `createUrlEngine` (SSRF guard, restricted resolver, guarded fetchers `engine`/`rdap` sharing `URL_FETCH_CONCURRENCY`, providers + breakers, cache, brands/shorteners, token key, engine version)                                                                                                    |
| `url.engine.ts`              | The adapter (U3): echo-checked writer reads, S3 part reads (org prefix, size, SHA-256), extraction + normalization, stable seqs, lookalikes, resolved host addresses (`HostAddressResolver`, IP reputation), reputation (a local-feed MySQL failure is internal: `FeedErrorScope`), fetch selection and chains (chain cache), final-URL, hop and hop-address reputation and final-URL lookalike, `url-map/1`, aggregation, the streaming rewrite, inspection selection, child rows, readiness `url-engine` |
| `url-rows.ts`                | Pure helpers: E1 completeness, extra parts, seq assignment, static risk, the bounded JSON columns, rewrite object keys (`chainItems` and `mergeLookalike` are re-exported from url-security, shared with the click-service)                                                                                                                                                                                                                                                                                |
| `url-store.ts`               | `PrismaUrlStore`: parse row, attachment rows, `message_urls` of earlier rounds, active tenant domains (LRU 60 s), the `local_feed` query (`org_scope = 0`, not expired); every read echo-checked (`InconsistentUrlReadError`)                                                                                                                                                                                                                                                                              |
| `rewrite-store.ts`           | `S3RewriteStore`: multipart `Upload` of the rewritten EML (`message/rfc822`, tag `eg-object=rewrite` as `Tagging` of the creating request, never a separate PutObjectTagging); a skipped rewrite aborts (and deletes a completed single-part object); an upload error deletes the key and is thrown (transient)                                                                                                                                                                                            |
| `url-results.ts`             | `UrlResultsService` + consumer of `scan.url.results` (U15): `processOnce`, strict payload, echo-checked load by `inspectionId`, forged/mismatched results dropped, `WHERE status = 'pending'` update with the dynamic verdict (M5/S9/U3 from the stored lookalike confidence), dynamic cache entry                                                                                                                                                                                                         |
| `inspection-sweeper.ts`      | `InspectionSweeper` (U15): leader lock `scan:url-inspections`, expires pending rows older than `URL_DYNAMIC_PENDING_TTL_SECONDS` in batches of 500                                                                                                                                                                                                                                                                                                                                                         |
| `url-metrics.ts`             | The U18 email-worker series (bounded labels; unknown values become `other`)                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `../../parts/part-reader.ts` | `S3PartReader`, shared with the attachment engine (moved from `engines/attachment/`)                                                                                                                                                                                                                                                                                                                                                                                                                       |

Generic changes of the orchestrator (as 4.2 A12): `EngineChildRows.urls { messageUrls, results,
rewrite, inspections }`; `ScanRepository.insertFinal` writes them in the final row's transaction
only when the final row was inserted (`message_urls` `createMany … skipDuplicates` plus a seq/hash
read-back, `url_scan_results`, `url_rewrites` with the `org/<org>/rewrite/` key check,
`url_dynamic_inspections` + one validated `mail.url.inspection_requested.v1` outbox row each);
the failure codes `inconsistent_read` and `extract_timeout` have their own reason codes and metric
reasons. `ScanningModule` starts the results consumer and the sweeper where `SCAN_CONSUMERS`
contains `url` (and verifies `scan.url.results` passively).

**Configuration** (`.env.example` section "URL protection (step 4.3)"; validated by
`scanning/url-config.ts`): `SCAN_ENGINES` (default `rspamd,attachment,url`), `SCAN_URL_*` (attempts
< 10; the round deadline covers `6 × (120 + 60) s`), `URL_MAX_*`, `URL_EXTRA_PART_MAX_BYTES`,
`URL_EXTRACT_TIMEOUT_MS`, `URL_REPUTATION_PROVIDERS` (documented-only providers refused),
`URL_DNSBL_*` (never echoed in errors), `URL_RDAP_BASE_URL`, `URL_PROVIDER_*`, `URL_DNS_*`,
`URL_CACHE_*` (`URL_CACHE_HMAC_KEY` ≥ 32 characters required where the url engine consumes with
the cache), `URL_SCAN_TIME_FETCH`, `URL_FETCH_*` (proxy mode with `URL_EGRESS_PROXY_TOKEN`),
`URL_SHORTENER_*`, `URL_PROTECTED_*`, `URL_LOOKALIKE_*`, `URL_REWRITE_*`, `URL_CLICK_BASE_URL`
(https in production), `URL_TOKEN_KEY_*` (64 hex, ids 1..255, previous slot with its own id),
`URL_TOKEN_*_EXPIRY_DAYS`, `URL_DYNAMIC_*`. TEST-ONLY `URL_FETCH_TEST_ALLOW_CIDRS` (documentation
ranges only) and `URL_FETCH_TEST_DIAL_MAP` are refused unless APP_ENV is `local`/`ci`
(NODE_ENV=production with APP_ENV `staging`/`production`).

**Tests:** unit tests in `src/scanning/engines/url/*.test.ts` and `src/scanning/url-config.test.ts`;
package integration `integration/url-*.test.ts` against the real writer, MinIO, Redis, RabbitMQ,
dns-sink and url-test (host-run with `URL_FETCH_TEST_DIAL_MAP`; `docker compose --profile smtp-test
up -d test-pki dns-sink url-test`).

## BEC engine and stage-2 engines (step 4.4)

Design [12-phishing-bec.md](../../docs/plan/steps/12-phishing-bec.md) (decision ids B*n*),
runbook [bec-detection.md](../../docs/runbooks/bec-detection.md), deployment
[bec-detection.md](../../docs/deployment/bec-detection.md). Rules, text analysis, identity, history
keys and the AI layer live in [`@email-gateway/bec`](../../packages/bec); this worker wires them.
Code: `src/scanning/engines/bec/`, `src/scanning/bec-config.ts`.

**Generic stage-2 capability (B2; the orchestrator never names an engine).** An engine whose
catalog entry declares `dependsOn` is a stage-2 engine: its consumer takes only
`mail.message.scan_stage_ready.v1` (`scanEventTypes(entry)`), stage-1 consumers `parsed.v1` +
`rescan_requested.v1`. `ScanRepository.complete()` (both locks held, finals read after them) writes
one validated `scan_stage_ready.v1` outbox row per stage-2 engine whose required dependencies all
have finals, when the final inserted by this transaction is one of them (`stageTriggersFor`, pure;
exactly once per round; never by the deadline sweeper; `scan_stage_triggers_total{engine}`). The
round service handles trigger `stage`: round = `payload.lifecycleRound`; another engine's trigger
→ ledger no-op `other_stage_engine`; `decideOpen(…, 'stage')` never applies E3; the round must
exist with `payload.scanId` (else ledger no-op `stage_round_missing`, warned). The engine context
now carries `scanId` and `scanKind`. Config: every enabled stage-2 engine needs an enabled
dependency and some stage-1 engine must be enabled; the minimum round deadline is the maximum over
the stage-1 engines plus the maximum over the stage-2 engines of `maxAttempts × (timeoutMs +
SCAN_RETRY_MAX_MS)` (default 1 440 + 315 = 1 755 s).

| File                 | Content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `registration.ts`    | `becRegistration` (consumer `email-worker.scan.bec`, budget `SCAN_BEC_*`, `settingsFor` = `resolveBecSettings` with the platform settings of the env, invalid row → platform), `createBecEngine` (static data, local models from the manifest with hash check, LLM providers per mode — `anthropic` or `fake`, breaker, Redis budgets, engine version and model info metrics)                                                                                                                                                                          |
| `bec.engine.ts`      | The adapter (B4): echo-checked writer reads, dependency input states, text parts (`S3PartReader`; prefix read above `BEC_TEXT_MAX_BYTES`, no hash check on a partial read), an incomplete header set (`stored_headers_truncated` or > 200 rows) → `bec.content_incomplete`, history reads, `evaluateBecRules`, the AI layer, `bec_scan_results` + history child rows (inbound rows only for an authenticated From with a final verdict `clean`/`unknown`); outbound/internal → `skipped` (`bec.not_inbound`) with pair updates; readiness `bec-engine` |
| `bec-store.ts`       | `PrismaBecStore`: round row, dependency finals, auth row, URL results joined with `message_urls`, headers (≤ 200, read as 201 to detect truncation), parse row (incl. `defects`), subject, tenant data (LRU ≤ 1 000 organizations, `BEC_TENANT_DATA_CACHE_TTL_MS`), history rows; every read echo-checked (`InconsistentBecReadError` → `inconsistent_read`)                                                                                                                                                                                           |
| `ai-layer.ts`        | `BecAiLayer`: modes per layer (tenant choice within the platform cap), LLM gating, breaker, per-process concurrency, budget check before every call, timeout; `combineVerdict` with the invariant; ≤ 2 applied, ≤ 3 shadow assessments; never throws                                                                                                                                                                                                                                                                                                   |
| `llm-budget.ts`      | `RedisLlmBudget`: one Lua script over `eg:bec:llm:t:<org>:<yyyymmdd>` and `eg:bec:llm:m:<epochMinute>` (check both, increment both only when both have room); Redis error / timeout → `unavailable` (no call)                                                                                                                                                                                                                                                                                                                                          |
| `history-sweeper.ts` | `BecHistorySweeper` (B12): leader lock `scan:bec-history`, per organization rows older than its retention deleted in batches of 1 000 (`SCAN_DB_TIMEOUT_MS` transactions)                                                                                                                                                                                                                                                                                                                                                                              |
| `bec-metrics.ts`     | The B19 email-worker series (bounded labels)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

`EngineChildRows.bec { result, history }`: `ScanRepository.insertFinal` writes the
`bec_scan_results` row (unique per scan) and — round 0 of an initial scan only — the history
upserts (`INSERT … ON DUPLICATE KEY UPDATE` via `$executeRaw`, sorted keys, saturating counters,
`infra` JSON read-modify-write under `SELECT … FOR UPDATE`, ≤ 51 rows) in the final row's
transaction, only when the final row was inserted.

**Configuration** (`.env.example` section "Phishing and BEC detection (step 4.4)"; validated by
`scanning/bec-config.ts`): `SCAN_ENGINES` default `rspamd,attachment,url,bec`, `SCAN_BEC_*`
(attempts < 10), `BEC_TEXT_*`, the platform settings `BEC_SUSPICIOUS_SCORE` … `BEC_HISTORY_*_RETENTION_DAYS`
(through `becPlatformSettingsSchema`, errors name the env key), `BEC_LOCAL_MODEL(_SHADOW)` (in
the packaged manifest with the file hash, else the worker refuses to start), `BEC_LLM_*`
(`fake` refused with NODE_ENV=production; a mode other than `off` with `anthropic` requires
`BEC_LLM_API_KEY` where bec consumes), `BEC_CONTEXT_HMAC_KEY` (≥ 32 characters, required where bec
consumes), `BEC_HISTORY_*`, `BEC_TENANT_DATA_CACHE_TTL_MS`, `BEC_SUPPRESSION*`, `BEC_MAX_*`.

**Tests:** unit tests in `src/scanning/stage-trigger.test.ts`, `src/scanning/bec-config.test.ts`,
`src/scanning/engines/bec/*.test.ts` (including the shared-list contract with
`@email-gateway/security-contracts`); package integration `integration/bec-scan.test.ts` (real
Rspamd auth results through dns-sink, url engine on url-test, fake LLM, history, suppressions,
trust, budgets, wrong-read guard) and `integration/bec-stage.test.ts` (the trigger end to end on a
throwaway vhost).

## DLP engine (step 4.5)

Design [13-dlp.md](../../docs/plan/steps/13-dlp.md) (decision ids D*n*), runbook
[dlp.md](../../docs/runbooks/dlp.md), deployment [dlp.md](../../docs/deployment/dlp.md), performance
[dlp.md](../../docs/performance/dlp.md). Detectors, context scoring, dictionaries, tenant patterns
(re2js), classification, policy evaluation, masking, evidence build/seal and the format extractors
live in [`@email-gateway/dlp`](../../packages/dlp); this worker wires them. Code:
`src/scanning/engines/dlp/`, `src/scanning/dlp-config.ts`. A **stage-1, required** engine on
`scan.dlp` (ledger consumer `email-worker.scan.dlp`); outbound/internal always, inbound only with
the tenant's `inboundEnabled` (else `skipped`, `dlp.not_inbound`). Engine outcome = DLP verdict
(`clean` / `unknown` / `suspicious` / `skipped`, never `malicious`); the policy action is in
`scan_engine_results.action` and `dlp_scan_results.action`.

| File                      | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `registration.ts`         | `dlpRegistration` (after `becRegistration`; budget `SCAN_DLP_*`, `settingsFor` = `resolveDlpSettings`, invalid row → platform), `createDlpEngine` (store, part reader, extractor pool, byte budget `DLP_BYTE_BUDGET_BYTES`, S3 evidence objects, evidence KEK, engine version, `dlp_extractor_info`), `dlpLimitsFromConfig` (the 4.2 archive limits for the shared walker)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `dlp.engine.ts`           | The adapter (D3): direction rule; echo-checked loads; bodies (`readPrefix` above `DLP_BODY_MAX_BYTES`, full reads SHA-256-checked); attachments read as `DLP_MAX_ATTACHMENTS + 1`, `not_stored` / `oversize` / `attachment_cap` decided without a child, the rest through the extractor pool, up to `DLP_EXTRACTOR_POOL_SIZE` at a time per message (results applied in part order; the first failure aborts the rest); `detect()` under `DLP_DETECT_TIMEOUT_MS` of its own work (`WorkClock`, paused while it yields the loop); custom patterns re-validated at tenant load without the wall-clock cost probe and compiled once per row version (`CompiledPatternCache`); coverage-only incidents (no category, partial coverage); classification, coverage, `evaluateDlpPolicy` (tenant active domains, `rcptTruncated`); stored JSON validated with the security-contracts view schemas; evidence build + seal + `PutObject` before finalize; the incident payload; readiness `dlp-engine` and `dlp-extractor` |
| `dlp-store.ts`            | `PrismaDlpStore`: message (direction echo, recipient count), parse row, attachment rows, tenant data (LRU ≤ 1 000 organizations, `DLP_TENANT_DATA_CACHE_TTL_MS`: enabled policies + rules, unexpired exceptions, patterns compiled once, dictionaries in one trie, compliance row, active domains); every read echo-checked (`InconsistentDlpReadError` → `inconsistent_read`); snapshot ids are **public ids**, internal policy/rule ids kept beside them; `aadhaarEnabled` (D17)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `extractor/child.ts`      | The DLP extractor child (D4): the 4.2 walker (`inspectBytes` with `NOOP_YARA_ENGINE` and the `ExtractionSession` visitor) + `@email-gateway/dlp/extract`; loads pdfjs before its handshake (`ready`, `kind: dlp-extractor`); selftest hooks only with `EG_INSPECTOR_SELFTEST=1`; unreadable documents → definite `parse_error`. Module graph: no `child_process`, no bec, no AI SDK (`child-graph.test.ts`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `extractor/pool.ts`       | `DlpExtractorPool` = `ChildPool` with `extractorDescriptor` (entry, handshake with the extractor version, bounded `extraction` reply; isolation, prlimit, CPU/RSS sampling, wall clock, recycling of the 4.2 pool)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `extractor/extraction.ts` | Job limits (`{ walk, extract }`), `walkSummaryOf` (4.2 inspection → walk summary), the bounded reply schema, `notExtracted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `evidence-objects.ts`     | Evidence object keys (`org/<org>/dlp-evidence/<yyyy>/<mm>/<scanId>-<uuidv7>.bin`), S3 put/delete, `deleteUncommittedEvidence` (orphan of a lost finalize)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `evidence-sweeper.ts`     | `DlpEvidenceSweeper` (D16): leader lock `scan:dlp-evidence`, crypto-shred expired rows in batches of 500 (`SCAN_DB_TIMEOUT_MS` transactions), delete objects, clear `object_key` after a successful delete, `dlp_evidence_expired_unpurged`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `dlp-metrics.ts`          | The D22 series (bounded labels only)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

`EngineChildRows.dlp { result, evidence, incident }`: `ScanRepository.insertFinal` writes the
`dlp_scan_results` row, the `dlp_evidence` row (key under the organization's evidence prefix, else
`dlp_evidence_key_invalid`) and the `mail.message.dlp_incident.v1` outbox row (validated, else
`dlp_incident_payload_invalid`; none when the message row is gone) in the final row's transaction,
only when the final row was inserted. When the final was not inserted (a duplicate finalizer or a
ledger duplicate) or the transaction threw, `ScanRepository.finalize` calls the
`dlpEvidenceUncommitted` hook, which deletes the evidence object (`dlp_evidence_writes_total{result="orphan_deleted"|"orphan_left"}`).

**Configuration** (`.env.example` section "Data loss prevention (step 4.5)"; validated by
`scanning/dlp-config.ts`): `SCAN_ENGINES` default `rspamd,attachment,url,bec,dlp`, `SCAN_DLP_*`
(attempts < 10; the deadline rule includes dlp as stage 1), the extractor pool and limits
(`DLP_EXTRACTOR_RLIMITS=best_effort` refused with NODE_ENV=production), attachment/text/detection
bounds, the platform settings through `dlpPlatformSettingsSchema` (errors name the env key),
`DLP_ATTACHMENT_MAX_BYTES` ≤ `DLP_BYTE_BUDGET_BYTES`, `DLP_EVIDENCE_KEY` (exactly 64 hex where dlp
consumes with evidence enabled; never echoed) and `DLP_EVIDENCE_KEY_PREVIOUS` (empty or 64 hex,
different).

**Tests:** unit tests in `src/scanning/dlp-config.test.ts` and `src/scanning/engines/dlp/*.test.ts`
(engine on the synthetic corpus with an in-process extractor, a captured-log test that no value or
masked sample is logged, store echo checks, sweeper, registration, the Prisma-enum and reason-code
contract tests, extractor pool with a fake spawn, the extractor child's module graph); package
integration `integration/dlp-scan.test.ts` (real MySQL writer, MinIO and extractor children:
masked rows, encrypted evidence, rule action and incident, exception, idempotent duplicates with
orphan deletion, rescan, not-extracted codes, a selftest CPU kill, Aadhaar gating, the sweeper, a
forged read). Benchmark: `pnpm --filter @email-gateway/email-worker bench:dlp`.

## Message lifecycle (step 3.3 L8.2)

The MIME stage **does not change the message lifecycle state** (the scan stage does, through
the transition service: E3, E6, E7 above)
([08-message-lifecycle.md](../../docs/plan/steps/08-message-lifecycle.md) L2 and L8.2,
[ADR-0025](../../docs/architecture/adr/0025-message-lifecycle-state-machine.md)). The SMTP
commit creates every message `persisted` (version 1), and the parse runs **within**
`persisted`: it is a preparatory stage whose record is `email_message_parses` (its own stage
table), not a lifecycle state, and the finalize transaction never writes `status`,
`status_changed_at`, `version`, `lifecycle_round`, `status_reason` or
`email_message_status_history` (one-door rule: only `@email-gateway/message-lifecycle` writes
them). The consumers of the parse outcome own the next transition: `mail.message.parsed.v1` →
the scan orchestration of step 4.1 moves `persisted → scanning`;
`mail.message.parse_failed.v1` → the policy engine of step 5.2 moves
`persisted → policy_evaluated` with its fail-safe. A parse state would be a sixteenth state or a
fake producer of `scanning`/`scan_failed`. The lifecycle read API shows the parse outcome next to
the state.

## Transport (step 3.2 Q13)

`AmqpModule` (`@email-gateway/common`) holds one connection (reconnects with backoff, never
exits the process) and a confirm publisher; `createMimeConsumer` builds the stage's
`QueueConsumer`:

- queue `email.received` (work policy), accepted type `mail.message.received.v1` only (any other
  type, schema version, an invalid payload or a tenant mismatch between routing key, header and
  envelope is dead-lettered at once), consumer `email-worker.mime-parser` (the ledger name is
  unchanged, so events handled by the 3.1 poller are ledger duplicates);
- prefetch = `MIME_CONCURRENCY`: at most that many deliveries are unacknowledged per replica,
  which is also the parse memory bound; replicas are competing consumers;
- manual ack after `MimeIngestionService.handle` returned (`handled` or `duplicate`);
- a failed attempt is classified with the stage's own transient check (`classifyMimeFailure`):
  an S3, MySQL or network outage is **transient** (the stage gave the parse attempt back; the
  consumer holds the delivery for the backoff `MIME_RETRY_BASE_MS`..`MIME_RETRY_MAX_MS`, then
  republishes a copy to the queue's tail and acks the original, without consuming a queue
  attempt; dead-lettered only after the 24 h retry age); anything else is **retryable**
  (`x-eg-attempt + 1`). `MIME_MAX_ATTEMPTS` is below the queue's limit of 8, so the stage's poison
  guard finalizes `parse_failed / max_attempts_exceeded` first and a received message always
  ends with a parse row, not a dead letter;
- a held delivery keeps its prefetch slot: during an outage consumption pauses (backpressure)
  instead of spinning. On shutdown held deliveries are requeued.

There is **no outbox poller fallback** any more (design Q14): the `ShardedOutboxFeed`, its
cursors (`outbox:email-worker.mime-parser[#i/n]`), locks (`ew:outbox:*`) and the `MIME_OUTBOX_*`
keys were removed. During a broker outage received events stay in `message_outbox` (unpublished)
and the event-relay publishes them when the broker is back; a published event whose parse never
happened is re-driven by the event-relay's reconciler. The consumer records every confirmed
retry hop (`retrying`) and dead-letter copy (`dead_lettered`) in `message_consumer_progress`
(best effort, bounded wait), so the reconciler never re-drives an event that is still retrying
or was dead-lettered on purpose (step 3.2 review round 1). Old `outbox:email-worker.mime-parser*`
rows in `stream_cursors` are no longer read and can be deleted.

Dead letters land in `email.dead-letter` (headers `x-eg-source-queue`, `x-eg-failure-reason`,
...) and are replayed through the api (`POST /api/v1/platform/dead-letters/replay`); a replayed
event that was already parsed is a ledger duplicate.

## Configuration

Every key, with its default, is in [`.env.example`](../../.env.example) under "MIME ingestion
(step 3.1)" and is validated in `src/config.ts`. Startup refuses:

- `MIME_MAX_ATTACHMENT_BYTES` or `MIME_MAX_BODY_BYTES` above `MIME_MAX_MESSAGE_BYTES`;
- `MIME_MAX_HEADER_LINE_BYTES` above `MIME_MAX_HEADER_BLOCK_BYTES`;
- `MIME_MAX_DECODED_RATIO` below 1;
- `MIME_MAX_DEPTH` outside 1–50, `MIME_MAX_PARTS` outside 2–1000, or `MIME_MAX_ATTACHMENTS`
  above `MIME_MAX_PARTS`;
- a `MIME_MAX_DEPTH` and `MIME_MAX_PARTS` whose longest `part_path`
  (`1 + MIME_MAX_DEPTH × (1 + digits(MIME_MAX_PARTS - 1))`) exceeds the 128 characters of
  `email_attachments.part_path` (for example depth 32 with 1000 parts). The parser also stops as
  `nesting_depth` before a path longer than 128 characters;
- `MIME_MAX_STORED_HEADERS` outside 1–500, or `MIME_FILENAME_MAX_CHARS` outside 16–240;
- `MIME_RETRY_MAX_MS` below `MIME_RETRY_BASE_MS` or above 60 000 (the `hold` retry keeps the
  prefetch slot);
- `MIME_MAX_ATTEMPTS` at or above 8, the attempt limit of `email.received`;
- `MIME_S3_TIMEOUT_MS` not below `MIME_PARSE_TIMEOUT_MS` (a stalled S3 call must fail as a
  retry before the parse budget runs out);
- `MIME_CONCURRENCY × (MIME_S3_PART_SIZE_BYTES × (MIME_S3_QUEUE_SIZE + 1) +
MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES)` above `MIME_MEMORY_BUDGET_BYTES` (the consumer runs
  at most `MIME_CONCURRENCY` parses; defaults: 4 × 23 MiB = 92 MiB of 256 MiB);
- `MIME_S3_PART_SIZE_BYTES` below 5 MiB.

`MIME_INGESTION_ENABLED=false` leaves the stage out (the `email-worker-scan` Deployment). The
worker also reads `DATABASE_URL`, `S3_*`, `REDIS_URL`, `RABBITMQ_EMAIL_WORKER_URL` (required with
the MIME role;
comma-separated node URLs, `_FILE` supported; `RABBITMQ_URL` and `RABBITMQ_PREFETCH` are no longer
read) and the base keys. The Compose
service passes every `MIME_*` key as `${KEY:-default}`, and `infrastructure/kubernetes/base/email-worker.yaml`
sets the defaults.

Scan role (`.env.example` section "Security scanning (step 4.1)", validated in
`src/scanning/config.ts`): `SCAN_ENABLED`, `SCAN_ENGINES` (validated against the engine catalog),
`RABBITMQ_SCANNER_URL` (required with the scan role; `_FILE` supported), `SCAN_RSPAMD_URL`
(required with the rspamd engine), `RSPAMD_CONTROLLER_URL` / `RSPAMD_CONTROLLER_PASSWORD` (read
password, optional, `_FILE` supported), `SCAN_RSPAMD_CONCURRENCY` (prefetch, ≤ 64),
`SCAN_RSPAMD_TIMEOUT_MS`, `SCAN_RSPAMD_MAX_ATTEMPTS`, `SCAN_RSPAMD_MAX_BYTES`, `SCAN_RETRY_*`,
`SCAN_S3_TIMEOUT_MS`, `SCAN_DB_TIMEOUT_MS`, `SCAN_ROUND_DEADLINE_SECONDS`, `SCAN_SWEEP_*`,
`SCAN_BREAKER_*`, `SCAN_SETTINGS_CACHE_TTL_MS` (0 disables the cache), `SCAN_ENGINE_VERSION_TTL_MS`
and the platform thresholds `SCAN_RSPAMD_*` (S8, shared with the api). Startup refuses:

- both roles disabled; the MIME role without `RABBITMQ_EMAIL_WORKER_URL`; the scan role without
  `RABBITMQ_SCANNER_URL` or (rspamd enabled) `SCAN_RSPAMD_URL`;
- an unknown, duplicate or empty `SCAN_ENGINES`;
- `SCAN_RSPAMD_MAX_ATTEMPTS` at or above 10, the attempt limit of `scan.spam`;
- `SCAN_RETRY_MAX_MS` above 60 000 or below `SCAN_RETRY_BASE_MS`;
- `SCAN_ROUND_DEADLINE_SECONDS` below `SCAN_RSPAMD_MAX_ATTEMPTS × (SCAN_RSPAMD_TIMEOUT_MS +
SCAN_RETRY_MAX_MS) / 1000` (480 s with the defaults) or above 6 hours;
- platform thresholds that `rspamdPlatformSettingsSchema` refuses (`0 < MIN < MAX ≤ 100`,
  `MIN ≤ SUSPICIOUS < SPAM ≤ MAX`, two decimals, the allowed verdict values);
- a breaker window below 10 calls, a ratio outside (0, 1], a settings TTL above 300 000.

## Metrics (design M16)

| Series                                                            | Meaning                                                                                                    |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `mime_parse_messages_total{status}`                               | `parsed`, `parsed_with_defects`, `parse_limit_exceeded`, `parse_failed`, `duplicate` and `message_missing` |
| `mime_parse_duration_seconds`                                     | Download to commit                                                                                         |
| `mime_parse_bytes_total`                                          | EML bytes read                                                                                             |
| `mime_limit_exceeded_total{limit}` / `mime_defects_total{defect}` | Per code                                                                                                   |
| `mime_parse_failures_total{reason}`                               | `parse_failed` reasons                                                                                     |
| `mime_attachments_total` / `mime_attachment_flags_total{flag}`    | Attachment rows and their flags                                                                            |
| `mime_retries_total{class}`                                       | Failed attempts by dependency (`s3`, `db`, `other`); the log line says whether it was transient            |

The 3.1 `mime_outbox_poll_lag_seconds` and `mime_outbox_invalid_total` series were removed with
the poller. The transport reports the shared step 3.2 §5.3 series: `amqp_connection_up` /
`_blocked` / `amqp_reconnects_total{connection="email-worker"}`,
`amqp_consumer_{deliveries,messages,retries,dead_lettered}_total`,
`amqp_consumer_handle_seconds`, `amqp_consumer_in_flight` and `amqp_consumer_active`
(`queue="email.received"`), and `amqp_publish_*` for retry and dead-letter copies.

### Scan stage metrics (step 4.1 S17)

A contract for `infrastructure/monitoring/rules/scanning.rules.yml`; labels are bounded enums.

| Series                                                                                  | Labels                            | Meaning                                                                                                     |
| --------------------------------------------------------------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `scan_engine_results_total`                                                             | `engine`, `outcome`, `final`      | Results recorded (`final="false"`: a failed attempt that is retried)                                        |
| `scan_engine_duration_seconds`                                                          | `engine`, `outcome`               | One engine call (0.05 … 60 s)                                                                               |
| `scan_engine_failures_total`                                                            | `engine`, `reason`                | `timeout`, `error`, `protocol_error`, `circuit_open`, `soft_reject`, `eml_unavailable`, `deadline_exceeded` |
| `scan_engine_circuit_state`                                                             | `engine`                          | 0 closed, 1 half-open, 2 open                                                                               |
| `scan_engine_circuit_transitions_total`                                                 | `engine`, `to`                    | Breaker transitions                                                                                         |
| `scan_rounds_completed_total`                                                           | `outcome`, `verdict`, `scan_kind` | Verdict distribution of completed rounds                                                                    |
| `scan_round_duration_seconds`                                                           | `outcome`                         | Round opening → completion                                                                                  |
| `scan_event_lag_seconds`                                                                | `engine`                          | now − trigger `occurredAt` at handling start (queue lag)                                                    |
| `scan_events_skipped_total`                                                             | `engine`, `reason`                | `message_not_found`, `older_round`, `lifecycle_<state>`, `already_final`, `duplicate`                       |
| `scan_rounds_superseded_total` / `scan_deadline_finalized_total`                        | `engine`                          | Superseded completions / deadline finalizations                                                             |
| `scan_settings_cache_total` / `scan_settings_invalid_total`                             | `result` / `engine`               | Settings cache hits and misses / invalid tenant rows                                                        |
| `scan_engine_info`                                                                      | `engine`, `version`               | Engine version in use (1)                                                                                   |
| `scan_deadline_sweeper_errors_total`                                                    | —                                 | Database errors of the sweeper                                                                              |
| `lifecycle_transitions_total` (+ `_ignored_total`, `lifecycle_version_conflicts_total`) | `from`, `to`, `result`            | The transition service's series for E3/E6/E7                                                                |

The scan consumer reports the shared `amqp_*` series with `queue="scan.spam"` and
`connection="email-worker-scanner"`.

## Running on the host

Infrastructure runs in Docker Compose. If the `email-worker` container is running, stop or pause
it first, or set another `HTTP_PORT`:

```bash
pnpm --filter @email-gateway/email-worker dev    # reads ../../.env; HTTP_PORT=3021 to avoid a clash
curl -s http://127.0.0.1:3020/health/ready
curl -s http://127.0.0.1:3020/metrics | grep -E '^(mime|scan)_'
```

With the scan role the host process also connects as `eg-scanner` (`RABBITMQ_SCANNER_URL`) and
scans with the Rspamd of Compose (`SCAN_RSPAMD_URL=http://127.0.0.1:${RSPAMD_HOST_PORT}`). The
dev pass-through approves only scanned messages (step 4.1 S15: E27 `scanned → approved` on
`mail.message.scanned.v1`, never a `scan_failed` one), so run a delivery-worker built from this
tree: a delivery-worker image from before step 4.1 still applies the retired E4
(`persisted → approved`) and approves a message before its scan opens; the scan is then skipped
(`scan_events_skipped_total{reason="lifecycle_approved"}`).

The host process connects with `RABBITMQ_EMAIL_WORKER_URL` from `.env` (the role user on vhost
`email-gateway`, provisioned by `pnpm rabbitmq:init`). It consumes whatever the event-relay has
published to `email.received`.

## Tests

```bash
pnpm --filter @email-gateway/email-worker test               # unit tests (no infrastructure)
pnpm --filter @email-gateway/email-worker test:integration   # real MySQL writer, MinIO, RabbitMQ (from .env)
```

- **Unit tests** (`src/**/*.test.ts`) cover:
  - the config refusals (including `MIME_MAX_ATTEMPTS` and the 60 s hold limit) and the key
    builder;
  - the S3 sink against an in-memory S3 HTTP handler: object headers, abort of single-part and
    multipart uploads, failure and cleanup;
  - every branch of the M3 flow with fakes, and the payload schemas;
  - the scan stage: the Rspamd mapping (R0–R10, precedence, tenant overrides), the adapter with
    a fake client, aggregation, the circuit breaker (injected clock), the settings resolver
    (cache, TTL, LRU, invalid rows), the round service and the sweeper with a fake store, the
    scan config refusals, and the equality of the verdict literals of event-contracts and
    security-contracts;
  - equality of the `MIME_LIMIT_NAMES` lists in mime-parser and event-contracts;
  - the log-redaction marker test;
  - the Nest wiring and readiness checks, and that the `email.received` consumer gets the queue,
    event type, prefetch, retry overrides and classifier of Q13.
- **Integration tests** (`integration/`, `vitest.integration.config.ts`) run against the real
  MySQL writer, MinIO and RabbitMQ. Each suite creates a throwaway vhost `eg-it-<hex>` with the
  full topology (`infrastructure/rabbitmq/init.mjs --vhost`, deleted afterwards), publishes the
  received events exactly as the event-relay does (registry exchange, `org.<id>.<type>`, Q2
  headers, confirmed) and runs the stage with the production factories. Their `it-mime-<run>-*` fixture organizations, the per-run consumers,
  ledger rows, cursors and the org S3 prefixes are removed afterwards. The `globalSetup` pauses a
  live email-worker (the container, or a host process on `EMAIL_WORKER_HOST_PORT`). Fixture
  recipients are `discarded`, so a running delivery-worker dev pass-through plans no delivery for
  them. The suites cover:
  - the mime-parser corpus end to end, with the SHA-256 of every downloaded object checked
    against its row;
  - a multipart message with RFC 2047 and RFC 2231 names;
  - a zip bomb and nested archives (generated with yazl);
  - a 53 MB message streamed with live memory growth below 32 MiB;
  - the size, attachment and body limits, and `eml_missing`, `eml_key_mismatch` and
    `integrity_mismatch`;
  - an S3 outage (transient hold retries, attempts not consumed, no dead letter), a deterministic
    failure ending through the poison guard, the poison guard after a crash loop and a
    cross-tenant envelope;
  - duplicate delivery: the same envelope twice (sequentially and at once with prefetch 4), two
    competing consumers with different events, a second event id and a redelivery to a fresh
    consumer;
  - consumer crash: the consumer in a child process (vite-node) SIGKILLed before the finalize
    commit and, separately, after the commit before the ack: redelivered, one parse row, one
    ledger row;
  - a MySQL outage through an in-process TCP proxy: transient holds, no dead letter, recovery
    with one attempt;
  - a backlog of 2000 events with prefetch 4: the management API never reports more than 4
    unacknowledged messages, all 2000 are processed.
- **Scan integration suites** (`integration/scan-*.test.ts`) run the scan stage with the
  production factories against the real Rspamd (test RBL profile, dns-sink `scan.test` zones),
  MySQL writer, MinIO, Redis and a throwaway vhost, in `it-scan-<run>-*` organizations with
  per-run consumer names:
  - `scan-corpus`: every fixture of `tests/fixtures/scan-corpus/manifest.json` → the manifest
    verdict, reason codes, symbols, score range and auth row, a schema-valid `scanned.v1` outbox
    row without symbol options, and the history `persisted → scanning → scanned`; per-tenant
    thresholds changing the verdict of the same message; an invalid tenant row falling back to
    the platform settings; Rspamd reputation keys in Redis DB `RSPAMD_REDIS_DB` with TTLs;
  - `scan-resilience`: Rspamd unreachable (error attempts, final error, `scan_failed`), hanging
    (timeout attempts, `scan_timeout`), the breaker opening and failing fast without calls,
    recovery within the budget (`scanned` with a real result), a missing EML
    (`eml_unavailable` at once), the deadline sweeper finalizing a round whose engine never
    reports;
  - `scan-rounds`: the same event twice and three event ids at once (one final row, one
    transition), a rescan (new round, old rows unchanged, a late round-0 trigger skipped), Bayes
    learning with per-run tokens (`BAYES_SPAM`, higher score), fuzzy add/delete (`fuzzy.spam` and
    back).
  - Since step 4.2 these pipelines run with `SCAN_ENGINES=rspamd` (rounds require Rspamd only);
    the attachment engine has its own suites.
- **Attachment unit tests** (`src/scanning/engines/attachment/**/*.test.ts`): file-type
  detection (every magic type, PE `e_lfanew`, OOXML/macro/ODF/jar/apk sub-typing, MSI, ISO,
  scripts by extension), the archive walker over the generated corpus (zip/gzip/tar/tgz, depth,
  entry count, entry size, decompressed total, ratio bombs stopped early, every encryption
  marker, malformed/truncated/CRC/bad tar checksum, traversal, overlap, unsupported formats,
  OOXML parts scanned by YARA, ≤ 20 findings, no entry names), the verdict mapper (every rule
  M1–C1, A0, E1, ordering, tenant deny/allow/raise-only), the cache (key, content version, TTLs,
  too large, Redis errors/timeouts bypass), the byte budget, the inspector pool with a fake child
  (environment, prlimit arguments, 0700 cwd, bundle mismatch, wait queue, recycling, CPU/memory/
  wall/crash/SIGXCPU/heap classification, abort, stale directories), the samplers, the bundle id
  equal to `yara/bundle.mjs --check`, the child's module graph (no `child_process`, no fs
  writes), the engine adapter with fakes (every failure mapping, cache hit/miss/version change,
  sandbox selection, metrics), the registration, the watcher with an in-memory writer, the
  rescan payload contract, and the AppModule wiring of the attachment consumer (real children).
- **Attachment integration suites** (`integration/attachment-*.test.ts`, real clamd, MySQL
  writer, MinIO, Redis; `it-scan-<run>-*` organizations):
  - `attachment-scan`: EICAR plain/zip/nested/past the depth limit/gzip/tar → malicious; clean
    archives; 7z/rar → unknown; zip bomb; encrypted, malformed and truncated archives; a
    truncated PDF; large attachments near and above the limits and not stored; a disguised
    executable and tenant deny/allow/raise; known-bad hashes added and removed, an inner hash;
    YARA test rules; cache hit without a clamd call and a miss after a simulated database
    update; no attachments (`skipped`); an incomplete parse; schema-valid rows without names;
    sandbox rows and their outbox events; duplicates (one set of rows, one submission, one
    event); missing and corrupt part objects;
  - `attachment-resilience`: clamd unreachable (closed port: attempts, breaker open,
    `scan_failed`, never clean), recovery, and the inspector's CPU, memory, wall-clock and crash
    kills with real children (`selftest`); the `prlimit` variant runs on Linux only (skipped on
    the macOS host). The Linux production path (`prlimit` + the `/proc` sampler) is covered in
    the container by the stack suite `tests/integration/attachment-inspector-container.test.ts`;
  - `attachment-rescan`: an admin job and a watcher-detected signature change executed by the
    runner (batches, window, states, malicious and attachment-less messages skipped, counts,
    cursor, `max_messages`, cancellation), the requested rescans completing new rounds.
