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
`scan.*` and `email.policy.evaluate` queues). Security engine orchestration (Rspamd, ClamAV,
YARA, URL, BEC, DLP) follows in step 4.x.

Data plane: the MySQL **writer** only (ADR-0014, no `PrismaReadService`), S3 (`S3_BUCKET_MAIL`)
and RabbitMQ with the worker's own least-privilege user (`RABBITMQ_EMAIL_WORKER_URL`: read
`email.received`, write `email.ingestion` and `email.events` for retry and dead-letter copies;
it cannot configure anything or reach `email.delivery`). Redis stays connected and in readiness
as in phase 0, but the parse path does not use it. Health is `GET /health/live` and
`GET /health/ready` (checks `mysql`, `rabbitmq`, `redis`, `s3`; `rabbitmq` = connected, not
blocked by a resource alarm, `email.ingestion`, `email.events` and `email.received` verified
passively). Metrics are on `GET /metrics`. The default port is 3020.

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

The components are plain classes wired in the module, so the integration tests build the same
graph without Nest (`createMimeIngestionService`, `createMimeConsumer`).

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

`MIME_INGESTION_ENABLED=false` leaves the stage out (scanning-only replicas in later steps). The
worker also reads `DATABASE_URL`, `S3_*`, `REDIS_URL`, `RABBITMQ_EMAIL_WORKER_URL` (required;
comma-separated node URLs, `_FILE` supported; `RABBITMQ_URL` and `RABBITMQ_PREFETCH` are no longer
read) and the base keys. The Compose
service passes every `MIME_*` key as `${KEY:-default}`, and `infrastructure/kubernetes/base/email-worker.yaml`
sets the defaults.

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

## Running on the host

Infrastructure runs in Docker Compose. If the `email-worker` container is running, stop or pause
it first, or set another `HTTP_PORT`:

```bash
pnpm --filter @email-gateway/email-worker dev    # reads ../../.env; HTTP_PORT=3021 to avoid a clash
curl -s http://127.0.0.1:3020/health/ready
curl -s http://127.0.0.1:3020/metrics | grep '^mime_'
```

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
