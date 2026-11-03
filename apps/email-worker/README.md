# @email-gateway/email-worker

Email Processing Service. Since step 3.1 it runs the **post-queue MIME ingestion stage**
(design [06-mime-ingestion.md](../../docs/plan/steps/06-mime-ingestion.md),
[ADR-0022](../../docs/architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md)). For each
`mail.message.received.v1` it streams the stored EML from S3 and parses it with
[`@email-gateway/mime-parser`](../../packages/mime-parser/README.md). Bodies and attachments
are streamed to S3, and one writer transaction records the parse metadata, an `email_events`
row and a `mail.message.parsed.v1` or `mail.message.parse_failed.v1` outbox event. The events
are **written** to `message_outbox` only: nothing publishes them to RabbitMQ or consumes them
yet (the relay that sets `published_at` is step 3.2). Security engine orchestration (Rspamd, ClamAV, YARA, URL, BEC, DLP) follows in step 4.x.

Data plane: the MySQL **writer** only (ADR-0014, no `PrismaReadService`) and S3 (`S3_BUCKET_MAIL`).
RabbitMQ (`QUEUES.emailProcessing` is asserted) and Redis stay connected and in readiness as in
phase 0, but the parse path uses neither of them. Health is `GET /health/live` and
`GET /health/ready` (checks `mysql`, `rabbitmq`, `redis`, `s3`). Metrics are on `GET /metrics`.
The default port is 3020.

## Modules

| Path                                           | Responsibility                                                                                                                                                                                                              |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/config.ts`                                | zod config, including every `MIME_*` key of design §5 and the M5 cross-field refusals (`validateMimeConfig`)                                                                                                                |
| `src/mime-ingestion/limits.ts`                 | config → `MimeLimits`                                                                                                                                                                                                       |
| `src/mime-ingestion/part-keys.ts`              | deterministic part keys `org/{org}/part/{yyyy}/{mm}/{dd}/{messageId}/{partIndex}.{text\|html\|att}` (UTC date of `received_at`) and the organization-prefix check                                                           |
| `src/mime-ingestion/s3-part-sink.ts`           | the parser's `PartSink`: one `@aws-sdk/lib-storage` `Upload` per part, ranged `GetObject` for the zip inspector, abort without an object, cleanup of this attempt's objects                                                 |
| `src/mime-ingestion/eml-source.ts`             | streaming `GetObject` of `email_messages.eml_object_key`. `NoSuchKey` → `eml_missing`, anything else is an infrastructure error                                                                                             |
| `src/mime-ingestion/mime-repository.ts`        | writer persistence: ledger, message and parse row reads, `markParsing`, attempt decrement, and the finalize transaction                                                                                                     |
| `src/mime-ingestion/mime-ingestion.service.ts` | `MimeIngestionService.handle(event)`: the M3 flow                                                                                                                                                                           |
| `src/mime-ingestion/payloads.ts`               | the event payloads, validated with `messageParsedV1` and `messageParseFailedV1` before insert                                                                                                                               |
| `src/mime-ingestion/mime-metrics.ts`           | the M16 series and the outbox-feed adapter                                                                                                                                                                                  |
| `src/mime-ingestion/mime-ingestion.module.ts`  | `MimeIngestionModule.forRoot(config, logger)`: the `ShardedOutboxFeed`, the service and `MimeIngestionRuntime` (starts after bootstrap, stops before the database closes). Imported only when `MIME_INGESTION_ENABLED=true` |

The components are plain classes wired in the module, so the integration tests build the same
graph without Nest (`createMimeIngestionService`, `createMimeFeed`).

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

## Transport and cursors

Until step 3.2 adds the RabbitMQ relay, events come from the shared outbox feed of
`@email-gateway/common` (design M2). Step 3.2 replaces the feed with a competing consumer on
`email-worker.message-received`, and the handler stays the same. The feed settings are:

- consumer `email-worker.mime-parser`, event `mail.message.received.v1`, initial position `oldest`
  (every received message is parsed, and re-reads cost nothing);
- `MIME_OUTBOX_SHARDS = n`. With `n = 1`, the cursor is `stream_cursors.name =
'outbox:email-worker.mime-parser'` and the lock is `GET_LOCK('ew:outbox:email-worker.mime-parser')`.
  With `n > 1`, each shard `i` reads `MOD(id, n) = i` under the cursor
  `outbox:email-worker.mime-parser#i/n` and the lock `ew:outbox:email-worker.mime-parser#i/n`;
- `MIME_OUTBOX_MAX_HELD_SHARDS` limits the shard locks one replica holds, so replicas spread the
  shards. Replicas without a lock idle. Every shard needs a runner: run at least
  `MIME_OUTBOX_SHARDS / MIME_OUTBOX_MAX_HELD_SHARDS` replicas. A shard nobody runs is not
  silent: each poller that does not hold its shard reports that shard's lag from its durable
  cursor (at most every 10 s), so `mime_outbox_poll_lag_seconds` grows;
- `MIME_CONCURRENCY` sets the rows of a page handled at the same time. The cursor still advances
  in id order, and only past rows older than `MIME_OUTBOX_SAFETY_LAG_MS`.

**Changing the shard count** creates new cursors, which start at the minimum of the consumer's
existing cursors: rows are re-read, never skipped, and the ledger and parse rows make the re-read
free. Old cursors are left in place. Delete them once the new layout runs:

```sql
DELETE FROM stream_cursors
WHERE name = 'outbox:email-worker.mime-parser' OR name LIKE 'outbox:email-worker.mime-parser#%/<old n>';
```

**Resetting** (re-reading from the oldest retained outbox row): stop every email-worker, delete
all of the consumer's cursors (`name = 'outbox:email-worker.mime-parser' OR name LIKE
'outbox:email-worker.mime-parser#%'`) and start again. Messages with a final parse row are
skipped as duplicates. A reset never re-parses a message: re-parsing is out of scope for step 3.1.

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
- `MIME_OUTBOX_SAFETY_LAG_MS` below 30 000;
- `MIME_OUTBOX_MAX_HELD_SHARDS` above `MIME_OUTBOX_SHARDS`, or `MIME_RETRY_MAX_MS` below
  `MIME_RETRY_BASE_MS`;
- `MIME_S3_TIMEOUT_MS` not below `MIME_PARSE_TIMEOUT_MS` (a stalled S3 call must fail as a
  retry before the parse budget runs out);
- `MIME_CONCURRENCY × MIME_OUTBOX_MAX_HELD_SHARDS × (MIME_S3_PART_SIZE_BYTES ×
(MIME_S3_QUEUE_SIZE + 1) + MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES)` above
  `MIME_MEMORY_BUDGET_BYTES` (every held shard runs its own `MIME_CONCURRENCY` parses; defaults:
  4 × 1 × 23 MiB = 92 MiB of 256 MiB);
- `MIME_S3_PART_SIZE_BYTES` below 5 MiB.

`MIME_INGESTION_ENABLED=false` leaves the stage out (scanning-only replicas in later steps). The
worker also reads `DATABASE_URL`, `S3_*`, `REDIS_URL`, `RABBITMQ_*` and the base keys. The Compose
service passes every `MIME_*` key as `${KEY:-default}`, and `infrastructure/kubernetes/base/email-worker.yaml`
sets the defaults.

## Metrics (design M16)

| Series                                                                           | Meaning                                                                                                    |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `mime_parse_messages_total{status}`                                              | `parsed`, `parsed_with_defects`, `parse_limit_exceeded`, `parse_failed`, `duplicate` and `message_missing` |
| `mime_parse_duration_seconds`                                                    | Download to commit                                                                                         |
| `mime_parse_bytes_total`                                                         | EML bytes read                                                                                             |
| `mime_limit_exceeded_total{limit}` / `mime_defects_total{defect}`                | Per code                                                                                                   |
| `mime_parse_failures_total{reason}`                                              | `parse_failed` reasons                                                                                     |
| `mime_attachments_total` / `mime_attachment_flags_total{flag}`                   | Attachment rows and their flags                                                                            |
| `mime_retries_total{class}`                                                      | Failed attempts by dependency (`s3`, `db`, `other`); the log line says whether it was transient            |
| `mime_outbox_poll_lag_seconds{consumer}` / `mime_outbox_invalid_total{consumer}` | Outbox feed; the lag is the maximum over every shard, including shards no replica runs                     |

## Running on the host

Infrastructure runs in Docker Compose. If the `email-worker` container is running, stop or pause
it first, or set another `HTTP_PORT`:

```bash
pnpm --filter @email-gateway/email-worker dev    # reads ../../.env; HTTP_PORT=3021 to avoid a clash
curl -s http://127.0.0.1:3020/health/ready
curl -s http://127.0.0.1:3020/metrics | grep '^mime_'
```

On its first start the worker parses every retained `mail.message.received.v1` row (initial
position `oldest`).

## Tests

```bash
pnpm --filter @email-gateway/email-worker test               # unit tests (no infrastructure)
pnpm --filter @email-gateway/email-worker test:integration   # real MySQL writer, MinIO (from .env)
```

- **Unit tests** (`src/**/*.test.ts`) cover:
  - the config refusals and the key builder;
  - the S3 sink against an in-memory S3 HTTP handler: object headers, abort of single-part and
    multipart uploads, failure and cleanup;
  - every branch of the M3 flow with fakes, and the payload schemas;
  - equality of the `MIME_LIMIT_NAMES` lists in mime-parser and event-contracts;
  - the log-redaction marker test;
  - the Nest wiring and readiness checks.
- **Integration tests** (`integration/`, `vitest.integration.config.ts`) run against the real
  MySQL writer and MinIO. Their `it-mime-<run>-*` fixture organizations, the per-run consumers,
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
  - an S3 outage (retried, attempts not consumed), the poison guard and a cross-tenant envelope;
  - duplicate delivery: the same event twice, concurrent handles, two workers with different
    events, a second event id and a poller re-read;
  - the shared feed with 2 shards and concurrency 4 against the real outbox.
