# Step 3.1: MIME parser and email ingestion service (post-queue parsing)

Status: **implemented and verified locally (§12, 2026-11-03)**: WP1–WP5 done, full gate green, stack test and step 2.2/2.3 regressions passing with the email-worker running. Not complete: the commit is pending, and the items in §12.2 "Not verified" cannot be verified locally. Owner: principal architect. Decision record: [ADR-0022](../../architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md). It refines ADR-0002 (MIME placement) and ADR-0008 (part key layout) and supersedes no Accepted ADR.

This note is the single source of truth for the implementers of this step. It builds on step 2.2 ([04-smtp-gateway.md](04-smtp-gateway.md), commit `b793683`) and step 2.3 ([05-routing.md](05-routing.md), commit `6c6497c`). Their decisions stay in force unless a decision below names them. Each work package (WP1–WP5, §11) follows the decisions below. If a decision proves impossible, for example because a library behaves differently from what is assumed here, the implementer:

- documents the deviation in the docs their package owns and in their final report;
- picks the closest alternative that keeps the **invariants of §2.0**.

**Nobody silently changes a decision.** Section numbers (§) and decision ids (M*n*) are stable references.

---

## 1. Starting point (inspected)

| Area                       | Current state (commit `6c6497c`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Durable ingestion (2.2 D7) | smtp-adapter LMTP `:10050`/`:10051` streams the EML to S3 (`org/{organizationId}/eml/yyyy/mm/dd/{objectRef}.eml`, SHA-256 while streaming) and assigns the message id through `message_identities` (ingest key `v2:`…). It resolves the tenant from the trusted recipient domain (inbound) or the authenticated connector's sender domain (outbound) and splits per organization. Per organization it commits `email_messages` (`status = received`, raw `subject` with encoded-words left as-is, `header_from` address, `eml_object_key`, `eml_sha256`, `size_bytes`), `email_recipients`, one `email_events` `received` row and one `mail.message.received.v1` outbox row, all in one writer transaction before the `250`. **Requirements 1–3 of the brief are done at SMTP time; this step does not touch that path.**                                                                                                                                             |
| Events                     | `mail.message.received.v1` (`messageId`, `receivedAt`, `direction`, `emlS3Key`, `sizeBytes`, `envelopeFrom`, `recipientCount`), `mail.delivery.approved.v1`, `mail.delivery.status_changed.v1`, … in `packages/event-contracts/src/events.ts`. The envelope regex is `^[a-z]+(\.[a-z_]+)+\.v\d+$`. **No outbox relay** (3.2). `QUEUES.emailProcessing` = `email-worker.message-received` bound to `mail.message.received.v1` is asserted by email-worker but never fed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Outbox poller (2.3 R6)     | `apps/delivery-worker/src/approvals/outbox-poller.ts`: durable cursor `outbox:<consumer>` in `stream_cursors`, safety lag, an in-memory set of recent event ids, invalid rows skipped and counted, `processOnce` per row **inside** the transaction of the handler `(event, tx)`, rows handled **sequentially**, single active poller per consumer via `GET_LOCK('dw:outbox:<consumer>')` on the dedicated connection of `shared/advisory-locks.ts`. Behind `ApprovalFeed<T>` (`approval-feed.ts`). Helpers `shared/db.ts` (`withTransactionDefaults`, `isUniqueViolation`, `idString`) and `shared/uuidv7.ts`. Consumers: `delivery-worker.planner` (approvals, initial position `oldest`) and `delivery-worker.dev-passthrough` (received → approval, `latest`).                                                                                                                                                                                                    |
| email-worker               | Skeleton: writer Prisma, RabbitMQ (asserts `QUEUES.emailProcessing`), Redis, S3, health (`mysql`, `rabbitmq`, `redis`, `s3`), port 3020. No logic, no metrics, no integration tests. Compose service `email-worker` (apps profile).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Schema (1.1)               | Partitioned (monthly, `received_at`): `email_messages` (`attachment_count`, `subject` VARCHAR(998), `version`, `status` enum `received/scanning/…` with **no parse states**), `email_headers` (`seq`, `name` VARCHAR(128), `value` VARCHAR(2048); "allow-list of security-relevant headers only"; unique `(message_id, seq, received_at)`), `email_attachments` (`part_index`, `parent_part_index` "for files extracted from archives", `filename` VARCHAR(255), declared/detected content type, `size_bytes`, `sha256` NOT NULL, `object_key` NULL, `verdict`; unique `(message_id, part_index, received_at)`), `email_events` (append-only), `email_message_status_history`. Not partitioned: `message_outbox` (daily), `message_idempotency` (`processOnce`), `stream_cursors`. 70 tables, 18 partitioned (`PARTITION_REGISTRY`). No body or preview columns exist, **so no previews are added** (brief: "bounded previews only if the schema already allows it"). |
| Libraries in the lockfile  | `mailparser@3.9.46` (smtp-adapter, bounce DSN parsing) pins `@zone-eu/mailsplit@5.4.26`, `libmime@5.5.1`, `libqp@3.0.1`, `libbase64@1.4.1`, `iconv-lite@0.7.3`. `file-type@21` (transitive, ESM-only). No zip reader. Build: CommonJS, `moduleResolution: node10`. pnpm `minimumReleaseAge` 7 days.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Logger                     | pino with `REDACT_PATHS` (credentials, tokens, DKIM keys). Mail-content fields are not in the list. Step 2.2 rule: logs carry ids, never addresses beyond the domain at info level.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Tests                      | Stack suites in `tests/integration` (`smtp-*.test.ts`, `routing-*.test.ts`, gates `smtpStackGate`/`routingStackGate`, `swaks` from `smtp-tools`, `SmtpFixtures`). The delivery-worker integration harness (`apps/delivery-worker/integration`, `vitest.integration.config.ts`, `globalSetup` pauses a live worker).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

---

## 2. Decisions

### 2.0 Invariants (never traded away)

1. **The SMTP hot path is unchanged.** Nothing in smtp-adapter's LMTP ingestion moves or slows down. Parsing is post-queue.
2. **Content is untrusted.** No attachment or body is executed, rendered, opened (beyond magic-byte sniffing and the zip central directory) or converted to HTML or text. No header-derived value is trusted for routing, tenancy or authorization.
3. **Bounded memory, no silent truncation.** Messages are streamed from S3 and every part is streamed to S3. Every limit (M5) is checked on the stream before data is buffered. Hitting a limit is a recorded outcome, and storage caps (column widths, row caps) are recorded as defects.
4. **Never a crash, always a status.** Malformed input yields a best-effort record and an explicit status. Infrastructure failures (S3, MySQL) are retried, never recorded as a content verdict.
5. **Tenant from trusted context only**: the envelope's `organizationId` must match the writer row of the message. Every key and row uses the row's organization. `eml_object_key` must start with `org/{organizationId}/`.
6. **No bodies or attachment bytes in MySQL, on the outbox or in logs.** MySQL holds S3 keys, hashes, sizes, types, flags and bounded header metadata only.
7. **Idempotent per event and per message.** A duplicate, redelivered or concurrent event creates no second header, attachment, `email_events`, outbox row or S3 object (deterministic keys).
8. **One writer transaction** commits the metadata, the processing event and the outbox event (transactional outbox, ADR-0005). The data plane is writer-only (ADR-0014).

### M1. Where it runs: email-worker

The post-queue ingestion stage is the **`MimeIngestionModule` of `apps/email-worker`**. Why:

- ADR-0002's service map assigns "Email Processing" to email-worker. The app already declares the queue `email-worker.message-received` bound to `mail.message.received.v1`, which step 3.2 will feed.
- Parsing is CPU- and IO-heavy and scales with mail volume. As its own deployable it scales independently of smtp-adapter (edge latency) and delivery-worker (reinjection, status).
- Its next consumer, scanning (4.x), runs in the same deployable and reads the parse output (rows plus S3 parts). The event boundary still stays explicit, so the stages can be split later.

**Rejected alternatives:** parsing in smtp-adapter (SMTP latency, which the brief forbids); a new `ingestion-worker` app (an extra deployable with no scaling difference).

A role flag `MIME_INGESTION_ENABLED` (default `true`) lets later scanning-only replicas switch the stage off.

### M2. Transport: a shared outbox feed (interim until 3.2)

The delivery-worker poller is **factored into `packages/common/src/outbox/`**. That avoids copying it, and common already depends on `@email-gateway/database`, `@email-gateway/event-contracts` and `@email-gateway/logger`, so no new package needs installing. It is exported from `@email-gateway/common`:

```ts
export type HandleOutcome = 'handled' | 'duplicate';
/** Handles one event; must be idempotent; throws on a retryable failure. */
export type EventHandler<T> = (event: EventEnvelope<T>) => Promise<HandleOutcome>;
/** The transport step 3.2 replaces with a RabbitMQ consumer (same handler). */
export interface EventFeed<T> {
  start(handler: EventHandler<T>): void;
  stop(): Promise<void>;
}
/** Adapter for handlers whose effects all run inside processOnce's transaction (step 2.3 shape). */
export function processOnceHandler<T>(
  prisma: PrismaClient,
  consumer: string,
  handler: (event: EventEnvelope<T>, tx: Prisma.TransactionClient) => Promise<void>,
  options: { txTimeoutMs: number },
): EventHandler<T>;
export interface OutboxPollerMetrics {
  pollLag(consumer: string, seconds: number): void;
  invalid(consumer: string): void;
}
export class OutboxPoller<T> implements EventFeed<T> {
  /* options below */
}
export class ShardedOutboxFeed<T> implements EventFeed<T> {
  /* N pollers, one per shard */
}
export class AdvisoryLocks {
  /* moved unchanged, plus heldCount(prefix) */
}
export function withTransactionDefaults(/* moved unchanged */);
export function isUniqueViolation(error: unknown): boolean; // moved
export function uuidv7(nowMs?: number): string; // moved from delivery-worker/src/shared/uuidv7.ts
```

`OutboxPollerOptions<T>`: `prisma`, `locks`, `logger`, `metrics: OutboxPollerMetrics`, `consumer`, `eventType`, `schema`, `initialPosition: 'oldest' | 'latest'`, `pollIntervalMs`, `safetyLagMs`, `batchSize`, `lockPrefix` (`'dw'` for delivery-worker, `'ew'` for email-worker), optional `concurrency` (default **1**), `shard` (default `{ index: 0, count: 1 }`), `failureBackoff` (`{ baseMs, maxMs }`, default none), `maxHeldLocks` (default unlimited) and `now`. The per-row `txTimeoutMs` moves into `processOnceHandler`.

Behaviour (the step 2.3 R6 semantics are kept exactly; the additions are new):

- **Unchanged:** cursor `outbox:<consumer>` (shard count 1); lock `<lockPrefix>:outbox:<consumer>`; safety-lag cursor advance through the contiguous prefix of handled rows; a failing handler freezes the cursor but not the rows after it; invalid rows skipped and counted; the `recent` set; `published_at` never touched; initial positions as in R6.
- **Concurrency:** the rows of one page are handled by up to `concurrency` concurrent handlers. Outcomes are collected per row and the cursor advance is computed afterwards in id order with the R6 rule, so the result equals sequential handling. `concurrency = 1` is exactly today's behaviour. A page never starts more than `batchSize` new rows.
- **Sharding:** with `shard.count = n > 1` the query adds `AND MOD(id, n) = index`. The cursor becomes `outbox:<consumer>#<index>/<n>` and the lock `<lockPrefix>:outbox:<consumer>#<index>/<n>` (≤ 64 characters, checked). A shard cursor created for the first time starts at the **minimum** `position_id` of the consumer's existing cursors (`name = 'outbox:<consumer>'` or `LIKE 'outbox:<consumer>#%'`), or at `initialPosition` when none exist. Changing `n` therefore re-reads rather than skips; the ledger makes re-reads free of effects, and old cursors are left for an operator to delete (documented). `ShardedOutboxFeed` creates one poller per shard. Each poll of a shard first calls `locks.ensure()` only while this replica holds fewer than `maxHeldLocks` shard locks, so replicas spread the shards. Replicas without a lock idle, as in R6.
- **Lag of a shard this process does not hold** (review round, §12.4): a shard poller that idles (lock held elsewhere, or `maxHeldLocks` reached) reports that shard's lag from its durable cursor, at most every 10 s: the seconds by which the oldest row past the cursor is older than `safetyLagMs`. A shard another replica keeps up with stays near 0; a shard no replica runs grows, so `ShardedOutboxFeed`'s maximum (now over every shard) shows it. Every shard needs a runner: replicas × `maxHeldLocks` ≥ shards.
- **Failure backoff:** when set, a row whose handler threw is not retried before `min(maxMs, baseMs × 2^(failures-1))`, tracked in memory per event id. It still freezes the cursor. This keeps an S3 outage from turning into a tight retry loop.
- **Metrics** go through `OutboxPollerMetrics`. delivery-worker adapts it to its existing `delivery_outbox_poll_lag_seconds{consumer}` and `delivery_outbox_invalid_total{consumer}` series (names unchanged); email-worker uses `mime_outbox_poll_lag_seconds{consumer}` and `mime_outbox_invalid_total{consumer}`.
- **Logging:** a handler error is logged as `{ outboxId, eventId, errName, errCode }` only. Since this step, **no `err.message` and no `err` object are logged by the poller**, because a parser error message could quote content (M15). delivery-worker keeps its own logging inside its handlers.

**delivery-worker migrates to the shared feed** without any behaviour change:

- `approval-feed.ts` re-exports `EventFeed` as `ApprovalFeed`.
- `DeliveryApprovalConsumer` and `DevPassThroughApprover` call `feed.start(processOnceHandler(prisma, CONSUMER, fn, { txTimeoutMs }))`, with the same consumer names and transaction budgets (`PLANNING_TX_TIMEOUT_MS`, `RECORDER_TX_TIMEOUT_MS`).
- `lockPrefix: 'dw'` keeps the lock names. Every other import of the moved helpers switches to `@email-gateway/common`, and the old files are deleted.

**The email-worker consumer** (`email-worker.mime-parser`, event `mail.message.received.v1`, initial position **`oldest`**, because every received message must be parsed and the ledger and parse rows make re-reads free) runs a `ShardedOutboxFeed` with `concurrency = MIME_CONCURRENCY`, `shard.count = MIME_OUTBOX_SHARDS`, `maxHeldLocks = MIME_OUTBOX_MAX_HELD_SHARDS`, `lockPrefix 'ew'` and failure backoff `MIME_RETRY_BASE_MS`/`MIME_RETRY_MAX_MS`. Its handler is **staged**, not `processOnceHandler`, because the parse (S3 I/O, seconds) must not run inside a database transaction (M3). Step 3.2 replaces the feed with a competing consumer on `email-worker.message-received`, with the handler unchanged.

### M3. Processing flow (one event)

`MimeIngestionService.handle(event): Promise<HandleOutcome>`, with consumer name `email-worker.mime-parser` (`MIME_CONSUMER`):

1. **Ledger pre-check:** a row `(consumer, eventId)` in `message_idempotency` → `'duplicate'`. No work happens.
2. **Load the message** from the writer: `email_messages` by `(id = payload.messageId, received_at = payload.receivedAt, organization_id = envelope.organizationId)`. If it is missing, run `processOnce` with a no-op (ledger row only), log a warning with the ids, count `outcome="message_missing"` and return `'handled'`. Nothing is written for a message that does not exist, and the event is not trusted.
3. **Load the parse row** (`email_message_parses` by `message_id, received_at`). A final status → `processOnce` no-op → `'duplicate'` (per-message idempotency: a different event id for the same message never parses twice).
4. **Mark parsing**, in a short transaction of its own: insert `status = parsing, attempts = 1, parser_version, event_id, started_at`, or, when the row exists in `parsing`, `attempts = attempts + 1, started_at = now`. A P2002 race re-reads and updates. If `attempts > MIME_MAX_ATTEMPTS` after the increment, the message has crashed the process, or failed with a non-transient error (M3.10), that many times, so go straight to step 9 with `parse_failed / max_attempts_exceeded`. That is the poison-message guard.
5. **Pre-read checks** (no download):
   - `eml_object_key` not under `org/{organizationId}/` → `parse_failed / eml_key_mismatch`. A key without any `org/<id>/` prefix cannot be carried by the event contract, so `mail.message.parse_failed.v1` carries `emlS3Key: null` for it (review round, §12.4).
   - `size_bytes > MIME_MAX_MESSAGE_BYTES` → `parse_limit_exceeded` with `['message_size']`, no parse, no parts.
6. **Stream the EML**: `GetObject(S3_BUCKET_MAIL, eml_object_key)` with an `AbortSignal`. `MIME_S3_TIMEOUT_MS` bounds **each single wait on S3** (the request until it answers, every body chunk the parser waits for, every part write waiting for upload capacity, every part finish, every ranged read); a longer wait fails as `S3Stalled` / `UploadTimedOut`, an infrastructure retry. Time the parser spends on the bytes (backpressure) is not S3 time, so a large message is never cut by the S3 budget. `NoSuchKey`/404 → `parse_failed / eml_missing`. Any other S3 error is an infrastructure error.
7. **Parse** with `@email-gateway/mime-parser` (M4) under a wall-clock `AbortSignal` of `MIME_PARSE_TIMEOUT_MS`. The parser receives a **part sink** implemented by email-worker (M11), which streams each body and attachment to its deterministic key. It also receives the limits (M5), and an archive reader factory (M10) backed by ranged GETs of the object just stored.
8. **Integrity**: the parser hashes and counts the bytes it read. If the SHA-256 ≠ `email_messages.eml_sha256` or the byte count ≠ `size_bytes`, the result becomes `parse_failed / integrity_mismatch`: no headers or attachments are recorded, and the part objects written by this attempt are deleted (best effort). The step never parses a different object than the one ingested.
9. **Finalize**, in one writer transaction through `processOnce(txPrisma, MIME_CONSUMER, eventId, tx => …)` with budget `MIME_DB_TIMEOUT_MS`:
   1. `UPDATE email_message_parses SET status = <final>, … WHERE message_id = ? AND received_at = ? AND organization_id = ? AND status = 'parsing'`. If 0 rows are affected, another worker finalized first: throw an internal `AlreadyFinalized` error, which rolls back, and return `'duplicate'`. The S3 objects are identical, because the keys are deterministic for the same bytes and parser version.
   2. `createMany` `email_headers` (M7) and `email_attachments` (M9). The unique keys are the backstop.
   3. `UPDATE email_messages SET subject = <decoded subject>, attachment_count = <n> WHERE id, received_at, organization_id`. **`status`, `status_changed_at` and `version` are never touched** (M13).
   4. One `email_events` row: `event_type = 'parsed' | 'parse_failed'`, `source_service = 'email-worker'`, `event_id` = the new outbox event id, `occurred_at = completed_at`, `details = { status, limitsExceeded, defectCount, attachmentCount, parserVersion }` (codes and counts only).
   5. One `message_outbox` row: `mail.message.parsed.v1` or `mail.message.parse_failed.v1` (M14). `event_id = uuidv7()`, `aggregate_type 'message'`, `aggregate_id` = the decimal message id, `correlation_id` = the received event's `correlationId`, and the payload validated with the schema before insert.
10. **Errors:**
    - A **transient** failure (`isTransientFailure`: any S3 service error, a network or timeout error, `S3Stalled`/`UploadTimedOut`, a Prisma connection, pool, transaction-timeout or write-conflict/deadlock error) decrements `attempts` (best effort, its own small transaction) and is rethrown. The feed retries with backoff, the cursor stays frozen at that row and the message is never marked failed for an outage. A process crash skips the decrement, so the attempt counts toward the poison guard.
    - **Any other exception** during the attempt (a data error such as Prisma `P2000` "value too long", a contract violation of the payload, an unexpected exception) is also rethrown and retried, but **keeps its attempt**: it would fail the same way every time, and giving the attempt back would retry it forever with the cursor frozen. After `MIME_MAX_ATTEMPTS` such attempts, step 4 finalizes `parse_failed / max_attempts_exceeded` (review round, §12.4).
    - A **parse timeout** is a content verdict (`parse_limit_exceeded ['parse_timeout']`) only when the message itself was slow. When the budget runs out while an S3 call had been pending for at least `min(1 s, MIME_PARSE_TIMEOUT_MS / 4)`, or after at least half of the budget went to S3 waits, the attempt is an infrastructure retry (`S3Stalled`, invariant 4). A download that does not answer within the parse budget is `S3Stalled` too.
    - A **content-side exception** inside the parser library that the library did not map to an outcome becomes `parse_failed / parser_error`. The library guarantees this mapping (M4).

Requirements of the brief mapped to the flow: 1 → M3.6 (streamed read of the stored EML); 2 → the step 2.2 registry id (`message_identities`), carried unchanged; 3 → the envelope organization checked against the writer row (M3.2, invariant 5); 4–11 → M4–M9; 12 → EML hash re-verified (M3.8) and SHA-256 per stored part; 13 → M3.9 and §3; 14 → the EML is already in S3 (2.2), parts per M11; 15 → M14 and `email_events`; 16 → M13.

### M4. Parser library `@email-gateway/mime-parser` (new package)

A pure library (no Nest, no Prisma, no AWS SDK) in `packages/mime-parser`, so its limits and corpus are unit-tested in isolation and step 4.x can reuse the sniffer and archive inspector. Dependencies, pinned **exactly**, at the newest release older than the repository's 7-day `minimumReleaseAge`:

- `@zone-eu/mailsplit` (≥ 5.4.26);
- `libmime`, `libqp` and `libbase64` at the versions that mailsplit pins (5.5.1 / 3.0.1 / 1.4.1, or the newer pins of the chosen mailsplit);
- `iconv-lite` (0.7.x);
- `yauzl` ≥ 3.2.1 (3.4.x) with `@types/yauzl`;
- dev only: `yazl` (zip generation in tests).

**Not** `mailparser`, `nodemailer`, `html-to-text`, `linkify-it` or `file-type` (ADR-0022).

API (names are binding; internals are the implementer's):

```ts
export const PARSER_VERSION: string; // e.g. 'mime-1'; bump on any change that alters output
export const MIME_LIMIT_NAMES: readonly [...]; // M5
export const MIME_DEFECT_CODES: readonly [...]; // M6
export const ATTACHMENT_FLAGS: readonly [...]; // M9, M10
export interface MimeLimits {
  /* one field per M5 limit, plus archive thresholds (M10) */
}
export interface PartInfo {
  partIndex: number;
  partPath: string;
  depth: number;
  kind: 'text' | 'html' | 'attachment';
}
export interface StoredPart {
  key: string;
  readRange(start: number, endInclusive: number, signal: AbortSignal): Promise<Buffer>;
}
export interface PartWriter {
  write(chunk: Buffer): Promise<void>; // honours backpressure
  finish(): Promise<StoredPart>; // object durable after this
  abort(): Promise<void>; // no object remains
}
export interface PartSink {
  open(part: PartInfo): Promise<PartWriter>;
}
export function parseMessage(
  input: Readable,
  options: { limits: MimeLimits; sink: PartSink; signal: AbortSignal },
): Promise<MimeParseResult>;
export function sanitizeFilename(raw: string | undefined, maxChars: number): SanitizedFilename;
export function sniffContentType(head: Buffer): string; // M9
export function inspectZip(
  part: StoredPart,
  sizeBytes: number,
  limits: MimeLimits,
  signal: AbortSignal,
): Promise<ArchiveInfo>;
```

`MimeParseResult`:

- `status`: `parsed | parsed_with_defects | parse_limit_exceeded | parse_failed`, with `failureReason?: 'parser_error'`;
- `limitsExceeded: LimitName[]` and `defects: DefectCode[]` (unique, in first-seen order);
- `stats`: `bytesRead`, `sha256` (hex of all input bytes), `partCount`, `maxDepth`, `headerCount` (fields of the top-level block), `attachmentCount`, `decodedBytes`, `durationMs`;
- `subject` (decoded, M7), `headers: ExtractedHeader[]` (M7);
- `textBody` and `htmlBody`: `BodyResult | null`, where `BodyResult = { key: string | null; sha256; sizeBytes; charset; partIndex; flags }`;
- `attachments: AttachmentResult[]` (M9);
- `structure: StructureNode[]` (M13/§3; no filenames, no header values).

Behaviour:

- **Streaming:** the input is consumed with `for await` through a byte counter and SHA-256 into a mailsplit `Splitter` configured with `{ maxHeadSize: limits.maxHeaderBlockBytes, maxChildNodes: limits.maxParts + 1 }`. Embedded `message/rfc822` is parsed (`ignoreEmbedded: false`). Output chunks are consumed with `for await` too, and every sink write is awaited, so backpressure reaches the S3 GET stream. The memory per message is bounded by mailsplit's line buffer plus the sink's upload buffer, never the message size. A body with no line breaks (for example 20 MiB of base64 on one line) must stay within that bound; mailsplit's truncated-line handling is relied on, and a test proves it.
- **Leaf decoding:** the transfer encoding is decoded as a stream with `libbase64.Decoder` or `libqp.Decoder` (7bit, 8bit and binary pass through; anything else → defect `unknown_transfer_encoding`, decoded as binary). `format=flowed` is **not** applied to stored bodies; the stored text is the decoded part content. Text and HTML bodies are then converted to UTF-8 with `iconv-lite` `decodeStream` for the declared charset (none → `us-ascii`, treated as UTF-8-compatible). An unknown or unsupported charset is decoded as UTF-8 with replacement characters and gets defect `unknown_charset`; it never throws. Attachments keep their decoded bytes as they are.
- **Error mapping:** an error thrown by the **sink**, a **stored part's `readRange`** or the **input stream** is rethrown unchanged (infrastructure; the worker retries). The `signal` firing is mapped to `parse_timeout` (M5). Any other exception from mailsplit, libmime, the decoders, iconv-lite or yauzl becomes a defect or an outcome: a zip error → flag `archive_malformed`; a header-size error from mailsplit → limit `header_block_size`; a child-node error → limit `part_count`; anything else unexpected → `parse_failed / parser_error`, keeping what was extracted. Errors are classified by class or code, **never by matching or logging their message text**.
- **No logging inside the library.** It returns codes; the worker logs.

### M5. Limits (validated in config, enforced on the stream)

| Limit name (`limitsExceeded`) | Config key (default)                         | Enforced                                                                                                                                                                         | On breach                                                                                                                                                                                |
| ----------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `message_size`                | `MIME_MAX_MESSAGE_BYTES` (53 477 376)        | Before the download from `size_bytes` (M3.5), and again on the byte counter                                                                                                      | Not parsed (pre-check), or the parse stops                                                                                                                                               |
| `nesting_depth`               | `MIME_MAX_DEPTH` (10)                        | When a node is emitted: root = 0, every multipart child +1, the root of an embedded `message/rfc822` +1 below its container                                                      | Parse stops                                                                                                                                                                              |
| `part_count`                  | `MIME_MAX_PARTS` (250)                       | Every node counts (containers and leaves); mailsplit `maxChildNodes` as a backstop                                                                                               | Parse stops                                                                                                                                                                              |
| `header_count`                | `MIME_MAX_HEADERS` (1 000)                   | Header fields in any one node's header block                                                                                                                                     | Parse stops                                                                                                                                                                              |
| `header_line_length`          | `MIME_MAX_HEADER_LINE_BYTES` (32 768)        | Bytes of one unfolded header field                                                                                                                                               | Parse stops                                                                                                                                                                              |
| `header_block_size`           | `MIME_MAX_HEADER_BLOCK_BYTES` (262 144)      | mailsplit `maxHeadSize` per node (bounded before parsing the block)                                                                                                              | Parse stops                                                                                                                                                                              |
| `attachment_count`            | `MIME_MAX_ATTACHMENTS` (100)                 | Leaf parts classified as attachments (M9)                                                                                                                                        | Parse stops                                                                                                                                                                              |
| `attachment_size`             | `MIME_MAX_ATTACHMENT_BYTES` (26 214 400)     | Decoded bytes of one attachment                                                                                                                                                  | That part's writer is **aborted** (no object). Hashing continues to the end of the part. Row with `object_key = NULL`, full size, SHA-256, flag `not_stored_size_limit`. Parse continues |
| `body_size`                   | `MIME_MAX_BODY_BYTES` (10 485 760)           | Decoded and converted bytes of the text or HTML body                                                                                                                             | As `attachment_size`, for the body (`key = null`, flag `not_stored_size_limit`). Parse continues                                                                                         |
| `decoded_ratio`               | `MIME_MAX_DECODED_RATIO` (1.1)               | Per leaf: decoded bytes ÷ max(encoded bytes, 1), checked while streaming once ≥ 64 KiB are decoded (base64 ≤ 0.75 and QP ≤ 1, so a higher ratio means a decoder anomaly or bomb) | Parse stops                                                                                                                                                                              |
| `total_decoded_size`          | `MIME_MAX_TOTAL_DECODED_BYTES` (104 857 600) | Sum of decoded bytes over all leaves                                                                                                                                             | Parse stops                                                                                                                                                                              |
| `parse_timeout`               | `MIME_PARSE_TIMEOUT_MS` (120 000)            | Wall clock from the start of the download to the end of the parse (`AbortSignal`); recorded only when the stage was not stalled on S3 (M3.10)                                    | Parse stops                                                                                                                                                                              |

"Parse stops" means:

- the in-flight part's writer is aborted, and that part is recorded in `structure` with `truncated: true` but **not** as an attachment or body row;
- everything completed before the stop is kept;
- the status is `parse_limit_exceeded` with every limit hit, in order.

A per-part limit (`attachment_size`, `body_size`) also sets `parse_limit_exceeded` while the parse continues, so the scanners and policy see that content was not stored.

Config validation (zod `superRefine`) refuses startup when:

- `MIME_MAX_ATTACHMENT_BYTES`, `MIME_MAX_BODY_BYTES` > `MIME_MAX_MESSAGE_BYTES`;
- `MIME_MAX_HEADER_LINE_BYTES` > `MIME_MAX_HEADER_BLOCK_BYTES`;
- `MIME_MAX_DECODED_RATIO` < 1;
- `MIME_MAX_DEPTH` ∉ 1..50, `MIME_MAX_PARTS` ∉ 2..1000, `MIME_MAX_ATTACHMENTS` > `MIME_MAX_PARTS`;
- `1 + MIME_MAX_DEPTH × (1 + digits(MIME_MAX_PARTS − 1))` > 128, the longest `part_path` against `email_attachments.part_path VARCHAR(128)` (for example depth 32 with 1 000 parts). The parser also stops as `nesting_depth` before a path longer than `MAX_PART_PATH_CHARS` (128);
- `MIME_S3_TIMEOUT_MS` ≥ `MIME_PARSE_TIMEOUT_MS` (a stalled S3 call must fail as a retry before the parse budget runs out);
- `MIME_MAX_STORED_HEADERS` ∉ 1..500 or `MIME_FILENAME_MAX_CHARS` ∉ 16..240;
- `MIME_OUTBOX_SAFETY_LAG_MS` < 30 000 (must exceed smtp-adapter's ingestion transaction budget);
- `MIME_OUTBOX_MAX_HELD_SHARDS` > `MIME_OUTBOX_SHARDS`;
- `MIME_CONCURRENCY × MIME_OUTBOX_MAX_HELD_SHARDS × (MIME_S3_PART_SIZE_BYTES × (MIME_S3_QUEUE_SIZE + 1) + MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES)` > `MIME_MEMORY_BUDGET_BYTES` (default 268 435 456; every held shard runs its own `MIME_CONCURRENCY` parses, each with one part upload and at most one zip central directory; defaults 4 × 1 × 23 MiB = 92 MiB).

### M6. Malformed MIME: best effort plus defects

Malformed input is parsed as far as mailsplit allows. Every anomaly detected adds a `MIME_DEFECT_CODES` entry, and a parse with ≥ 1 defect and no limit ends `parsed_with_defects`. The required codes (more may be added, snake_case, ≤ 48 characters):

| Code                                                                      | Meaning                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `no_headers`                                                              | No header block (the message starts with a blank line, or its first line is no header)                                                                                                                                                               |
| `invalid_header_line`                                                     | A line in a header block that is not `name: value` (dropped by mailsplit or libmime)                                                                                                                                                                 |
| `missing_boundary_parameter`                                              | `multipart/*` without `boundary=` (the body is treated as one leaf)                                                                                                                                                                                  |
| `boundary_not_found`                                                      | A multipart whose boundary never occurs (no child parts)                                                                                                                                                                                             |
| `missing_closing_boundary`                                                | A multipart that reaches EOF without its `--boundary--`. Detected from mailsplit's node and data sequence; if mailsplit does not expose it, a delimiter-line tracker over the multipart's `data` chunks (defect detection only, never used to split) |
| `invalid_base64`                                                          | Characters outside the alphabet or a bad padding/length (libbase64 skips them; count the skipped input)                                                                                                                                              |
| `invalid_quoted_printable`                                                | `=` not followed by two hex digits or a soft line break                                                                                                                                                                                              |
| `unknown_transfer_encoding`                                               | A CTE other than 7bit/8bit/binary/base64/quoted-printable                                                                                                                                                                                            |
| `unknown_charset`                                                         | A body or encoded-word charset that iconv-lite cannot decode (UTF-8 with U+FFFD used)                                                                                                                                                                |
| `invalid_encoded_word`                                                    | A malformed RFC 2047 word or RFC 2231 parameter (left raw, escaped)                                                                                                                                                                                  |
| `duplicate_singleton_header`                                              | More than one `From`, `Sender`, `Subject`, `Date`, `Message-ID`, `To`, `Cc`, `Reply-To`, `In-Reply-To`, `References` (RFC 5322 §3.6)                                                                                                                 |
| `header_control_chars`, `header_bidi_control`                             | Control characters (replaced) or bidi controls (kept, flagged) in a stored header value                                                                                                                                                              |
| `header_value_truncated`, `stored_headers_truncated`, `subject_truncated` | Storage caps of M7 (never silent)                                                                                                                                                                                                                    |
| `nul_bytes`                                                               | NUL bytes in a header block                                                                                                                                                                                                                          |
| `empty_message`                                                           | Zero bytes (also `no_headers`)                                                                                                                                                                                                                       |

A message whose root is not `multipart/*` and not `text/*` (for example a bare `application/pdf`) is valid: its single leaf is an attachment.

### M7. Headers (untrusted metadata)

- **Envelope sender and recipients** come from `email_messages.envelope_from` and `email_recipients` (trusted, step 2.2) and are not re-derived. This step copies no header address into a routing or tenancy field.
- **Stored headers** (`email_headers`, top-level block only, in their order of appearance, `seq` 0..n-1): `From`, `Sender`, `Reply-To`, `To`, `Cc`, `Subject`, `Message-ID`, `Date`, `In-Reply-To`, `References`, `Return-Path`, `Authentication-Results`. `name` is the canonical spelling above; every occurrence is a row (several `Authentication-Results` are normal).
- `value`:
  1. unfold;
  2. decode RFC 2047 with `libmime.decodeWords` (malformed words left raw plus `invalid_encoded_word`);
  3. raw 8-bit UTF-8 (RFC 6532) kept when valid, else decoded as latin1 plus `unknown_charset`;
  4. normalize to NFC and make well-formed (`toWellFormed`);
  5. replace C0 (except HT), C1 and DEL with U+FFFD (`header_control_chars`) and keep bidi controls but add `header_bidi_control`;
  6. truncate to **2 048 code points** at a code-point boundary (`header_value_truncated`).
- At most `MIME_MAX_STORED_HEADERS` (200) rows; the rest are dropped with `stored_headers_truncated`. `headerCount` counts every field of the top-level block.
- `email_messages.subject` is overwritten with the decoded subject, ≤ **998** code points (`subject_truncated`). This replaces step 2.2's raw value, which D7 left encoded "for step 3.1". `header_from` and `internet_message_id` keep the ingestion values.
- No address-list parsing in this step: values are stored decoded but unparsed, so nodemailer's address parser (GHSA-prgh-xp8r-p3m5) is not used. Steps 4.4 and 4.1 parse what they need from these rows.
- Headers of nested messages are not stored in `email_headers`. Their content type, charset and part path are in `structure`.

### M8. Bodies

- **Selection:** walking the tree in order, outside any embedded `message/rfc822` subtree, the first leaf of type `text/plain` and the first of type `text/html` whose disposition is not `attachment` and that has no filename are the **text body** and the **HTML body**. Every other leaf (further inline text parts, inline images, calendar parts, every leaf inside a nested message) is an attachment (M9).
- **Stored object:** the transfer-decoded, UTF-8-converted bytes, streamed to `…/{partIndex}.text` or `…/{partIndex}.html` (M11). SHA-256 and size are those of the stored bytes. The original charset goes to `text_body_charset`/`html_body_charset`. HTML is never sanitized, rendered or converted.
- MySQL holds only the key, SHA-256, size and charset (`email_message_parses`). **No preview** (the schema has no preview column, and none is added).

### M9. Attachments, filenames and sniffing

One `email_attachments` row per attachment leaf (`part_index` = the leaf's index in `structure`). Per row:

- `part_path` and `depth`;
- `disposition` (`attachment` or `inline`);
- `declared_content_type` (lower-cased `type/subtype`, ≤ 255);
- `detected_content_type` from the sniffer;
- `size_bytes` (decoded), `encoded_size_bytes`, `sha256` (decoded bytes) and `object_key` (NULL when not stored);
- `filename` (sanitized, below), `original_filename` (escaped original) and `flags` (JSON array of `ATTACHMENT_FLAGS`);
- `archive_info` (JSON, M10);
- `verdict` stays NULL (4.x).

**Filename sanitization** (`sanitizeFilename`). The source is mailsplit's `node.filename`: Content-Disposition `filename`, else Content-Type `name`, both RFC 2231 and RFC 2047 decoded by libmime. The steps run in this order:

1. Normalize to NFC and make the string well-formed.
2. Take the last path component (split on `/` and `\`) and strip a drive prefix such as `C:` → `filename_path_stripped`.
3. Remove C0/C1/DEL → `filename_control_chars`; remove bidi controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) → `filename_bidi_control`; remove zero-width characters (U+200B–U+200D, U+FEFF).
4. Replace `<>:"|?*` with `_`, collapse whitespace runs, and trim leading dots and spaces and trailing dots and spaces. Internal padding of ≥ 3 spaces before a final extension → `filename_whitespace_padding`.
5. Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`, with any extension) get a `_` prefix → `filename_reserved_name`.
6. Cap at `MIME_FILENAME_MAX_CHARS` (200) code points, keeping the final extension (≤ 16 characters) → `filename_truncated`.
7. If the result is empty, `filename = NULL` → `filename_missing`.

Extension flags:

- `filename_executable_extension`: the final extension is in the executable set (`exe scr com bat cmd pif cpl dll msi msp js jse vbs vbe wsf wsh hta ps1 psm1 lnk jar iso img vhd vhdx reg application appx msix appinstaller sh apk scf url`).
- `filename_double_extension`: the name has ≥ 2 extensions, the last is in the executable set and the one before it is in the document or media set (`pdf doc docx docm xls xlsx xlsm ppt pptx txt rtf csv jpg jpeg png gif bmp mp3 mp4 wav zip html htm`).
- `filename_extension_mismatch`: the sniffed type is an executable or archive, and the extension says otherwise.

`original_filename` is the raw decoded name with every code point outside printable Unicode, every bidi or zero-width character and `\` written as `\u{XXXX}` escapes, capped at 1 024 characters (`original_filename_truncated`). It is metadata only, never used as a path or an S3 key, and never logged.

**Sniffing** (`sniffContentType`, a fixed table over the first 4 096 bytes plus fixed offsets). Every attachment's first 4 KiB is kept in memory for this; that is the only buffering per part.

| Detected type                                                                | Signature                                                                            |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `application/pdf`                                                            | `%PDF-`                                                                              |
| `application/zip`                                                            | `PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`                                             |
| `application/gzip`                                                           | `1F 8B`                                                                              |
| `application/x-bzip2`, `application/x-xz`, `application/x-7z-compressed`     | `BZh`, `FD 37 7A 58 5A 00`, `37 7A BC AF 27 1C`                                      |
| `application/vnd.rar`                                                        | `Rar!\x1A\x07\x00` / `\x01\x00`                                                      |
| `application/x-tar`                                                          | `ustar` at offset 257                                                                |
| `application/vnd.ms-cab-compressed`                                          | `MSCF`                                                                               |
| `application/x-ole-storage`                                                  | `D0 CF 11 E0 A1 B1 1A E1`                                                            |
| `application/x-msdownload`, `application/x-elf`, `application/x-mach-binary` | `MZ`, `7F 45 4C 46`, `FE ED FA CE/CF`, `CE/CF FA ED FE`, `CA FE BA BE`               |
| `application/x-ms-shortcut`                                                  | `4C 00 00 00 01 14 02 00`                                                            |
| `application/x-sh`                                                           | `#!`                                                                                 |
| `text/rtf`                                                                   | `{\rtf`                                                                              |
| `image/png`, `image/jpeg`, `image/gif`, `image/bmp`, `image/webp`            | the usual magic numbers                                                              |
| `text/html`                                                                  | after an optional BOM and whitespace, a case-insensitive `<!doctype html` or `<html` |
| `application/octet-stream`                                                   | anything else                                                                        |

Sniff flags:

- `content_type_mismatch`: the declared and detected types differ and the detected type is not `application/octet-stream`;
- `executable`: an executable or shortcut type, or a shell script;
- `archive`: any archive type.

Other flags: `nested_message_part` (the leaf is inside an embedded message), `not_stored_size_limit`.

### M10. Archive bombs (metadata only, flags for 4.x)

When the sniffed type is an archive:

- **zip** (`inspectZip`, only when the object was stored). `yauzl.fromRandomAccessReader` is used over a `StoredPart.readRange`-backed reader with `lazyEntries: true`, `autoClose`, `decodeStrings: true`, `validateEntrySizes: false` (no entry is ever read) and `strictFileNames: false`. Reads are served from two bounded fetches: the last min(size, 65 557) bytes (EOCD plus comment), then the central directory. A central directory larger than `MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES` (8 388 608) → `archive_not_inspected`. Iteration stops after `MIME_ARCHIVE_MAX_ENTRIES` + 1 entries. Flags:
  - `archive_entry_count`: more than `MIME_ARCHIVE_MAX_ENTRIES` (1 000) entries;
  - `archive_compression_ratio`: an entry's `uncompressedSize ÷ max(compressedSize, 1)` > `MIME_ARCHIVE_MAX_RATIO` (100);
  - `archive_total_size`: the sum of declared uncompressed sizes > `MIME_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES` (1 073 741 824);
  - `archive_encrypted`: general-purpose bit 0 set;
  - `archive_nested`: an entry name ending in an archive extension (`zip rar 7z gz tgz tar bz2 xz cab iso jar arj lzh z ace img`);
  - `archive_overlapping_entries`: two entries whose local-header offset plus compressed size overlap, sorted by `relativeOffsetOfLocalHeader`, which is the Fifield non-recursive bomb;
  - `archive_path_traversal`: an entry name with `..` components, a leading `/` or a drive letter;
  - `archive_malformed`: yauzl rejected the archive.
- **gzip**: the header (FLG, FNAME) and the trailing ISIZE, both kept from the stream (first 4 KiB, last 8 bytes). Ratio = ISIZE ÷ compressed size → `archive_compression_ratio`. An FNAME ending in an archive extension → `archive_nested`. ISIZE is mod 2³², so a hint only.
- **Other types** (rar, 7z, bzip2, xz, tar, cab): `archive_not_inspected` plus the type.
- `archive_info` JSON: `{ type, inspected, entries, declaredUncompressedBytes, maxRatio, encryptedEntries, nestedArchives }`, numbers only and no entry names.

Declared sizes can lie. Step 4.2 enforces real limits while decompressing; this step never decompresses.

### M11. S3 layout and objects

- **Keys (deterministic):** `org/{organizationId}/part/{yyyy}/{mm}/{dd}/{messageId}/{partIndex}.{text|html|att}`. The date is the UTC date of the message's `received_at` (not "now"), so a retry on another day writes the same key. `organizationId` and `messageId` come from the writer row. Filenames are never part of a key.
- **Upload:** `@aws-sdk/lib-storage` `Upload` per part (`MIME_S3_PART_SIZE_BYTES` ≥ 5 MiB, `MIME_S3_QUEUE_SIZE`, `leavePartsOnError: false`, abort controller), with the step 2.2 `EmlUpload` pattern as the model (`write` with backpressure, `finish`, `abort`).
- **Object headers:** `ContentType` `text/plain; charset=utf-8` for `.text` and `application/octet-stream` for `.html` and `.att`, plus `ContentDisposition: attachment`. That way an object opened by mistake through a presigned URL is never rendered. **No filename and no header value in object metadata.** Bucket default encryption applies (ADR-0008).
- **Ranged reads** for M10 use `GetObject` with `Range` on the just-finished key.
- The read of the EML is a streaming `GetObject` of `email_messages.eml_object_key` from `S3_BUCKET_MAIL`.

### M12. Idempotency

| Duplicate                                               | Guard                                                                                                                                                                           |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Same event redelivered (poller re-read, 3.2 redelivery) | Ledger pre-check (M3.1) and `processOnce` in the final transaction                                                                                                              |
| Different event for the same message                    | Parse row final → duplicate (M3.3); conditional final `UPDATE … WHERE status = 'parsing'` (M3.9.1)                                                                              |
| Two workers on the same message concurrently            | Both write the **same** S3 keys with the same bytes; one final `UPDATE` wins, and the other rolls back (`AlreadyFinalized`). Header and attachment unique keys are the backstop |
| Crash after S3 writes, before commit                    | The next attempt overwrites the same keys; nothing is orphaned (a different parser version is the documented exception, §8)                                                     |
| Crash or timeout loop                                   | `attempts` > `MIME_MAX_ATTEMPTS` (5) → `parse_failed / max_attempts_exceeded`                                                                                                   |

### M13. Processing status and the hand-off to step 3.3

- Parse state lives in **`email_message_parses.status`**: `parsing → parsed | parsed_with_defects | parse_limit_exceeded | parse_failed`. The state before parsing is the step 2.2 `email_messages.status = received`, with no parse row. That is the brief's "persisted" state.
- Transitions are only ever `none → parsing` (insert), `parsing → parsing` (`attempts + 1`) and `parsing → final` (conditional update). A final row is never changed by this step.
- **`email_messages.status` is not changed** in this step. Under the step 2.3 dev pass-through, the delivery planner moves it to `delivery_queued` concurrently, and a parser write could regress it. Step 3.3 owns the message lifecycle. It will:
  1. append the parse states to `MessageStatus` (or keep this table as its stage record);
  2. define `received → parsing → parsed → scanning …`, with `parse_failed` and `parse_limit_exceeded` routed to policy (fail-safe quarantine);
  3. write `email_message_status_history` atomically.

  The 3.1 parse row, the `email_events` `parsed`/`parse_failed` row and the outbox events are its inputs.

- `structure` (JSON, ≤ `MIME_MAX_PARTS` entries) holds one object per node in document order: `{ index, path, parent, depth, contentType, multipart?, charset?, encoding?, disposition?, encodedBytes?, decodedBytes?, kind: 'container'|'text'|'html'|'attachment'|'message', truncated? }`. It never holds filenames or header values. Nested `message/rfc822` containers have `kind: 'message'`, and their children keep the structure below them.

### M14. Events

**`mail.message.parsed.v1`** (`messageParsedV1`), written by email-worker for `parsed`, `parsed_with_defects` and `parse_limit_exceeded`:

```ts
{
  messageId: decimalId, receivedAt: iso, direction,
  emlS3Key: 'org/<id>/…',
  parseStatus: 'parsed' | 'parsed_with_defects' | 'parse_limit_exceeded',
  parserVersion: string (1..32),
  limitsExceeded: MimeLimitName[] (≤ 16, unique),
  defects: string[] matching /^[a-z0-9_]{1,48}$/ (≤ 64),
  textBody: { s3Key: 'org/<id>/…' | null, sha256: hex64, sizeBytes: int ≥ 0 } | null,
  htmlBody: same | null,
  attachmentCount: int ≥ 0, flaggedAttachmentCount: int ≥ 0,
  attachmentFlags: string[] /^[a-z0-9_]{1,48}$/ (≤ 64, union over attachments),
  partCount: int ≥ 0, maxDepth: int ≥ 0, headerCount: int ≥ 0,
}
```

**`mail.message.parse_failed.v1`** (`messageParseFailedV1`):

```ts
{
  messageId, receivedAt, direction,
  emlS3Key: 'org/<id>/…' | null, // null only for an eml_key_mismatch whose key has no org/<id>/ prefix
  reason: 'eml_missing' | 'eml_key_mismatch' | 'integrity_mismatch' | 'max_attempts_exceeded' | 'parser_error',
  attempts: int ≥ 1, parserVersion,
}
```

- Both events carry ids, keys, hashes, codes and counts. **No address, subject, filename or header value.** Consumers (4.x) read `email_attachments` and `email_message_parses` from the writer.
- `event-contracts` exports `MIME_LIMIT_NAMES`, `MESSAGE_PARSE_STATUSES` and `PARSE_FAILURE_REASONS`, with `EventTypes.MessageParsed` and `EventTypes.MessageParseFailed`.
- `QUEUES` is **not** changed (3.2 adds bindings).
- `mime-parser` keeps its own copy of the limit names (it does not depend on event-contracts), and an email-worker unit test asserts that the two lists are equal.

### M15. Logging and redaction

- email-worker logs `{ eventId, messageId, organizationId, status, limitsExceeded, defects (codes), attachmentCount, bytes, durationMs, attempts, failureReason, errName, errCode }`. It **never** logs subject, filenames, addresses, header values, body bytes, S3 object content or parser error messages, and never logs `err` objects from the parser, S3 or the decoders.
- `packages/logger` `REDACT_PATHS` adds defence in depth, top level and `*.`: `subject`, `filename`, `originalFilename`, `envelopeFrom`, `headerFrom`, `headerValue`, `textBody`, `htmlBody`, `rawHeaders`, `payload.envelopeFrom`, `*.payload.envelopeFrom`. Existing log fields are checked by grep first: no current log call may lose a field it needs. `recipients`, `from` and `to` are **not** added, because they are used as counts and status names.
- **Tests prove it:** a parse of a fixture full of unique marker strings (subject, filename, From, body, a header value), including a failing parse and an infrastructure-error retry, runs with a captured pino destination, and no log line may contain any marker. A logger unit test asserts the new paths are censored.

### M16. Metrics (email-worker `GET /metrics`, `MetricsModule`)

| Series                                                                           | Meaning                                                                                                                         |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `mime_parse_messages_total{status}`                                              | Final outcomes (`parsed`, `parsed_with_defects`, `parse_limit_exceeded`, `parse_failed`) plus `duplicate` and `message_missing` |
| `mime_parse_duration_seconds` (histogram)                                        | Download to commit                                                                                                              |
| `mime_parse_bytes_total`                                                         | EML bytes read                                                                                                                  |
| `mime_limit_exceeded_total{limit}` / `mime_defects_total{defect}`                | Per code                                                                                                                        |
| `mime_parse_failures_total{reason}`                                              | parse_failed reasons                                                                                                            |
| `mime_attachments_total` / `mime_attachment_flags_total{flag}`                   | Attachments and their flags                                                                                                     |
| `mime_retries_total{class}`                                                      | Infrastructure retries (`s3`, `db`, `other`)                                                                                    |
| `mime_outbox_poll_lag_seconds{consumer}` / `mime_outbox_invalid_total{consumer}` | Feed (M2)                                                                                                                       |

Readiness stays `mysql`, `rabbitmq`, `redis`, `s3`. Redis is not used by the parse path. The ledger and the parse row are the truth, so no Redis dedupe cache is added.

### M17. Step 2.3 dev pass-through

It stays **unchanged**: `delivery-worker.dev-passthrough` keeps approving on `mail.message.received.v1`, independent of parsing (development only, documented). The routing stack suites must pass unchanged with the email-worker running. Switching the pass-through to `mail.message.parsed.v1` is a later decision of 5.x.

---

## 3. Data model (one forward migration `mime_ingestion`, WP1)

Created with `pnpm db:migrate:dev --create-only --name mime_ingestion`, then the SQL is hand-reviewed and adjusted: the `PARTITION BY` clause, `ALGORITHM=INSTANT` where possible, no FKs.

**New enum `MessageParseStatus`**: `parsing`, `parsed`, `parsed_with_defects`, `parse_limit_exceeded`, `parse_failed`.

**New table `email_message_parses`** (model `EmailMessageParse`, **PARTITIONED** by `RANGE COLUMNS(received_at)` monthly, created with `PARTITION pmax`, no FKs, registry entry `monthly('email_message_parses', 'received_at', 6, 'core')`):

| Column                                         | Type                                 | Notes                                                                      |
| ---------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------- |
| `id`                                           | BIGINT UNSIGNED AUTO_INCREMENT       | PK `(id, received_at)`                                                     |
| `received_at`                                  | DATETIME(3) NOT NULL                 | Copied from the message                                                    |
| `message_id`, `organization_id`                | BIGINT UNSIGNED NOT NULL             | Unique `(message_id, received_at)`; index `(organization_id, received_at)` |
| `status`                                       | `MessageParseStatus` NOT NULL        | Index `(status, updated_at)` (monitoring of stuck `parsing`)               |
| `attempts`                                     | SMALLINT UNSIGNED NOT NULL DEFAULT 0 | M3.4                                                                       |
| `parser_version`                               | VARCHAR(32) NOT NULL                 | `PARSER_VERSION`                                                           |
| `event_id`                                     | CHAR(36) NULL                        | Received event that started the parse                                      |
| `failure_reason`                               | VARCHAR(64) NULL                     | parse_failed reason                                                        |
| `limits_exceeded`, `defects`                   | JSON NULL                            | Arrays of codes                                                            |
| `part_count`, `attachment_count`               | SMALLINT UNSIGNED NULL               |                                                                            |
| `max_depth`                                    | TINYINT UNSIGNED NULL                |                                                                            |
| `header_count`                                 | INT UNSIGNED NULL                    |                                                                            |
| `bytes_read`, `decoded_bytes`                  | BIGINT UNSIGNED NULL                 |                                                                            |
| `text_body_object_key`, `html_body_object_key` | VARCHAR(512) NULL                    | NULL when no body or not stored                                            |
| `text_body_sha256`, `html_body_sha256`         | CHAR(64) NULL                        |                                                                            |
| `text_body_size_bytes`, `html_body_size_bytes` | INT UNSIGNED NULL                    |                                                                            |
| `text_body_charset`, `html_body_charset`       | VARCHAR(64) NULL                     | Declared charset (normalized)                                              |
| `structure`                                    | JSON NULL                            | M13; ≤ `MIME_MAX_PARTS` nodes                                              |
| `started_at`                                   | DATETIME(3) NOT NULL                 | Last attempt                                                               |
| `completed_at`                                 | DATETIME(3) NULL                     |                                                                            |
| `duration_ms`                                  | INT UNSIGNED NULL                    |                                                                            |
| `created_at`, `updated_at`                     | DATETIME(3)                          | Mutable row                                                                |

**`email_attachments`, new nullable columns** (`ALTER TABLE … ADD COLUMN …, ALGORITHM=INSTANT`; the table is partitioned, so no FK and the unique key is unchanged):

| Column               | Type                                                                    |
| -------------------- | ----------------------------------------------------------------------- |
| `part_path`          | VARCHAR(128) NULL                                                       |
| `depth`              | TINYINT UNSIGNED NULL                                                   |
| `disposition`        | ENUM('attachment', 'inline') NULL (Prisma enum `AttachmentDisposition`) |
| `encoded_size_bytes` | INT UNSIGNED NULL                                                       |
| `original_filename`  | VARCHAR(1024) NULL                                                      |
| `flags`              | JSON NULL                                                               |
| `archive_info`       | JSON NULL                                                               |

Docs comment on `parent_part_index`: still "for files extracted from archives" (4.2); 3.1 leaves it NULL.

**Unchanged:** `email_messages` (only `subject` and `attachment_count` values are written), `email_headers`, `email_events`, `message_outbox`, `message_idempotency`, `stream_cursors` (new cursor names only).

**Counts:** 71 tables, 19 partitioned. Verified on a throwaway schema `email_gateway_verify` per `docs/database/README.md`, never with `migrate reset` on the main schema. Then `pnpm db:migrate` and `pnpm db:partitions apply` on the main schema.

---

## 4. Contracts (summary)

| Contract                               | Producer → consumer                                                                     | Defined in                                                            |
| -------------------------------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `mail.message.received.v1` (unchanged) | smtp-adapter → email-worker (outbox poller; 3.2: queue `email-worker.message-received`) | `event-contracts/src/events.ts`                                       |
| `mail.message.parsed.v1` (new)         | email-worker → scanning (4.x), lifecycle (3.3)                                          | M14                                                                   |
| `mail.message.parse_failed.v1` (new)   | email-worker → lifecycle (3.3), policy (5.x)                                            | M14                                                                   |
| `EventFeed` / `OutboxPoller` (moved)   | `@email-gateway/common` → delivery-worker, email-worker                                 | M2                                                                    |
| S3 part keys                           | email-worker → 4.x scanners, archive (8.1)                                              | M11; `contracts.md` §11 row "Attachment part" becomes IMPLEMENTED 3.1 |
| `@email-gateway/mime-parser` API       | library → email-worker (4.2 may reuse sniffer and inspector)                            | M4                                                                    |
| REST/OpenAPI                           | **No change** (message APIs are step 6.1)                                               | —                                                                     |

---

## 5. Configuration (email-worker; `.env.example` section "MIME ingestion (step 3.1)")

All keys are validated in `apps/email-worker/src/config.ts` (zod, the cross-field rules of M5). No secrets are added. Defaults:

```
MIME_INGESTION_ENABLED=true
MIME_CONCURRENCY=4
MIME_OUTBOX_POLL_INTERVAL_MS=1000
MIME_OUTBOX_SAFETY_LAG_MS=120000
MIME_OUTBOX_BATCH_SIZE=100
MIME_OUTBOX_SHARDS=1
MIME_OUTBOX_MAX_HELD_SHARDS=1
MIME_RETRY_BASE_MS=1000
MIME_RETRY_MAX_MS=60000
MIME_MAX_ATTEMPTS=5
MIME_DB_TIMEOUT_MS=15000
MIME_S3_TIMEOUT_MS=30000
MIME_S3_PART_SIZE_BYTES=5242880
MIME_S3_QUEUE_SIZE=2
MIME_MEMORY_BUDGET_BYTES=268435456
MIME_MAX_MESSAGE_BYTES=53477376
MIME_MAX_DEPTH=10
MIME_MAX_PARTS=250
MIME_MAX_HEADERS=1000
MIME_MAX_HEADER_LINE_BYTES=32768
MIME_MAX_HEADER_BLOCK_BYTES=262144
MIME_MAX_ATTACHMENTS=100
MIME_MAX_ATTACHMENT_BYTES=26214400
MIME_MAX_BODY_BYTES=10485760
MIME_MAX_DECODED_RATIO=1.1
MIME_MAX_TOTAL_DECODED_BYTES=104857600
MIME_PARSE_TIMEOUT_MS=120000
MIME_MAX_STORED_HEADERS=200
MIME_FILENAME_MAX_CHARS=200
MIME_ARCHIVE_MAX_ENTRIES=1000
MIME_ARCHIVE_MAX_RATIO=100
MIME_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES=1073741824
MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES=8388608
```

The same values are appended to the local `.env` (no existing value or secret is changed). The compose `email-worker` service passes them with `${KEY:-default}`. The email-worker also reads the existing `DATABASE_URL`, `S3_*`, `REDIS_URL`, `RABBITMQ_*` and base keys.

---

## 6. Compose and infrastructure

- `docker-compose.yml` `email-worker`: add the `MIME_*` environment (§5). The healthcheck is unchanged. No new service or volume.
- `.env.example`: the new section after "Mail routing and delivery (step 2.3)".
- Kubernetes manifests, if present for email-worker under `infrastructure/`: add the same env keys with their defaults. Nothing else changes.
- Images are built **one at a time** (8 GB VM). The analytics and observability profiles are never started together with the apps profile.

---

## 7. Alternatives considered

| Alternative                                                       | Why not                                                                                                                                                                  |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Parse inside smtp-adapter before `250`                            | Lengthens every SMTP session; ties edge capacity to parse cost; the brief forbids moving the hot path                                                                    |
| `mailparser` (`simpleParser` or `MailParser`)                     | Buffers (simpleParser); text↔HTML conversion surface (XSS advisory in `textToHtml`), nodemailer address parser (ReDoS and recursion advisories); no depth or part limits |
| `postal-mime`                                                     | Buffers the whole message                                                                                                                                                |
| Hand-written MIME parser                                          | Forbidden by the brief; parser bugs are the main risk                                                                                                                    |
| `file-type` for sniffing                                          | ESM-only (CJS/node10 build); broad scope; 4.2 owns file-type detection                                                                                                   |
| Full archive listing by extraction, or `unzipper`/`adm-zip`       | Extraction is the bomb; adm-zip buffers; yauzl reads only metadata through random access                                                                                 |
| Parse inside the processOnce transaction (step 2.3 handler shape) | Holds a writer connection and an open transaction across seconds of S3 I/O; transaction timeouts under load                                                              |
| New `MessageStatus` values now                                    | Races with the dev pass-through planner and pre-empts 3.3                                                                                                                |
| Per-part rows in a new `email_mime_parts` table                   | 5–10 rows per message at 1M messages a day for data only the scanners use; the bounded JSON `structure` on the parse row is enough                                       |
| Copy the poller into email-worker                                 | Two diverging copies; the brief asks to factor it                                                                                                                        |
| A single non-sharded poller                                       | One active replica only; sharding plus in-replica concurrency keep the stage scalable until 3.2's competing consumers                                                    |

---

## 8. Risks and mitigations

| Risk                                                                               | Mitigation                                                                                                                                                                                                                                                            |
| ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A parser or decoder CVE                                                            | Exact pins, advisories checked on every bump (ADR-0022), limits outside the library, no rendering paths used, corpus tests                                                                                                                                            |
| A synchronous CPU loop inside a library ignores the `AbortSignal`                  | Streaming bounded by line and part limits; `attempts` poison guard after a crash; liveness probe restarts a hung process. A worker-thread sandbox is noted for 4.x                                                                                                    |
| S3 slow but alive → `parse_timeout` recorded for good mail                         | `MIME_PARSE_TIMEOUT_MS` defaults to 120 s; `MIME_S3_TIMEOUT_MS` (30 s, must be below it) bounds each S3 wait as an infrastructure retry; a parse timeout while stalled on S3 is retried as `S3Stalled` (M3.10); the metric per limit makes a wave of timeouts visible |
| Declared zip sizes lie                                                             | Flags are hints; overlap detection catches the Fifield bomb; 4.2 decompresses with hard limits                                                                                                                                                                        |
| Changing `PARSER_VERSION` shifts part indices → old objects orphaned on a re-parse | No re-parse in this step (final rows never change); a future re-parse deletes the message's `part/` prefix first (documented)                                                                                                                                         |
| Shard count change                                                                 | New shard cursors start at the minimum of the existing cursors (re-read, never skip); runbook note to delete old cursors                                                                                                                                              |
| A shard no replica runs (replicas × `MIME_OUTBOX_MAX_HELD_SHARDS` < shards)        | Never parsed, but not silent: pollers that do not hold a shard report its lag from its durable cursor (every 10 s), so `mime_outbox_poll_lag_seconds` grows; runbook sizing rule                                                                                      |
| A deterministic failure (data or contract error) retried forever, cursor frozen    | Only transient failures give their attempt back; others count toward `MIME_MAX_ATTEMPTS` and end `max_attempts_exceeded` (M3.10)                                                                                                                                      |
| Poller refactor breaks delivery-worker                                             | Names, cursors, locks and metrics unchanged; delivery-worker unit and integration suites and the 2.3 routing stack suites rerun                                                                                                                                       |
| Log redaction regresses an existing field                                          | Grep existing log calls before adding paths; logger tests                                                                                                                                                                                                             |
| Memory at concurrency × large messages                                             | Config refuses budgets above `MIME_MEMORY_BUDGET_BYTES`, counting every held shard; the large-message test checks the heap bound                                                                                                                                      |
| Outbox rows never pruned (no relay; the partition guard keeps unpublished rows)    | Unchanged from 2.3 (3.2's relay sets `published_at`)                                                                                                                                                                                                                  |

---

## 9. Test plan

**Fixture corpus** (`packages/mime-parser/test/fixtures/`, small files generated by `test/fixtures/generate.ts` and committed; `.gitattributes` marks them `-text` so CRLF survives; a test regenerates them in memory and asserts byte equality, which catches drift):

- missing boundary parameter;
- boundary never present;
- unterminated multipart (no closing delimiter);
- truncated base64 and invalid base64 characters;
- invalid quoted-printable;
- unknown CTE;
- unknown charset (`x-unknown`), mislabelled charset;
- garbage and binary input, empty file, headers only, no headers (starts with a blank line);
- NUL in headers;
- duplicate From and Subject;
- nested `message/rfc822` (2 levels, with attachments inside);
- deep nesting at the limit and the limit + 1 (generated, small);
- multiple attachments (≥ 5, mixed inline and attachment);
- inline image;
- multipart/alternative with text and HTML;
- HTML-only;
- a single-part `application/pdf` root;
- RFC 2047 B and Q in UTF-8, ISO-8859-1, Shift_JIS, KOI8-R, plus a broken encoded word;
- RFC 2231 continuations with charset and language (`filename*0*=UTF-8''…; filename*1*=…`);
- raw UTF-8 headers (RFC 6532);
- path-traversal filenames (`../../etc/passwd`, `..\\..\\win.ini`, `C:\\x.exe`);
- bidi RLO filename (`invoice\u202Efdp.exe`);
- zero-width characters;
- double extension `report.pdf.exe` and whitespace padding;
- reserved name `CON.txt`;
- over-long filename;
- header flood (> `MIME_MAX_HEADERS`) and an over-long header line;
- part flood (> `MIME_MAX_PARTS`).

**Generated at test time (never committed):**

- a large email near `MIME_MAX_MESSAGE_BYTES`, streamed from a generator (not built in memory), with a 20 MiB attachment;
- one over the size, attachment and body limits;
- a zip bomb: a deflated 200 MiB of zeros with yazl (ratio ≫ 100), an entry-count bomb (1 001 entries), an encrypted-flag zip (bit 0 set in the central directory) and an overlapping-entries zip (hand-patched central directory offsets);
- a nested archive (a zip containing a `.zip` and a `.tar.gz`);
- gzip with a large ISIZE.

**Unit tests (mime-parser):**

- every M5 limit at the limit (passes) and the limit + 1 (recorded name, `parse_limit_exceeded`, parse stopped or continued per M5, writer aborted);
- every M6 defect;
- every filename rule and flag;
- every sniffer row;
- every M10 flag;
- the error mapping: sink, `readRange` and input errors are rethrown; library errors become codes; the timeout becomes `parse_timeout`;
- the bounded-memory single-line body.

**Unit tests (common/outbox):** the existing delivery-worker poller tests moved, plus concurrency (the cursor equals the sequential result with out-of-order completion), sharding (MOD filter, cursor and lock names, minimum initial cursor, `maxHeldLocks`), failure backoff and `processOnceHandler`.

**Unit tests (email-worker):** config refusals (M5), key builder, the sink (abort leaves no object, mocked), the flow in M3 with fakes (missing message, final row, max attempts, key mismatch, pre-size limit, integrity mismatch, infrastructure error decrements attempts and rethrows), the event payloads validated by the schemas, the limit-names equality with event-contracts, and the log-redaction marker test (M15).

**Unit tests (logger):** the new redact paths.

**Integration tests** (`apps/email-worker/integration`, real MySQL writer, MinIO and Redis from `.env`; `it-mime-*` fixture organizations cleaned up afterwards; `globalSetup` pauses a live email-worker like the delivery-worker harness does):

- the corpus end to end: rows, S3 objects (SHA-256 of the downloaded object equals the row), the outbox event parsed by the schema, `email_events`, the decoded `email_messages.subject`;
- the large email;
- the zip bomb and the nested archive flags;
- **duplicate delivery**: the same event twice; two concurrent `handle` calls for the same event; a second event id for the same message; a re-read through the poller. Each gives exactly one parse row, the same header and attachment rows, one `parsed` `email_events` row, one outbox event and the same S3 objects (listing the message prefix);
- S3 unavailable (wrong bucket or endpoint for one run) → retried, `attempts` not consumed, no final row;
- a simulated crash (attempts preset to the maximum) → `max_attempts_exceeded`;
- a cross-tenant envelope (an `organizationId` that is not the row's) → no effect;
- the shared poller against the real outbox with shards 2 and concurrency 4.

**Stack test** (`tests/integration/mime-ingestion.test.ts`, gate = the step 2.2 SMTP stack plus a ready email-worker on `EMAIL_WORKER_HOST_PORT`):

1. `swaks` through `postfix:25` to a fixture domain, carrying a multipart message with text, HTML, an RFC 2231 Unicode-named attachment and an RFC 2047 subject.
2. Wait for the `email_messages` row (step 2.2), then for its `email_message_parses` row `parsed`.
3. Assert the header rows, attachment rows (sanitized and original filename, sniffed type, SHA-256 equal to the downloaded S3 object), body objects, the decoded subject, and one `mail.message.parsed.v1` outbox row parsed with `messageParsedV1`.
4. Run a malformed message through the same path → `parsed_with_defects`.

**Regressions:** the step 2.2 `smtp-*` and step 2.3 `routing-*` stack suites with the email-worker running, and the delivery-worker unit and integration suites. Full gate: `pnpm build`, `lint`, `typecheck`, `test`, `test:e2e`, `test:integration`, `format:check`, `db:status` clean, the migration verified on `email_gateway_verify`.

---

## 10. Not in scope

- RabbitMQ relay, queue bindings for the new events, DLQ and replay (3.2). The outbox poller stays the interim transport.
- Message lifecycle state machine, `MessageStatus` changes, `email_message_status_history` writes (3.3).
- Security engines, full file-type detection, archive extraction and recursive scanning, ClamAV, YARA, hash caches (4.x). The archive flags here are inputs to 4.2.
- URL extraction, HTML sanitization or rendering, text↔HTML conversion, address-list parsing of headers (4.3/4.4).
- Previews or snippets of bodies (no schema column).
- Re-parsing on a parser version change, re-parse API, deletion of a message's part prefix.
- Storing nested messages' headers in `email_headers`, or re-assembling nested `.eml` objects.
- Changing the dev pass-through trigger (5.x).
- REST endpoints for parse results (6.1) and portal views (7.x).
- A worker-thread or sandbox isolation of the parser (noted in §8 for 4.x).

---

## 11. Work packages

Three sequential waves. Packages in one wave touch disjoint files. **Only WP2 runs `pnpm install` and changes `pnpm-lock.yaml` or any `package.json` dependency list in this step.** Later packages report a missing dependency instead of installing it.

| Wave | Package | Scope                                                                                                                                                                                                                     |
| ---- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | WP1     | Migration `mime_ingestion`, `schema.prisma`, partition registry, `event-contracts` events, `logger` redaction, schema and partition tests, `docs/database/*`, `docs/architecture/contracts.md`, `data-ownership.md`       |
| 1    | WP2     | New package `packages/mime-parser` (parser, limits, defects, headers, filenames, sniffer, archive inspection, corpus, unit tests), `.gitattributes`, all dependency additions (including email-worker's) and the lockfile |
| 1    | WP3     | Shared outbox feed in `packages/common/src/outbox` (+ `index.ts`), delivery-worker migrated to it (old files deleted, tests moved), delivery-worker README                                                                |
| 2    | WP4     | email-worker `MimeIngestionModule`: config, consumer, S3 sink, repository, metrics, wiring, unit and integration tests, README, `.env.example`, local `.env`, compose env, root `package.json` `test:integration`         |
| 3    | WP5     | Stack test, step 2.2 and 2.3 regressions, full gate, docs (README, execution plan, overview, failure handling, security boundaries, diagrams), §12 verification record                                                    |

## 12. Verification results

§12.1 is WP4's record of the email-worker. §12.2 is the closing record (WP5): the stack test, the regressions, the full gate, the migration verification, the deviations of every package and what is not verifiable locally.

### 12.1 WP4: email-worker MIME ingestion (verified on 2026-11-03)

**What was built:** `apps/email-worker/src/mime-ingestion/` contains these components (see the
[email-worker README](../../../apps/email-worker/README.md)):

- config: the 33 `MIME_*` keys of §5 and the M5 refusals in `src/config.ts`;
- the part key builder and `S3PartSink` (lib-storage `Upload`);
- `S3EmlSource`, `MimeRepository` (writer only) and `MimeIngestionService` (M3);
- `MimeMetrics` (M16) and `MimeIngestionModule` (a `ShardedOutboxFeed`, `MimeIngestionRuntime`).

The configuration is in `.env.example` (section "MIME ingestion (step 3.1)"), the local `.env`
(appended, with no existing value changed), the `docker-compose.yml` `email-worker` environment
and `infrastructure/kubernetes/base/email-worker.yaml`. The root `test:integration` script now
also runs the email-worker suites.

**Checks run** (all passed):

| Command                                                      | Result                                      |
| ------------------------------------------------------------ | ------------------------------------------- |
| `pnpm build`                                                 | 18/18 tasks                                 |
| `pnpm lint`, `pnpm typecheck`                                | 27/27 tasks each                            |
| `pnpm test`                                                  | 26/26 tasks; email-worker: 49 unit tests    |
| `pnpm --filter @email-gateway/email-worker test:integration` | 15 tests against the MySQL writer and MinIO |
| `pnpm format:check`                                          | clean                                       |

The integration suites cover:

- the 35-file mime-parser corpus;
- a multipart message with RFC 2047 and RFC 2231 names;
- the zip bomb (200 MiB of zeros, deflated with yazl) and a nested archive;
- the size, attachment and body limits;
- `eml_missing`, `eml_key_mismatch` and `integrity_mismatch`;
- an S3 outage (attempts back at 0, no final row, then parsed with `attempts = 1`);
- the poison guard (attempts preset to 5 → `max_attempts_exceeded`, attempts 6);
- a cross-tenant envelope;
- duplicate delivery: the same event twice, two concurrent handles, two workers with different
  event ids, a second event id, and a poller re-read through a fresh `OutboxPoller` inside the
  safety lag;
- `ShardedOutboxFeed` with 2 shards and concurrency 4 on the real outbox.

The fixture organizations, ledger rows, cursors and S3 prefixes were removed afterwards (checked:
0 `it-mime-*` organizations, cursors or ledger rows left).

**Large email:** 53.0 MB (20 MiB and 17 MiB base64 attachments), streamed to MinIO from a
generator and parsed in about 1.5 s. Live memory growth was sampled after forced GCs
(`--expose-gc`). Three runs measured 0.2 MB to 18.5 MB. The test asserts < 32 MiB.

**Host run:** `HTTP_PORT=3021 pnpm --filter @email-gateway/email-worker dev` reported
`/health/ready` `ok` (mysql, rabbitmq, redis, s3). From `oldest` it parsed the 18 retained
`mail.message.received.v1` rows of the local database (all `parsed`). It then parsed a fixture
written to `message_outbox` end to end:

- parse row `parsed` with `attempts = 1`;
- 1 attachment row and 3 part objects;
- the decoded subject;
- a schema-valid `mail.message.parsed.v1`;
- a ledger row for `email-worker.mime-parser`.

`/metrics` showed `mime_parse_messages_total{status="parsed"} 19` and
`mime_outbox_poll_lag_seconds 0`. The run logged no warn or error lines. The fixture was cleaned
up and the host process stopped.

**Deviations and notes (WP4):**

- The poller's handler and the 3.2 consumer treat `MimeIngestionService.handle` as a staged
  handler (M2). A duplicate found at M3.3, at `markParsing` or by `AlreadyFinalized` also writes a
  ledger row (`recordNoop`), so a later re-read stops at the M3.1 pre-check.
- Integrity (M3.8): when the parser stopped reading early (`message_size` or `parse_timeout`,
  `inputComplete = false`), only `bytesRead > size_bytes` can be detected. The hash cannot be
  compared for a partial read.
- When the download itself outlives `MIME_PARSE_TIMEOUT_MS`, the GET's abort counts as the parse
  timeout. The parser records `parse_limit_exceeded ['parse_timeout']`, not an infrastructure
  retry.
- `S3PartWriter.abort` aborts the upload (no `PutObject`, or `AbortMultipartUpload`). It does not
  delete an object an earlier attempt may have left at the same key. Deleting it could remove an
  object that a concurrent winner's committed row references.
- Integration fixtures insert recipients as `discarded`, not `pending`. The running
  delivery-worker has the step 2.3 dev pass-through enabled and would otherwise plan deliveries
  for the fixture `mail.message.received.v1` rows. The MIME stage never reads recipients.
- `apps/email-worker/tsconfig.json` now includes `integration`, so typecheck and lint cover the
  suites. `tsconfig.build.json` excludes `src/**/*.test-support.ts` (the unit-test fakes).
- Not verified here: the container image with this code. It was not rebuilt, and the running
  `email-worker` container is the phase-0 image. The stack test and the regressions are WP5's.

### 12.2 WP5: stack test, regressions, full gate (verified on 2026-11-03)

**Runtime used.** Every suite below ran against the Compose stack with these app containers. The
three images were rebuilt from this tree, one at a time
(`docker compose --profile apps build <service>`, then `up -d --wait --no-deps <service>`):

- `email-worker`: the step 3.1 code, `MIME_INGESTION_ENABLED=true`;
- `delivery-worker`: the WP3 migration to the shared outbox feed, with
  `DELIVERY_DEV_PASSTHROUGH_ENABLED=true`;
- `smtp-adapter`: the new `logger` redaction paths and `common`.

The other app containers (`api`, `admin-portal`, `policy-engine`, `notification-worker`,
`archive-worker`) were not rebuilt. Step 3.1 changes none of their code; only the shared `logger`
and `common` packages changed under them. The local `.env` has
`SMTP_ADAPTER_HOST=host.docker.internal`; the gate's socketmap probe from `postfix` confirmed that
Postfix reached the adapter.

**Stack test** `tests/integration/mime-ingestion.test.ts`:

- The gate, `support/mime-stack.ts`, is `smtpStackGate` plus an email-worker that answers
  `/health/ready` on `EMAIL_WORKER_HOST_PORT` and exports `mime_parse_messages_total` on
  `/metrics`. The metrics check catches a phase-0 image, which is also "ready". Missing pieces fail
  the suite with an explanation, and only `SMTP_STACK_TESTS=skip` skips it. This was checked by
  stopping the email-worker: the suite failed with "email-worker is not ready on 127.0.0.1:3020".
- Scenario 1: swaks from smtp-tools to `postfix:25` sends a fixture domain a multipart/mixed
  message. It has an RFC 2047 UTF-8 subject, a QP text body, an HTML body and a PDF attachment with
  the RFC 2231 UTF-8 filename `C:\Users\Finanz\Größe – Bericht.pdf`. The test waits for the step
  2.2 `email_messages` row, then for the final `email_message_parses` row, and asserts:
  - `parsed`, `attempts = 1`, no limits or defects, `bytes_read = size_bytes`, and `event_id`
    equal to the received outbox event;
  - the decoded `email_messages.subject`, `attachment_count = 1`, and the ingestion fields
    unchanged;
  - `email_headers`: allow-list names only, `seq` 0..n-1, no `Received`, the decoded Subject, and
    the From, To and Message-ID values;
  - text and HTML objects under `org/{org}/part/yyyy/mm/dd/{messageId}/{n}.text|.html`. Their
    SHA-256 and size equal the row, and the content is decoded (`Hello ✓ MIME stack.`);
  - the attachment row: filename `Größe – Bericht.pdf`, `original_filename`
    `C:\u{005C}Users\u{005C}Finanz\u{005C}Größe – Bericht.pdf`, flag `filename_path_stripped`, and
    declared and detected `application/pdf`. Its SHA-256 equals the SHA-256 of the object
    downloaded from MinIO, and the object's bytes are the PDF. The key ends in `.att` and holds no
    filename;
  - the org prefix holds exactly the EML and the three part objects;
  - one email-worker `email_events` row `parsed`, linked to the outbox event;
  - exactly one `mail.message.parsed.v1` row. It parses with `messageParsedV1`, carries the body
    keys, hashes and sizes, and has the correlation id of the received event. Its JSON holds none of
    the sender, recipient, domain, subject or filename strings;
  - the consumer's ledger row.
- Scenario 2: a multipart message without its closing delimiter and with invalid base64 goes
  through the same path. It ends `parsed_with_defects`, with `missing_closing_boundary` and
  `invalid_base64` on the row and in the event. The text body and the broken attachment are still
  stored and match their hashes.
- Cleanup: the fixture organizations, including their parse, header, attachment, event, outbox and
  ledger rows, and the org S3 prefix (EML and parts).

**Regressions and package suites** (all passed, nothing skipped unless stated):

| Command                                                               | Result                                                                                                                                                                                                                                |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm --filter @email-gateway/integration-tests run test:integration` | 26 files, **177 tests passed, 0 skipped** (567 s): every step 2.2 `smtp-*` suite (incl. `smtp-concurrency` and the MinIO/Redis/Postfix outages), every step 2.3 `routing-*` suite, `mime-ingestion` (2) and the infrastructure suites |
| `pnpm --filter @email-gateway/delivery-worker test`                   | 16 files, 102 tests (the poller, lock and helper tests moved to `common` in WP3)                                                                                                                                                      |
| `pnpm --filter @email-gateway/delivery-worker test:integration`       | 5 files, 33 tests                                                                                                                                                                                                                     |
| `pnpm --filter @email-gateway/email-worker test`                      | 7 files, 49 tests                                                                                                                                                                                                                     |
| `pnpm --filter @email-gateway/email-worker test:integration`          | 2 files, 15 tests                                                                                                                                                                                                                     |

During the first stack run the email-worker parsed every message the suites ingested:
`mime_parse_messages_total` was `parsed` 881 and `parsed_with_defects` 1, with no
`parse_failed`, no `message_missing`, no retries and no warn or error log line. Afterwards no
parse, header or attachment row was left without its message, and no fixture organization of the
run was left. One `it-smtp-…-closed` organization created at 12:13 UTC, before this run, is left
over from an earlier run and was not touched.

**Full gate from the root** (2026-11-03, in this order, all exit 0):

| Command                 | Result                                                                                                                                                                                                                                                                      |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm build`            | 18/18 tasks                                                                                                                                                                                                                                                                 |
| `pnpm lint`             | 27/27 tasks                                                                                                                                                                                                                                                                 |
| `pnpm typecheck`        | 27/27 tasks                                                                                                                                                                                                                                                                 |
| `pnpm test`             | 26/26 tasks, 2 351 tests: api 1 173, smtp-adapter 330, mime-parser 231, mail-routing 143, database 128, delivery-worker 102, common 89, email-worker 49, logger 38, config 33, event-contracts 30, admin-portal 2, archive-worker 1, policy-engine 1, notification-worker 1 |
| `pnpm test:e2e`         | 10/10 tasks, api 205                                                                                                                                                                                                                                                        |
| `pnpm test:integration` | stack 177 (26 files, 0 skipped), api 214 + 1 skipped (the existing container-only case in `common.test.ts`), smtp-adapter 65, mail-routing 16, delivery-worker 33, email-worker 15                                                                                          |
| `pnpm format:check`     | clean (after `pnpm format`)                                                                                                                                                                                                                                                 |
| `pnpm db:status`        | 9 migrations, "Database schema is up to date!"                                                                                                                                                                                                                              |

**Migration verification** (re-run by WP5 on a throwaway schema, per
[docs/database/README.md](../../database/README.md#clean-schema-verification)):

1. Root created `email_gateway_verify` and granted it to the migrator.
2. `prisma migrate deploy` applied all 9 migrations, ending with `20261103200000_mime_ingestion`.
3. `dist/partitioning/cli.js apply` reported `ok: true`, 19 partition actions and 0 errors.
4. `prisma migrate diff --from-url <verify> --to-schema-datamodel prisma/schema.prisma --exit-code`
   reported "No difference detected" (exit 0).
5. Counts: **71 tables, 19 partitioned**, `email_message_parses` with 5 partitions after
   maintenance, and the 7 new `email_attachments` columns present.
6. The schema was dropped and the grant revoked. `SHOW DATABASES LIKE 'email_gateway_verify'` is
   empty. The main schema was never reset.

**Changes made by WP5 outside the new suite.** Every change is to test code in `tests/`; no
production code was changed:

- `tests/integration/support/smtp-fixtures.ts`:
  - `cleanup()` also deletes the step 3.1 rows of the fixture organizations (`email_attachments`,
    `email_headers`, `email_message_parses`, and the parse events and outbox rows, also in the
    second pass), and the `message_idempotency` rows of the run's outbox events;
  - new `emlObjectKeys(org)` lists the `org/{id}/eml/` keys only.

  Without these changes, a running email-worker would leave parse rows behind and add part
  objects to the org prefixes.

- Step 2.2 suites, adjusted the same way step 2.3 adjusted them for the delivery-worker's rows.
  They still assert exactly what ingestion wrote:
  - `smtp-concurrency.test.ts` and `smtp-durability.test.ts` count EML objects with
    `emlObjectKeys`, because every parsed message adds at least one `part/` object;
  - `smtp-inbound.test.ts` suite 1 also excludes `mail.message.parsed.v1` and
    `mail.message.parse_failed.v1` from its "exactly one ingestion outbox row" query, as it already
    did for `mail.delivery.*`.

  No assertion was removed or loosened beyond excluding the email-worker's own rows.

- New `tests/integration/support/mime-stack.ts` (the gate) and `tests/integration/support/mime.ts`
  (message builders, parse-state reads). No dependency was added to the tests package.

**Defects found in other packages:** none. No fix to production code was needed.

**Deviations from this note** (all keep the invariants of §2.0):

- WP2, `@email-gateway/mime-parser`. Details are in the
  [package README](../../../packages/mime-parser/README.md#deviations-from-the-design-documented-as-required-by-0):
  - QP is decoded with `libqp.decode` over line-aligned batches, because libqp 3.0.1's `Decoder`
    buffers the whole part. Base64 uses `libbase64.decode` over quartet-aligned input, so invalid
    input can be counted;
  - `defaultInlineEmbedded: true`, so a `message/rfc822` part without a disposition is parsed as
    a nested message. One with `attachment` disposition or a base64/QP encoding stays a single
    leaf;
  - yauzl runs with `decodeStrings: false`, so `archive_path_traversal` is not masked by yauzl's
    own rejection, and names are judged from the raw bytes;
  - `missing_closing_boundary` comes from one delimiter scanner over all open multiparts;
  - additional flags `filename_zero_width` and `original_filename_truncated`, and an additional
    stat `inputComplete`. ISO-2022-JP bodies get `unknown_charset`;
  - `part_path` could exceed `VARCHAR(128)` only with `MIME_MAX_DEPTH` above about 30 (closed in the review round, §12.4: config refusal plus a parser cap).
- WP4, email-worker: §12.1 "Deviations and notes". In short: duplicates found at M3.3,
  `markParsing` or `AlreadyFinalized` also write a ledger row. Integrity can compare only
  `bytesRead > size_bytes` after an early stop. A download that outlives `MIME_PARSE_TIMEOUT_MS`
  counted as `parse_timeout` (changed in the review round, §12.4: it is now an `S3Stalled` retry). `abort` never deletes an object an earlier attempt left. The
  integration fixtures use `discarded` recipients.
- WP1 and WP3 reported no deviation in the docs they own. The migration, the events and the
  delivery-worker migration match §3, M14 and M2. The delivery-worker keeps its cursor, lock and
  metric names, and its suites and the 2.3 routing suites pass unchanged.
- WP5: the stack gate also requires the `mime_*` series on `/metrics`, not only readiness.

**OpenAPI:** unchanged. Step 3.1 adds no REST endpoint (message APIs are step 6.1), so
`docs/api/openapi.json` is untouched.

**Docs updated by WP5:**

- the [README](../../../README.md): status, the step 3.1 env section and the append command, how to
  run the stage, stack and package test commands, layout and links;
- the [execution plan](../execution-plan.md) row 3.1;
- [overview](../../architecture/overview.md): service rows 5 and 6, the mail-path diagram, the
  post-queue text, the step 3.1 section and "Not built yet";
- [failure handling](../../architecture/failure-handling.md): the "email-worker MIME ingestion"
  section, the S3 row, cross-cutting rows and alerts;
- [security boundaries](../../architecture/security-boundaries.md): "Untrusted message content",
  the redaction row, the object-key row and known gaps;
- the [security README](../../security/README.md);
- diagram [20 (new)](../../architecture/diagrams/20-mime-ingestion-sequence.md) and diagrams 2, 3
  and 6, plus the diagram index;
- the new runbook [mime-ingestion](../../runbooks/mime-ingestion.md): stuck `parsing` rows, cursor
  reset, shard-count change and `parse_failed` triage.

**Not verified (not verifiable locally, or not run):**

- the commit (pending), and a CI run of the new and adjusted suites;
- the images of `api`, `admin-portal`, `policy-engine`, `notification-worker` and
  `archive-worker`, which were not rebuilt with the new `logger`/`common`;
- throughput at the design target (1M messages/day, 300 msg/s bursts) with several sharded
  email-worker replicas: only the 2-shard, concurrency-4 integration case and the
  40 × 1 000-message SMTP run, which the worker parsed alongside, were exercised;
- AWS S3 with SSE-KMS, throttling and real network latency (MinIO only), and Kubernetes liveness
  restarts of a hung parse;
- a worker-thread or sandbox isolation of the parser, which is not built (§8, §10; noted for 4.x).

The RabbitMQ transport (3.2), the lifecycle transitions (3.3) and the consumers of the parse
events (4.x) are out of scope (§10).

### 12.3 Verification round 1 (independent re-run, 2026-11-03)

An independent verification re-ran every check from a clean turbo cache (`--force`) in this
order. All passed after the one fix below.

| Command                                                          | Result                                                                                                                                                                               |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm install --frozen-lockfile`, `pnpm db:generate`             | lockfile up to date, client generated                                                                                                                                                |
| `pnpm db:migrate`, `pnpm db:status`                              | 9 migrations, nothing pending, "Database schema is up to date!"                                                                                                                      |
| `prisma migrate diff` main schema ↔ `schema.prisma`              | "No difference detected"                                                                                                                                                             |
| clean schema `email_gateway_verify` (§12.2 procedure)            | 9 migrations applied; partitions `apply` 19 actions, second `apply` 0; drift check exit 0; 71 tables, 19 partitioned, `email_message_parses` 5 partitions; dropped and grant revoked |
| `pnpm format:check`                                              | clean                                                                                                                                                                                |
| `pnpm lint`, `pnpm typecheck`                                    | 27/27 tasks each                                                                                                                                                                     |
| `pnpm test`                                                      | 26/26 tasks, 2 351 tests (same per-package counts as §12.2)                                                                                                                          |
| `pnpm test:e2e`                                                  | 10/10 tasks, api 205                                                                                                                                                                 |
| `pnpm build`                                                     | 18/18 tasks                                                                                                                                                                          |
| `pnpm test:integration`                                          | stack 26 files, 177 passed, 0 skipped (565 s); api 214 + 1 skipped; smtp-adapter 65; mail-routing 16; delivery-worker 33; email-worker 15                                            |
| `pnpm --filter @email-gateway/smtp-adapter run test:integration` | after the fix: 65 passed (twice), no residue                                                                                                                                         |

**Runtime.** Images rebuilt one at a time from this tree: `db-migrate` (it carries the new
migration), `email-worker`, `delivery-worker`, `smtp-adapter`, `api`, `policy-engine`,
`notification-worker` and `archive-worker` (all depend on the changed `logger`/`common`;
`admin-portal` does not). The apps and smtp-test profiles were brought up with
`SMTP_ADAPTER_HOST=smtp-adapter` set temporarily in `.env` (both Postfix containers resolved the
adapter as `smtp-adapter`). `.env` was restored afterwards and is byte-identical to its backup.
`clamav` had been OOM-killed during the image builds and was restarted (volume kept). During the
run the email-worker counted `parsed` 375, `parsed_with_defects` 1 and `duplicate` 4, no
`parse_failed`, no warn or error log line.

**Defect found and fixed (test code only).** The smtp-adapter integration suite ingests real
messages (EML in MinIO, `mail.message.received.v1` in the outbox), so the running email-worker
parses them. Its fixture cleanup did not know the step 3.1 rows: every run left 12 parse rows and
72 header rows without their message, plus `email-worker.mime-parser` ledger rows (the 13:35 UTC
WP5 run and this run each left two such organizations). Two of its assertions also counted the
email-worker's rows by timing luck. Fix in `apps/smtp-adapter/integration/`:

- `support/fixtures.ts`: `cleanup()` deletes the parse, header and attachment rows, the
  email-worker's events and outbox rows and the consumer ledger rows of the run's outbox events,
  and runs a second pass after 1.5 s for in-flight email-worker or delivery-worker commits. New
  `emlObjectKeys()` and `EMAIL_WORKER_EVENT_TYPES`, as in `tests/integration/support/smtp-fixtures.ts`.
- `ingestion.test.ts`: the "exactly one event / outbox row" checks exclude only the
  email-worker's own rows (`sourceService` `email-worker`, the two parse event types), and the
  redelivery check compares the EML objects only. Nothing else was relaxed.

**Cleanup done** (checked afterwards: 0 `it-*` organizations, plans, domains, ledger consumers or
cursors; 0 parse, header or delivery rows without their message; both Postfix queues empty):

- the residue of the smtp-adapter suite above, and four `email_deliveries` rows (with their
  reinjection, status and history rows) of the WP5 run's organization 5095;
- the `it-smtp-87f25e8c-closed` organization of an earlier run, with its plan, 2 domains, DKIM key
  row and SMTP connector; 7 ledger rows of consumer `it-f75fd495.planner`; 53
  `email-worker.mime-parser` ledger rows whose outbox event no longer exists;
- 9 EML objects in MinIO under the prefixes of five deleted organizations (2814, 2815,
  3472–3474);
- **the api `common.test.ts` probe** (`SmtpEmailSender against the Compose Postfix`). Each api
  integration run sends `probe@gateway.test` through the local MX. `gateway.test` is a domain of
  the demo organization, so the probe becomes a real message of organization 2: an
  `email_messages` row with recipients, events, outbox rows (received, parsed, delivery approved
  and status changes), deliveries planned by the dev pass-through, a parse row and headers, an EML
  and a part object, and a deferred copy in `postfix-outbound` (`mail.gateway.test` does not
  resolve). This run removed 2 deferred queue entries and the 19 probe messages accumulated since
  2026-11-02 (all their rows and 38 objects). The probe itself is unchanged (step 2.3 known item);
  every api integration run adds one such message again.

**Left as is:** one demo-organization message `persist-1793635548` (sender `sender@example.org`,
2026-11-02 16:06 UTC, from an earlier step 2.2 run; not an `it-*` fixture). Short-lived
`sa:dom:it-*` cache keys in Redis expire within seconds. `redis-dkim` could not be scanned with
the writer ACL.

**Open items (not changed by this round):** the `eml_key_mismatch` contract edge case (an EML key
without any `org/<n>/` prefix cannot be published and would be retried; fixed in §12.4); the api
`log-email-sender.ts` subject now redacted by the logger; the commit and CI run; the items of §12.2
"Not verified".

### 12.4 Review round (correctness, security and completeness findings, 2026-11-03)

Eight medium-or-higher findings were checked against the code. Seven were real and are fixed
with tests; one (relay) is a scope statement and is answered in the docs.

| Finding                                                                                                          | Verdict and fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Every exception gave its attempt back, so deterministic failures retried forever (high)                          | Real. `isTransientFailure` (`error-fields.ts`) now decides: S3 service errors, network/timeout errors, `S3Stalled`/`UploadTimedOut`, Prisma connection, pool, transaction-API and write-conflict codes give the attempt back; everything else (P2000, a contract `ZodError`, an unexpected exception) keeps it, so `MIME_MAX_ATTEMPTS` ends the message as `max_attempts_exceeded`. Unit tests: P2000 three times then the guard, `TypeError`; log line carries `transient`                                                                                                |
| `eml_key_mismatch` with a key that has no `org/<n>/` prefix fails the payload schema and loops (medium ×2)       | Real. `mail.message.parse_failed.v1` `emlS3Key` is now `s3Key.nullable()`; `buildParseFailedPayload` carries `null` for a key the contract refuses. Tests: event-contracts, payloads (`eml/x.eml`, `org/0/…`, `/org/7/…`, empty), service, and an integration case that rewrites the writer row's key to `eml/it/…` and gets one final row and one valid event                                                                                                                                                                                                             |
| `part_path` can exceed `VARCHAR(128)` under accepted limits (medium)                                             | Real. Config refuses `1 + MIME_MAX_DEPTH × (1 + digits(MIME_MAX_PARTS − 1)) > 128` (depth 32 with 1 000 parts is refused; 31 is the maximum). The parser stops as `nesting_depth` before a path longer than `MAX_PART_PATH_CHARS` (128). Parser tests build 42 and 45 levels of 10 siblings (paths of 127 and 130 characters). `PARSER_VERSION` is not bumped: the output changes only for inputs that could never be recorded before                                                                                                                                      |
| A hung S3 call became a `parse_timeout` verdict; `MIME_S3_TIMEOUT_MS` < parse budget cut slow parses (medium ×2) | Real (both). `MIME_S3_TIMEOUT_MS` now bounds each single wait on S3 (`s3-waits.ts` `withStallTimeout` for the body, per-wait timer in `S3PartWriter`), default 30 s, and must be below `MIME_PARSE_TIMEOUT_MS`. The service tracks S3 waits (`S3WaitTracker`); a parse timeout while an S3 call was pending ≥ `min(1 s, budget/4)`, or after half the budget went to S3, is an `S3Stalled` retry. Tests: stalled body, hung GET, stalled part write (retry, attempt back), slow parse with no S3 wait (verdict kept), slow consumer never timed out, sink per-wait timeout |
| A shard no replica runs reported lag 0 (medium)                                                                  | Real. A poller that does not hold its shard reports that shard's lag from its durable cursor (every 10 s at most). Unit tests (maxHeld reached, held elsewhere, no cursor, probe throttle) and an integration case against MySQL (2 shards, maxHeld 1: gauge > 200 s for a 300 s old row)                                                                                                                                                                                                                                                                                  |
| The memory refusal ignored sharding (medium)                                                                     | Real. `parseMemoryBytes` = `MIME_CONCURRENCY × MIME_OUTBOX_MAX_HELD_SHARDS × (part size × (queue + 1) + MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES)`. Tests: 4 × 8 × 23 MiB refused, 4 × 2 accepted                                                                                                                                                                                                                                                                                                                                                                          |
| The parse events are written, not published (medium)                                                             | Not a code defect: the relay is step 3.2 by design (§10). The README, the email-worker README and the execution plan now say explicitly that the events are written to `message_outbox` only, nothing publishes or consumes them and `published_at` stays null until 3.2                                                                                                                                                                                                                                                                                                   |

**Configuration change:** the default of `MIME_S3_TIMEOUT_MS` is now 30 000 (`.env.example`,
Compose, Kubernetes); an existing `.env` with 120 000 is refused at startup and was changed in the
local `.env`.

**Final gate (2026-11-03, after the fixes):** `pnpm install --frozen-lockfile`; `db:generate`;
`db:migrate` (9 migrations, nothing pending); `db:status` up to date; `prisma migrate diff` main ↔
schema "No difference detected" (no schema change in this round); `format:check` clean;
`lint --force` 27/27; `typecheck --force` 27/27; `test --force` 26/26 tasks, 2 378 tests (api
1 173, smtp-adapter 330, mime-parser 233, mail-routing 143, database 128, delivery-worker 102,
common 92, email-worker 70, logger 38, config 33, event-contracts 31, others 5); `test:e2e
--force` api 205; `build --force` 18/18; the 8 app images rebuilt one at a time; stack recreated
with the adapter in its container; `pnpm test:integration`: stack 26 files / 177 passed, api 214

- 1 skipped, smtp-adapter 65, mail-routing 16, delivery-worker 33, email-worker 17. The first
  integration attempt failed 2 ClamAV tests in `mail-plane.test.ts` because clamd was OOM-killed on
  the 8 GB VM (unrelated to this step); clamd was restarted (RabbitMQ stopped for its load, then
  started again) and the whole integration run was repeated green. During the green run the
  email-worker container parsed 940 messages (1 with defects, 4 duplicates), no parse_failed, no
  retries, lag 0, no warn or error log line. Residue afterwards: no `it-*` organizations, cursors or
  ledger rows, no orphan parse, header or delivery rows, no row left `parsing`. One deferred
  `postfix-outbound` entry is the known api probe (§12.3).
