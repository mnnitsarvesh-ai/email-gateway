# Step 3.2: RabbitMQ event-driven processing architecture

Status: **implemented and verified locally (§13, 2026-11-04); review round 1 findings (F1–F5) fixed and the full gate re-run green (§14)**: WP1–WP5 done, full gate green, stack chaos suites, the 3-node node-failure test and the step 2.2/2.3/3.1 regressions passing through the broker. **Not complete:** the commit is pending, CI has not run, and the items of §13.8 (production broker, TLS, Kubernetes, 1 M/day throughput) cannot be verified locally. Owner: principal architect. Decision records: [ADR-0023](../../architecture/adr/0023-outbox-relay-and-reconciliation.md) (outbox relay and reconciliation in a dedicated `event-relay` deployable; amends ADR-0002) and [ADR-0024](../../architecture/adr/0024-rabbitmq-topology-retry-dead-letter.md) (topology v1, tenant routing keys, retry, dead-letter, replay, least privilege, client library; **supersedes ADR-0005**, carrying its outbox, ledger and envelope decisions forward).

This note is the single source of truth for the implementers of this step. It builds on step 2.2 ([04-smtp-gateway.md](04-smtp-gateway.md), `b793683`), step 2.3 ([05-routing.md](05-routing.md), `6c6497c`) and step 3.1 ([06-mime-ingestion.md](06-mime-ingestion.md), `05c1465`); their decisions stay in force unless a decision below names them. If a decision proves impossible (for example a broker feature behaves differently from what is assumed here), the implementer:

- documents the deviation in the docs their package owns and in their final report;
- picks the closest alternative that keeps the **invariants of §2.0**.

**Nobody silently changes a decision.** Section numbers (§) and decision ids (Q*n*) are stable references.

---

## 1. Starting point (inspected, commit `05c1465`)

| Area             | Current state                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Producers        | Every producer writes `message_outbox` in its writer transaction: smtp-adapter `mail.message.received.v1`; email-worker `mail.message.parsed.v1` / `parse_failed.v1`; delivery-worker dev pass-through and (later) policy `mail.delivery.approved.v1`; the shared recorder `mail.delivery.status_changed.v1`; api `domain.status.changed.v1` / `domain.routing.changed.v1`. Payloads are zod-validated before insert. **Nothing publishes**: `published_at` is NULL on every row (local DB: ~3.5 k rows), so the partition-drop guard (`no-null-rows published_at`) never drops a `message_outbox` partition.                                                                                                                                                                                                     |
| `message_outbox` | Partitioned daily by `created_at` (retention 7, drop guarded), PK `(id, created_at)`, index `(published_at, id)`, columns `event_id`, `organization_id`, `event_type`, `aggregate_type`, `aggregate_id`, `correlation_id`, `payload` (JSON), `available_at`, `published_at`, `attempts`, `last_error` (VARCHAR 1024). No unique on `event_id`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Ledger / cursors | `message_idempotency (consumer, event_id)` PK, written by `processOnce` in the effect transaction. `stream_cursors (name PK, position_id, …)`. Local ledger consumers: `delivery-worker.dev-passthrough`, `delivery-worker.planner`, `email-worker.mime-parser`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Transport today  | `@email-gateway/common` `outbox/`: `EventFeed<T>` (`start(handler)`, `stop()`), `EventHandler<T>` → `'handled' \| 'duplicate'` or throws, `processOnceHandler`, `OutboxPoller` (cursor, safety lag, shards, concurrency, failure backoff), `ShardedOutboxFeed`, `AdvisoryLocks` (GET_LOCK on a dedicated connection, `maxHeldLocks`), `withTransactionDefaults`, `isUniqueViolation`, `uuidv7`. Consumers: email-worker `MimeIngestionModule` (`ShardedOutboxFeed`, consumer `email-worker.mime-parser`), delivery-worker `DeliveryApprovalConsumer` (`OutboxPoller`, `delivery-worker.planner`) and `DevPassThroughApprover` (`OutboxPoller`, `delivery-worker.dev-passthrough`, `latest`). smtp-adapter `DomainCacheInvalidator` tails the outbox from `MAX(id)` for cache invalidation (TTL is the guarantee). |
| RabbitMQ code    | `packages/event-contracts/src/topology.ts` (ADR-0005: `mail.events` topic + `mail.dlx`, five `<service>.<event>` quorum queues with `x-delivery-limit` and `<queue>.dlq`). `packages/common/src/messaging/rabbitmq.module.ts`: one connection + confirm channel per process, asserts the legacy topology at startup, **exits the process on connection loss** (crash-only), health = passive `checkExchange('mail.events')`. Used by email-worker, delivery-worker, policy-engine, archive-worker, notification-worker (none consumes anything). amqplib `^0.10.9` is already in the lockfile (common, tests).                                                                                                                                                                                                    |
| Broker           | Compose `rabbitmq` (`rabbitmq:4.1-management-alpine`, 4.1.8, single node, vhost `/`, administrator `RABBITMQ_USER`), plugins `rabbitmq_management`, `rabbitmq_prometheus` (`:15692`, not published). `rabbitmq.conf`: `consumer_timeout = 1800000`, watermark 0.6, disk free 1 GB. The legacy queues exist on `/` and are empty.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Monitoring       | `infrastructure/monitoring/prometheus.yml` scrapes `rabbitmq:15692/metrics` (aggregated only), smtp-adapter and delivery-worker. No alert rules exist (10.3). Observability profile must not run together with the apps profile on this machine.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| RBAC             | Platform permissions `platform:organizations`, `platform:operations`, `platform:tenant_override` (seed catalog `packages/database/src/seed/catalog.ts`); `@RequirePermissions`, `@RequireMfa`, `@UserOnly` decorators; `AuditService` in the api.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

---

## 2. Decisions

### 2.0 Invariants (never traded away)

1. **The outbox is the source of truth.** An event exists once its outbox row commits. The relay marks a row published **only after the broker confirms it**; nothing deletes, fakes or silently skips a row.
2. **At-least-once everywhere, exactly-once effects.** Every consumer handles each event through `processOnce` (or a staged handler that ends in it); duplicates from redelivery, relay retries, reconciliation re-drives or replay leave no second effect.
3. **Manual acks after effects commit.** A consumer acks only after the handler returned (`handled` or `duplicate`) or after a retry/dead-letter copy was confirmed.
4. **No content on the broker.** Messages carry ids, S3 keys, hashes, codes and counts only; an enforced guard refuses anything else (Q7).
5. **Tenant from trusted context.** The routing key, the `x-eg-organization-id` header and the envelope `organizationId` (set by the producer from the writer row) must agree; consumers still check against the writer row as before (3.1 M3.2, 2.3 R5).
6. **Fail closed, never drop work queues.** Work queues reject publishes when full (the outbox absorbs the backlog); only dormant queues of unbuilt stages are bounded lossy buffers (Q4), and they are never the source of truth.
7. **No mock consumers.** Queues of stages that do not exist yet are declared and bound, with no consumer.
8. **Credentials only from `.env`/secrets**; nothing prints them (scripts, logs, test output).

### Q1. Topology v1 (exactly six exchanges, fourteen queues)

Declared as data in `packages/event-contracts/src/topology.ts` (`TOPOLOGY_VERSION = 1`, §3) and generated into `infrastructure/rabbitmq/definitions.json`. All exchanges: `topic`, durable, not auto-delete, not internal. All queues: durable, `x-queue-type: quorum` (the only queue argument; everything mutable is a policy, Q4). The default exchange (`""`) and `amq.*` are never used. Dedicated vhost **`email-gateway`** (`RABBITMQ_VHOST`), created with `default_queue_type: quorum` and description `email-gateway topology v1`.

Event → exchange (the event registry, `packages/event-contracts/src/registry.ts`):

| Event type                             | Exchange          | Aggregate                                                                                                          |
| -------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------ |
| `mail.message.received.v1`             | `email.ingestion` | message                                                                                                            |
| `mail.message.parsed.v1`               | `email.ingestion` | message                                                                                                            |
| `mail.message.parse_failed.v1`         | `email.ingestion` | message                                                                                                            |
| `mail.message.scanned.v1`              | `email.security`  | message                                                                                                            |
| `mail.policy.decided.v1`               | `email.policy`    | message                                                                                                            |
| `mail.delivery.approved.v1`            | `email.delivery`  | message                                                                                                            |
| `mail.delivery.status_changed.v1`      | `email.delivery`  | message                                                                                                            |
| `domain.status.changed.v1`             | `email.events`    | domain                                                                                                             |
| `domain.routing.changed.v1`            | `email.events`    | domain                                                                                                             |
| `mail.attachment.sandbox_requested.v1` | `email.security`  | message — **reserved**: routing only, no schema yet (4.6 defines it); the relay refuses to publish a reserved type |

Queues, bindings and who consumes them (full table with policies in §3):

| Queue                    | Role        | Event bindings (exchange: key)                                                                             | Consumer (ledger name)                                                  |
| ------------------------ | ----------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `email.received`         | work        | `email.ingestion`: `org.*.mail.message.received.v1`                                                        | **email-worker** MIME ingestion (`email-worker.mime-parser`), this step |
| `scan.auth`              | dormant     | `email.ingestion`: `org.*.mail.message.parsed.v1`                                                          | 4.1 SPF/DKIM/DMARC results via Rspamd (email-worker)                    |
| `scan.spam`              | dormant     | `email.ingestion`: `org.*.mail.message.parsed.v1`                                                          | 4.1 Rspamd verdict (email-worker)                                       |
| `scan.url`               | dormant     | `email.ingestion`: `org.*.mail.message.parsed.v1`                                                          | 4.3 URL protection (email-worker)                                       |
| `scan.attachment`        | dormant     | `email.ingestion`: `org.*.mail.message.parsed.v1`                                                          | 4.2 ClamAV + YARA (email-worker)                                        |
| `scan.dlp`               | dormant     | `email.ingestion`: `org.*.mail.message.parsed.v1`                                                          | 4.5 DLP (email-worker)                                                  |
| `scan.sandbox`           | dormant     | `email.security`: `org.*.mail.attachment.sandbox_requested.v1` (reserved)                                  | 4.6 sandbox orchestration                                               |
| `email.policy.evaluate`  | dormant     | `email.security`: `org.*.mail.message.scanned.v1`; `email.ingestion`: `org.*.mail.message.parse_failed.v1` | 5.1/5.2 policy-engine (parse failures go to policy fail-safe, 3.1 M13)  |
| `email.delivery.pending` | work        | `email.delivery`: `org.*.mail.delivery.approved.v1`                                                        | **delivery-worker** planner (`delivery-worker.planner`), this step      |
| `email.delivery.retry`   | delay       | `email.delivery`: `delay.email.delivery.pending.#` (no event binding)                                      | none by design: expired messages return to `email.delivery.pending`     |
| `email.quarantine`       | dormant     | `email.policy`: `org.*.mail.policy.decided.v1`                                                             | 5.3 quarantine (acts on `action = quarantine`)                          |
| `email.archive`          | dormant     | `email.policy`: `org.*.mail.policy.decided.v1`                                                             | 8.1 archive-worker (acts on `archive = true`)                           |
| `email.analytics`        | dormant     | `email.events`: `org.#` (the firehose)                                                                     | ClickHouse ingestion (ADR-0009), not scheduled yet                      |
| `email.dead-letter`      | dead-letter | `email.events`: `dead-letter.#`                                                                            | none: operators replay through the api (Q9)                             |

Plus, for every queue except the delay and dead-letter queues, a **retry binding** `retry.<queue>.#` on its **home exchange** (§3), and five **exchange-to-exchange bindings** `email.{ingestion,security,policy,delivery,archive}` → `email.events` with `org.#`. `email.archive` (exchange) carries no event yet; it exists for archive-stage outputs (8.1) and is already bound into the firehose.

### Q2. Routing keys and headers (tenant-aware, versioned)

- **Event key:** `org.<organizationId>.<eventType>` (decimal id, e.g. `org.42.mail.message.received.v1`). Event bindings use `org.*.<eventType>`; a later per-tenant queue binds `org.<id>.#`.
- **Internal hops** (never matched by `org.#`, so never in the firehose):
  - retry into one queue: `retry.<queue>.org.<id>.<eventType>` on the queue's home exchange;
  - into the delivery delay queue: `delay.email.delivery.pending.org.<id>.<eventType>` on `email.delivery`;
  - expiry from the delay queue (broker dead-letter, fixed key): `retry.email.delivery.pending.expired`;
  - dead-letter: consumer-published `dead-letter.<queue>.org.<id>.<eventType>`; broker-published (policy) `dead-letter.<queue>`; both on `email.events`.
  - No queue name is a dot-prefix of another (a topology test asserts it), so `retry.<queue>.#` never matches another queue.
- **AMQP properties** (every publish): `persistent` (`deliveryMode 2`), `contentType 'application/json'`, `contentEncoding 'utf-8'`, `messageId = eventId`, `correlationId = envelope.correlationId`, `type = eventType`, `timestamp = occurredAt` (seconds), `appId = <publishing service>`, `mandatory: true` on the publish call. `expiration` only on delay hops.
- **Headers** (constants in `packages/common/src/messaging/headers.ts`): `x-eg-envelope-version: 1`, `x-eg-event-type`, `x-eg-schema-version` (integer `N` of `.vN`), `x-eg-organization-id` (decimal string), `x-eg-correlation-id`. Retry state: `x-eg-attempt` (counted failures, starts 0), `x-eg-transient-retries`, `x-eg-first-failed-at` (ISO), `x-eg-last-error-class` (code). Dead letters: `x-eg-source-queue`, `x-eg-failure-reason`, `x-eg-failure-class` (`fatal` \| `retryable` \| `transient`), `x-eg-attempts`, `x-eg-dead-lettered-at`, `x-eg-dead-lettered-by` (consumer name). Replay: `x-eg-replay-id`, `x-eg-replay-count`, `x-eg-replayed-at`. OpenTelemetry's amqplib instrumentation may add `traceparent`; it is propagated but never trusted.
- **Message body** = the JSON envelope (`eventEnvelopeSchema`, unchanged): `occurredAt` = the outbox row's `created_at`, `organizationId` = `organization_id`, `correlationId` = `correlation_id`.
- **Correlation:** the consumer's logger child carries `{ queue, eventId, eventType, organizationId, correlationId }` for the whole handling, so logs of every stage join on `correlationId` (ADR-0011).

### Q3. Schema versioning

- The registry maps each concrete type `<name>.vN` to its zod schema and exchange; `schemaVersionOf(type)` = `N`. The relay validates the payload with the registry schema before publishing (a stored row can predate a schema change).
- A consumer declares the event types it accepts (`eventTypes`, a subset of what is bound to its queue, checked at construction). A delivery whose `type`/`x-eg-event-type` is not accepted, whose `x-eg-schema-version` does not equal the version of `eventType`, or whose envelope/payload fails the schema is **dead-lettered immediately** (`unknown_event_type`, `unsupported_schema_version`, `contract_invalid`) and never retried.
- Breaking change = new `vN+1` type, new binding to the same queue, the consumer accepts both until producers stop writing `vN` (ADR-0024 decision 1).

### Q4. Policies: work, dormant, delay, dead-letter

Generated per queue (`eg.<queue>`, pattern `^<escaped name>$`, `apply-to: queues`, priority 10), imported with the definitions. Services cannot change them (no `policymaker` tag).

| Role        | Policy definition                                                                                                                                                                                                       |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| work        | `delivery-limit: 20`, `dead-letter-exchange: email.events`, `dead-letter-routing-key: dead-letter.<queue>`, `dead-letter-strategy: at-least-once`, `overflow: reject-publish`, `max-length: 1000000`                    |
| dormant     | `delivery-limit: -1`, `max-length: 10000`, `overflow: drop-head` (no dead-lettering)                                                                                                                                    |
| delay       | `delivery-limit: -1`, `dead-letter-exchange: email.delivery`, `dead-letter-routing-key: retry.email.delivery.pending.expired`, `dead-letter-strategy: at-least-once`, `overflow: reject-publish`, `max-length: 1000000` |
| dead-letter | `delivery-limit: -1`, `overflow: reject-publish`, `max-length: 1000000`                                                                                                                                                 |

- `delivery-limit` is a **backstop** for crash loops only; application retries republish copies (Q8), which do not count towards it.
- `delivery-limit: -1` (unlimited) on every queue that no stage consumes (review round 1, §14 F2). RabbitMQ 4.x applies a default limit of 20 to a quorum queue whose policy sets none and drops a message over it when the queue has no dead-letter target. Dead-letter replay and operator inspection read these queues with `basic.get` and return what they do not take with `nack(requeue)`, which counts as a delivery (§13.6); without `-1` a dead letter disappeared after about 20 scans (measured: gone at the 22nd return; with `-1`, still there after 30).
- `reject-publish` on a work queue nacks the relay's publish → the row stays unpublished with backoff (backpressure into MySQL, nothing lost).
- **Dormant** queues exist because the brief requires them bound now; without a consumer they would grow without bound (1 M messages/day per scan queue) and, with `reject-publish`, would block every publish of `mail.message.parsed.v1`. Their stage's step switches the policy to `work` (a policy change, no re-declare) and onboards older messages from MySQL. This is documented in the topology doc and the runbook.

### Q5. Provisioning (definitions file + init script; services verify only)

- `toRabbitDefinitions(TOPOLOGY)` (event-contracts) produces the JSON for `POST /api/definitions/{vhost}`: `exchanges`, `queues`, `bindings` (queue and exchange destinations), `policies`, plus a top-level `topology_version`. `pnpm --filter @email-gateway/event-contracts topology:export` writes `infrastructure/rabbitmq/definitions.json` (Prettier-formatted, committed); a unit test fails when the committed file differs from the generated one.
- `infrastructure/rabbitmq/init.mjs` (plain Node 22, no dependencies, `fetch` against the management API) is the **only** provisioning code: waits for the API (≤ 120 s), creates/updates the vhost (description `email-gateway topology v<N>`, `default_queue_type: quorum`), imports the definitions (stripping `topology_version`), and with `--users` creates/updates the role users and permissions (Q10) from the environment. `--cleanup-legacy` deletes the ADR-0005 objects on vhost `/` (`mail.events`, `mail.dlx`, the five queues and their `.dlq`) **only when each is empty**, else warns and leaves it. `--delete-vhost <name>` exists for test teardown and refuses `email-gateway` and `/`. Idempotent; exit code ≠ 0 on any failure; never prints passwords or URLs with credentials.
- Compose one-shot `rabbitmq-init` (default profile, image `node:22-bookworm-slim`, mounts `infrastructure/rabbitmq` read-only, `depends_on rabbitmq: service_healthy`, `restart: 'no'`) runs `node /rabbitmq/init.mjs --users --cleanup-legacy`. App services depend on it (`service_completed_successfully`). Host: `pnpm rabbitmq:init` (root script, `node --env-file=.env infrastructure/rabbitmq/init.mjs --users`).
- Services **never declare** (their users have `configure = ^$`). At startup and in readiness, the client verifies passively (`checkExchange`/`checkQueue`) the exchanges it publishes to and the queues it consumes; a missing object keeps readiness red and is retried, it does not crash the process.
- Kubernetes: manifests gain the role secrets and the `event-relay` Deployment; provisioning a production broker (Amazon MQ or a self-managed cluster, definitions import job) is 10.1 and **not** in scope.

### Q6. Shared AMQP client library (`packages/common/src/messaging/`)

**amqplib `^0.10.9` (already in the lockfile) + an own recovery layer**; no new dependency (alternatives in ADR-0024). Framework-free classes plus a thin Nest module. Exported from `@email-gateway/common`. API (implementers code against exactly this; names may gain optional options, not lose them):

```ts
// connection.ts
export interface AmqpConnectionOptions {
  /** One or more amqp(s):// URLs (cluster nodes); tried in rotation on (re)connect. */
  urls: string[];
  connectionName: string;
  logger: Logger;
  metrics?: MessagingMetrics;
  heartbeatSeconds?: number; // default 30
  reconnect?: { baseMs: number; maxMs: number }; // default 500 / 30 000, equal jitter
}
export class BrokerUnavailableError extends Error {}
export class AmqpConnection implements HealthIndicator {
  readonly healthName = 'rabbitmq';
  constructor(options: AmqpConnectionOptions);
  start(): void; // connects in the background; reconnects until close()
  get connected(): boolean;
  get blocked(): boolean; // connection.blocked (memory/disk alarm)
  waitUntilConnected(timeoutMs: number): Promise<void>;
  /** Runs `setup` on every (re)connect (consumers re-subscribe here); returns an unregister fn. */
  onConnected(setup: (model: ChannelModel) => Promise<void>): () => void;
  createConfirmChannel(): Promise<ConfirmChannel>; // BrokerUnavailableError while disconnected
  createChannel(): Promise<Channel>;
  /** Passive checks; added by publishers/consumers; part of checkHealth. */
  requireTopology(objects: { exchanges?: string[]; queues?: string[] }): void;
  checkHealth(): Promise<void>; // connected, not blocked, topology verified
  close(): Promise<void>;
}

// publisher.ts
export type PublishOutcome = 'confirmed' | 'nacked' | 'returned' | 'timeout' | 'refused';
export interface PublishItem {
  envelope: EventEnvelope;
  /** Defaults: registry exchange and `org.<id>.<eventType>`. */
  exchange?: string;
  routingKey?: string;
  headers?: Record<string, string | number>;
  expirationMs?: number;
}
export interface PublishResult { outcome: PublishOutcome; code?: string /* guard code, return reply */ }
export class ConfirmPublisher {
  constructor(options: {
    connection: AmqpConnection; logger: Logger; metrics?: MessagingMetrics;
    appId: string; confirmTimeoutMs: number; maxMessageBytes: number;
  });
  /** One confirm channel, publishes in order, resolves per item; rejects with
   *  BrokerUnavailableError (all unresolved items unconfirmed) when the channel/connection dies. */
  publishBatch(items: PublishItem[]): Promise<PublishResult[]>;
  publish(item: PublishItem): Promise<void>; // throws unless 'confirmed'
  /** Re-publishes an existing delivery's bytes (retry, dead-letter, replay) after the guard. */
  republish(raw: { content: Buffer; properties: MessageProperties }, target: { exchange: string; routingKey: string; headers: Record<string, unknown>; expirationMs?: number }): Promise<void>;
  close(): Promise<void>;
}

// codec.ts, headers.ts, content-guard.ts, backoff.ts, errors.ts
export function encodeEvent(envelope: EventEnvelope, appId: string): { exchange: string; routingKey: string; content: Buffer; options: Options.Publish };
export type DecodeResult<T> =
  | { ok: true; event: EventEnvelope<T>; attempt: number; transientRetries: number; firstFailedAt?: Date }
  | { ok: false; reason: 'contract_invalid' | 'unknown_event_type' | 'unsupported_schema_version' | 'tenant_mismatch' };
export function decodeDelivery<T>(msg: ConsumeMessage, accepted: ReadonlyMap<string, ZodType<T>>): DecodeResult<T>;
export class ContentGuardError extends Error { readonly code: ContentGuardCode; readonly path: string }
export function assertMetadataOnly(value: unknown, options?: { maxStringLength?: number }): void;
export function backoffDelay(attempt: number, policy: { baseMs: number; maxMs: number }, random?: () => number): number;
export class NonRetryableError extends Error { constructor(readonly code: string) }
export type FailureClass = 'transient' | 'retryable' | 'fatal';
export function isTransientInfrastructureError(error: unknown): boolean;
export function defaultClassify(error: unknown): FailureClass;

// consumer.ts
export interface QueueConsumerOptions<T> {
  connection: AmqpConnection;
  publisher: ConfirmPublisher; // for retry and dead-letter copies
  queue: QueueName; // must be a work (or, in tests, dormant) queue of TOPOLOGY
  consumer: string; // ledger name, for logs, metrics, x-eg-dead-lettered-by
  eventTypes: string[]; // accepted, ⊆ types bound to the queue
  prefetch: number; // = max concurrent handlers
  retry?: Partial<RetryPolicy>; // overrides of the topology's policy (validated)
  classify?: (error: unknown) => FailureClass; // default defaultClassify
  logger: Logger;
  metrics?: MessagingMetrics;
  now?: () => Date;
  random?: () => number;
}
export class QueueConsumer<T> implements EventFeed<T> {
  constructor(options: QueueConsumerOptions<T>);
  start(handler: EventHandler<T>): void; // subscribes on every (re)connect, manual ack
  stop(): Promise<void>; // cancel, wait in-flight (bounded), nack(requeue) held messages, close
}

// metrics.ts
export interface MessagingMetrics { /* methods for the series in §5.3 */ }
export function createMessagingMetrics(metrics: MetricsService): MessagingMetrics;

// amqp.module.ts (Nest)
export class AmqpModule {
  static forRoot(options: { urls: string[]; connectionName: string; appId: string;
    confirmTimeoutMs?: number; maxMessageBytes?: number;
    verify?: { exchanges?: string[]; queues?: string[] } }): DynamicModule;
  // global; provides AmqpConnection (also a HealthIndicator) and ConfirmPublisher; starts on
  // module init without awaiting the broker; closes on destroy (after consumers stopped).
}
```

Behaviour that is part of the contract:

- **Recovery.** Connection `error`/`close` (not initiated by `close()`) → `connected = false`, every open channel is dropped, pending confirms reject with `BrokerUnavailableError`, reconnect with equal-jitter backoff rotating through `urls`, then re-run every `onConnected` setup in registration order. Channel-level errors (e.g. `PRECONDITION_FAILED`, `ACCESS_REFUSED`) close that channel only; its owner re-creates it after a backoff. Deliveries of a dead channel are never acked on a new channel (amqplib delivery tags are per channel); the broker redelivers them. **The process never exits on a broker failure** (replaces the crash-only `RabbitMqModule`).
- **Confirms.** `publishBatch` publishes all items on one confirm channel, then awaits each item's callback; per-item timeout `confirmTimeoutMs` → `timeout` and the channel is closed and re-created (it is unreliable after a lost confirm). A `basic.return` (mandatory, unroutable) marks that item `returned` even though the broker acks it afterwards. While `blocked`, `publishBatch` waits for `unblocked` up to `confirmTimeoutMs`, then returns `timeout` for all items.
- **Guard and size.** Every publish path runs `assertMetadataOnly(envelope)` and checks the encoded size ≤ `maxMessageBytes` (default 131 072, hard max 262 144) → `refused` with the guard code; nothing is sent.
- **Consumer.** `basic.consume` with `noAck: false`, `prefetch(prefetch)` per channel (one channel per consumer), up to `prefetch` handlers in flight. Per delivery: decode (Q3) → on failure dead-letter (fatal); else run the handler with the logger child of Q2; on `handled`/`duplicate` → ack; on throw → classify → Q8. Redelivered deliveries (`fields.redelivered`) are counted. A handler result arriving after its channel died is dropped (logged at debug).
- **Logging** never includes `err.message`, `err` objects or payload values; only `{ queue, eventId, eventType, organizationId, correlationId, errName, errCode, failureClass, attempt }` (3.1 M15 rule; reuse the token-only `errorFields` pattern, moved to common).

### Q7. Content guard (`assertMetadataOnly`)

Refuses, with `ContentGuardError(code, path)` (the path is a JSON path, never a value):

| Code                | Rule                                                                                                                                                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `binary_value`      | any `Buffer`, `ArrayBuffer`, typed array, `DataView`, `Blob`-like value, or a serialized buffer `{ type: 'Buffer', data: [...] }`                                                                                         |
| `oversized_string`  | any string longer than 2 048 characters                                                                                                                                                                                   |
| `mime_content`      | a string with a CR/LF followed by a MIME header (`/\r?\n(content-(type\|transfer-encoding\|disposition)\|mime-version)\s*:/i`) or starting with one                                                                       |
| `base64_blob`       | a run of ≥ 512 base64 characters (`[A-Za-z0-9+/=_-]`, CR/LF allowed)                                                                                                                                                      |
| `forbidden_field`   | a key (case-insensitive) in `body`, `rawBody`, `raw`, `html`, `text`, `content`, `contentBase64`, `data`, `bytes`, `eml`, `mime`, `attachmentData`, `attachmentContent` whose value is a string, a number array or binary |
| `too_deep`          | nesting deeper than 16 levels or more than 10 000 nodes                                                                                                                                                                   |
| `message_too_large` | encoded envelope > `maxMessageBytes` (publisher)                                                                                                                                                                          |

Every registered event's valid payload (including a 1 000-recipient approval) passes; tests prove both directions. The broker adds `max_message_size = 1048576` in `rabbitmq.conf` as a last line of defence.

### Q8. Retry, backoff and dead-letter (consumer side)

`RetryPolicy` per work queue in the topology (overridable per service within validated bounds):

```ts
interface RetryPolicy {
  strategy: 'hold' | 'delay-queue';
  maxAttempts: number; // counted (retryable) failures before dead-letter
  baseDelayMs: number;
  maxDelayMs: number; // hold: ≤ 60 000 (a held message keeps its prefetch slot)
  maxRetryAgeMs: number; // transient retries stop after this age since x-eg-first-failed-at
  delayQueue?: QueueName; // delay-queue only (email.delivery.retry)
}
```

| Queue                    | strategy                             | maxAttempts | base / max delay | maxRetryAge |
| ------------------------ | ------------------------------------ | ----------- | ---------------- | ----------- |
| `email.received`         | hold                                 | 8           | 1 s / 60 s       | 24 h        |
| `email.delivery.pending` | delay-queue (`email.delivery.retry`) | 10          | 5 s / 15 min     | 48 h        |
| dormant queues           | hold (for their future consumer)     | 5           | 1 s / 60 s       | 24 h        |

Backoff: `d = min(maxDelayMs, baseDelayMs · 2^(n−1))`, delay = `d/2 + random·d/2` (equal jitter; never below half), `n` = `x-eg-attempt` for retryable failures and `x-eg-transient-retries` for transient ones.

On a handler failure:

1. **fatal** (`NonRetryableError(code)`, or a decode failure) → dead-letter now, reason = the code.
2. **transient** (`classify` → `transient`: database connection/pool/timeout/deadlock/lock-wait, S3 5xx/throttling/network, socket errors, `AbortError`/`TimeoutError`) → `x-eg-transient-retries + 1`, `x-eg-attempt` unchanged, `x-eg-first-failed-at` set once. If `now − firstFailedAt > maxRetryAgeMs` → dead-letter `retry_age_exceeded`. An outage therefore never consumes attempts, and never dead-letters before the age limit.
3. **retryable** (anything else) → `x-eg-attempt + 1`; if it reaches `maxAttempts` → dead-letter `max_attempts_exceeded`.
4. **Retry hop:**
   - `hold`: wait the delay **while holding the delivery** (its prefetch slot), then `republish` a copy to the home exchange with `retry.<queue>.org.<id>.<eventType>` and the updated headers, await the confirm, then ack the original. All slots held during an outage = consumption pauses = backpressure. On `stop()` a held delivery is nacked with requeue.
   - `delay-queue`: `republish` a copy to `email.delivery` with `delay.email.delivery.pending.org.<id>.<eventType>` and `expirationMs = delay`, confirm, ack the original. The broker dead-letters the expired copy back to `email.delivery.pending` (Q4 delay policy). Quorum queues expire messages at the head only, so a short delay behind a longer one waits for it: the effective delay is ≥ the computed one and at most `maxDelayMs` late (documented).
5. **Dead-letter hop:** `republish` a copy to `email.events` with `dead-letter.<queue>.org.<id>.<eventType>` and the failure headers (Q2), confirm, ack the original. Reason codes: `contract_invalid`, `unknown_event_type`, `unsupported_schema_version`, `tenant_mismatch`, `max_attempts_exceeded`, `retry_age_exceeded`, or the handler's `NonRetryableError` code (`/^[a-z0-9_]{1,48}$/`, else `handler_rejected`).
6. If a retry or dead-letter `republish` is not confirmed (broker down, `reject-publish` on a full queue), the original is **not** acked: it is nacked with requeue after the delay (hold) or left to be redelivered when the channel dies. Never acked without a confirmed copy.
7. Broker dead letters (`delivery-limit` reached by redeliveries without an application decision, e.g. a crash loop) arrive in `email.dead-letter` with `x-death`/`x-first-death-reason: delivery_limit`. RabbitMQ 4.x semantics of which returns increment `x-delivery-count` must be confirmed empirically by WP2 and recorded; the design does not rely on them (the MIME poison guard, 3.1 M3.4, bounds MIME crash loops independently).

A retry copy keeps the same body, `messageId` (= `eventId`) and `correlationId`, so idempotency and correlation hold across hops; it moves to the queue's tail (no head-of-line blocking; ordering across retries is not preserved and no consumer relies on it).

### Q9. Dead-letter replay (platform API, audited)

- **Endpoints** in a new api module `apps/api/src/modules/dead-letters/` (controller only translates; logic in `DeadLetterReplayService`):
  - `GET /api/v1/platform/dead-letters` → `{ queue: 'email.dead-letter', messages, consumers }` (passive `checkQueue`). `@RequirePermissions('platform:operations')`, `@UserOnly()`.
  - `POST /api/v1/platform/dead-letters/replay` → body `{ sourceQueue, limit (1–1000), eventType?, organizationId? (organization public id), failureReason?, dryRun? (default false), reason (operator text, 10–500 characters) }`. `@RequirePermissions('platform:dead_letter_replay')`, `@RequireMfa()`, `@UserOnly()` (no API keys, no override tokens). `sourceQueue` must be a **work** queue (`email.received`, `email.delivery.pending`; dormant/delay/dead-letter → 400 `source_queue_not_replayable`).
  - Response: `{ replayId, dryRun, scanned, matched, replayed, skipped: { invalid, notMatching }, items: [{ eventId, eventType, organizationId (public id or null), sourceQueue, failureReason, replayed }] }` (items ≤ `limit`).
- **New permission** `platform:dead_letter_replay` ("Platform: replay dead-lettered pipeline messages") in the seed catalog, granted to `super_admin` (all) and `platform_admin`. Applied with `pnpm db:seed` (catalog seed is idempotent; no migration).
- **Algorithm** (one replay at a time platform-wide: Redis `SET dlq:replay:lock <replayId> NX PX 300000`, else 409 `replay_in_progress`; broker connection = `RABBITMQ_OPS_URL`, opened lazily per request and closed after; unset → 503 `dead_letter_replay_unavailable`):
  1. `channel.get('email.dead-letter', { noAck: false })` repeatedly, holding every fetched message unacked, until `matched = limit`, the queue is empty, or `scanned = DEAD_LETTER_REPLAY_SCAN_MAX` (default 10 000).
  2. Source queue of a message = `x-eg-source-queue`, else `x-first-death-queue`, else the first `x-death[].queue`. Match = source queue and the optional filters (event type from `x-eg-event-type`/`type`, organization from `x-eg-organization-id`, reason from `x-eg-failure-reason`/`x-first-death-reason`).
  3. Each match: decode the envelope (schema + registry) and run the content guard; invalid → `skipped.invalid` (left in the queue). Valid and not `dryRun` → `republish` the **unchanged body** to the source queue's home exchange with `retry.<sourceQueue>.org.<id>.<eventType>`, properties kept (`messageId`, `correlationId`, `type`, `timestamp`, `appId`), headers: the Q2 base headers, `x-eg-attempt: 0`, `x-eg-transient-retries: 0`, no `x-eg-first-failed-at`, no failure headers, no `x-death`/`x-first-death-*`/`x-last-death-*`, `x-eg-replay-id`, `x-eg-replay-count` = previous + 1, `x-eg-replayed-at`. Confirm, then **ack** the dead letter.
  4. Every message not replayed is `nack`ed with `requeue: true` at the end (also on any error and on `dryRun`); a crash closes the channel, which requeues them as well.
  5. One `audit_logs` row through `AuditService`: `action: 'platform.dead_letters.replay'` (follow the existing action naming if it differs), `resource_type: 'queue'`, `resource_id: sourceQueue`, `metadata: { replayId, dryRun, filters, scanned, matched, replayed, skipped, reason, outcome: 'complete' | 'partial', eventIds (≤ 100) }`, written even when nothing matched or the broker failed half-way (`partial`).
- **Safety:** replayed events keep their `eventId`; a consumer that already applied one records a ledger duplicate. A crash between the confirm and the ack leaves a copy in both queues; replaying it again is a duplicate. Platform-wide (cross-tenant) by nature; the organization filter narrows it.

### Q10. Vhost, users and permissions (least privilege)

| User (`.env` key)                                      | Used by                | configure | write                                                               | read                         |
| ------------------------------------------------------ | ---------------------- | --------- | ------------------------------------------------------------------- | ---------------------------- |
| `RABBITMQ_USER` (administrator, exists)                | init, tests, operators | `.*`      | `.*`                                                                | `.*`                         |
| `RABBITMQ_RELAY_USER` = `eg-relay`                     | event-relay            | `^$`      | `^email\.(ingestion\|security\|policy\|delivery\|archive\|events)$` | `^$`                         |
| `RABBITMQ_EMAIL_WORKER_USER` = `eg-email-worker`       | email-worker           | `^$`      | `^email\.(ingestion\|events)$`                                      | `^email\.received$`          |
| `RABBITMQ_DELIVERY_WORKER_USER` = `eg-delivery-worker` | delivery-worker        | `^$`      | `^email\.(delivery\|events)$`                                       | `^email\.delivery\.pending$` |
| `RABBITMQ_OPS_USER` = `eg-ops`                         | api (replay, stats)    | `^$`      | `^email\.(ingestion\|delivery)$` (review round 1)                   | `^email\.dead-letter$`       |

- Role users have no tags (no management UI/API). Passive declares need no permission. A consumer's write right on its home exchange lets it publish forged events of its own stage only; the email-worker cannot reach `email.delivery` (approvals). Handlers keep checking events against writer rows.
- **Topic permissions** (review round 1, §14 F1): the routing keys each user may publish, per exchange, set and verified by `init.mjs --users`. `eg-relay`: `^org\.[1-9][0-9]{0,19}\.` on each of the six exchanges (only the relay publishes event keys). `eg-email-worker`: `^retry\.email\.received\.` on `email.ingestion`, `^dead-letter\.email\.received(\.|$)` on `email.events`. `eg-delivery-worker`: `^(retry|delay)\.email\.delivery\.pending\.` on `email.delivery`, `^dead-letter\.email\.delivery\.pending(\.|$)` on `email.events`. `eg-ops`: `^retry\.email\.received\.` on `email.ingestion`, `^retry\.email\.delivery\.pending\.` on `email.delivery`. Read is `^$` everywhere (no user binds; consuming is not affected, verified).
- **Residual risk** (accepted, recorded in ADR-0024): a retry key reaches its work queue, so a leaked `eg-delivery-worker` or `eg-ops` credential can still publish a `retry.email.delivery.pending.org.<id>.mail.delivery.approved.v1` message. The planner therefore plans only approvals the gateway issued: a `message_outbox` row with the same `event_id`, `event_type`, `organization_id` and payload (`assertApprovalIssued`, else a fatal dead letter `approval_not_issued` / `approval_mismatch`). Such a credential can at most re-send an approval that was really issued (a ledger duplicate) or fill the queue.
- Each service reads its **own** URL key (`RABBITMQ_RELAY_URL`, `RABBITMQ_EMAIL_WORKER_URL`, `RABBITMQ_DELIVERY_WORKER_URL`, `RABBITMQ_OPS_URL`; comma-separated list for cluster nodes; `*_FILE` supported by `load-config`), so host-run services (`pnpm dev` loads the whole `.env`) still use least privilege. `RABBITMQ_URL` stays the administrator URL on `/` for tests and tools only; Compose stops passing it to services. `RABBITMQ_PREFETCH` is no longer read (per-consumer prefetch keys, §6).
- policy-engine, archive-worker and notification-worker **stop connecting to RabbitMQ** in this step (they consume nothing; their legacy queue assertions are removed with `RabbitMqModule`). Their steps (5.x, 8.1, 6.2) add a role user and their consumer. Their readiness loses the `rabbitmq` check (documented in contracts §9).

### Q11. The outbox relay (`apps/event-relay`, ADR-0023)

New NestJS app `@email-gateway/event-relay` (port **3070**, `EVENT_RELAY_HOST_PORT`), same layout as the workers (`config.ts` zod, `instrumentation.ts` first, `main.ts`, `app.module.ts`, `HealthModule` with `mysql` + `rabbitmq`, `MetricsModule` `/metrics`). Built with `infrastructure/docker/node-service.Dockerfile` (`APP=event-relay`). Writer only (ADR-0014).

`OutboxRelay` (plain class, wired by `RelayModule`; the integration tests build the same graph):

1. `RELAY_SHARDS` shard loops; a loop runs a shard only while holding `GET_LOCK('er:relay#<i>/<n>')` through the shared `AdvisoryLocks` with `maxHeldLocks = RELAY_MAX_HELD_SHARDS` (lock name ≤ 64 characters). Shard predicate `MOD(CRC32(CONCAT(aggregate_type, ':', aggregate_id)), n) = i`.
2. Before touching the database: broker not connected or `blocked` → sleep with broker backoff (`RELAY_BROKER_BACKOFF_BASE_MS`/`MAX_MS`, equal jitter).
3. Read (writer): `SELECT id, created_at, event_id, organization_id, event_type, aggregate_type, aggregate_id, correlation_id, payload, available_at, attempts FROM message_outbox WHERE published_at IS NULL AND attempts < :max AND <shard> [AND organization_id IN (:scope)] ORDER BY id LIMIT :RELAY_SCAN_LIMIT`.
4. Walk in id order: a row with `available_at > now` blocks its aggregate (skip it and every later row of the same `(aggregate_type, aggregate_id)` in this pass); take up to `RELAY_BATCH_SIZE` publishable rows.
5. Build each envelope; unknown or reserved type → poison `unknown_event_type`; payload schema failure → poison `contract_invalid`; guard/size failure → poison `<guard code>`. Poison = `attempts = RELAY_MAX_ATTEMPTS, last_error = <code>`; never published.
6. `publishBatch` → per row: `confirmed` → collect; `returned` → `attempts + 1, available_at = now + rowBackoff(attempts), last_error = 'unroutable'`; `nacked` (a full work queue with `reject-publish`, or a quorum queue without quorum: infrastructure, review round 1 §14 F3) → `available_at = now + rowBackoff(shard nack streak), last_error = 'nacked'`, **`attempts` unchanged**, so a queue that stays full never turns rows into poison; the streak counts the shard's consecutive passes with a nack and resets after a pass without one; `timeout`/`BrokerUnavailableError` → nothing written, broker backoff.
7. `UPDATE message_outbox SET published_at = NOW(3) WHERE published_at IS NULL AND (id, created_at) IN (…)` for the confirmed rows. A database error here leaves them unpublished (republished later; duplicates absorbed).
8. Full batch → poll again immediately; otherwise wait `RELAY_POLL_INTERVAL_MS`. A database error → relay backoff (same base/max as broker), no broker work.
9. Lag: `outbox_relay_lag_seconds{shard}` = `now − created_at` of the oldest row read in step 3 (0 when none); a shard this replica does not hold is measured from `SELECT MIN(created_at) …` at most every 10 s (step 3.1 M2 rule, so an unowned shard shows growing lag).

The optional `organization_id IN (…)` scope is a constructor option only (integration tests and future dedicated per-tenant relays); it is not an environment key.

`last_error` holds codes only. `attempts` counts row-specific publish failures (mandatory returns), not outages and not broker nacks.

### Q12. Reconciliation service (`apps/event-relay`, ADR-0023)

`OutboxReconciler`, single active instance (`GET_LOCK('er:reconciler')`), every `RECONCILE_INTERVAL_MS`:

1. **Outbox health** (metrics only; the relay is the re-drive): `outbox_unpublished_rows` (count, capped at 100 000), `outbox_unpublished_oldest_seconds` (non-poison), `outbox_poison_rows` (`attempts ≥ RELAY_MAX_ATTEMPTS`, count and oldest id logged).
2. **Unconsumed sweep.** For each queue in `RECONCILE_QUEUES` (default `email.received,email.delivery.pending`; must be work queues with a ledger consumer in the topology): event types bound to it → `(queue, eventTypes, ledgerConsumer)`. Cursor `reconcile:unconsumed` in `stream_cursors` over `message_outbox.id`. Each run reads up to `RECONCILE_BATCH_SIZE` rows `id > cursor` (scope option as in Q11) with `created_at ≥ now − RECONCILE_LOOKBACK_HOURS`, in id order:
   - stop at the first row whose `created_at > now − RECONCILE_UNCONSUMED_AFTER_SECONDS` (not due; the minimum 300 s is far above every writer transaction budget, so no uncommitted smaller id can be passed);
   - row of an untracked type, or poison → settled for this check;
   - unpublished, not poison → stop the cursor here (the relay owns it; lag alerts fire);
   - published less than `RECONCILE_UNCONSUMED_AFTER_SECONDS` ago → stop (not due);
   - published long enough ago: batch-check `message_idempotency (ledgerConsumer, event_id)`; present → settled; absent → **re-drive**: `UPDATE message_outbox SET published_at = NULL, available_at = NOW(3), redrive_count = redrive_count + 1, last_redriven_at = NOW(3) WHERE id = ? AND created_at = ? AND published_at IS NOT NULL AND redrive_count < RECONCILE_MAX_REDRIVES`; if `redrive_count` is already at the maximum → exhausted (`reconcile_exhausted_total{queue}`, warn log with ids, `last_redriven_at = NULL`).
   - The cursor advances through the contiguous prefix of rows handled above.
   - First start: the cursor starts at `MIN(id)` of rows with `created_at ≥ now − RECONCILE_LOOKBACK_HOURS` (`RECONCILE_START_POSITION=oldest`) or at `MAX(id)` (`latest`).
3. **Re-check** of earlier re-drives (index on `last_redriven_at`): rows with `last_redriven_at < now − RECONCILE_UNCONSUMED_AFTER_SECONDS`, published: ledger present → settled (`last_redriven_at = NULL`, `redrive_count` kept as history); absent → re-drive again (bounded as above) or exhausted.
4. A re-driven row is republished by the relay with its original `event_id` to its exchange, so every bound queue gets a copy and every ledger absorbs it. Requirement on tracked consumers: **every handled event leaves a ledger row** (true for `processOnceHandler`; MIME writes one for duplicates and missing messages, 3.1 M3).
5. **Not lost, only unhandled** (review round 1, §14 F4/F5). Before re-driving, the reconciler reads the consumer's `message_consumer_progress` row (written by `QueueConsumer` after each confirmed retry hop, `retrying`, and after the confirmed dead-letter copy, `dead_lettered`): `dead_lettered` → settled (`reconcile_skipped_total{reason="dead_lettered"}`; replay is the recovery path, a re-drive would only make another dead letter and a false exhausted alert); `retrying` with its last hop within `RECONCILE_UNCONSUMED_AFTER_SECONDS` + the queue's longest hop gap (2 × `maxDelayMs`: 2 min for `email.received`, 30 min for `email.delivery.pending`) → deferred. Then the queue's ready count (passive declare on the relay connection): above 0, or not readable → deferred (`queue_backlog`, `queue_unknown`), so a consumer outage or a slow drain is never multiplied by re-drive copies. A deferred row is watched (`last_redriven_at = NOW(3)`, `redrive_count` unchanged) and looked at again by the re-check (step 3). A ledger row always wins (a replayed dead letter that was handled is settled). A `dead_lettered` record whose reason a relay copy cannot produce (`contract_invalid`, `unknown_event_type`, `unsupported_schema_version`, `tenant_mismatch`, `approval_not_issued`, `approval_mismatch`: a forged or altered copy carrying a real event id) does **not** settle the row, so a forged copy cannot hide a lost event (§14 F1/F4 interplay).
6. What this covers: received but never parsed (no `email-worker.mime-parser` ledger row, including a parse stuck in `parsing` after a lost message), approved but never planned (no `delivery-worker.planner` row), outbox rows unpublished past a threshold (metrics + alerts). Planned-but-not-reinjected deliveries stay with the step 2.3 `DeliveryReconciler` (unchanged). Dormant stages are not tracked until they exist.

### Q13. Consumers switched to RabbitMQ

- **email-worker:** `MimeIngestionModule` builds `new QueueConsumer<MessageReceivedV1>({ queue: 'email.received', consumer: MIME_CONSUMER, eventTypes: ['mail.message.received.v1'], prefetch: MIME_CONCURRENCY, retry: { baseDelayMs: MIME_RETRY_BASE_MS, maxDelayMs: MIME_RETRY_MAX_MS }, classify })` with `classify` = the stage's existing `isTransientFailure` → `transient`, else `retryable` (the service's poison guard finalizes after `MIME_MAX_ATTEMPTS`; config refuses `MIME_MAX_ATTEMPTS ≥` the queue's `maxAttempts`). `MimeIngestionService.handle` is unchanged. The `ShardedOutboxFeed` path and `MIME_OUTBOX_*` keys are **removed** (§Q14). The memory refusal of 3.1 §12.4 now multiplies by `MIME_CONCURRENCY` only.
- **delivery-worker:** `DeliveryApprovalConsumer` gets `new QueueConsumer<DeliveryApprovedV1>({ queue: 'email.delivery.pending', consumer: PLANNER_CONSUMER, eventTypes: ['mail.delivery.approved.v1'], prefetch: DELIVERY_APPROVAL_PREFETCH })` through the `ApprovalFeed` interface, still wrapping `processOnceHandler(prisma, PLANNER_CONSUMER, planner.plan, { txTimeoutMs: PLANNING_TX_TIMEOUT_MS })`. Retry is the delay-queue strategy (Q8). Consumer names are unchanged, so ledger rows written by the step 2.3/3.1 pollers make the relay's backlog replay free.
- **Dev pass-through** (development only, `APP_ENV` local/ci): stays on the shared `OutboxPoller` (`delivery-worker.dev-passthrough`, cursor and `latest` unchanged). Reason: it is not a pipeline stage, it has no queue in the brief's fixed list, and a dev-only queue would break "exactly fourteen". Its approvals go to the outbox → relay → `email.delivery.pending` → planner, so the step 2.3 end-to-end path keeps working **through the broker**. Step 5.x replaces it.
- **smtp-adapter `DomainCacheInvalidator`** stays an outbox tail (per-replica cache invalidation needs fan-out to every replica, i.e. one queue per replica, not in the brief's list; the TTL is the guarantee). Documented.

### Q14. What is removed

- `packages/common/src/messaging/rabbitmq.module.ts` (`RabbitMqModule`, `RabbitMqService`, crash-only exit) and its users in five apps.
- The legacy topology exports (`EXCHANGES`, `QUEUES`, `QueueDefinition`, `queueArguments`, `deadLetterQueueName`): WP1 moves them unchanged to `legacy-topology.ts` (`@deprecated`), WP4 deletes the file once nothing imports it.
- `ShardedOutboxFeed` (no user left) and the email-worker `createMimeFeed`/`MIME_OUTBOX_*` configuration. `OutboxPoller` stays (dev pass-through) with its tests.
- The ADR-0005 objects on vhost `/` (init `--cleanup-legacy`, only when empty).
- The outbox **poller fallback for production consumers is not kept**: two transports for one consumer double the failure modes and the test matrix, and the reconciler plus the relay's backlog replay already cover a broker outage. Said so in the README and the runbook.

### Q15. Monitoring

- Broker: Prometheus job `rabbitmq-detailed` on `rabbitmq:15692/metrics/detailed?vhost=email-gateway&family=queue_coarse_metrics&family=queue_consumer_count` (per-queue ready, unacked, total, consumers). Exact series names are verified against the running 4.1 broker by WP3 and recorded in the runbook. `RABBITMQ_PROMETHEUS_HOST_PORT` (default 15692) publishes `:15692` on 127.0.0.1 for tests.
- Application series (§5.3) on `/metrics` of event-relay, email-worker, delivery-worker and api; Prometheus jobs added for `event-relay:3070` and `email-worker:3020`.
- Alert rules `infrastructure/monitoring/rules/messaging.rules.yml` (loaded through `rule_files` in `prometheus.yml`), each with `runbook_url` to `docs/runbooks/rabbitmq-messaging.md`: `OutboxRelayLagHigh` (max lag > 60 s for 5 m), `OutboxRelayNoShardOwner` (sum of held shards < `RELAY_SHARDS` for 5 m, or relay target down), `OutboxPoisonRows` (> 0), `OutboxUnpublishedOld` (oldest > 15 m), `DeadLetterQueueNotEmpty` (> 0 for 10 m, warning), `DeadLetterRateHigh` (rate of dead letters > 0.1/s for 10 m), `WorkQueueBacklog` (ready > 10 000 for 10 m on a work queue), `WorkQueueNoConsumer` (consumers = 0 for 5 m on a work queue), `DormantQueueAtLimit` (≥ 90 % of 10 000), `AmqpConnectionDown` (`amqp_connection_up == 0` for 2 m), `RedeliveryRateHigh`, `ReconcileExhausted` (increase > 0). Validated with `promtool check rules` (docker image `prom/prometheus:v3.6.0`, run once, no profile start).
- Dashboards are 10.3 (not in scope).

### Q16. Backpressure (requirement 12)

Prefetch bounds in-flight deliveries per consumer (`MIME_CONCURRENCY`, `DELIVERY_APPROVAL_PREFETCH`); held retries keep their slot (an outage pauses consumption instead of spinning); work queues reject publishes beyond `max-length` and the relay keeps rows unpublished with backoff; the relay waits while the broker signals `connection.blocked`; `RELAY_BATCH_SIZE` bounds unconfirmed publishes per shard. The queue-backlog test measures `messages_unacknowledged ≤ prefetch × consumers` during a 5 000-message backlog.

### Brief requirements → decisions

| #   | Requirement                      | Where                                                                      |
| --- | -------------------------------- | -------------------------------------------------------------------------- |
| 1   | Durable message publishing       | Q1 (durable exchanges, quorum queues), Q2 (`deliveryMode 2`), Q11 (outbox) |
| 2   | Publisher confirms               | Q6 confirms, Q11 step 6–7                                                  |
| 3   | Manual consumer acknowledgements | Q6 consumer, §2.0.3                                                        |
| 4   | Idempotent consumers             | §2.0.2, Q13 (`processOnce`, unchanged consumer names)                      |
| 5   | Retry queues                     | Q8 (`email.delivery.retry` delay queue; hold-and-republish)                |
| 6   | Dead-letter queues               | Q4, Q8.5, `email.dead-letter`, Q9 replay                                   |
| 7   | Exponential backoff              | Q8 (equal jitter), relay row/broker backoff Q11                            |
| 8   | Queue monitoring                 | Q15                                                                        |
| 9   | Tenant-aware routing             | Q2 (`org.<id>.<event>`), §2.0.5                                            |
| 10  | Message correlation IDs          | Q2 (`messageId`, `correlationId`, logger child)                            |
| 11  | Schema versioning                | Q3                                                                         |
| 12  | Consumer backpressure            | Q16                                                                        |
| –   | No bodies/attachments on the bus | Q7                                                                         |
| –   | Independently scalable workers   | Q6 competing consumers, Q11 shards, separate deployables                   |
| –   | Reconciliation service           | Q12                                                                        |

---

## 3. Topology reference (v1)

**Exchanges** (topic, durable): `email.ingestion`, `email.security`, `email.policy`, `email.delivery`, `email.archive`, `email.events`.

**Exchange-to-exchange bindings:** `email.ingestion` → `email.events` (`org.#`); `email.security` → `email.events` (`org.#`); `email.policy` → `email.events` (`org.#`); `email.delivery` → `email.events` (`org.#`); `email.archive` → `email.events` (`org.#`).

**Queues** (quorum, durable):

| Queue                    | Role        | Home exchange     | Bindings (exchange → key)                                                                                                                                | Policy      | Retry policy                      |
| ------------------------ | ----------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | --------------------------------- |
| `email.received`         | work        | `email.ingestion` | `email.ingestion` `org.*.mail.message.received.v1`; `email.ingestion` `retry.email.received.#`                                                           | work        | hold 8 × 1 s–60 s, 24 h           |
| `scan.auth`              | dormant     | `email.security`  | `email.ingestion` `org.*.mail.message.parsed.v1`; `email.security` `retry.scan.auth.#`                                                                   | dormant     | hold 5 × 1 s–60 s                 |
| `scan.spam`              | dormant     | `email.security`  | `email.ingestion` `org.*.mail.message.parsed.v1`; `email.security` `retry.scan.spam.#`                                                                   | dormant     | hold 5                            |
| `scan.url`               | dormant     | `email.security`  | `email.ingestion` `org.*.mail.message.parsed.v1`; `email.security` `retry.scan.url.#`                                                                    | dormant     | hold 5                            |
| `scan.attachment`        | dormant     | `email.security`  | `email.ingestion` `org.*.mail.message.parsed.v1`; `email.security` `retry.scan.attachment.#`                                                             | dormant     | hold 5                            |
| `scan.dlp`               | dormant     | `email.security`  | `email.ingestion` `org.*.mail.message.parsed.v1`; `email.security` `retry.scan.dlp.#`                                                                    | dormant     | hold 5                            |
| `scan.sandbox`           | dormant     | `email.security`  | `email.security` `org.*.mail.attachment.sandbox_requested.v1` (reserved); `email.security` `retry.scan.sandbox.#`                                        | dormant     | hold 5                            |
| `email.policy.evaluate`  | dormant     | `email.policy`    | `email.security` `org.*.mail.message.scanned.v1`; `email.ingestion` `org.*.mail.message.parse_failed.v1`; `email.policy` `retry.email.policy.evaluate.#` | dormant     | hold 5                            |
| `email.delivery.pending` | work        | `email.delivery`  | `email.delivery` `org.*.mail.delivery.approved.v1`; `email.delivery` `retry.email.delivery.pending.#`                                                    | work        | delay-queue 10 × 5 s–15 min, 48 h |
| `email.delivery.retry`   | delay       | `email.delivery`  | `email.delivery` `delay.email.delivery.pending.#`                                                                                                        | delay       | –                                 |
| `email.quarantine`       | dormant     | `email.policy`    | `email.policy` `org.*.mail.policy.decided.v1`; `email.policy` `retry.email.quarantine.#`                                                                 | dormant     | hold 5                            |
| `email.archive`          | dormant     | `email.archive`   | `email.policy` `org.*.mail.policy.decided.v1`; `email.archive` `retry.email.archive.#`                                                                   | dormant     | hold 5                            |
| `email.analytics`        | dormant     | `email.events`    | `email.events` `org.#`; `email.events` `retry.email.analytics.#`                                                                                         | dormant     | hold 5                            |
| `email.dead-letter`      | dead-letter | `email.events`    | `email.events` `dead-letter.#`                                                                                                                           | dead-letter | –                                 |

Topology invariants asserted by unit tests (WP1): exactly these 6 exchanges and 14 queues; every queue quorum; every event binding `(X, org.*.T)` has `EVENT_REGISTRY[T].exchange === X` (or `T` reserved on `X`); every registered event type reaches at least one queue (the firehose guarantees `email.analytics`); no queue name is a dot-prefix of another; every non-delay, non-dead-letter queue has exactly one retry binding on its home exchange; the delay queue's dead-letter target routes to exactly `email.delivery.pending`; `retry`/`delay`/`dead-letter` keys never match an `org.*`/`org.#` binding; hold policies have `maxDelayMs ≤ 60 000`; the generated definitions equal the committed file.

```mermaid
flowchart LR
  subgraph producers[Producers via message_outbox]
    SA[smtp-adapter]:::p
    EW[email-worker]:::p
    DW[delivery-worker / recorder]:::p
    API[api]:::p
  end
  R[event-relay\nconfirmed publish]
  SA & EW & DW & API --> OB[(message_outbox)] --> R
  R -->|org.id.mail.message.*| XI{{email.ingestion}}
  R -->|org.id.mail.message.scanned.v1| XS{{email.security}}
  R -->|org.id.mail.policy.decided.v1| XP{{email.policy}}
  R -->|org.id.mail.delivery.*| XD{{email.delivery}}
  R -->|org.id.domain.*| XE{{email.events}}
  XA{{email.archive}}
  XI -->|org.*.received.v1| Q1[email.received]
  XI -->|org.*.parsed.v1| QS[scan.auth / spam / url / attachment / dlp]
  XI -->|org.*.parse_failed.v1| QP[email.policy.evaluate]
  XS -->|org.*.scanned.v1| QP
  XS -->|org.*.sandbox_requested.v1| QSB[scan.sandbox]
  XP -->|org.*.policy.decided.v1| QQ[email.quarantine]
  XP -->|org.*.policy.decided.v1| QA[email.archive]
  XD -->|org.*.approved.v1| QD[email.delivery.pending]
  XD -->|delay.email.delivery.pending.#| QR[email.delivery.retry\nTTL per message]
  QR -. expired: retry.email.delivery.pending.expired .-> XD
  XI & XS & XP & XD & XA -->|org.#| XE
  XE -->|org.#| QAN[email.analytics]
  XE -->|dead-letter.#| DLQ[email.dead-letter]
  Q1 -. dead-letter.email.received .-> XE
  QD -. dead-letter.email.delivery.pending .-> XE
```

---

## 4. Data model (one forward migration `event_relay`, WP1)

Created with `pnpm db:migrate:dev --create-only --name event_relay`, SQL reviewed by hand:

```sql
ALTER TABLE `message_outbox`
  ADD COLUMN `redrive_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN `last_redriven_at` DATETIME(3) NULL,
  ALGORITHM=INSTANT;
CREATE INDEX `message_outbox_last_redriven_at_idx` ON `message_outbox` (`last_redriven_at`);
```

- `schema.prisma` `MessageOutbox`: `redriveCount Int @default(0) @map("redrive_count") @db.UnsignedSmallInt` ("reconciliation re-drives, ADR-0023"), `lastRedrivenAt DateTime? @map("last_redriven_at") @db.DateTime(3)` ("set while a re-drive awaits its re-check; NULL once settled or exhausted"), `@@index([lastRedrivenAt])`. Doc comment of the model: the relay (event-relay) sets `published_at` after the broker confirms; `attempts`/`available_at`/`last_error` are the relay's row backoff; `attempts ≥ RELAY_MAX_ATTEMPTS` = poison.
- Table and partition counts are unchanged (71 tables, 19 partitioned). `docs/database/*` (data dictionary, retention: outbox partitions now drop once published) updated.
- No other schema change: the ledger, cursors (`reconcile:unconsumed`) and audit tables exist. Permission `platform:dead_letter_replay` is seed data (catalog), not a migration.
- Verification: drift check, `db:status`, clean-schema check in the throwaway `email_gateway_verify` (migrate deploy + partitions apply, 71/19), upgrade over data on the main schema; drop the throwaway schema afterwards.

**Review round 1 (§14): second forward migration `consumer_progress`** (`20261104120000_consumer_progress`, SQL generated with `prisma migrate diff` against the main schema, reviewed by hand):

```sql
CREATE TABLE `message_consumer_progress` (
    `consumer` VARCHAR(100) NOT NULL,
    `event_id` CHAR(36) NOT NULL,
    `state` ENUM('retrying', 'dead_lettered') NOT NULL,
    `reason` VARCHAR(48) NULL,
    `attempt` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `transient_retries` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    INDEX `message_consumer_progress_updated_at_idx`(`updated_at`),
    PRIMARY KEY (`consumer`, `event_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE INDEX `message_outbox_event_id_idx` ON `message_outbox`(`event_id`);
```

- `message_consumer_progress` (not partitioned, no foreign keys, keyed like the ledger; codes and counters only): one row per `(consumer, event_id)` a RabbitMQ consumer has not handled, upserted (`INSERT … ON DUPLICATE KEY UPDATE`) after every confirmed retry or dead-letter hop. Read by the reconciler (Q12 step 5). Purged after 30 days with the ledger (`db:partitions`).
- `message_outbox (event_id)`: a local index per daily partition, for the planner's approval provenance lookup (Q10 residual risk).
- 72 tables, 19 partitioned.

---

## 5. Contracts (summary)

### 5.1 Event envelope and registry

Envelope unchanged. New exports in `@email-gateway/event-contracts`: `EVENT_REGISTRY`, `eventDefinition(type)`, `schemaVersionOf(type)`, `RESERVED_EVENT_TYPES`, `EXCHANGE_NAMES`, `QUEUE_NAMES`, `ExchangeName`, `QueueName`, `QueueRole`, `RetryPolicy`, `QueueDefinition`, `TOPOLOGY`, `TOPOLOGY_VERSION`, `DEFAULT_VHOST = 'email-gateway'`, `queueDefinition(name)`, `eventRoutingKey(orgId, type)`, `retryRoutingKey(queue, orgId, type)`, `delayRoutingKey(queue, orgId, type)`, `deadLetterRoutingKey(queue, orgId?, type?)`, `parseRoutingKey(key)` (→ `{ kind: 'event' | 'retry' | 'delay' | 'dead-letter', queue?, organizationId?, eventType? }`), `eventTypesBoundTo(queue)`, `toRabbitDefinitions(topology, { vhost })`. Exact shapes are WP1's to choose within Q1–Q4; WP2 and later read them from the code.

### 5.2 Headers

Q2 (constants `HEADERS` in `packages/common/src/messaging/headers.ts`).

### 5.3 Metric names (a contract for the alert rules and 10.3 dashboards)

| Series                                                                                 | Type      | Labels                                                                              | Emitted by             |
| -------------------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------- | ---------------------- |
| `amqp_connection_up`                                                                   | gauge     | `connection`                                                                        | every AMQP client      |
| `amqp_connection_blocked`                                                              | gauge     | `connection`                                                                        | every AMQP client      |
| `amqp_reconnects_total`                                                                | counter   | `connection`                                                                        | every AMQP client      |
| `amqp_publish_total`                                                                   | counter   | `exchange`, `outcome`                                                               | ConfirmPublisher       |
| `amqp_publish_confirm_seconds`                                                         | histogram | `exchange`                                                                          | ConfirmPublisher       |
| `amqp_consumer_deliveries_total`                                                       | counter   | `queue`, `redelivered`                                                              | QueueConsumer          |
| `amqp_consumer_messages_total`                                                         | counter   | `queue`, `outcome` (`handled`, `duplicate`, `retried`, `dead_lettered`, `requeued`) | QueueConsumer          |
| `amqp_consumer_retries_total`                                                          | counter   | `queue`, `class` (`transient`, `retryable`)                                         | QueueConsumer          |
| `amqp_consumer_dead_lettered_total`                                                    | counter   | `queue`, `reason`                                                                   | QueueConsumer          |
| `amqp_consumer_handle_seconds`                                                         | histogram | `queue`                                                                             | QueueConsumer          |
| `amqp_consumer_in_flight`                                                              | gauge     | `queue`                                                                             | QueueConsumer          |
| `amqp_consumer_active`                                                                 | gauge     | `queue`                                                                             | QueueConsumer          |
| `outbox_relay_published_total`                                                         | counter   | `exchange`, `event_type`                                                            | event-relay            |
| `outbox_relay_failures_total`                                                          | counter   | `reason`                                                                            | event-relay            |
| `outbox_relay_lag_seconds`                                                             | gauge     | `shard`                                                                             | event-relay            |
| `outbox_relay_batch_seconds`                                                           | histogram | –                                                                                   | event-relay            |
| `outbox_relay_shards_held`                                                             | gauge     | –                                                                                   | event-relay            |
| `outbox_unpublished_rows` / `outbox_unpublished_oldest_seconds` / `outbox_poison_rows` | gauge     | –                                                                                   | event-relay reconciler |
| `reconcile_redriven_total` / `reconcile_exhausted_total`                               | counter   | `queue`                                                                             | event-relay reconciler |
| `reconcile_unconsumed_rows`                                                            | gauge     | `queue`                                                                             | event-relay reconciler |
| `reconcile_run_seconds`                                                                | histogram | –                                                                                   | event-relay reconciler |
| `dead_letter_replay_total`                                                             | counter   | `source_queue`, `outcome`                                                           | api                    |

The 3.1 series `mime_outbox_poll_lag_seconds`/`mime_outbox_invalid_total` are removed with the MIME poller; delivery-worker keeps `delivery_outbox_*` for the dev pass-through only.

### 5.4 HTTP

`GET /api/v1/platform/dead-letters`, `POST /api/v1/platform/dead-letters/replay` (Q9), in `docs/api/openapi.json` and the api docs. event-relay: `/health/live`, `/health/ready` (`mysql`, `rabbitmq`), `/metrics`. Readiness `rabbitmq` of email-worker, delivery-worker and event-relay = `AmqpConnection.checkHealth` (connected, not blocked, required objects verified).

---

## 6. Configuration

`.env.example` (section "RabbitMQ", WP1) — secrets as `__GENERATE__`, URLs as `${VAR}` references; WP1 appends the new keys with working values to the local `.env` (existing secrets untouched):

```
RABBITMQ_PROMETHEUS_HOST_PORT=15692
RABBITMQ_VHOST=email-gateway
RABBITMQ_MGMT_URL=http://localhost:${RABBITMQ_MGMT_HOST_PORT}
RABBITMQ_RELAY_USER=eg-relay
RABBITMQ_RELAY_PASSWORD=__GENERATE__
RABBITMQ_RELAY_URL=amqp://${RABBITMQ_RELAY_USER}:${RABBITMQ_RELAY_PASSWORD}@localhost:${RABBITMQ_HOST_PORT}/${RABBITMQ_VHOST}
RABBITMQ_EMAIL_WORKER_USER=eg-email-worker
RABBITMQ_EMAIL_WORKER_PASSWORD=__GENERATE__
RABBITMQ_EMAIL_WORKER_URL=amqp://…/${RABBITMQ_VHOST}
RABBITMQ_DELIVERY_WORKER_USER=eg-delivery-worker
RABBITMQ_DELIVERY_WORKER_PASSWORD=__GENERATE__
RABBITMQ_DELIVERY_WORKER_URL=amqp://…/${RABBITMQ_VHOST}
RABBITMQ_OPS_USER=eg-ops
RABBITMQ_OPS_PASSWORD=__GENERATE__
RABBITMQ_OPS_URL=amqp://…/${RABBITMQ_VHOST}
# Test-only 3-node cluster (profile rabbitmq-cluster)
RABBITMQ_CLUSTER_ERLANG_COOKIE=__GENERATE__
RABBITMQ_CLUSTER_NODE1_HOST_PORT=5701
RABBITMQ_CLUSTER_NODE2_HOST_PORT=5702
RABBITMQ_CLUSTER_NODE3_HOST_PORT=5703
RABBITMQ_CLUSTER_MGMT_HOST_PORT=15701
EVENT_RELAY_HOST_PORT=3070
```

`RABBITMQ_URL` keeps its value and is documented as "administrator, tests and tools only"; `RABBITMQ_PREFETCH` is documented as no longer read.

event-relay (`apps/event-relay/src/config.ts`, keys in `.env.example` section "Event relay (step 3.2)", WP1 adds them; WP3 owns the schema):

| Key                                        | Default                                 | Bounds / rule                            |
| ------------------------------------------ | --------------------------------------- | ---------------------------------------- |
| `HTTP_PORT`                                | 3070                                    |                                          |
| `RABBITMQ_RELAY_URL`                       | required                                | comma-separated amqp(s) URLs             |
| `RELAY_ENABLED` / `RECONCILE_ENABLED`      | true                                    | role flags                               |
| `RELAY_SHARDS`                             | 4                                       | 1–64                                     |
| `RELAY_MAX_HELD_SHARDS`                    | 4                                       | 1–64                                     |
| `RELAY_BATCH_SIZE`                         | 200                                     | 1–1000                                   |
| `RELAY_SCAN_LIMIT`                         | 1000                                    | ≥ batch, ≤ 10 000                        |
| `RELAY_POLL_INTERVAL_MS`                   | 250                                     | 50–60 000                                |
| `RELAY_CONFIRM_TIMEOUT_MS`                 | 15000                                   | 1 000–120 000                            |
| `RELAY_BROKER_BACKOFF_BASE_MS` / `_MAX_MS` | 500 / 30000                             | base ≤ max                               |
| `RELAY_ROW_BACKOFF_BASE_MS` / `_MAX_MS`    | 1000 / 300000                           | base ≤ max                               |
| `RELAY_MAX_ATTEMPTS`                       | 10                                      | 1–100                                    |
| `RELAY_MAX_MESSAGE_BYTES`                  | 131072                                  | 4 096–262 144                            |
| `RECONCILE_INTERVAL_MS`                    | 60000                                   | 1 000–3 600 000                          |
| `RECONCILE_UNCONSUMED_AFTER_SECONDS`       | 900                                     | ≥ 300                                    |
| `RECONCILE_MAX_REDRIVES`                   | 3                                       | 0–20 (0 = detect only)                   |
| `RECONCILE_LOOKBACK_HOURS`                 | 72                                      | 1–144 (below the 7-day outbox retention) |
| `RECONCILE_BATCH_SIZE`                     | 1000                                    | 1–10 000                                 |
| `RECONCILE_QUEUES`                         | `email.received,email.delivery.pending` | each a work queue with a ledger consumer |
| `RECONCILE_START_POSITION`                 | oldest                                  | `oldest` \| `latest`                     |

email-worker: `RABBITMQ_EMAIL_WORKER_URL` (required), `MIME_CONCURRENCY` = prefetch (existing), `MIME_RETRY_BASE_MS`/`MIME_RETRY_MAX_MS` (existing; now the queue backoff, max ≤ 60 000), `MIME_MAX_ATTEMPTS` (< queue `maxAttempts` 8); removed `MIME_OUTBOX_POLL_INTERVAL_MS`, `MIME_OUTBOX_SAFETY_LAG_MS`, `MIME_OUTBOX_BATCH_SIZE`, `MIME_OUTBOX_SHARDS`, `MIME_OUTBOX_MAX_HELD_SHARDS`.
delivery-worker: `RABBITMQ_DELIVERY_WORKER_URL` (required), `DELIVERY_APPROVAL_PREFETCH` (default 4, 1–64); `DELIVERY_OUTBOX_*` now serve the dev pass-through only.
api: `RABBITMQ_OPS_URL` (optional; replay answers 503 without it), `DEAD_LETTER_REPLAY_SCAN_MAX` (default 10 000, 1–100 000).
`packages/config`: `amqpUrlListSchema` (comma-separated `amqp(s)://` URLs → `string[]`, error never echoes the value). `rabbitmqConfigSchema` is removed once no app composes it (WP4).

---

## 7. Compose and infrastructure (WP1)

- `rabbitmq`: publish `127.0.0.1:${RABBITMQ_PROMETHEUS_HOST_PORT:-15692}:15692`; `rabbitmq.conf` adds `max_message_size = 1048576` and keeps the rest (comment: topology comes from `definitions.json` via `rabbitmq-init`).
- `rabbitmq-init` (Q5). `x-node-service.depends_on` gains `rabbitmq-init: service_completed_successfully`.
- `x-node-env` **stops** passing `RABBITMQ_URL`. Per service: email-worker `RABBITMQ_EMAIL_WORKER_URL: amqp://${RABBITMQ_EMAIL_WORKER_USER:?}:${RABBITMQ_EMAIL_WORKER_PASSWORD:?}@rabbitmq:5672/${RABBITMQ_VHOST:-email-gateway}`; delivery-worker `RABBITMQ_DELIVERY_WORKER_URL`; api `RABBITMQ_OPS_URL`; event-relay `RABBITMQ_RELAY_URL`. MIME `MIME_OUTBOX_*` entries removed from the email-worker service; `DELIVERY_APPROVAL_PREFETCH` added to delivery-worker.
- New `event-relay` service (apps profile, image `email-gateway/event-relay:local`, `HTTP_PORT 3070`, all `RELAY_*`/`RECONCILE_*` with `${KEY:-default}`, healthcheck on `/health/ready`, port `127.0.0.1:${EVENT_RELAY_HOST_PORT:-3070}:3070`).
- **Profile `rabbitmq-cluster`** (test-only, node-failure test): `rabbitmq-node1..3` (same image, hostnames `rmq1..3`), shared Erlang cookie from `RABBITMQ_CLUSTER_ERLANG_COOKIE` written to `/var/lib/rabbitmq/.erlang.cookie` (mode 400, owner rabbitmq) by a small entrypoint wrapper `infrastructure/rabbitmq/cluster/entrypoint.sh` before `docker-entrypoint.sh rabbitmq-server`, `infrastructure/rabbitmq/cluster/rabbitmq.conf` (`cluster_formation.peer_discovery_backend = classic_config`, the three nodes, `vm_memory_high_watermark.absolute = 256MiB`, `disk_free_limit.absolute = 256MB`, `max_message_size`, `consumer_timeout`), `mem_limit: 448m` each, named volumes `rabbitmq-cluster-1-data` … `-3-data` (removed explicitly by the test procedure, never `down -v`), AMQP on `127.0.0.1:5701–5703`, management on `127.0.0.1:15701` (node 1). Default user = `RABBITMQ_USER`/`RABBITMQ_PASSWORD`. Never started by `pnpm infra:up`/`stack:up`.
- Kubernetes base: role URL secrets (`RABBITMQ_*_URL_FILE`) on email-worker, delivery-worker, api; RabbitMQ env removed from policy-engine, archive-worker, notification-worker, smtp-adapter (which never used it); new `event-relay.yaml` Deployment (2 replicas, probes, `/metrics` annotation) in the kustomization.
- Prometheus (WP3): jobs `event-relay`, `email-worker`, `rabbitmq-detailed`; `rule_files`; the compose `prometheus` service mounts `infrastructure/monitoring/rules`.

---

## 8. Alternatives considered

| Decision            | Chosen                                                        | Rejected (why)                                                                                                                                                                                |
| ------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Relay home          | dedicated `event-relay` app                                   | module in email-worker/delivery-worker (couples scaling and failure, broad publish rights); in each producer (credentials everywhere, still needs a sweeper)                                  |
| Claiming            | advisory-lock shards by aggregate hash                        | `FOR UPDATE SKIP LOCKED` (transaction held across broker round trips or lease columns + sweeper; loses per-aggregate order); single global lock (no scale-out)                                |
| Retry               | hold-and-republish + one delay queue for delivery             | 13 extra `<queue>.retry` TTL queues (outside the fixed list); delayed-message plugin (not bundled, non-replicated, 7th exchange); `x-delivery-limit` only (no backoff, outages dead-letter)   |
| Dormant queues      | bounded `drop-head` policy                                    | `reject-publish` (blocks the whole pipeline); unbounded (broker exhaustion at 1 M/day); not binding them (brief requires it)                                                                  |
| Provisioning        | definitions file + idempotent init; services verify passively | every service asserting its queues (needs `configure` rights, argument drift causes `PRECONDITION_FAILED`); broker `load_definitions` at boot (cannot create users without committing hashes) |
| Client              | amqplib + own recovery                                        | amqp-connection-manager (in-memory buffering hides unpublished state), Rascal, @golevelup/nestjs-rabbitmq (config-driven topology duplicate, heavier)                                         |
| Replay              | authenticated platform API                                    | CLI (no authenticated identity; audit would trust a flag); automatic re-queue of dead letters (loops on deterministic failures)                                                               |
| Reconciler re-drive | un-publish the original outbox row                            | targeted publish into one queue (consumer rights for the relay user, per-queue routing knowledge, bypasses relay ordering and metrics); fabricating new events (new ids defeat ledgers)       |
| Poller fallback     | removed for production consumers                              | `*_TRANSPORT=outbox` switch (two code paths, two failure models, a larger test matrix for a local-only benefit)                                                                               |
| Dev pass-through    | stays on the outbox poller                                    | a dev-only queue (breaks the fixed list); consuming `email.policy.evaluate` (pretends to be the policy stage)                                                                                 |

---

## 9. Risks and mitigations

| Risk                                                                       | Mitigation                                                                                                                                                                                        |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First relay start publishes the whole pre-3.2 backlog                      | Consumer names unchanged, so ledger rows of the pollers make it duplicates; locally ~3.5 k rows; dormant queues are bounded. Documented in the runbook                                            |
| Quorum per-message TTL expires at the head only                            | Bounded lateness (≤ `maxDelayMs`), documented; only delivery uses the delay queue                                                                                                                 |
| `x-delivery-count` semantics of RabbitMQ 4.1 for channel-close returns     | Not relied upon; WP2 measures and records them; MIME poison guard and application attempts bound loops                                                                                            |
| Hold strategy pins prefetch slots during long outages                      | Intended backpressure; `maxDelayMs ≤ 60 s` ≪ `consumer_timeout` (30 min); age limit 24 h before dead-letter                                                                                       |
| Dormant queues drop messages                                               | By design until their stage exists; never the source of truth; `DormantQueueAtLimit` alert; stage onboarding from MySQL is part of each later step                                                |
| Lock connection loss → two relays briefly own a shard                      | Duplicates only (absorbed); confirmed rows marked with `WHERE published_at IS NULL`                                                                                                               |
| Reconciler re-drive duplicates in sibling queues (e.g. analytics)          | Every consumer is idempotent by `eventId`; re-drives are bounded (`RECONCILE_MAX_REDRIVES`); events that are retrying, dead-lettered or behind a backlog are not re-driven (Q12 step 5, §14)      |
| A forged approval on the broker (leaked broker credential, api compromise) | Topic permissions (only the relay publishes event keys); the planner plans only approvals with a matching outbox row (`approval_not_issued` / `approval_mismatch` dead letters); §14 F1           |
| A progress write fails (database down at the hop)                          | Logged; the delivery is acked anyway (never blocked on it). The reconciler may then re-drive that event once: a bounded duplicate every ledger absorbs                                            |
| A replayed approval older than the outbox retention (7 days)               | Its provenance can no longer be proven: dead-lettered `approval_not_issued` (fail closed); replays older than 7 days need operator action (runbook)                                               |
| Poison rows block outbox partition drops                                   | `OutboxPoisonRows` alert + runbook (fix and reset `attempts`, or document); never auto-deleted                                                                                                    |
| Integration suites race with live containers on the shared outbox          | In-process relays/reconcilers use the organization scope option; globalSetup pauses live `event-relay`/workers (the step 2.3 `live-worker.ts` pattern); suites use throwaway vhosts `eg-it-<hex>` |
| 8 GB Docker VM and the 3-node cluster                                      | `mem_limit 448m` ×3; apps profile stopped during the test (services in-process); ClamAV stopped only if needed and restarted after; reported honestly if it still cannot run                      |
| Topology argument drift on existing queues                                 | Only `x-queue-type` is an argument; everything else is a policy                                                                                                                                   |

---

## 10. Test plan

**Unit (Vitest)**

- event-contracts (WP1): topology invariants (§3 list), registry (every type has a schema and exchange, versions parse, reserved types have none), routing-key builders/parser round-trips, definitions generation and the committed-file drift check, retry policy validation.
- common messaging (WP2): backoff maths (equal jitter bounds with injected random, caps, overflow-safe for large n); content guard (each code, nested paths, a 1 000-recipient approval and every registered example payload pass, a Buffer, a JSON-serialized Buffer, a base64 PDF, a MIME part, a 2 049-character string, forbidden keys); codec (properties, headers, schema-version mismatch, tenant mismatch, unknown type); consumer decision table with a fake channel (handled/duplicate → ack; transient → hold + republish without attempt; retryable → attempt + 1; max attempts and retry age → dead-letter with headers; fatal → immediate; unconfirmed copy → no ack; stop during hold → nack requeue; result after channel death → dropped); publisher with a fake confirm channel (ack, nack, return-then-ack, timeout closes the channel, connection loss rejects pending); connection recovery with a fake `connect` (rotation, backoff, setups re-run, no `process.exit`).
- event-relay (WP3): batch walk (aggregate blocking, backoff skip, poison classification, batch bound), outcome → row updates, broker/db backoff, shard predicate and lock names, lag reporting for unowned shards; reconciler (cursor rules: not due, unpublished stop, poison settled, re-drive bound, exhausted, re-check, lookback, first-start positions); config bounds.
- email-worker / delivery-worker (WP4): wiring builds `QueueConsumer` with the right queue, types, prefetch, retry overrides and classifier; config refusals (`MIME_MAX_ATTEMPTS`, hold max).
- api (WP4): replay service with a fake channel (matching, filters, invalid skipped, requeue of the rest, header rewrite, confirm-before-ack, dry run, partial outcome audit), controller e2e (validation, 401/403, MFA, API key refused, 503 without URL, 409 lock).

**Integration (real broker, MySQL writer, Redis)** — each suite creates a throwaway vhost with the full topology (`init.mjs --vhost eg-it-<hex>`) and deletes it; in-process relays/reconcilers are scoped to fixture organizations; live containers that would race are paused.

| Scenario (brief)             | Suite (package)                                                                                                                                                                                                                                                                                                                         |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Topology and permissions     | WP2 `tests/integration/messaging-topology.test.ts`: the real vhost has exactly 6 exchanges (non-`amq.*`), 14 quorum queues, the bindings and policies; each role user can do exactly its permissions (e.g. email-worker cannot publish to `email.delivery`, nobody but admin can declare)                                               |
| Client recovery              | WP2 `messaging-client.test.ts`: confirms, mandatory returns, guard refusal, reconnect through an in-process TCP proxy cut, consumer re-subscribe, retry/dead-letter headers, delay queue round trip through `email.delivery.retry`                                                                                                      |
| RabbitMQ restart mid-stream  | WP3 relay suite through a TCP proxy cut (fast); WP5 stack suite with `docker compose restart rabbitmq` while 300 messages flow SMTP → parse → delivery: every message parsed once and delivered once, 0 dead letters, all outbox rows published                                                                                         |
| Broker node failure          | WP5 `rabbitmq-cluster` profile: 3 nodes; publish 3 000 confirmed events and consume with a `processOnce` test ledger; `docker kill` the leader of `email.received` mid-stream, keep going, restart it; every confirmed event processed exactly once, unconfirmed ones republished. Run by a dedicated script, not by `test:integration` |
| Consumer crash               | WP4 email-worker suite: the consumer runs in a child process and is SIGKILLed (a) before the commit and (b) after the commit before the ack; redelivered, one parse row, one ledger row; WP5 stack: `docker kill email-worker` mid-stream                                                                                               |
| Duplicate event              | WP4: the same envelope published twice and a duplicate outbox row with the same `event_id` → one effect (MIME and planner); WP5 stack: an admin-published copy of a real received event                                                                                                                                                 |
| Database outage              | WP3: relay with MySQL behind a TCP proxy cut → no row marked, publishes stop, resumes; WP4: consumers with the DB proxy cut → transient holds/delay retries without attempts, recovered, 0 dead letters; WP5 stack: `docker compose pause mysql` for 20 s mid-stream                                                                    |
| Queue backlog / backpressure | WP4: 5 000 approvals (or received events) backlog with prefetch 4: `messages_unacknowledged ≤ 4` sampled through the management API, all processed; WP3: `reject-publish` on a full work queue (test vhost with a lowered policy) → rows stay unpublished with backoff, then drain                                                      |
| Dead-letter replay           | WP2: failing handler → `max_attempts_exceeded` with headers; WP4 api suite: dead letters → `POST …/replay` (real HTTP, platform admin with MFA, audit row, Redis lock) → processed once; replaying again → ledger duplicate; dry run changes nothing; WP5 stack: replay through the live api                                            |
| Reconciliation               | WP3: published row without a ledger row → re-driven, consumed, settled; exhausted after the maximum; unpublished rows reported; poison rows reported                                                                                                                                                                                    |

**Regressions (WP5):** the step 2.2 `smtp-*`, step 2.3 `routing-*` and step 3.1 `mime-ingestion` stack suites with the rebuilt containers (event-relay, email-worker, delivery-worker, api; images built **one at a time**), so MIME and delivery run through the broker; package suites (`api`, `smtp-adapter`, `mail-routing`, `delivery-worker`, `email-worker`, `event-relay`); `tests/integration/services.test.ts` includes event-relay; the full gate (`format:check`, `lint`, `typecheck`, `test`, `test:e2e`, `build`, `db:migrate` + `db:status` + drift, clean-schema check, `db:seed` twice, `test:integration`).

---

## 11. Not in scope

- Consumers of the dormant queues (scan.*, policy, quarantine, archive, analytics) and switching their policies (4.x, 5.x, 8.1, analytics).
- Notification/webhook consumers and their queue (6.2; not in the brief's list).
- Moving the smtp-adapter cache invalidation or the dev pass-through onto RabbitMQ.
- Message lifecycle (`email_messages.status`) changes (3.3).
- Production broker provisioning (Amazon MQ or self-managed cluster, TLS `amqps`, definitions job), Grafana dashboards, Alertmanager routing (10.1, 10.3).
- Per-tenant queues, fairness scheduling or tenant rate limits on queues (the routing key makes them a binding change later).
- Federation/shovel to the DR region (10.2).
- A portal page for dead letters (7.x).
- Outbox row purge tooling for poison rows (operators follow the runbook).

---

## 12. Work packages

Four sequential waves; packages in one wave touch disjoint files. **Only WP3 runs `pnpm install` and changes `pnpm-lock.yaml`** (new workspace package `apps/event-relay`); no other package adds a dependency (amqplib, prom-client and zod are already present) — a missing dependency is reported, not installed.

| Wave | Package | Scope                                                                                                                                                                                                                                                                                                                     |
| ---- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | WP1     | event-contracts registry/topology/definitions (+ legacy file), `definitions.json`, migration `event_relay` + schema + seed permission, `packages/config`, broker provisioning (`init.mjs`, conf, cluster profile), compose, `.env.example` + local `.env`, k8s, topology doc, contracts/data-ownership/database/rbac docs |
| 2    | WP2     | `packages/common/src/messaging/*` client library (connection, publisher, consumer, codec, headers, guard, backoff, errors, metrics, Nest module) with unit tests; broker integration suites in `tests/integration` (topology, permissions, client)                                                                        |
| 3    | WP3     | `apps/event-relay` (relay, reconciler, config, metrics, health, unit + integration tests, README), root `package.json` scripts, lockfile, Prometheus jobs and alert rules, runbook `rabbitmq-messaging.md`                                                                                                                |
| 3    | WP4     | email-worker and delivery-worker on `QueueConsumer`, removals (Q14) incl. policy/archive/notification workers and `common` legacy module, api dead-letter module + OpenAPI + tests, worker READMEs                                                                                                                        |
| 4    | WP5     | Stack chaos suites, cluster node-failure test, regressions, image rebuilds (one at a time), full gate, docs (README, overview, failure handling, security boundaries, diagrams, execution plan), §13 verification record                                                                                                  |

## 13. Verification results

Recorded by WP5 on 2026-11-04 on the development machine (macOS, Docker Desktop VM 8 GB shared with other projects' containers), branch `build/platform`, Compose infrastructure plus the `smtp-test` profile and the **whole apps profile as containers built from this tree**, `DELIVERY_DEV_PASSTHROUGH_ENABLED=true`, `APP_ENV=local`. Nothing was committed.

### 13.1 Images and stack

- Rebuilt one at a time (`docker compose --profile apps build <service>`, nothing else building): `db-migrate` 49 s, `event-relay` 63 s, `email-worker` 81 s, `delivery-worker` 57 s, `api` 63 s, `policy-engine` 53 s, `archive-worker` 53 s, `notification-worker` 53 s; then `smtp-adapter` 63 s (not in the list, rebuilt because `common` changed under it). `admin-portal` was not rebuilt (no change in this step).
- `docker compose --profile apps up -d --wait`: `db-migrate` (10 migrations, nothing pending, partitions up to date) and `rabbitmq-init` ran first; every app container healthy. Readiness checks per service match contracts §9 (`services.test.ts`): event-relay `mysql`, `rabbitmq`; email-worker and delivery-worker `mysql`, `rabbitmq`, `redis`, `s3`; policy-engine `mysql`, `redis`; archive-worker `mysql`, `s3`; notification-worker `mysql`; api without `rabbitmq` (ops connection per request).
- **Pre-3.2 backlog:** 3 592 unpublished outbox rows (3 401 `domain.status.changed.v1`, 130 `domain.routing.changed.v1`, 53 `mail.delivery.status_changed.v1`, 3 received, 3 parsed, 2 approvals) were all published within ~0.5 s of the relay's start; 0 poison rows; the 3 received and 2 approval events were consumed as ledger **duplicates** (consumer names unchanged), as designed. `outbox_relay_shards_held = 4`, `outbox_relay_lag_seconds = 0` on all shards, `outbox_unpublished_rows = 0`.
- **Legacy cleanup on `/`:** the first `rabbitmq-init` kept every ADR-0005 queue (`kept: not empty`) although all held 0 messages: RabbitMQ 4.1 answers `400 … queue.delete operations with if-empty flag set are not supported by quorum queues`. Fixed in `init.mjs` (§13.5); after re-running `docker compose up rabbitmq-init` all ten queues and both exchanges were deleted; vhost `/` holds no queue and no non-default exchange.
- Local environment change: `.env` had `SMTP_ADAPTER_HOST=host.docker.internal` (from the host-run verification of 2.2/2.3) while the adapter ran only as a container, so Postfix's lookups were refused (`451 4.3.0 Temporary lookup failure`). Set to `smtp-adapter` (the `.env.example` default) and recreated `postfix`/`postfix-outbound`. The stack gate had not caught it (§13.5).

### 13.2 Stack chaos suites (`tests/integration/messaging-*.test.ts`, live containers)

Gate `support/messaging-stack.ts`: the routing gate (incl. the dev pass-through) plus running containers `event-relay`, `email-worker`, `delivery-worker`, `api`, `rabbitmq`, a ready event-relay and api, and an email-worker exporting `amqp_consumer_messages_total`. Every scenario sends single-recipient messages with `smtp-source` through `postfix:25` to a fixture domain whose destination is `mail-sink`, then asserts per message: one `email_message_parses` row (final), one `email-worker.mime-parser` ledger row, one parse event; one approval, one `delivery-worker.planner` ledger row, one delivery (`delivered`), one reinjection group, no recipient with two deliveries; every outbox row of the run published; the dead-letter queue depth unchanged; exactly `n` files in the sink mailbox. Fixtures are removed by `SmtpFixtures.cleanup` (rows, ledger rows, S3 prefix, sink mailbox).

| Suite                      | Scenario                                                                                                                                                                                                                                                   | Result (2026-11-04)                                                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `messaging-restart`        | 300 messages; `docker compose restart rabbitmq` once after 100 stored (received events in flight) and once after 75 approvals were planned (approvals in flight)                                                                                           | passed (4 runs): restarts 8.4–8.7 s; all 300 delivered 39–65 s after the first send; 300/300/300 parses, MIME ledger, approvals, planner ledger, deliveries, reinjections; 0 unpublished; 0 dead letters                                                                                                                                                                |
| `messaging-db-outage`      | 300 messages; `docker compose pause mysql` for 20.2 s after ~80 parsed; unpause; replica health                                                                                                                                                            | passed (4 runs): all exactly once, 0 dead letters (transient holds, no attempt consumed), 0 unpublished; all delivered 42–131 s after the first send; replica `Replica_IO_Running`/`SQL_Running` Yes, lag 0 right after the unpause; `mysql-replica` healthy                                                                                                            |
| `messaging-consumer-crash` | 300 messages; `docker kill` (SIGKILL) of the email-worker after ~90 parsed; `docker start` after 5 s (the restart policy does not apply to a manual kill)                                                                                                  | passed (4 runs): worker ready again after 12.1–12.8 s; 4 deliveries redelivered in one run; all exactly once, 0 dead letters                                                                                                                                                                                                                                            |
| `messaging-duplicates`     | one message through the whole pipeline; the administrator publishes exact copies (envelope from the outbox rows, `appId event-relay`) of its received event and approval, twice                                                                            | passed (4 runs): `amqp_consumer_messages_total{outcome="duplicate"}` +2 on each consumer; every count unchanged; queues empty; 1 sink file                                                                                                                                                                                                                              |
| `messaging-backlog`        | `docker compose pause email-worker`; 500 messages; all 500 received events published (confirmed) into `email.received` (496 ready, 4 in the paused consumer's prefetch); unpause; management API sampled every 250 ms                                      | passed (5 runs): drained in 2.9–4.5 s (111–170 msg/s); max unacked 4 (queue counter) and 4 (consumer channel counter, sampled in the last 2 runs) = `MIME_CONCURRENCY`; 1 consumer; all 500 exactly once                                                                                                                                                                |
| `messaging-replay`         | a genuine pending delivery (fixture message, EML in MinIO, pending recipient; approval in the outbox marked published) dead-lettered with the exact `max_attempts_exceeded` headers of the library; MFA platform admin replays it through the **live api** | passed (4 runs): dry run matched 1, moved nothing; replay matched/replayed 1, dead-letter queue back to its depth; planned once, delivered, 1 sink file; 1 audit row (`platform.dead_letters_replayed`, actor = the admin's public id, `outcome complete`); second replay matched 0; the same letter put back and replayed → planner ledger duplicate, still 1 delivery |
| `messaging-legacy-cleanup` | ADR-0005 quorum queues + exchanges in a throwaway vhost, one queue holding a message; `init.mjs --cleanup-legacy --legacy-vhost`                                                                                                                           | passed: empty queues and `mail.dlx` deleted, the non-empty queue and its bound `mail.events` kept with a warning; second run idempotent; output contains no password                                                                                                                                                                                                    |

### 13.3 Broker node failure (`tests/integration/cluster/node-failure.test.ts`, `pnpm --filter @email-gateway/integration-tests test:cluster`)

Procedure as in the test header and the runbook. The app containers were stopped; the first attempt used `docker compose --profile apps stop`, which also stopped MySQL and the default profile (corrected in the procedure: stop the app services by name); ClamAV stayed up (memory sufficed). `docker compose --profile rabbitmq-cluster up -d --wait` → 3 healthy nodes in 12 s (`rabbit@rmq1..3` running and disk nodes), `init.mjs --mgmt-url http://127.0.0.1:15701 --users` provisioned topology v1 and the role users.

Result: **passed** (21.8 s). 3 000 events published to `email.ingestion` in batches of 20 every 50 ms by `eg-relay`, consumed from `email.received` by `eg-email-worker` (prefetch 16) with a `processOnce` ledger; leader before `rabbit@rmq1`, killed (`docker kill`) after 1 000 confirms, down for 8.0 s while another third was published, started again; new leader `rabbit@rmq3`; 40 publishes unconfirmed (all republished with the same event id and confirmed), 3 000/3 000 confirmed event ids with exactly one ledger row and exactly one `handled` outcome, 20 redeliveries recorded as ledger duplicates, 0 lost, queue empty. Ledger rows deleted. Afterwards the three cluster containers were removed, exactly `email-gateway_rabbitmq-cluster-{1,2,3}-data` were deleted, and the apps profile came back healthy (replica IO/SQL running, lag 0).

### 13.4 Regressions and the full gate

| Command                                                                   | Result                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm format:check`                                                       | clean                                                                                                                                                                                                                                                                                                          |
| `pnpm turbo run build --force` / `lint --force` / `typecheck --force`     | 19 / 28 / 28 tasks successful                                                                                                                                                                                                                                                                                  |
| `pnpm turbo run test --force`                                             | 27 tasks, **2 643 tests** (api 1 188, smtp-adapter 330, mime-parser 233, common 201, mail-routing 143, database 128, delivery-worker 104, event-relay 88, event-contracts 74, email-worker 72, config 39, logger 38, admin-portal 2, policy-engine/archive-worker/notification-worker 1 each)                  |
| `pnpm turbo run test:e2e --force`                                         | api **225**                                                                                                                                                                                                                                                                                                    |
| `pnpm db:migrate` / `pnpm db:status` / drift (`migrate diff --exit-code`) | 10 migrations, nothing pending, "Database schema is up to date!", "No difference detected"                                                                                                                                                                                                                     |
| clean-schema check in `email_gateway_verify`                              | `migrate deploy` of all 10 migrations, `partitions apply` (19 actions), drift "No difference detected", **71 tables, 19 partitioned**; schema dropped and grants revoked                                                                                                                                       |
| `pnpm db:seed` twice                                                      | both exit 0; 36 permissions, 8 roles, 145 role-permission rows                                                                                                                                                                                                                                                 |
| `docker run prom/prometheus:v3.6.0 promtool …`                            | `check config` valid (1 rule file), `check rules` 12 rules, `test rules` SUCCESS                                                                                                                                                                                                                               |
| `pnpm test:integration` (first run)                                       | stack suites 36 files: 217 passed, 2 failed, both expected changes of this step (§13.5: a parse event is now published; 36 permissions); the chain stopped before the package suites                                                                                                                           |
| `pnpm test:integration` (second run)                                      | stack 36 files, **219 passed, 0 skipped**; api 217 + 1 skipped, smtp-adapter 65, mail-routing 16, delivery-worker 36; email-worker 19 + **1 failed** (the live event-relay marked a fixture row, §13.5 item 8), so event-relay did not run. After the fix: email-worker 20, delivery-worker 36, event-relay 11 |
| `pnpm test:integration` (final run, 18 min)                               | **all green**: stack 36 files, **219 passed, 0 skipped** (932 s); api 18 files 217 + 1 skipped; smtp-adapter 65; mail-routing 16; delivery-worker 36; email-worker 20; event-relay 11                                                                                                                          |

Every step 2.2 `smtp-*` (incl. `smtp-concurrency` 40 × 1 000, zero loss, 37 msg/s end to end), step 2.3 `routing-*` and step 3.1 `mime-ingestion` suite passed with MIME and delivery running **through the broker**. Durations of note: `routing-rate-limit` 164 s (three one-minute windows), whole stack run 14–15.5 min; `smtp-concurrency` in the final run 1 000 messages, 129 msg/s SMTP accept, 45.9 msg/s end to end, loss 0.

### 13.5 Production-code and test fixes made by WP5

Production code:

1. `infrastructure/rabbitmq/init.mjs` `--cleanup-legacy`: quorum queues refuse `DELETE ?if-empty=true` on RabbitMQ 4.x (HTTP 400), so the cleanup never removed any legacy queue (and therefore never the bound exchanges). It now checks `messages == 0` and `consumers == 0` itself and deletes quorum queues without the flag (classic queues keep `if-empty`); warnings name the HTTP status. New test-only option `--legacy-vhost <name>` points the cleanup at another vhost. Test: `tests/integration/messaging-legacy-cleanup.test.ts`. Residual race (documented): a message published between the check and the delete would be lost; nothing publishes to the legacy exchanges any more.

No other production code was changed. Test support and environment:

2. `tests/integration/support/smtp-stack.ts`: the reachability probe treated `postmap` exit 1 as NOTFOUND, but a `fatal: … Connection refused` also exits 1, so a stack whose Postfix could not reach the adapter passed the gate. The probe now also requires an empty stderr.
3. `tests/integration/mime-ingestion.test.ts`: asserted `publishedAt: null` on the `mail.message.parsed.v1` row (true before the relay existed); it now waits for the row to be published by the event-relay.
4. `tests/integration/seed.test.ts`: 35 → 36 permissions, and asserts `platform:dead_letter_replay` is held by `platform_admin` and `super_admin` only.
5. `tests/integration/services.test.ts`: event-relay added; exact readiness checks per service (no `rabbitmq` on policy-engine, archive-worker, notification-worker, api, smtp-adapter); relay holds all shards, one AMQP connection up, no poison rows.
6. `support/env.ts` (event-relay port), `support/metrics.ts` (more services), `support/broker.ts` (`runInit` exported, channel `user`).
7. Local `.env`: `SMTP_ADAPTER_HOST=smtp-adapter` (container mode).
8. `apps/email-worker/integration/support/live-worker.ts` and `apps/delivery-worker/integration/support/live-worker.ts` (vitest globalSetup): they paused only their own live worker, so the live `event-relay` published and marked the suites' fixture outbox rows (`mail.message.parsed.v1` with `published_at` set where the email-worker suite expects `NULL`). They now pause the live `event-relay` as well, as `apps/event-relay/integration/support/live-relay.ts` does; the paused containers recover by themselves (readiness green again without a restart).

No fixture-cleanup change was needed for the broker path: `SmtpFixtures.cleanup` already removes ledger rows through the run's outbox event ids, and none of the 2.2/2.3/3.1 suites needed a timing change.

### 13.6 Measured broker behaviour (WP2, `docs/architecture/messaging-topology.md` "Client behaviour")

`x-delivery-count` increments by one per return for both `nack(requeue)` and a channel close with the delivery unacked; `delivery-limit 20` dead-letters after 21 deliveries with `dead-letter.<queue>` and `x-first-death-reason: delivery_limit`; no `x-acquired-count` on 4.1.8 quorum queues; the queue-level `messages_unacknowledged` was once seen one above the prefetch while acks were in flight (the backlog suite therefore also samples the consumer channel's counter; both stayed at 4 here); the delay hop through `email.delivery.retry` returns to `email.delivery.pending` after the per-message TTL.

### 13.7 Deviations recorded

- Audit action of a replay is `platform.dead_letters_replayed` (api naming D14), not `platform.dead_letters.replay` as written in Q9 (WP4 decision; runbook updated).
- `DELIVERY_OUTBOX_SAFETY_LAG_MS` governs only the dev pass-through; in the stack suites approvals followed ingestion within seconds.

### 13.8 Not complete / not verified locally

- **Commit pending**; CI has not run any of these suites (the workflow change for the event-relay image and the cluster profile is not executed).
- **Production broker:** Amazon MQ or a self-managed production cluster, its definitions-import job, `amqps://` / TLS client settings and certificate handling (10.1) — not verified; locally plain AMQP.
- **Kubernetes:** the `event-relay` Deployment and the role-URL secrets in `infrastructure/kubernetes` (WP1/WP3) render (`kubectl kustomize` of `base`, `overlays/saas`, `overlays/dedicated`: 48 objects each, the event-relay Deployment included) but were never applied to a cluster; liveness/readiness under Kubernetes restarts not exercised.
- **Throughput at 1 M messages/day** (≈ 12 msg/s average, peaks higher) with several relay replicas and sharded workers: not measured; local figures are a single relay (4 shards) and one consumer per queue (backlog drain 111–170 msg/s for MIME; 1 000-message SMTP run 37 msg/s end to end, bounded by the SMTP path).
- Alertmanager routing and dashboards (10.3); the rules are validated by `promtool` only, not fired in a running Prometheus (the observability profile cannot run with the apps profile on this VM).
- The node-failure test ran on a local 3-node cluster with 448 MiB nodes; network partitions (as opposed to a killed node) and a minority-only cluster were not tested.
- `admin-portal` image not rebuilt (unchanged).

### 13.9 Independent verification (round 1, 2026-11-04)

Re-run by the verification engineer on the same machine, from the working tree as WP1–WP5 left it (nothing committed). No product or test code was changed in this round.

| Command                                                                   | Result                                                                                                                                                                                       |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm install --frozen-lockfile` / `pnpm db:generate`                     | lockfile up to date / client generated                                                                                                                                                       |
| `pnpm db:migrate` / `pnpm db:status` / drift (`migrate diff --exit-code`) | 10 migrations, nothing pending; "Database schema is up to date!"; no difference                                                                                                              |
| clean-schema check in `email_gateway_verify`                              | `migrate deploy` of 10 migrations, `partitions apply` (19 actions), drift "No difference detected", 71 tables, 19 partitioned; schema dropped and grants revoked                             |
| `pnpm format:check` / `lint` / `typecheck`                                | clean / 28 of 28 / 28 of 28                                                                                                                                                                  |
| `pnpm test` / `pnpm test:e2e` / `pnpm build`                              | 27 of 27 tasks, 2 643 tests / api 225 / 19 of 19                                                                                                                                             |
| image rebuilds, one at a time                                             | `db-migrate` 71 s, `event-relay` 59 s, `email-worker` 69 s, `delivery-worker` 57 s, `api` 61 s, `policy-engine` 54 s, `archive-worker` 51 s, `notification-worker` 51 s, `smtp-adapter` 57 s |
| `docker compose --profile apps --profile smtp-test up -d --wait`          | every app healthy, `db-migrate` and `rabbitmq-init` exited 0; `clamav` unhealthy (OOM-killed, see below), restarted, healthy after about 15 s                                                |
| `pnpm test:integration` (1 086 s)                                         | all green: stack 36 files, 219 passed (914 s); api 18 files, 217 passed and 1 skipped; smtp-adapter 65; mail-routing 16; delivery-worker 36; email-worker 20; event-relay 11                 |

Every step 2.2 `smtp-*`, step 2.3 `routing-*` and step 3.1 `mime-ingestion` suite and every `messaging-*` chaos suite passed through the RabbitMQ path. `smtp-concurrency` measured 1 000 messages, 40 sessions, 52.4 msg/s SMTP accept, 30.2 msg/s end to end, loss 0. The skipped api test is the "policy service down" branch of `common.test.ts`, which skips while smtp-adapter is running.

Environment handling: `SMTP_ADAPTER_HOST=smtp-adapter` was set in `.env` only for this run. Afterwards `.env` was put back to `SMTP_ADAPTER_HOST=host.docker.internal`, and `cmp` confirmed it is byte-identical to the backup. This undoes the permanent change in §13.5 item 7. The running `postfix` containers keep `smtp-adapter` until they are recreated.

ClamAV: during `up --wait`, `clamav` was reported unhealthy with `OOMKilled=true` (the 8 GB VM). It was restarted and stayed healthy for the whole run (`OOMKilled=false` afterwards). This is recorded as an environment event, not a product failure. No suite needed a re-run.

Leftovers after the run:

- **Postfix:** the `postfix` and `postfix-notify` queues were empty. `postfix-outbound` held 3 deferred `probe@gateway.test` messages from the api `common.test.ts` SmtpEmailSender probe: one from this run and two from WP5's runs (`mail.gateway.test` does not resolve). They were removed with `postsuper -d` by queue id, so all three queues are now at 0. This is a test-hygiene gap from before step 3.2: the probe never cleans up after itself, and it also leaves its EML and part objects in S3 under the seeded `demo` organization (org 2, 12 objects, none of them `it-*`).
- **MySQL:** 0 `it-*` organizations, domains and users, 0 `it.*` ledger rows, 0 unpublished outbox rows. **S3:** 0 `it-*` objects.
- **RabbitMQ:** all work, delay and dead-letter queues were at 0 after the run. Seven dormant queues had no consumer and held events from this run and earlier ones: `email.analytics`, `scan.attachment`, `scan.auth`, `scan.dlp`, `scan.spam` and `scan.url` at 10 000 each (the `max-length` cap with `drop-head`), and `email.policy.evaluate` at 7. They were purged. The final depth (`rabbitmqctl list_queues -p email-gateway`) is 0 on all 14 queues, with 1 consumer on `email.received` and 1 on `email.delivery.pending`. Vhost `/` has no queues. Note: until their stages exist, every stack run fills the dormant queues up to the cap, so after test runs they have to be purged by name.

## 14. Review round 1: findings and fixes (2026-11-04)

Six findings at medium or above (five distinct issues; two findings describe the reconciler issue from two angles). Each was checked against the code and the live broker before it was fixed. All were confirmed; none was rejected.

| #      | Finding (severity)                                                                                                                                                          | Confirmed by                                                                                                                                                                                   | Fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Tests                                                                                                                                                                                                                                                                                                            |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F1     | The broker is a trust boundary for approvals: `eg-ops`, `eg-relay` and `eg-delivery-worker` could publish a self-consistent forged approval that the planner planned (high) | `init.mjs` gave `eg-ops` write on the six exchanges and set no topic permissions; `decodeDelivery` accepts retry keys; the planner checked only the EML prefix, the message and the recipients | (1) `assertApprovalIssued` in the planner, inside the `processOnce` transaction: a `message_outbox` row with the same `event_id`, `event_type`, `organization_id` (pruned by `created_at ≥ received_at − 5 min`) **and payload**, else fatal `approval_not_issued` / `approval_mismatch`; new index `message_outbox (event_id)` (migration `20261104120000_consumer_progress`). The message is looked up first: an approval of a message that does not exist is rejected and acked (nothing to plan). (2) `eg-ops` write narrowed to `^email\.(ingestion\|delivery)$`. (3) Topic permissions per user and exchange (Q10), set and verified exactly by `init.mjs --users`. (4) Residual risk in Q10 and ADR-0024. | planner unit tests (forged, mismatch, replay passes, missing message); delivery-worker integration `approvals.test.ts` (forged and altered approvals dead-lettered, real one planned); `messaging-permissions.test.ts` (each role refused outside its keys, `ACCESS_REFUSED`); replay suites unchanged and green |
| F2     | Dead letters silently deleted after about 20 replay scans (quorum default `delivery-limit` 20, no DLX on `email.dead-letter`) (high, reported twice)                        | live broker: `delivery_limit: 20`, no dead-letter target on `email.dead-letter`; replay `nack(requeue)`s every message it does not take                                                        | `delivery-limit: -1` in the dead-letter, delay and dormant policies (`topology.ts`), `definitions.json` regenerated and imported (Q4)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | topology unit test; api integration `dead-letters.test.ts` keeps dead letters across more than 20 returning scans                                                                                                                                                                                                |
| F3     | A work queue that stays full turned healthy outbox rows into poison (a nack counted as `attempts + 1`) (high)                                                               | `runShard` handled `nacked` like `returned`; 10 nacks ≈ 4–9 minutes                                                                                                                            | a nack is infrastructure: `last_error = 'nacked'`, `available_at` from the shard's run of consecutive nacking passes, `attempts` unchanged; only mandatory returns and contract/guard failures count (Q11 step 6)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | relay unit tests (no attempt on nack, never poison while full, drains); relay integration with `RELAY_MAX_ATTEMPTS=2` and at least 30 nacks: `attempts` stays 0, all rows published after the drain                                                                                                              |
| F4, F5 | The reconciler took "no ledger row" for "lost": it re-drove events still queued, retrying or dead-lettered (medium and high)                                                | consumers wrote nothing on retry or dead-letter hops; the delivery retry span (≥ 18 min) exceeds the 900 s threshold                                                                           | `QueueConsumer` records `message_consumer_progress` (`retrying` after each confirmed retry hop, `dead_lettered` after the confirmed dead-letter copy; best effort, bounded wait). The reconciler settles `dead_lettered`, defers `retrying` within the threshold plus 2 × `maxDelayMs`, and defers while the queue has ready messages or its depth is unknown (Q12 step 5). A dead letter with a reason a relay copy cannot produce (contract, schema version, tenant, approval provenance) never settles a row, so a forged copy cannot hide a lost event. Purged after 30 days with the ledger.                                                                                                                | reconciler unit tests (dead-lettered settled, untrusted reasons re-driven, retrying deferred then re-driven, per-queue hop gaps, backlog and unknown depth deferred); reconciler integration against the real writer and broker; consumer unit tests for the progress records                                    |

Changes found during the re-verification:

- **Test cleanup race (new dead letters).** The first full run left 20 `approval_not_issued` dead letters of an `it-*` organization: `SmtpFixtures.cleanup` deleted the run's outbox rows while dev pass-through approvals were still on their way to the planner, and the planner then found the message but no outbox row. Fixed twice over: the planner reads the message before the provenance (a missing message is a plain rejection), and the cleanup deletes messages before outbox rows (in one transaction snapshot a visible message implies a visible outbox row). It also removes the run's `message_consumer_progress` rows. The next runs left no dead letters and no progress rows.
- **`smtp-concurrency` assertion.** One run stored all 1 000 messages (1 000 identities, EMLs and outbox rows, loss 0) but counted 999 distinct queue ids: the Postfix ids `4jKFxV5fmHz12JnW` and `4jKFxV5fMHz12Jnw` differ only in case, and `GROUP BY mta_queue_id` merges them under the column's case-insensitive collation `utf8mb4_unicode_ci`. The test now counts distinct ids case-sensitively. The underlying collation issue is **not fixed** here (outside this step; see §14.2).
- **`routing-signals` timeout.** The "re-read the whole delivery log" case timed out once (180 s) because the local `postfix-outbound` maillog had grown to 26 MB over many runs. It was rotated with `postfix logrotate` (the tailer follows rotations); no code change.

### 14.1 Re-verification

Lead engineer, same machine, working tree as above (nothing committed). Every command of the final round passed:

| Command                                                                   | Result                                                                                                                                                                                                                                                                                  |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm db:migrate` / `pnpm db:status` / drift (`migrate diff --exit-code`) | 11 migrations, nothing pending; "Database schema is up to date!"; "No difference detected"                                                                                                                                                                                              |
| clean-schema check in `email_gateway_verify`                              | `migrate deploy` of 11 migrations, `partitions apply` (19 actions, `message_consumer_progress` purge included), drift "No difference detected", 72 tables, 19 partitioned; schema dropped and grant revoked                                                                             |
| `pnpm format:check` / `lint` / `typecheck` / `build`                      | clean / 28 of 28 / 28 of 28 / 19 of 19                                                                                                                                                                                                                                                  |
| `pnpm test` / `pnpm test:e2e`                                             | 27 of 27 tasks, 2 670 tests / api 225                                                                                                                                                                                                                                                   |
| image rebuilds, one at a time                                             | `db-migrate`, `event-relay` (twice), `email-worker`, `delivery-worker` (twice), `api`, `policy-engine`, `archive-worker`, `notification-worker`, `smtp-adapter`: all rc 0                                                                                                               |
| `docker compose --profile apps --profile smtp-test up -d --wait`          | every app healthy, `db-migrate` and `rabbitmq-init` exited 0 (definitions with `delivery-limit: -1`, topic permissions verified); `clamav` OOM-killed on the 8 GB VM again, restarted, healthy for every run                                                                            |
| `pnpm test:integration` (final run, 1 104 s)                              | all green: stack 36 files, 226 passed; api 18 files, 218 passed and 1 skipped (the policy-down branch, skipped while smtp-adapter runs); smtp-adapter 65; mail-routing 16; delivery-worker 37; email-worker 20; event-relay 15. `smtp-concurrency`: 1 000 messages, 40 sessions, loss 0 |

Earlier full runs of this round: run 1 all green (stack 226, api 218 + 1 skipped, delivery-worker 37, event-relay 15) but left the 20 test dead letters described above; run 2 failed on the `routing-signals` log re-read timeout; run 3 failed on the `smtp-concurrency` case-insensitive queue-id count. The chain stops at the first failing package, so runs 2 and 3 did not reach the api and package suites; the final run is the one that counts.

Leftovers after the final run: MySQL 0 `it-*` organizations, domains and users, 0 `it.*` ledger rows, 0 `message_consumer_progress` rows, 0 unpublished and 0 poison outbox rows; `email.dead-letter` 0; Postfix queues 0 after removing the one deferred `probe@gateway.test` message of the api `common.test.ts` probe (pre-existing gap, §13.9); the dormant queues (`email.analytics`, `scan.*`) were purged by name; all 14 queues at 0, vhost `/` has no queues. `.env` was set to `SMTP_ADAPTER_HOST=smtp-adapter` for the runs only and restored byte-identical (`cmp`). The local `postfix-outbound` maillog was rotated once (`postfix logrotate`).

### 14.2 Not done / not verified

- The 3-node broker node-failure test (`test:cluster`) was not re-run in this round (it cannot run next to the apps profile on this VM); no code on its path changed except the topology policies, which it imports.
- **`mta_queue_id`, `outbound_queue_id` and `dsn_queue_id` use the case-insensitive collation `utf8mb4_unicode_ci`.** Postfix queue ids are case-sensitive, so two ids that differ only in case compare equal. Besides the test assertion above, the bounce and delivery-status matching (`recorder.ts`, `bounces.repository.ts`, `delivery-reconciler.ts` look up `outbound_queue_id`) could in principle match the wrong delivery. This predates step 3.2 and is not fixed here; it needs a forward migration to a binary collation for those columns (step 2.3 owner).
- The backlog deferral of the reconciler waits as long as the queue has ready messages: under a sustained backlog a lost event is re-driven only once the queue drains (nothing is lost; the row stays watched). Production tuning of this, and of the hop-gap window, needs real traffic.
- Every item of §13.8 still applies (commit pending, CI, production broker and TLS, Kubernetes, throughput at 1 M/day, alert delivery).

### 14.2 Independent pre-commit verification (2026-11-04)

Re-run from a clean shell after review round 1, before the commit:

- `pnpm install --frozen-lockfile`, `format:check`, `lint`, `typecheck`, `test`, `test:e2e`, `build`, `db:status`: all pass.
- Ten images rebuilt one at a time (db-migrate, event-relay, api, smtp-adapter, email-worker, delivery-worker, policy-engine, archive-worker, notification-worker, admin-portal).
- `pnpm test:integration` with `SMTP_ADAPTER_HOST=smtp-adapter`: stack 226/226, api 218 + 1 skipped, smtp-adapter 65, mail-routing 16, delivery-worker 37, email-worker 20, event-relay 15; smtp-concurrency 1 000 messages, loss 0. clamav came up unhealthy (OOM on the 8 GB VM) and was restarted before the run. `.env` restored byte-identical.
- Node-failure test on the `rabbitmq-cluster` profile (re-run because review round 1 changed the topology policies it imports): 3 000/3 000 confirmed, leader `rabbit@rmq1` killed, `rabbit@rmq3` elected, down 3.7 s, 20 unconfirmed publishes republished, 0 handled twice, 15 ledger duplicates absorbed, 0 lost. Cluster containers and exactly the three cluster volumes removed; apps profile healthy again.
- After cleanup: all 14 queues at 0 messages; postfix, postfix-outbound and postfix-notify queues at 0 (one api `common.test.ts` probe removed).
