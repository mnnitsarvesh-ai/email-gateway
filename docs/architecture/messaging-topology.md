# Messaging topology (RabbitMQ, topology v2)

The reference for the RabbitMQ broker objects of the gateway: exchanges, queues, bindings, routing keys, headers, policies, dead-letter paths, retry hops, the dormant-queue rule, users and permissions, and provisioning. Decisions: [ADR-0024](adr/0024-rabbitmq-topology-retry-dead-letter.md) (topology, retry, dead-letter, replay, least privilege; supersedes ADR-0005) and [ADR-0023](adr/0023-outbox-relay-and-reconciliation.md) (outbox relay and reconciliation). Design: [step 3.2](../plan/steps/07-rabbitmq.md) (§ and Q references below point there).

## Status

**Topology v2 (step 3.3, [design L7](../plan/steps/08-message-lifecycle.md#l7-events-packagesevent-contracts-registry-topology-v2), [ADR-0025](adr/0025-message-lifecycle-state-machine.md)).** `TOPOLOGY_VERSION = 2` adds two registered event types and five bindings to topology v1; the six exchanges, fourteen queues and their policies are unchanged:

- `mail.message.state_changed.v1` on `email.events` (every applied lifecycle transition): no binding of its own, it reaches only the `email.analytics` firehose (`org.#`).
- `mail.message.rescan_requested.v1` on `email.security` (the api's administrative rescan): bound with `org.*.mail.message.rescan_requested.v1` to `scan.auth`, `scan.spam`, `scan.url`, `scan.attachment` and `scan.dlp` (dormant until 4.x; each stage consumes both `parsed.v1` and `rescan_requested.v1`, and must check the event's `lifecycleRound` against the writer row).
- The vhost description is `email-gateway topology v2`. `init.mjs` imports additively (existing objects unchanged), so `pnpm rabbitmq:init` (or the Compose `rabbitmq-init`) upgrades a v1 vhost in place. No permission changes: the relay already publishes `^org\.` keys to every exchange.

| Part                                                                                                                                | Status                                                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Event registry, topology as data, routing-key builders/parser, invariants, definitions generator (`packages/event-contracts`)       | **IMPLEMENTED** (step 3.2 WP1), unit-tested (`registry.test.ts`, `topology.test.ts`)                                                                                              |
| `infrastructure/rabbitmq/definitions.json`, `init.mjs`, Compose `rabbitmq-init`, `pnpm rabbitmq:init`, role users, cluster profile  | **IMPLEMENTED** (step 3.2 WP1); applied to the local broker and to the 3-node test cluster                                                                                        |
| AMQP client library (connection recovery, confirm publisher, consumer with retry/dead-letter, content guard, headers constants)     | **IMPLEMENTED** (step 3.2 WP2, `packages/common/src/messaging/`); unit-tested with amqplib fakes, integration-tested against the broker (`tests/integration/messaging-*.test.ts`) |
| `apps/event-relay` (outbox relay and reconciler), Prometheus jobs and alert rules                                                   | step 3.2, **WP3** (not built yet)                                                                                                                                                 |
| email-worker and delivery-worker consuming `email.received` / `email.delivery.pending`; dead-letter replay API; legacy code removal | step 3.2, **WP4** (not built yet). Until then nothing publishes to or consumes from this vhost: producers write `message_outbox`, and the step 2.3/3.1 outbox pollers still run   |
| Consumers of the dormant queues                                                                                                     | Their own steps (table below)                                                                                                                                                     |

## Source of truth and provisioning

- **`packages/event-contracts/src/registry.ts`**: `EVENT_REGISTRY` (every concrete event type `<name>.vN` → exchange, zod schema, outbox `aggregate_type`, version), `RESERVED_EVENT_TYPES`, `eventDefinition(type)`, `schemaVersionOf(type)`.
- **`packages/event-contracts/src/topology.ts`**: `TOPOLOGY` (`TOPOLOGY_VERSION = 2`, `DEFAULT_VHOST = 'email-gateway'`), `EXCHANGE_NAMES`, `QUEUE_NAMES`, per-queue role, home exchange, bindings, consumer, retry policy and policy definition; helpers `queueDefinition`, `eventRoutingKey`, `retryRoutingKey`, `delayRoutingKey`, `deadLetterRoutingKey`, `parseRoutingKey`, `eventTypesBoundTo`, `routeMessage`/`topicMatches` (AMQP topic semantics), `retryPolicyViolations`, `validateTopology` (the §3 invariants, run by the tests and by the export CLI).
- **`packages/event-contracts/src/definitions.ts`**: `toRabbitDefinitions(topology, { vhost })` → the body of `POST /api/definitions/{vhost}` plus `topology_version`. During the step 3.2 transition the package root still exports the ADR-0005 names (`EXCHANGES`, `QUEUES`, `QueueDefinition`, …) from `legacy-topology.ts`; topology v1's queue type is exported from the root as `TopologyQueueDefinition` until WP4 deletes the legacy file.
- **`infrastructure/rabbitmq/definitions.json`**: generated, committed. `pnpm --filter @email-gateway/event-contracts topology:export` rewrites it (build, export, Prettier); a unit test fails when the committed file differs from the generated one. Never edit it by hand.
- **`infrastructure/rabbitmq/init.mjs`**: the only provisioning code (plain Node 22, no dependencies, the management HTTP API as the administrator). It waits for the API (≤ 120 s); creates/updates the vhost (description `email-gateway topology v<N>`, `default_queue_type: quorum`) and gives the administrator full permissions on it; imports the definitions (without `topology_version`, every object's `vhost` set to the target); with `--users` creates/updates the four role users (no tags) and sets exactly their permissions; with `--cleanup-legacy` deletes the ADR-0005 objects on vhost `/` (below) only when empty; then **verifies**: exactly the 6 exchanges (topic, durable, not internal) and 14 queues (quorum, durable), each queue's effective policy is `eg.<queue>`, every binding present and no other binding, every policy equal to the file, the role users without tags and with exactly their permissions. Idempotent; exits non-zero on any failure; logs object names and counts only. `--vhost <name>` provisions another vhost (integration suites use `eg-it-<hex>`), `--mgmt-url <url>` another broker, `--definitions <path>` another file, `--delete-vhost <name>` tears a test vhost down (refuses `email-gateway` and `/`).
- **Compose** `rabbitmq-init` (default profile, `node:22-bookworm-slim`, mounts `infrastructure/rabbitmq` read-only, `--users --cleanup-legacy`, after `rabbitmq` is healthy); every app service waits for it (`service_completed_successfully`). **Host:** `pnpm rabbitmq:init` (`node --env-file=.env infrastructure/rabbitmq/init.mjs --users`, management URL from `RABBITMQ_MGMT_URL`).
- **Services never declare** (their users have `configure = ^$`). The client library (WP2) verifies passively (`checkExchange`/`checkQueue`) the exchanges a service publishes to and the queues it consumes; a missing object keeps readiness red, it does not crash the process.
- An import never deletes: a binding, queue or policy removed from `TOPOLOGY` must be deleted explicitly (the verification reports leftovers as unexpected objects). Topology changes are a new `TOPOLOGY_VERSION` with a migration note.

## Exchanges

Six exchanges, all `topic`, durable, not auto-delete, not internal, no arguments. The default exchange (`""`) and `amq.*` are never used.

| Exchange          | Carries (events published here, see the registry)                                                                              | Bound to `email.events` with `org.#` |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| `email.ingestion` | `mail.message.received.v1`, `mail.message.parsed.v1`, `mail.message.parse_failed.v1`                                           | yes                                  |
| `email.security`  | `mail.message.scanned.v1`, `mail.message.rescan_requested.v1` (v2); reserved `mail.attachment.sandbox_requested.v1`            | yes                                  |
| `email.policy`    | `mail.policy.decided.v1`                                                                                                       | yes                                  |
| `email.delivery`  | `mail.delivery.approved.v1`, `mail.delivery.status_changed.v1`                                                                 | yes                                  |
| `email.archive`   | nothing yet (archive-stage outputs, 8.1)                                                                                       | yes                                  |
| `email.events`    | `domain.status.changed.v1`, `domain.routing.changed.v1`, `mail.message.state_changed.v1` (v2); the firehose; every dead letter | –                                    |

`mail.attachment.sandbox_requested.v1` is **reserved**: routed (the `scan.sandbox` binding exists) but without a schema until step 4.6; the relay refuses to publish a reserved type.

## Queues

Fourteen quorum queues (durable, `x-queue-type: quorum` is the **only** queue argument; everything mutable is a policy). Role decides the policy (below).

| Queue                    | Role        | Home exchange     | Event bindings (exchange: key)                                                                                     | Consumer                                                                               | Retry policy                                             |
| ------------------------ | ----------- | ----------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `email.received`         | work        | `email.ingestion` | `email.ingestion`: `org.*.mail.message.received.v1`                                                                | email-worker MIME ingestion, ledger `email-worker.mime-parser` (step 3.2 WP4)          | hold, 8 attempts, 1 s–60 s, 24 h                         |
| `scan.auth`              | dormant     | `email.security`  | `email.ingestion`: `org.*.mail.message.parsed.v1`; `email.security`: `org.*.mail.message.rescan_requested.v1` (v2) | **step 4.1** (email-worker): SPF/DKIM/DMARC results via Rspamd                         | hold, 5, 1 s–60 s, 24 h                                  |
| `scan.spam`              | dormant     | `email.security`  | `email.ingestion`: `org.*.mail.message.parsed.v1`; `email.security`: `org.*.mail.message.rescan_requested.v1` (v2) | **step 4.1** (email-worker): Rspamd verdict                                            | hold, 5, 1 s–60 s, 24 h                                  |
| `scan.url`               | dormant     | `email.security`  | `email.ingestion`: `org.*.mail.message.parsed.v1`; `email.security`: `org.*.mail.message.rescan_requested.v1` (v2) | **step 4.3** (email-worker): URL protection                                            | hold, 5, 1 s–60 s, 24 h                                  |
| `scan.attachment`        | dormant     | `email.security`  | `email.ingestion`: `org.*.mail.message.parsed.v1`; `email.security`: `org.*.mail.message.rescan_requested.v1` (v2) | **step 4.2** (email-worker): ClamAV + YARA                                             | hold, 5, 1 s–60 s, 24 h                                  |
| `scan.dlp`               | dormant     | `email.security`  | `email.ingestion`: `org.*.mail.message.parsed.v1`; `email.security`: `org.*.mail.message.rescan_requested.v1` (v2) | **step 4.5** (email-worker): DLP                                                       | hold, 5, 1 s–60 s, 24 h                                  |
| `scan.sandbox`           | dormant     | `email.security`  | `email.security`: `org.*.mail.attachment.sandbox_requested.v1` (reserved)                                          | **step 4.6**: sandbox orchestration                                                    | hold, 5, 1 s–60 s, 24 h                                  |
| `email.policy.evaluate`  | dormant     | `email.policy`    | `email.security`: `org.*.mail.message.scanned.v1`; `email.ingestion`: `org.*.mail.message.parse_failed.v1`         | **steps 5.1/5.2** (policy-engine); parse failures go to the policy fail-safe (3.1 M13) | hold, 5, 1 s–60 s, 24 h                                  |
| `email.delivery.pending` | work        | `email.delivery`  | `email.delivery`: `org.*.mail.delivery.approved.v1`                                                                | delivery-worker planner, ledger `delivery-worker.planner` (step 3.2 WP4)               | delay-queue `email.delivery.retry`, 10, 5 s–15 min, 48 h |
| `email.delivery.retry`   | delay       | `email.delivery`  | none; internal binding `email.delivery`: `delay.email.delivery.pending.#`                                          | none by design: expired messages return to `email.delivery.pending`                    | –                                                        |
| `email.quarantine`       | dormant     | `email.policy`    | `email.policy`: `org.*.mail.policy.decided.v1`                                                                     | **step 5.3**: quarantine (acts on `action = quarantine`)                               | hold, 5, 1 s–60 s, 24 h                                  |
| `email.archive`          | dormant     | `email.archive`   | `email.policy`: `org.*.mail.policy.decided.v1`                                                                     | **step 8.1** (archive-worker; acts on `archive = true`)                                | hold, 5, 1 s–60 s, 24 h                                  |
| `email.analytics`        | dormant     | `email.events`    | `email.events`: `org.#` (the firehose: every event of every exchange)                                              | ClickHouse ingestion (ADR-0009), **not scheduled yet**                                 | hold, 5, 1 s–60 s, 24 h                                  |
| `email.dead-letter`      | dead-letter | `email.events`    | none; internal binding `email.events`: `dead-letter.#`                                                             | none: operators replay through the api (Q9, step 3.2 WP4)                              | –                                                        |

Plus, on every work and dormant queue, exactly one **retry binding** `retry.<queue>.#` on its home exchange. 37 bindings in total (v1: 32): 32 queue bindings and the five exchange-to-exchange bindings `email.{ingestion,security,policy,delivery,archive}` → `email.events` (`org.#`).

Where each event lands (`routeMessage`, asserted by `topology.test.ts`):

| Event type                         | Queues                                                                                      |
| ---------------------------------- | ------------------------------------------------------------------------------------------- |
| `mail.message.received.v1`         | `email.received`, `email.analytics`                                                         |
| `mail.message.parsed.v1`           | `scan.auth`, `scan.spam`, `scan.url`, `scan.attachment`, `scan.dlp`, `email.analytics`      |
| `mail.message.parse_failed.v1`     | `email.policy.evaluate`, `email.analytics`                                                  |
| `mail.message.scanned.v1`          | `email.policy.evaluate`, `email.analytics`                                                  |
| `mail.policy.decided.v1`           | `email.quarantine`, `email.archive`, `email.analytics`                                      |
| `mail.delivery.approved.v1`        | `email.delivery.pending`, `email.analytics`                                                 |
| `mail.delivery.status_changed.v1`  | `email.analytics` (webhooks/notifications 6.2 add a queue later)                            |
| `domain.status.changed.v1`         | `email.analytics` (the smtp-adapter cache invalidation stays an outbox tail, Q13)           |
| `domain.routing.changed.v1`        | `email.analytics` (same)                                                                    |
| `mail.message.state_changed.v1`    | `email.analytics` (v2; analytics and webhooks 6.2 consume it later)                         |
| `mail.message.rescan_requested.v1` | `scan.auth`, `scan.spam`, `scan.url`, `scan.attachment`, `scan.dlp`, `email.analytics` (v2) |

```mermaid
flowchart LR
  subgraph producers[Producers via message_outbox]
    SA[smtp-adapter]:::p
    EW[email-worker]:::p
    DW[delivery-worker / recorder]:::p
    API[api]:::p
  end
  R[event-relay\nconfirmed publish\nstep 3.2 WP3]
  SA & EW & DW & API --> OB[(message_outbox)] --> R
  R -->|org.id.mail.message.*| XI{{email.ingestion}}
  R -->|org.id.mail.message.scanned.v1, rescan_requested.v1| XS{{email.security}}
  R -->|org.id.mail.policy.decided.v1| XP{{email.policy}}
  R -->|org.id.mail.delivery.*| XD{{email.delivery}}
  R -->|org.id.domain.*, mail.message.state_changed.v1| XE{{email.events}}
  XA{{email.archive}}
  XI -->|org.*.received.v1| Q1[email.received\nwork: email-worker]
  XI -->|org.*.parsed.v1| QS[scan.auth / spam / url / attachment / dlp\ndormant: 4.1-4.5]
  XI -->|org.*.parse_failed.v1| QP[email.policy.evaluate\ndormant: 5.1/5.2]
  XS -->|org.*.scanned.v1| QP
  XS -->|org.*.rescan_requested.v1 v2| QS
  XS -->|org.*.sandbox_requested.v1| QSB[scan.sandbox\ndormant: 4.6]
  XP -->|org.*.policy.decided.v1| QQ[email.quarantine\ndormant: 5.3]
  XP -->|org.*.policy.decided.v1| QA[email.archive\ndormant: 8.1]
  XD -->|org.*.approved.v1| QD[email.delivery.pending\nwork: delivery-worker]
  XD -->|delay.email.delivery.pending.#| QR[email.delivery.retry\nTTL per message]
  QR -. expired: retry.email.delivery.pending.expired .-> XD
  XD -->|retry.email.delivery.pending.#| QD
  XI -->|retry.email.received.#| Q1
  XI & XS & XP & XD & XA -->|org.#| XE
  XE -->|org.#| QAN[email.analytics\ndormant: analytics]
  XE -->|dead-letter.#| DLQ[email.dead-letter\nreplay via api]
  Q1 -. dead-letter.email.received .-> XE
  QD -. dead-letter.email.delivery.pending .-> XE
  classDef p fill:#eef,stroke:#88a
```

## Routing keys

| Key                                                                         | Published to              | By                                                    | Matches                                                  |
| --------------------------------------------------------------------------- | ------------------------- | ----------------------------------------------------- | -------------------------------------------------------- |
| `org.<organizationId>.<eventType>` (e.g. `org.42.mail.message.received.v1`) | the registry exchange     | the relay                                             | event bindings `org.*.<eventType>`, the firehose `org.#` |
| `retry.<queue>.org.<id>.<eventType>`                                        | the queue's home exchange | the consumer (hold retry), the replay API             | exactly that queue's `retry.<queue>.#`                   |
| `delay.email.delivery.pending.org.<id>.<eventType>`                         | `email.delivery`          | the delivery consumer (delay-queue retry)             | exactly `email.delivery.retry`                           |
| `retry.email.delivery.pending.expired`                                      | `email.delivery`          | the broker (delay-queue expiry, fixed key)            | exactly `email.delivery.pending`                         |
| `dead-letter.<queue>.org.<id>.<eventType>`                                  | `email.events`            | the consumer (application dead letter)                | exactly `email.dead-letter`                              |
| `dead-letter.<queue>`                                                       | `email.events`            | the broker (work-queue policy, e.g. `delivery-limit`) | exactly `email.dead-letter`                              |

- The organization id is the decimal `organizations.id` from the outbox row (trusted context). The routing key, the `x-eg-organization-id` header and the envelope `organizationId` must agree (consumers dead-letter a mismatch as `tenant_mismatch`, WP2).
- Internal hops never start with `org.`, so the firehose never sees them; no queue name is a dot-prefix of another (`scan.auth` vs `scan.auth.x` is refused by `validateTopology`), so `retry.<queue>.#` matches one queue only. `parseRoutingKey` resolves dotted queue names by the longest whole-word match.
- A per-tenant queue later is a binding `org.<id>.#` (no key change).

## Message properties and headers

Defined by Q2; the constants (`HEADERS`) and the codec are built by **step 3.2 WP2** (`packages/common/src/messaging/headers.ts`, `codec.ts`).

- Properties on every publish: `persistent` (delivery mode 2), `contentType application/json`, `contentEncoding utf-8`, `messageId = eventId`, `correlationId`, `type = eventType`, `timestamp = occurredAt` (seconds), `appId = <publishing service>`, `mandatory: true`. `expiration` only on delay hops.
- Base headers: `x-eg-envelope-version: 1`, `x-eg-event-type`, `x-eg-schema-version` (`N` of `.vN`, `schemaVersionOf`), `x-eg-organization-id` (decimal string), `x-eg-correlation-id`.
- Retry state: `x-eg-attempt` (counted failures), `x-eg-transient-retries`, `x-eg-first-failed-at`, `x-eg-last-error-class`. Dead letters: `x-eg-source-queue`, `x-eg-failure-reason` (a code), `x-eg-failure-class` (`fatal` | `retryable` | `transient`), `x-eg-attempts`, `x-eg-dead-lettered-at`, `x-eg-dead-lettered-by`. Replay: `x-eg-replay-id`, `x-eg-replay-count`, `x-eg-replayed-at`. Broker dead letters carry `x-death` / `x-first-death-*` instead.
- Body: the JSON envelope (`eventEnvelopeSchema`, unchanged), ids, S3 keys, hashes, codes and counts only. A content guard refuses anything else (Q7, WP2); the broker caps `max_message_size` at 1 MiB (`rabbitmq.conf`).

## Policies

One policy per queue, `eg.<queue>`, pattern `^<escaped queue name>$`, `apply-to: queues`, priority 10, imported with the definitions. Services cannot change policies (no `policymaker`/`administrator` tag).

| Role        | Queues                                                                                    | Definition                                                                                                                                                                                                              |
| ----------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| work        | `email.received`, `email.delivery.pending`                                                | `delivery-limit: 20`, `dead-letter-exchange: email.events`, `dead-letter-routing-key: dead-letter.<queue>`, `dead-letter-strategy: at-least-once`, `overflow: reject-publish`, `max-length: 1000000`                    |
| dormant     | `scan.*`, `email.policy.evaluate`, `email.quarantine`, `email.archive`, `email.analytics` | `delivery-limit: -1`, `max-length: 10000`, `overflow: drop-head` (no dead-lettering)                                                                                                                                    |
| delay       | `email.delivery.retry`                                                                    | `delivery-limit: -1`, `dead-letter-exchange: email.delivery`, `dead-letter-routing-key: retry.email.delivery.pending.expired`, `dead-letter-strategy: at-least-once`, `overflow: reject-publish`, `max-length: 1000000` |
| dead-letter | `email.dead-letter`                                                                       | `delivery-limit: -1`, `overflow: reject-publish`, `max-length: 1000000`                                                                                                                                                 |

- `delivery-limit` is a crash-loop backstop only: application retries republish copies (a copy is a new message with its own count). Returns of the original do count: every `nack(requeue)` and every channel/connection loss with the delivery unacked (measured below).
- `delivery-limit: -1` (unlimited) on every queue no stage consumes. RabbitMQ 4.x gives a quorum queue without a policy limit a default of 20 and drops a message over it when the queue has no dead-letter target; replay scans and operator inspection return messages with `nack(requeue)`, which counts. Measured on 4.1.8: without `-1` a message was gone at the 22nd return; with `-1` it was still there after 30 (step 3.2 review round 1).
- `reject-publish` on a work queue nacks the relay's publish; the outbox row stays unpublished with backoff (backpressure into MySQL, nothing lost). A nack is infrastructure: it never counts as an attempt, so a queue that stays full never turns rows into poison. Work queues never drop.

### The dormant-queue rule

Queues of stages that do not exist yet are declared and bound now (the brief's fixed list), with **no consumer** (no mock consumers). Without a bound they would grow by up to a million messages a day each, and with `reject-publish` they would block every publish of `mail.message.parsed.v1` to the working queues. So they are **bounded lossy buffers** (`max-length 10000`, `drop-head`) and **never the source of truth**. When its stage is built, that stage's step:

1. switches the queue to the work policy (a policy change in `TOPOLOGY`, no re-declare),
2. adds a role user (or extends one) with read on the queue in `init.mjs`, a ledger consumer name and a `RECONCILE_QUEUES` entry,
3. onboards older messages from MySQL (the outbox and the stage's tables), not from the queue.

The `DormantQueueAtLimit` alert (WP3) shows when a dormant queue is full and dropping.

## Dead-letter paths and retry hops

Behaviour of the consumer library (Q8, **step 3.2 WP2**):

- **Hold** (`email.received`, dormant queues): on a retryable or transient failure the consumer keeps the delivery (its prefetch slot) for the backoff delay (≤ 60 s), republishes a copy with `retry.<queue>.org.<id>.<type>` to the home exchange, waits for the confirm and acks the original.
- **Delay queue** (`email.delivery.pending`): the consumer republishes a copy to `email.delivery` with `delay.email.delivery.pending.org.<id>.<type>` and a per-message `expiration`, confirms, acks. `email.delivery.retry` has no consumer; on expiry the broker dead-letters the copy with `retry.email.delivery.pending.expired` back to `email.delivery.pending`. Quorum queues expire at the head only, so a short delay behind a longer one waits for it (lateness ≤ `maxDelayMs`).
- **Dead letter**: after `maxAttempts` counted failures, `maxRetryAgeMs` of transient retries, a fatal error or a contract failure, the consumer republishes a copy with `dead-letter.<queue>.org.<id>.<type>` and the failure headers to `email.events`. Crash loops hit `delivery-limit` and the broker dead-letters with `dead-letter.<queue>`. Both land in `email.dead-letter`.
- Backoff: `d = min(maxDelayMs, baseDelayMs · 2^(n−1))`, delay ∈ `[d/2, d]` (equal jitter). A copy keeps `messageId = eventId` and `correlationId`, so ledgers absorb duplicates.
- **Replay** (`POST /api/v1/platform/dead-letters/replay`, `platform:dead_letter_replay` + MFA, audited; **step 3.2 WP4**) republishes dead letters of a work queue with `retry.<sourceQueue>.org.<id>.<type>` and fresh retry headers.

The delay → expiry → work-queue path and the internal keys were checked against the local broker during WP1 (a throwaway vhost: an event reached `email.received` and `email.analytics`, a retry key only `email.received`, a broker-style `dead-letter.email.received` only `email.dead-letter`, and a 1.5 s delay hop returned to `email.delivery.pending`).

## Client library (`@email-gateway/common` messaging, step 3.2 WP2)

Framework-free classes plus one Nest module, exported from `@email-gateway/common` (design Q6):

| Module             | Exports                                                                                                                                                               |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connection.ts`    | `AmqpConnection` (also the `rabbitmq` `HealthIndicator`), `BrokerUnavailableError`                                                                                    |
| `publisher.ts`     | `ConfirmPublisher` (`publishBatch`, `publish`, `republish`, `close`), `PublishFailedError`, `DEFAULT_MAX_MESSAGE_BYTES` (131 072), `HARD_MAX_MESSAGE_BYTES` (262 144) |
| `consumer.ts`      | `QueueConsumer<T>` (implements `EventFeed<T>`), `resolveRetryPolicy`                                                                                                  |
| `codec.ts`         | `encodeEvent`, `decodeDelivery`, `baseHeaders`, `retryState`                                                                                                          |
| `headers.ts`       | `HEADERS` (Q2 names), `ENVELOPE_VERSION`, `BROKER_HEADERS`                                                                                                            |
| `content-guard.ts` | `assertMetadataOnly`, `ContentGuardError` (`code`, JSON `path`), the Q7 codes                                                                                         |
| `backoff.ts`       | `backoffDelay` (equal jitter, overflow-safe), abortable `sleep`                                                                                                       |
| `errors.ts`        | `NonRetryableError`, `FailureClass`, `isTransientInfrastructureError`, `defaultClassify`, token-only `errorFields`, `amqpReplyName`                                   |
| `metrics.ts`       | `MessagingMetrics`, `createMessagingMetrics(MetricsService)` (the twelve `amqp_*` series of §5.3)                                                                     |
| `amqp.module.ts`   | `AmqpModule.forRoot({ urls, connectionName, appId, confirmTimeoutMs?, maxMessageBytes?, verify?, logger? })`                                                          |

Recovery and retry behaviour (contract, verified by the unit and integration suites):

- **Connection.** Connects in the background (module init never awaits the broker). On an unexpected `error`/`close` the connection is marked down at once, amqplib closes every channel (pending confirms reject), and the client reconnects with equal-jitter backoff (default 500 ms – 30 s; a connection that lived < 5 s counts as a failed attempt) rotating through the URLs, then re-runs every `onConnected` setup in registration order. It **never exits the process**. `checkHealth` = connected, not `blocked`, every object of `requireTopology` verified passively once per connection (a missing exchange/queue keeps readiness red and is re-checked on the next probe).
- **Publisher.** One confirm channel, created lazily and re-created after a broker close with a short backoff (100 ms – 5 s). Every path runs the content guard on the envelope (or the raw bytes for `republish`) and its headers, plus the size check, before sending (`refused` + code, nothing sent). Per item: broker ack → `confirmed`; a `basic.return` before the ack → `returned` (`code: NO_ROUTE`); broker nack → `nacked`; no confirm within `confirmTimeoutMs` → `timeout`, and the channel is closed and re-created (every unresolved item of that channel becomes `timeout`). Channel or connection death with confirms pending rejects the call with `BrokerUnavailableError` (`code` = the AMQP reply name, e.g. `ACCESS_REFUSED`). While the connection is `blocked`, a batch waits for `unblocked` up to `confirmTimeoutMs`, then returns `timeout` for all items.
- **Consumer.** One channel per consumer, `prefetch` = max deliveries in flight, `noAck: false`. A channel closed by the broker (or a broker `basic.cancel`) re-subscribes after backoff (1 s – 30 s) on the same connection; a lost connection re-subscribes through `onConnected`. A handler result for a dead channel is dropped (debug log); the broker redelivers. Decision table: `handled`/`duplicate` → ack; decode failure → dead-letter at once (`contract_invalid`, `unknown_event_type`, `unsupported_schema_version`, `tenant_mismatch`); `NonRetryableError` → dead-letter with its code (`handler_rejected` if not a `[a-z0-9_]{1,48}` token); transient → `x-eg-transient-retries + 1` (no attempt), dead-letter `retry_age_exceeded` past `maxRetryAgeMs`; anything else → `x-eg-attempt + 1`, dead-letter `max_attempts_exceeded` when it reaches `maxAttempts`. `x-eg-attempts` on a dead letter = counted failures including a fatal one. Copies drop the broker headers (`x-death`, `x-first-death-*`, `x-last-death-*`, `x-delivery-count`) and the previous failure headers.
- **Never acked without a confirmed copy.** Hold: wait the delay holding the slot, republish, confirm, ack; an unconfirmed copy → `nack(requeue)`. Delay queue: republish with `expiration`, confirm, ack; unconfirmed → hold up to `min(delay, 60 s)` then `nack(requeue)`. Dead letter: unconfirmed → hold one base backoff then `nack(requeue)`. If the content guard refuses the dead-letter copy (the delivery itself carries content), the original is rejected (`nack`, no requeue) to the queue policy's broker dead-letter target (`dead-letter.<queue>` for work queues; dormant queues have none and drop it) — the library never copies content.
- **stop()**: cancel the subscription, release held deliveries (`nack(requeue)`), wait for running handlers up to `stopTimeoutMs` (default 30 s), close the channel (the broker requeues anything left).
- **Logs** carry tokens only: per delivery a logger child `{ queue, eventId, eventType, organizationId, correlationId }`, plus `errName`, `errCode`, `failureClass`, `attempt`, `reason`, AMQP reply names and node indexes. Never `err.message`, error objects, payload values, broker reply text or URLs (they carry credentials).

## Client behaviour (measured)

Measured on the local broker (RabbitMQ **4.1.8**, single node, quorum queues, the work policy `eg.email.received`) by `tests/integration/messaging-client.test.ts` (throwaway vhost `eg-it-<hex>`; the assertions encode the findings, so a broker upgrade that changes them fails the suite):

| Behaviour                                                          | Finding                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `x-delivery-count` after `basic.nack(requeue=true)`                | Incremented by 1 per return (first delivery: header absent; then 1, 2, …).                                                                                                                                                                                                                                           |
| `x-delivery-count` after a channel close with the delivery unacked | Also incremented by 1 per return (same sequence). A consumer crash, a lost connection and an explicit requeue all count the same.                                                                                                                                                                                    |
| Work-policy `delivery-limit: 20`                                   | After the first delivery + 20 returns (21 deliveries) the broker dead-letters the message to `email.events` with routing key **`dead-letter.email.received`** (`x-first-death-reason: delivery_limit`, `x-first-death-queue: email.received`, `x-death[0].reason: delivery_limit`); it lands in `email.dead-letter`. |
| `x-acquired-count`                                                 | Not present on deliveries of 4.1.8 quorum queues.                                                                                                                                                                                                                                                                    |
| Queue-level `messages_unacknowledged` (management API)             | With one prefetch-4 consumer and 200 queued messages, the per-channel counter never exceeded 4; the queue's own counter was seen at 5 (acks in flight, as far as observed). Backpressure checks use the channel counter (or the client's in-flight count).                                                           |
| Delay hop through `email.delivery.retry`                           | A copy with `expiration` 1 500 ms sat in `email.delivery.retry` (no consumer) and expired back into `email.delivery.pending` through the delay policy (`retry.email.delivery.pending.expired`); handled ≥ 1.4 s after the first attempt.                                                                             |
| TCP partition (proxy cut 1.5 s with 200 events flowing)            | The in-flight batch rejected with `BrokerUnavailableError`; the client reconnected (`amqp_reconnects_total` +1), the consumer re-subscribed, the test republished unconfirmed items, every event reached the ledger exactly once (`processOnce`; redeliveries were `duplicate`).                                     |

Consequences for the library and its users:

- Every `nack(requeue)` the library issues (unconfirmed retry/dead-letter copy, `stop()` during a hold) and every crash or connection loss spends one of the 20 returns of `delivery-limit`. A message whose copies cannot be confirmed 20 times in a row (e.g. `email.dead-letter` full under `reject-publish`) is dead-lettered by the broker with `delivery_limit` instead of looping forever. Application retries (hold / delay copies) are new messages and reset the count, so retries bounded by `maxAttempts` / `maxRetryAgeMs` never hit the limit.
- Broker dead letters carry no `x-eg-failure-*` headers; replay (Q9) reads `x-first-death-queue` / `x-death` for them.

## Vhost, users and permissions (Q10)

Vhost **`email-gateway`** (`RABBITMQ_VHOST`). Role users have **no tags** (no management UI/API access); passwords and URLs come only from `.env` / secrets.

| User (`.env` key)                                      | Used by                                          | configure | write                                                               | read                         |
| ------------------------------------------------------ | ------------------------------------------------ | --------- | ------------------------------------------------------------------- | ---------------------------- |
| `RABBITMQ_USER` (administrator, broker default user)   | `init.mjs`, tests, operators                     | `.*`      | `.*`                                                                | `.*`                         |
| `RABBITMQ_RELAY_USER` = `eg-relay`                     | event-relay (`RABBITMQ_RELAY_URL`)               | `^$`      | `^email\.(ingestion\|security\|policy\|delivery\|archive\|events)$` | `^$`                         |
| `RABBITMQ_EMAIL_WORKER_USER` = `eg-email-worker`       | email-worker (`RABBITMQ_EMAIL_WORKER_URL`)       | `^$`      | `^email\.(ingestion\|events)$`                                      | `^email\.received$`          |
| `RABBITMQ_DELIVERY_WORKER_USER` = `eg-delivery-worker` | delivery-worker (`RABBITMQ_DELIVERY_WORKER_URL`) | `^$`      | `^email\.(delivery\|events)$`                                       | `^email\.delivery\.pending$` |
| `RABBITMQ_OPS_USER` = `eg-ops`                         | api replay and stats (`RABBITMQ_OPS_URL`)        | `^$`      | `^email\.(ingestion\|delivery)$`                                    | `^email\.dead-letter$`       |

- Each service reads only its own URL key (a comma-separated list of `amqp(s)://` URLs for cluster nodes, `amqpUrlListSchema` in `@email-gateway/config`; `*_FILE` in Kubernetes). `RABBITMQ_URL` is the administrator URL on `/` for tests and tools only; Compose no longer passes it to services. `RABBITMQ_PREFETCH` is no longer read.
- policy-engine, archive-worker and notification-worker get no broker user in step 3.2 (they consume nothing); their steps add one.
- The email-worker cannot publish approvals (no write on `email.delivery`); consumers still check every event against the writer row.
- **Topic permissions** (routing keys each user may publish, per exchange; `init.mjs --users` sets and verifies them exactly; read `^$`, no user binds):

| User                 | Exchange          | write (routing keys)                            |
| -------------------- | ----------------- | ----------------------------------------------- |
| `eg-relay`           | each of the six   | `^org\.[1-9][0-9]{0,19}\.` (event keys only)    |
| `eg-email-worker`    | `email.ingestion` | `^retry\.email\.received\.`                     |
| `eg-email-worker`    | `email.events`    | `^dead-letter\.email\.received(\.\|$)`          |
| `eg-delivery-worker` | `email.delivery`  | `^(retry\|delay)\.email\.delivery\.pending\.`   |
| `eg-delivery-worker` | `email.events`    | `^dead-letter\.email\.delivery\.pending(\.\|$)` |
| `eg-ops`             | `email.ingestion` | `^retry\.email\.received\.`                     |
| `eg-ops`             | `email.delivery`  | `^retry\.email\.delivery\.pending\.`            |

- Only the relay can publish an event key (`org.<id>.<type>`). A retry key still reaches its work queue, so the broker alone cannot stop a leaked `eg-delivery-worker` or `eg-ops` credential from sending an approval-shaped retry message: the delivery planner plans only approvals with a matching `message_outbox` row (same event id, type, organization and payload) and dead-letters others as `approval_not_issued` / `approval_mismatch` (ADR-0024 amendment).

## Legacy objects (ADR-0005)

The superseded topology on vhost `/` (`mail.events`, `mail.dlx`, the queues `email-worker.message-received`, `policy-engine.message-scanned`, `delivery-worker.policy-decided`, `archive-worker.policy-decided`, `notification-worker.events` and their `.dlq`) is still asserted by the pre-3.2 `RabbitMqModule` of the running images. `init.mjs --cleanup-legacy` (the Compose `rabbitmq-init` default) deletes each queue only when it holds 0 messages (`DELETE ?if-empty=true`) and each exchange only when unbound (`?if-unused=true`), and warns otherwise. Step 3.2 WP4 removes `RabbitMqModule`; WP5 runs the cleanup after the images are rebuilt.

## Test-only 3-node cluster

Compose profile `rabbitmq-cluster`: `rabbitmq-node1..3` (hostnames `rmq1..3`, `classic_config` peer discovery, shared Erlang cookie `RABBITMQ_CLUSTER_ERLANG_COOKIE` written by `infrastructure/rabbitmq/cluster/entrypoint.sh`, `mem_limit 448m` each, watermark 256 MiB), AMQP on `127.0.0.1:5701–5703`, management on `127.0.0.1:15701` (node 1), volumes `rabbitmq-cluster-{1,2,3}-data`. Used by the broker node-failure test (WP5). Procedure: [local stack runbook](../runbooks/local-stack.md#rabbitmq).
