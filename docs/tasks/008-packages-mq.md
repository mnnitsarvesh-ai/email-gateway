# 008: packages/mq — quorum-queue topology, confirmed publish, manual-ack consume, DLQ

Owner agent: backend-engineer
Depends on: 002, 003, 006
Status: draft
Branch: feat/008-packages-mq
Phase: 0

## User story

Story: _to be written by product-owner_

As a pipeline service author, I want one RabbitMQ client that only publishes with confirms, only consumes with manual acks and bounded prefetch, validates every payload with zod, and routes poison messages to a DLQ so that no service can lose or silently drop a message.

## Acceptance criteria

AC-1 Given a local RabbitMQ, when `declareTopology` runs for the scan topology, then each queue reports `x-queue-type = quorum`, `x-dead-letter-exchange = esg.dlx`, dead-letter routing key `<queue>.dlq`, `x-delivery-limit` equal to config (default 5), `x-dead-letter-strategy = at-least-once` and `x-overflow = reject-publish`; each `<queue>.dlq` is also quorum.
AC-2 Given `declareTopology`, when run twice, then the second run succeeds with no change (queue definitions identical, no `PRECONDITION_FAILED`).
AC-3 Given `publish` with a valid payload, when the broker confirms, then the promise resolves and the message is in the queue with `persistent` delivery mode, `content-type application/json`, `message_id` = `event_id` and header `schema_version`.
AC-4 Given the broker stopped (or blocking confirms), when `publish` is called, then it rejects within the configured confirm timeout and the caller observes the error (so an outbox row would stay unpublished).
AC-5 Given a broker `nack` on a publish (for example queue at `reject-publish` overflow), when `publish` runs, then it rejects; it never resolves without an ack.
AC-6 Given an unroutable routing key, when `publish` runs with `mandatory`, then it rejects with a returned-message error.
AC-7 Given a payload whose serialized size exceeds 16 KiB, when `publish` runs, then it throws `PayloadTooLargeError` before any network write and the broker's message count is unchanged.
AC-8 Given a payload with an extra key such as `eml` or `body`, or one failing the zod schema, when `publish` runs, then it throws a validation error and nothing is sent.
AC-9 Given `consume`, when called without `prefetch` or with 0 or 257, then it fails (type error and runtime error); no option exists to auto-ack (`noAck` is always false).
AC-10 Given prefetch N, when 50 messages are queued and the handler blocks, then at most N messages are unacked at the broker (`messages_unacknowledged` <= N).
AC-11 Given a handler returning `'ack'`, when it completes, then the message is acked and the queue depth reaches 0.
AC-12 Given a message that is not valid JSON or fails the zod schema, when consumed, then it is dead-lettered immediately (`nack requeue=false`) to `<q>.dlq` without the handler running, and the log has `organization_id` and `message_uuid` when extractable.
AC-13 Given a handler that always throws or returns `'retry'`, when consumed, then the message is redelivered and lands in `<q>.dlq` after `x-delivery-limit` deliveries, with `deliveryCount` increasing in `meta`.
AC-14 Given a consumer process killed after the handler's durable write but before ack, when it restarts, then the message is redelivered with `meta.redelivered = true`.
AC-15 Given `close()` with a handler in flight, when called, then new deliveries stop, the in-flight handler finishes and is acked, and unacked messages are returned to the queue; a handler exceeding the deadline is abandoned and its message redelivered.
AC-16 Given the connection dropped and the broker restarted, when the broker returns, then the client reconnects with capped backoff and consumers resume; a publish in flight during the drop rejects.
AC-17 Given handler logs, when a message is consumed, then each log line carries `organization_id`, `message_uuid` and `stage` from the payload (via `forMessage`).

## Out of scope

- `outbox-publisher`, the service that polls the outbox and calls `publish` (Phase 1).
- Recording idempotency keys. Handlers do that in their own writer transaction; this package only provides the redelivery count and envelope to the handler.
- Delayed-retry or backoff queues (Phase 5, for webhooks). No mail-delivery retry logic at all (ADR-022).
- RabbitMQ Streams, Kafka-style patterns and non-core plugins (ADR-007, ADR-024 compatibility).

## Design notes

### Library

`amqplib` with `ConfirmChannel`. There is one connection per process, with heartbeat and reconnect that uses jittered backoff and has a cap. Consumers resume after a reconnect. A publish that is in flight during a disconnect **rejects**; it isn't retried silently, so the outbox row stays unpublished.

### API (`@esg/mq`)

```ts
export function connectMq(cfg: MqConfig, log: Logger): Promise<Mq>;

interface Mq {
  declareTopology(t: Topology): Promise<void>;   // idempotent; asserts exchanges/queues/bindings
  publish<S extends z.ZodTypeAny>(p: {
    exchange: string; routingKey: string; schema: S; payload: z.infer<S>; messageId: string;  // messageId = event_id
  }): Promise<void>;                              // resolves only on broker ack (confirm); rejects on nack/return/timeout
  consume<S extends z.ZodTypeAny>(c: {
    queue: string; schema: S; prefetch: number;   // prefetch required, 1..256
    handler: (msg: z.infer<S>, meta: { redelivered: boolean; deliveryCount: number; messageId: string }) => Promise<'ack' | 'retry'>;
  }): Promise<ConsumerHandle>;
  close(): Promise<void>;                         // stop consuming, wait for in-flight handlers, then close
}
```

### Topology rules (`declareTopology`)

Names come from `@esg/schemas/topology` (002).
- Every queue is `x-queue-type: quorum`, with a DLX of `esg.dlx` and a dead-letter routing key of `<queue>.dlq`.
- `x-delivery-limit` is set from config (default 5), so poison messages that keep failing end up in the DLQ.
- `x-dead-letter-strategy: at-least-once` together with `x-overflow: reject-publish`, so dead-lettering doesn't lose messages. Confirm this works on the chosen broker (ADR-024).
- Every DLQ is itself a quorum queue.
- Exchanges are durable. Publishing uses `mandatory: true`, so an unroutable message is returned and the `publish` promise rejects.

### Publish

- The payload is parsed with `schema` before sending. An invalid payload throws, and nothing is sent.
- **Size guard (hard rule 3).** If the serialized payload is over 16 KiB, publish throws `PayloadTooLargeError` before sending. Payloads only carry ids and S3 keys, so 16 KiB is generous.
- `persistent: true`, `contentType: application/json`, `messageId` set, and `headers.schema_version` set.
- Await the confirm, with a confirm timeout from config. A timeout is a rejection.

### Consume

- `noAck: false` always, with `prefetch` required.
- If the payload fails JSON parsing or the zod schema, the client logs `organization_id` and `message_uuid` when they can be extracted, and dead-letters immediately with `nack(requeue=false)`. Retrying a malformed message can't succeed.
- Handler returns `'ack'`: the client acks. Handlers must only return this after their side effect is durable.
- Handler returns `'retry'` or throws: the client does `nack(requeue=true)`, and the quorum delivery-limit eventually dead-letters the message.
- Handler logs are bound through `forMessage` (006) with the payload's `organization_id`, `message_uuid` and `stage`.
- Graceful shutdown stops new deliveries (`cancel`), waits for in-flight handlers up to a deadline, then closes. Unacked messages go back to the queue. That is safe because consumers are idempotent.

### Tests

These run against local RabbitMQ.
- `publish` resolves only after the confirm. With the broker stopped, `publish` rejects within the timeout.
- An unroutable routing key rejects.
- An oversized payload throws before sending, and the broker receives nothing.
- A schema-invalid payload on consume goes straight to `<q>.dlq`. A handler that always throws dead-letters after `x-delivery-limit` deliveries.
- A handler that returns `'ack'` after a simulated durable write: killing the consumer process before the ack leads to redelivery with `redelivered = true`.
- Prefetch is respected: no more than N unacked messages are in flight.
- `declareTopology` run twice is a no-op, and the declared queues report `x-queue-type = quorum`.

## Hard rules at risk

- **3 (no EML in queues).** `.strict()` schemas (002) plus the 16 KiB guard.
- **6 (idempotent consumers, ack after durable).** Manual acks only, `'ack'` only from the handler, and redelivery metadata exposed. The handler records the idempotency key; that pattern is reviewed in Phase 1.
- **Messaging conventions.** Quorum queues, confirms, DLQ and bounded prefetch are enforced by the API shape. There is no way to auto-ack or publish without a confirm.

## NEEDS SARVESH

None. ADR-024 compatibility is handled by using core features only.
