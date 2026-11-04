# ADR-0005: RabbitMQ quorum queues, transactional outbox, idempotent consumers

**Status:** Superseded by [ADR-0024](0024-rabbitmq-topology-retry-dead-letter.md) (step 3.2): the topology below (`mail.events`, `mail.dlx`, `<queue>.dlq`) is replaced; the transactional outbox, the `processOnce` ledger and the envelope are carried forward there unchanged. Earlier amended by [ADR-0014](0014-mysql-data-model-partitioning-read-write-split.md): the tables are now `message_outbox` and `message_idempotency`, and the envelope carries `organizationId`

**Context.** Pipeline stages must survive crashes and redeliveries without losing mail or applying an action twice. At-least-once delivery is the realistic guarantee.

**Decision.**

- **RabbitMQ 4.x**: one topic exchange `mail.events`, plus `mail.dlx` for dead letters. Work queues are **quorum queues** with `x-delivery-limit`, dead-lettering to `<queue>.dlq` (`at-least-once` strategy), with `reject-publish` on overflow. Topology lives as data in `packages/event-contracts` and is asserted idempotently by each service at startup.
- **Publisher confirms and manual acks only.** A consumer acks after its effects commit.
- **Transactional outbox** (`outbox_events`): state changes and their events commit in one MySQL transaction, and a relay publishes and marks them.
- **Idempotent consumers**: `processOnce(prisma, consumer, eventId, handler)` inserts `(consumer, event_id)` into `processed_events` in the same transaction as the handler's effects. A duplicate hits the primary key and is skipped. A failing handler rolls back the ledger row, so a retry can succeed.
- **Envelope**: `eventId`, versioned `eventType` (`mail.message.received.v1`), `occurredAt`, `correlationId`, `tenantId`, `payload`. Payloads carry ids and S3 keys, never bodies.

**Alternatives.** Kafka: excellent for analytics streams, but at our volume per-message work queues with DLQs and per-message acks are simpler in RabbitMQ. Redis Streams: weaker durability guarantees.

**Consequences.** Every consumer must be written against `processOnce`. Breaking contract changes require a new event version, with both versions consumed during migration.
