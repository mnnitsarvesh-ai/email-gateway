# 21. Event relay, consumers, retry, dead letter and replay

Step 3.2 ([design and verification record](../../plan/steps/07-rabbitmq.md), [ADR-0023](../adr/0023-outbox-relay-and-reconciliation.md), [ADR-0024](../adr/0024-rabbitmq-topology-retry-dead-letter.md), [topology](../messaging-topology.md), [runbook](../../runbooks/rabbitmq-messaging.md)). Every pipeline event goes from the producer's writer transaction (`message_outbox`) through the `event-relay` to a topic exchange of vhost `email-gateway`, into a quorum queue and to a consumer that applies it exactly once with `processOnce`. The example is the delivery path (`mail.delivery.approved.v1` → `email.delivery.pending` → delivery-worker planner), whose retries use the delay queue; `email.received` (email-worker) is the same except that retries are held and republished (hold strategy).

```mermaid
sequenceDiagram
  autonumber
  participant P as Producer<br/>(smtp-adapter, email-worker,<br/>delivery-worker, api)
  participant DB as MySQL writer<br/>message_outbox
  participant R as event-relay<br/>OutboxRelay (shard i/n)
  participant X as email.delivery<br/>(topic exchange)
  participant Q as email.delivery.pending<br/>(quorum, work)
  participant C as delivery-worker<br/>QueueConsumer + processOnce
  participant D as email.delivery.retry<br/>(delay queue)
  participant E as email.events →<br/>email.dead-letter
  participant A as api<br/>dead-letter replay
  participant REC as event-relay<br/>OutboxReconciler

  P->>DB: state change + outbox row (same transaction, payload validated)
  loop every RELAY_POLL_INTERVAL_MS while holding GET_LOCK('er:relay#i/n')
    R->>DB: SELECT unpublished, non-poison rows of the shard ORDER BY id LIMIT RELAY_SCAN_LIMIT
    R->>R: envelope per row#59; registry schema + content guard (else poison: attempts = max, last_error = code)
    R->>X: publish batch: persistent, mandatory, messageId = eventId, key org.<id>.mail.delivery.approved.v1
    alt confirmed
      X-->>R: ack
      R->>DB: SET published_at = NOW(3) WHERE published_at IS NULL (confirmed rows only)
    else nacked (reject-publish: queue full) or returned (unroutable)
      R->>DB: attempts + 1, available_at = backoff, last_error = nacked | unroutable
    else timeout, connection lost, broker blocked
      R->>R: write nothing (rows stay unpublished), broker backoff, republish later
    end
  end
  X->>Q: route by binding org.*.mail.delivery.approved.v1 (and org.# to email.events → email.analytics)
  Q->>C: deliver (manual ack, prefetch DELIVERY_APPROVAL_PREFETCH)
  C->>C: decode: accepted type, x-eg-schema-version, envelope schema, tenant (routing key = header = envelope)
  alt decode fails (contract_invalid, unknown_event_type, unsupported_schema_version, tenant_mismatch)
    C->>E: copy with failure headers (fatal), confirmed
    C->>Q: ack original
  else handler: processOnce(delivery-worker.planner, eventId) + planner in one transaction
    C->>DB: ledger row + effects COMMIT (or the ledger row exists: duplicate, no effect)
    C->>Q: ack
  else transient failure (database, S3, network)
    C->>D: copy, x-eg-transient-retries + 1 (attempt unchanged), expiration = backoff, confirmed
    C->>Q: ack original
    D-->>X: expired: broker dead-letters with retry.email.delivery.pending.expired
    X->>Q: back to email.delivery.pending
  else retryable failure, x-eg-attempt + 1 below maxAttempts (10)
    C->>D: copy with exponential backoff (equal jitter, 5 s … 15 min), confirmed#59; ack original
  else maxAttempts reached, retry age (48 h) exceeded, or NonRetryableError
    C->>E: copy to dead-letter.email.delivery.pending.org.<id>.<type> with x-eg-source-queue, failure reason, class, attempts, confirmed
    C->>Q: ack original (never acked without a confirmed copy)
  end
  Note over Q,C: Connection or channel lost: unacked deliveries return to the queue and are redelivered#59;<br/>a handler that had committed records a ledger duplicate. delivery-limit 20 is the crash-loop backstop.
  A->>E: POST /api/v1/platform/dead-letters/replay (MFA platform admin, Redis lock): basic.get matching letters
  A->>X: unchanged body to retry.email.delivery.pending.org.<id>.<type>, attempts reset, x-eg-replay-id, confirmed
  A->>E: ack replayed letters#59; nack(requeue) everything else
  A->>DB: one audit_logs row (platform.dead_letters_replayed)
  X->>Q: replayed copy → C applies it once (or records a ledger duplicate)
  loop every RECONCILE_INTERVAL_MS while holding GET_LOCK('er:reconciler')
    REC->>DB: published rows older than RECONCILE_UNCONSUMED_AFTER_SECONDS without a ledger row of the queue's consumer
    REC->>DB: re-drive: published_at = NULL, redrive_count + 1 (≤ RECONCILE_MAX_REDRIVES), same event_id
    Note over REC,R: the relay republishes the row#59; every bound queue gets a copy, every ledger absorbs duplicates
  end
```

**Legend.** Every message is IMPLEMENTED (step 3.2). The same flow serves `email.received` (email-worker MIME ingestion) with the **hold** strategy: a transient or retryable failure keeps the delivery and its prefetch slot for the backoff (≤ 60 s), then republishes a copy to `email.ingestion` with `retry.email.received.org.<id>.<type>` and acks the original. Dormant queues (`scan.*`, `email.policy.evaluate`, `email.quarantine`, `email.archive`, `email.analytics`) are bound and receive copies, but have no consumer until their step.

## Status

| Step in the sequence                                               | Status          | Evidence                                                                                                                                          |
| ------------------------------------------------------------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Relay shards, confirmed publish, marking, poison rows, row backoff | IMPLEMENTED 3.2 | `apps/event-relay/src/relay/*.test.ts`; `apps/event-relay/integration/relay.test.ts` (TCP-proxy cuts, reject-publish, two relays)                 |
| Topology, routing keys, bindings, policies, role users             | IMPLEMENTED 3.2 | `packages/event-contracts` tests; `tests/integration/messaging-topology.test.ts`, `messaging-permissions.test.ts`                                 |
| Consumer decode, ack, retry (hold / delay queue), dead letter      | IMPLEMENTED 3.2 | `packages/common/src/messaging/consumer.test.ts`; `tests/integration/messaging-client.test.ts`; worker integration suites                         |
| Redelivery after a crash or broker restart, exactly-once effects   | IMPLEMENTED 3.2 | stack `messaging-restart.test.ts`, `messaging-consumer-crash.test.ts`, `messaging-db-outage.test.ts`; `cluster/node-failure.test.ts`              |
| Duplicates (relay retry, redelivery, re-drive, replay)             | IMPLEMENTED 3.2 | stack `messaging-duplicates.test.ts`; email-worker and delivery-worker idempotency suites                                                         |
| Backpressure (prefetch bounds unacked deliveries)                  | IMPLEMENTED 3.2 | stack `messaging-backlog.test.ts` (500 messages, unacked ≤ `MIME_CONCURRENCY`); email-worker `rabbitmq.test.ts` (2 000 queued events, prefetch 4) |
| Audited dead-letter replay                                         | IMPLEMENTED 3.2 | `apps/api` `dead-letters.e2e.test.ts`, `integration/dead-letters.test.ts`; stack `messaging-replay.test.ts` (through the live api)                |
| Reconciler re-drive and exhaustion                                 | IMPLEMENTED 3.2 | `apps/event-relay/src/reconciler/*.test.ts`, `apps/event-relay/integration/reconciler.test.ts`                                                    |
