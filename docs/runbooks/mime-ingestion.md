# Runbook: MIME ingestion (post-queue parsing)

For platform operators. The email-worker parses every received message after the SMTP `250`: it streams the EML from S3, stores bodies and attachments under `org/{organizationId}/part/…` and commits `email_message_parses`, `email_headers`, `email_attachments`, an `email_events` row and a `mail.message.parsed.v1` or `mail.message.parse_failed.v1` outbox event. Background: [email-worker README](../../apps/email-worker/README.md), design [step 3.1](../plan/steps/06-mime-ingestion.md) M2, M3, M12, M13, [ADR-0022](../architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md), [failure handling](../architecture/failure-handling.md#email-worker-mime-ingestion-step-31).

Parsing never affects mail acceptance, and until step 3.3 it does not change `email_messages.status`. Under the step 2.3 development pass-through (local/CI only), delivery runs independently of parsing.

Since step 3.2 the worker consumes `mail.message.received.v1` from the RabbitMQ quorum queue `email.received` (published by the event-relay; ledger consumer `email-worker.mime-parser`, prefetch `MIME_CONCURRENCY`). The 3.1 outbox feed, its cursors (`outbox:email-worker.mime-parser…`) and the `MIME_OUTBOX_*` keys are gone; broker-side operations (relay lag, dead letters, replay, reconciliation) are in the [RabbitMQ messaging runbook](rabbitmq-messaging.md).

## Detection

- Metrics on the email-worker's `GET /metrics`:
  - `mime_parse_messages_total{status}`: the outcomes;
  - `mime_parse_failures_total{reason}`: the `parse_failed` reasons;
  - `mime_limit_exceeded_total{limit}`;
  - `mime_retries_total{class}`: failed attempts by dependency (`s3`, `db`, `other`); the log line says `transient: true|false`;
  - `amqp_consumer_messages_total{queue="email.received",outcome}` (`handled`, `duplicate`, `retried`, `dead_lettered`, `requeued`), `amqp_consumer_in_flight`, `amqp_consumer_retries_total{class}`, `amqp_consumer_dead_lettered_total{reason}`: the queue consumer;
  - how far behind the stage is: the queue depth (`rabbitmq_detailed_queue_messages_ready{queue="email.received"}`, alert `WorkQueueBacklog`) and the relay's `outbox_relay_lag_seconds`.
- Logs carry `eventId`, `messageId`, `organizationId`, `status`, codes, counts and `errName`/`errCode`. They never carry content, so search by these ids.
- The parse state of recent messages. Use the writer and a bounded `received_at` range so the partitions prune:

  ```sql
  SELECT status, failure_reason, COUNT(*) AS messages, MIN(started_at) AS oldest_start
    FROM email_message_parses
   WHERE received_at >= NOW() - INTERVAL 2 DAY
   GROUP BY status, failure_reason ORDER BY messages DESC;
  ```

- Received messages without a parse row (not read yet, or the worker is down or behind):

  ```sql
  SELECT m.organization_id, COUNT(*) AS unparsed, MIN(m.received_at) AS oldest
    FROM email_messages m
    LEFT JOIN email_message_parses p ON p.message_id = m.id AND p.received_at = m.received_at
   WHERE m.received_at >= NOW() - INTERVAL 1 DAY AND m.received_at < NOW() - INTERVAL 5 MINUTE
     AND p.id IS NULL
   GROUP BY m.organization_id;
  ```

## Stuck `parsing` rows

A row stays `parsing` only when an attempt did not finish: a crash, an OOM kill, a hang, a deploy during the parse, or a failed attempt that the queue consumer retries with backoff (`MIME_RETRY_BASE_MS`…`MIME_RETRY_MAX_MS`; the delivery is held, then republished to `email.received`). A transient failure (S3, MySQL or network outage, `S3Stalled`) gives the attempt back, so an outage never fails a message. Any other failed attempt (log line `MIME ingestion attempt failed; it will be retried and counts toward MIME_MAX_ATTEMPTS`, `transient: false`, with `errName`/`errCode`) keeps its attempt: a failure that repeats on every attempt ends as `parse_failed / max_attempts_exceeded` after `MIME_MAX_ATTEMPTS` attempts (below the queue's own `maxAttempts` of 8, so the message is recorded rather than dead-lettered).

```sql
SELECT message_id, organization_id, received_at, attempts, started_at, event_id
  FROM email_message_parses
 WHERE status = 'parsing' AND updated_at < NOW() - INTERVAL 10 MINUTE
   AND received_at >= NOW() - INTERVAL 7 DAY
 ORDER BY updated_at LIMIT 100;            -- index (status, updated_at)
```

1. **Check the worker first.** Look at `/health/ready` (mysql, rabbitmq, redis, s3), the restarts of the container or pod, and `mime_retries_total` rising, which points to an S3 or MySQL outage. Fix the dependency. Held retries complete and the queue drains by itself; transient retries never consume an attempt and dead-letter only after 24 h (`retry_age_exceeded`).
2. **A crash loop on one message** shows `attempts` growing with restarts. After `MIME_MAX_ATTEMPTS` (5) started attempts, the next delivery finalizes it as `parse_failed / max_attempts_exceeded` without parsing. Nothing needs to be done, but keep the `message_id` for the parser triage below (a crash on content is a parser bug).
3. **After a crash** the broker returns the unacked delivery to `email.received` and it is delivered again (`fields.redelivered`, `amqp_consumer_deliveries_total{redelivered="true"}`), which resumes the row (`attempts + 1`). A row that stays `parsing` with nothing in the queue means the event was lost between broker and consumer or dead-lettered: see [re-driving a received event](#re-driving-a-received-event) below. Messages with a final parse row are skipped as duplicates. Never set `status` by hand. The worker never changes a final row, so a hand-written final status would hide the message from scanning.

## Re-driving a received event

There is no cursor to reset any more (step 3.2). A received event that was not parsed is re-driven by the mechanisms below; each keeps the `eventId`, so the ledger (`message_idempotency`) and the final parse rows make every copy of an already handled event a duplicate.

1. **Unpublished outbox row** (`published_at IS NULL`): the event-relay publishes it; check `outbox_relay_lag_seconds`, `OutboxRelayNoShardOwner` and poison rows ([messaging runbook](rabbitmq-messaging.md#poison-rows)).
2. **Published, never handled** (no `email-worker.mime-parser` ledger row): the event-relay reconciler re-drives the outbox row after `RECONCILE_UNCONSUMED_AFTER_SECONDS` (default 900 s), up to `RECONCILE_MAX_REDRIVES` times; then `ReconcileExhausted` fires and the [reconciliation-exhausted procedure](rabbitmq-messaging.md#reconciliation-exhausted) applies (a reviewed single-row `published_at = NULL`).
3. **Dead-lettered** (the consumer gave up: `max_attempts_exceeded`, `retry_age_exceeded`, a contract or tenant mismatch): inspect with a dry run and replay with `POST /api/v1/platform/dead-letters/replay` (`sourceQueue: "email.received"`, MFA platform admin, audited) after fixing the cause ([dead-letter replay](rabbitmq-messaging.md#dead-letter-inspection-and-replay)).

Ledger rows to check (writer):

```sql
SELECT o.id, o.event_id, o.published_at, o.redrive_count, o.last_redriven_at, i.processed_at
  FROM message_outbox o
  LEFT JOIN message_idempotency i ON i.consumer = 'email-worker.mime-parser' AND i.event_id = o.event_id
 WHERE o.event_type = 'mail.message.received.v1' AND o.aggregate_id = '<message id>'
   AND o.created_at >= NOW() - INTERVAL 7 DAY;
```

## Scaling

Replicas are competing consumers of `email.received`: each holds at most `MIME_CONCURRENCY` unacked deliveries (its prefetch), so adding replicas adds throughput and the broker spreads the queue. There are no shards or locks to rebalance. The memory refusal of the worker multiplies by `MIME_CONCURRENCY` only.

## `parse_failed` triage

`parse_failed` is a recorded content-side outcome. It is never caused by an outage: infrastructure errors are retried, not recorded. The reason is on the parse row (`failure_reason`), the `email_events` `parse_failed` row and the `mail.message.parse_failed.v1` event.

| Reason                  | Meaning                                                                                                        | Action                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eml_missing`           | `GetObject` answered `NoSuchKey` for `eml_object_key`                                                          | The EML was deleted (versioning keeps the old versions: `aws s3api list-object-versions --prefix <key>`) or the key is wrong. Ingestion writes the object before its commit, so treat this as an incident: check bucket lifecycle rules and deletions in the access log                                                                                                                 |
| `eml_key_mismatch`      | `eml_object_key` is not under `org/{organizationId}/`                                                          | A data-integrity or tenant-isolation incident: the row points outside its tenant prefix. Escalate to security. Do not re-drive. A key without any `org/<id>/` prefix is published as `emlS3Key: null` (read the key from the row)                                                                                                                                                       |
| `integrity_mismatch`    | The SHA-256 or byte count of the object differs from `email_messages.eml_sha256` / `size_bytes`                | The object changed after ingestion (an overwrite, or corruption). Compare the object versions. Nothing of the content was recorded. Escalate as an integrity incident                                                                                                                                                                                                                   |
| `max_attempts_exceeded` | `MIME_MAX_ATTEMPTS` attempts started without finishing (crash, OOM, hang) or failed with a non-transient error | Probably a parser defect, a data error (look for the `transient: false` retry lines and their `errCode`, for example `P2000`) or a resource limit. Check the worker's restarts and memory around `started_at`. Reproduce offline with `@email-gateway/mime-parser` on a copy of the EML, inside a secured environment only (the content is untrusted). Never attach the EML to a ticket |
| `parser_error`          | A library exception that the parser did not map to a defect or limit. What was extracted is kept               | A parser bug. Record the `message_id` and parser version, and reproduce offline as above. A fix bumps `PARSER_VERSION`. Re-parsing existing messages is out of scope for step 3.1                                                                                                                                                                                                       |

`parse_limit_exceeded` (`limits_exceeded` on the row) and `parsed_with_defects` (`defects`) are not failures: the message was parsed as far as allowed and the codes go to scanning and policy (4.x, 5.x). `parse_timeout` is recorded only when the message itself was slow: when the parse budget runs out while an S3 call had been pending for at least `min(1 s, budget / 4)`, or after half the budget went to S3 waits, the attempt is retried as `S3Stalled` instead (and `MIME_S3_TIMEOUT_MS`, which must be below `MIME_PARSE_TIMEOUT_MS`, fails a single stalled S3 call first). A wave of `S3Stalled` / `UploadTimedOut` retries (`mime_retries_total{class="s3"}`) means a slow or hung S3; a wave of `parse_timeout` limits points at content or CPU starvation. Compare `mime_parse_duration_seconds` and the S3 latency.

## Do not

- Do not delete `email_message_parses` rows to force a re-parse. The part keys depend on the parser version, and re-parsing is out of scope for step 3.1.
- Do not copy bodies, attachments, subjects or filenames into tickets or logs. Use the ids and codes.
- Do not purge `email.received` or `email.dead-letter` (management UI "Purge"): the outbox is the source of truth, but a purge forces re-drives through reconciliation and loses the dead letters' failure headers. Replay or re-drive instead.
