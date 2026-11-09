# 20. Post-queue MIME ingestion

Step 3.1 ([design and verification record](../../plan/steps/06-mime-ingestion.md), [ADR-0022](../adr/0022-mime-parsing-and-post-queue-ingestion.md)). After the SMTP `250` (diagram [6](06-inbound-smtp-sequence.md)), the email-worker parses every received message from the stored EML. It streams the bodies and attachments to S3 and commits the parse metadata, an `email_events` row and a `mail.message.parsed.v1` (or `mail.message.parse_failed.v1`) outbox event in one writer transaction. Since step 3.2 the event is delivered through RabbitMQ: the event-relay publishes `mail.message.received.v1` (confirmed) to `email.ingestion`, and the email-worker consumes the quorum queue `email.received` with a `QueueConsumer` (prefetch = `MIME_CONCURRENCY`, manual ack after the transaction). The 3.1 outbox feed (`ShardedOutboxFeed`) is removed ([diagram 21](21-event-relay-sequence.md)).

```mermaid
sequenceDiagram
  autonumber
  participant ING as smtp-adapter<br/>LMTP ingestion
  participant DB as MySQL writer
  participant RL as event-relay
  participant FEED as email-worker<br/>QueueConsumer email.received
  participant SVC as email-worker<br/>MimeIngestionService
  participant P as mime-parser<br/>(library)
  participant S3 as S3 (MinIO)
  participant MQ as RabbitMQ<br/>email.ingestion

  ING->>DB: email_messages (received), recipients, email_events received,<br/>message_outbox mail.message.received.v1 (one txn, before the 250)
  RL->>DB: read unpublished rows of its shard
  RL->>MQ: publish org.<id>.mail.message.received.v1 (confirms), then mark published_at
  MQ->>FEED: deliver from email.received (prefetch MIME_CONCURRENCY)
  FEED->>FEED: decode: type, schema version, envelope, tenant (routing key = header = envelope)
  FEED->>SVC: handle(event), up to MIME_CONCURRENCY at once#59; ack after it returns
  SVC->>DB: ledger pre-check (email-worker.mime-parser, eventId)
  SVC->>DB: load email_messages by (id, received_at, organization_id = envelope org)
  alt missing row or cross-tenant envelope
    SVC->>DB: ledger row only (message_missing)
  else parse row already final
    SVC->>DB: ledger row only (duplicate)
  else
    SVC->>DB: email_message_parses: insert parsing, attempts 1 (or attempts + 1)
    alt attempts > MIME_MAX_ATTEMPTS (poison guard)
      SVC->>DB: finalize parse_failed / max_attempts_exceeded
    else eml key outside org/{org}/ or size above MIME_MAX_MESSAGE_BYTES
      SVC->>DB: finalize parse_failed / eml_key_mismatch, or parse_limit_exceeded [message_size]
    else
      SVC->>S3: GetObject eml_object_key (streamed#59; MIME_S3_TIMEOUT_MS per wait on S3)
      SVC->>P: parseMessage(stream, limits, part sink, AbortSignal MIME_PARSE_TIMEOUT_MS)
      loop each body / attachment leaf
        P->>S3: Upload org/{org}/part/yyyy/mm/dd/{messageId}/{partIndex}.text|html|att<br/>(deterministic key, ContentDisposition attachment)
        opt zip attachment
          P->>S3: ranged GETs (EOCD, central directory): flags only, never extracted
        end
      end
      P-->>SVC: status, limits, defects, headers (allow-list), bodies, attachments, structure, sha256 + bytes read
      alt sha256 or byte count differs from email_messages
        SVC->>S3: delete this attempt's part objects (best effort)
        SVC->>DB: finalize parse_failed / integrity_mismatch
      else
        SVC->>DB: one txn (processOnce): UPDATE parse row WHERE status = parsing,<br/>email_headers, email_attachments, email_messages.subject + attachment_count,<br/>email_events parsed, message_outbox mail.message.parsed.v1
      end
    end
  end
  alt transient: S3 / MySQL / network error, S3Stalled (parse budget ran out waiting on S3)
    SVC->>DB: attempts - 1 (best effort)
    SVC-->>FEED: rethrow, classified transient: the delivery is held for the backoff and republished (retry.email.received…), no queue attempt consumed, never failed for an outage
  else any other error (data or contract error, unexpected exception)
    SVC-->>FEED: rethrow, retryable (x-eg-attempt + 1): after MIME_MAX_ATTEMPTS the poison guard finalizes max_attempts_exceeded (below the queue's 8, so it is recorded, not dead-lettered)
  end
  RL->>MQ: publish mail.message.parsed.v1 (confirms) → scan.* and email.analytics (dormant until 4.x)
  rect rgb(255, 248, 225)
    MQ-->>MQ: consumers of scan.* (PLANNED 4.x) and the lifecycle (PLANNED 3.3)
  end
```

**Legend.** Plain messages: IMPLEMENTED. The shaded (amber) block and participants marked `(PLANNED x.y)`: PLANNED. `email_messages.status` is not changed by this step (step 3.3 owns the lifecycle); the step 2.3 development pass-through keeps approving on `mail.message.received.v1`, independent of parsing.

## Status

| Step in the sequence                                                    | Status          | Evidence                                                                                                                                              |
| ----------------------------------------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `email.received` consumer (prefetch, retries, crash redelivery)         | IMPLEMENTED 3.2 | `apps/email-worker/integration/rabbitmq.test.ts` (SIGKILL before/after commit), stack `messaging-consumer-crash.test.ts`, `messaging-backlog.test.ts` |
| Ledger, missing message, cross-tenant envelope, final-row duplicate     | IMPLEMENTED     | `mime-ingestion.service.test.ts`; `apps/email-worker/integration/*.test.ts`                                                                           |
| Poison guard, key mismatch, pre-size limit, `eml_missing`               | IMPLEMENTED     | `apps/email-worker/integration/mime-ingestion.test.ts`                                                                                                |
| Streaming parse with limits, defects, headers, filenames, sniffing, zip | IMPLEMENTED     | `packages/mime-parser` unit tests and corpus; the email-worker integration suite (53 MB message, zip bomb, nested archives)                           |
| Part objects with deterministic keys, SHA-256 equal to the rows         | IMPLEMENTED     | `apps/email-worker/integration/mime-ingestion.test.ts`; `tests/integration/mime-ingestion.test.ts` (through Postfix and MinIO)                        |
| Integrity mismatch                                                      | IMPLEMENTED     | `apps/email-worker/integration/mime-ingestion.test.ts`                                                                                                |
| Finalize transaction, `parsed` event, `mail.message.parsed.v1`          | IMPLEMENTED     | `tests/integration/mime-ingestion.test.ts` (one outbox row, `messageParsedV1`, no address, subject or filename)                                       |
| Malformed MIME → `parsed_with_defects`                                  | IMPLEMENTED     | `tests/integration/mime-ingestion.test.ts` (missing closing boundary, invalid base64)                                                                 |
| Infrastructure retry without consuming attempts                         | IMPLEMENTED     | `apps/email-worker/integration/mime-ingestion.test.ts` (S3 unavailable)                                                                               |
| RabbitMQ relay of the received and parse events                         | IMPLEMENTED 3.2 | `apps/event-relay` suites; consumers of the parse events PLANNED 4.x / 3.3                                                                            |
