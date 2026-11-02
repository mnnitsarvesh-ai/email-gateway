# 9. Email scanning sequence

`email-worker` consumes `mail.message.received.v1`, fans the message out to the security engines in parallel, records every engine result, and publishes `mail.message.scanned.v1`. Engines return `error` and `timeout` as **explicit outcomes**: an engine that fails is never treated as `clean`. Engines never choose the final action; the policy engine does (ADR-0007).

```mermaid
sequenceDiagram
  autonumber
  participant MQ as RabbitMQ queue email-worker.message-received
  participant EW as email-worker consumer (PLANNED 4.1)
  participant DB as MySQL writer
  participant S3 as S3 mail bucket
  participant RS as Rspamd /checkv2
  participant AV as ClamAV INSTREAM
  participant EN as YARA, URL, BEC, DLP, sandbox (PLANNED 4.2 to 4.6)

  MQ->>EW: envelope {eventId, organizationId, correlationId, payload messageId, receivedAt, emlS3Key}
  rect rgb(255, 248, 225)
    EW->>EW: parseEvent with messageReceivedV1 (zod), else reject to DLQ
    EW->>EW: check emlS3Key starts with org/{envelope organizationId}/ (PLANNED 3.x)
    EW->>DB: BEGIN, processOnce INSERT message_idempotency (consumer, eventId)
    alt duplicate eventId
      DB-->>EW: primary key violation, already processed
      EW->>MQ: ack, no effect
    else first delivery
      EW->>DB: INSERT email_scans (scan_kind initial, attempt, status running),<br/>UPDATE email_messages status scanning WHERE id and received_at
      EW->>S3: GET EML (streamed)
      par each engine with its own AbortSignal timeout
        EW->>RS: POST /checkv2 (PLANNED 4.1, circuit breaker, Redis cache)
        RS-->>EW: score, symbols, or error, or timeout
      and
        EW->>AV: INSTREAM attachments (PLANNED 4.2)
        AV-->>EW: OK, FOUND, or error, or timeout
      and
        EW->>EN: scan(input, signal)
        EN-->>EW: EngineVerdict clean, suspicious, malicious, error or timeout
      end
      EW->>DB: INSERT scan_engine_results one row per engine (outcome, score, duration_ms, evidence)
      EW->>EW: aggregate and score (PLANNED 5.1), list timedOutStages
      EW->>DB: UPDATE email_scans completed, verdict, risk_score, scoring_version
      EW->>DB: UPDATE email_messages status scanned, INSERT email_message_status_history, email_events
      EW->>DB: INSERT message_outbox mail.message.scanned.v1 {scanIds, timedOutStages}
      EW->>DB: COMMIT
      EW->>MQ: ack after COMMIT
    end
    alt handler throws (S3 or MySQL unavailable)
      EW->>DB: ROLLBACK, ledger row included
      EW->>MQ: nack, redelivered until x-delivery-limit 5, then email-worker.message-received.dlq
    end
  end
```

**Legend.** Plain participants are running daemons (IMPLEMENTED); everything the worker does is inside the shaded block and PLANNED. The `processOnce` ledger semantics used here are IMPLEMENTED and tested (`tests/integration/mysql.test.ts`).

## Status

| Element                                              | Status               | Evidence or delivering step                                                                                                                      |
| ---------------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Queue `email-worker.message-received` and its DLQ    | IMPLEMENTED          | `topology.ts`; asserted by `RabbitMqService` at email-worker startup; `events.test.ts`                                                           |
| Event schema `messageReceivedV1`, `messageScannedV1` | IMPLEMENTED          | `events.test.ts` (decimal ids, `org/{id}/` keys, `scanIds`)                                                                                      |
| `processOnce` on `message_idempotency`               | IMPLEMENTED          | `idempotency.test.ts`, `mysql.test.ts`                                                                                                           |
| Security engine contract                             | IMPLEMENTED          | `packages/security-contracts` (types and `engineVerdictSchema`)                                                                                  |
| Rspamd `/checkv2`, ClamAV `INSTREAM` daemons         | IMPLEMENTED          | `mail-plane.test.ts` (verdict, EICAR)                                                                                                            |
| `email_scans`, `scan_engine_results` tables          | IMPLEMENTED          | Step 1.1 schema, partitioned by `received_at` (`schema.test.ts`)                                                                                 |
| Consumer, engine adapters, aggregation               | PLANNED 4.1–4.6, 5.1 |                                                                                                                                                  |
| Key-prefix equality check against the envelope       | PLANNED 3.x          | The zod schema checks the **format** `org/{decimal}/` only, not that it equals the envelope's `organizationId`; consumers must add that check    |
| Pausing consumption during infrastructure outages    | PLANNED 3.2          | Without it, a MySQL or S3 outage burns the 5 redeliveries and moves healthy messages to the DLQ (see [failure handling](../failure-handling.md)) |

## Contract gaps to resolve in step 4.x

| Gap                                                                                                                                                    | Where                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| `scan_engine_results.outcome` allows `skipped`; `VerdictOutcome` in `security-contracts` does not                                                      | `packages/security-contracts/src/index.ts`, schema |
| `scan_engine_results.engine` names `sandbox` and `reputation`; `SecurityStage` has neither (it has `antispam, antivirus, yara, url, bec, dlp`)         | same                                               |
| `EngineVerdict.score` is 0–100; `email_messages.risk_score` and `email_scans.risk_score` are 0–1000 (the aggregated score). The mapping belongs to 5.1 | `security-contracts`, step 1.1 schema              |
