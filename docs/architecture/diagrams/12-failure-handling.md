# 12. Failure handling architecture

How the platform keeps mail safe when a component fails. The principle: **every hop either has durably accepted the message or has told the previous hop to retry.** Postfix's disk spool is the buffer in front of everything; MySQL holds state and the outbox; RabbitMQ holds work; a failure anywhere turns into a retry, a dead letter or a fallback, never into silent loss or a silent `clean`. The per-dependency detail is in [failure-handling.md](../failure-handling.md).

```mermaid
flowchart LR
  classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
  classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
  classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b

  sender["Sending MTA<br/>retries on 4xx for days"]:::ext

  subgraph edge["Edge: nothing accepted unchecked"]
    spool["Postfix disk spool<br/>IMPLEMENTED"]:::impl
    polFail["smtp-adapter down, slow or erroring<br/>(policy, socketmap, SASL, Redis, DB)<br/>4xx on both Postfix instances<br/>IMPLEMENTED"]:::impl
    milFail["Rspamd milter down<br/>milter_default_action tempfail<br/>IMPLEMENTED config"]:::impl
  end

  subgraph ingest["Ingestion: 250 only after commit"]
    ingFail["S3 or MySQL writer failure<br/>LMTP 451 per organization, Postfix retries<br/>IMPLEMENTED"]:::impl
    dedupe["Duplicate ingest_key<br/>250 without rewriting<br/>IMPLEMENTED"]:::impl
  end

  subgraph async["Async pipeline: at-least-once, exactly-once effects"]
    outbox["message_outbox<br/>unpublished rows retried with available_at backoff<br/>table IMPLEMENTED, relay PLANNED 3.2"]:::planned
    confirms["Publisher confirms<br/>ConfirmChannel IMPLEMENTED"]:::impl
    quorum["Quorum queues, x-delivery-limit,<br/>reject-publish on overflow<br/>IMPLEMENTED"]:::impl
    once["processOnce on message_idempotency<br/>duplicate delivery is a no-op<br/>IMPLEMENTED"]:::impl
    dlq["queue.dlq via mail.dlx<br/>at-least-once dead-lettering<br/>IMPLEMENTED"]:::impl
    replay["DLQ replay tool and<br/>stuck-message reconciliation (Q7)<br/>PLANNED 3.2"]:::planned
    pause["Pause consumers while a dependency is down<br/>so outages do not exhaust delivery limits<br/>PLANNED 3.2"]:::planned
    crash["Broker connection lost:<br/>process exits, orchestrator restarts<br/>IMPLEMENTED"]:::impl
  end

  subgraph verdicts["Scanning"]
    engFail["Engine error or timeout is an explicit outcome<br/>policy decides, e.g. quarantine engine_unavailable<br/>contract IMPLEMENTED, use PLANNED 4.x, 5.2"]:::planned
  end

  subgraph dbl["Database"]
    readerFb["Replica down, stopped or lagging:<br/>PrismaReadService falls back to the writer,<br/>readiness stays ok<br/>IMPLEMENTED"]:::impl
    partJob["Partition maintenance: future partitions,<br/>outbox drop guard, non-zero exit on failure"]:::impl
    alerts["Alerts: reader mode, pmax rows, DLQ depth,<br/>outbox age, job failures<br/>PLANNED 10.3"]:::planned
  end

  delivery["postfix-outbound owns retries, backoff, DSNs;<br/>DSN copies → bounce_events, suppressions<br/>IMPLEMENTED"]:::impl
  dworker["delivery-worker: retries only its own reinjection hop<br/>(backoff, max age → expired); rate limit or Redis error → deferred;<br/>ambiguous crash window resolved by the log binding<br/>IMPLEMENTED 2.3"]:::impl
  dstatus["Per-recipient status from the delivery log + DSN copies;<br/>idempotent signals; missing signal → unknown, never guessed<br/>IMPLEMENTED 2.3"]:::impl
  ready["/health/ready 503 removes the pod from service<br/>IMPLEMENTED"]:::impl

  sender --> spool
  polFail -->|"4xx"| sender
  milFail -->|"4xx"| sender
  spool -->|"LMTP retry"| ingFail
  ingFail -->|"4xx keeps mail in spool"| spool
  spool --> dedupe
  dedupe --> outbox
  outbox -.->|"P 3.2"| confirms
  confirms --> quorum
  quorum --> once
  once -->|"handler throws: rollback, nack"| quorum
  quorum -->|"delivery limit reached"| dlq
  dlq -.->|"P 3.2"| replay
  replay -.-> quorum
  pause -.-> quorum
  crash --> quorum
  once -.-> engFail
  once -.-> delivery
  dedupe -->|"outbox poller (interim, R6)"| dworker
  dworker -->|"reinject 10026 / 10027"| delivery
  delivery --> dstatus
  readerFb -.-> alerts
  partJob -.-> alerts
  dlq -.-> alerts
```

**Legend.** Green solid: IMPLEMENTED (each box names the mechanism). Amber dashed and dotted arrows: PLANNED with the step.

## Status

| Mechanism                                                  | Status                 | Evidence or delivering step                                                                                                                                                                      |
| ---------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Policy service fail-closed (down, slow, throws, malformed) | IMPLEMENTED            | `main.cf` (`smtpd_policy_service_default_action`, 10 s timeout); `mail-plane.test.ts`, `policy-server.service.test.ts`, `smtp-fail-closed.test.ts` (Redis down; adapter container stopped in CI) |
| Socketmap / SASL fail-closed                               | IMPLEMENTED            | `TEMP Lookup failed` → `451 4.3.0`; SASL temporary failure → `454 4.7.0` (`smtp-fail-closed.test.ts`)                                                                                            |
| Milter fail-closed                                         | IMPLEMENTED            | `main.cf` (`milter_default_action = tempfail`). Configuration only; no automated test stops Rspamd mid-session                                                                                   |
| Postfix spool (both instances), survives restarts          | IMPLEMENTED            | `postfix-spool`, `postfix-outbound-spool` volumes; `smtp-durability.test.ts` suite 6. EBS-backed ASG in production is PLANNED 10.1                                                               |
| Ingestion `250 after commit`, `451` on failure             | IMPLEMENTED            | `ingestion.service.test.ts`, `apps/smtp-adapter/integration/ingestion.test.ts`, `smtp-durability.test.ts` suite 5 (MinIO stopped)                                                                |
| Registry de-duplication `(organization_id, ingest_key)`    | IMPLEMENTED            | `schema.test.ts`; ingestion dedupe in `smtp-durability.test.ts` suite 7                                                                                                                          |
| Outbox table, relay                                        | PLANNED 3.2            | `message_outbox` (daily partitions, `(published_at, id)` index) exists                                                                                                                           |
| Publisher confirms, manual acks, quorum queues, DLQs       | IMPLEMENTED            | `rabbitmq.module.ts`, `topology.ts`; `events.test.ts`, `rabbitmq-redis.test.ts`                                                                                                                  |
| `processOnce`                                              | IMPLEMENTED            | `idempotency.test.ts`, `mysql.test.ts` (once, duplicate, rollback)                                                                                                                               |
| Crash-only RabbitMQ reconnect                              | IMPLEMENTED            | `RabbitMqService` exits on an unexpected `close`; restart policy in Compose and Kubernetes                                                                                                       |
| Reader to writer fallback                                  | IMPLEMENTED            | `prisma-read.service.test.ts`, `replication.test.ts`                                                                                                                                             |
| Readiness gating                                           | IMPLEMENTED            | `health.service.test.ts` (2 s per check, 503 on any failure)                                                                                                                                     |
| Engine `error` / `timeout` outcomes                        | IMPLEMENTED (contract) | `packages/security-contracts`; `quarantine_messages.reason` includes `engine_unavailable`. Use PLANNED 4.x, 5.2                                                                                  |
| DLQ replay, reconciliation, consumer pause                 | PLANNED 3.2            |                                                                                                                                                                                                  |
| Partition maintenance                                      | IMPLEMENTED            | `packages/database/src/partitioning/*.test.ts`, `tests/integration/partitions.test.ts`, CI migrations job (runs `apply` twice)                                                                   |
| Alerting                                                   | PLANNED 10.3           |                                                                                                                                                                                                  |
| Outbound retries and DSNs in Postfix, bounce processing    | IMPLEMENTED            | ADR-0006; `postfix-outbound` queue settings; `bounces.test.ts`, `smtp-outbound.test.ts` (hard bounce)                                                                                            |
| delivery-worker hop retry, fail-closed rate limits         | IMPLEMENTED 2.3        | `reinjection.test.ts`, `rate-limit.test.ts` (worker integration); `routing-rate-limit.test.ts` (Redis stopped: nothing sent, delivered after recovery)                                           |
| Destination outage → Postfix retry → delivered             | IMPLEMENTED 2.3        | `routing-retry.test.ts` (sink stopped and started, no `postqueue -f`; failover along the next-hop list); [diagram 19](19-retry-bounce-sequence.md)                                               |
| Status signals idempotent, stale → `unknown`               | IMPLEMENTED 2.3        | `recorder.test.ts`, `status-tailer.test.ts`, `routing-signals.test.ts` (whole log re-read, bounce notice redelivered: no change)                                                                 |
