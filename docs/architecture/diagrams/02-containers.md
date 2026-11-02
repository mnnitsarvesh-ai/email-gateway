# 2. Container architecture (C4 level 2)

The deployables, the mail daemons and the data stores, with the arrows that carry mail, events and reads. The eight deployables are the seven NestJS apps in `apps/*` plus the Next.js `admin-portal`.

```mermaid
flowchart LR
  classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
  classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
  classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b

  sender["Sending MTA"]:::ext
  browser["Admin browser"]:::ext
  tenantMx["Tenant mail server"]:::ext

  subgraph edge["Mail edge"]
    pfIn["Postfix inbound MX<br/>:25"]:::impl
    pfOut["Postfix outbound<br/>PLANNED 2.2"]:::planned
    rspamd["Rspamd 3.12<br/>milter :11332, HTTP :11333"]:::impl
    clamav["ClamAV 1.4<br/>clamd :3310"]:::impl
  end

  subgraph apps["Deployables"]
    portal["admin-portal<br/>Next.js :3001"]:::impl
    api["api<br/>:3000"]:::impl
    smtp["smtp-adapter<br/>policy :10040, HTTP :3010"]:::impl
    lmtp["smtp-adapter LMTP ingestion<br/>PLANNED 2.2 / 3.1"]:::planned
    ew["email-worker<br/>:3020"]:::impl
    pe["policy-engine<br/>:3030"]:::impl
    dw["delivery-worker<br/>:3040"]:::impl
    aw["archive-worker<br/>:3060"]:::impl
    nw["notification-worker<br/>:3050"]:::impl
  end

  subgraph data["Data stores"]
    mysqlW[("MySQL 8.4 primary<br/>writer, GTID")]:::impl
    mysqlR[("MySQL 8.4 replica<br/>reader")]:::impl
    mq{{"RabbitMQ 4.1<br/>mail.events, mail.dlx"}}:::impl
    redis[("Redis 7.4")]:::impl
    s3[("S3 / MinIO<br/>mail + archive buckets")]:::impl
    os[("OpenSearch 2.19<br/>analytics profile")]:::impl
    ch[("ClickHouse 25.8<br/>analytics profile")]:::impl
  end

  obs["OTel Collector, Prometheus, Grafana<br/>observability profile"]:::impl

  sender -->|"SMTP"| pfIn
  pfIn -->|"policy delegation"| smtp
  pfIn -->|"milter"| rspamd
  rspamd -->|"own state"| redis
  pfIn -.->|"LMTP, P 2.2"| lmtp
  lmtp -.->|"EML, P 3.1"| s3
  lmtp -.->|"message + outbox txn, P 3.1"| mysqlW
  mysqlW -.->|"outbox relay, P 3.2"| mq
  mq -.->|"message.received, P 4.1"| ew
  ew -.->|"/checkv2, P 4.1"| rspamd
  ew -.->|"INSTREAM, P 4.2"| clamav
  ew -.->|"read EML, P 4.1"| s3
  mq -.->|"message.scanned, P 5.2"| pe
  mq -.->|"policy.decided, P 2.3"| dw
  mq -.->|"policy.decided, P 8.1"| aw
  mq -.->|"policy.decided, P 6.2"| nw
  dw -.->|"SMTP reinject, P 2.3"| pfOut
  pfOut -.->|"SMTP, P 2.2"| tenantMx
  aw -.->|"archive copy, P 8.1"| s3
  mq -.->|"indexing feed, no step yet"| os
  mq -.->|"event history feed, no step yet"| ch

  browser -->|"HTTPS"| portal
  portal -->|"server-side /health/ready"| api
  api -->|"DML, writer"| mysqlW
  api -->|"control-plane reads"| mysqlR
  mysqlW -->|"GTID replication"| mysqlR
  smtp -->|"writer"| mysqlW
  ew -->|"writer"| mysqlW
  pe -->|"writer"| mysqlW
  dw -->|"writer"| mysqlW
  aw -->|"writer"| mysqlW
  nw -->|"writer"| mysqlW
  ew -->|"topology assert"| mq
  pe -->|"topology assert"| mq
  dw -->|"topology assert"| mq
  aw -->|"topology assert"| mq
  nw -->|"topology assert"| mq
  api -->|"health"| redis
  api -->|"health"| s3
  apps -->|"OTLP traces, metrics"| obs
```

**Legend.** Green solid: IMPLEMENTED. Amber dashed and dotted arrows: PLANNED with the step. "Topology assert" means the worker declares its exchange, quorum queue and DLQ at startup; it does not consume yet.

## Status

| Element                                                | Status          | Evidence or delivering step                                                                                              |
| ------------------------------------------------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Postfix inbound, policy delegation, milter             | IMPLEMENTED     | `infrastructure/postfix/*`; `mail-plane.test.ts`                                                                         |
| Rspamd, ClamAV daemons                                 | IMPLEMENTED     | `mail-plane.test.ts` (`/checkv2` verdict, EICAR)                                                                         |
| 7 Nest deployables + admin-portal                      | IMPLEMENTED     | `apps/*/src/app.module.ts`, `app.module.test.ts` per app; `services.test.ts`. Shells only: health and topology           |
| MySQL primary + replica, GTID replication              | IMPLEMENTED     | `docker-compose.yml`; `replication.test.ts`                                                                              |
| `api` reads from the replica                           | IMPLEMENTED     | `PrismaReadService` (`prisma-read.service.test.ts`); no feature module reads from it yet                                 |
| RabbitMQ topology (exchanges, quorum queues, DLQs)     | IMPLEMENTED     | `packages/event-contracts/src/topology.ts`, `RabbitMqService.assertTopology`; `events.test.ts`, `rabbitmq-redis.test.ts` |
| Redis, MinIO                                           | IMPLEMENTED     | `rabbitmq-redis.test.ts` (auth, TTL), `storage.test.ts` (buckets, tenant-prefixed key, anonymous denied)                 |
| OpenSearch, ClickHouse containers                      | IMPLEMENTED     | Compose `analytics` profile, validated by `docker compose config` in CI. Not exercised by tests                          |
| Observability containers, OTLP export                  | IMPLEMENTED     | Compose `observability` profile, `packages/logger/src/tracing.ts`. Validated by `docker compose config`; no runtime test |
| LMTP ingestion, S3 write, ingestion transaction        | PLANNED 2.2/3.1 | Locally Postfix discards accepted mail (`POSTFIX_RELAY_TRANSPORT=discard:`)                                              |
| Outbox relay                                           | PLANNED 3.2     | `message_outbox` table exists                                                                                            |
| Consumers (email-worker, policy-engine, delivery, ...) | PLANNED 4.1–8.1 | Queues exist; no consumer code                                                                                           |
| Postfix outbound                                       | PLANNED 2.2     |                                                                                                                          |
| OpenSearch and ClickHouse feeds                        | PLANNED         | ADR-0009. **No execution-plan step owns them yet** (reported as an open item)                                            |
