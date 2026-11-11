# 2. Container architecture (C4 level 2)

The deployables, the mail daemons and the data stores, with the arrows that carry mail, events and reads. The nine deployables are the eight NestJS apps in `apps/*` (step 3.2 added `event-relay`) plus the Next.js `admin-portal`.

```mermaid
flowchart LR
  classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
  classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
  classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b

  sender["Sending MTA"]:::ext
  browser["Admin browser"]:::ext
  tenantMx["Tenant mail server"]:::ext

  subgraph edge["Mail edge"]
    pfIn["postfix inbound MX<br/>:25 (postscreen)"]:::impl
    pfOut["postfix-outbound<br/>587 submission, 25 connector relay,<br/>10026/10027 reinjection"]:::impl
    rspamd["Rspamd 3.12<br/>milter :11332, HTTP :11333"]:::impl
    rspamdOut["rspamd-outbound<br/>DKIM signing milter"]:::impl
    redisDkim[("redis-dkim<br/>signing keys, ACLs,<br/>no persistence")]:::impl
    clamav["ClamAV 1.4<br/>clamd :3310"]:::impl
  end

  subgraph apps["Deployables"]
    portal["admin-portal<br/>Next.js :3001"]:::impl
    api["api<br/>:3000"]:::impl
    smtp["smtp-adapter<br/>policy :10040, socketmap :10041,<br/>SASL :10042, HTTP :3010"]:::impl
    lmtp["smtp-adapter LMTP<br/>ingestion :10050/:10051,<br/>bounces :10052"]:::impl
    ew["email-worker<br/>:3020"]:::impl
    pe["policy-engine<br/>:3030"]:::impl
    dw["delivery-worker<br/>:3040"]:::impl
    aw["archive-worker<br/>:3060"]:::impl
    nw["notification-worker<br/>:3050"]:::impl
    er["event-relay<br/>outbox relay + reconciler<br/>:3070 (3.2)"]:::impl
    clickSvc["click-service (4.3)<br/>public GET /c/{token} :3080,<br/>admin :3081"]:::impl
    ubw["url-browser-worker (4.3, profile url-browser)<br/>Chromium headless shell, :3090,<br/>network url-sandbox (internal)"]:::impl
    uep["url-egress-proxy (4.3)<br/>:3128, admin :3091,<br/>SSRF guard"]:::impl
    sbc["sandbox-controller (4.6, profile apps)<br/>:3092, network sandbox-control (internal);<br/>no DB/Redis/mail bucket; backend disabled:<br/>EXECUTION DISABLED"]:::impl
    sbr["detonation runners + sinkhole (4.6)<br/>LOCAL/CI exec override only, NOT a VM;<br/>VM runner NOT IMPLEMENTED"]:::planned
  end

  subgraph data["Data stores"]
    mysqlW[("MySQL 8.4 primary<br/>writer, GTID")]:::impl
    mysqlR[("MySQL 8.4 replica<br/>reader")]:::impl
    mq{{"RabbitMQ 4.1, vhost email-gateway<br/>6 exchanges, 19 quorum queues<br/>(topology v8 since 4.6)"}}:::impl
    redis[("Redis 7.4")]:::impl
    s3[("S3 / MinIO<br/>mail + archive buckets,<br/>restricted sandbox bucket (4.6)")]:::impl
    os[("OpenSearch 2.19<br/>analytics profile")]:::impl
    ch[("ClickHouse 25.8<br/>analytics profile")]:::impl
  end

  obs["OTel Collector, Prometheus, Grafana<br/>observability profile"]:::impl

  sender -->|"SMTP"| pfIn
  tenantMx -->|"587 SASL / 25 connector"| pfOut
  pfIn -->|"policy, socketmap"| smtp
  pfOut -->|"policy, socketmap, SASL"| smtp
  pfIn -->|"milter"| rspamd
  rspamd -->|"own state"| redis
  pfIn -->|"LMTP inbound"| lmtp
  pfOut -->|"LMTP outbound, DSN copies"| lmtp
  lmtp -->|"EML"| s3
  lmtp -->|"message + outbox txn per tenant"| mysqlW
  smtp -->|"caches, rate limits"| redis
  pfOut -->|"10027 milter"| rspamdOut
  rspamdOut -->|"read keys"| redisDkim
  api -->|"publish keys"| redisDkim
  smtp -->|"selector probe"| redisDkim
  mysqlW -->|"message_outbox (shards, writer)"| er
  er -->|"confirmed publish, eg-relay"| mq
  mq -->|"email.received (MIME, 3.1/3.2)"| ew
  ew -->|"scan.spam: /checkv2 (4.1)"| rspamd
  ew -->|"scan.attachment: INSTREAM (4.2)"| clamav
  mq -->|"scan.url, scan.url.results (4.3)"| ew
  ew -->|"rewritten copies org/{org}/rewrite/ (4.3)"| s3
  mq -->|"scan.url.inspect (lossy), eg-url-browser"| ubw
  ubw -->|"inspection_completed.v1 (confirms)"| mq
  ubw -->|"all browser traffic (token auth)"| uep
  clickSvc -->|"gateway_click: URL rows, click events + clicked.v1"| mysqlW
  clickSvc -->|"rate limits, URL cache (HMAC)"| redis
  ew -->|"read EML, write parts (3.1)"| s3
  mq -->|"scan.sandbox.submissions, scan.sandbox.results (4.6)"| ew
  ew -->|"sealed samples (sandbox bucket, 4.6)"| s3
  mq -->|"scan.sandbox (task_requested.v1), eg-sandbox"| sbc
  sbc -->|"task_completed.v1 (MAC, confirms)"| mq
  sbc -->|"samples/ read, artifacts/ write (own MinIO user)"| s3
  sbc -.->|"exec override only"| sbr
  mq -->|"email.policy.evaluate (5.2), eg-policy-engine"| pe
  pe -->|"policy copies org/{org}/policy/ (5.2)"| s3
  mq -->|"email.delivery.pending (3.2)"| dw
  mq -.->|"email.archive (dormant, archive_requested.v1 since 5.2), P 8.1"| aw
  mq -->|"email.notifications (5.2: policy alerts, sender notices); webhooks P 6.2"| nw
  api -->|"dead-letter view and replay, eg-ops"| mq
  dw -->|"SMTP reinject 10026/10027 (2.3)"| pfOut
  pfOut -->|"SMTP: tenant destination / MX"| tenantMx
  aw -.->|"archive copy, P 8.1"| s3
  mq -.->|"email.analytics (dormant), no step yet"| os
  mq -.->|"email.analytics (dormant), no step yet"| ch

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
  api -->|"health"| redis
  api -->|"health"| s3
  apps -->|"OTLP traces, metrics"| obs
```

**Legend.** Green solid: IMPLEMENTED. Amber dashed and dotted arrows: PLANNED with the step. Since step 3.2 no service declares broker objects: `rabbitmq-init` provisions the vhost from `infrastructure/rabbitmq/definitions.json`, services verify passively with their least-privilege role users, and policy-engine, archive-worker and notification-worker do not connect to RabbitMQ until their consumers exist. Step 4.6: the `sandbox-controller` runs in the `apps` profile on the internal `sandbox-control` network only (its port is not reachable from the host) with backend `disabled` — **execution of unknown files is disabled**; the detonation runners and the recording sinkhole exist only with the LOCAL/CI exec override (`infrastructure/sandbox/compose.exec.yml`; a shared-kernel container, **not a VM boundary**); a VM-class runner is not implemented. "Dormant" queues are declared and bound with no consumer (bounded `drop-head` buffers, [messaging topology](../messaging-topology.md)).

## Status

| Element                                               | Status                                                                                                                                                      | Evidence or delivering step                                                                                                                                      |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Postfix inbound, policy delegation, socketmap, milter | IMPLEMENTED                                                                                                                                                 | `infrastructure/postfix/*`; `mail-plane.test.ts`, `smtp-inbound.test.ts`, `smtp-relay-control.test.ts`                                                           |
| postfix-outbound (587, 25, 10026, 10027), SASL        | IMPLEMENTED                                                                                                                                                 | `infrastructure/postfix-outbound/*`; `smtp-relay-control.test.ts`, `smtp-outbound.test.ts`                                                                       |
| rspamd-outbound + redis-dkim (DKIM signing)           | IMPLEMENTED                                                                                                                                                 | `infrastructure/rspamd-outbound/*`, `infrastructure/redis-dkim/*`; `smtp-outbound.test.ts` (signature verifies)                                                  |
| Rspamd, ClamAV daemons                                | IMPLEMENTED                                                                                                                                                 | `mail-plane.test.ts` (`/checkv2` verdict, EICAR)                                                                                                                 |
| 8 Nest deployables + admin-portal                     | IMPLEMENTED                                                                                                                                                 | `apps/*/src/app.module.ts`, `app.module.test.ts` per app; `services.test.ts` (readiness checks per service)                                                      |
| MySQL primary + replica, GTID replication             | IMPLEMENTED                                                                                                                                                 | `docker-compose.yml`; `replication.test.ts`                                                                                                                      |
| `api` reads from the replica                          | IMPLEMENTED                                                                                                                                                 | `PrismaReadService` (`prisma-read.service.test.ts`); no feature module reads from it yet                                                                         |
| RabbitMQ topology v1 (vhost, 6 exchanges, 14 queues)  | IMPLEMENTED 3.2                                                                                                                                             | `packages/event-contracts/src/topology.ts`, `infrastructure/rabbitmq/{definitions.json,init.mjs}`; `messaging-topology.test.ts`, `messaging-permissions.test.ts` |
| Redis, MinIO                                          | IMPLEMENTED                                                                                                                                                 | `rabbitmq-redis.test.ts` (auth, TTL), `storage.test.ts` (buckets, tenant-prefixed key, anonymous denied)                                                         |
| OpenSearch, ClickHouse containers                     | IMPLEMENTED                                                                                                                                                 | Compose `analytics` profile, validated by `docker compose config` in CI. Not exercised by tests                                                                  |
| Observability containers, OTLP export                 | IMPLEMENTED                                                                                                                                                 | Compose `observability` profile, `packages/logger/src/tracing.ts`. Validated by `docker compose config`; no runtime test                                         |
| LMTP ingestion, S3 write, ingestion transaction       | IMPLEMENTED                                                                                                                                                 | `apps/smtp-adapter/src/{lmtp,ingestion}`; `smtp-inbound.test.ts`, `smtp-durability.test.ts`, `smtp-concurrency.test.ts`                                          |
| Bounce notices → bounce_events, suppressions          | IMPLEMENTED                                                                                                                                                 | `apps/smtp-adapter/src/bounces`; `bounces.test.ts`, `smtp-outbound.test.ts`                                                                                      |
| MIME parsing (headers, attachments rows)              | IMPLEMENTED                                                                                                                                                 | step 3.1: email-worker `MimeIngestionModule`, consuming `email.received` since 3.2; `mime-ingestion.test.ts`                                                     |
| event-relay (outbox relay, reconciler)                | IMPLEMENTED 3.2                                                                                                                                             | `apps/event-relay`; relay/reconciler integration suites, `services.test.ts`, `messaging-*.test.ts` stack suites                                                  |
| Consumers email-worker, delivery-worker               | IMPLEMENTED 3.2                                                                                                                                             | `QueueConsumer` on `email.received` / `email.delivery.pending`; worker integration suites, `messaging-*.test.ts`                                                 |
| Dead-letter view and replay (api)                     | IMPLEMENTED 3.2                                                                                                                                             | `apps/api/src/modules/dead-letters`; `dead-letters.test.ts`, `messaging-replay.test.ts`                                                                          |
| Scan consumers (rspamd, attachment, url)              | IMPLEMENTED 4.1–4.3                                                                                                                                         | email-worker scan role; `scan-*`, `attachment-*`, `url-*` stack suites                                                                                           |
| click-service, url-browser-worker, url-egress-proxy   | IMPLEMENTED 4.3                                                                                                                                             | `apps/click-service`, `apps/url-browser-worker`; click-service unit/e2e/integration, the browser container suite (profile `url-browser`), `url-smtp.test.ts`     |
| Consumers policy-engine, notification (5.2); archive  | IMPLEMENTED 5.2 (policy-engine on `email.policy.evaluate`, notification-worker on `email.notifications`: `policy-smtp.test.ts`); archive-worker PLANNED 8.1 | `email.archive` stays dormant until 8.1                                                                                                                          |
| OpenSearch and ClickHouse feeds                       | PLANNED                                                                                                                                                     | ADR-0009. **No execution-plan step owns them yet** (reported as an open item)                                                                                    |
