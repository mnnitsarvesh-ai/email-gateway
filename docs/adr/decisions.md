# Architecture Decision Records

Owner and approver: Sarvesh. Statuses are `Proposed`, `Accepted`, `Superseded by ADR-NNN` and `Rejected`. To change an Accepted decision, add a new ADR that supersedes it. Never edit an Accepted ADR in place.

## Index

| ADR | Title | Status |
|---|---|---|
| ADR-001 | Postfix as the MTA, on an EC2 ASG with EBS spool | Accepted |
| ADR-002 | Rspamd for spam filtering, as both milter and post-queue worker | Accepted |
| ADR-003 | ClamAV for antivirus scanning | Accepted |
| ADR-004 | YARA for custom content and attachment rules | Accepted |
| ADR-005 | Node.js 24 LTS and TypeScript (strict) for all services | Accepted |
| ADR-006 | pnpm and Turborepo monorepo; services import only from `packages/` | Accepted |
| ADR-007 | RabbitMQ with quorum queues, publisher confirms and manual acks; no Kafka | Accepted |
| ADR-008 | MySQL 8.4: one writer plus read replicas | Accepted |
| ADR-009 | Redis for caches, rate limits and ephemeral state only | Accepted |
| ADR-010 | S3 for EML, attachments and archive storage; queues carry keys, not bodies | Accepted |
| ADR-011 | OpenSearch for message trace and search | Accepted |
| ADR-012 | ClickHouse for event history and analytics, not MySQL | Accepted |
| ADR-013 | Next.js for the admin and end-user portal | Accepted |
| ADR-014 | Terraform, EKS, Helm and ArgoCD for infra and delivery | Accepted |
| ADR-015 | zod, pino and vitest as standard libraries; swaks for SMTP tests; EICAR only | Accepted |
| ADR-016 | dbmate for MySQL migrations, forward-only | Accepted |
| ADR-017 | Multi-tenancy: `organization_id` on every tenant table; tenant never from headers | Accepted |
| ADR-018 | SaaS and dedicated deployments from one codebase, differing only by config | Accepted |
| ADR-019 | Writer-only data plane; replicas for control-plane reads only | Accepted |
| ADR-020 | Split between pre-queue (in-session) and post-queue processing | Accepted |
| ADR-021 | LMTP handoff from Postfix to ingest-service | Accepted |
| ADR-022 | Postfix owns delivery retries | Accepted |
| ADR-023 | Transactional outbox, idempotent consumers and fail-safe engine states | Accepted |
| ADR-024 | Amazon MQ vs self-managed RabbitMQ | Proposed |
| ADR-025 | Aurora MySQL vs RDS MySQL | Proposed |
| ADR-026 | Partitioned per-message tables plus a non-partitioned message identity table | Proposed |
| ADR-027 | UUIDv7 identifiers and tenant-first S3 key layout | Proposed |

Region baseline for all ADRs: primary is AWS ap-south-1 (Mumbai) and DR is ap-south-2 (Hyderabad).

---

## ADR-020: Split between pre-queue (in-session) and post-queue processing

**Status:** Accepted

**Context.** A gateway can reject mail during the SMTP session or after accepting it. Rejecting during the session is cheap and creates no backscatter, but every check adds latency while the client waits. At 300 msg/s, a slow engine such as ClamAV or a large attachment would hold connections open and exhaust Postfix process limits. Rejecting after acceptance means generating an NDR, which is backscatter to forged senders and can get our IPs listed.

**Decision.** In-session checks are limited to fast work: `policy-adapter` through `check_policy_service` (recipient validation, tenant resolution, rate limits, sender reputation) and Rspamd as a milter. These are the only components that may reject or defer. Heavy scanning (ClamAV, YARA, Rspamd in full) runs post-queue. Post-queue outcomes are `deliver`, `tag`, `quarantine` and `discard`. The pipeline never bounces.

**Consequences.**
- No policy backscatter. Our sending IPs stay off blocklists because of rejections.
- Mail that is malicious but passes in-session checks is accepted, then quarantined or discarded. Senders get no signal, which is intended.
- In-session components need tight latency budgets and must fail to `4xx` (tempfail), never to accept-all or reject-all.
- `discard` must always be audited (ClickHouse event plus a quarantine/trace record), because the sender is never told.

---

## ADR-021: LMTP handoff from Postfix to ingest-service

**Status:** Accepted

**Context.** After Postfix queues a message, it needs to hand it to our pipeline in a way that is acknowledged and retryable. The options considered were a content filter over SMTP, a pipe to a command, and LMTP. A pipe runs a process per message and its error semantics are weak. SMTP works but has no per-recipient status.

**Decision.** Postfix delivers to `ingest-service` over LMTP. `ingest-service` streams the EML to S3, then commits the `messages`, `message_recipients` and `outbox` rows in one MySQL writer transaction. It replies `250` per recipient only after the commit. Any failure replies `4xx`.

**Consequences.**
- Postfix's EBS spool stays the durable buffer until we hold the message. A crash, an S3 outage or a DB outage leaves mail queued in Postfix, not lost.
- Per-recipient LMTP replies allow partial acceptance, for example when one recipient's tenant is suspended.
- `ingest-service` must be idempotent on retry. A 250 lost in transit makes Postfix redeliver, so ingest dedupes using the queue ID and message fingerprint.
- Ingest throughput is bounded by writer transaction rate. At 300 msg/s this is well within one MySQL writer, but keep the transaction small: no event history in it (see ADR-012).

---

## ADR-022: Postfix owns delivery retries

**Status:** Accepted

**Context.** After the policy decision, mail has to reach the next hop: a tenant's mail server for inbound mail, the internet for outbound. Delivery needs MX lookup, TLS policy, per-destination concurrency, backoff, queue lifetime and RFC-compliant DSNs. Postfix already handles all of this well. Rebuilding it in Node would be a large, risky job.

**Decision.** `delivery-service` reinjects approved mail into a dedicated Postfix outbound instance over SMTP and records the handoff. Once Postfix accepts the mail, Postfix owns all retries, deferrals, queue lifetime and delivery DSNs. Our services never schedule delivery retries.

**Consequences.**
- No retry scheduler in our code. Delivery state comes from Postfix logs, which we parse into ClickHouse events.
- Outbound Postfix also needs EBS spool and ASG sizing. Tenant-server outages are absorbed by the outbound queue, so set `maximal_queue_lifetime` with that in mind.
- Delivery DSNs that Postfix generates are not policy bounces, so they don't conflict with ADR-020. Their wording and envelope still need review so they don't leak scan details.
- Reinjection is at-least-once. `delivery-service` records the handoff under its idempotency key before acking, so a repeat attempt is a no-op.

---

## ADR-024: Amazon MQ vs self-managed RabbitMQ

**Status:** Proposed

Open question: should we run RabbitMQ on Amazon MQ (managed, though its quorum-queue support, version lag and limits need checking) or self-manage it on EKS or EC2 (full control, with operational burden and DR in Hyderabad to handle ourselves)? The decision must keep quorum queues, publisher confirms and manual acks (ADR-007). Owner: architect. Approver: Sarvesh.

## ADR-025: Aurora MySQL vs RDS MySQL

**Status:** Proposed

Open question: Aurora MySQL (fast failover, storage-level replication, Global Database for Hyderabad DR, but MySQL 8.4 version availability needs checking) or RDS for MySQL 8.4 (exact version match, cross-region read replica for DR, slower failover)? The decision must keep a single writer for the data plane (ADR-019). Owner: architect. Approver: Sarvesh.

## ADR-026: Partitioned per-message tables plus a non-partitioned message identity table

**Status:** Proposed

**Context.** At 1M messages a day, `email_messages` grows by about 30M rows a month, and `message_recipients`, `scans` and `deliveries` grow several times faster. Deleting rows for retention at that scale is slow and puts load on the writer that the data plane depends on (ADR-019). MySQL range partitioning lets retention drop whole partitions, but it has two limits: partitioned tables cannot have foreign keys, and every unique key, including the primary key, must contain the partition column. That would stop us enforcing global uniqueness of `message_uuid` or the LMTP-retry dedupe key (ADR-021) on the partitioned tables themselves.

**Decision.**
- `email_messages`, `message_recipients`, `scans` and `deliveries` are partitioned by `RANGE COLUMNS(received_at)`, one partition per month, plus a `pmax` catch-all. Their keys include `received_at`.
- A non-partitioned `message_identity` table (`message_uuid` PK, `organization_id`, `received_at`, UNIQUE(`organization_id`, `dedupe_key`)) holds global identity and the LMTP-retry dedupe key. Ingest inserts it first, inside the same writer transaction as the message, recipients and outbox rows.
- Non-partitioned tables that need referential integrity, such as `quarantine`, reference `message_identity`.
- Queue payloads carry `received_at` so consumers can address partitioned rows by their full key.

**Consequences.**
- Retention drops partitions instead of deleting rows. `message_identity` still needs a batched purge.
- Integrity between partitioned tables is the application's job: one writer transaction, plus tests.
- A partition maintenance job and an alert are required (Phase 1). The `pmax` catch-all means a missing partition can never cause ingest `4xx`.
- The DDL stays compatible with MySQL 8.0 and 8.4 until ADR-025 is decided.

## ADR-027: UUIDv7 identifiers and tenant-first S3 key layout

**Status:** Proposed

**Context.** Ids appear in MySQL keys, queue payloads, idempotency keys, S3 keys, logs and portal URLs. Auto-increment ids can be enumerated, and they collide between SaaS and dedicated deployments. Random UUIDv4 primary keys fragment InnoDB indexes. S3 keys need a layout that supports per-tenant lifecycle, export, deletion and IAM prefix conditions, and that lets a worker check that a key belongs to the tenant named in the payload.

**Decision.**
- `organization_id`, `message_uuid` and other entity ids are UUIDv7. They are stored as `BINARY(16)` in MySQL with no byte swap, and carried as canonical lowercase strings everywhere else. `outbox.id` and `audit_logs.id` stay `BIGINT AUTO_INCREMENT` for ordering.
- S3 keys are tenant-first, and only `packages/s3` builds them:
  - `org/{organization_id}/eml/{yyyy}/{mm}/{dd}/{message_uuid}.eml`
  - `org/{organization_id}/part/{yyyy}/{mm}/{dd}/{message_uuid}/{part_index}.bin`
  - in the archive bucket, `org/{organization_id}/archive/{yyyy}/{mm}/{dd}/{message_uuid}.eml`
- Every S3 read checks that the key's `org/` prefix matches the `organization_id` in the payload.

**Consequences.**
- Ids are time-ordered, which keeps InnoDB inserts mostly appending. They aren't enumerable, and they are unique across deployments.
- Per-tenant S3 operations become prefix operations.
- Ids leak their creation time to the minute. That is acceptable, because `received_at` is already shown to tenants.

