# Architecture diagrams

Fifteen Mermaid diagrams describe the gateway from system context down to message states, failure handling, isolation and the AWS regions. GitHub renders them inline. They are written against the repository as it is on branch `build/platform` (mail-path diagrams updated for step 2.2). Where a diagram shows something that does not exist yet, it says so and names the step in [`docs/plan/execution-plan.md`](../../plan/execution-plan.md) that delivers it.

## Status convention

Every component and every arrow is labelled as one of two states:

| Status          | Meaning                                                                                                                                                                                               | Flowchart / state diagram                         | Sequence diagram                                                       |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------- |
| **IMPLEMENTED** | Exists in this repository and is exercised by a unit, e2e or integration test, or by a CI validation step (`docker compose config`, `kubectl kustomize`, `terraform validate`). The evidence is named | Green box, **solid** border, solid arrow `-->`    | Plain participant and message                                          |
| **PLANNED x.y** | Designed (ADRs, step design notes) but not built. `x.y` is the execution-plan step that delivers it                                                                                                   | Amber box, **dashed** border, dotted arrow `-.->` | Participant named `... (PLANNED x.y)`, messages inside a shaded `rect` |
| external        | Not built by this project (senders, tenants' mail systems, DNS, AWS services we only consume)                                                                                                         | Grey box                                          | Plain participant                                                      |

The colour is never the only signal. Every planned element also carries the text `PLANNED x.y` (or `P x.y` on short arrow labels), so the diagrams read correctly in monochrome and for colour-blind readers. Each diagram is followed by a legend and a status table that lists the evidence (file or test) for every IMPLEMENTED element.

The class definitions shared by every flowchart:

```text
classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b
```

## Index

| #   | Diagram                                                         | Type             | Contains PLANNED elements                                                                             |
| --- | --------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------- |
| 1   | [System context](01-system-context.md)                          | flowchart (C4-1) | Yes: M365/Google connectors (8.2), notifications (6.2), threat feeds, AWS (10.1)                      |
| 2   | [Container architecture](02-containers.md)                      | flowchart (C4-2) | Yes: outbox relay (3.2), all consumers (3.x–8.x), OpenSearch/ClickHouse feeds                         |
| 3   | [Component architecture](03-components.md)                      | flowchart        | Yes: every business module (1.2–8.3)                                                                  |
| 4   | [SaaS deployment](04-deployment-saas.md)                        | flowchart        | Yes: EKS cluster, ALB, Postfix ASG, managed data stores (10.1)                                        |
| 5   | [Dedicated deployment](05-deployment-dedicated.md)              | flowchart        | Yes: per-customer account/VPC provisioning (8.3, 10.1)                                                |
| 6   | [Inbound SMTP sequence](06-inbound-smtp-sequence.md)            | sequence         | Yes: MIME parsing (3.1), outbox relay (3.2)                                                           |
| 7   | [Outbound SMTP sequence](07-outbound-smtp-sequence.md)          | sequence         | Yes: scanning and policy (4.x, 5.2), delivery-worker (2.3); the SMTP path itself is implemented (2.2) |
| 8   | [Internal email inspection](08-internal-inspection-sequence.md) | sequence + flow  | Yes, entirely (2.3, 8.2)                                                                              |
| 9   | [Email scanning sequence](09-scanning-sequence.md)              | sequence         | Yes: consumer and engine adapters (4.1–4.6, 5.1). Contract, queue and daemons are implemented         |
| 10  | [Quarantine and release](10-quarantine-release-sequence.md)     | sequence         | Yes, entirely (5.2, 5.3, 6.1, 1.3). Tables are implemented                                            |
| 11  | [Message state machine](11-message-state-machine.md)            | stateDiagram-v2  | Yes: every transition (3.3). The status enum is implemented                                           |
| 12  | [Failure handling](12-failure-handling.md)                      | flowchart        | Yes: ingestion 4xx, outbox relay, consumers, replay and reconciliation (3.x), alerts (10.3)           |
| 13  | [Multi-tenant isolation](13-multi-tenant-isolation.md)          | flowchart        | Yes: key-prefix equality check (3.x), API rate limits (6.1)                                           |
| 14  | [AWS Mumbai (ap-south-1) production](14-aws-mumbai.md)          | flowchart        | Yes: everything except the S3 + KMS Terraform module (10.1)                                           |
| 15  | [Hyderabad (ap-south-2) DR](15-dr-hyderabad.md)                 | flowchart        | Yes, entirely (10.2)                                                                                  |

**Every diagram contains PLANNED elements.** Diagrams 7, 8, 10 and 15 are entirely planned (apart from the tables and contracts they rely on), which reflects the state of the product: Phase 0 plus the step 1.1 database.

## What is implemented today (summary)

| Area             | Implemented and tested                                                                                                                                                                                                                                                                                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mail edge        | Postfix inbound MX (relay denial `554`, STARTTLS, size limit), Postfix policy delegation to `smtp-adapter` (answers `DUNNO`, fails closed to `4xx`), Rspamd milter configured with `milter_default_action = tempfail`. Accepted mail is **discarded** locally (`relay_transport = discard`) until LMTP ingestion exists (`infrastructure/postfix/entrypoint.sh`)    |
| Engines          | Rspamd (`/checkv2` returns a verdict) and ClamAV (EICAR detected) run as daemons and are tested directly (`tests/integration/mail-plane.test.ts`). No Node adapter calls them yet                                                                                                                                                                                   |
| Services         | 8 deployables boot, validate config, connect to their dependencies, expose `/health/live` and `/health/ready`, and the 5 workers assert their RabbitMQ topology. The API serves `/v1/meta`. No consumer or business endpoint exists                                                                                                                                 |
| Data             | 61-table MySQL schema with 16 partitioned tables (`tests/integration/schema.test.ts`), GTID primary + replica, reader account and `PrismaReadService` writer fallback (`tests/integration/replication.test.ts`, `prisma-read.service.test.ts`), `processOnce` on `message_idempotency` (`tests/integration/mysql.test.ts`), MinIO buckets with tenant-prefixed keys |
| Contracts        | Event envelope and three event payloads with decimal ids and `org/{organizationId}/` keys, RabbitMQ topology as data, security-engine contract (`packages/event-contracts`, `packages/security-contracts`)                                                                                                                                                          |
| Deploy artefacts | Compose stack, Kustomize base + `saas`/`dedicated` overlays (rendered in CI), Terraform S3 + KMS module (`terraform validate` in CI, never applied)                                                                                                                                                                                                                 |

## Related documents

- [Architecture overview](../overview.md)
- [Inter-service contracts](../contracts.md)
- [Data ownership](../data-ownership.md)
- [Security boundaries](../security-boundaries.md)
- [Failure handling](../failure-handling.md)
- [ADRs](../adr/README.md)
