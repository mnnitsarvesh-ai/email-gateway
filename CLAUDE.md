# CLAUDE.md — Email Security Gateway

A multi-tenant Email Security Gateway, comparable to Zoho eProtect. It scans inbound, outbound and internal mail, and can archive mail for tenants that turn archiving on. One codebase ships as both shared SaaS and dedicated single-tenant deployments.

Read this file before every task. Architecture decisions are in [docs/adr/decisions.md](docs/adr/decisions.md). If a rule here conflicts with an Accepted ADR, stop and ask Sarvesh. Don't pick one yourself.

## Sizing and topology

| Item | Target |
|---|---|
| Volume | 1M emails/day (about 12 msg/s on average) |
| Burst | 300 msg/s sustained, end to end |
| Primary region | AWS ap-south-1 (Mumbai) |
| DR region | AWS ap-south-2 (Hyderabad) |
| Deployment modes | Shared SaaS (many tenants) and dedicated (one tenant). Same code, different Helm values and Terraform vars |

Deployment modes are configuration, not code. Never write branches like `if (deploymentMode === 'dedicated')` or `if (orgId === ...)` in business logic. Put the difference in config or in tenant policy.

## Stack

- **MTA:** Postfix on an EC2 Auto Scaling Group with EBS-backed spool. Separate inbound and outbound instances.
- **In-session filtering:** Rspamd (milter) and our `policy-adapter` (Postfix `check_policy_service`).
- **Scanning:** ClamAV and YARA, plus Rspamd in post-queue workers.
- **Services:** Node.js 24 LTS and TypeScript in `strict` mode. zod validates every external input and every message payload. pino for logging. vitest for tests.
- **Monorepo:** pnpm workspaces and Turborepo.
- **Messaging:** RabbitMQ with quorum queues, publisher confirms and manual acks. No Kafka.
- **Database:** MySQL 8.4 with one writer and read replicas. dbmate for migrations.
- **Cache and ephemeral state:** Redis. Never the source of truth.
- **Object storage:** S3 holds EML bodies, attachments and archive copies.
- **Search:** OpenSearch, for message trace and search in the portal.
- **Event history and analytics:** ClickHouse.
- **Portal:** Next.js.
- **Infra:** Terraform for AWS, EKS, Helm and ArgoCD (GitOps).
- **SMTP testing:** swaks.

## Core design: the mail path

This design underlies everything else. Don't change it without a new ADR.

```
            ┌──────────────────── IN-SESSION (pre-queue) ────────────────────┐
 sender ──► │ Postfix inbound ── check_policy_service ──► policy-adapter      │
            │                 └─ milter ───────────────► Rspamd              │
            │   only these two may REJECT (5xx) or DEFER (4xx)               │
            └───────────────┬────────────────────────────────────────────────┘
                            │ queued on EBS spool
                            ▼ LMTP
                     ingest-service ── stream EML ──► S3
                            │  one writer txn: message + recipients + outbox row
                            │  250 only after COMMIT, 4xx on any failure
                            ▼
                     outbox-publisher ──► RabbitMQ (IDs + S3 keys only)
                            ▼
                     scan workers (clamav, yara, rspamd, …)
                            ▼
                     aggregator ──► policy-engine
                            ▼
              deliver │ tag │ quarantine │ discard      (never bounce)
                            ▼
                     delivery-service ──► Postfix outbound ──► next hop
                                          (Postfix owns retries)
```

1. **Inbound Postfix runs in-session checks only.** It calls `policy-adapter` through `check_policy_service` and Rspamd as a milter. These two are the only components allowed to reject. A reject during the SMTP session doesn't create backscatter.
2. **Postfix queues the message, then hands it to `ingest-service` over LMTP.**
3. **`ingest-service`** streams the EML to S3, never buffering the whole message in memory. It then writes the `messages` row, the `message_recipients` rows and an `outbox` row in **one MySQL writer transaction**. It returns `250` only after the transaction commits. Any failure, whether S3, the DB, a timeout or validation, returns `4xx` so Postfix keeps the message and retries.
4. **`outbox-publisher`** reads committed outbox rows and publishes them to RabbitMQ with publisher confirms. **Scan workers** consume the messages, fetch the EML from S3 and record verdicts. The **aggregator** waits until every required stage reports or times out, then hands off to **`policy-engine`**.
5. **Post-queue decisions** are `deliver`, `tag`, `quarantine` or `discard`. **The pipeline never bounces.** Once Postfix has said 250, policy never produces an NDR. `discard` is silent to the sender and always audited.
6. **`delivery-service`** reinjects the mail into a **Postfix outbound** instance. From then on, Postfix owns retries, backoff, queue lifetime and DSNs. Don't build a retry scheduler in Node.

**Direction (inbound, outbound or internal)** comes from the listener or connector the mail arrived on and from the tenant's verified domains. Inbound mail arrives on the MX listener. Outbound mail arrives on a registered tenant connector, identified by source IP, SMTP AUTH or client cert. Internal mail is outbound-connector mail whose recipient is in the same tenant's verified domains. Headers never decide direction.

**Archiving** is a per-tenant setting. When it's on, `policy-engine` writes an archive record and an archive S3 copy whatever the delivery decision was. When it's off, nothing is archived. Never archive by default.

## Hard rules

Breaking any of these blocks a merge. If a task seems to need breaking one, stop and ask Sarvesh.

1. **Never 250 before durable persist.** A `250` means the EML is in S3 and the writer transaction has committed. Every error path returns `4xx`.
2. **The data plane uses the MySQL writer only.** Ingest, scan, aggregation, policy and delivery read and write through the writer connection. Read replicas are only for control-plane reads such as portal lists, reports and dashboards. Replica lag must never affect a mail decision.
3. **Queues carry IDs and S3 keys only, never EML.** No message bodies, attachments or base64 blobs in RabbitMQ payloads. Workers fetch from S3.
4. **Tenant identity never comes from message headers.** Not from `From`, `To`, `X-*` or anything else a sender controls. Resolve it from the connector or listener plus the verified-domain lookup, and carry it as `organization_id` from then on.
5. **Engines never report `clean` on failure.** The only valid engine states are `clean`, `suspicious`, `malicious`, `unknown`, `timeout`, `error` and `not_scanned`. A crash, timeout, oversize skip or parse failure must map to `timeout`, `error` or `not_scanned`. Tenant policy decides what happens next. Engine code never does.
6. **Consumers are idempotent.** The idempotency key is `tenant_id:message_uuid:stage:stage_version`, where `tenant_id` is the `organization_id` value. Redelivery must be a no-op. Ack only after the side effect is durable.
7. **Every tenant-scoped table has `organization_id`.** It is `NOT NULL`, indexed, and in every query's `WHERE` clause. A query on a tenant table without it is a bug.
8. **Services import only from `packages/`, never from each other.** Shared types, schemas and clients belong in a package. Turborepo and lint config enforce this boundary.
9. **No secrets in git.** No keys, passwords, DKIM private keys, tokens or real `.env` files. Use AWS Secrets Manager or SSM in the cloud and gitignored `.env.local` for local dev. Commit `.env.example` with placeholders only.
10. **Agents never run** `terraform apply` (or `destroy`), `kubectl` against any cloud cluster, the `aws` CLI, or `git push`. `terraform plan` against local or mocked backends, `kubectl` against a local kind or k3d cluster, and local commits in a worktree are fine.
11. **Event history goes to ClickHouse, not MySQL.** Per-message stage events, verdict history and delivery attempts are append-only ClickHouse rows. MySQL holds current state only.
12. **Malware tests use EICAR only.** Never commit, download or generate real malware samples, not even zipped or password-protected.

## Repo layout

```
services/            deployable apps, one per directory
  policy-adapter/      Postfix check_policy_service (in-session)
  ingest-service/      LMTP server → S3 + writer txn
  outbox-publisher/    outbox → RabbitMQ
  scan-clamav/         scan workers (one per engine)
  scan-yara/
  scan-rspamd/
  aggregator/          collects stage verdicts
  policy-engine/       deliver | tag | quarantine | discard
  delivery-service/    reinject into Postfix outbound
  api/                 control-plane API
  portal/              Next.js admin and end-user portal
packages/            shared libraries (the only thing services import)
  config/  db/  mq/  s3/  schemas/  logger/  idempotency/  tenancy/  testing/
postfix/             Postfix main.cf/master.cf templates, inbound and outbound
infra/terraform/     AWS: VPC, EKS, EC2 ASG for Postfix, RDS, MQ, S3, OpenSearch, ClickHouse
infra/helm/          charts and per-deployment values (saas, dedicated-<name>)
deploy/local/        docker compose for local dev (Postfix, Rspamd, ClamAV, RabbitMQ,
                     MySQL, Redis, MinIO, OpenSearch, ClickHouse)
db/migrations/       dbmate migrations (MySQL)
test/e2e/            end-to-end tests against deploy/local (opt-in: pnpm test:e2e)
tooling/             build and lint tooling (workspaces, @esg/*)
  eslint-config/       shared flat ESLint config; boundary + control-plane rules
  workspace-guard/     fails on package.json deps from/onto services
  lint-fixtures/       deliberately bad fixtures + vitest proving lint/TS rules
  repo-checks/         repo-level checks (CI, gitignore, CLAUDE.md commands, pins)
docs/                ADRs, runbooks, design notes
  adr/decisions.md
```

When a new service or package is added, update this tree.

## Commands

Requires Node 24 (`.node-version`) and the pinned pnpm (`packageManager`). Commands naming a service that doesn't exist yet (`--filter=ingest-service`) are exempt from the repo-checks command test.

```sh
pnpm install
pnpm turbo run build lint typecheck test       # all must pass before review
pnpm turbo run test --filter=ingest-service    # one service
pnpm test:e2e                                  # opt-in, uncached; needs deploy/local up
docker compose -f deploy/local/compose.yaml up -d
pnpm dbmate up                                 # local MySQL only
swaks --server localhost:2525 --to user@tenant-a.test --from x@ext.test   # inbound smoke test
```

## Coding conventions

- TypeScript `strict`. No `any` and no unexplained `as` casts. Parse at the boundary with zod and trust the type inside.
- Log with pino as structured JSON. Include `organization_id`, `message_uuid` and `stage` on every pipeline log line. Never log message bodies, attachment content or credentials.
- Every MySQL schema change is a dbmate migration in `db/migrations/`. Migrations are forward-only and safe to run online.
- Every RabbitMQ consumer uses manual acks, a bounded prefetch and a dead-letter queue. Every publisher uses confirms.
- Tests use vitest. Test pipeline behaviour end to end with swaks against `deploy/local`.

## Task workflow

Sarvesh is the product owner and final approver. There is no human product or QA team, so each agent role must do its own job fully.

1. **product-owner** writes the task: problem, acceptance criteria, out of scope. Sarvesh confirms it.
2. **architect** checks the task against this file and the ADRs. It names the affected services and packages, schema and queue changes, and any new ADR needed. If an Accepted ADR has to change, it stops and asks Sarvesh.
3. **implementer** works in its own git worktree on a feature branch. It commits locally and never pushes.
4. **qa-engineer** writes and runs tests against the acceptance criteria. That includes failure paths (4xx on S3 or DB failure, engine timeout → not `clean`, redelivery → no-op) and swaks scenarios.
5. **code-reviewer** and **security-reviewer** review in parallel. The code reviewer checks correctness, the hard rules and conventions. The security reviewer checks tenant isolation, secrets, injection, header trust and the malware-handling rules.
6. **Sarvesh merges.** No agent merges or pushes.

Any step can send the task back to an earlier step. Record the reason in the task.

## Definition of done

A task is done when all of these hold:

- [ ] Every acceptance criterion is met and has a test.
- [ ] `pnpm turbo run build lint typecheck test` passes.
- [ ] No hard rule is broken: 250 only after commit, writer-only data plane, no EML in queues, no header-derived tenant, no clean-on-failure, idempotent consumers, `organization_id` present, no cross-service imports, no secrets, EICAR only.
- [ ] Failure paths are tested, not just the happy path.
- [ ] Schema changes ship as dbmate migrations. Queue or payload changes update the zod schemas in `packages/schemas`.
- [ ] Logs, metrics and ClickHouse events exist for any new pipeline stage.
- [ ] Docs are updated: this file (layout or commands), ADRs if a decision changed, runbook if ops changed.
- [ ] code-reviewer and security-reviewer have both approved.
- [ ] Sarvesh has approved and merged.
