# Roadmap: Email Security Gateway

Owner: architect. Approver: Sarvesh. Status: **Draft**, waiting for Sarvesh's review.

This roadmap follows [CLAUDE.md](../../CLAUDE.md) and the Accepted ADRs in [docs/adr/decisions.md](../adr/decisions.md). If it ever conflicts with them, they win.

- **Length:** 26 weeks. Week 1 starts Monday 2 November 2026, so week 26 ends around Friday 30 April 2027.
- **Regions:** primary ap-south-1 (Mumbai), DR ap-south-2 (Hyderabad).
- **Deployment modes:** shared SaaS and dedicated, from one codebase. Every exit criterion must hold in both modes unless it names one.
- **Exit criteria** are checked by qa-engineer against `deploy/local`, and from Phase 3 also against the AWS environment. Each one has to be shown with a test, a swaks transcript, a DB, S3 or ClickHouse query, or a dashboard screenshot linked from `docs/qa/`.

## At a glance

| Phase | Weeks | Goal | Needs AWS? |
|---|---|---|---|
| 0 Foundations | 1–3 | Repo, contracts, local stack, schema v1, threat model, e2e harness | No (Terraform plan against mocks only) |
| 1 Inbound core | 4–7 | Receive → persist → deliver end to end, with no scanning | No |
| 2 Security core | 8–12 | ClamAV, YARA and Rspamd workers, aggregator, policy-engine, quarantine | No (AWS infra track starts in parallel) |
| 3 Portal + outbound, dogfood | 13–16 | Portal, outbound path, Threatcop's own domain live through the gateway | **Yes**, first real environment |
| 4 Internal + advanced detection | 17–20 | Internal mail, URL analysis, DLP, risk scorer | Yes |
| 5 Enterprise | 21–23 | Per-tenant archiving, SSO/SCIM, webhooks | Yes |
| 6 Scale, DR, go-live | 24–26 | 300 msg/s sustained, DR drill to Hyderabad, dedicated profile, go-live | Yes, including DR region |

### Infra track (runs alongside Phases 1–3)

devops-engineer builds the real Terraform modules and Helm charts from week 6, but only `fmt`, `validate`, `terraform test` with mock providers, and `plan` against local or mocked backends. Sarvesh runs every `apply`. The first apply, a staging/dogfood environment in ap-south-1, is planned for **week 12**, so Phase 3 can start on real infrastructure in week 13.

### What ADR-024 and ADR-025 block

- **They block Phase 3, not Phases 0–2.** In Phases 0–2 the services talk to RabbitMQ over AMQP 0-9-1 and to MySQL over the MySQL protocol. Both work the same whether the server is Amazon MQ or self-managed RabbitMQ, and Aurora or RDS. Local development uses the containers in `deploy/local`.
- The `mysql` and `rabbitmq` Terraform modules can't move past skeletons (task 010) until the ADRs are decided, and Phase 3 needs those modules applied. **Both ADRs need a decision by the end of week 10**, so the modules can be finished in weeks 10–11 and applied in week 12.
- Phase 6's DR drill depends on the same choices: Aurora Global Database vs an RDS cross-region read replica, and how RabbitMQ runs in DR.
- Until ADR-025 is decided, all DDL must work on both MySQL 8.0 (Aurora MySQL v3 compatibility) and 8.4. Until ADR-024 is decided, `packages/mq` uses only features both brokers support: quorum queues, `x-delivery-limit`, dead-letter exchanges and publisher confirms. No stream queues and no extra plugins.

---

## Phase 0: Foundations (weeks 1–3)

**Goal.** Put in place everything an implementer needs to build pipeline services safely: the monorepo and CI, shared contracts, the local stack, schema v1, the threat model and the e2e harness. **No pipeline service code is written in this phase.**

**Scope**
- Monorepo scaffold, plus CI that fails on cross-service imports (task 001).
- Shared contracts: ids, the event envelope, the scan contract and idempotency keys (002).
- Local docker compose stack, including a MySQL writer with a real GTID replica and Mailpit standing in for the customer's downstream server (003).
- Baseline Postfix inbound and outbound config, plus Rspamd milter wiring, with proof that there is no open relay (004).
- dbmate migrations v1 (005).
- Shared packages: `config` and `logger` (006), `db` (007), `mq` (008) and `s3` (009).
- Terraform module skeletons for saas and dedicated, primary and DR (010).
- STRIDE threat model (011).
- SMTP e2e harness and test corpus layout (012).
- Task files: `docs/tasks/001-*` to `012-*`.

**Exit criteria**
1. `pnpm install && pnpm turbo run build lint typecheck test` passes from a clean clone on Node 24, and the same pipeline passes in CI.
2. A fixture file in which one service imports from another fails `pnpm turbo run lint`. So does a fixture in which a data-plane service imports `@esg/db/control-plane`. Both fixtures are covered by a test.
3. `docker compose -f deploy/local/compose.yaml --profile mta up -d` brings every service to `healthy` within 5 minutes on a developer laptop. The replica reports `Replica_IO_Running=Yes` and `Replica_SQL_Running=Yes`, with GTID auto-position.
4. `pnpm dbmate up` against the local writer creates every v1 table. A schema test shows that every tenant table has `organization_id NOT NULL` with an index whose leftmost column is `organization_id`, and the same schema appears on the replica.
5. The open-relay swaks suite passes against local inbound Postfix: relay to an external domain is denied, and an unknown recipient at a tenant domain is rejected in-session.
6. The e2e harness runs `pnpm turbo run test:e2e` against `deploy/local` and passes its Phase 0 smoke specs: outbound reinjection reaches Mailpit, and inbound mail sits in the Postfix queue while `ingest-service` is absent.
7. `terraform fmt -check`, `terraform validate` and `terraform test` with mock providers pass for every module and env root in CI. No cloud credentials are present in CI.
8. `docs/threat-model.md` exists, with assets, trust boundaries and a STRIDE table that maps each mitigation to a hard rule or a task.
9. gitleaks, or the scanner chosen in task 001, runs in CI and reports zero findings.

## Phase 1: Inbound core (weeks 4–7)

**Goal.** Inbound mail flows end to end, receive → persist → deliver, with the full durability and idempotency machinery but **no scanning**. Every required engine stage reports `not_scanned` (reason `stage_not_enabled`), and the Phase 1 policy delivers. This proves the mail path from ADR-020 to ADR-023 before any detection exists.

**Scope**
- `policy-adapter`: tenant resolution from listener and verified domain, recipient validation and rate limits. On dependency failure it returns `4xx`.
- `ingest-service`: an LMTP server that streams EML to S3, then makes one writer transaction (message, recipients, outbox, identity/dedupe), and only then replies `250`. Per-recipient replies.
- `outbox-publisher`: publishes with confirms; RabbitMQ topology and DLQs.
- A placeholder stage worker that emits `not_scanned` for each required stage. This proves the aggregator's contract, and Phase 2 replaces it.
- `aggregator`, which waits for all required stages or a stage deadline. A missing stage becomes `timeout`, never `clean`.
- `policy-engine` with a fixed Phase 1 policy (`deliver`) and a recorded `policy_version`.
- `delivery-service`, which reinjects into Postfix outbound and records the handoff idempotently.
- ClickHouse added to `deploy/local`, with stage events written for every stage.
- Partition maintenance job and alert (see ADR-026).
- Prometheus metrics and Grafana dashboards for queue depth and age, ingest 4xx rate and Postfix queue size.

**Exit criteria**
1. swaks to `tenant-a.test` through local inbound Postfix arrives in Mailpit (tenant downstream). Exactly one `email_messages` row, one `message_identity` row and the matching `message_recipients` rows exist, along with an S3 object whose SHA-256 matches the delivered body before headers were added.
2. Every required stage has a `scans` row with state `not_scanned` and reason `stage_not_enabled`. No `scans` row anywhere has state `clean`.
3. With MinIO stopped, ingest replies `4xx` and no MySQL rows are written for that message. The message stays in the Postfix deferred queue, and once MinIO is back it is delivered exactly once.
4. With the MySQL writer stopped mid-transaction, ingest replies `4xx`, no partial rows remain, and after recovery the message is delivered exactly once.
5. Redelivering a scan result or policy message (same idempotency key) changes no rows and produces no second delivery handoff.
6. Zero-loss check: 10,000 uniquely tagged messages at 50 msg/s, while ingest, the RabbitMQ node and the MySQL writer are each restarted once. Every message that got `250` has a final decision and exactly one delivery handoff, with no losses and no duplicates.
7. A message to an unknown recipient at a tenant domain is rejected in-session with `550 5.1.1`. Relay to an external domain is denied. A message whose `From`/`To` headers name tenant B but whose envelope recipient is tenant A is stored under tenant A.
8. Every pipeline stage writes a ClickHouse event carrying `organization_id`, `message_uuid` and `stage`. MySQL has no history tables.
9. Grafana shows queue depth and age, ingest 4xx rate and Postfix queue size for the local stack.

## Phase 2: Security core (weeks 8–12)

**Goal.** Real detection. ClamAV, YARA and Rspamd run as post-queue workers. The aggregator collects their verdicts, `policy-engine` applies tenant policy, and quarantine holds mail that policy blocks.

**Scope**
- `scan-clamav`, `scan-yara` and `scan-rspamd` workers, with hostile-input limits (size, MIME depth and part count, archive ratio, depth and count, deadlines).
- Fail-safe state mapping: crash → `error`, deadline → `timeout`, limit or encrypted → `not_scanned`, each with a reason code.
- Rspamd in-session reject thresholds enabled. Only the milter and `policy-adapter` reject.
- Versioned tenant policy model (per-state actions, including `timeout`, `error` and `not_scanned`) and `policy-engine` decisions: `deliver`, `tag`, `quarantine` or `discard`. `discard` is always audited.
- Quarantine store: a row plus the existing S3 object, with a release and delete API in `services/api`. Release reinjects through `delivery-service`. The portal UI comes in Phase 3.
- Baseline detection metrics on the labelled corpus.
- Infra track: ADR-024 and ADR-025 decided by week 10. `mysql` and `rabbitmq` modules finished, and Sarvesh applies the staging environment in week 12.

**Exit criteria**
1. An EICAR message, sent as a plain attachment and again inside a zip, is quarantined. The `scans` row for `clamav` has state `malicious`, and the quarantine row lists the engine, the state and the policy rule.
2. With clamd stopped, killed mid-scan, or forced past its deadline, the ClamAV stage records `error` or `timeout`, never `clean`. The decision matches the tenant policy for that state.
3. A zip bomb fixture (ratio or depth over the limit) and a MIME fixture nested deeper than the limit each give `not_scanned` or `suspicious` with a reason code. The worker stays up, and its memory stays under the configured limit.
4. A message held in quarantine and released through the API is delivered to Mailpit exactly once. The release is in `audit_logs`, with the actor recorded.
5. A `discard` decision produces no NDR, no Mailpit delivery, and a ClickHouse audit event plus a trace record.
6. A corpus run reports detection rate and false-positive rate for each category. The numbers are written down as the Phase 2 baseline.
7. In-session, a Rspamd score above the reject threshold gives a `5xx` during the session. With Rspamd down, the session gets `4xx` (milter tempfail), never a silent accept.
8. Sarvesh has applied the staging Terraform for ap-south-1, and the applied environment passes `helm lint` and ArgoCD sync health checks.

## Phase 3: Portal + outbound; dogfood on Threatcop's domain (weeks 13–16)

**Goal.** Tenant admins and end users can see and act on their mail. Outbound mail flows through the gateway. **Threatcop's own domain runs on the gateway**, inbound and outbound, in ap-south-1.

**Scope**
- `services/api` control-plane routes: domains and verification, mail servers, policy, quarantine, and message trace. AuthZ checks tenant and role on every route. Replica reads, with `read({ fresh: true })` after writes.
- `services/portal` (Next.js): quarantine list and detail with block reasons, sandboxed previews, message trace, domain verification flow and policy editor.
- OpenSearch for trace and search, added to `deploy/local` and the AWS environment.
- Outbound: tenant connectors (registered IP, SMTP AUTH or client cert), outbound scanning, DKIM signing with keys from Secrets Manager, and per-tenant outbound rate limits.
- `connectors` table migration. Direction comes from listener or connector plus verified domains, never from headers.
- Dogfood cutover runbook with a rollback plan: low MX TTL and the previous MX kept documented.

**Exit criteria**
1. In the portal, a tenant-A admin sees only tenant-A messages. Asking the API for a tenant-B message or quarantine id returns `404`, with tests for every route.
2. Every quarantined, tagged and discarded message in the portal shows the decision, the contributing engines with their states (including `timeout`, `error` and `not_scanned`), the policy rule and the time.
3. Previews render in an iframe with `sandbox` set (no `allow-scripts`, no `allow-same-origin`) and a restrictive CSP. A test asserts the attributes.
4. Outbound mail from tenant A's registered connector is DKIM-signed, and it passes SPF, DKIM and DMARC at a third-party mailbox (Gmail or Outlook test account). Mail from an unregistered IP is rejected. Tenant A's connector can't send as a tenant-B domain.
5. Threatcop's domain MX points at the gateway, and for **14 consecutive days**: every message that got `250` reaches a final state, no message is lost (checked against Postfix logs vs `email_messages`), and there is no unplanned rollback.
6. Outbound IPs aren't listed on the major DNSBLs at the end of the dogfood window, and DMARC aggregate reports show more than 99% alignment for dogfood mail.
7. Ingest p99 (LMTP DATA to `250`) is under 2 s at dogfood volume, shown on a dashboard.

## Phase 4: Internal mail + advanced detection (weeks 17–20)

**Goal.** Scan mail sent inside a tenant, and add detection beyond signatures and spam scores.

**Scope**
- Internal direction: outbound-connector mail whose recipient is in the same tenant's verified domains. It is scanned and then delivered to the tenant's own mail server.
- URL analysis: extraction, reputation lookup, and an SSRF-safe fetcher (resolve, then check, pin the IP, re-check on redirect, egress-only). URL rewriting and time-of-click checks only if Sarvesh approves them.
- DLP rules for outbound and internal mail. Logs record rule ids only, never matched values.
- A deterministic risk scorer combines engine results. Its version is recorded on every verdict.
- Corpus expanded for phishing and DLP. Before-and-after metrics are required for every rule or weight change.

**Exit criteria**
1. Internal mail (tenant-A connector to a tenant-A domain) is stored with `direction = internal`, goes through the configured stages, and is delivered to tenant A's mail server. Changing the headers doesn't change the direction.
2. The URL fetcher blocks private, loopback, link-local, metadata (`169.254.169.254`, `fd00:ec2::254`) and reserved targets on IPv4 and IPv6, including through redirects and DNS rebinding. There is one test per range.
3. A DLP fixture (synthetic Aadhaar, PAN or card numbers) in outbound mail triggers the configured action. Logs and ClickHouse hold the rule id only.
4. Given the same engine results and policy version, the scorer gives the same score and verdict on 1,000 repeated runs.
5. Corpus metrics meet the targets Sarvesh sets (see NEEDS SARVESH).

## Phase 5: Enterprise (weeks 21–23)

**Goal.** The features enterprise buyers need: per-tenant archiving, SSO/SCIM and webhooks.

**Scope**
- Per-tenant archiving, off by default. When it's on, `policy-engine` writes an archive record and an S3 copy to the archive bucket, whatever the decision. The archive has its own retention, search and export, and optional S3 Object Lock if Sarvesh approves it.
- SSO: SAML 2.0 and OIDC per tenant, plus SCIM 2.0 user provisioning.
- Webhooks: HMAC-signed, delivered through the outbox, with retries via RabbitMQ dead-letter TTL queues, not a Node scheduler. Per-tenant endpoints, with SSRF-safe delivery.
- Audit log export.

**Exit criteria**
1. With archiving off (the default), a message produces no archive S3 object and no archive row. With it on, every message, including quarantined and discarded ones, has exactly one archive copy under `org/{organization_id}/archive/`.
2. Archive search returns only the requesting tenant's messages, and export runs to completion for a tenant with at least 100k archived messages.
3. SSO login works with at least one SAML IdP and one OIDC IdP. A SCIM deprovision disables the user within 60 s and ends their sessions.
4. Webhooks are signed. A receiver that is down gets retries with backoff, then a DLQ entry. A webhook URL that points at a private address is refused.
5. Every admin action (policy change, quarantine release, user change) appears in `audit_logs` and in the export.

## Phase 6: Scale, DR, dedicated profile, go-live (weeks 24–26)

**Goal.** Prove the sizing targets, prove DR to Hyderabad, prove that a dedicated deployment is pure configuration, and go live.

**Scope**
- A load environment in ap-south-1 sized from the production Terraform vars.
- KEDA scalers on queue depth and HPA for request-driven services. Postfix ASG scale-in with drain lifecycle hooks.
- DR to ap-south-2, following the ADR-025 and ADR-024 decisions. Runbook and drill.
- A `dedicated-<name>` Helm values file and Terraform tfvars, with no code or chart forks.
- Go-live checklist, on-call, external penetration test and first paying customer.

**Exit criteria**
1. **300 msg/s sustained for 60 minutes**, end to end, with the zero-loss check passing and per-stage p50, p95 and p99 reported. p99 must be within the latency targets Sarvesh sets.
2. During the load run, killing one Postfix inbound instance, one scan worker pod and one RabbitMQ node loses nothing and duplicates nothing.
3. DR drill: ap-south-1 is declared lost. Mail flows through ap-south-2 within the agreed RTO, with data loss within the agreed RPO. The drill report is in `docs/runbooks/`.
4. A dedicated deployment is created from the same chart and modules, with only values and tfvars files changed (shown by a diff). It passes Phase 1–3 smoke tests.
5. A grep of `services/` and `packages/` finds no `deploymentMode` or org-id branches in business logic.
6. The external pen test has no open critical or high findings. Sarvesh signs the go-live checklist.

---

## NEEDS SARVESH

1. **ADR-024 (Amazon MQ vs self-managed RabbitMQ).** Needed by the **end of week 10**. It blocks Phase 3. Options: (a) Amazon MQ for RabbitMQ, which is managed, but you have to check quorum-queue support on the current engine version, cluster size limits and the DR story (shovel or federation between regions); (b) self-managed with the RabbitMQ cluster operator on EKS. *Recommendation:* (a) if a check in week 8 confirms quorum queues, `x-delivery-limit` and confirms on the offered version, because it costs less ops for a small team. Otherwise (b).
2. **ADR-025 (Aurora MySQL vs RDS MySQL).** Needed by the **end of week 10**. It blocks Phase 3 and shapes the Phase 6 DR drill. *Recommendation:* RDS for MySQL 8.4 with a cross-region read replica to ap-south-2, unless Aurora offers an 8.4-compatible version by week 8. It matches CLAUDE.md exactly, and failover of a few minutes is acceptable because Postfix spools mail while the writer is down (ADR-021).
3. **Default tenant policy for failure states (Phase 2).** What should a new tenant's policy do with `timeout`, `error` and `not_scanned`? Options: deliver with a tag (fail-open), quarantine (fail-closed), or a split by engine. *Recommendation:* quarantine when the AV stage (ClamAV) fails or is skipped, and deliver with a tag when only Rspamd or YARA fail, with tenants able to override.
4. **Dogfood environment (Phase 3).** Dogfood on an environment that later becomes production SaaS, or on a separate staging account? *Recommendation:* make the production-shaped SaaS environment in ap-south-1 the dogfood environment, with Threatcop as tenant #1. This avoids rebuilding before go-live.
5. **URL rewriting and time-of-click protection (Phase 4).** Rewriting changes message content and needs a click-redirect service. *Recommendation:* defer rewriting until after go-live. Phase 4 does extraction and reputation only.
6. **Detection quality targets (Phase 4 exit 5).** *Recommendation:* on the labelled corpus, malware-eicar 100% detection, spam ≥ 95% detection with ham false positives ≤ 0.1%, and phishing ≥ 90%. Revisit once real dogfood data exists.
7. **Latency, RPO and RTO targets (Phase 6).** *Recommendation:* p99 from `250` to delivery handoff ≤ 60 s at 300 msg/s, ingest p99 ≤ 2 s, RPO ≤ 5 min, RTO ≤ 4 h. Mail in the Postfix spool is the main loss risk, so keep EBS snapshots of the spool volumes.
8. **Proposed ADR-026 (partitioned message tables with an identity table) and ADR-027 (UUIDv7 ids and S3 key layout).** These must be Accepted before tasks 002, 005 and 009 are marked ready.
9. **Table name `email_messages` vs `messages`.** Your brief says `email_messages`. CLAUDE.md and ADR-021 say `messages`. *Recommendation:* use `email_messages` and update the wording in CLAUDE.md. This is a rename, not a change of decision, so ADR-021 still holds. The details are in task 005.
