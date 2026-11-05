# Email Security Gateway

A multi-tenant email security gateway: inbound, outbound and internal mail inspection, spam and phishing detection, malware and attachment scanning, URL protection, BEC detection, DLP, quarantine and optional archiving. It runs as shared SaaS or as a dedicated per-customer deployment. The design target is **1M emails/day**, scaling horizontally beyond that.

> **Status: Phase 4 in progress (step 4.1: Rspamd integration and the security scan pipeline; implemented, review round 2 fixed, full gate and whole integration chain green locally; not complete: an open delivery-worker defect makes the step 3.2 suite `messaging-db-outage` fail in 2 of 3 runs, the CR2 close-out review left no record, commit and CI pending; see [§13.5](docs/plan/steps/09-rspamd.md#135-not-complete--not-verified)).** Phase 0 (monorepo, local stack, health, CI, architecture docs), step 1.1 (the MySQL schema with the read/write split), steps 1.2/1.3 (tenants, first-party authentication with MFA and API keys, eight default roles, tenant-scoped authorization with an audited platform override, the organizations API) and step 2.1 (domain onboarding: DNS verification, generated MX/SPF/DKIM/DMARC records, encrypted DKIM keys with rotation, the domain lifecycle) are in place. Step 2.2 adds the mail plane: an inbound MX (`postfix`, postscreen, relay domains and policy from smtp-adapter, Rspamd milter) and an outbound MTA (`postfix-outbound`: SASL submission, source-IP / client-certificate connector relay, internal reinjection listeners), durable LMTP ingestion into S3 + MySQL (`250` only after both), outbound connectors and recipient allow-lists in the api, DKIM signing in a dedicated Rspamd fed by the api through an isolated Redis, bounce processing into suppressions, loop prevention and Prometheus metrics. Step 2.3 adds routing and delivery: the delivery-worker plans approved recipients into reinjection groups and hands them to `postfix-outbound` (10026 for inbound and internal mail to the organization's destination servers — customer servers or the Microsoft 365 / Google Workspace presets, with failover and verified TLS — and 10027 for outbound mail via the recipient's MX, never shortcutting to another tenant), per-recipient directions (`inbound`, `outbound`, `internal`) with one parent message, outbound rate limits, loop prevention, and per-recipient delivery status read from Postfix's own delivery log (`delivered` only after the remote server's `2xx`), with an append-only delivery audit and the destination and delivery-status APIs. **Approval is still development-only:** until policies exist (step 5.2) local and CI stacks deliver through a pass-through that is refused outside `APP_ENV=local|ci`; since step 4.1 it approves only messages that the scan stage completed (`scanned`), never `scan_failed` ones. **Open item of step 2.3:** the gateway does not yet send its own DSN to the authenticated sender when it fails an outbound or internal recipient itself (refused at its internal hop, loop, hop expiry, domain inactive, content missing); those failures are recorded and visible through the API, and Postfix's own DSNs (remote `5xx`, expiry, delay) are sent ([§10](docs/plan/steps/05-routing.md#10-not-in-scope), planned with step 6.2). Step 3.1 adds post-queue MIME ingestion in the email-worker ([design](docs/plan/steps/06-mime-ingestion.md), [ADR-0022](docs/architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md)): every received message is streamed from S3 through a bounded, non-rendering parser (`@email-gateway/mime-parser`); bodies and attachments go to S3 under deterministic `org/{organizationId}/part/…` keys, and one writer transaction records the parse status (`parsed`, `parsed_with_defects`, `parse_limit_exceeded`, `parse_failed`), allow-listed headers, attachment metadata (sanitized filenames, sniffed types, SHA-256, archive-bomb flags), the decoded subject, an `email_events` row and a `mail.message.parsed.v1` / `mail.message.parse_failed.v1` outbox event. The SMTP path is unchanged. Step 3.2 makes the pipeline event-driven over RabbitMQ ([design and verification record](docs/plan/steps/07-rabbitmq.md), [ADR-0023](docs/architecture/adr/0023-outbox-relay-and-reconciliation.md), [ADR-0024](docs/architecture/adr/0024-rabbitmq-topology-retry-dead-letter.md)): a ninth deployable, **`event-relay`**, publishes every `message_outbox` row with publisher confirms (marking it published only after the confirm) into topology v1 (vhost `email-gateway`, six topic exchanges, fourteen quorum queues, tenant-aware routing keys `org.<id>.<eventType>`, least-privilege role users) and reconciles published events against the consumers' ledgers; the email-worker consumes `email.received` and the delivery-worker `email.delivery.pending` through the shared client library (manual acks after the `processOnce` transaction, retries with exponential backoff that never consume an attempt during outages, a delay queue for delivery, one dead-letter queue, a content guard that keeps bodies off the bus); dead letters are replayed only through an audited, MFA-protected platform API. **The outbox poller is no longer a production transport and there is no fallback to it** (two transports per consumer would double the failure modes; a broker outage leaves rows unpublished in the outbox and the reconciler covers lost events); only the development-only dev pass-through and smtp-adapter's cache invalidation still tail the outbox. Step 3.3 adds the message lifecycle (fifteen states, one transition service, history, rescan and release APIs, expiry). Step 4.1 adds the security scan pipeline (below): every parsed message is scanned post-queue by Rspamd in the email-worker scan role and ends `scanned` or `scan_failed`, with standardized verdicts and SPF/DKIM/DMARC/ARC results recorded. Policies (5.x) come next. See [docs/architecture/overview.md](docs/architecture/overview.md#what-exists-now-and-what-comes-next) and [docs/plan/execution-plan.md](docs/plan/execution-plan.md).

## Stack

| Layer                        | Technology                                                |
| ---------------------------- | --------------------------------------------------------- |
| Services                     | Node.js 22, TypeScript (strict), NestJS 11, REST          |
| Portal                       | Next.js 15, React 19, Tailwind CSS 4, shadcn/ui           |
| Database                     | MySQL 8.4 + Prisma (version-controlled migrations)        |
| Mail plane                   | Postfix (inbound MX + outbound MTA), Rspamd, ClamAV, YARA |
| Messaging / cache            | RabbitMQ 4.1 (quorum queues, outbox relay), Redis         |
| Storage / search / analytics | AWS S3 (MinIO locally), OpenSearch, ClickHouse            |
| Platform                     | Docker, Kubernetes (Kustomize), Terraform, GitHub Actions |
| Observability                | pino JSON logs, OpenTelemetry, Prometheus, Grafana        |

## Quick start

**Prerequisites:** Node.js ≥ 22.12, pnpm 9 (`corepack enable`), and Docker with Compose v2 (≈ 6 GB RAM for the full stack).

```bash
pnpm install
pnpm env:init                       # creates .env with random local secrets (git-ignored)
docker compose up -d --wait         # MySQL primary + replica, RabbitMQ, Redis, MinIO, both Postfix MTAs, Rspamd, ClamAV, redis-dkim
pnpm db:migrate                     # history preflight + apply database migrations
pnpm test:integration               # verify every infrastructure service
```

Then either run the services on the host, with hot reload:

```bash
pnpm dev                            # all services (reads ../../.env)
pnpm --filter @email-gateway/api dev  # or just one
```

or run everything in containers:

```bash
docker compose --profile apps up -d --build --wait
pnpm test:integration               # now also checks every service's /health/ready
```

MySQL runs as a GTID primary plus a read replica. The one-shot `mysql-replica-setup` container creates the database accounts and seeds the replica with CLONE on first start (about 10 s). After that it is a no-op. Only the api reads from the replica (`DATABASE_READ_URL`); see [replication](docs/database/replication.md). If your `.env` predates the replica, append `MYSQL_REPLICA_HOST_PORT`, `MYSQL_READER_*`, `MYSQL_REPLICATION_*` (password at most 32 characters) and `DATABASE_READ_*` from `.env.example`, without regenerating the existing secrets.

Step 1.2/1.3 (tenants, authentication, RBAC) adds api keys: `AUTH_JWT_SECRET`, `AUTH_TOKEN_PEPPER`, `DATA_ENCRYPTION_KEY` (secrets), `PORTAL_PUBLIC_URL`, `HTTP_TRUST_PROXY` and the `AUTH_*`/`PLATFORM_*`/`ORG_*` tuning keys (see the "API authentication and tenancy" section of `.env.example`). If your `.env` predates them, append that section from `.env.example` and fill the `__GENERATE_64__` placeholders with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`, without rotating existing secrets (never `env:init --force`). Transactional email (invitations, password resets) goes through `NOTIFY_SMTP_*`; when `NOTIFY_SMTP_HOST` is empty the api logs the email (with a dev link) instead of sending it.

Step 2.1 (domain onboarding) adds the section "Domain onboarding and DNS (step 2.1)" of `.env.example`: `DNS_*` (resolver mode, servers, DoH URL, timeouts, propagation upstreams, cache), `GATEWAY_*` (the MX hosts and SPF include customers publish, DMARC report addresses), `DOMAIN_*` (verification label and lifetime, reserved names, background-job tuning) and `DKIM_ROTATION_OVERLAP_DAYS`. None of them is a secret. `GATEWAY_MX_HOSTS` and `GATEWAY_SPF_INCLUDE` have no default: the api refuses to start without them. If your `.env` predates them, append the section without touching anything else:

```bash
grep -q '^GATEWAY_MX_HOSTS=' .env || sed -n '/^# --- Domain onboarding and DNS (step 2.1) ---/,/^DKIM_ROTATION_OVERLAP_DAYS=/p' .env.example >> .env
```

The local values point at `.test` names; in a real deployment set `GATEWAY_MX_HOSTS`/`GATEWAY_SPF_INCLUDE` to the gateway's public names and choose the DNS resolver ([runbook](docs/runbooks/domain-verification.md#dns-resolver-modes)). The API integration tests never use public DNS: they run their own in-process DNS server.

Step 2.2 (SMTP gateway) adds the section "SMTP gateway (step 2.2)" of `.env.example`: host ports of the outbound MTA and redis-dkim, `SMTP_ADAPTER_HOST` (where both Postfix containers reach smtp-adapter: `smtp-adapter` for the apps profile and CI, `host.docker.internal` when the adapter runs on the host with `pnpm --filter @email-gateway/smtp-adapter dev`), Postfix limits, TLS certificate paths (`POSTFIX_*TLS_*_PATH`) and queue timings, the redis-dkim passwords (`REDIS_DKIM_*_PASSWORD`, secrets) and URLs, `GATEWAY_TRACE_SECRET` (secret), and the adapter's cache, rate-limit, SASL and ingestion tuning. `POSTFIX_RELAY_DOMAINS` is deprecated: relay domains now come from the database through smtp-adapter. If your `.env` predates the section, append it and fill its placeholders yourself (never `env:init --force`):

```bash
grep -q '^GATEWAY_TRACE_SECRET=' .env || sed -n '/^# --- SMTP gateway (step 2.2) ---/,$p' .env.example >> .env
# then replace each __GENERATE__ / __GENERATE_64__ in the appended lines, e.g. with
node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
```

Step 2.3 (mail routing) adds the section "Mail routing and delivery (step 2.3)" of `.env.example` (no secrets): the delivery-worker's reinjection, polling, status-log and rate-limit keys, the destination-host rules (`ROUTING_*`, including the custom-destination port allow-list `ROUTING_ALLOWED_DESTINATION_PORTS`), the delivery-log directory (`POSTFIX_OUTBOUND_LOG_DIR`, git-ignored `.local/`), the outbound connect timeout and the test CA path. For a worker on the host the local `.env` uses the test-only `reinject-forwarder` (`DELIVERY_REINJECT_HOST=127.0.0.1`, ports `2626`/`2627`), `DELIVERY_STATUS_LOG_PATH=../../.local/postfix-outbound-log/maillog`, the test-profile backoff (`POSTFIX_MINIMAL_BACKOFF_TIME=10s`, `POSTFIX_MAXIMAL_BACKOFF_TIME=60s`, `POSTFIX_QUEUE_RUN_DELAY=10s`) and `DELIVERY_DEV_PASSTHROUGH_ENABLED=true` (**development only**: delivers without scanning or policy). Append the section with `grep -q '^DELIVERY_REINJECT_HOST=' .env || sed -n '/^# --- Mail routing and delivery (step 2.3) ---/,$p' .env.example >> .env`, set those local values, then recreate both Postfix containers. Run the worker with `pnpm --filter @email-gateway/delivery-worker dev` next to the adapter; details in [docs/deployment/mail-routing.md](docs/deployment/mail-routing.md).

Step 3.1 (MIME ingestion) adds the section "MIME ingestion (step 3.1)" of `.env.example` (no secrets): `MIME_INGESTION_ENABLED`, the feed's concurrency, polling, safety lag, shards and retry backoff, the S3 upload buffers and memory budget, and every parse limit (`MIME_MAX_*`, `MIME_PARSE_TIMEOUT_MS`, `MIME_ARCHIVE_*`). The email-worker refuses to start with inconsistent values (for example a per-part limit above `MIME_MAX_MESSAGE_BYTES`, parse buffers above `MIME_MEMORY_BUDGET_BYTES`, a `MIME_MAX_DEPTH` whose `part_path` could overflow its column, or `MIME_S3_TIMEOUT_MS` not below `MIME_PARSE_TIMEOUT_MS`). If your `.env` predates it, append the section unchanged. If it has `MIME_S3_TIMEOUT_MS=120000` (the first default), set it to `30000`, or the email-worker refuses to start:

```bash
grep -q '^MIME_INGESTION_ENABLED=' .env || sed -n '/^# --- MIME ingestion (step 3.1) ---/,$p' .env.example >> .env
```

Run the stage with `pnpm --filter @email-gateway/email-worker dev` (stop the `email-worker` container first, or set `HTTP_PORT`), or as the apps-profile container (`docker compose --profile apps build email-worker`, one image at a time on a small Docker VM). Since step 3.2 it consumes `email.received` (the `MIME_OUTBOX_*` keys are no longer read and can be removed from `.env`).

Step 3.2 (RabbitMQ) adds the sections "RabbitMQ" and "Event relay (step 3.2)" of `.env.example`: `RABBITMQ_VHOST`, `RABBITMQ_MGMT_URL`, `RABBITMQ_PROMETHEUS_HOST_PORT`, one user, password (`__GENERATE__`) and URL per role (`RABBITMQ_RELAY_*`, `RABBITMQ_EMAIL_WORKER_*`, `RABBITMQ_DELIVERY_WORKER_*`, `RABBITMQ_OPS_*`), the test-only cluster keys (`RABBITMQ_CLUSTER_*`), `EVENT_RELAY_HOST_PORT` and the relay/reconciler tuning (`RELAY_*`, `RECONCILE_*`), plus `DELIVERY_APPROVAL_PREFETCH` and `DEAD_LETTER_REPLAY_SCAN_MAX`. `RABBITMQ_URL` is now the administrator on `/` for tests and tools only (services no longer receive it) and `RABBITMQ_PREFETCH` is not read. If your `.env` predates the step, append the sections and generate the passwords (never `env:init --force`). The Compose one-shot `rabbitmq-init` provisions the vhost, topology and role users on every `docker compose up` and removes the empty pre-3.2 objects on vhost `/`; from the host, `pnpm rabbitmq:init` does the same without the cleanup. The first relay start publishes the whole pre-3.2 outbox backlog; the consumers record it as ledger duplicates. Operations: [RabbitMQ messaging runbook](docs/runbooks/rabbitmq-messaging.md); topology: [docs/architecture/messaging-topology.md](docs/architecture/messaging-topology.md); relay: [apps/event-relay/README.md](apps/event-relay/README.md). Details, metrics and cursors: [apps/email-worker/README.md](apps/email-worker/README.md); operations: [runbook](docs/runbooks/mime-ingestion.md).

The API serves business routes under `/api/v1` ([ADR-0015](docs/architecture/adr/0015-api-base-path.md)); health endpoints stay at `/health/*`, and outside production the OpenAPI UI is at `/docs` (snapshot: [docs/api/openapi.json](docs/api/openapi.json)). Endpoints and conventions: [docs/api/README.md](docs/api/README.md).

### First login (local)

The admin-portal pages for login, invitations and password reset arrive with steps 7.x, so the first platform administrator is created from the command line and activated through the API:

```bash
pnpm db:seed                                        # catalog: permissions, 8 roles, plans, the platform organization
pnpm --filter @email-gateway/api build              # the bootstrap CLI runs from dist/
pnpm --filter @email-gateway/api auth:bootstrap -- --email ops@example.com --display-name "Ops"
# prints an acceptance link …/auth/accept-invitation#token=egt_… to stdout (treat it like a password)

API=http://127.0.0.1:${API_HOST_PORT:-3000}/api/v1
curl -s -X POST $API/auth/invitations/accept -H 'content-type: application/json' \
  -d '{"token":"egt_…","password":"<12+ characters, not a common password>"}'   # → 204
curl -s -X POST $API/auth/login -H 'content-type: application/json' \
  -d '{"email":"ops@example.com","password":"…","organization":"platform"}'
```

The API must be running (`pnpm --filter @email-gateway/api dev`, or the `apps` Compose profile). The platform organization requires MFA, so the first login returns `mfaEnrollmentRequired: true`: enroll with `POST /auth/mfa/totp/setup` and `POST /auth/mfa/totp/enable { code }` (bearer token from the login; store the recovery codes), then refresh the session (`POST /auth/refresh`) to get an MFA access token; later logins finish with `POST /auth/mfa/verify`. Afterwards the administrator can create customer organizations (`POST /api/v1/organizations` with an `initialAdmin`), whose invitation emails go through `NOTIFY_SMTP_*` or, without a relay, are logged with a dev link. Details: [docs/security/authentication.md](docs/security/authentication.md).

On first start, ClamAV downloads about 300 MB of signatures. `--wait` blocks until it is healthy, which can take a few minutes.

Optional profiles: `--profile analytics` (OpenSearch, ClickHouse) and `--profile observability` (OpenTelemetry Collector, Prometheus, Grafana).

## Services and ports

All ports bind to `127.0.0.1`. You can change any host port in `.env` (`*_HOST_PORT`) if it clashes with something else on your machine.

| Service              | Port                                                                                                  | Health                                                                                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| api                  | 3000                                                                                                  | `/health/live`, `/health/ready`, OpenAPI at `/docs` (business routes under `/api/v1`)                                                                    |
| admin-portal         | 3001                                                                                                  | `/api/health`                                                                                                                                            |
| smtp-adapter         | 3010 (HTTP, `/metrics`)                                                                               | `/health/ready`; internal Postfix listeners: policy 10040, socketmap 10041, SASL 10042, LMTP 10050 (inbound) / 10051 (outbound) / 10052 (bounce notices) |
| email-worker         | 3020 (HTTP, `/metrics`)                                                                               | `/health/ready` (MIME role 3.1: `rabbitmq`; scan role 4.1: `rabbitmq-scanner`)                                                                           |
| policy-engine        | 3030                                                                                                  | `/health/ready`                                                                                                                                          |
| delivery-worker      | 3040                                                                                                  | `/health/ready`                                                                                                                                          |
| notification-worker  | 3050                                                                                                  | `/health/ready`                                                                                                                                          |
| archive-worker       | 3060                                                                                                  | `/health/ready`                                                                                                                                          |
| event-relay          | 3070 (HTTP, `/metrics`; `EVENT_RELAY_HOST_PORT`)                                                      | `/health/ready` (`mysql` writer, `rabbitmq`); outbox relay and reconciler (3.2), lifecycle expiry sweeper and lifecycle check (3.3)                      |
| postfix (inbound MX) | 2525 → 25 (`SMTP_HOST_PORT`)                                                                          | Container health check                                                                                                                                   |
| postfix-outbound     | 2587 → 587 submission, 2527 → 25 connector relay (`SUBMISSION_HOST_PORT`, `OUTBOUND_RELAY_HOST_PORT`) | Container health check; reinjection 10026/10027 are never published                                                                                      |
| rspamd-outbound      | none (milter of postfix-outbound 10027 only)                                                          | Container health check                                                                                                                                   |
| redis-dkim           | 6391 (`REDIS_DKIM_HOST_PORT`)                                                                         | ACL users per role, no persistence (ADR-0020)                                                                                                            |
| postfix-notify       | 2526 (`NOTIFY_SMARTHOST_HOST_PORT`)                                                                   | Platform transactional mail smarthost                                                                                                                    |
| MySQL (primary)      | 3306 (`MYSQL_HOST_PORT`)                                                                              | Container health check                                                                                                                                   |
| MySQL (replica)      | 3308 (`MYSQL_REPLICA_HOST_PORT`)                                                                      | Healthy only while replication runs                                                                                                                      |
| RabbitMQ             | 5672, management 15672, Prometheus 15692 (`RABBITMQ_PROMETHEUS_HOST_PORT`)                            | Container health check; topology in vhost `email-gateway` applied by the one-shot `rabbitmq-init`                                                        |
| Redis                | 6379                                                                                                  |                                                                                                                                                          |
| MinIO                | 9000, console 9001                                                                                    |                                                                                                                                                          |
| Rspamd               | 11333 (scan, `RSPAMD_HOST_PORT`), 11334 (controller, `RSPAMD_CONTROLLER_HOST_PORT`; passwords)        | Container health check (`rspamc stat` from loopback); milter 11332 for `postfix` only; also on `mailtest` (172.31.250.11) locally                        |
| ClamAV               | 3310                                                                                                  |                                                                                                                                                          |

Test-only services (Compose profile `smtp-test`, never deployed; no host ports): `mail-sink` (a Postfix that stores whatever it receives under `/var/mail/sink/<domain>/<local>/` and refuses `hard-bounce@`, `soft-bounce@` and `policy-block@`), `dns-sink` (CoreDNS authoritative for `sink.test` and, since step 4.1, the `scan.test` test zones: the outbound MTA's and the inbound Rspamd's only resolver, so locally neither can reach the Internet) and `smtp-tools` (swaks, `smtp-source`, openssl).

### SMTP stack tests

`pnpm test:integration` includes the stack SMTP suites `tests/integration/smtp-*.test.ts` (real SMTP through both Postfix instances, swaks/smtp-source from `smtp-tools`, S3 and MySQL assertions, MinIO/Redis/Postfix outages, a 40-session × 1 000-message zero-loss run). They need the `smtp-test` profile and a running smtp-adapter, and **fail** with an explanation when either is missing:

```bash
docker compose up -d --wait
docker compose --profile smtp-test up -d --wait mail-sink dns-sink smtp-tools
pnpm build                                          # the suites run the api's dkim:sync CLI from dist/
pnpm --filter @email-gateway/smtp-adapter dev       # with SMTP_ADAPTER_HOST=host.docker.internal in .env
pnpm test:integration
```

The step 2.3 routing suites (`routing-*.test.ts`) also need the delivery-worker with `DELIVERY_DEV_PASSTHROUGH_ENABLED=true`, and the step 3.1 suite `mime-ingestion.test.ts` needs an email-worker with the MIME stage on `EMAIL_WORKER_HOST_PORT` (`pnpm --filter @email-gateway/email-worker dev` or the rebuilt container; its gate checks `/health/ready` and the `mime_*` series on `/metrics`). With the email-worker running, every message of the other suites is parsed too; their fixtures clean up the parse rows and part objects. The step 3.2 stack suites `messaging-*.test.ts` (broker restart, MySQL writer pause, email-worker SIGKILL, duplicate events, a 500-message backlog, dead-letter replay through the api) need the whole apps profile **as containers** built from this tree (they restart, pause and kill them) and `DELIVERY_DEV_PASSTHROUGH_ENABLED=true`. The step 3.3 suites `lifecycle-*.test.ts` need the same (release and rescan through the live api, a SIGKILL of the delivery-worker); `lifecycle-event-relay.test.ts` stops the `event-relay` container for its duration, runs a test-only event-relay on the host (`LIFECYCLE_TEST_RELAY_PORT`, default 3071) with short sweep intervals, and starts the container again. The step 4.1 suites `scan-*.test.ts` send through the inbound MX's `mailtest` address (172.31.250.10, so the client is in the `scan.test` SPF records) and need the email-worker scan role and the scanned pass-through (the routing, MIME and messaging gates check both); `scan-resilience.test.ts` stops and starts the `rspamd` container. Suites that send mail purge the dormant queues (`scan.auth`, `scan.url`, `scan.attachment`, `scan.dlp`, `scan.sandbox`, `email.policy.evaluate`, `email.quarantine`, `email.archive`, `email.analytics`) in `afterAll`. The broker node-failure test runs only on the test-only `rabbitmq-cluster` profile: `pnpm --filter @email-gateway/integration-tests test:cluster` after the procedure in the [RabbitMQ runbook](docs/runbooks/rabbitmq-messaging.md#node-failure-test).

```bash
pnpm --filter @email-gateway/integration-tests run test:integration   # the stack suites only
pnpm --filter @email-gateway/email-worker test                       # email-worker unit tests
pnpm --filter @email-gateway/email-worker test:integration           # MIME ingestion against the MySQL writer and MinIO
pnpm --filter @email-gateway/mime-parser test                        # parser, limits, corpus
pnpm --filter @email-gateway/rspamd test:integration                 # scan corpus, Bayes, fuzzy against the real Rspamd
```

With the apps profile instead (`SMTP_ADAPTER_HOST=smtp-adapter`, as in CI) the adapter and the api run as containers and the suites publish DKIM keys inside the api container. `SMTP_STACK_TESTS=skip` skips the SMTP suites explicitly (with a visible notice); `SMTP_LOAD_SESSIONS` / `SMTP_LOAD_MESSAGES` scale the load test down on a small machine.

## Message lifecycle (step 3.3)

Every message has one lifecycle state in `email_messages.status` (fifteen states: `received`, `persisted`, `scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `approved`, `quarantined`, `held_for_review`, `rejected`, `delivery_pending`, `delivery_retry`, `delivered`, `archived`, `expired`), plus `status_reason`, `version` (+1 per applied transition) and `lifecycle_round` (+1 on a rescan or release). Every write goes through `@email-gateway/message-lifecycle` ([packages/message-lifecycle](packages/message-lifecycle/README.md)): the transition table (edges E1–E27), a row lock plus a version compare-and-set, an idempotency key per transition, and in the same transaction one `email_message_status_history` row (actor role/service/type/id, reason, causing event, correlation id, occurrence time), one `email_events` row `lifecycle.<state>` and one `mail.message.state_changed.v1` outbox row. Late, duplicate or out-of-order requests never move a message backwards; they are recorded as `lifecycle.ignored`. Design: [step 3.3](docs/plan/steps/08-message-lifecycle.md), [ADR-0025](docs/architecture/adr/0025-message-lifecycle-state-machine.md), diagrams [11](docs/architecture/diagrams/11-message-state-machine.md) and [22](docs/architecture/diagrams/22-delivery-lifecycle.md), runbook [message lifecycle](docs/runbooks/message-lifecycle.md).

Who moves a message today: smtp-adapter (`received` → `persisted` in the SMTP commit), the email-worker scan role (`persisted → scanning → scanned | scan_failed`, step 4.1), the dev pass-through of the delivery-worker (`scanned → approved`, E27, local/CI only, until the 5.2 policy engine; E4 `persisted → approved` is retired), the delivery planner (`approved → delivery_pending`), the shared delivery recorder (`delivery_retry` / `delivered` / `rejected`, derived from the per-recipient states), the api (operator rescan and release) and event-relay (expiry, lost-derivation recovery). The policy states are valid in the machine but have no producer before Phase 5. A partial delivery is `delivered` with reason `delivery_partial`; every recipient failed is `rejected` with `delivery_failed`.

event-relay roles (each a flag, single owner through MySQL `GET_LOCK`): `RELAY_ENABLED` (outbox relay), `RECONCILE_ENABLED` (re-drive of unconsumed events), `LIFECYCLE_EXPIRY_ENABLED` (expires a message stuck past its state's deadline, `LIFECYCLE_DEADLINE_<STATE>_HOURS`), `LIFECYCLE_CHECK_ENABLED` (re-derives a lost delivery transition, gauges of stuck messages). Keys: `.env.example` section "Message lifecycle (step 3.3)".

Routes (OpenAPI at `/docs`, [docs/api/README.md](docs/api/README.md)):

| Route                                         | Permission           | Does                                                                                                                                                                                                                 |
| --------------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/v1/messages/{id}/lifecycle`         | `message:read`       | State, reason, version, round, parse outcome, recipient counts, allowed actions (replica)                                                                                                                            |
| `GET /api/v1/messages/{id}/lifecycle/history` | `message:read`       | Applied transitions oldest first, cursor pagination                                                                                                                                                                  |
| `POST /api/v1/messages/{id}/rescan`           | `message:rescan`     | `Idempotency-Key` required; E19 → `scanning` with a new round, `rescan_requested.v1`; since step 4.1 every registered engine scans the new round (old rounds are kept) and the round ends `scanned` or `scan_failed` |
| `POST /api/v1/messages/{id}/release`          | `quarantine:release` | `Idempotency-Key` required; `quarantined`/`held_for_review` → `approved`, released `quarantined` recipients → `pending`, delivered via 2.3                                                                           |

Reading a message's state locally: the api route above, or on the writer `SELECT status, status_reason, version, lifecycle_round, status_changed_at FROM email_messages WHERE id = ?` and `SELECT version, from_status, to_status, reason_code, actor_role, actor_service, changed_at FROM email_message_status_history WHERE message_id = ? ORDER BY version` (add `received_at` for partition pruning). The stack suites `tests/integration/lifecycle-*.test.ts` exercise release, rescan, expiry, recovery, re-drive and a delivery-worker crash.

## Security scanning (step 4.1)

Every parsed message is scanned post-queue by the **email-worker scan role** ([design and verification record](docs/plan/steps/09-rspamd.md), [ADR-0026](docs/architecture/adr/0026-security-scan-pipeline.md), [runbook](docs/runbooks/scan-pipeline.md), [Rspamd deployment](docs/deployment/rspamd.md), diagrams [9](docs/architecture/diagrams/09-scanning-sequence.md) and [23](docs/architecture/diagrams/23-scan-pipeline.md)): `mail.message.parsed.v1` (or an operator's `rescan_requested.v1`) on `scan.spam` → the round opens (`persisted → scanning`, one `email_scans` row per lifecycle round) → the EML is streamed from S3 to Rspamd `/checkv2` with the trusted envelope (client IP, HELO and host name from Postfix XFORWARD, envelope sender, recipients) → the reply is mapped to one of seven verdicts (`clean`, `spam`, `suspicious`, `malicious`, `unknown`, `timeout`, `error`) with reason codes such as `spam.gtube`, `auth.spf_fail`, `auth.dmarc_reject`, `phishing.known_bad_url` → `scan_engine_results`, `email_auth_results` (SPF/DKIM/DMARC/ARC), `scanned` or `scan_failed` and `mail.message.scanned.v1` in one transaction. Engine timeouts, errors, an open circuit breaker or a missing EML are **never clean**: they are retried (non-final attempt rows) and end `scan_failed` when the attempt budget or the round deadline is spent. Rspamd also runs at SMTP time as the inbound milter ([ADR-0027](docs/architecture/adr/0027-rspamd-milter-policy.md)): it rejects only GTUBE and score ≥ 15 (`554 5.7.1`), strips forged `Authentication-Results`/`X-Spam*` headers, adds ours, and **accepts** when Rspamd is down (the post-queue scan still runs).

Running it locally: `docker compose up -d --wait` starts `rspamd`; `docker compose --profile smtp-test up -d --wait dns-sink` serves the `scan.test` zones Rspamd resolves (`RSPAMD_DNS_SERVERS=172.31.250.53`); the email-worker runs both roles (`MIME_INGESTION_ENABLED=true`, `SCAN_ENABLED=true`, broker user `eg-scanner` from `RABBITMQ_SCANNER_URL`; `pnpm rabbitmq:init` creates it). New keys: `.env.example` section "Security scanning (step 4.1)" — `RABBITMQ_SCANNER_*`, `SCAN_ENABLED`, `SCAN_ENGINES`, `SCAN_RSPAMD_URL`, `RSPAMD_CONTROLLER_URL`, `RSPAMD_CONTROLLER_PASSWORD`, `RSPAMD_CONTROLLER_ENABLE_PASSWORD`, the `SCAN_RSPAMD_*` thresholds, timeouts, attempts, breaker, deadline and sweeper keys, `SCAN_FUZZY_WEIGHT`, and the `RSPAMD_*` keys of the Rspamd container (DNS, Redis DB 1, Bayes `min_learns`, RBL profile, phishing feeds, milter reject score, authserv-id). Existing `.env` files: append the section and generate the three new secrets yourself (never `pnpm env:init --force`; see [docs/deployment/rspamd.md](docs/deployment/rspamd.md#environment-envexample-section-security-scanning-step-41)). `RECONCILE_QUEUES` now includes `scan.spam`.

| Route                                                                                     | Permission               | Does                                                                                                                           |
| ----------------------------------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `GET /api/v1/messages/{id}/scans`                                                         | `message:read`           | Every scan round, newest first: verdict, reasons, engines with symbols and attempts, SPF/DKIM/DMARC/ARC (replica)              |
| `GET /api/v1/scan-settings`                                                               | `policy:read`            | Per engine: platform settings, bounds, the organization's override, the effective settings                                     |
| `PUT` / `DELETE /api/v1/scan-settings/{engine}`                                           | `scan:settings_manage`   | Tenant thresholds within platform bounds (severities only raised), version compare-and-set, audited; workers apply within 30 s |
| `POST /api/v1/platform/organizations/{organizationId}/messages/{messageId}/scan-training` | `platform:scan_training` | Platform admins only (MFA): learn spam/ham (Bayes), add/delete a fuzzy hash, from the stored EML; audited                      |

The stack suites `tests/integration/scan-*.test.ts` exercise the milter (GTUBE, forged headers), clean and spoofed mail through Postfix to delivery, an Rspamd outage within and past the attempt budget, and an administrative rescan.

## Common commands

| Command                                                       | Does                                                                                          |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `pnpm build` / `pnpm dev`                                     | Build / run all workspaces (Turborepo)                                                        |
| `pnpm lint` / `pnpm typecheck` / `pnpm format`                | Code quality                                                                                  |
| `pnpm test`                                                   | Unit tests                                                                                    |
| `pnpm test:e2e`                                               | In-process API e2e tests (dependencies stubbed)                                               |
| `pnpm test:integration`                                       | Tests against the running Compose stack                                                       |
| `pnpm db:migrate` / `db:migrate:dev` / `db:status`            | Prisma migrations (`db:migrate` runs a history preflight first)                               |
| `pnpm db:reset:local`                                         | Local only: reset the schema, then partitions and seed (upgrading a phase-0 volume)           |
| `pnpm db:partitions -- plan\|apply`                           | Partition maintenance (create ahead, drop expired)                                            |
| `pnpm db:seed`                                                | Seed the catalog and demo data (idempotent)                                                   |
| `pnpm --filter @email-gateway/api auth:bootstrap`             | Invite the first platform super admin (after `build`; prints the link to stdout)              |
| `pnpm --filter @email-gateway/api dkim:sync`                  | Publish DKIM signing keys to redis-dkim once (after `build`; e.g. after a restart)            |
| `pnpm db:perf`                                                | Database performance test (throwaway schema)                                                  |
| `pnpm rabbitmq:init`                                          | Apply the RabbitMQ topology v2 and role users from the host (idempotent)                      |
| `pnpm --filter @email-gateway/integration-tests test:cluster` | Broker node-failure test on the 3-node `rabbitmq-cluster` profile (not in `test:integration`) |
| `pnpm infra:up` / `pnpm stack:up` / `pnpm stack:down`         | Compose shortcuts                                                                             |

## Repository layout

```
apps/
  api/                  REST API: identity, tenants, domains, quarantine, reporting, audit, integrations
  admin-portal/         Next.js admin console
  smtp-adapter/         Postfix extension services: policy, socketmap, SASL, LMTP ingestion, bounces
  email-worker/         Email processing: post-queue MIME ingestion (3.1); scan role with the Rspamd engine (4.1)
  policy-engine/        Tenant policy evaluation → deliver | tag | quarantine | discard
  delivery-worker/      Reinjection into outbound Postfix
  notification-worker/  Digests and alerts
  archive-worker/       Optional per-tenant archiving
  event-relay/          Outbox relay (confirmed publish to RabbitMQ) and reconciliation (3.2); lifecycle expiry and check (3.3)
packages/
  common/               NestJS cross-cutting: bootstrap, health, correlation, errors, infra clients, AMQP client library
  config/               zod-validated configuration, <KEY>_FILE secrets
  database/             Prisma schema, migrations, client, idempotency helper
  event-contracts/      Event envelope, schemas and registry, RabbitMQ topology v3 and definitions
  security-contracts/   Verdicts, engine catalog, normalized results, scan settings (4.1)
  rspamd/               Rspamd HTTP client: streamed /checkv2, controller learn/fuzzy, reply normalization (4.1)
  shared-types/         Domain primitives shared with the portal
  logger/               pino JSON logger, request context, OpenTelemetry bootstrap
  mime-parser/          Streaming MIME parser with limits, defects, filename sanitization, sniffing, zip inspection
  mail-routing/         Direction resolution, destination safety, route planning, delivery status recorder
  message-lifecycle/    Message state machine: transition table, ordering rule, transition service (3.3)
infrastructure/         docker, kubernetes, terraform, postfix, rspamd, clamav, rabbitmq, mysql, minio, monitoring
docs/                   architecture (+ ADRs), database, api, security, deployment, runbooks
tests/integration/      Tests against the running stack
scripts/                Developer tooling
```

## Documentation

- [Architecture overview](docs/architecture/overview.md)
- [Technology decision records](docs/architecture/adr/README.md)
- [Database: conventions, schema reference, partitioning, retention, backups](docs/database/README.md)
- [MySQL replication and the read/write split](docs/database/replication.md)
- [API conventions and endpoints](docs/api/README.md) (OpenAPI snapshot: [docs/api/openapi.json](docs/api/openapi.json))
- [Security baseline](docs/security/README.md)
- [Authentication, sessions and the platform override](docs/security/authentication.md)
- [Roles and permissions (RBAC)](docs/security/rbac.md)
- [Deployment](docs/deployment/README.md)
- [Runbook: local stack](docs/runbooks/local-stack.md)
- [Runbook: organization deletion](docs/runbooks/organization-deletion.md)
- [Adding a domain (customer guide: verification, MX, SPF, DKIM, DMARC)](docs/domains/onboarding.md)
- [Runbook: domain verification and DNS checks](docs/runbooks/domain-verification.md)
- [DNS resolution (ADR-0017)](docs/architecture/adr/0017-dns-resolution-strategy.md) and [DKIM key custody (ADR-0018)](docs/architecture/adr/0018-dkim-key-custody.md)
- [SMTP gateway topology (ADR-0019)](docs/architecture/adr/0019-smtp-gateway-topology.md), [DKIM signing (ADR-0020)](docs/architecture/adr/0020-dkim-signing.md) and the [step 2.2 design and verification record](docs/plan/steps/04-smtp-gateway.md)
- [Deployment: SMTP gateway (EC2 Auto Scaling Groups, ports, drain)](docs/deployment/smtp-gateway.md)
- [Mail routing and delivery tracking (ADR-0021)](docs/architecture/adr/0021-mail-routing-and-delivery-status.md), the [step 2.3 design and verification record](docs/plan/steps/05-routing.md), [operations](docs/deployment/mail-routing.md), [destination servers (customer guide: Microsoft 365, Google Workspace)](docs/domains/destination-servers.md), runbooks [delivery status log](docs/runbooks/delivery-status-log.md) and [deferred delivery backlog](docs/runbooks/delivery-deferred-backlog.md)
- Runbooks: [policy service down](docs/runbooks/smtp-policy-service-down.md), [persistence failure](docs/runbooks/smtp-persistence-failure.md), [queue backlog](docs/runbooks/smtp-queue-backlog.md), [gateway restart](docs/runbooks/smtp-gateway-restart.md), [TLS certificate rotation](docs/runbooks/smtp-tls-cert-rotation.md), [DKIM signing](docs/runbooks/smtp-dkim-signing.md), [tenant reputation (bounce ratio PromQL and thresholds)](docs/runbooks/smtp-tenant-reputation.md)
- [SMTP concurrency results (smtp-source, zero loss)](docs/performance/smtp-concurrency.md)
- [Outbox relay and reconciliation (ADR-0023)](docs/architecture/adr/0023-outbox-relay-and-reconciliation.md), [RabbitMQ topology, retry, dead letters (ADR-0024)](docs/architecture/adr/0024-rabbitmq-topology-retry-dead-letter.md), the [step 3.2 design and verification record](docs/plan/steps/07-rabbitmq.md), the [messaging topology](docs/architecture/messaging-topology.md), the [event-relay README](apps/event-relay/README.md), the [RabbitMQ messaging runbook](docs/runbooks/rabbitmq-messaging.md) and [diagram 21](docs/architecture/diagrams/21-event-relay-sequence.md)
- [MIME parsing and post-queue ingestion (ADR-0022)](docs/architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md), the [step 3.1 design and verification record](docs/plan/steps/06-mime-ingestion.md), the [email-worker](apps/email-worker/README.md) and [mime-parser](packages/mime-parser/README.md) READMEs, the [MIME ingestion runbook](docs/runbooks/mime-ingestion.md) and [diagram 20](docs/architecture/diagrams/20-mime-ingestion-sequence.md)
- [Security scan pipeline (ADR-0026)](docs/architecture/adr/0026-security-scan-pipeline.md), [Rspamd milter policy (ADR-0027)](docs/architecture/adr/0027-rspamd-milter-policy.md), the [step 4.1 design and verification record](docs/plan/steps/09-rspamd.md), [Rspamd deployment](docs/deployment/rspamd.md), the [scan pipeline runbook](docs/runbooks/scan-pipeline.md) and diagrams [9](docs/architecture/diagrams/09-scanning-sequence.md) and [23](docs/architecture/diagrams/23-scan-pipeline.md)
- [Message lifecycle (ADR-0025)](docs/architecture/adr/0025-message-lifecycle-state-machine.md), the [step 3.3 design and verification record](docs/plan/steps/08-message-lifecycle.md), the [message-lifecycle README](packages/message-lifecycle/README.md), the [message lifecycle runbook](docs/runbooks/message-lifecycle.md) and diagrams [11](docs/architecture/diagrams/11-message-state-machine.md) and [22](docs/architecture/diagrams/22-delivery-lifecycle.md)

## Engineering rules (short version)

- Strict TypeScript, ESLint, Prettier. No `any`, no `console`.
- No business logic in controllers. No credentials in code or git.
- Apps never import each other. Shared code goes through `packages/*`.
- The tenant comes from authentication or the mail connector, never from headers. Deployment mode is configuration, never a code branch.
- Consumers are idempotent (`processOnce`). Events carry ids and S3 keys, never message bodies.
- Every schema change ships with a reviewed migration.
