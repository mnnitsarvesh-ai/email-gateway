# Email Security Gateway

A multi-tenant email security gateway: inbound, outbound and internal mail inspection, spam and phishing detection, malware and attachment scanning, URL protection, BEC detection, DLP, quarantine and optional archiving. It runs as shared SaaS or as a dedicated per-customer deployment. The design target is **1M emails/day**, scaling horizontally beyond that.

> **Status: Phase 2 in progress (step 2.2: Postfix SMTP gateway).** Phase 0 (monorepo, local stack, health, CI, architecture docs), step 1.1 (the MySQL schema with the read/write split), steps 1.2/1.3 (tenants, first-party authentication with MFA and API keys, eight default roles, tenant-scoped authorization with an audited platform override, the organizations API) and step 2.1 (domain onboarding: DNS verification, generated MX/SPF/DKIM/DMARC records, encrypted DKIM keys with rotation, the domain lifecycle) are in place. Step 2.2 adds the mail plane: an inbound MX (`postfix`, postscreen, relay domains and policy from smtp-adapter, Rspamd milter) and an outbound MTA (`postfix-outbound`: SASL submission, source-IP / client-certificate connector relay, internal reinjection listeners), durable LMTP ingestion into S3 + MySQL (`250` only after both), outbound connectors and recipient allow-lists in the api, DKIM signing in a dedicated Rspamd fed by the api through an isolated Redis, bounce processing into suppressions, loop prevention and Prometheus metrics. Message processing after ingestion (MIME parsing, the outbox relay, scanning, policies, delivery) comes in later steps. See [docs/architecture/overview.md](docs/architecture/overview.md#what-exists-now-and-what-comes-next) and [docs/plan/execution-plan.md](docs/plan/execution-plan.md).

## Stack

| Layer                        | Technology                                                |
| ---------------------------- | --------------------------------------------------------- |
| Services                     | Node.js 22, TypeScript (strict), NestJS 11, REST          |
| Portal                       | Next.js 15, React 19, Tailwind CSS 4, shadcn/ui           |
| Database                     | MySQL 8.4 + Prisma (version-controlled migrations)        |
| Mail plane                   | Postfix (inbound MX + outbound MTA), Rspamd, ClamAV, YARA |
| Messaging / cache            | RabbitMQ (quorum queues), Redis                           |
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
| email-worker         | 3020                                                                                                  | `/health/ready`                                                                                                                                          |
| policy-engine        | 3030                                                                                                  | `/health/ready`                                                                                                                                          |
| delivery-worker      | 3040                                                                                                  | `/health/ready`                                                                                                                                          |
| notification-worker  | 3050                                                                                                  | `/health/ready`                                                                                                                                          |
| archive-worker       | 3060                                                                                                  | `/health/ready`                                                                                                                                          |
| postfix (inbound MX) | 2525 → 25 (`SMTP_HOST_PORT`)                                                                          | Container health check                                                                                                                                   |
| postfix-outbound     | 2587 → 587 submission, 2527 → 25 connector relay (`SUBMISSION_HOST_PORT`, `OUTBOUND_RELAY_HOST_PORT`) | Container health check; reinjection 10026/10027 are never published                                                                                      |
| rspamd-outbound      | none (milter of postfix-outbound 10027 only)                                                          | Container health check                                                                                                                                   |
| redis-dkim           | 6391 (`REDIS_DKIM_HOST_PORT`)                                                                         | ACL users per role, no persistence (ADR-0020)                                                                                                            |
| postfix-notify       | 2526 (`NOTIFY_SMARTHOST_HOST_PORT`)                                                                   | Platform transactional mail smarthost                                                                                                                    |
| MySQL (primary)      | 3306 (`MYSQL_HOST_PORT`)                                                                              | Container health check                                                                                                                                   |
| MySQL (replica)      | 3308 (`MYSQL_REPLICA_HOST_PORT`)                                                                      | Healthy only while replication runs                                                                                                                      |
| RabbitMQ             | 5672, management 15672                                                                                |                                                                                                                                                          |
| Redis                | 6379                                                                                                  |                                                                                                                                                          |
| MinIO                | 9000, console 9001                                                                                    |                                                                                                                                                          |
| Rspamd               | 11333 (scan), 11334 (controller)                                                                      |                                                                                                                                                          |
| ClamAV               | 3310                                                                                                  |                                                                                                                                                          |

Test-only services (Compose profile `smtp-test`, never deployed; no host ports): `mail-sink` (a Postfix that stores whatever it receives under `/var/mail/sink/<domain>/<local>/` and refuses `hard-bounce@`, `soft-bounce@` and `policy-block@`), `dns-sink` (CoreDNS authoritative for `sink.test` only: the outbound MTA's only resolver, so locally it can never reach the Internet) and `smtp-tools` (swaks, `smtp-source`, openssl).

### SMTP stack tests

`pnpm test:integration` includes the stack SMTP suites `tests/integration/smtp-*.test.ts` (real SMTP through both Postfix instances, swaks/smtp-source from `smtp-tools`, S3 and MySQL assertions, MinIO/Redis/Postfix outages, a 40-session × 1 000-message zero-loss run). They need the `smtp-test` profile and a running smtp-adapter, and **fail** with an explanation when either is missing:

```bash
docker compose up -d --wait
docker compose --profile smtp-test up -d --wait mail-sink dns-sink smtp-tools
pnpm build                                          # the suites run the api's dkim:sync CLI from dist/
pnpm --filter @email-gateway/smtp-adapter dev       # with SMTP_ADAPTER_HOST=host.docker.internal in .env
pnpm test:integration
```

With the apps profile instead (`SMTP_ADAPTER_HOST=smtp-adapter`, as in CI) the adapter and the api run as containers and the suites publish DKIM keys inside the api container. `SMTP_STACK_TESTS=skip` skips the SMTP suites explicitly (with a visible notice); `SMTP_LOAD_SESSIONS` / `SMTP_LOAD_MESSAGES` scale the load test down on a small machine.

## Common commands

| Command                                               | Does                                                                                |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `pnpm build` / `pnpm dev`                             | Build / run all workspaces (Turborepo)                                              |
| `pnpm lint` / `pnpm typecheck` / `pnpm format`        | Code quality                                                                        |
| `pnpm test`                                           | Unit tests                                                                          |
| `pnpm test:e2e`                                       | In-process API e2e tests (dependencies stubbed)                                     |
| `pnpm test:integration`                               | Tests against the running Compose stack                                             |
| `pnpm db:migrate` / `db:migrate:dev` / `db:status`    | Prisma migrations (`db:migrate` runs a history preflight first)                     |
| `pnpm db:reset:local`                                 | Local only: reset the schema, then partitions and seed (upgrading a phase-0 volume) |
| `pnpm db:partitions -- plan\|apply`                   | Partition maintenance (create ahead, drop expired)                                  |
| `pnpm db:seed`                                        | Seed the catalog and demo data (idempotent)                                         |
| `pnpm --filter @email-gateway/api auth:bootstrap`     | Invite the first platform super admin (after `build`; prints the link to stdout)    |
| `pnpm --filter @email-gateway/api dkim:sync`          | Publish DKIM signing keys to redis-dkim once (after `build`; e.g. after a restart)  |
| `pnpm db:perf`                                        | Database performance test (throwaway schema)                                        |
| `pnpm infra:up` / `pnpm stack:up` / `pnpm stack:down` | Compose shortcuts                                                                   |

## Repository layout

```
apps/
  api/                  REST API: identity, tenants, domains, quarantine, reporting, audit, integrations
  admin-portal/         Next.js admin console
  smtp-adapter/         Postfix extension services: policy, socketmap, SASL, LMTP ingestion, bounces
  email-worker/         Email processing + security engine orchestration
  policy-engine/        Tenant policy evaluation → deliver | tag | quarantine | discard
  delivery-worker/      Reinjection into outbound Postfix
  notification-worker/  Digests and alerts
  archive-worker/       Optional per-tenant archiving
packages/
  common/               NestJS cross-cutting: bootstrap, health, correlation, errors, infra clients
  config/               zod-validated configuration, <KEY>_FILE secrets
  database/             Prisma schema, migrations, client, idempotency helper
  event-contracts/      RabbitMQ envelope, event schemas, queue topology
  security-contracts/   Security engine interface and verdict schema
  shared-types/         Domain primitives shared with the portal
  logger/               pino JSON logger, request context, OpenTelemetry bootstrap
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
- Runbooks: [policy service down](docs/runbooks/smtp-policy-service-down.md), [persistence failure](docs/runbooks/smtp-persistence-failure.md), [queue backlog](docs/runbooks/smtp-queue-backlog.md), [gateway restart](docs/runbooks/smtp-gateway-restart.md), [TLS certificate rotation](docs/runbooks/smtp-tls-cert-rotation.md), [DKIM signing](docs/runbooks/smtp-dkim-signing.md), [tenant reputation (bounce ratio PromQL and thresholds)](docs/runbooks/smtp-tenant-reputation.md)
- [SMTP concurrency results (smtp-source, zero loss)](docs/performance/smtp-concurrency.md)

## Engineering rules (short version)

- Strict TypeScript, ESLint, Prettier. No `any`, no `console`.
- No business logic in controllers. No credentials in code or git.
- Apps never import each other. Shared code goes through `packages/*`.
- The tenant comes from authentication or the mail connector, never from headers. Deployment mode is configuration, never a code branch.
- Consumers are idempotent (`processOnce`). Events carry ids and S3 keys, never message bodies.
- Every schema change ships with a reviewed migration.
