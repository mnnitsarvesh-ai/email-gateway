# Email Security Gateway

A multi-tenant email security gateway: inbound, outbound and internal mail inspection, spam and phishing detection, malware and attachment scanning, URL protection, BEC detection, DLP, quarantine and optional archiving. It runs as shared SaaS or as a dedicated per-customer deployment. The design target is **1M emails/day**, scaling horizontally beyond that.

> **Status: Phase 1 in progress (steps 1.2/1.3: tenants, authentication, RBAC).** Phase 0 (monorepo, local stack, health, CI, architecture docs) and step 1.1 (the MySQL schema with the read/write split) are in place. The control-plane API now has first-party authentication (Argon2id passwords, JWT access tokens with rotating refresh tokens, TOTP MFA, API keys), eight default roles, tenant-scoped authorization with an audited platform override, and the organizations API (catalog, settings, features, limits, usage, deletion workflow). Mail-processing features come in later phases. See [docs/architecture/overview.md](docs/architecture/overview.md#what-exists-now-and-what-comes-next) and [docs/plan/execution-plan.md](docs/plan/execution-plan.md).

## Stack

| Layer                        | Technology                                                |
| ---------------------------- | --------------------------------------------------------- |
| Services                     | Node.js 22, TypeScript (strict), NestJS 11, REST          |
| Portal                       | Next.js 15, React 19, Tailwind CSS 4, shadcn/ui           |
| Database                     | MySQL 8.4 + Prisma (version-controlled migrations)        |
| Mail plane                   | Postfix, Rspamd, ClamAV, YARA                             |
| Messaging / cache            | RabbitMQ (quorum queues), Redis                           |
| Storage / search / analytics | AWS S3 (MinIO locally), OpenSearch, ClickHouse            |
| Platform                     | Docker, Kubernetes (Kustomize), Terraform, GitHub Actions |
| Observability                | pino JSON logs, OpenTelemetry, Prometheus, Grafana        |

## Quick start

**Prerequisites:** Node.js ≥ 22.12, pnpm 9 (`corepack enable`), and Docker with Compose v2 (≈ 6 GB RAM for the full stack).

```bash
pnpm install
pnpm env:init                       # creates .env with random local secrets (git-ignored)
docker compose up -d --wait         # MySQL primary + replica, RabbitMQ, Redis, MinIO, Postfix, Rspamd, ClamAV
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

| Service             | Port                                          | Health                                                                                |
| ------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------- |
| api                 | 3000                                          | `/health/live`, `/health/ready`, OpenAPI at `/docs` (business routes under `/api/v1`) |
| admin-portal        | 3001                                          | `/api/health`                                                                         |
| smtp-adapter        | 3010 (HTTP), 10040 (Postfix policy, internal) | `/health/ready`                                                                       |
| email-worker        | 3020                                          | `/health/ready`                                                                       |
| policy-engine       | 3030                                          | `/health/ready`                                                                       |
| delivery-worker     | 3040                                          | `/health/ready`                                                                       |
| notification-worker | 3050                                          | `/health/ready`                                                                       |
| archive-worker      | 3060                                          | `/health/ready`                                                                       |
| Postfix (SMTP)      | 2525 → 25                                     | Container health check                                                                |
| MySQL (primary)     | 3306 (`MYSQL_HOST_PORT`)                      | Container health check                                                                |
| MySQL (replica)     | 3308 (`MYSQL_REPLICA_HOST_PORT`)              | Healthy only while replication runs                                                   |
| RabbitMQ            | 5672, management 15672                        |                                                                                       |
| Redis               | 6379                                          |                                                                                       |
| MinIO               | 9000, console 9001                            |                                                                                       |
| Rspamd              | 11333 (scan), 11334 (controller)              |                                                                                       |
| ClamAV              | 3310                                          |                                                                                       |

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
| `pnpm db:perf`                                        | Database performance test (throwaway schema)                                        |
| `pnpm infra:up` / `pnpm stack:up` / `pnpm stack:down` | Compose shortcuts                                                                   |

## Repository layout

```
apps/
  api/                  REST API: identity, tenants, domains, quarantine, reporting, audit, integrations
  admin-portal/         Next.js admin console
  smtp-adapter/         Postfix policy server (in-session checks); LMTP ingestion next
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

## Engineering rules (short version)

- Strict TypeScript, ESLint, Prettier. No `any`, no `console`.
- No business logic in controllers. No credentials in code or git.
- Apps never import each other. Shared code goes through `packages/*`.
- The tenant comes from authentication or the mail connector, never from headers. Deployment mode is configuration, never a code branch.
- Consumers are idempotent (`processOnce`). Events carry ids and S3 keys, never message bodies.
- Every schema change ships with a reviewed migration.
