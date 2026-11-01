# Email Security Gateway

A multi-tenant email security gateway: inbound, outbound and internal mail inspection, spam and phishing detection, malware and attachment scanning, URL protection, BEC detection, DLP, quarantine and optional archiving. It runs as shared SaaS or as a dedicated per-customer deployment. The design target is **1M emails/day**, scaling horizontally beyond that.

> **Status: Phase 0 (foundation).** The monorepo, shared packages, service shells with health checks, the initial schema and migrations, the local stack, CI, and the architecture docs are in place. Mail-processing features come in later phases. See [docs/architecture/overview.md](docs/architecture/overview.md#what-exists-now-and-what-comes-next).

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
docker compose up -d --wait         # MySQL, RabbitMQ, Redis, MinIO, Postfix, Rspamd, ClamAV
pnpm db:migrate                     # apply database migrations
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

On first start, ClamAV downloads about 300 MB of signatures. `--wait` blocks until it is healthy, which can take a few minutes.

Optional profiles: `--profile analytics` (OpenSearch, ClickHouse) and `--profile observability` (OpenTelemetry Collector, Prometheus, Grafana).

## Services and ports

All ports bind to `127.0.0.1`. You can change any host port in `.env` (`*_HOST_PORT`) if it clashes with something else on your machine.

| Service             | Port                                          | Health                                              |
| ------------------- | --------------------------------------------- | --------------------------------------------------- |
| api                 | 3000                                          | `/health/live`, `/health/ready`, OpenAPI at `/docs` |
| admin-portal        | 3001                                          | `/api/health`                                       |
| smtp-adapter        | 3010 (HTTP), 10040 (Postfix policy, internal) | `/health/ready`                                     |
| email-worker        | 3020                                          | `/health/ready`                                     |
| policy-engine       | 3030                                          | `/health/ready`                                     |
| delivery-worker     | 3040                                          | `/health/ready`                                     |
| notification-worker | 3050                                          | `/health/ready`                                     |
| archive-worker      | 3060                                          | `/health/ready`                                     |
| Postfix (SMTP)      | 2525 → 25                                     | Container health check                              |
| MySQL               | 3306                                          |                                                     |
| RabbitMQ            | 5672, management 15672                        |                                                     |
| Redis               | 6379                                          |                                                     |
| MinIO               | 9000, console 9001                            |                                                     |
| Rspamd              | 11333 (scan), 11334 (controller)              |                                                     |
| ClamAV              | 3310                                          |                                                     |

## Common commands

| Command                                               | Does                                            |
| ----------------------------------------------------- | ----------------------------------------------- |
| `pnpm build` / `pnpm dev`                             | Build / run all workspaces (Turborepo)          |
| `pnpm lint` / `pnpm typecheck` / `pnpm format`        | Code quality                                    |
| `pnpm test`                                           | Unit tests                                      |
| `pnpm test:e2e`                                       | In-process API e2e tests (dependencies stubbed) |
| `pnpm test:integration`                               | Tests against the running Compose stack         |
| `pnpm db:migrate` / `db:migrate:dev` / `db:status`    | Prisma migrations                               |
| `pnpm infra:up` / `pnpm stack:up` / `pnpm stack:down` | Compose shortcuts                               |

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
- [Database conventions and migrations](docs/database/README.md)
- [API conventions](docs/api/README.md)
- [Security baseline](docs/security/README.md)
- [Deployment](docs/deployment/README.md)
- [Runbook: local stack](docs/runbooks/local-stack.md)

## Engineering rules (short version)

- Strict TypeScript, ESLint, Prettier. No `any`, no `console`.
- No business logic in controllers. No credentials in code or git.
- Apps never import each other. Shared code goes through `packages/*`.
- The tenant comes from authentication or the mail connector, never from headers. Deployment mode is configuration, never a code branch.
- Consumers are idempotent (`processOnce`). Events carry ids and S3 keys, never message bodies.
- Every schema change ships with a reviewed migration.
