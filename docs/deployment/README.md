# Deployment

## Environments

| Environment                 | Where                                  | How                                                                                                                   |
| --------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Local                       | Docker Compose                         | `docker-compose.yml` (see the root README)                                                                            |
| CI                          | GitHub Actions                         | `.github/workflows/ci.yml`: lint, typecheck, unit/e2e, migrations, then the full Compose stack with integration tests |
| Staging / Production (SaaS) | AWS EKS (ap-south-1), DR in ap-south-2 | `infrastructure/kubernetes/overlays/saas` + Terraform                                                                 |
| Dedicated customer          | Customer-specific AWS account or VPC   | `infrastructure/kubernetes/overlays/dedicated` + Terraform variables                                                  |

## Topology

- **EKS** runs the stateless Node services and the admin portal (`infrastructure/kubernetes/base`). Each Deployment has liveness, readiness and startup probes, an HPA, a PDB, zone spread and a hardened security context.
- **EC2 Auto Scaling Groups** run Postfix inbound and outbound, with EBS spools behind an NLB on port 25. The spool must outlive any pod.
- **Managed services** (via Terraform): RDS/Aurora MySQL 8.4 (writer plus a reader endpoint for the api's control-plane reads), ElastiCache Redis, Amazon MQ for RabbitMQ (or self-managed), Amazon OpenSearch, S3 + KMS, and ClickHouse (Cloud or EC2).

## Release flow

1. Merge to `main` → CI green.
2. Build images once per commit, tag them with the git SHA, and push to ECR. _(Added with the infrastructure phase.)_
3. Run the migration Job (`APP=database` image, `prisma migrate deploy`) **before** rolling out services. Migrations must be backwards compatible with the previous release.
4. Roll out with `maxUnavailable: 0`. Readiness gates traffic.

## Building images

```bash
docker build -f infrastructure/docker/node-service.Dockerfile --build-arg APP=api -t email-gateway/api .
docker build -f infrastructure/docker/node-service.Dockerfile --build-arg APP=database -t email-gateway/db-migrate .
docker build -f infrastructure/docker/admin-portal.Dockerfile -t email-gateway/admin-portal .
```

One recipe builds every Nest service: `pnpm deploy` produces a pruned production bundle, and the Prisma client is generated inside it.

## Kubernetes

```bash
kubectl kustomize infrastructure/kubernetes/overlays/saas        # render
kubectl apply -k infrastructure/kubernetes/overlays/saas         # apply
```

The manifests expect an `email-gateway-secrets` Secret (managed by External Secrets), mounted at `/var/run/secrets/gateway` and read through the `<KEY>_FILE` convention, plus per-environment values for the ConfigMap.

| Secret key               | Read as                                                     | Used by       | Points at                                                                                          |
| ------------------------ | ----------------------------------------------------------- | ------------- | -------------------------------------------------------------------------------------------------- |
| `database-url`           | `DATABASE_URL_FILE`                                         | every service | MySQL **writer**: the RDS instance endpoint, or the Aurora cluster (writer) endpoint (DML account) |
| `database-read-url`      | `DATABASE_READ_URL_FILE`                                    | `api` only    | MySQL **reader**: an RDS read replica endpoint, or the Aurora reader endpoint (reader account)     |
| `migration-database-url` | `MIGRATION_DATABASE_URL` (migration Job, not in `base` yet) | `db-migrate`  | MySQL writer, migrator (DDL) account                                                               |
| `rabbitmq-url`           | `RABBITMQ_URL_FILE`                                         | every service | Amazon MQ / RabbitMQ                                                                               |
| `redis-url`              | `REDIS_URL_FILE`                                            | every service | ElastiCache Redis                                                                                  |
| `auth-jwt-secret`        | `AUTH_JWT_SECRET_FILE`                                      | `api` only    | HMAC key for access tokens (at least 64 characters)                                                |
| `auth-token-pepper`      | `AUTH_TOKEN_PEPPER_FILE`                                    | `api` only    | HMAC pepper for API-key and recovery-code hashes (at least 64 characters)                          |
| `data-encryption-key`    | `DATA_ENCRYPTION_KEY_FILE`                                  | `api` only    | AES-256-GCM key, exactly 64 hex characters (application-encrypted columns such as MFA secrets)     |
| `notify-smtp-password`   | `NOTIFY_SMTP_PASSWORD_FILE`                                 | `api`         | Password of the transactional-email relay (SES SMTP or similar); optional                          |

`database-read-url` is **required** by the `api` Deployment: a missing file fails startup. An environment without a replica sets it to the writer URL; the api then reports `writer-fallback` (`not a replica`) and reads from the writer. The ConfigMap carries `DATABASE_READ_MAX_LAG_SECONDS` (`'10'`) and `DATABASE_READ_LAG_CHECK_INTERVAL_MS` (`'5000'`). Data-plane Deployments get no reader URL: they are writer-only by design.

### MySQL on RDS / Aurora

- `DATABASE_URL` → the RDS instance or Aurora **cluster (writer) endpoint**. `DATABASE_READ_URL` → an RDS **read replica** endpoint or the Aurora **reader endpoint**.
- The reader account needs `SELECT` on the schema plus `REPLICATION CLIENT` (for the lag probe), and nothing else.
- The lag probe uses `SHOW REPLICA STATUS`, which works on RDS for MySQL read replicas. Aurora replicas return no rows, so on Aurora the api stays in `writer-fallback` until the Aurora probe (`information_schema.replica_host_status`) lands, which is planned for step 10.1.

Details: [docs/database/replication.md](../database/replication.md).

### Authentication, tenancy and transactional email (step 1.2/1.3)

- The three auth secrets above are **required** by the `api`: a missing or too-short value fails startup. Never rotate `auth-token-pepper` (stored API-key and recovery-code hashes depend on it). To rotate `auth-jwt-secret` or `data-encryption-key`, put the old value in `AUTH_JWT_PREVIOUS_SECRET` / `DATA_ENCRYPTION_KEY_PREVIOUS` (also as secret files) for one rotation window, then remove it.
- The ConfigMap carries `HTTP_TRUST_PROXY` (`'1'`: one proxy hop, the ALB/ingress, so client IPs and rate limits use the real address), `PORTAL_PUBLIC_URL` (set per overlay, must be `https://` in staging and production; links in invitation, reset and verification emails), the token TTL defaults (`AUTH_ACCESS_TOKEN_TTL_SECONDS`, `AUTH_REFRESH_TOKEN_TTL_SECONDS`, `AUTH_SESSION_MAX_AGE_SECONDS`, `AUTH_PASSWORD_RESET_TTL_SECONDS`, `AUTH_EMAIL_VERIFICATION_TTL_SECONDS`, `AUTH_INVITATION_TTL_SECONDS`), `NOTIFY_SMTP_PORT` (`'587'`) and `NOTIFY_SMTP_SECURE` (`starttls`). The remaining `AUTH_*`, `PLATFORM_OVERRIDE_MAX_MINUTES` and `ORG_DELETION_*` keys have safe defaults (see `.env.example`).
- `NOTIFY_SMTP_HOST`, `NOTIFY_SMTP_USER` and `NOTIFY_SMTP_FROM` are set per overlay. Locally the api submits to the `postfix-notify` smarthost, which relays upstream with SASL and a pinned certificate (`NOTIFY_RELAY_*`; see docs/security/authentication.md). In clusters the same role moves to the outbound Postfix tier built in step 2.2; until then point `NOTIFY_SMTP_HOST` at a relay that handles PIPELINING correctly. Without `NOTIFY_SMTP_HOST` the api only logs outbound emails (and warns at startup in production). `NOTIFY_SMTP_SECURE=none` is rejected outside `local`/`ci`, and certificate verification is always on.
- Business routes are served under `/api/v1`; the load balancer rule added with the infrastructure phase must forward `/api/*` to the api Service. Probes stay on `/health/*`.

## Terraform

See `infrastructure/terraform/README.md`. Remote state is per AWS account, and `backend.hcl` is not committed.
