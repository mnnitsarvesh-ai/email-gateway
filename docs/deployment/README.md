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
- **EC2 Auto Scaling Groups** run Postfix inbound and outbound, with EBS spools behind an NLB on port 25. The spool must outlive any pod. Details (listeners, security groups, static egress IPs, drain and instance refresh, DKIM signer and redis-dkim): [SMTP gateway deployment](smtp-gateway.md). The inbound Rspamd (milter and scan engine, step 4.1): [Rspamd deployment](rspamd.md). Routing per direction, the delivery log and its status-reader sidecar, retry schedule and egress rules (step 2.3): [Mail routing and delivery tracking](mail-routing.md).
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

| Secret key               | Read as                                                     | Used by                      | Points at                                                                                          |
| ------------------------ | ----------------------------------------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| `database-url`           | `DATABASE_URL_FILE`                                         | every service                | MySQL **writer**: the RDS instance endpoint, or the Aurora cluster (writer) endpoint (DML account) |
| `database-read-url`      | `DATABASE_READ_URL_FILE`                                    | `api` only                   | MySQL **reader**: an RDS read replica endpoint, or the Aurora reader endpoint (reader account)     |
| `migration-database-url` | `MIGRATION_DATABASE_URL` (migration Job, not in `base` yet) | `db-migrate`                 | MySQL writer, migrator (DDL) account                                                               |
| `rabbitmq-url`           | `RABBITMQ_URL_FILE`                                         | every service                | Amazon MQ / RabbitMQ                                                                               |
| `redis-url`              | `REDIS_URL_FILE`                                            | every service                | ElastiCache Redis                                                                                  |
| `auth-jwt-secret`        | `AUTH_JWT_SECRET_FILE`                                      | `api` only                   | HMAC key for access tokens (at least 64 characters)                                                |
| `auth-token-pepper`      | `AUTH_TOKEN_PEPPER_FILE`                                    | `api` only                   | HMAC pepper for API-key and recovery-code hashes (at least 64 characters)                          |
| `data-encryption-key`    | `DATA_ENCRYPTION_KEY_FILE`                                  | `api` only                   | AES-256-GCM key, exactly 64 hex characters (application-encrypted columns such as MFA secrets)     |
| `notify-smtp-password`   | `NOTIFY_SMTP_PASSWORD_FILE`                                 | `api`, `notification-worker` | Password of the transactional-email relay (SES SMTP or similar); optional                          |

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
- Business routes are served under `/api/v1`; probes stay on `/health/*` and the Prometheus scrape on `/metrics`, both internal. Since step 6.1 the base `api.yaml` has an `Ingress` (class nginx, host placeholder `api.replace-per-environment.invalid`, TLS Secret `api-tls`, set per environment) that routes **only** `Prefix /api/v1/` to the api Service; never add `/metrics`, `/health` or `/docs` to it (`apps/api/test/public-boundary.e2e.test.ts` fails, [ADR-0053](../architecture/adr/0053-public-internal-api-boundary.md)). A load balancer in front of it must forward `/api/v1/*` only.

### REST API conventions (step 6.1)

- **New Secret** `email-gateway-api-cursor-key` (External Secrets), **api only**: key `key` = 64 random hex characters (`openssl rand -hex 32`), mounted at `/var/run/secrets/api-cursor` and read as `API_CURSOR_KEY_FILE` (required: a missing or malformed key fails startup, the error names the key only); optional key `previous-key` = the previous key during a rotation (`API_CURSOR_KEY_PREVIOUS`, verification only). Rotation: [runbook](../runbooks/api-rate-limits-and-reports.md#cursor-key-rotation).
- **Non-secret keys** (set on the api container in `api.yaml`, defaults of `.env.example` section "REST API conventions (step 6.1)"): `API_CURSOR_TTL_SECONDS` (86 400), `API_RATE_PRINCIPAL_PER_MINUTE` (600), `API_RATE_TENANT_DEFAULT_PER_MINUTE` (300), `API_RATE_TENANT_MIN_PER_MINUTE` (10), `API_RATE_TENANT_MAX_PER_MINUTE` (10 000), `API_RATE_SENSITIVE_PER_MINUTE` (30), `API_RATE_EXPENSIVE_PER_MINUTE` (60), `API_RATE_LIMIT_CACHE_SECONDS` (60), `API_IDEMPOTENCY_LEGACY_MODE` (`enforce`), `API_IDEMPOTENCY_PENDING_TTL_SECONDS` (300), `API_LIST_SCAN_BUDGET_ROWS` (5 000), `API_MESSAGES_MAX_RANGE_DAYS` (31), `API_AUDIT_MAX_RANGE_DAYS` (90), `REPORTS_MAX_RANGE_DAYS` (31), `REPORTS_CACHE_TTL_SECONDS` (60), `REPORTS_QUERY_TIMEOUT_MS` (10 000), `RECIPIENT_SUPPRESSIONS_MAX_MANUAL` (100 000).
- **Redis** is now on the request path of every authenticated api call (global rate limiter, fail closed: a Redis outage answers `503`); size and monitor it accordingly (alert `ApiRateLimitStoreErrors`).
- **Replica**: the new list, report and billing routes read the replica; report queries are bounded by `MAX_EXECUTION_TIME` (`REPORTS_QUERY_TIMEOUT_MS`).
- **Rollout order:** migration `rest_api` (online DDL: two `email_messages` indexes, one `delivery_suppressions` index, `api_idempotency_keys.state`) → the Secret → the api. Clients of the 22 legacy sensitive routes must send `Idempotency-Key` (or run the api with `API_IDEMPOTENCY_LEGACY_MODE=warn` during a transition).
- **Monitoring:** Prometheus scrapes the api's `/metrics` in-cluster (job `api`); rules `infrastructure/monitoring/rules/api.rules.yml`.
- Rendered with `kubectl kustomize` (both overlays); not applied to a cluster in this repository.

### Domain onboarding and DNS (step 2.1)

The api verifies customer domains and checks their MX, SPF, DKIM and DMARC records itself ([ADR-0017](../architecture/adr/0017-dns-resolution-strategy.md)); the background checks run inside the api (`DOMAIN_BACKGROUND_JOBS_ENABLED`, safe with several replicas). Every key is listed with its default in `.env.example` and validated at startup; error messages name the key, never the value.

- **Required per environment (no default):** `GATEWAY_MX_HOSTS` (comma list of `priority:host`, the gateway's public MX names that customers point their domains at, e.g. `10:mx1.mail.example.net,20:mx2.mail.example.net`) and `GATEWAY_SPF_INCLUDE` (the SPF record customers include, e.g. `_spf.mail.example.net`). The base ConfigMap carries `replace-per-environment.invalid` placeholders; every overlay must replace them, and the names must resolve before customers are onboarded. Customers can never onboard these names (they are reserved), nor names under `DOMAIN_RESERVED_SUFFIXES`.
- **Optional:** `GATEWAY_DMARC_RUA` / `GATEWAY_DMARC_RUF` (comma lists of `mailto:` URIs added to DMARC recommendations). A destination outside the customer's domain needs an authorization record `<customer domain>._report._dmarc.<destination domain>` (RFC 7489 §7.1), e.g. a wildcard `*._report._dmarc.mail.example.net TXT "v=DMARC1"` published by the operator.
- **Resolver mode.** `DNS_RESOLVER_MODE=system` (default) uses `node:dns` against `DNS_SERVERS` (comma list of `ip`, `ip:port`, `[ipv6]:port`; empty = the pod's resolver, i.e. cluster DNS / the VPC resolver). Prefer a validating caching resolver you operate (e.g. Unbound) when the platform resolver rewrites or filters answers. `DNS_RESOLVER_MODE=doh` uses DNS-over-HTTPS (RFC 8484 wire format) against `DNS_DOH_URL`; `https://` is required outside `local`/`ci` and URLs with credentials are rejected. DoH reports real TTLs; system mode cannot (answers are then cached for at most `DNS_CACHE_NEGATIVE_TTL_SECONDS`).
- **DoH privacy.** In `doh` mode every customer domain name the api checks (and its SPF include targets) is sent to the DoH provider. Use a provider covered by your data-processing terms, or a self-hosted DoH endpoint, for dedicated deployments with data-residency requirements. DNSSEC validation is delegated to the chosen upstream; the gateway records the DoH `AD` flag as evidence only.
- **Propagation upstreams.** `DNS_PROPAGATION_UPSTREAMS` (same syntax as the mode: IPs for `system`, URLs for `doh`) adds resolvers queried only for MX: an MX record counts as valid only when every definitive answer agrees with the primary resolver. Leave it empty to skip the check; unreachable upstreams only add a warning.
- **Timeouts and cache.** `DNS_TIMEOUT_MS` per try × `DNS_TRIES` must fit in `DOMAIN_CHECK_DEADLINE_MS` (validated). Definitive answers are cached in Redis under `eg:dns:v1:*` for at most `DNS_CACHE_MAX_TTL_SECONDS` (`0` disables the cache); timeouts and `SERVFAIL` are never cached and never change a domain's status.
- **Jobs and schedule:** `DOMAIN_JOBS_INTERVAL_SECONDS`, `DOMAIN_CHECK_BATCH_SIZE`, `DOMAIN_CHECK_CONCURRENCY`, `DOMAIN_RETRY_BASE_SECONDS` / `DOMAIN_RETRY_MAX_SECONDS` (backoff), `DOMAIN_RECHECK_INCOMPLETE_SECONDS`, `DOMAIN_RECHECK_INTERVAL_SECONDS`, `DOMAIN_VERIFICATION_TTL_DAYS`, `DOMAIN_VERIFICATION_LABEL` and `DKIM_ROTATION_OVERLAP_DAYS` have production defaults in the ConfigMap.
- **Egress:** the api pods need outbound DNS (UDP and TCP 53) to the configured resolvers, or HTTPS to the DoH endpoint. No secret is added by this step; DKIM private keys are encrypted with the existing `data-encryption-key` ([ADR-0018](../architecture/adr/0018-dkim-key-custody.md)).

### SMTP gateway (step 2.2)

Inbound MX (`postfix`), outbound MTA (`postfix-outbound`: submission 587, connector relay 25, reinjection 10026/10027), the DKIM signer `rspamd-outbound` and its key store `redis-dkim`, and the test-only sinks of the `smtp-test` profile are described in [smtp-gateway.md](smtp-gateway.md), including every environment key, the fail-closed behaviour without smtp-adapter and the deviations from the design. New secrets: `REDIS_DKIM_WRITER_PASSWORD`, `REDIS_DKIM_READER_PASSWORD`, `REDIS_DKIM_PROBE_PASSWORD` (redis-dkim, rspamd-outbound; as URLs for the api and smtp-adapter) and `GATEWAY_TRACE_SECRET` (smtp-adapter).

### Security scanning (step 4.1)

The inbound `rspamd` is both the SMTP-time milter of the inbound Postfix (rejects only GTUBE and score >= `RSPAMD_MILTER_REJECT_SCORE`; Postfix **accepts** when it is down, `milter_default_action = accept`, [ADR-0027](../architecture/adr/0027-rspamd-milter-policy.md)) and the post-queue scan engine of the email-worker's scan role (`/checkv2`, [ADR-0026](../architecture/adr/0026-security-scan-pipeline.md)). Topology, every `RSPAMD_*` key, production feeds (Spamhaus DQS, SURBL/URIBL, OpenPhish, bad-URL map) as configuration, the recursive resolver requirement, dedicated Redis and sizing, Bayes/fuzzy operations, memory, local verification and the deviations from the design: [rspamd.md](rspamd.md). New secrets: `RSPAMD_CONTROLLER_PASSWORD` (rspamd, email-worker), `RSPAMD_CONTROLLER_ENABLE_PASSWORD` (rspamd, api), `RABBITMQ_SCANNER_PASSWORD` (rabbitmq-init, email-worker scan role), optional `RSPAMD_SPAMHAUS_DQS_KEY` (rspamd, production).

### Policy engine (step 5.2)

The `policy-engine` (EKS Deployment, ≥ 2 replicas) consumes `email.policy.evaluate` as `eg-policy-engine` and is the **only automatic producer of delivery approvals**; the delivery-worker's development pass-through is removed (`DELIVERY_DEV_PASSTHROUGH_ENABLED=true` is refused). The `notification-worker` consumes `email.notifications` as `eg-notification` and sends policy alerts and sender notices through the transactional relay. Rollout order (migration → topology v9 + broker users → api → policy-engine → delivery-worker → notification-worker), the backlog of held `scanned` messages evaluated at activation, the S3 lifecycle rule `eg-policy-copy-expiry`, IAM, Kubernetes and the new Secret keys `rabbitmq-policy-engine-url` / `rabbitmq-notification-url`: [policy-engine.md](policy-engine.md). Runbook: [policy-engine](../runbooks/policy-engine.md).

### Webhooks and security alerts (step 6.2)

The `webhook-worker` image runs as two Deployments: `webhook-fanout` (consumes `email.webhooks` as `eg-webhook` and projects internal events into public webhook events, deliveries and security alert requests) and `webhook-delivery` (signs and POSTs through the SSRF-guarded client; the **only** workload with Internet egress for webhooks, TCP 443 to public addresses). Rollout order (migration → topology v11 + `eg-webhook` → api → webhook-worker → notification-worker), the new Secret `email-gateway-webhook-secret-key` (api encrypts, webhook-delivery decrypts) and the Secret key `rabbitmq-webhook-url`, egress, DNS and sizing: [webhooks.md](webhooks.md). Runbook: [webhooks](../runbooks/webhooks.md).

## Terraform

See `infrastructure/terraform/README.md`. Remote state is per AWS account, and `backend.hcl` is not committed.
