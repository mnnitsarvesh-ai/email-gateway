# Deployment: API-mode protection — the mailbox-worker (step API-1)

Design: [docs/plan/steps/35-api-mode-protection.md](../plan/steps/35-api-mode-protection.md) (D4, D5, D7, D10, D11, D16, §5), [ADR-0098](../architecture/adr/0098-protection-modes-and-detect-mode-copies.md), [ADR-0099](../architecture/adr/0099-mailbox-access-consent-and-custody.md), [ADR-0100](../architecture/adr/0100-api-mode-intake-mailbox-worker.md). Worker internals: [apps/mailbox-worker/README.md](../../apps/mailbox-worker/README.md). Provider clients: [packages/mailbox-api/README.md](../../packages/mailbox-api/README.md). Customer guides: [api-mode-microsoft-365.md](../integrations/api-mode-microsoft-365.md), [api-mode-google-workspace.md](../integrations/api-mode-google-workspace.md). Operations: `docs/runbooks/api-mode.md` (step API-1 WP7).

API mode protects a tenant **without an MX change**: the gateway sees mail only as a copy (journal copy through the 8.6 intake, optional mailbox change feeds) and **never delivers, forwards or bounces it** (N1). The mailbox-worker records one detection copy per mailbox, deduplicates journal and feed copies, measures the lag, keeps the mailbox inventory and evaluates coverage and health. In API-1 it only **reads** mailboxes (the consented `Mail.ReadWrite` / `gmail.modify` write scopes are used from API-2).

## What is deployed

| Workload         | Image                          | Replicas  | Talks to                                                                                                                                                  |
| ---------------- | ------------------------------ | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mailbox-worker` | `email-gateway/mailbox-worker` | 2 (PDB 1) | MySQL writer, Redis, RabbitMQ (`eg-mailbox`), the mail bucket (S3), HTTPS to Microsoft Graph, Gmail, Google Admin SDK Directory and 8.2's token endpoints |
| `api`            | `email-gateway/api`            | as before | serves the public Graph notification route (only sets `sync_requested_at`) and the API-mode pages                                                         |
| `event-relay`    | `email-gateway/event-relay`    | as before | `RECONCILE_QUEUES` gains `email.mailbox`                                                                                                                  |

Manifest: `infrastructure/kubernetes/base/mailbox-worker.yaml` (Deployment, ServiceAccount, Service for metrics, PDB, NetworkPolicy; listed in `kustomization.yaml`); configuration keys in `config.yaml` (section "API-mode protection"). Locally the Compose `apps` profile runs one container (`mailbox-worker`, host port `MAILBOX_WORKER_HOST_PORT` 3087, 256 MiB, read-only root file system). HTTP 3087 serves `/health/live`, `/health/ready` (MySQL, Redis, S3, RabbitMQ) and `/metrics` only; provider APIs are deliberately not readiness dependencies.

## Roles (`MAILBOX_WORKER_ROLES`, default `copies,feeds,inventory,health`)

| Role        | What it does                                                                                                                                                                                                                                                                       | Concurrency                                                                                                                                |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `copies`    | Consumes `mail.message.copy_scanned.v1` from `email.mailbox` as `eg-mailbox` (ledger `mailbox-worker.copies`, retry `hold`, reconciled): per-mailbox copy rows, dedupe by Message-ID + mailbox, hybrid inline link, lag, counters (D7)                                             | every replica; prefetch 16                                                                                                                 |
| `feeds`     | Every `API_MODE_FEED_TICK_MS` claims due mailboxes (`FOR UPDATE SKIP LOCKED`, lease 120 s) and runs the Graph Inbox delta (with optional change-notification subscriptions) or the Gmail history; fetches content only when no copy of the Message-ID exists for the mailbox (D10) | every replica; ≤ `API_MODE_FETCH_CONCURRENCY` (16) per replica, ≤ `API_MODE_FETCH_CONCURRENCY_PER_CONNECTION` (4) per connection and claim |
| `inventory` | Per API connection every `API_MODE_INVENTORY_INTERVAL_HOURS` or on request: users of the linked domains, aliases, disabled/deleted, the per-connection cap (D11.1)                                                                                                                 | every replica; one connection at a time per replica (claim + lease)                                                                        |
| `health`    | Leader `GET_LOCK('eg:mailbox:health')`, every `API_MODE_HEALTH_INTERVAL_MS`: coverage per mailbox, connection health, audit + `api_mode_unhealthy` alert outbox rows, pruning, feed start/stop sweeps; flushes the Redis counters every `API_MODE_COUNTER_FLUSH_SECONDS` (D11)     | one leader; the gauges are 0 on the other replicas (aggregate with `max()`)                                                                |

Every outbound event is an outbox row relayed by the event-relay (`mail.message.received.v1` of fetched copies, `notification.alert_requested.v1`); the worker publishes only its own retry and dead-letter hops. A role set without `feeds` and `inventory` holds no credential key and makes no provider call (for example a copies-only Deployment: `MAILBOX_WORKER_ROLES=copies,health`).

## Configuration

All keys are in `.env.example` (section "API-mode protection") and `infrastructure/kubernetes/base/config.yaml`; defaults are the design's (D16). The worker also reads the shared `DATABASE_URL`, `REDIS_URL`, `S3_*`, `INGEST_HEADER_MAX_BYTES`, `PROVIDER_CREDENTIAL_ENCRYPTION_KEY` (+ `_PREVIOUS`), `PROVIDER_M365_LOGIN_URL`, `PROVIDER_M365_GRAPH_URL`, `PROVIDER_GOOGLE_TOKEN_URL`, `PROVIDER_GOOGLE_ADMIN_URL`, `PROVIDER_ALLOW_HTTP_ENDPOINTS` and `PROVIDER_M365_ALLOW_PLATFORM_SECRET`. Refused configurations name the key, never the value:

- `API_MODE_GRAPH_URL`, `API_MODE_GMAIL_URL`, `API_MODE_GOOGLE_ADMIN_URL` must be `https://graph.microsoft.com`, `https://gmail.googleapis.com`, `https://admin.googleapis.com` unless `APP_ENV` is `local`/`ci`; `http:` additionally needs `API_MODE_ALLOW_HTTP_ENDPOINTS=true` (local/ci only).
- `API_MODE_GRAPH_NOTIFICATION_URL` must be `https:` outside local/ci, without credentials, query or fragment; with it, `API_MODE_NOTIFICATION_SECRET` (≥ 32 characters) is required for the `feeds` role.
- The `feeds` and `inventory` roles need `PROVIDER_CREDENTIAL_ENCRYPTION_KEY`; the `copies` role needs `RABBITMQ_MAILBOX_URL`.
- Thresholds stay ordered (coverage fail ≤ warn, lag fail ≥ warn, renew-before < subscription lifetime).

Secrets (Kubernetes, all mounted as `_FILE`): `email-gateway-secrets` keys `database-url`, `redis-url` and the new **`rabbitmq-mailbox-url`** (the `eg-mailbox` user of topology v17); **`email-gateway-api-mode-notification-secret`** key `secret` (64 hex characters, `API_MODE_NOTIFICATION_SECRET`); `email-gateway-provider-credential-key` (as the integration-worker); the optional **`email-gateway-provider-mailbox-platform`** with `m365-mailbox-cert.pem` and `m365-mailbox-cert-thumbprint` (and a Google service-account key file added by an overlay patch that also sets `PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH`, because that path is read whenever it is set). The ConfigMap holds only the platform client ids (`PROVIDER_M365_MAILBOX_APP_CLIENT_ID`, `PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID`); a set client id whose certificate or key file is unreadable stops the worker at start (fail closed, never a silent fallback). Production uses a certificate: `PROVIDER_M365_ALLOW_PLATFORM_SECRET=false`.

## Custody of `PROVIDER_CREDENTIAL_ENCRYPTION_KEY` (ADR-0099)

The mailbox-worker is a **decrypting holder** of 8.2's credential key, besides the integration-worker (verification) and the `ato-respond` Deployment (8.5). It decrypts only the `*.mailbox_remediation` grant of the API connection it works on, through 8.2's `ProviderGrantStore` (AES-GCM, AAD bound to organization, connection, grant and credential version), and obtains tokens through `ProviderTokenService` (in-memory LRU cache only; Microsoft: client credentials for the bound tenant, resource `graph`; Google: JWT bearer with subject = the mailbox for Gmail and = the grant's delegated administrator for the Directory). Tokens never leave process memory; nothing secret is logged, stored, put in an error, an audit row or an outbox row. Key rotation follows the 8.2 procedure (set `_PREVIOUS`, re-encrypt with the integration-worker's maintenance, then remove `_PREVIOUS`) — roll the mailbox-worker together with the integration-worker and the api.

A grant that is not `active` (revoked, error, re-consent pending) is handled at the next claim (D4): feeds stop (`feed_status = revoked`, cursors, subscription ids and client-state hashes cleared; Graph subscriptions expire at the provider and their notifications no longer match), inventory becomes `unavailable`, health reports `mailbox_access.grant`. Journal detect scanning continues (it needs no grant). Restoring the grant restarts the feeds (`pending`) at the next health sweep, without backfill.

## Egress

NetworkPolicy: MySQL (3306), Redis (6379), RabbitMQ (5671/5672), cluster DNS, OTLP (4318), and TCP 443 to **public** addresses only (S3, `graph.microsoft.com`, `gmail.googleapis.com`, `admin.googleapis.com`, `login.microsoftonline.com`, `oauth2.googleapis.com`). The provider client of `@email-gateway/idp-adapters` is the second control: it only calls the configured family origins (provider-returned links are followed only when same-origin and under the base path), never follows redirects, refuses proxy environment variables, caps response bytes and streams MIME bodies (≤ `API_MODE_MAX_MESSAGE_BYTES`, 50 MiB) straight to the mail bucket with SHA-256 and size.

S3 (IRSA role of the ServiceAccount): `s3:PutObject` on `org/*/eml/*` of the mail bucket (fetched copies, `message/rfc822`, deterministic keys so a retry overwrites) and `s3:GetObject` on `org/*/eml/*` (bounded range reads of the header block, `INGEST_HEADER_MAX_BYTES`, for the lag of journal copies). No delete, no archive bucket.

## Graph change notifications and public ingress

Notifications are optional (`feed_mode = notify`, Microsoft 365 only) and are **hints**: the Inbox delta query stays the source of truth, and without them the feed polls every `API_MODE_FEED_POLL_SECONDS` (300 s). To use them:

1. Expose the api route `POST /api/v1/provider-notifications/graph` (and `/graph/lifecycle`) publicly over **https** through the api Ingress (Graph cannot reach a private address). The route is unauthenticated by design but unprivileged (N3): it answers Graph's validation handshake, and for a notification only sets `api_mailboxes.sync_requested_at` after a constant-time client-state hash match on a stored subscription id and a tenant check; it always answers `202` with an empty body, caps the body at 256 KiB and rate-limits per client IP (`API_MODE_NOTIFICATION_RATE_PER_MINUTE`, 1 200).
2. Set `API_MODE_GRAPH_NOTIFICATION_URL` (ConfigMap, per overlay) to that public URL and create `email-gateway-api-mode-notification-secret`. The mailbox-worker derives each mailbox's client state as `HMAC-SHA256(secret, "api-mode-graph-client-state/1\0<mailbox>\0<version>")`, sends it to Graph once and stores only its SHA-256. Rotating the secret invalidates current subscriptions' client states: notifications stop matching (polling continues) until each subscription is re-created; clear `subscription_id` of the affected mailboxes (or toggle the connection's feed mode) to re-create them at once.
3. Subscriptions live `API_MODE_GRAPH_SUBSCRIPTION_MINUTES` (4 230, Graph's maximum for mail) and are renewed `API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES` (720) before expiry; with a live subscription the safety poll is `API_MODE_FEED_SAFETY_POLL_SECONDS` (3 600). Lifecycle events: `reauthorizationRequired` forces a renewal, `subscriptionRemoved` a re-creation, `missed` a sync.

Locally the TEST-ONLY idp-simulator (Compose profile `smtp-test`) posts notifications to `http://api:3000/api/v1/provider-notifications/graph` on the shared Compose network (`http:` is accepted only with `APP_ENV=local|ci`).

## Throttling and `Retry-After`

Every provider call takes one unit of the per-connection, per-family Redis budget first (`mbx:rb:<apiConnectionPublicId>:<family>:s<epochSecond>`, `API_MODE_GRAPH_REQUESTS_PER_SECOND` 8, `API_MODE_GMAIL_REQUESTS_PER_SECOND` 10, `API_MODE_DIRECTORY_REQUESTS_PER_SECOND` 5); a call waits ≤ 1 s for budget, then the mailbox is retried 2 s later (no failure counted). One tenant's connection can never consume another's budget (N7). A `429`, a Google rate-limit `403` or a `503` **with** `Retry-After` pauses the whole connection family for every replica: Redis `mbx:throttle:<apiConnectionPublicId>:<family>` with TTL = `Retry-After` (capped at 600 s; a longer existing pause is kept), `api_mode_connections.throttled_until`, counters `throttled_429` / `throttled_503` and `api_mode_throttled_total`. The mailbox ends `throttled` with `next_sync_at` at the end of the pause; every worker checks the pause before any call of that family. Other retryable failures back off per mailbox (`30 s × 2^(n−1)`, ≤ 1 h; `feed_status = error` from the third consecutive failure).

## Scaling

- **Replicas**: every role is safe on every replica (claims with leases, the ledger, the health leader lock). Two replicas (PDB 1) cover a restart; add replicas for many feed mailboxes. Throughput per tenant is bounded by the provider budgets, not by replicas.
- **Writer pool**: 20 connections per replica (`DATABASE_CONNECTION_LIMIT` in `src/app.module.ts`) plus one advisory-lock connection; at 2 replicas the worker uses ≤ 42 writer connections — include it in the writer budget (`max_connections` 300, 80 % budget) when raising replicas.
- **Memory**: MIME bodies are streamed (multipart upload of 5 MiB parts, queue 2) and Gmail `format=raw` is decoded by the streaming extractor; the 768 MiB limit covers 16 concurrent syncs.
- **Queue**: `email.mailbox` backlog is alerted at 10 000 ready messages (`ApiModeCopyQueueBacklog`); scale replicas or check the copies role's errors.
- **Inventory**: ≤ `API_MODE_MAX_MAILBOXES_PER_CONNECTION` (50 000) in-scope users per connection; beyond, the inventory fails `inventory_limit` without changes.

## Rollout order

1. Migration `api_mode_protection` (migration Job), `pnpm db:seed` (feature `api_mode_protection`), partitions (`api_message_copies`).
2. Topology v17 (`rabbitmq-init` / `init.mjs --users`: queue `email.mailbox`, user `eg-mailbox`), `email.mailbox` in the event-relay's `RECONCILE_QUEUES`.
3. Secrets and ConfigMap keys above; the api Ingress path for notifications if used.
4. `api`, `email-worker`, `smtp-adapter`, `archive-worker`, `integration-worker` (API-1 changes), then the `mailbox-worker`. Nothing on the mail path depends on it: while it is down, copies stay `pending` in the queue (reconciled), feeds and inventory pause, and health shows stale data.

## Metrics and alerts

Series (no organization labels): `api_mode_copies_total{source,result}`, `api_mode_lag_seconds{source}` (buckets 60/300/900/3600/14400), `api_mode_provider_requests_total{provider,family,status_class}`, `api_mode_throttled_total{provider,family}`, `api_mode_feed_syncs_total{provider,result}`, `api_mode_cursor_resets_total{provider}`, `api_mode_fetch_bytes_total{provider}`, `api_mode_inventory_runs_total{provider,result}`, `api_mode_health_transitions_total{health}`, `api_mode_alerts_total{result}`, and the health leader's gauges `api_mode_subscriptions{state}`, `api_mode_mailboxes{coverage}`, `api_mode_connections{health}`; plus the shared `amqp_*` consumer series. Prometheus job `mailbox-worker` (`infrastructure/monitoring/prometheus.yml`); rules `infrastructure/monitoring/rules/api-mode.rules.yml` with promtool tests in `infrastructure/monitoring/tests/api-mode.rules.test.yml`: `ApiModeConnectionsFailing` (critical, 15 min), `ApiModeCoverageGaps` (6 h), `ApiModeLagHigh` (p95 > 900 s, 15 min), `ApiModeThrottlingSustained` (> 0.1/s, 30 min), `ApiModeCursorResets` (any in 1 h), `ApiModeCopyQueueBacklog` (> 10 000 ready, 15 min).

## Local stack

```bash
pnpm --filter @email-gateway/idp-adapters build              # simulators for the idp-simulator
docker compose --profile apps build mailbox-worker           # alone, never in parallel with other builds
docker compose --profile apps up -d --no-deps mailbox-worker
curl -fsS http://127.0.0.1:${MAILBOX_WORKER_HOST_PORT:-3087}/health/ready
```

Host-run: `pnpm --filter @email-gateway/mailbox-worker dev` (reads `../../.env`; the local `.env` points the provider URLs at `http://idp-simulator:8080/…`, which only resolves on the Compose network — override `API_MODE_*_URL` with a published simulator port for a host run). Integration tests: `pnpm --filter @email-gateway/mailbox-worker test:integration` (real MySQL writer, Redis, MinIO and a throwaway RabbitMQ vhost; in-process simulators; synthetic `it-apimode-*` organizations only).
