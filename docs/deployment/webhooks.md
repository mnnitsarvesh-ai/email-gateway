# Deployment: webhooks and security alerts (step 6.2)

Design: [docs/plan/steps/19-webhooks-notifications.md](../plan/steps/19-webhooks-notifications.md) (W1–W13, N1–N4, §4); ADR-0054 (event model), ADR-0055 (signing and delivery), ADR-0056 (security alerts), [ADR-0057](../architecture/adr/0057-idempotent-secret-bearing-routes-redacted-replay.md). Service: [apps/webhook-worker](../../apps/webhook-worker/README.md). Runbook: [webhooks.md](../runbooks/webhooks.md).

## What is deployed

| Workload              | Image                 | Role                                                                                                                                                                     | Broker user / secrets                                                                              |
| --------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `webhook-fanout`      | `webhook-worker`      | `WEBHOOK_WORKER_ROLES=fanout`: consumes `email.webhooks`, writes `webhook_events`, `webhook_deliveries`, alert windows and `notification.alert_requested.v1` outbox rows | `eg-webhook` (`rabbitmq-webhook-url`); `database-url`; the cipher key (required by config, unused) |
| `webhook-delivery`    | `webhook-worker`      | `WEBHOOK_WORKER_ROLES=delivery`: claims, signs and POSTs deliveries, retries, auto-disables, range replays, maintenance (GET_LOCK leader)                                | `database-url`, `redis-url`; **decrypts** with `email-gateway-webhook-secret-key`                  |
| `api`                 | `api`                 | registration, history, replay requests, notification settings and preferences                                                                                            | **encrypts** with `email-gateway-webhook-secret-key`                                               |
| `notification-worker` | `notification-worker` | sends `notification.alert_requested.v1` security alert e-mails (consumes `email.notifications`, new binding in topology v11)                                             | unchanged (`rabbitmq-notification-url`)                                                            |

Compose runs both worker roles in one `webhook-worker` container (apps profile, port 3075). Kubernetes: `infrastructure/kubernetes/base/webhook-fanout.yaml` and `webhook-delivery.yaml` (two replicas each, PDB, zone spread, non-root, read-only root filesystem, probes on `/health/live` and `/health/ready`, Prometheus on `/metrics`). Readiness: fanout = mysql + rabbitmq (`email.events`, `email.webhooks` verified passively); delivery = mysql + redis.

## Rollout order

1. **Migration** `20261112193111_webhooks_notifications` (`prisma migrate deploy`, before any service; it asserts `webhook_subscriptions` / `webhook_deliveries` are empty before adding `public_id`), then `pnpm db:partitions apply` (monthly partitions of `webhook_events` and `webhook_delivery_attempts`, retention 2 months).
2. **Topology v11 and broker users**: re-import `infrastructure/rabbitmq/definitions.json` with `infrastructure/rabbitmq/init.mjs` (queue `email.webhooks` with policy `eg.email.webhooks`, eight source bindings and its retry binding, the `notification.alert_requested.v1` binding of `email.notifications`, user `eg-webhook`, the `ops` user's new retry key). Rerun the 3-node cluster suite for topology changes. From this point `email.webhooks` accumulates events until the fanout runs (bounded at 1 000 000; deploy the fanout promptly, or purge the queue by name if it was filled before any subscription existed).
3. **api** (new Secret mounted, `WEBHOOK_*` keys): subscriptions can be created; nothing is delivered yet.
4. **webhook-worker**: `webhook-fanout` then `webhook-delivery`. Check `webhook_fanout_events_total` and `webhook_delivery_attempts_total` move, and `/health/ready` of both.
5. **notification-worker** (the security alert handler). Alert requests written before it rolls out wait in `email.notifications`.

Rollback: scale `webhook-delivery` to 0 first (stops outbound calls; deliveries stay `pending`), then `webhook-fanout` (events queue in `email.webhooks`, watch [WebhookFanoutBacklog](../runbooks/webhooks.md#webhookfanoutbacklog)). The migration is forward-only.

## Configuration

Shared by the api and the worker (ConfigMap `email-gateway-config`): `WEBHOOK_ALLOWED_PORTS = '443'`, `WEBHOOK_ALLOW_HTTP = 'false'`. Worker keys and bounds are listed in [apps/webhook-worker/README.md](../../apps/webhook-worker/README.md) and set in the Deployments (defaults of §4.4). The TEST-ONLY seams `WEBHOOK_ALLOW_HTTP=true`, `WEBHOOK_TEST_ALLOW_CIDRS`, `WEBHOOK_TEST_DIAL_MAP` and `WEBHOOK_EXTRA_CA_PATH` are refused at startup outside `APP_ENV` `local`/`ci` and are never set in `base` or an overlay.

## Secrets and key custody

| Secret                                             | Keys                           | Mounted in                                | Notes                                                                                                                                                                                                                                                                                                                           |
| -------------------------------------------------- | ------------------------------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `email-gateway-webhook-secret-key` (new)           | `key`, optional `previous-key` | api, webhook-delivery, webhook-fanout     | AES-256-GCM key of `webhook_subscriptions.secret_ciphertext`: 64 hex characters (`openssl rand -hex 32`). The api encrypts, the delivery role decrypts; no other workload holds it. `previous-key` decrypts only (rotation, [runbook](../runbooks/webhooks.md#encryption-key-rotation-webhook_secret_encryption_key_previous)). |
| `email-gateway-secrets` key `rabbitmq-webhook-url` | —                              | webhook-fanout, webhook-delivery (config) | `amqp(s)://eg-webhook:<password>@<broker>/email-gateway`; Amazon MQ needs the user and its permissions from `init.mjs`.                                                                                                                                                                                                         |

Separate from `DATA_ENCRYPTION_KEY` on purpose (custody stays narrow). The fanout role mounts the key only because the shared worker configuration requires it; it never decrypts. Startup errors name keys, never values; signing secrets never appear in logs, metrics, audit rows or idempotency rows.

## Egress

`webhook-delivery` is the **only** workload that reaches tenant endpoints. Its NetworkPolicy (in `webhook-delivery.yaml`) allows MySQL (3306), Redis (6379), cluster DNS (53), the OTLP collector (4318) and **TCP 443 to public addresses only** (private, CGNAT, loopback, link-local/metadata, documentation, multicast and reserved IPv4/IPv6 ranges excluded); no RabbitMQ (the role has no broker client). `webhook-fanout` has no Internet egress (MySQL, RabbitMQ, DNS, OTLP). The SSRF guard in the worker is the authoritative control (every resolved A/AAAA answer checked, the validated IP dialed, the connected address re-checked, no redirects, https and the allowed ports only); the NetworkPolicy is the second layer and NetworkPolicy cannot name FQDNs.

- **DNS**: `WEBHOOK_DNS_SERVERS` empty = the pod resolver. Point it (or the cluster DNS forwarder) at a resolver **without internal zones**, so internal names cannot be resolved for a tenant URL at all; the guard still refuses internal answers.
- **Egress IPs**: tenants may allow-list the platform's NAT gateway addresses; publishing them is a deployment decision outside 6.2.
- No egress proxy is used for webhooks in 6.2 (a CONNECT proxy would hide the connected address from the re-check).

## Sizing (not measured locally)

Per delivery replica: `WEBHOOK_DELIVERY_CONCURRENCY` (32) attempts in flight, each bounded by `WEBHOOK_HTTP_TOTAL_TIMEOUT_MS` (10 s), so a replica sustains ≥ 3 attempts/s against endpoints that all time out and far more against healthy ones. Caps are shared across replicas through Redis: `WEBHOOK_MAX_INFLIGHT_PER_ORG` (16) and `WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION` (4, or the subscription's `max_concurrency`), `WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE` (600). The caps are reserved atomically by one Lua script over three keys (`wh:slots:org:<id>`, `wh:slots:sub:<id>` — sorted sets with one member per reservation scored by its lease expiry, so a killed replica's slots expire after one lease — and `wh:rate:sub:<id>:<minute>`): this needs a single Redis endpoint (ElastiCache non-cluster mode, as for the other services); Redis Cluster would need hash tags and is not supported in 6.2. The fanout's cost is one cache lookup per internal event without a matching subscription and one writer transaction per event that matches (budget `WEBHOOK_FANOUT_TX_TIMEOUT_MS`, 120 s). Production throughput (1 M messages/day per tenant) is reasoned, not measured.

## Monitoring

Prometheus job `webhook-worker` (`webhook-worker:3075/metrics`; in Kubernetes the two Services). Rules: `infrastructure/monitoring/rules/webhooks.rules.yml` (tests in `infrastructure/monitoring/tests/webhooks.rules.test.yml`): WebhookFanoutBacklog, WebhookDeliveryStalled, WebhookOldestDueAge, WebhookDeadLetters, WebhookSsrfBlockedSpike, WebhookFanoutErrors, WebhookRateLimitStoreErrors, SecurityAlertNotificationFailures.

## Local verification

```bash
docker compose --profile smtp-test up -d webhook-receiver   # test endpoint (admin 127.0.0.1:18091)
docker build -f infrastructure/docker/node-service.Dockerfile --build-arg APP=webhook-worker \
  -t email-gateway/webhook-worker:local .                   # one image at a time
docker compose --profile apps up -d --no-deps webhook-worker
curl -s http://127.0.0.1:3075/health/ready
pnpm --filter @email-gateway/webhook-worker test:integration   # real MySQL, Redis, RabbitMQ
```
