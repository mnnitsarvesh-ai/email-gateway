# Policy engine deployment (step 5.2)

Design: [step 5.2](../plan/steps/16-policy-engine.md) (P12–P15, P20, P21, P24, §5); decisions [ADR-0043](../architecture/adr/0043-policy-dsl-and-deterministic-evaluator.md), [ADR-0044](../architecture/adr/0044-policy-evaluation-placement-and-delivery-gating.md), [ADR-0045](../architecture/adr/0045-policy-action-semantics.md). Operations: [runbook](../runbooks/policy-engine.md). Service: [apps/policy-engine](../../apps/policy-engine/README.md).

## What changes for operations

- The `policy-engine` consumes `email.policy.evaluate` (topology v9) and is the **only automatic producer of delivery approvals** (`source = policy`). The development pass-through of the delivery-worker is gone; `DELIVERY_DEV_PASSTHROUGH_ENABLED=true` now **fails startup** in every environment (`removed in step 5.2 (ADR-0044): delivery is approved by the policy-engine; remove the key`). `DELIVERY_DEV_PASSTHROUGH_RISK_HOLD` and `DELIVERY_OUTBOX_*` are ignored.
- **Delivery depends on the policy-engine.** When it is down, mail is held in `scanned` / `scan_failed` (never delivered unchecked) and the queue buffers; alert `PolicyEvaluationsStalled` (critical).
- ALLOW with TAG/WARN header edits delivers a **policy copy** written to the mail bucket under `org/<org>/policy/…` (tag `eg-object=policy-copy`).
- The `notification-worker` consumes `email.notifications` and sends policy alerts and outbound sender non-delivery notices through the transactional relay (`NOTIFY_SMTP_*`).

## Rollout order

1. **Migration** `20261111021501_policy_engine` (Job, `prisma migrate deploy`; additive, backward compatible: the previous release ignores the new tables and columns). Legacy-format demo policies are retired (disabled), never deleted.
2. **Topology v9 and broker users**: run `rabbitmq-init` (`infrastructure/rabbitmq/init.mjs --users --cleanup-legacy`; it prunes the old `email.archive` binding) with `RABBITMQ_POLICY_ENGINE_USER/PASSWORD` and `RABBITMQ_NOTIFICATION_USER/PASSWORD`. Create the Secret keys below. See [rabbitmq-messaging.md](../runbooks/rabbitmq-messaging.md) "Upgrading to v9".
3. **api** (policy management, departments, test/dry-run, history). Tenants can author and publish policies before the engine runs; nothing is evaluated yet.
4. **policy-engine** (≥ 2 replicas). From this moment it evaluates every queued round: **the backlog of held `scanned` messages** (everything scanned since v9 was applied with no consumer, and, where the pass-through never ran, everything waiting in `scanned`) is evaluated under the generation current at evaluation time. Rounds already decided, rescanned or expired are skipped (`policy_lifecycle_skipped_total`). Watch `policy_evaluations_total` and the queue depth; expect a burst of approvals.
5. **delivery-worker** without the pass-through keys (remove `DELIVERY_DEV_PASSTHROUGH_*` and `DELIVERY_OUTBOX_*` from its environment first; a `true` left behind stops the rollout at readiness, which is intended).
6. **notification-worker**.
7. **event-relay**: add `email.policy.evaluate` and `email.notifications` to `RECONCILE_QUEUES` (both done in the base manifests).

Rollback: scale the policy-engine to 0 → mail is held (not delivered) until it is back. Do **not** re-enable a pass-through: there is none.

## Configuration (§5)

| Key                                                                                                                                                                     | Service                        | Default                       | Bounds                              |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ----------------------------- | ----------------------------------- |
| `RABBITMQ_POLICY_ENGINE_URL` (`_FILE`)                                                                                                                                  | policy-engine                  | —                             | role user `eg-policy-engine`        |
| `POLICY_PLATFORM_DEFAULT`                                                                                                                                               | policy-engine, api (ConfigMap) | `pol-default/1`               | a key of `POLICY_PLATFORM_DEFAULTS` |
| `POLICY_EVALUATE_PREFETCH`                                                                                                                                              | policy-engine                  | 8                             | 1–64                                |
| `POLICY_DB_TX_TIMEOUT_MS`                                                                                                                                               | policy-engine                  | 120 000                       | 120 000–600 000                     |
| `POLICY_SNAPSHOT_CACHE_MAX_ENTRIES`                                                                                                                                     | policy-engine                  | 1000                          | 10–100 000                          |
| `POLICY_COPY_MAX_MESSAGE_BYTES` / `POLICY_COPY_MAX_HEADER_BYTES`                                                                                                        | policy-engine                  | 25 MiB / 256 KiB              | 1–50 MiB / 16 KiB–1 MiB             |
| `POLICY_COPY_RETENTION_DAYS`                                                                                                                                            | minio-init, S3 lifecycle       | 30                            | 1–365                               |
| `POLICY_MAX_POLICIES`, `POLICY_MAX_VERSIONS_PER_POLICY`, `POLICY_MAX_ACTIVE_RULES`, `POLICY_HISTORY_MAX_RANGE_DAYS`, `DEPARTMENT_MAX_PER_ORG`, `DEPARTMENT_MAX_MEMBERS` | api                            | 100, 200, 1000, 31, 500, 5000 | see `.env.example`                  |
| `RABBITMQ_NOTIFICATION_URL` (`_FILE`), `NOTIFICATION_PREFETCH`, `NOTIFICATION_DB_TX_TIMEOUT_MS`, `NOTIFICATION_MAX_RECIPIENTS`                                          | notification-worker            | —, 4, 120 000, 50             | 1–32, 120 000–600 000, 1–500        |

## Kubernetes

`infrastructure/kubernetes/base/policy-engine.yaml` (Deployment ≥ 2 replicas, HPA 2–10, PDB `minAvailable: 1`, zone spread, probes `/health/live` and `/health/ready` — readiness = mysql, rabbitmq, redis, s3 — read-only root, `terminationGracePeriodSeconds: 150` > one evaluation budget), `notification-worker.yaml`, the api bounds in `api.yaml`, `POLICY_PLATFORM_DEFAULT` in the ConfigMap, `RECONCILE_QUEUES` in `event-relay.yaml`. The delivery-worker manifest never carried pass-through keys. Render with `kubectl kustomize infrastructure/kubernetes/overlays/{saas,dedicated}`.

New keys of the `email-gateway-secrets` Secret (External Secrets):

| Secret key                        | Read as                           | Used by                                                               |
| --------------------------------- | --------------------------------- | --------------------------------------------------------------------- |
| `rabbitmq-policy-engine-url`      | `RABBITMQ_POLICY_ENGINE_URL_FILE` | policy-engine (`eg-policy-engine`, one URL per node, comma-separated) |
| `rabbitmq-notification-url`       | `RABBITMQ_NOTIFICATION_URL_FILE`  | notification-worker (`eg-notification`)                               |
| `notify-smtp-password` (existing) | `NOTIFY_SMTP_PASSWORD_FILE`       | api, notification-worker                                              |

The notification-worker reads `NOTIFY_SMTP_HOST`, `NOTIFY_SMTP_FROM`, `NOTIFY_SMTP_USER` and `PORTAL_PUBLIC_URL` from the overlay / ConfigMap like the api (TLS: `NOTIFY_SMTP_SECURE=starttls`).

## S3 / IAM

- The policy-engine's role (IRSA) needs on the mail bucket: `s3:GetObject` on `org/*/eml/*` and `org/*/rewrite/*` (the delivered base object), `s3:PutObject` **with** `s3:PutObjectTagging` on `org/*/policy/*` (the tag is set on the creating request; multipart uploads also need `s3:AbortMultipartUpload`), `s3:DeleteObject` on `org/*/policy/*` (cleanup of a failed upload), `s3:ListBucket`/`HeadBucket` for readiness. No access to other prefixes is required.
- Lifecycle rule `eg-policy-copy-expiry` on the mail bucket: filter tag `eg-object = policy-copy`, expiration `POLICY_COPY_RETENTION_DAYS` (30), noncurrent versions after 1 day. Locally `infrastructure/minio/init-buckets.sh` installs it next to `eg-rewrite-expiry` (`mc ilm import` replaces the whole configuration, so both rules are written together). The Terraform mail-storage module (`aws_s3_bucket_lifecycle_configuration.mail`) has only `expire-processed-mail` and does not define the step 4.3 rewrite rule either: add `eg-rewrite-expiry` and `eg-policy-copy-expiry` to it together (open item, recorded in the step note).
- Copies are written inside the evaluation transaction before the outbox rows; a copy whose evaluation rolled back is an orphan the rule removes.

## Monitoring

Prometheus scrapes `policy-engine:3030/metrics` and `notification-worker:3050/metrics` (`infrastructure/monitoring/prometheus.yml`). Alerts `infrastructure/monitoring/rules/policy-engine.rules.yml` (promtool tests in `tests/policy-engine.rules.test.yml`): `PolicyEvaluationsStalled` (critical), `PolicyInputErrors`, `PolicySnapshotInvalidVersion`, `PolicyInconsistentReads`, `PolicyRiskMissing`, `PolicyNotificationFailures`. The delivery-worker's `delivery_approvals_total{object}` gains `policy_copy`; the pass-through series (`delivery_approvals_skipped_total`, `delivery_risk_holds_total`, `delivery_dlp_holds_total`, `delivery_dlp_alerts_approved_total`, `delivery_bec_ai_only_not_held_total`, `delivery_outbox_*`) no longer exist: remove them from dashboards.

## Local

`docker compose --profile apps up -d --wait` runs the policy-engine and notification-worker (see [local-stack.md](../runbooks/local-stack.md)). Existing `.env`: remove `DELIVERY_DEV_PASSTHROUGH_*` and append the "Policy engine (step 5.2 …)" section of `.env.example`; re-run `docker compose run --rm --no-deps minio-init` for the lifecycle rule.
