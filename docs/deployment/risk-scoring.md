# Risk scoring deployment (step 5.1)

Design: [15-risk-scoring.md](../plan/steps/15-risk-scoring.md) (R10, R13, R16, R17, §3, §5), [ADR-0041](../architecture/adr/0041-risk-scoring-model.md) (the model), [ADR-0042](../architecture/adr/0042-risk-scoring-placement-and-policy-handoff.md) (placement and hand-off). Operations: [runbook](../runbooks/risk-scoring.md). Calibration: [docs/performance/risk-scoring-calibration.md](../performance/risk-scoring-calibration.md).

**What this deploys, plainly.** The email-worker scores every completed scan round and stores the result; the api serves profiles, the dry-run and the scores in the scans read API. Nothing is enforced from the score outside local/ci: policy (5.2) and quarantine (5.3) are not built, and the only reader that acts on a score is the development pass-through of the delivery-worker, which is refused outside `APP_ENV=local|ci`. The default weights and thresholds are engineering defaults calibrated on a synthetic dataset; **they are not validated detection accuracy.**

## Topology

No new Deployment, queue, event, topology version or secret.

- **Every scan-role email-worker** (`email-worker` scan Deployment, `email-worker-attachment`, `-url`, `-bec`, `-dlp`, `-sandbox`): any of them can complete a round (the replica that inserts the last required final, or the deadline sweeper) or write the late sandbox final, so each one scores and each one gets the risk keys. The scoring library `@email-gateway/risk-scoring` is part of the image (pure code, no I/O).
- **api**: the `risk-scoring` module (profile routes on the writer, dry-run and reads on the replica) and the `risk` section of `GET /api/v1/messages/{messageId}/scans`.
- **delivery-worker**: reads the revision-0 row only in the development pass-through (local/ci). Production manifests have no pass-through and no risk key.

## Database

One forward migration, `20261110203003_risk_scoring` (additive): the tables `risk_scoring_profiles`, `risk_scoring_profile_versions` and `message_risk_scores` (monthly partitions, retention `core` 6 months like `email_scans`), and the nullable column `email_scans.risk_profile_version_id` added with `ALGORITHM=INSTANT` (verified on MySQL 8.4, [schema reference](../database/schema-reference.md)). After it: 104 tables, 31 partitioned. Run `pnpm db:partitions apply` (or the partition CronJob) after the migration so `message_risk_scores` gets its monthly partitions. No seed change: the routes use the existing `policy:read`, `policy:manage` and `policy:publish` permissions.

## Configuration

| Key                                  | Service                    | Default         | Bounds                                                                 | Where set                                                                                |
| ------------------------------------ | -------------------------- | --------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `RISK_PLATFORM_PROFILE`              | email-worker (scan), api   | `rsk-default/1` | a shipped platform profile id (`RISK_PLATFORM_PROFILES`); else refused | Compose `email-worker`, `api`; Kubernetes `env` of every scan email-worker and `api`     |
| `RISK_PROFILE_CACHE_MAX_ENTRIES`     | email-worker (scan)        | `10000`         | 100–100 000                                                            | Compose `email-worker`; Kubernetes `env` of every scan email-worker                      |
| `RISK_PROFILE_MAX_VERSIONS`          | api                        | `200`           | 10–1 000 versions per organization                                     | Compose `api`; Kubernetes `api.yaml`                                                     |
| `DELIVERY_DEV_PASSTHROUGH_RISK_HOLD` | delivery-worker (local/ci) | `true`          | boolean; read only when `DELIVERY_DEV_PASSTHROUGH_ENABLED=true`        | Compose `delivery-worker`; not in Kubernetes (the pass-through is refused in production) |

No secret is added. `.env.example` has the section "Risk scoring (step 5.1, …)"; `scripts/init-env.mjs` copies the defaults. A service refuses to start with a value outside its bounds (zod configuration).

### Platform profile versions

| Id              | Shipped in | Contents                                                                                                                                                                            |
| --------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rsk-default/1` | step 5.1   | Thresholds low 100 / medium 300 / high 550 / critical 800; actions none/low `deliver`, medium `tag`, high/critical `quarantine`; signal map `risk-signals/1`; scorer `risk-score/1` |

A platform profile is data in the library and never changes in place: a new default is a new id (`rsk-default/2`) shipped in an image, then selected with `RISK_PLATFORM_PROFILE` on the email-worker **and** the api together. Stored rows keep the profile id, SHA-256 and versions they were scored with; existing rows are not re-scored (a rescan scores anew). Tenant versions record their `baseProfile`; a version whose base is no longer shipped falls back to the platform default (`base_profile_retired`, counted, alerted by `RiskProfileFallback`).

## Rollout order (upgrading from step 4.6)

1. **Migration first:** `pnpm db:migrate` (the migration Job), then `pnpm db:partitions apply`. The old images ignore the new tables and the new nullable column.
2. **email-worker** (every scan-role Deployment): from now on every completed round gets a revision-0 row and the snapshot columns. During the rolling update an old replica can still complete rounds without a row; `RiskScoreMissing` (critical, `for: 30m`) may fire if the rollout is slower than its window — finish the rollout, then confirm the alert resolves. A round opened by an old replica has no snapshot (`risk_profile_version_id` NULL) and is scored with the platform default.
3. **api**: the profile routes, the dry-run and the scans read API `risk` section. Publish tenant versions only after step 2 is complete, so every replica that opens rounds records the snapshot.
4. **delivery-worker** (local/ci only): the pass-through reads the revision-0 row. Deploying it before step 2 would hold every new round as `risk_missing` (fail-safe, but not useful).

## Rollback

The migration is forward-only and stays in place (the tables and the column are additive; nothing reads them once the images are rolled back). Roll back in the reverse order:

1. delivery-worker (local/ci): roll back, or set `DELIVERY_DEV_PASSTHROUGH_RISK_HOLD=false` (restores the 4.6 holds exactly; for diagnosis only).
2. api: the risk routes disappear; stored profiles and versions are kept.
3. email-worker: rounds stop being scored. A later roll-forward resumes scoring at the next completed round; rounds completed in between have no row (the 5.2 policy contract treats a missing row as a hold).

A bad tenant profile is not a deployment rollback: activate an earlier published version or reset to the platform default (runbook, [Profiles](../runbooks/risk-scoring.md#profiles-publish-activate-rollback-reset)); the change applies to rounds opened afterwards.

## Monitoring

Alert rules `infrastructure/monitoring/rules/risk-scoring.rules.yml` (promtool tests in `infrastructure/monitoring/tests/risk-scoring.rules.test.yml`): `RiskScoringErrors` (warning; critical after 1 h), `RiskProfileFallback`, `RiskScoreMissing`, `RiskUnmappedCodes`. Metrics and responses: [runbook](../runbooks/risk-scoring.md#metrics).

## Verification (local)

`docker compose --profile apps config` and `kubectl kustomize infrastructure/kubernetes/base` render the keys (step 5.1 WP3). The stack suite `tests/integration/risk-smtp.test.ts` exercises the whole path through Postfix and the containers; results in [§13 of the design](../plan/steps/15-risk-scoring.md#13-verification-results). The Kubernetes manifests are rendered only, never applied to a cluster.
