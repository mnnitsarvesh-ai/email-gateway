# Deployment: journaling and compliance archiving (step 8.1)

Design: [docs/plan/steps/23-journaling-archiving.md](../plan/steps/23-journaling-archiving.md) (A1, A8–A10, A14, A16, A29, A30, §4.8), ADR-0064..0069. Operations: [runbooks/archive.md](../runbooks/archive.md). Worker internals: [apps/archive-worker/README.md](../../apps/archive-worker/README.md).

## What is deployed

| Workload         | Image                          | Roles (`ARCHIVE_WORKER_ROLES`) | Replicas         | Talks to                                                                                 |
| ---------------- | ------------------------------ | ------------------------------ | ---------------- | ---------------------------------------------------------------------------------------- |
| `archive-worker` | `email-gateway/archive-worker` | `capture,index`                | 1–6 (HPA on CPU) | MySQL writer, RabbitMQ (`eg-archive`), S3 (mail read, archive write), OpenSearch (write) |
| `archive-jobs`   | `email-gateway/archive-worker` | `lifecycle,ediscovery`         | 2 (PDB 1)        | MySQL writer, S3 (archive versions, replica targets), OpenSearch (read/write)            |
| `api`            | `email-gateway/api`            | —                              | as before        | archive read/decrypt only, OpenSearch through tenant aliases (WP4)                       |

Manifests: `infrastructure/kubernetes/base/archive-worker.yaml`, `archive-jobs.yaml` (both in `kustomization.yaml`). Every replica runs the claim-based loops (capture scheduler, disposal pipeline, case searches, exports); the single-run jobs are leader-elected with `GET_LOCK` (`eg:archive-journal-sweep`, `eg:archive-policy-reconcile`, `eg:archive-index-sync`, `eg:archive-index-reconcile`, `eg:archive-lifecycle`, `eg:archive-root-rewrap`), so a second replica only takes over. Locally one Compose container runs all four roles.

Readiness: mysql and s3 on both, plus rabbitmq on `archive-worker` (`email.archive` and `email.events` verified passively). OpenSearch is deliberately not a readiness dependency: capture continues while the index is down (the queue grows, `ArchiveIndexLag` fires).

## Rollout order

1. Migration `journaling_archiving` (the migration Job, as every release).
2. Topology v12 and the role user `eg-archive` (`infrastructure/rabbitmq/init.mjs` / the broker definitions of the environment); Secret key `rabbitmq-archive-url`.
3. The archive bucket **with Object Lock** (Terraform `mail-storage`, below) and, where required, its replication target.
4. The Amazon OpenSearch domain with the two FGAC users (below).
5. The Secrets of this step (below), then the `api` (reads, settings, searches).
6. `archive-worker`, then `archive-jobs`.

Nothing on the mail path depends on the archive: SMTP, scanning, policy and delivery never wait for these Deployments (invariant 8). Starting the archive late is safe: the journal sweep starts at `now` (no backfill), the policy reconciler at `oldest` (it recovers every ARCHIVE request still in `policy_execution_logs`).

## Configuration

Shared keys (ConfigMap `email-gateway-config`, also read by the api): `ARCHIVE_ROOT_KEY_ID`, `ARCHIVE_SEARCH_URL`, `ARCHIVE_SEARCH_TIMEOUT_MS`, `ARCHIVE_SEARCH_INDEX_PREFIX`, `ARCHIVE_OBJECT_LOCK`, `ARCHIVE_MAX_RETENTION_DAYS`, `ARCHIVE_EXPORT_SIGNING_KEY_ID`, the export bounds. Worker tunables and the roles are in the two manifests with their §4.8 defaults. `ARCHIVE_TEST_DAY_SECONDS` is refused outside `APP_ENV` local/ci and never set in a cluster. `ARCHIVE_INDEX_SHARDS`/`_REPLICAS` are `1/1` in the base manifest; production sizing is step 10.1.

## Secrets and key custody

| Secret (External Secrets)              | Item                                         | Read as                                                   | Mounted in                                |
| -------------------------------------- | -------------------------------------------- | --------------------------------------------------------- | ----------------------------------------- |
| `email-gateway-secrets`                | `database-url`                               | `DATABASE_URL_FILE`                                       | both                                      |
| `email-gateway-secrets`                | `rabbitmq-archive-url`                       | `RABBITMQ_ARCHIVE_URL_FILE`                               | `archive-worker` only (`eg-archive`)      |
| `email-gateway-archive-root-key`       | `key` (64 hex)                               | `ARCHIVE_ROOT_KEY_FILE`                                   | both, and the api                         |
| `email-gateway-archive-root-key`       | `previous-key`, `previous-key-id`            | `ARCHIVE_ROOT_KEY_PREVIOUS(_ID)` (optional env)           | both, and the api, during a root rotation |
| `email-gateway-archive-search-worker`  | `password`                                   | `ARCHIVE_SEARCH_PASSWORD_FILE` (user `eg-archive-worker`) | both                                      |
| `email-gateway-archive-export-signing` | `private-key` (Ed25519 PKCS#8 DER base64url) | `ARCHIVE_EXPORT_SIGNING_KEY_FILE`                         | `archive-jobs` only                       |

The api mounts only the `public-key` item of `email-gateway-archive-export-signing` and its own search Secret (`email-gateway-archive-search-api`, user `eg-archive-api`). The root key decrypts every archived message of every tenant: store it in the secret manager with versioning and a recovery copy held under dual control; losing it makes the archive unreadable (the tenant keys are only stored wrapped). Root rotation and the re-wrap job: [runbook](../runbooks/archive.md#root-key-rotation).

**KMS note.** In 8.1 the root key is a configured key behind the `ArchiveRootKeyProvider` interface (`@email-gateway/archive`). An AWS KMS provider (wrap/unwrap through `kms:Encrypt`/`kms:Decrypt` with an encryption context equal to the AAD) is a drop-in planned for step 10.1; S3 server-side encryption (SSE-KMS) of the archive bucket is independent and recommended on top of the application encryption.

## Archive bucket (AWS)

Terraform `infrastructure/terraform/modules/mail-storage` (WP1) creates the archive bucket with:

- **Object Lock enabled at creation** (`object_lock_enabled = true`) and **no default retention**: the worker sets the mode and retain-until per object for tenants whose `archive_settings.object_lock_mode` is `governance` or `compliance` (A10). Object Lock cannot be enabled on an existing bucket.
- Versioning on (required by Object Lock), public access blocked, SSE.
- Lifecycle: abort incomplete multipart uploads after 1 day; expire objects tagged `eg-object=archive-export` (exports) a day after `ARCHIVE_EXPORT_TTL_HOURS` plus their noncurrent versions; optional storage-class transitions of `org/*/archive/` (never an expiration rule: disposal is the only deletion path, A14).

**Cross-region replication (CRR, step 10.2).** Replicate to a DR bucket that is itself created with Object Lock (replicated versions keep their mode and retain-until when the replication role has `s3:ReplicateObject` + `s3:GetObjectRetention`/`s3:GetObjectLegalHold` on the source and the destination allows them). **S3 replication never replicates version deletes**: list every replica bucket in `ARCHIVE_REPLICA_TARGETS` (`bucket` or `bucket@region`, same endpoint and credentials) on `archive-jobs`, and the disposal pipeline deletes the same keys' versions there too.

## IAM per role (IRSA)

| Role (ServiceAccount)                 | Actions                                                                                                                                                                                                              | Resources                                                            |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `archive-worker` (capture,index)      | `s3:GetObject`                                                                                                                                                                                                       | mail bucket `org/*/eml/*`, `org/*/part/*`                            |
|                                       | `s3:PutObject`, `s3:PutObjectRetention`, `s3:GetObject`, `s3:GetObjectVersion`, `s3:DeleteObjectVersion` (own uncommitted, unlocked attempts only), `s3:GetBucketObjectLockConfiguration`, `s3:AbortMultipartUpload` | archive bucket `org/*/archive/*` (and the bucket for the lock probe) |
| `archive-jobs` (lifecycle,ediscovery) | `s3:ListBucketVersions`, `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectRetention`, `s3:PutObjectRetention`, `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention`, `s3:GetBucketObjectLockConfiguration`    | archive bucket `org/*/archive/*` and every replica target bucket     |
|                                       | `s3:PutObject`, `s3:PutObjectTagging`, `s3:GetObject`, `s3:DeleteObjectVersion`, `s3:AbortMultipartUpload`                                                                                                           | archive bucket `org/*/exports/*`                                     |
| `api`                                 | `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetBucketObjectLockConfiguration`                                                                                                                                         | archive bucket only                                                  |

`s3:BypassGovernanceRetention` is used for (a) governance-locked **orphans** (versions no committed record or open disposal references, `ARCHIVE_GOVERNANCE_BYPASS_ORPHANS`) and (b) the apply-lock pass `governance → compliance` (S3 requires the bypass to change the mode of a governance version, WP1 deviation 6). It is never used on a recorded version of a live record. Compliance-locked versions cannot be deleted by anyone before their date; the pipeline records them and retries after their lock.

## Amazon OpenSearch (fine-grained access control)

The domain runs in the VPC (HTTPS 443; the NetworkPolicies of both Deployments allow `10.0.80.0/20`, the data subnet planned for the domain in step 10.1; adjust the CIDR to the environment). Two internal users, mapped to roles:

| User                | Role permissions                                                                                                                                                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eg-archive-worker` | index permissions `indices:data/write/*`, `indices:data/read/*`, `indices:admin/create`, `indices:admin/delete`, `indices:admin/aliases*`, `indices:admin/refresh` on `<prefix>-v*` and `<prefix>-t*`; cluster `indices:admin/index_template/*`, `cluster:monitor/health` |
| `eg-archive-api`    | `indices:data/read/search*`, `indices:data/read/get` on `<prefix>-t*` only (tenant aliases); `cluster:monitor/health`                                                                                                                                                     |

Document-level security is not needed: every tenant alias carries a `term org_id` filter and the api's query builder adds the same term (two independent guards, ADR-0068). SigV4 instead of basic auth is deferred to 10.1. Locally the security plugin is off (ADR-0009) and `ARCHIVE_SEARCH_USERNAME`/`_PASSWORD` are empty.

## Egress

| Destination                 | Port      | archive-worker | archive-jobs |
| --------------------------- | --------- | -------------- | ------------ |
| MySQL writer (10.0.32.0/20) | 3306      | yes            | yes          |
| RabbitMQ (10.0.64.0/20)     | 5671/5672 | yes            | no           |
| OpenSearch (10.0.80.0/20)   | 443       | yes            | yes          |
| S3 (public addresses)       | 443       | yes            | yes          |
| DNS, OTLP                   | 53, 4318  | yes            | yes          |

No Redis, no Internet egress beyond S3.

## Sizing (measured locally, WP3)

Capture baseline (1 000 synthetic messages, ~5 KiB originals, one scan round each, concurrency 4, laptop MySQL/MinIO): ≈ 92 captures/s, p95 capture latency 54 ms, peak RSS 230 MiB in the test process. Requests/limits: `archive-worker` 250m/512Mi (limit 768Mi), `archive-jobs` 250m/384Mi (limit 768Mi). Large originals are streamed (lib-storage keeps ≤ 2 parts of `ARCHIVE_S3_PART_SIZE_BYTES` in memory per capture). Production sizing (index shards, HPA bounds, MySQL growth ≈ 0.2 TB/year per 1 M archived messages/day) is step 10.1.

## MinIO (local) vs AWS

| Topic                 | Local (Compose)                                                                                                  | AWS                                                     |
| --------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Object Lock           | MinIO `mc mb --with-lock` (`init-buckets.sh` recreates an empty unlocked bucket once)                            | bucket created with Object Lock by Terraform            |
| Governance/compliance | same semantics (WP1 probe: refused deletes, extend-only, bypass rules)                                           | same                                                    |
| Replication           | `gateway-archive-replica` test bucket (tests copy objects; MinIO bucket replication works but is not configured) | CRR to the DR bucket (10.2)                             |
| Credentials           | every service uses the MinIO root credentials                                                                    | IRSA roles per Deployment (table above)                 |
| OpenSearch            | single node, security plugin off, HTTP                                                                           | Amazon OpenSearch, FGAC, HTTPS + basic auth             |
| Root key              | `.env` value                                                                                                     | secret manager (External Secrets), KMS provider in 10.1 |
| Test seam             | `ARCHIVE_TEST_DAY_SECONDS` (local/ci only)                                                                       | refused                                                 |

## Monitoring

Prometheus job `archive-worker` (`infrastructure/monitoring/prometheus.yml`; in Kubernetes both Services). Alerts: `infrastructure/monitoring/rules/archive.rules.yml` (14 rules: `ArchiveWorkerDown`, `ArchiveCaptureBacklog` 6 h/24 h (overdue or erroring intents only), `ArchiveCaptureLost`, `ArchiveCaptureAgedOut`, `ArchiveCaptureFailures`, `ArchiveIntegrityFailure`, `ArchiveSweepStalled`, `ArchiveIndexLag`, `ArchiveReconcileMismatch`, `ArchiveDisposalStuck` ×2, `ArchiveRootKeyRewrapPending`, `ArchiveExportFailures`), promtool tests in `tests/archive.rules.test.yml`. Each alert links its runbook section.

## Local verification

```bash
docker compose --profile search up -d --wait opensearch       # 512 MB heap, 1.5 GB limit
pnpm --filter @email-gateway/archive-worker build
pnpm --filter @email-gateway/archive-worker test:integration  # real MySQL, MinIO, OpenSearch, RabbitMQ
kubectl kustomize infrastructure/kubernetes/overlays/saas | grep -A3 'name: archive-jobs'
```
