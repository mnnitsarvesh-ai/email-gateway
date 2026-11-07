# Data loss prevention deployment (step 4.5)

Design: [13-dlp.md](../plan/steps/13-dlp.md) (D1, D2, D4, D16, D22, D24), [ADR-0036](../architecture/adr/0036-dlp-engine-and-extraction.md), [ADR-0037](../architecture/adr/0037-dlp-policy-actions-and-lifecycle-binding.md), [ADR-0038](../architecture/adr/0038-dlp-evidence-masking-and-aadhaar-gating.md). Operations: [runbook](../runbooks/dlp.md). Performance: [docs/performance/dlp.md](../performance/dlp.md).

## Topology

- **`email-worker-dlp`** (`infrastructure/kubernetes/base/email-worker-dlp.yaml`): the email-worker image with `SCAN_CONSUMERS=dlp`, `MIME_INGESTION_ENABLED=false`, broker user `eg-scanner`. Consumes `scan.dlp` (topology v7: a stage-1 work queue binding `mail.message.parsed.v1` and `mail.message.rescan_requested.v1` plus its retry key), runs two **DLP extractor children** (the generalized 4.2 child pool) and the **evidence sweeper** (MySQL advisory lock `scan:dlp-evidence`, one leader across replicas). Readiness `dlp-engine` and `dlp-extractor` (at least one child ready; `rlimits` must say `prlimit` and `permissionModel` `true` in production). HPA on CPU (KEDA on `scan.dlp` ready messages in production, target 100 per replica), PDB `minAvailable: 1`.
- **Every scan replica** has `SCAN_ENGINES=rspamd,attachment,url,bec,dlp` (`email-gateway-config`) after phase 2: rounds require `dlp` for every direction (inbound rounds finish fast with `skipped` unless the tenant enabled inbound scanning). Only `email-worker-dlp` consumes `scan.dlp` and holds the evidence key; other scan replicas validate the DLP keys but need no secret.
- **Deadline:** `B(dlp) = 3 × (120 s + 60 s) = 540 s`, below `B(url)`, so the stage-1 maximum and the default `SCAN_ROUND_DEADLINE_SECONDS=1800` are unchanged (the worker still refuses a deadline below the rule, naming the keys).
- **event-relay:** `RECONCILE_QUEUES` gains `scan.dlp` (`event-relay.yaml`) so lost `parsed.v1` / rescan deliveries are re-driven. The incident event `mail.message.dlp_incident.v1` is published to `email.security` and reaches only the `email.analytics` firehose in this step (the notification-worker binds it in 6.2).
- **api:** reads the same platform keys (bounds of the DLP routes and `/api/v1/scan-settings/dlp`) and holds the evidence key to open evidence in the audited route only.

## Rollout order (upgrading from step 4.4)

1. `pnpm db:migrate` (migration `dlp_engine`: 8 tables), `pnpm db:partitions apply`, `pnpm db:seed` (4 `dlp:*` permissions), `pnpm rabbitmq:init` (topology v7: `scan.dlp` becomes a work queue, the scanner user may read it).
2. Create the Secret `email-gateway-dlp-evidence-key` (below).
3. **Phase 1:** deploy the step 4.5 image to every service (api, delivery-worker, event-relay, every email-worker Deployment) and create `email-worker-dlp`, with `SCAN_ENGINES` **unchanged** (`rspamd,attachment,url,bec`). `email-worker-dlp` starts consuming `scan.dlp` (rounds do not require it yet: its finals are recorded but not waited for). Wait until no pod of the previous image is left (`kubectl rollout status` for every email-worker Deployment) and `dlp-extractor` is ready on every `email-worker-dlp` pod.
4. **Phase 2:** set `SCAN_ENGINES=rspamd,attachment,url,bec,dlp` in `email-gateway-config` and restart the scan replicas. From now on outbound approval waits for the dlp final and its policy action.

A replica that opens a round requiring `dlp` while nobody consumes `scan.dlp` ends that round `scan_failed` at its deadline (never clean); see the runbook's [rollout query](../runbooks/dlp.md#rollout-order). Rolling back reverses the order: remove `dlp` from `SCAN_ENGINES` first, then roll back the image (the DLP tables stay; nothing reads them).

## Secrets

| Secret                           | Key            | Mounted in                                  | Notes                                                                                                                                                                                                                                                    |
| -------------------------------- | -------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `email-gateway-dlp-evidence-key` | `key`          | `email-worker-dlp` and `api` only (file)    | `DLP_EVIDENCE_KEY`: exactly 64 hex characters (`openssl rand -hex 32`). Key-encryption key of every evidence data key (`dlp-evidence/1`). A dedicated secret: never `DATA_ENCRYPTION_KEY`. Required where dlp consumes with `DLP_EVIDENCE_ENABLED=true`. |
| `email-gateway-dlp-evidence-key` | `previous-key` | `email-worker-dlp` and `api` (optional env) | `DLP_EVIDENCE_KEY_PREVIOUS`: the key before a rotation (64 hex, different from `key`), kept ≥ 180 days (`DLP_EVIDENCE_MAX_RETENTION_DAYS`). Absent = no rotation in progress.                                                                            |

`DATABASE_URL`, `RABBITMQ_SCANNER_URL`, `REDIS_URL` and the S3 credentials come from `email-gateway-secrets` as for the other scan replicas. Local Compose: `.env` (`DLP_EVIDENCE_KEY` generated by `scripts/init-env.mjs`); only the `email-worker` and `api` services receive it. Rotation procedure: [runbook](../runbooks/dlp.md#evidence-access-audit-purge-and-key-rotation).

## Configuration

Platform keys shared with the api are in `email-gateway-config` (`config.yaml`): `DLP_CONFIDENCE_THRESHOLD`, `DLP_CONTEXT_WINDOW_CHARS`, `DLP_BULK_MIN_DISTINCT`, `DLP_DEFAULT_POLICY` (`alert`), `DLP_CUSTOM_PATTERN_MAX_LENGTH`, `DLP_CUSTOM_PATTERN_PROBE_MAX_MS` (read by the api only since the closer review: the worker does not time patterns), `DLP_CUSTOM_SCAN_MAX_CHARS`, the per-tenant caps (`DLP_CUSTOM_PATTERNS_MAX_PER_TENANT`, `DLP_DICTIONARIES_MAX_PER_TENANT`, `DLP_DICTIONARY_MAX_TERMS`, `DLP_POLICIES_MAX_PER_TENANT`, `DLP_RULES_MAX_PER_POLICY`, `DLP_EXCEPTIONS_MAX_PER_TENANT`, `DLP_EXCEPTION_MAX_DAYS`) and the evidence cap and retention (`DLP_EVIDENCE_ENABLED`, `DLP_EVIDENCE_DEFAULT_RETENTION_DAYS`, `DLP_EVIDENCE_MAX_RETENTION_DAYS`). The engine-only keys (budgets `SCAN_DLP_*`, extractor pool and limits, attachment/text/detection bounds, evidence size and sweep interval, tenant cache TTL) are set in `email-worker-dlp.yaml`; every key, default and bound is in `.env.example` (section "Data loss prevention (step 4.5)"). The worker refuses to start (naming the key, never its value) with: `SCAN_DLP_MAX_ATTEMPTS` ≥ 10, a platform setting out of bounds, `DLP_ATTACHMENT_MAX_BYTES` above `DLP_BYTE_BUDGET_BYTES` or `ATTACHMENT_MAX_BYTES`, `DLP_EXTRACT_CPU_SECONDS` above `DLP_EXTRACT_TIMEOUT_MS`, `DLP_EXTRACT_MAX_RSS_MB` not above `DLP_EXTRACTOR_HEAP_MB`, `DLP_EXTRACT_TIMEOUT_MS` / `DLP_DETECT_TIMEOUT_MS` / `SCAN_S3_TIMEOUT_MS` not below `SCAN_DLP_TIMEOUT_MS`, `DLP_EXTRACT_TIMEOUT_MS + DLP_DETECT_TIMEOUT_MS` not below `SCAN_DLP_TIMEOUT_MS`, `DLP_EXTRACTOR_RLIMITS=best_effort` with `NODE_ENV=production`, a deadline below the rule, and (where dlp consumes) a missing or malformed evidence key or a previous key equal to the current one.

## Memory sizing

Per `email-worker-dlp` replica (defaults):

| Part               | Bound                                                                                                                           | Estimate      |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Extractor children | `DLP_EXTRACTOR_POOL_SIZE` (2) × `DLP_EXTRACT_MAX_RSS_MB` (512 MiB; killed above, V8 heap capped at `DLP_EXTRACTOR_HEAP_MB` 256) | ≤ 1 024 MiB   |
| Attachment buffers | `DLP_BYTE_BUDGET_BYTES` (64 MiB) across the in-flight messages                                                                  | ≤ 64 MiB      |
| Text and detection | `SCAN_DLP_CONCURRENCY` (4) × `DLP_TEXT_MAX_CHARS_PER_MESSAGE` (4 M UTF-16 units ≈ 8 MB, plus normalization copies ≈ 3×)         | ≈ 100 MiB     |
| Worker process     | Nest, Prisma, AWS SDK, tenant LRU (≤ 1 000 organizations: compiled patterns and phrase tries), dictionaries                     | ≈ 300–400 MiB |

Requests 1 CPU / 1.25 GiB, limits 2 CPU / 2 GiB. The kernel's memory limit must stay above the sum: if the container is OOM-killed before the sampler kills a child, the whole replica restarts (`DlpExtractorKillsHigh` shows `crash`). Do not raise `DLP_EXTRACTOR_POOL_SIZE` or `DLP_EXTRACT_MAX_RSS_MB` without raising the limit. On the local 8 GB Docker VM the single `email-worker` container runs every engine; its extractor children add up to 1 GiB on top of the attachment inspector's.

## Extractor isolation

The children are spawned with an empty environment (`NODE_ENV`, `PATH`), IPC only, Node's permission model (reads of the application and workspace directories, no child processes, no workers, no writes), `--max-old-space-size`, and on Linux `prlimit --cpu --core=0` (`DLP_EXTRACTOR_RLIMITS=required`: the pod refuses to start without `prlimit`, which the image ships in `util-linux`). pdfjs-dist 4.10.38 (legacy build) runs with `isEvalSupported: false`, no font faces, no system fonts; the child loads pdfjs before its handshake, so a child that cannot load it under the permission model never becomes ready (`pdfjs_unavailable`). No new egress: the children have no network access and the NetworkPolicy of `email-worker-dlp` allows MySQL, Redis, RabbitMQ, DNS, OTLP and S3 only.

## Data handling and retention

- `dlp_scan_results` (6 months, monthly partitions): masked samples, codes, counts, public ids only.
- `dlp_evidence` rows (7 months) and objects `org/<org>/dlp-evidence/<yyyy>/<mm>/<scanId>-<uuidv7>.bin` (mail bucket): ciphertext only; expired evidence is crypto-shredded by the sweeper at the tenant's retention (1–180 days, default 30) and its object deleted.
- Organization deletion removes the DLP rows and evidence objects (api tenant-data module).

## Local (Compose)

`docker compose` passes the DLP keys to `email-worker` (with `DLP_EXTRACTOR_RLIMITS=required`) and the bound keys plus the evidence key to `api`. Host runs read `../../.env` (`DLP_EXTRACTOR_RLIMITS=best_effort` on macOS). Integration: `pnpm --filter @email-gateway/email-worker test:integration` (suite `integration/dlp-scan.test.ts`).
