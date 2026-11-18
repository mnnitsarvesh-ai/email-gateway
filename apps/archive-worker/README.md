# @email-gateway/archive-worker

Journaling and compliance archiving (step 8.1, [design](../../docs/plan/steps/23-journaling-archiving.md), ADR-0064..0069). Writer-only MySQL (never `PrismaReadService`, ADR-0014), S3 (mail bucket read, archive bucket write), RabbitMQ for the capture role, OpenSearch for index/ediscovery (and lifecycle when configured). HTTP port 3060 serves `/health/*` and `/metrics` only. Operations: [docs/runbooks/archive.md](../../docs/runbooks/archive.md); deployment: [docs/deployment/archive.md](../../docs/deployment/archive.md).

## Roles (`ARCHIVE_WORKER_ROLES`, default `capture,index,lifecycle,ediscovery`)

Compose runs all four in one container; Kubernetes runs `archive-worker` (`capture,index`) and `archive-jobs` (`lifecycle,ediscovery`) from the same image.

| Role         | Loop (module)                                                                   | Concurrency                                                                    | State                                                                                    |
| ------------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `capture`    | `email.archive` consumer (`capture/consumer.ts`)                                | `ARCHIVE_PREFETCH`, ledger `archive-worker.archive` (`processOnce`)            | intents (policy source)                                                                  |
|              | journal completeness sweep (`capture/sweeps.ts`)                                | leader `eg:archive-journal-sweep`                                              | cursor `archive:journal-sweep`                                                           |
|              | policy reconciler (`capture/sweeps.ts`)                                         | leader `eg:archive-policy-reconcile`                                           | cursor `archive:policy-reconcile`                                                        |
|              | capture scheduler + outcome refresh (`capture/scheduler.ts`, `executor.ts`)     | every replica, `FOR UPDATE SKIP LOCKED` + lease, `ARCHIVE_CAPTURE_CONCURRENCY` | intents, records, objects, index ops                                                     |
|              | intent gauges + stuck intents (`scheduler.maintain`)                            | every replica, every 60 s                                                      | —                                                                                        |
| `index`      | index sync (`index/index-sync.ts`)                                              | leader `eg:archive-index-sync`                                                 | `archive_index_queue`, `indexed_at`                                                      |
|              | per-day reconciliation (`index/reconcile.ts`)                                   | leader `eg:archive-index-reconcile`                                            | `archive_index_checks`, cursors `archive:index-reconcile:<org>`                          |
| `lifecycle`  | expiry, apply-lock pass, orphans, disposal verification, gauges (`lifecycle/*`) | leader `eg:archive-lifecycle`                                                  | cursors `archive:lock:<org>`, `archive:orphans:<org>[:<day>]`, `archive:disposal-verify` |
|              | disposal pipeline (`lifecycle/disposal.ts`)                                     | every replica, `FOR UPDATE SKIP LOCKED` + lease                                | `archive_disposals`                                                                      |
|              | root key re-wrap (`keys/root-rewrap.ts`)                                        | leader `eg:archive-root-rewrap`                                                | `archive_encryption_keys`                                                                |
| `ediscovery` | case searches (`ediscovery/searches.ts`)                                        | every replica, one claimed search per pass                                     | `ediscovery_searches`, `ediscovery_search_hits`                                          |
|              | exports + expiry (`ediscovery/exports.ts`)                                      | `ARCHIVE_EXPORT_CONCURRENCY` loops                                             | `ediscovery_exports`, export objects                                                     |

Leader locks are `GET_LOCK` on a dedicated connection (`AdvisoryLocks`), re-checked every pass; leader-written gauges are 0 on the other replicas. The Object Lock availability of the archive bucket is probed once at start (`GetObjectLockConfiguration`, skipped with `ARCHIVE_OBJECT_LOCK=disabled`) and retried until it succeeds.

## Guarantees

- **Completeness:** every message row is visited once by the journal sweep (stops at the first row newer than `ARCHIVE_SWEEP_SAFETY_LAG_SECONDS`); every stored ARCHIVE request is re-read by the policy reconciler, so the lossy queue only lowers latency.
- **Idempotency:** one intent and one record per `(message_id, received_at)`; captures are attempt-scoped (`…/<captureId>/…`); every write after a claim is a CAS on the claimed lease; a lost unique race deletes its own unlocked versions.
- **Order of a capture (A5):** writer facts (echo-checked) → tenant key + fresh DEK → `captureId` → EML streamed and encrypted into a multipart upload (Object Lock headers for locked tenants; `object_lock_unavailable` when a lock is needed but absent) with the plaintext SHA-256 checked against `eml_sha256` before the upload completes (`integrity_mismatch` aborts it) → journal object (bounded Range reads of the decoded parts) → scan snapshot (the shared read-model selects, `archive-scan/1`) → retention → ONE transaction (record, intent `captured_open`, index op).
- **Tenant isolation:** the tenant comes from the processed row; every S3 key is checked against `org/<organizationId>/<area>/`; OpenSearch documents carry routing = organization and are searched through the tenant alias plus the tenant term.
- **No content in logs or metrics:** logs carry ids, codes, HTTP statuses and OpenSearch error types; metric labels are bounded enums.
- **Disposal:** decision (crypto-shred) → objects (archive bucket, orphans, replica targets; locked versions retried after their lock) → index (not visible through the alias, no queued op) → row (+ registry row per the purge contract); verification re-opens a disposal that left anything behind.

## Failure behaviour

| Failure                         | Effect                                                                                                                              |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| RabbitMQ down                   | capture continues from the sweeps; the consumer reconnects                                                                          |
| OpenSearch down                 | capture, lifecycle objects and rows continue; the index queue grows; disposals wait at `objects_deleted`; searches fail with a code |
| S3 down / slow                  | capture retries with backoff (`ARCHIVE_CAPTURE_RETRY_BASE_MS`…`_MAX_MS`); disposals back off                                        |
| MySQL down                      | every loop backs off (logged by class name and code)                                                                                |
| worker killed mid-capture       | the claim's lease expires and another replica captures; the dead attempt's objects are orphans                                      |
| original missing / message gone | intent `lost` (alert)                                                                                                               |

## Configuration (`src/config.ts`, §4.8)

`baseConfigSchema` + `httpConfigSchema(3060)` + database + S3 + `archiveKeysFieldsSchema` + `archiveSearchFieldsSchema` + `archiveStorageConfigSchema` + `archiveTestSeamFieldsSchema` (`@email-gateway/config`) and every worker key of §4.8 with its bounds. `RABBITMQ_ARCHIVE_URL` is required by `capture`, `ARCHIVE_SEARCH_URL` by `index`/`ediscovery`, `ARCHIVE_EXPORT_SIGNING_KEY` by `ediscovery`; `ARCHIVE_TEST_DAY_SECONDS` only in `APP_ENV` local/ci. Errors name keys, never values.

## Metrics

See [the runbook](../../docs/runbooks/archive.md#metrics) and `src/metrics/archive-metrics.ts`; alerts in `infrastructure/monitoring/rules/archive.rules.yml`.

## Rebuild CLI

`node dist/cli/reindex.js --organization <publicId> | --all [--version vN]` (locally `pnpm --filter @email-gateway/archive-worker reindex -- --all`), see the runbook.

## Development and tests

```bash
pnpm --filter @email-gateway/archive-worker dev               # all roles, reads ../../.env
pnpm --filter @email-gateway/archive-worker test              # unit (fakes; no infrastructure)
docker compose --profile search up -d --wait opensearch
pnpm --filter @email-gateway/archive-worker test:integration  # real MySQL, MinIO, OpenSearch, RabbitMQ
IT_LOG_LEVEL=warn pnpm --filter @email-gateway/archive-worker test:integration   # with worker logs
ARCHIVE_IT_BASELINE_MESSAGES=200 pnpm --filter @email-gateway/archive-worker exec vitest run --config vitest.integration.config.ts integration/baseline.test.ts
```

The integration suites pause a live archive-worker (container or host process on port 3060) while they run, create their own `it-arch-<run>-*` organizations on the `enterprise` plan, use the index prefix `eg-archive-wp3-<run>`, per-run lock and cursor names, and delete every row, object version, index, alias and template they created.
