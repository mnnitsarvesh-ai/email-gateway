# @email-gateway/archive-worker

Journaling and compliance archiving (step 8.1, [design](../../docs/plan/steps/23-journaling-archiving.md), ADR-0064..0069). Writer-only MySQL (never `PrismaReadService`, ADR-0014), S3 (mail bucket read, archive bucket write), RabbitMQ for the capture role, OpenSearch for index/ediscovery (and lifecycle when configured). HTTP port 3060 serves `/health/*` and `/metrics` only. Operations: [docs/runbooks/archive.md](../../docs/runbooks/archive.md); deployment: [docs/deployment/archive.md](../../docs/deployment/archive.md).

## Roles (`ARCHIVE_WORKER_ROLES`, default `capture,index,lifecycle,ediscovery`)

Compose runs all four in one container; Kubernetes runs `archive-worker` (`capture,index`) and `archive-jobs` (`lifecycle,ediscovery`) from the same image.

| Role         | Loop (module)                                                                  | Concurrency                                                                    | State                                                                                    |
| ------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `capture`    | `email.archive` consumer (`capture/consumer.ts`)                               | `ARCHIVE_PREFETCH`, ledger `archive-worker.archive` (`processOnce`)            | intents (policy source)                                                                  |
|              | journal completeness sweep (`capture/sweeps.ts`)                               | leader `eg:archive-journal-sweep`                                              | cursor `archive:journal-sweep`                                                           |
|              | policy reconciler (`capture/sweeps.ts`)                                        | leader `eg:archive-policy-reconcile`                                           | cursor `archive:policy-reconcile`                                                        |
|              | capture scheduler + outcome refresh (`capture/scheduler.ts`, `executor.ts`)    | every replica, `FOR UPDATE SKIP LOCKED` + lease, `ARCHIVE_CAPTURE_CONCURRENCY` | intents, records, objects, index ops                                                     |
|              | intent gauges + stuck intents (`scheduler.maintain`)                           | every replica, every 60 s                                                      | —                                                                                        |
|              | journal intake health (`capture/intake-health.ts`, step 8.6 D9)                | leader `eg:archive-intake-health`, `JOURNAL_INTAKE_HEALTH_INTERVAL_MS`         | `journal_intake_sources.health_*`, audit rows, `notification.alert_requested.v1` outbox  |
| `index`      | index sync (`index/index-sync.ts`)                                             | leader `eg:archive-index-sync`                                                 | `archive_index_queue`, `indexed_at`                                                      |
|              | per-day reconciliation (`index/reconcile.ts`)                                  | leader `eg:archive-index-reconcile`                                            | `archive_index_checks`, cursors `archive:index-reconcile:<org>`                          |
| `lifecycle`  | expiry, apply-lock pass, orphans, disposal verification, pruning (8.6), gauges | leader `eg:archive-lifecycle`                                                  | cursors `archive:lock:<org>`, `archive:orphans:<org>[:<day>]`, `archive:disposal-verify` |
|              | disposal pipeline (`lifecycle/disposal.ts`)                                    | every replica, `FOR UPDATE SKIP LOCKED` + lease                                | `archive_disposals`                                                                      |
|              | root key re-wrap (`keys/root-rewrap.ts`)                                       | leader `eg:archive-root-rewrap`                                                | `archive_encryption_keys`                                                                |
| `ediscovery` | case searches (`ediscovery/searches.ts`)                                       | every replica, one claimed search per pass                                     | `ediscovery_searches`, `ediscovery_search_hits`                                          |
|              | exports + expiry (`ediscovery/exports.ts`)                                     | `ARCHIVE_EXPORT_CONCURRENCY` loops                                             | `ediscovery_exports`, export objects                                                     |

Leader locks are `GET_LOCK` on a dedicated connection (`AdvisoryLocks`), re-checked every pass; leader-written gauges are 0 on the other replicas. The Object Lock availability of the archive bucket is probed once at start (`GetObjectLockConfiguration`, skipped with `ARCHIVE_OBJECT_LOCK=disabled`) and retried until it succeeds.

## Journal intake and cross-source dedupe (step 8.6)

[Design](../../docs/plan/steps/27-journal-intake-and-archive-split.md) D6, D7, D9, ADR-0087/0088. Journal intake messages (`ingest_source = journal_intake`) are captured by the same engine once `journaled` (category `delivered`): record sources (`source_gateway`, `source_journal_intake`, `intake_source_id`), the journal `intake` block from `journal_intake_messages`, parties with the envelope `field`, NULL recipient directions kept. Every capture with a complete parse computes the dedupe key (`capture/dedupe.ts`: the stored EML's header block by a bounded range GET, the parse's attachment hashes) and looks up `archive_dedupe_keys`; a live candidate record (window `ARCHIVE_DEDUPE_WINDOW_HOURS`, at least one intake copy) gets the copy merged (`executor.merge`: the copy's journal object and, for a differing body, its EML as a content variant, both under the record's DEK with the copy's public id as subject; one REPEATABLE READ transaction locking the record and the key's rows; `archive_record_sources`, the merged record, the variant's dedupe row, the intent `captured_open` with `merged`, `archive_id`, `archive_received_at`). A capture without a candidate adds its dedupe row under the same key lock and retries as a merge when one appeared. Refresh of a merged intent: record by `(archive_id, archive_received_at)`, facts by its own message; a gateway copy is authoritative for the outcome, an intake copy never overwrites it. Disposal, the lock pass, expiry lock extension and the orphan reconciliation use `storage/record-versions.ts` (record versions + merged journals and variants); exports add variants and a signed `merged.json`. See [archive.md](../../docs/runbooks/archive.md#journal-intake-sources-and-cross-source-dedupe-step-86).

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

`baseConfigSchema` + `httpConfigSchema(3060)` + database + S3 + `archiveKeysFieldsSchema` + `archiveSearchFieldsSchema` + `archiveStorageConfigSchema` + `archiveTestSeamFieldsSchema` (`@email-gateway/config`) and every worker key of §4.8 with its bounds. `RABBITMQ_ARCHIVE_URL` is required by `capture`, `ARCHIVE_SEARCH_URL` by `index`/`ediscovery`, `ARCHIVE_EXPORT_SIGNING_KEY` by `ediscovery`; `ARCHIVE_TEST_DAY_SECONDS` only in `APP_ENV` local/ci. Errors name keys, never values. Step 8.6 (§4.4): `JOURNAL_INTAKE_HEALTH_INTERVAL_MS` (60 000; 1 000–3 600 000), `JOURNAL_INTAKE_ALERT_MIN_INTERVAL_HOURS` (24), `ARCHIVE_DEDUPE_WINDOW_HOURS` (72), `ARCHIVE_MAX_CONTENT_VARIANTS` (4, ≤ merged copies), `ARCHIVE_MAX_MERGED_COPIES` (8, the `objects.merged` bound).

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
