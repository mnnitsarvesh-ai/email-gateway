# Runbook: journaling and compliance archiving (archive-worker)

Step 8.1 ([design](../plan/steps/23-journaling-archiving.md), ADR-0064..0069). Deployment, IAM and secrets: [deployment/archive.md](../deployment/archive.md). eDiscovery operations from the api side: [ediscovery.md](ediscovery.md). Worker internals: [apps/archive-worker/README.md](../../apps/archive-worker/README.md).

All SQL below runs on the **writer** (the archive tables are written only by the archive-worker and the api; never edit an `email_archives` row by hand). Never paste subjects, addresses or object contents into tickets: ids, codes and counts only.

## How capture works (one paragraph)

Every message of an entitled, enabled organization is visited once by the **journal completeness sweep** (cursor `archive:journal-sweep` over `email_messages.id`); eligible messages get an `archive_capture_intents` row. Policy ARCHIVE requests arrive through the lossy `email.archive` queue **and** are recovered by the **policy reconciler** (cursor `archive:policy-reconcile` over `policy_execution_logs.id`). The **capture scheduler** claims due intents (lease `ARCHIVE_CAPTURE_LEASE_SECONDS`), decides on fresh facts (wait / capture / skip / lost) and captures: encrypted EML + journal + scan snapshot objects, then one transaction (record, intent `captured_open`, index op). Captured intents are refreshed (+1 h, +24 h for final messages; hourly up to `ARCHIVE_OUTCOME_WINDOW_DAYS` otherwise) and then `closed`.

```sql
-- Intent states of an organization (capture issues = failed / lost / aged pending)
SELECT status, skip_reason, last_error_code, COUNT(*) FROM archive_capture_intents
WHERE organization_id = ? GROUP BY status, skip_reason, last_error_code;
-- Sweep positions
SELECT name, position_id, last_event_at, updated_at FROM stream_cursors WHERE name LIKE 'archive:%';
```

## ArchiveWorkerDown

A replica is not scraped for 5 minutes. Check the pod (`kubectl -n email-gateway get pods -l app.kubernetes.io/name=archive-worker` / `archive-jobs`), its readiness (`/health/ready`: mysql, s3, and rabbitmq on archive-worker) and its logs (codes only). Nothing is lost while it is down: intents wait, the sweeps resume from their cursors, the queue is lossy but reconciled, disposals resume from their state. Compose: `docker compose logs archive-worker`.

## ArchiveCaptureBacklog

The oldest **stalled** `pending` intent is older than 6 h (warning) / 24 h (critical). `archive_intent_oldest_pending_seconds` counts only intents that are overdue (their `next_check_at` more than 10 minutes in the past: the scheduler is not keeping up or no replica runs) or erroring (`last_error_code` set by a retry); intents waiting for a non-final message or in quarantine are expected to wait and do not count (closing-round fix of step 8.1). The original must be copied before the mail bucket's lifecycle removes it (30 days on AWS); intents older than `ARCHIVE_INTENT_MAX_AGE_DAYS` (25) stop retrying.

1. Look at the error codes: `SELECT last_error_code, attempts, COUNT(*) FROM archive_capture_intents WHERE status = 'pending' AND (last_error_code IS NOT NULL OR next_check_at < NOW() - INTERVAL 10 MINUTE) AND created_at < NOW() - INTERVAL 6 HOUR GROUP BY 1, 2;`
2. `object_lock_unprobed`: S3 was unreachable at start; the probe is retried each pass. S3 errors (`TimeoutError`, `ServiceUnavailable`): check S3 and the IAM role. `retention_policy_missing`: the tenant has no live default retention policy (settings require one; fix through the api). `tenant_key_unavailable`: the tenant's keys exist but none is active (should not happen; check `archive_encryption_keys`).
3. Waiting (`last_error_code` NULL, `next_check_at` in the future) intents are messages not yet in a capture point (still scanning, deferred delivery, quarantined without `include.quarantined`): they are expected to wait and are not counted. A wait in quarantine is marked `category = 'quarantined'` and is bounded by 100 days (`QUARANTINE_WAIT_MAX_DAYS`, above the longest quarantine hold plus review) instead of the 25-day intent max age: the message is captured on release (delivered) or at its final state.
4. Scale `archive-worker` (HPA) if every replica is busy (`archive_capture_duration_seconds`, `ARCHIVE_CAPTURE_CONCURRENCY`).

## ArchiveCaptureLost

An intent ended `lost`: `message_missing` (the message row is gone — partition dropped after 6 months) or `original_missing` (the original EML object is gone — mail-bucket lifecycle). Lost mail cannot be archived any more; the intent stays visible under capture issues (`GET /archive/capture-issues`) for the compliance record. Repeated `original_missing` means capture lagged past the mail-bucket retention: see ArchiveCaptureBacklog and consider a longer `mail_retention_days`.

## ArchiveCaptureAgedOut

An intent was skipped with `skip_reason = 'max_age'` (`archive_capture_skipped_total{reason="max_age"}`): its message did not reach a capturable state within `ARCHIVE_INTENT_MAX_AGE_DAYS` (25; a message waiting in quarantine: 100 days) and was **not archived**. It is listed under capture issues (`GET /archive/capture-issues?status=skipped`, code `max_age`; the portal's Capture issues tab). Find out why the message stayed non-final (`SELECT status, status_reason, status_changed_at FROM email_messages WHERE id = ?`): a stuck lifecycle (scan or delivery) is a defect of that stage. An aged-out intent is not retryable; if the message later reaches a capture point and must be archived, archive it through a policy ARCHIVE action or record the gap for the compliance officer.

## ArchiveCaptureFailures

An intent ended `failed`:

| `last_error_code`         | Meaning and fix                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `object_lock_unavailable` | The tenant's mode is governance/compliance but the archive bucket has no Object Lock (or `ARCHIVE_OBJECT_LOCK=disabled`). Nothing unlocked was stored. Fix the bucket (below), then retry. |
| `integrity_mismatch`      | The original's SHA-256 differs from `email_messages.eml_sha256` (see ArchiveIntegrityFailure).                                                                                             |
| `facts_invalid`           | The message's EML key is not under `org/<organizationId>/eml/` or its hash is malformed: investigate the ingest rows.                                                                      |
| other codes               | Retries ran past `ARCHIVE_INTENT_MAX_AGE_DAYS`.                                                                                                                                            |

Retry after fixing the cause: `POST /archive/capture-issues/{messageId}/retry` (api, `archive:manage`; `failed → pending`, never for `lost`).

## ArchiveIntegrityFailure

Critical. A plaintext SHA-256 did not match: at capture (the original in the mail bucket vs `email_messages.eml_sha256`; nothing was committed, the upload was aborted) or during an export (an archived original no longer decrypts to its recorded hash; the export failed with `archive_integrity_failed`). Treat as storage corruption or tampering: preserve the object versions (do not delete), compare the object's version history (`aws s3api list-object-versions --prefix org/<org>/...`), check access logs (CloudTrail data events) and escalate to security. Never "fix" a hash in MySQL.

## ArchiveSweepStalled

`archive_sweep_lag_seconds{sweep="journal"|"policy"}` is above 30 minutes for 15 minutes (the value is the age of the newest row the sweep passed; idle = the safety lag). Only the leader writes it (`archive_leader{job="journal_sweep"}` = 1 on exactly one replica). Check the leader's logs (`archive task failed; retried` with `errName`/`errCode`), the writer, and the cursor rows above. A sweep that stops at a row newer than the safety lag waits for it by design (an in-flight ingest transaction); a sweep stuck for longer means a row with a `created_at` in the future (clock skew): fix the clock, the sweep continues.

## ArchiveIndexLag

The oldest `archive_index_queue` row is older than 15 minutes. Search and case searches are incomplete meanwhile (searches report `index_lag`). Check OpenSearch (`GET _cluster/health`), the sync leader (`archive_leader{job="index_sync"}`), and failing rows: `SELECT last_error_code, attempts, COUNT(*) FROM archive_index_queue GROUP BY 1, 2;` (`es_rejected_execution_exception`: the domain is overloaded; `strict_dynamic_mapping_exception`: a mapping mismatch after a template change — rebuild). The queue only grows while OpenSearch is down; capture is never blocked. Metrics and logs carry the HTTP status and OpenSearch error type only.

## ArchiveReconcileMismatch

The per-day reconciliation (`eg:archive-index-reconcile`, every `ARCHIVE_RECONCILE_INTERVAL_MS`; the last `ARCHIVE_RECONCILE_RECENT_DAYS` days every run and older days rotating) found a day whose MySQL count (`active` + `expiry_review`) differs from the tenant alias count. The day was repaired automatically: every record of the day re-enqueued, stray documents deleted, `archive_index_checks.state = 'repairing'` until a later run counts equal (`ok`). A mismatch that keeps coming back means documents are written outside the worker or the alias is wrong: `GET _alias/<prefix>-t<organizationId>` must list every index of the active version. eDiscovery searches report `mismatched_days` while a day is not `ok`.

```sql
SELECT day, mysql_count, index_count, state, checked_at FROM archive_index_checks
WHERE organization_id = ? AND state <> 'ok' ORDER BY day DESC LIMIT 50;
```

## Rebuild (reindex CLI)

In the worker container (`archive-worker` Deployment), with the index role running elsewhere:

```bash
# One tenant: delete its documents and re-enqueue every live record (same index version).
node dist/cli/reindex.js --organization <organizationPublicId>
# Everything into a new version: template v2 (marked building), indices built by the CLI,
# ONE atomic alias swap for every tenant, old indices and template deleted, then the records
# changed during the rebuild re-enqueued. The index role follows the active version within 60 s.
node dist/cli/reindex.js --all --version v2
```

Output is counts only. Locally: `pnpm --filter @email-gateway/archive-worker reindex -- --all`. During a tenant rebuild the tenant's search shows fewer results until the queue drains (`X-EG-Index-Lag-Seconds`). After `--all`, `GET _cat/aliases/<prefix>-t*` lists only `<prefix>-v2-*` indices.

## ArchiveDisposalStuck

A disposal is open for more than 24 h (warning) or reached `ARCHIVE_DISPOSAL_MAX_ATTEMPTS` (critical). The record is already **crypto-shredded** (its DEK is gone at the decision, A14): no readable content remains whatever the state.

```sql
SELECT id, state, attempts, last_error_code, next_attempt_at, replica_status
FROM archive_disposals WHERE state NOT IN ('completed') AND requested_at > NOW() - INTERVAL 30 DAY
ORDER BY requested_at LIMIT 50;
```

- `shredded` with `replica_status.pending` entries: object versions still under Object Lock (compliance orphans, or replica copies whose lock is still running); the pipeline retries after the recorded `retainUntil`. Nothing to do.
- `shredded` with S3 errors (`AccessDenied`): the archive-jobs role lacks `s3:DeleteObjectVersion` / `s3:BypassGovernanceRetention` on the archive or a replica bucket.
- `objects_deleted` for long: the index delete is not applied (see ArchiveIndexLag); the pipeline waits until the document is no longer visible through the tenant alias.
- `failed`: fix the cause, then re-open: `UPDATE archive_disposals SET state = 'shredded', attempts = 0, next_attempt_at = NOW(3) WHERE id = ? AND requested_at = ?;` (the pipeline is idempotent).

The disposal verification re-checks a rotating sample of completed disposals (HEAD of every recorded version in the archive bucket and each replica, document absent) and re-opens one that left something behind (`last_error_code = 'verification_reopened'`).

## ArchiveRootKeyRewrapPending

A root key rotation is in progress for more than 2 hours. See [Root key rotation](#root-key-rotation). Check `archive_root_rewrap_pending`, the leader (`archive_leader{job="root_rewrap"}`) and the `archive.root_key_rewrapped` audit rows (counts per run). Rows that fail to unwrap with the previous key are counted as `failed` and retried each run: a tenant key wrapped under neither key means the previous key configured is not the one that wrapped it.

## ArchiveExportFailures

An eDiscovery export failed; the code is on the row (`SELECT public_id, error_code FROM ediscovery_exports WHERE status = 'failed' ORDER BY id DESC LIMIT 20;`): `ediscovery_export_too_large` (bounds `ARCHIVE_EXPORT_MAX_ITEMS`/`_MAX_BYTES`: narrow the review tags), `ediscovery_export_malicious_ack_required`, `ediscovery_search_not_completed`, `archive_content_unavailable` (a record was disposed between the search and the export: run the search again), `archive_integrity_failed` (see ArchiveIntegrityFailure), S3 codes. A failed export leaves no package object.

## Tenant key rotation

`POST /archive/keys/rotate` (api, `archive:manage`, MFA): a new version becomes `active`, the previous one `retired` (decrypt-only). Workers pick up the new version within `ARCHIVE_KEY_CACHE_TTL_MS`. Existing records keep their version (no DEK re-wrap in 8.1).

## Root key rotation

1. Generate a new 64-hex key and a new id (e.g. `r2`); store both in the secret manager.
2. Deploy the api, `archive-worker` and `archive-jobs` with `ARCHIVE_ROOT_KEY`/`_ID` = the new key and id and `ARCHIVE_ROOT_KEY_PREVIOUS`/`_PREVIOUS_ID` = the old ones (Secret `email-gateway-archive-root-key`: `key`, `previous-key`, `previous-key-id`; ConfigMap `ARCHIVE_ROOT_KEY_ID`). New tenant keys are wrapped under the new key at once.
3. The lifecycle role (`eg:archive-root-rewrap`) re-wraps every `archive_encryption_keys` row whose `root_key_id` is the previous id in bounded batches (`UPDATE … WHERE id = ? AND root_key_id = ?`) and writes one `archive.root_key_rewrapped` audit row per run with counts.
4. When `archive_root_rewrap_pending` is 0 and `SELECT COUNT(*) FROM archive_encryption_keys WHERE root_key_id = '<old id>' AND wrapped_key IS NOT NULL` is 0, remove the previous key from the Secret and redeploy.

**Key custody.** The root key exists only in the secret manager and in the memory of the api and the archive Deployments; it never appears in logs, errors, metrics or audit rows. Keep a recovery copy under dual control: without it every archived message is unreadable (tenant keys are stored only wrapped, record DEKs only wrapped under tenant keys). Crypto-shredding (`wrapped_dek = NULL`) is deliberate and irreversible.

## Object Lock modes and orphans

Per tenant `archive_settings.object_lock_mode`: `none` | `governance` | `compliance` (API `immutability`). Locked tenants' objects are uploaded with the mode and `retain-until = retain_until`; whenever the lifecycle keeps a record longer (policy lengthened, hold, review) it **extends** every version (`PutObjectRetention`) before updating the row. Retention is never shortened. A mode change to a stricter mode writes `stream_cursors` `archive:lock:<organizationId>`; the lifecycle leader's apply-lock pass locks every live record's versions and removes the cursor when done (`governance → compliance` uses `BypassGovernanceRetention`).

Orphans are versions under `org/<org>/archive/<day>/` that no record and no open disposal references (a capture that failed before its commit, or lost a race). Unlocked orphans of a failed attempt are deleted by the capture itself; locked ones are deleted by the orphan reconciliation after 24 h (governance: with bypass; compliance: recorded as `archive:orphans:<org>:<day>` and retried after the lock). `archive_orphans_total{result}` counts them.

## Object Lock migration (local MinIO archive bucket)

MinIO cannot enable Object Lock on an existing bucket. `infrastructure/minio/init-buckets.sh` (the `minio-init` job) recreates `S3_BUCKET_ARCHIVE` with `--with-lock` **only if it holds zero object versions**; otherwise it fails with "exists WITHOUT Object Lock … Follow docs/runbooks/archive.md (Object Lock migration); nothing was deleted." Locally:

1. Stop the archive-worker (`docker compose stop archive-worker`) and make sure no record references the bucket (`SELECT COUNT(*) FROM email_archives;` — a development database only).
2. Remove every version of the old bucket (MinIO console or `mc rm --recursive --versions --force local/<bucket>`), then `docker compose run --rm minio-init`.
3. Start the worker; the start-up probe logs `archive bucket Object Lock probed` with `objectLock: true` and `archive_object_lock_total{op="probe",result="ok"}`.

On AWS the bucket is created with Object Lock by Terraform; an existing unlocked bucket needs a new bucket and a copy (S3 Batch Operations) — never in place.

## Replica targets

`ARCHIVE_REPLICA_TARGETS` (archive-jobs) lists every bucket that holds replicated copies (CRR to the DR bucket, step 10.2). Disposal deletes the same keys' versions in each target (replication never replicates version deletes) and the verification HEADs them. Locally the test-only bucket `ARCHIVE_TEST_REPLICA_BUCKET` (`gateway-archive-replica`, lock-enabled) simulates a target; the integration suite copies objects into it.

## Disposals and organization purge

Expiry decisions (`eg:archive-lifecycle`, one transaction per record with the row locked: extended retention, legal hold, review, or disposal) write one `archive.lifecycle_run` audit row per organization and run with the counts. Every deletion goes through `archive_disposals` (append-only, compliance tier): decision (crypto-shred, `disposing`, index delete op) → objects (archive bucket, orphans, replicas) → index → row (and the `message_identities` row when the registry purge contract requires it). An organization deletion's purge (api, A24) sends the remaining records through the same pipeline with reason `organization_deleted` and queues `purge_org` (delete-by-query with the tenant's routing and term, then the alias removed).

## OpenSearch search profile and memory (local)

```bash
docker compose --profile search up -d --wait opensearch   # 2.19.3, heap 512 MB, container limit 1.5 GB
curl -s localhost:${OPENSEARCH_HOST_PORT}/_cluster/health
curl -s "localhost:${OPENSEARCH_HOST_PORT}/_cat/aliases/eg-archive-t*?v"
```

The `search` profile starts OpenSearch alone (no ClickHouse); never start `analytics` or `observability` together with `apps` on the 16 GB VM. Measured with the apps profile: OpenSearch ≈ 1.1 GiB of its 1.5 GiB limit (WP1). Integration suites use their own index prefix (`eg-archive-wp3-<run>`) and delete it.

## Metrics

`archive_capture_total{result,source,category}`, `archive_capture_skipped_total{reason}`, `archive_capture_duration_seconds{result}`, `archive_capture_bytes_total`, `archive_intents_pending`, `archive_intent_oldest_pending_seconds` (overdue or erroring intents only), `archive_sweep_lag_seconds{sweep}`, `archive_consumer_events_total{result}`, `archive_scope_unresolved_total`, `archive_scope_truncated_total` (a journal scope's department members exceeded 250 000; members beyond it are not in scope — split the departments or narrow the scope), `archive_index_queue_depth`, `archive_index_oldest_seconds`, `archive_index_ops_total{op,result}`, `archive_index_bulk_duration_seconds`, `archive_reconcile_days_total{result}`, `archive_expiry_total{outcome}`, `archive_disposals_total{stage,result}`, `archive_disposals_pending`, `archive_disposal_oldest_pending_seconds`, `archive_object_lock_total{op,result}`, `archive_root_rewrap_pending`, `archive_orphans_total{result}`, `archive_ediscovery_searches_total{result}`, `archive_exports_total{result}`, `archive_export_bytes_total`, `archive_integrity_failures_total`, plus `archive_leader{job}` (which replica holds which leader lock) and the shared `amqp_*` consumer series.
