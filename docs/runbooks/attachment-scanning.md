# Runbook: attachment scanning (ClamAV, YARA, inspector, cache, signature updates, rescans)

Step 4.2 ([design](../plan/steps/10-attachment-scanning.md), [ADR-0028](../architecture/adr/0028-attachment-scanning-engine.md), deployment: [attachment-scanning.md](../deployment/attachment-scanning.md), benchmark: [performance/attachment-scanning.md](../performance/attachment-scanning.md)). The attachment engine is one engine of the [scan pipeline](scan-pipeline.md); the URL engine of the same rounds: [url-scanning.md](url-scanning.md) (queue `scan.attachment`, ledger consumer `email-worker.scan.attachment`, production Deployment `email-worker-attachment`, `SCAN_CONSUMERS=attachment`). It is **required** in every round: a round whose attachment engine cannot decide ends `scan_failed`. Every alert of `infrastructure/monitoring/rules/attachment-scanning.rules.yml` links a section of this page; the generic scan alerts (`ScanEngineCircuitOpen`, `ScanRoundsFailing`, `ScanDeadlineFinalizations`, …) apply with `engine="attachment"` too.

**Rules that hold in every procedure below:**

- **Never clean by accident.** clamd errors, timeouts or an open breaker, an inspector crash or wall-clock timeout, a missing or corrupt part object, a Redis error and an incomplete attachment list are never `clean`. `clean` needs a complete inspection and a definite ClamAV `OK` (rule C1).
- **No file content outside S3 and memory.** Never copy an attachment to a laptop, a ticket or a shared drive; never run `clamdscan` on an extracted file. Investigate with hashes (`sha256`), sizes, type ids, signature and rule names, reason codes. Archive entries are identified by index path (`"2/0/5"`), never by name.
- **Never open or execute an attachment** (not even in a "safe" viewer). Detonation is the sandbox's job (step 4.6).
- **Engines classify, policy decides.** The engine records verdicts and sandbox submissions; it never strips, blocks or quarantines.
- **One door.** Rescans go through the lifecycle (E19: api `admin_rescan`, rescan jobs `signature_rescan`). Never edit `attachment_scan_results`, `scan_engine_results` or `email_messages` by hand.
- Read on the **replica** for investigations (or the scans read API); the writer is for the services.

## Contents

- [How an attachment is scanned](#how-an-attachment-is-scanned) · [Reading results](#reading-results) · [Series used by the alerts](#series-used-by-the-alerts)
- Alerts: [ClamavUnavailable](#clamavunavailable) · [ClamavSignaturesStale](#clamavsignaturesstale) · [AttachmentScanFailuresHigh](#attachmentscanfailureshigh) · [AttachmentInspectorKills](#attachmentinspectorkills) · [AttachmentScanQueueBacklog](#attachmentscanqueuebacklog) · [AttachmentScanLatencyHigh](#attachmentscanlatencyhigh) · [AttachmentCacheErrors](#attachmentcacheerrors) · [AttachmentSignatureChanged](#attachmentsignaturechanged) · [SandboxSubmissionsAccumulating](#sandboxsubmissionsaccumulating)
- Procedures: [clamd down, slow or OOM](#clamd-down-slow-or-oom) · [signature updates and rescan jobs](#signature-updates-and-rescan-jobs) · [inspector kills](#inspector-kills) · [limits tuning](#limits-tuning) · [known-hash management](#known-hash-management) · [cache flush](#cache-flush) · [the dev pass-through malicious hold](#the-dev-pass-through-malicious-hold) · [checking the alert rules](#checking-the-alert-rules)

## How an attachment is scanned

Per round (A3): the parse row and the `email_attachments` rows of the message are read on the writer for the envelope's organization; no rows on a complete parse → `skipped` (`attachment.none`); an incomplete parse (not final, no recorded attachment count, or any parse limit except `body_size`, including the header and decoded-ratio stops) → at least `suspicious` (`attachment.parse_incomplete`). The reads are echo-checked (message, organization, `received_at`, part order, requested hashes) and the number of attachment rows must match the parse row's `attachment_count`: a mismatch is a retried `inconsistent_read` attempt, never `skipped`. The SHA-256 of every attachment is looked up in `malware_signatures` (never cached). Per attachment (`ATTACHMENT_PER_MESSAGE_PARALLELISM` at a time, `ATTACHMENT_MEMORY_BUDGET_BYTES` byte budget): not stored or above the tenant's `maxAttachmentBytes` → `limit.attachment_size` + `attachment.not_scanned`; the part key must be `org/<org>/part/…`; the content cache (`eg:scan:att:v2:<sha256>:<contentVersion>`) is consulted; on a miss the part is read from S3 in full (size and SHA-256 verified), streamed to clamd (`INSTREAM` in one `IDSESSION` with `VERSION`) and, in parallel, inspected by a child process of the inspector pool (true type, archive walk with every limit checked while inflating, YARA-X on the attachment and each entry, office macro marker). Inner entry hashes are looked up; the result is cached; the verdict mapper `attachment-map/1` (A6) gives the attachment verdict (`malicious > suspicious > unknown > clean`); the engine result is the most severe one. Suspicious and unknown attachments with a stored part are submitted to the sandbox (a `sandbox_submissions` row + `mail.attachment.sandbox_requested.v1`, at most `ATTACHMENT_SANDBOX_MAX_PER_MESSAGE`), in the same transaction as the final row.

Attempt failures (retried with backoff up to `SCAN_ATTACHMENT_MAX_ATTEMPTS`, counted by the breaker): `unavailable`, `timeout`, `protocol_error` (clamd), `inspector_timeout`, `inspector_crash`. Retried but not the engine's fault: `inconsistent_read` (a writer read returned rows of another request, the Prisma wrong-read defect after a database stall; `scan_attachment_inconsistent_reads_total{read}` — a steady rate is a database-connection problem, not a scanner problem). Not retried, not the engine's fault: `part_unavailable` (NoSuchKey), `part_integrity` (size or hash differs), `part_key_mismatch`, `parse_row_missing`.

## Reading results

Tenant-scoped through `GET /api/v1/messages/{messageId}/scans` (engine `attachment` carries `attachments[]`). Tenants never see the cache result or the attachment engine's durations (the cache is shared across organizations; the times are whole seconds): read `cache_result` and `duration_ms` on the replica as an operator. On the replica:

```sql
-- Per-attachment results of a message's rounds (no content, no entry names).
SELECT s.lifecycle_round, r.part_index, r.verdict, r.reason_codes, r.detected_type, r.size_bytes,
       r.sha256, r.clamav_signature, r.clamav_db_version, r.yara_bundle_id, r.yara_matches,
       r.known_hash_severity, r.cache_result, r.duration_ms
FROM attachment_scan_results r
JOIN email_scans s ON s.id = r.scan_id AND s.received_at = r.received_at
WHERE r.message_id = ? AND r.received_at = ? AND r.organization_id = ?
ORDER BY s.lifecycle_round, r.part_index;

-- Where else a hash was seen (one organization).
SELECT message_id, received_at, verdict FROM attachment_scan_results
WHERE organization_id = ? AND sha256 = ? ORDER BY received_at DESC LIMIT 50;
```

The engine's final row (`scan_engine_results`, engine `attachment`) has `engine_version` = `clamav/<engine>/<db>;yara-x/<binding>/<bundle12>`, `settings_version` = `attachment-map/1;p=<12 hex>;t=<row version | none>`, signals `clamav:<signature>`, `yara:<rule>`, `hash:<12 hex>` with `part <index>`.

## Series used by the alerts

`scan_attachment_files_total{verdict,cache}`, `scan_attachment_stage_duration_seconds{stage}`, `scan_attachment_bytes_total{stage}`, `scan_attachment_detections_total{source,severity}`, `scan_attachment_findings_total{code}`, `scan_attachment_cache_total{result}`, `scan_attachment_inspector_kills_total{reason}`, `scan_attachment_inspector_pool{state}`, `scan_attachment_memory_budget_bytes{state}`, `clamav_requests_total{result}` / `clamav_request_duration_seconds{result}`, `scan_attachment_signature_info{component,version}`, `scan_attachment_clamav_db_age_seconds`, `scan_attachment_signature_changes_total{component}`, `scan_attachment_sandbox_submissions_total{verdict}`, `scan_attachment_rescan_messages_total{result,trigger}`; generic: `scan_engine_*{engine="attachment"}`, `scan_event_lag_seconds{engine="attachment"}`; queues: `rabbitmq_detailed_queue_messages_ready{queue="scan.attachment"|"scan.sandbox"}`. Labels are bounded enums: never a hash, a filename, a signature or rule name.

## ClamavUnavailable

The attachment engine's breaker is open (clamd refused or timed out repeatedly, or the inspector keeps failing). Check `clamav_requests_total{result=~"error|timeout"}` vs `scan_attachment_inspector_kills_total` to tell which. clamd: see [clamd down, slow or OOM](#clamd-down-slow-or-oom). Rounds keep retrying (hold retries, ~2 minutes of outage are absorbed with the defaults); longer → `scan_failed` → [rescan](#signature-updates-and-rescan-jobs) after recovery. Readiness of `email-worker-attachment` reports `clamav` down, so pods leave the Service but the consumer keeps its deliveries held (no loss).

## ClamavSignaturesStale

`scan_attachment_clamav_db_age_seconds` > 48 h: freshclam is not updating. Check the clamd pod log for freshclam (`Can't download`, `rate limited`, mirror errors, disk full of the database volume). Production should use a private mirror (deployment doc). Do not restart clamd repeatedly: every start reloads the full database (~1 GiB, minutes).

## AttachmentScanFailuresHigh

More than 5 % of final attachment results are `timeout`/`error`. Break down by `error_code` on the replica:

```sql
SELECT error_code, COUNT(*) FROM scan_engine_results
WHERE engine = 'attachment' AND is_final = 1 AND outcome IN ('timeout','error')
  AND received_at >= NOW() - INTERVAL 1 DAY GROUP BY error_code;
```

`unavailable`/`timeout`/`protocol_error`/`circuit_open` → clamd; `inspector_*` → [inspector kills](#inspector-kills); `part_unavailable`/`part_integrity` → S3 objects deleted or corrupted (check lifecycle rules and the MIME stage's `mime_*` series); `part_key_mismatch` is a tenancy defect (escalate, never "fix" rows); `deadline_exceeded` → the queue was not consumed in time ([backlog](#attachmentscanqueuebacklog)).

## AttachmentInspectorKills

Children are killed more than 0.1/s. `reason`: `cpu` / `memory` are a property of the file (definite `limit.cpu_time` / `limit.memory`, suspicious) — a burst means hostile or unusual files; check `scan_attachment_findings_total{code=~"limit.cpu_time|limit.memory"}` and the hashes in `attachment_scan_results`. `wall` (`inspector_timeout`, retried) means an overloaded host: compare pod CPU with its limit, lower `ATTACHMENT_INSPECTOR_POOL_SIZE` or add replicas. `crash` (`inspector_crash`, retried) means a native fault or an inspection bug: collect pod events (OOMKilled?), the binding version and the hashes; repeated crashes on the same file end `scan_failed` after the attempt budget (never clean).

## AttachmentScanQueueBacklog

`scan.attachment` > 1 000 ready or p95 event lag > 180 s. Scale `email-worker-attachment` (KEDA target 200 ready per replica) **and** keep `CLAMAV_MAX_CONNECTIONS × replicas ≤ clamd MaxThreads × clamd replicas` (scale clamd too). Check `scan_attachment_stage_duration_seconds` for the slow stage and the cache hit ratio (`scan_attachment_files_total{cache="hit"}`).

## AttachmentScanLatencyHigh

p95 of `stage="total"` > 30 s. Compare stages: `clamav` (clamd threads saturated, database reload with `ConcurrentDatabaseReload no`), `inspect` (pool too small, CPU-starved pod), `s3_read` (S3 latency), `cache_get` (Redis slow; bounded by `ATTACHMENT_CACHE_TIMEOUT_MS`).

## AttachmentCacheErrors

Redis errors or timeouts on the content cache. Scans continue without it (`cache_result = bypass`), never failing or producing `clean`, but every attachment is scanned in full (clamd load rises). Check Redis health and latency; nothing to clean up afterwards.

## AttachmentSignatureChanged

Informational: a ClamAV database (`clamav_db`), engine (`clamav_engine`) or YARA bundle (`yara_bundle`) version changed (`scan_signature_versions`). Old cache keys are unreachable at once. With `ATTACHMENT_SIGNATURE_RESCAN=record` (default) a `skipped` job row records the change; with `rescan` a `pending` job rescans recent messages ([below](#signature-updates-and-rescan-jobs)).

## SandboxSubmissionsAccumulating

Step 4.6 (topology v8): `mail.attachment.sandbox_requested.v1` is bound to the work queue `scan.sandbox.submissions`, consumed by the email-worker's sandbox dispatcher (ledger `email-worker.scan.sandbox`); `scan.sandbox` now carries the controller's tasks. Informational: more than 5000 ready submissions for 15 minutes means the dispatcher is not running (`SANDBOX_ENABLED=true` and `SCAN_CONSUMERS` empty or naming `sandbox` on some replica; Kubernetes `email-worker-sandbox`) or not keeping up (`SANDBOX_DISPATCH_CONCURRENCY`, S3 and MySQL latency). The round never waits for the sandbox; pending submissions expire after `SANDBOX_SUBMISSION_TTL_SECONDS` (verdict `timeout`, never `clean`). The authoritative record is `sandbox_submissions`; the volume submitted by this engine is `scan_attachment_sandbox_submissions_total{verdict}`. Dispatch, dedup and the warning-level backlog alert are in [sandbox-engine.md](sandbox-engine.md#sandboxdispatchbacklog).

## clamd down, slow or OOM

- **Down**: `kubectl get pods -l app.kubernetes.io/name=clamav`; locally `docker compose ps clamav` and `docker compose logs --tail 100 clamav`. A start takes about a minute (database load, longer on the first download). Locally: never run two clamd instances on the 8 GB VM, never start the analytics/observability profiles with the apps profile.
- **Slow**: clamd's `MaxThreads` reached (queued requests wait up to `CLAMAV_TIMEOUT_MS`), or a non-concurrent database reload (local `ConcurrentDatabaseReload no` blocks scans for the reload, ~6 s measured). Production uses concurrent reloads.
- **OOM**: the local container has `mem_limit 2048m` (peak measured 1.36 GiB at start, design §12 WP2). In production size pods for two engines in memory during a concurrent reload (requests 1.5 GiB, limit 3 GiB). An OOM kill shows as `ClamavUnavailable` and `clamav_requests_total{result="error"}`.
- `limit.clamav` with `clamav_requests_total{result="size_limit"}`: clamd refused a stream above its `StreamMaxLength` — a misconfiguration (it must stay above `ATTACHMENT_MAX_BYTES`, 30M vs 25 MiB).

## Signature updates and rescan jobs

The signature watcher (leader lock `scan:attachment-signatures`) polls every `ATTACHMENT_SIGNATURE_POLL_MS` and records versions in `scan_signature_versions`. Jobs live in `attachment_rescan_jobs` and are executed by the rescan runner (leader lock `scan:attachment-rescans`): every `ATTACHMENT_RESCAN_INTERVAL_MS`, at most `ATTACHMENT_RESCAN_BATCH_SIZE` candidates (default 50 per 10 s ≈ 300/min) from the job's window and states, with attachments, whose latest round's attachment final is not `malicious` (a `scan_failed` message always qualifies). Each candidate gets E19 (`scanner`, `signature_rescan`) and a `rescan_requested.v1` (every engine rescans: Rspamd too).

- **Admin job** (api, `platform:scan_rescan`, MFA): `POST /api/v1/platform/attachment-rescans` `{ windowHours, states?, organizationId?, maxMessages?, reason, dryRun? }`; list/get/cancel under the same path. Start with `dryRun: true` to see the estimate.
- **Progress**: `SELECT public_id, status, selected_count, requested_count, skipped_count, cursor_received_at, last_error FROM attachment_rescan_jobs ORDER BY created_at DESC LIMIT 20;` and `scan_attachment_rescan_messages_total`. A cancelled job stops at the next batch.
- **After a clamd outage**: messages that ended `scan_failed` are candidates of an admin job with `states: ['scan_failed']` and the outage window.
- Watch [ScanQueueBacklog](scan-pipeline.md#scanqueuebacklog) and [AttachmentScanQueueBacklog](#attachmentscanqueuebacklog) during large jobs; cancel if the queues grow.

## Inspector kills

Per file the worker samples each child's CPU time and RSS every 100 ms and SIGKILLs it above `ATTACHMENT_INSPECT_CPU_SECONDS` (10) or `ATTACHMENT_INSPECT_MAX_RSS_MB` (384); the wall clock is `ATTACHMENT_INSPECT_TIMEOUT_MS` (30 s). Children run under `prlimit --cpu --core=0` (`ATTACHMENT_INSPECTOR_RLIMITS=required`; the pool refuses to start without prlimit) and Node's permission model (no child processes, no file writes). Readiness `attachment-inspector` reports `ready`, `size`, `rlimits` and `bundleId`. A child is recycled after `ATTACHMENT_INSPECTOR_MAX_JOBS` jobs and after every kill. Stale private directories (`eg-inspect-*` older than 10 minutes) are removed at start.

## Limits tuning

Platform-only (they decide the cached content result; change them on the api and every scan worker together, ConfigMap `email-gateway-config`): `ATTACHMENT_ARCHIVE_MAX_DEPTH` (3), `_MAX_ENTRIES` (1000), `ATTACHMENT_MAX_ENTRY_BYTES` (25 MiB), `ATTACHMENT_MAX_DECOMPRESSED_BYTES` (100 MiB), `ATTACHMENT_MAX_COMPRESSION_RATIO` (100), CPU/RSS/YARA timeouts. Changing them changes the content version (A9): every cache entry becomes unreachable (a burst of full scans). Tenants may only tighten `maxAttachmentBytes`, add denied types, set an allow list and raise the type/mismatch/encrypted verdicts (`PUT /api/v1/scan-settings/attachment`). Changes apply to new scans; rescan to re-evaluate.

## Known-hash management

Platform-wide catalog `malware_signatures` (permission `platform:threat_intel_manage`, MFA, audited): `POST /api/v1/platform/threat-hashes` `{ sha256, severity, family?, reason, expiresAt? }`, `DELETE /api/v1/platform/threat-hashes/{sha256}?reason=`. Takes effect on the next scan at once (the lookup is never cached; cache hits still consult it). Severity `high`/`critical` → `malicious` (`malware.known_hash`), `low`/`medium` → `suspicious`. To act on mail already scanned, start an admin rescan job for the window.

## Cache flush

Values are `<mac>.<json>` under `ATTACHMENT_CACHE_HMAC_KEY` (only the attachment worker has it). A rising `scan_attachment_cache_total{result="rejected"}` means entries with a wrong MAC or shape: a key rotation in progress (harmless, misses until rewritten), replicas with different keys (give every attachment replica the same Secret), or someone writing `eg:scan:att:` keys into the shared Redis — investigate the Redis clients; the scanner already ignores such entries and rescans. Rotating the key: update the Secret `email-gateway-attachment-cache-key` (Compose: `.env`) and restart the attachment workers; old entries become misses.

Normally unnecessary (signature or limit changes switch the content version). To drop all content results (e.g. after an inspector bug fix shipped without a version change), scan and unlink the prefix — **never `FLUSHDB`** (the Redis instance is shared):

```bash
redis-cli --scan --pattern 'eg:scan:att:v2:*' | xargs -r -n 500 redis-cli unlink
```

One file only: `redis-cli --scan --pattern 'eg:scan:att:v2:<sha256>:*' | xargs -r redis-cli unlink`. Keys of the former unauthenticated format (`eg:scan:att:v1:*`) are never read; they expire by their TTL or can be unlinked the same way.

## Malicious attachments and policy

Since step 5.2 the development pass-through is gone: the policy-engine decides every scanned round ([policy-engine runbook](policy-engine.md)). A `malicious` attachment fires a risk hard block, and the policy strictness floor (`policy.floor.hard_block`) never lets it be delivered: EICAR ends `rejected` / `policy_discard` (inbound: no bounce), counted in `policy_evaluations_total{disposition="reject"}` and `policy_floor_raises_total{reason="hard_block"}`. The quarantine store is step 5.3.

## Checking the alert rules

```bash
cd infrastructure/monitoring
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 check rules rules/attachment-scanning.rules.yml
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 test rules tests/attachment-scanning.rules.test.yml
```
