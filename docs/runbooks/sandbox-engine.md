# Runbook: sandbox engine (email-worker side: dispatch, dedup, results, expiry, purge)

Design: [14-sandbox.md](../plan/steps/14-sandbox.md) (decision ids X*n*: X10, X13–X17, X19, X20),
ADRs [0039](../architecture/adr/0039-sandbox-security-boundary-and-backends.md) and
[0040](../architecture/adr/0040-sandbox-engine-dispatch-results-artifacts.md), threat model
[sandbox-threat-model.md](../security/sandbox-threat-model.md). The isolated controller has its
own runbook: [sandbox-controller.md](sandbox-controller.md). Code:
`apps/email-worker/src/scanning/sandbox/`, `packages/sandbox`.

Two facts frame every step below:

- **The sandbox never changes a round's verdict.** `sandbox` is an asynchronous engine (X10): it
  is not in `SCAN_ENGINES`, never in `email_scans.required_engines`, and `aggregateRound` ignores
  its finals. Its final row (`scan_engine_results`, engine `sandbox`) is written into the round when
  the round's last submission ends — before or after the round completes — and never touches
  `email_scans` or the lifecycle. Delivery is unaffected by any sandbox outage.
- **Execution of unknown files is disabled by default** (`SANDBOX_BACKEND=disabled` on the
  controller; production allows `disabled` or `static` only). With `disabled`, every analysis ends
  `not_executed` → verdict `unknown`. `not_executed`, failures, timeouts, static-only and
  non-VM runs are never `clean`.

Data rules: rows, events, logs and metrics carry ids, hashes, sizes, types, codes and counts
only. Sample and artifact bytes exist only sealed in the sandbox bucket (`SANDBOX_S3_BUCKET`).
**Never download, decrypt or paste a sample or an artifact into a ticket or chat**; the artifact
private key is held by no service (ops script `pnpm --filter @email-gateway/sandbox artifact:open`
only, under the custody procedure of the threat model).

## Contents

- [The three hops](#the-three-hops) · [Tenant opt-in](#tenant-opt-in) · [Dispatch](#dispatch) ·
  [Dedup and reuse](#dedup-and-reuse) · [Results](#results) · [Expiry](#expiry) ·
  [Purge and retention](#purge-and-retention) · [Reading results](#reading-results) ·
  [Topology v8 rollout](#topology-v8-rollout-pre-46-submissions)
- Alerts: [SandboxResultsRejected](#sandboxresultsrejected) ·
  [SandboxSubmissionsExpiring](#sandboxsubmissionsexpiring) ·
  [SandboxDispatchBacklog](#sandboxdispatchbacklog) ·
  [SandboxTaskQueueBacklog](#sandboxtaskqueuebacklog) · [SandboxPurgeStalled](#sandboxpurgestalled)
  (rules `infrastructure/monitoring/rules/sandbox-engine.rules.yml`); the 4.2
  [SandboxSubmissionsAccumulating](attachment-scanning.md#sandboxsubmissionsaccumulating) now
  watches `scan.sandbox.submissions`.
- [Metrics](#metrics) · [Configuration](#configuration) · [Checking the alert rules](#checking-the-alert-rules)

## The three hops

```
attachment engine (round final)
  └─ sandbox_submissions (pending) + mail.attachment.sandbox_requested.v1 (outbox)
       └─ scan.sandbox.submissions ── email-worker dispatcher (ledger email-worker.scan.sandbox)
            ├─ skip / link / reuse  → submission terminal or submitted
            └─ new analysis: stage sealed sample → samples/<yyyy>/<mm>/<taskId>.bin
                 └─ mail.sandbox.task_requested.v1 (outbox) ── scan.sandbox ── sandbox-controller
                      └─ mail.sandbox.task_completed.v1 (direct publish) ── scan.sandbox.results
                           └─ email-worker results consumer (ledger email-worker.scan.sandbox.results)
                                └─ analysis + artifacts + submissions + sandbox_completed.v1 + round final
```

The engine runs where `SCAN_ENABLED=true`, `SANDBOX_ENABLED=true` and `SCAN_CONSUMERS` is empty
or contains `sandbox` (Kubernetes: Deployment `email-worker-sandbox`, `SCAN_CONSUMERS=sandbox`).
Readiness `sandbox-bucket` (HeadBucket on the sandbox bucket) is added on those replicas. The
sweeper (leader lock `scan:sandbox`) runs on the same replicas.

## Tenant opt-in

Opt-in needs **both** the plan feature `attachment_sandbox` (`organization_features`) **and** the
tenant setting `enabled: true` (`scan_engine_settings`, engine `sandbox`, through
`PUT /api/v1/scan-settings/sandbox`; the api refuses `enabled: true` without the feature with
`409 feature_not_enabled`, the worker re-checks at use). Platform defaults:
`SANDBOX_TENANT_DEFAULT_ENABLED=false`, `SANDBOX_FILE_TYPES`, `SANDBOX_MAX_SAMPLE_BYTES`
(25 MiB, ≤ 64 MiB), `SANDBOX_BROWSER_ANALYSIS`. A tenant may only narrow them (file types ⊆
platform, size ≤ platform, browser only if the platform allows it). An invalid tenant row falls
back to the platform settings and counts `scan_settings_invalid_total{engine="sandbox"}`.

Skips (submission `skipped`, codes `sandbox.<reason>`, no verdict, metric
`scan_sandbox_submissions_total{result="skipped_<reason>"}`): `feature_disabled`,
`tenant_disabled`, `type_excluded`, `size_excluded` (also an empty part). A round whose
submissions are all skipped gets a `skipped` sandbox final.

```sql
-- Is a tenant opted in? (writer or replica; no content)
SELECT f.enabled AS feature, s.settings, s.version
FROM organizations o
LEFT JOIN organization_features f ON f.organization_id = o.id AND f.feature_key = 'attachment_sandbox'
LEFT JOIN scan_engine_settings s ON s.organization_id = o.id AND s.engine = 'sandbox'
WHERE o.id = ?;
```

## Dispatch

Per `sandbox_requested.v1` (X13 steps 1–7): the part key's organization must equal the envelope's
(else dead-lettered, `tenant_mismatch`); the submission is read on the writer and echo-checked
against the event (a mismatch is the Prisma wrong-read guard: retried,
`scan_sandbox_inconsistent_reads_total{read="submission"}`); gates; profile (`browser` for
html/svg when allowed, `execute` for scripts, hta, PE, MSI, ELF, LNK, `static` otherwise) and
limits (`SANDBOX_RUN_*`; browser ≥ 1024 MiB / 256 pids); `analysisKey` (profile, limits,
`SANDBOX_ANALYSIS_EPOCH`, `sandbox-map/1`) and `dedupeKey = <sha256>:<analysisKey>`; dedup
(below); staging; transaction B (`pending → dispatched` + the task outbox row).

Staging reads the part from the mail bucket (bounded by its size, SHA-256 verified), seals it
(`sandbox-sample/1` under `SANDBOX_SAMPLE_KEY`) and writes it to the sandbox bucket with the
worker's own S3 credentials. Failures:

| Failure                                    | Effect                                                                                                                        |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| part object missing (`NoSuchKey`)          | analysis `failed`/`sample_unavailable` (dedupe key cleared), its submissions `failed`, verdict `error`; final error           |
| part bytes differ (size or hash)           | the same with `sample_integrity`                                                                                              |
| S3 / MinIO outage (mail or sandbox bucket) | transient: the delivery is held and retried (`scan_sandbox_staging_failures_total{reason="storage_unavailable"}`); it resumes |
| deadline passed while staging              | no task is written; the sweeper expires the analysis (`timeout`)                                                              |

A redelivery after a crash between the dedup transaction and transaction B resumes at staging
(the creating event is recorded in `sandbox_analyses.requested_event_id`); after B it is a ledger
duplicate. Tasks are written to the outbox; the event-relay publishes them to `scan.sandbox`.

## Dedup and reuse

One analysis per `(sha256, analysis_key)` holds the unique `dedupe_key` while it is in flight or
reusable (`SELECT … FOR UPDATE` in the dispatcher):

- **reusable** — terminal with `reuse_until > now` → the submission is linked and completed at
  once from the stored analysis (`result="reused"`), no staging, no task;
- **in flight** — `pending`/`dispatched` with `deadline_at > now` → linked only (`linked`); the
  result completes it;
- **stale** — anything else → its `dedupe_key` is set to NULL and a new analysis is created;
- a unique violation (a concurrent dispatcher) → re-read and link; a deadlock between two
  dispatchers is transient and retried.

Reuse windows (`reuse_until`): `malicious`/`suspicious` `SANDBOX_REUSE_DEFINITE_SECONDS` (1 d),
`unknown` from a completed run `SANDBOX_REUSE_UNKNOWN_SECONDS` (6 h), `not_executed` with a
sample-dependent reason (`type_not_supported`, `profile_not_supported`, `size_exceeded`)
`SANDBOX_REUSE_NOT_EXECUTED_SECONDS` (1 h); `not_executed`/`deadline_passed` (backlog) and
`not_executed`/`backend_disabled` (no backend enabled yet), `error` and `timeout` never (the dedupe
key is cleared). A
window of 0 disables reuse. **Force fresh analyses for every sample** (for example after enabling
the `static` backend, so earlier `not_executed` results are not reused): bump
`SANDBOX_ANALYSIS_EPOCH` on every sandbox replica (it is part of the analysis key).

```sql
-- Which analysis holds a hash, and its reuse window.
SELECT id, public_id, status, verdict, reuse_until, deadline_at, dedupe_key IS NOT NULL AS holds_key
FROM sandbox_analyses WHERE sha256 = ? ORDER BY id DESC LIMIT 5;
```

## Results

Per `task_completed.v1` (X13 results): ledger pre-check; the event schema **and** every code
against the security-contracts enums; the analysis `FOR UPDATE` must match the task id, the hash
and the envelope organization; the result MAC (whole payload + organization, keyed to the
analysis's `result_token_sha256`, timing-safe; an analysis without a token hash accepts no
result) must verify (`bad_mac`); it must be `dispatched`; every artifact key must be
`artifacts/<yyyy>/<mm>/<taskId>/<runId>/<seq>-<kind>.bin` of this task, all of one run id (month
between dispatch and now). Then `sandbox-map/1`, the analysis update (bounded report
view, versions, `reuse_until`), the `sandbox_artifacts` rows (wrapped keys only there), up to 200
linked submissions completed (the sweeper completes the rest), `sandbox_completed.v1` per
submission and the round finals. After commit the sample object is deleted (best effort).

| Outcome                                                  | What it means                                                                             |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| rejected (`scan_sandbox_results_rejected_total{reason}`) | nothing written but the ledger row; see [SandboxResultsRejected](#sandboxresultsrejected) |
| terminal analysis → `duplicate`                          | a duplicate result (controller redelivery); no-op                                         |
| expired analysis → `late`                                | the result arrived after the deadline; no-op (info log); the analysis stays `timeout`     |
| schema-invalid payload                                   | dead-lettered by the consumer before the handler (`dead-letter.scan.sandbox.results.*`)   |

## Expiry

The sweeper (every `SANDBOX_SWEEP_INTERVAL_MS`, batches of `SANDBOX_SWEEP_BATCH`, leader lock
`scan:sandbox`) runs, in order:

- **(a)** `pending` submissions older than `SANDBOX_SUBMISSION_TTL_SECONDS` (1 h) → `expired`
  (`sandbox.timeout`): a stopped or absent dispatcher, and every pre-4.6 row;
- **(b)** `pending`/`dispatched` analyses past `deadline_at` (`SANDBOX_TASK_DEADLINE_SECONDS`,
  15 min) → `expired` (verdict `timeout`, dedupe key cleared) with their linked submissions: the
  controller is absent, not ready, or dropped the task (bounded lossy `scan.sandbox`);
- **(c)** `submitted` submissions whose analysis is terminal → completed (catch-up);
- **(d)** samples of terminal analyses deleted;
- **(e)** artifacts past retention: crypto-shredded, then their objects deleted;
- **(f)** analyses past retention whose artifact objects are gone: rows deleted.

```sql
-- Stuck work, oldest first (replica).
SELECT status, COUNT(*), MIN(created_at) FROM sandbox_submissions
WHERE status IN ('pending','submitted') GROUP BY status;
SELECT status, COUNT(*), MIN(deadline_at) FROM sandbox_analyses
WHERE status IN ('pending','dispatched') GROUP BY status;
```

## Purge and retention

- **Samples** (`samples/…`): deleted when the analysis ends (results consumer after commit, then
  sweeper step (d), `NoSuchKey` = done; `sample_deleted_at`). Backstop: the bucket lifecycle rule
  (`SANDBOX_SAMPLE_RETENTION_HOURS` rounded up to days).
- **Artifacts** (`artifacts/…`, ≤ 16 per analysis): kept `SANDBOX_ARTIFACT_RETENTION_DAYS` (30 d).
  Purge order: **`wrapped_key = NULL`, `purged_at`, `purge_reason = 'retention'` committed first**
  (from then on the object is undecryptable), then the object delete and `object_deleted_at`;
  failed deletes are retried every pass (`scan_sandbox_purge_failures_total{kind}`). Backstop:
  bucket lifecycle `SANDBOX_ARTIFACT_RETENTION_DAYS + 1`.
- **Analyses**: deleted after `SANDBOX_ANALYSIS_RETENTION_DAYS` (≥ artifact retention) once every
  artifact object is gone and the sample is deleted (artifact rows first). Submissions keep the
  6-month partition retention of `sandbox_submissions` (their `analysis_id` may then dangle).
- **Urgent purge of one analysis's artifacts** (operator, writer): crypto-shred first, the
  sweeper deletes the objects on its next pass:

```sql
UPDATE sandbox_artifacts SET wrapped_key = NULL, purged_at = NOW(3), purge_reason = 'operator'
WHERE analysis_id = ? AND purged_at IS NULL;
```

## Reading results

Tenant-scoped through `GET /api/v1/messages/{messageId}/scans` (attachment entries carry
`sandbox { status, skipReason, verdict, reasonCodes, executed, isolation, completedAt }`; the
`sandbox` engine entry carries the per-submission detail; no reuse flag, no analysis ids or
timings). As an operator on the replica:

```sql
-- Submissions of a message and their analyses (no content).
SELECT s.part_index, s.status, s.skip_reason, s.sandbox_verdict, s.sandbox_reason_codes,
       a.public_id, a.status AS analysis_status, a.backend, a.isolation, a.executed,
       a.controller_version, a.backend_version, a.map_version, a.not_executed_reason, a.error_code
FROM sandbox_submissions s LEFT JOIN sandbox_analyses a ON a.id = s.analysis_id
WHERE s.message_id = ? AND s.received_at = ? ORDER BY s.scan_id, s.part_index;

-- The round's sandbox final (never part of email_scans.scan_verdict).
SELECT scan_id, outcome, engine_version, reason_codes, evidence, settings_version
FROM scan_engine_results WHERE message_id = ? AND received_at = ? AND engine = 'sandbox';
```

`engine_version` is `<controller version>+<backend>/<backend version>` of the most severe
analysis (`sandbox-engine/1` when none ran, e.g. all skipped or expired before dispatch).

## Topology v8 rollout (pre-4.6 submissions)

Before 4.6, `sandbox_requested.v1` went to the dormant, lossy `scan.sandbox` buffer, which v8
rebinds to the controller's tasks (the rollout purges the dormant buffer once:
[sandbox-controller.md](sandbox-controller.md)). Submissions written before 4.6 therefore have
no event on `scan.sandbox.submissions` and stay `pending`: **the sweeper expires them after
`SANDBOX_SUBMISSION_TTL_SECONDS` (verdict `timeout`)**, writing their `sandbox_completed.v1` and a
`timeout` sandbox final into their (long completed) rounds. This is expected; it does not change
any round verdict or message state. Order: deploy the email-worker with `SANDBOX_ENABLED=true`
on the sandbox replicas, run `pnpm rabbitmq:init` (v8 bindings), then the controller.

## SandboxResultsRejected

Warning, category security: a `task_completed.v1` was rejected in the last 15 minutes.

- `bad_mac` — the MAC does not verify against the analysis's result token hash: `SANDBOX_RESULT_KEY`
  differs between the email-worker and the controller (rotation done on one side only), the body
  was modified after signing (a forged publish copying a genuine MAC), a result for another task's
  token, or an analysis dispatched before result tokens existed (`result_token_sha256` NULL; it
  expires). Compare the
  key fingerprints out of band (never print the keys); check who can publish
  `org.*.mail.sandbox.task_completed.v1` (only `eg-sandbox`, rabbitmq-init verify).
- `analysis_mismatch` / `unknown_analysis` — task id, hash or organization differ from the
  analysis, or the analysis does not exist (deleted after retention, or forged).
- `not_dispatched` — a result for an analysis whose task was never written (forged or a replay
  from another environment).
- `artifact_key_invalid` — artifact keys outside the task's prefix.
- `invalid_result` — codes outside the security-contracts enums (a controller newer than the
  email-worker: upgrade the email-worker first).

Rejected results write nothing; their analyses expire at the deadline (`timeout`). If forgery is
suspected, follow the threat model's incident procedure and rotate `SANDBOX_RESULT_KEY` on both
sides ([sandbox-controller.md](sandbox-controller.md)).

## SandboxSubmissionsExpiring

Info: more than 0.1 expiries per second for 30 minutes. Check which step expires them: (a)
submissions (dispatcher not running: `SandboxDispatchBacklog`, `SCAN_CONSUMERS`,
`SANDBOX_ENABLED`) or (b) analyses (controller absent / not ready: `SandboxTaskQueueBacklog`,
controller readiness). During the v8 rollout a burst of (a) expiries is expected (above).

## SandboxDispatchBacklog

Warning: `scan.sandbox.submissions` > 1000 ready for 15 minutes. Is a sandbox replica running and
ready (`/health/ready` with `rabbitmq-scanner` and `sandbox-bucket`)? Then staging latency
(`histogram_quantile(0.95, rate(scan_sandbox_staging_seconds_bucket[10m]))`), S3/MinIO and MySQL
health, and `SANDBOX_DISPATCH_CONCURRENCY` (1..32). Held retries keep their prefetch slot: a
MinIO outage stalls the queue until it recovers (by design, nothing is lost; max retry age 24 h).

## SandboxTaskQueueBacklog

Info: `scan.sandbox` > 1000 ready for 15 minutes. The controller is down, its backend is not
ready (the consumer is cancelled while the self-test fails) or it is too slow
(`SANDBOX_CONCURRENCY`, 1..4). The queue is lossy (max 10 000, drop-head): dropped tasks' analyses
expire at their deadline. See [sandbox-controller.md](sandbox-controller.md).

## SandboxPurgeStalled

Warning: object deletions in the sandbox bucket failed for over an hour
(`scan_sandbox_purge_failures_total{kind="sample"|"artifact_object"}`). The wrapped artifact keys
are already shredded (no exposure); this is storage hygiene. Check the bucket, the email-worker's
S3 permissions (production IAM role `email-worker-sandbox`: put/get/delete `samples/*`, get/delete
`artifacts/*`) and S3 health. The lifecycle rules are the backstop.

## Metrics

`scan_sandbox_submissions_total{result}` (`dispatched`, `linked`, `reused`, `skipped_<reason>`,
`failed`, `expired`), `scan_sandbox_analyses_total{status}`, `scan_sandbox_verdicts_total{verdict}`,
`scan_sandbox_results_rejected_total{reason}`, `scan_sandbox_staging_seconds`,
`scan_sandbox_staging_failures_total{reason}`, `scan_sandbox_purged_total{kind}` (`sample`,
`artifact_key`, `artifact_object`, `analysis`), `scan_sandbox_purge_failures_total{kind}`,
`scan_sandbox_finals_total{outcome}`, `scan_sandbox_inconsistent_reads_total{read}`. No tenant,
hash, task or host label.

## Configuration

`.env.example` section "Sandbox (step 4.6 …)". The email-worker reads the platform settings
(above), `SANDBOX_ENABLED` (code default `false`), `SANDBOX_S3_BUCKET`, `SANDBOX_SAMPLE_KEY`
(+`_PREVIOUS` during rotation), `SANDBOX_RESULT_KEY`, `SANDBOX_DISPATCH_CONCURRENCY`,
`SANDBOX_RESULTS_CONCURRENCY`, `SANDBOX_TASK_DEADLINE_SECONDS`, `SANDBOX_SUBMISSION_TTL_SECONDS`,
the three reuse windows, `SANDBOX_ANALYSIS_EPOCH`, `SANDBOX_RUN_*` (≤ the controller's clamp
defaults), `SANDBOX_MAX_ARTIFACT*`, `SANDBOX_SWEEP_*`, the three retentions and
`SANDBOX_PUBLISH_HASHES` (default `false`; `true` adds malicious hashes to `malware_signatures`,
source `sandbox`, 90 days — the attachment engine then flags those files on every tenant).
Refusals at start-up (keys named, never values): bucket, sample key and result key required
where the engine runs; result key ≠ sample key; analysis retention ≥ artifact retention; sample
retention covers the deadline; deadline > run timeout; run limits ≤ controller maxima.

## Checking the alert rules

```sh
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 check rules /m/rules/sandbox-engine.rules.yml
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 test rules /m/tests/sandbox-engine.rules.test.yml
```
