# Runbook: data loss prevention (dlp engine, extraction, policies, evidence)

Design: [13-dlp.md](../plan/steps/13-dlp.md) (decision ids D*n*), ADRs
[0036](../architecture/adr/0036-dlp-engine-and-extraction.md),
[0037](../architecture/adr/0037-dlp-policy-actions-and-lifecycle-binding.md),
[0038](../architecture/adr/0038-dlp-evidence-masking-and-aadhaar-gating.md). Deployment:
[docs/deployment/dlp.md](../deployment/dlp.md). Performance: [docs/performance/dlp.md](../performance/dlp.md).
Code: `apps/email-worker/src/scanning/engines/dlp/`, `packages/dlp`.

Data rules that apply to every step below: **never paste a matched value, a masked sample, extracted
text or an evidence document into a ticket, a chat or a log.** Logs and metrics of the engine carry
ids, codes, counts and durations only; the only place a raw value exists at rest is the encrypted
evidence object, read through the audited api route (D16).

## Contents

- [The engine](#the-engine) · [Reading a result](#reading-a-result) · [Coverage reasons](#coverage-reasons)
- Alerts: [DlpEngineFailuresHigh](#dlpenginefailureshigh) · [DlpScanQueueBacklog](#dlpscanqueuebacklog) ·
  [DlpExtractionFailuresHigh](#dlpextractionfailureshigh) · [DlpExtractorKillsHigh](#dlpextractorkillshigh) ·
  [DlpEvidenceWriteFailures](#dlpevidencewritefailures) · [DlpEvidencePurgeStalled](#dlpevidencepurgestalled) ·
  [DlpBlockRateSpike](#dlpblockratespike)
- [False positives and exceptions](#false-positives-and-exceptions) · [Custom pattern rejection codes](#custom-pattern-rejection-codes)
- [Evidence access, audit, purge and key rotation](#evidence-access-audit-purge-and-key-rotation) ·
  [Aadhaar enablement](#aadhaar-enablement) · [Policy holds](#policy-holds) ·
  [Rollout order](#rollout-order) · [Checking the alert rules](#checking-the-alert-rules)

## The engine

- `dlp` is a **stage-1, required** engine on `scan.dlp` (ledger consumer `email-worker.scan.dlp`,
  Deployment `email-worker-dlp`, `SCAN_CONSUMERS=dlp`). It consumes `mail.message.parsed.v1` and
  `mail.message.rescan_requested.v1` and needs no other engine's verdict.
- Outbound and internal mail is always scanned; inbound only when the tenant setting
  `inboundEnabled` is true, otherwise a fast `skipped` final with `dlp.not_inbound`.
- Per message: echo-checked writer reads (message, parse row, attachment rows read as
  `DLP_MAX_ATTACHMENTS + 1`, tenant data LRU with `DLP_TENANT_DATA_CACHE_TTL_MS`), the stored
  bodies (`DLP_BODY_MAX_BYTES`), attachment text extraction in the **extractor children** (the
  4.2 child pool: prlimit, empty environment, permission model, `DLP_EXTRACT_CPU_SECONDS`,
  `DLP_EXTRACT_MAX_RSS_MB`, `DLP_EXTRACT_TIMEOUT_MS`), `detect()` within `DLP_DETECT_TIMEOUT_MS`,
  the tenant policy, the sealed evidence object, then the final with the `dlp_scan_results` row,
  the `dlp_evidence` row and (action ≠ `allow`) one `mail.message.dlp_incident.v1` outbox row in
  the same transaction.
- Readiness: `dlp-engine` (engine version, rules version, evidence mode) and `dlp-extractor` (at
  least one child ready, `rlimits`, `permissionModel`, extractor version) on replicas running the
  consumer.
- Failure classes: MySQL / S3 / network → transient (retried, no attempt). Wrong read →
  `inconsistent_read` (retried). Part missing / tampered / foreign key, parse row missing → not
  retryable failure final. Extractor wall clock → `inspector_timeout`, crash → `inspector_crash`
  (retried). CPU / RSS kill → definite `dlp.not_extracted.resource_limit` for that attachment.
  Detection deadline → `extract_timeout` (retried). A failure final makes the round
  `scan_failed`; outbound mail is not approved.

## Reading a result

`dlp_scan_results` (one row per round, unique `(scan_id, received_at)`), as an operator with
read access to the writer (or through the scans read API with `dlp:read`):

```sql
SELECT scan_id, lifecycle_round, direction, verdict, action, action_source, coverage,
       finding_count, evidence_status, engine_version, policy_version
FROM dlp_scan_results WHERE message_id = ? ORDER BY scan_id;
```

- `verdict`: `suspicious` (a reportable finding), `unknown` (partial coverage, nothing found),
  `clean` (complete coverage, nothing found), `skipped` (inbound not enabled). Never `malicious`.
- `action` / `action_source`: the effective DLP action of the tenant policy (`tenant_policy`, the
  winning rule in `matched_policy_id` / `matched_rule_id`) or the platform default
  (`default_policy`: alert on payment_card, bank_account, national_id, passport, credential of
  high severity, outbound and internal).
- JSON columns (masked only): `findings` (detector, code, category, severity, confidence, count,
  sources by part index and index path, ≤ 3 masked samples, custom pattern / dictionary **public
  ids**), `categories`, `coverage_detail` (`{ aadhaar, sources: [...] }`), `policy`
  (`{ winner, matched, matchedTruncated, defaultPolicyMatched, exceptionsApplied }`, public ids).
- `scan_engine_results` (engine `dlp`) holds the standard final: outcome = the verdict, reason codes
  (action code first, then detector codes by severity, coverage codes, `dlp.no_findings`).

## Coverage reasons

Any of these makes the coverage `partial`, so the verdict is never `clean`:

| Code                                                 | Meaning / action                                                                                                                    |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `dlp.not_extracted.encrypted`                        | Encrypted archive entry or password-protected PDF. A rule may hold these (`coverageReasons`).                                       |
| `dlp.not_extracted.image` / `no_text_layer`          | Image or scanned PDF (no OCR in this step). Signature images make many messages `unknown`: expected.                                |
| `dlp.not_extracted.unsupported_type`                 | Legacy Office (OLE), RTF, 7z/rar/cab/bzip2/xz, embedded objects, nested messages.                                                   |
| `dlp.not_extracted.oversize` / `not_stored`          | Larger than `DLP_ATTACHMENT_MAX_BYTES`, or the part was not stored by the parser.                                                   |
| `dlp.not_extracted.parse_error`                      | The extractor could not read the document (malformed, DOCTYPE in office XML).                                                       |
| `dlp.not_extracted.archive_limit` / `resource_limit` | A 4.2 archive limit, or the child was killed for CPU / RSS (a property of the file).                                                |
| `dlp.not_extracted.attachment_cap`                   | More than `DLP_MAX_ATTACHMENTS` attachments.                                                                                        |
| `dlp.text.truncated` / `dlp.text.body_not_stored`    | Text beyond the byte / character budgets, HTML node cap; a body the parser did not store.                                           |
| `dlp.parse.incomplete`                               | The parse may hide parts (any limit but `body_size`, or a non-final parse).                                                         |
| `dlp.custom.scan_truncated` / `pattern_invalid`      | Tenant patterns ran on part of the text only; a stored pattern or dictionary no longer validates (`scan_dlp_custom_invalid_total`). |

## Series used by the alerts

`scan_engine_results_total{engine="dlp"}`, `rabbitmq_detailed_queue_messages_ready{queue="scan.dlp"}`,
`scan_dlp_results_total{verdict,action,direction}`, `scan_dlp_findings_total{detector}`,
`scan_dlp_coverage_total{reason}`, `dlp_extractions_total{format,status}`,
`dlp_extract_duration_seconds{format}`, `dlp_detect_duration_seconds`,
`dlp_extractor_kills_total{reason}`, `dlp_policy_evaluations_total{action,source}`,
`dlp_evidence_writes_total{result}`, `dlp_evidence_purged_total{reason}`,
`dlp_evidence_expired_unpurged`, `scan_dlp_custom_invalid_total`,
`scan_dlp_inconsistent_reads_total{read}`, `dlp_evidence_sweeper_errors_total`,
`dlp_extractor_pool_children{state}`, `dlp_byte_budget_bytes{kind}`, `dlp_extractor_info{extractor,pdfjs}`.

## DlpEngineFailuresHigh

More than 5 % of the final dlp results are `timeout` / `error`. Split by reason:
`sum by (reason) (rate(scan_engine_failures_total{engine="dlp"}[10m]))`.
`inconsistent_read` → see the 4.2 §6 writer-stall notes (the attempts retry); `inspector_timeout`
/ `inspector_crash` → [DlpExtractorKillsHigh](#dlpextractorkillshigh); `extract_timeout` → raise
`DLP_DETECT_TIMEOUT_MS` only after checking `dlp_detect_duration_seconds` (the deadline counts the
message's own detection work, not the time other scans hold the event loop, so a timeout means a
very large text or CPU starvation of the whole process, e.g. a CPU limit too low for the
replica); `part_*` → the parser's objects (S3). Rescan the affected messages after the fix
(`POST /api/v1/messages/{id}/rescan`).

## DlpScanQueueBacklog

`scan.dlp` has more than 1 000 ready messages for 10 minutes: outbound delivery waits. Check
`dlp_extractor_pool_children{state="waiting"}`, `dlp_byte_budget_bytes{kind="used"}` and the
replica count; scale `email-worker-dlp` (each replica needs ≈ 2 GiB, deployment doc). A queue with
no consumer at all (`rabbitmq_detailed_queue_consumers{queue="scan.dlp"} == 0`) after a rollout means
phase 1 was skipped: see [Rollout order](#rollout-order).

## DlpExtractionFailuresHigh

More than 10 % of extractions end with `parse_error` or `resource_limit`. Look at
`dlp_extractions_total` by format: one format (often `pdf`) after an upgrade points to the
extractor; many formats point to a campaign of hostile attachments (they stay `unknown`, never
clean; a tenant rule on `coverageReasons` can hold them). Do not raise the limits above the
deployment's memory budget.

## DlpExtractorKillsHigh

More than 10 extractor children killed in 15 minutes. `dlp_extractor_kills_total` by reason:
`cpu` / `memory` are file properties (definite `resource_limit`), `wall` / `crash` are retried
attempts. Repeated `crash` with readiness flapping: check the container's memory limit (the
kernel OOM killer kills the child before the sampler does) and the node's prlimit.

## DlpEvidenceWriteFailures

An evidence object could not be sealed or stored: the result carries `evidence_status = failed`
(the finding and the action stand). Check the bucket (S3 errors in the worker log by error name)
and the key (`DLP_EVIDENCE_KEY` must be 64 hex; the worker refuses to start otherwise). Nothing to
replay: a rescan writes new evidence for the new round.

## DlpEvidencePurgeStalled

Expired evidence rows still hold a wrapped key or an object for two hours. Exactly one
`email-worker-dlp` replica holds `GET_LOCK('scan:dlp-evidence')` and sweeps every
`DLP_EVIDENCE_SWEEP_INTERVAL_MS`. Check `dlp_evidence_sweeper_errors_total`, the leader's log
(`dlp evidence sweeper pass failed`) and S3 deletes. Rows are crypto-shredded first
(`wrapped_key = NULL`, `purged_at`, `purge_reason = 'retention'`), the object is deleted after, and
`object_key` is cleared only after a successful delete, so a lost delete is retried. Manual check:

```sql
SELECT COUNT(*) FROM dlp_evidence
WHERE expires_at <= NOW(3) AND (wrapped_key IS NOT NULL OR object_key IS NOT NULL);
```

## DlpBlockRateSpike

Informational: block + quarantine actions above 3 × the 1-day average. Either an exfiltration
attempt (check the incidents API `GET /api/v1/dlp/incidents?action=block`) or a new tenant rule or
custom pattern producing false positives (audit rows `dlp_rule.*`, `dlp_pattern.*`).

## False positives and exceptions

1. Find the finding codes and masked samples through the scans read API (`dlp:read`).
2. Prefer narrowing the rule (`minCount`, `minConfidence`, `recipients.externalOnly`,
   `attachmentsOnly`) or raising the category threshold (`/api/v1/scan-settings/dlp`, 0.5–0.95).
3. For a known partner or sender, add an **exception** (`POST /api/v1/dlp/exceptions`: scope
   sender/recipient address or domain, optional policy/rule target and detector/category filter,
   reason and expiry required). Applied exceptions are recorded in the result
   (`dlp.exception.applied`, `policy.exceptionsApplied`). Recipient exceptions are never applied to
   a truncated recipient list.
   Sender exceptions match the envelope sender (MAIL FROM), which nothing binds to an
   authenticated user: anyone submitting through the organization's connector (or any inbound
   sender) can use an exempted address. Prefer recipient or domain exceptions, and keep sender
   exceptions narrow (detector/category filter, short expiry).
4. Noisy detectors `PI1`, `PI2`, `BA3`, `SC1`, `CF2` may be disabled per tenant
   (`disabledDetectors`); the others cannot.
5. Changes apply within `DLP_TENANT_DATA_CACHE_TTL_MS` (30 s). Use a `monitor` policy first for a
   new rule.

## Custom pattern rejection codes

`pattern_syntax` (not RE2), `pattern_unsupported` (backreference, lookaround, possessive),
`pattern_too_complex` (`{n,m}` with m > 100 or nested product > 1 000), `pattern_matches_empty`,
`pattern_too_broad` (> 50 matches on the probe corpus), `pattern_too_slow` (> 50 ms on the probe
corpus), `pattern_invalid_options` (validator, keywords). The api's test endpoint
(`POST /api/v1/dlp/patterns/test`) returns the same codes; the sample and the pattern are never
logged. A stored pattern that stops validating (library upgrade) is skipped with
`dlp.custom.pattern_invalid` (partial coverage, `scan_dlp_custom_invalid_total`).

## Evidence access, audit, purge and key rotation

- **Read:** `GET /api/v1/messages/{messageId}/scans/{scanId}/dlp-evidence` — `dlp:evidence_read`,
  MFA, user only; the audit row `dlp_evidence.read` is committed before any byte is decrypted;
  `410 evidence_purged` / `evidence_expired`. Never store the response.
- **Purge:** `DELETE …/dlp-evidence` (one) or `DELETE /api/v1/dlp/evidence` (the tenant's), audited
  `dlp_evidence.purged`; the sweeper deletes the objects of purged rows it finds with an
  `object_key`.
- **Never raw in evidence:** Aadhaar (masked, also inside other matches' context), private keys
  (BEGIN line only), secrets / tokens (type only), JWT (header only), card numbers (first 6 + last
  4), CVV-like codes after `cvv`/`cvc`/`csc` (`***`).
- **Key rotation** (`DLP_EVIDENCE_KEY`, Secret `email-gateway-dlp-evidence-key`): generate 32 random
  bytes as hex; set the old key as `previous-key` and the new one as `key`; restart the api and
  `email-worker-dlp` (api first, so it can open evidence sealed with either key). Keep
  `previous-key` for at least `DLP_EVIDENCE_MAX_RETENTION_DAYS` (180) days, then remove it. There is
  no re-wrap job in this step. **Never** reuse `DATA_ENCRYPTION_KEY`.
- **Lost key:** every evidence row sealed under it is undecryptable (crypto-shredded in effect);
  results, findings and actions are unaffected.

## Aadhaar enablement

NI2 (Aadhaar) runs only for tenants with a recorded compliance basis
(`PUT /api/v1/dlp/compliance/aadhaar`, `dlp:compliance_manage`, MFA): enabled, a basis and a
reference, attested, and `aadhaar_review_due_at` in the future. Otherwise the detector does not run
at all (`coverage_detail.aadhaar = "disabled"`). Values are stored masked (last 4) only. Whether the
tenant's basis is lawful is the tenant's decision, not a platform function. An expired review turns
detection off silently at the next cache refresh; ask the tenant to renew.

## Policy holds

Since step 5.2 the policy-engine binds the DLP action (ADR-0037 through the strictness floor,
[policy-engine runbook](policy-engine.md)): `allow` → delivered; `alert` → delivered with the
mandatory `dlp-alert` TAG (outbound: recorded, header not added by default); `require_approval` → `held_for_review`;
`quarantine` → `quarantined`; `block` → `rejected` (outbound: a sender non-delivery notice is
requested unless the tenant turned `notices.senderNonDelivery` off; default on); a missing dlp
row is held. Counted in
`policy_floor_raises_total{reason="dlp_<action>"}`. The pass-through metrics
`delivery_dlp_holds_total` and `delivery_approvals_skipped_total` no longer exist.

## Rollout order

Two phases (D1): (1) deploy the new image to every service with `SCAN_ENGINES` unchanged and
`email-worker-dlp` running (it consumes `scan.dlp` already); (2) add `dlp` to `SCAN_ENGINES` in
`email-gateway-config` and restart the scan replicas. A replica that opens rounds requiring `dlp`
while nobody consumes `scan.dlp` ends those rounds `scan_failed` at the deadline (never clean).
Detection query:

```sql
SELECT COUNT(*) FROM email_scans
WHERE status = 'timed_out' AND JSON_CONTAINS(required_engines, '"dlp"')
  AND started_at > NOW(3) - INTERVAL 1 HOUR;
```

## Checking the alert rules

```sh
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 check rules /m/rules/dlp-scanning.rules.yml
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 test rules /m/tests/dlp-scanning.rules.test.yml
```
