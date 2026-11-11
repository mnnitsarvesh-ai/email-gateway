# Runbook: phishing and BEC detection (bec engine, stage trigger, AI layer, history)

Step 4.4 ([design](../plan/steps/12-phishing-bec.md), [ADR-0033](../architecture/adr/0033-bec-engine-and-stage-dependencies.md), [ADR-0034](../architecture/adr/0034-bec-ai-layer-invariant.md), [ADR-0035](../architecture/adr/0035-bec-communication-context-privacy.md), deployment: [bec-detection.md](../deployment/bec-detection.md)). The bec engine is one engine of the [scan pipeline](scan-pipeline.md) (queue `scan.bec`, ledger consumer `email-worker.scan.bec`, production Deployment `email-worker-bec`, `SCAN_CONSUMERS=bec`). It is **required** in every round and it is the first **stage-2** engine: it does not consume `parsed.v1`/`rescan_requested.v1` but `mail.message.scan_stage_ready.v1`, which the scan stage writes when the round's `rspamd` and `url` finals exist. The same replicas run the communication-history retention sweeper (lock `scan:bec-history`). Every alert of `infrastructure/monitoring/rules/bec-scanning.rules.yml` links a section of this page; the generic scan alerts (`ScanEngineCircuitOpen`, `ScanRoundsFailing`, `ScanDeadlineFinalizations`, …) apply with `engine="bec"` too.

**Rules that hold in every procedure below:**

- **Never clean by accident.** A failed, missing or not-in-round dependency (authentication, URL results), an incomplete text, a history read error and an AI failure are never `clean`: they add `bec.input_unavailable.*`, `bec.content_incomplete`, `bec.history_unavailable` and keep the verdict at least `unknown`. `clean` comes only from rule C0 (`clean.below_threshold`) with every input available.
- **Deterministic first.** The verdict is `bec-map/1` (rules with weights). The AI layer (local model, LLM) can never produce `clean`, never lower a verdict, raise to at most `suspicious` alone, and corroborate `malicious` only within `BEC_AI_MALICIOUS_BAND` of the threshold with identity **and** intent evidence. Shadow assessments never change anything.
- **Engines classify, policy decides.** The bec engine records a verdict, codes and evidence; it never blocks, quarantines or delivers (since step 5.2 the policy-engine holds them: the platform default quarantines a deterministic `suspicious` verdict and a `malicious` one fires the `hb.bec_malicious` hard block; step 4.4 B17).
- **No mail content in tickets.** Rows hold codes, weights, scores, span **offsets**, profile public ids and the tenant's own header identities; never body text, span text or excerpts. Logs carry ids, codes, counts and durations only. Do not paste message text into tickets or chat; reference `message_id`, `scan_id` and reason codes.
- **One door.** Rescans go through the lifecycle (api `admin_rescan`). Never edit `bec_scan_results`, `bec_contact_history` or `scan_engine_results` by hand; tenant data (profiles, trusted senders, suppressions, history purge) only through the api (`/api/v1/bec/…`, audited).
- Read on the **replica** for investigations (or the scans read API); the writer is for the services.

## Contents

- [The engine and the stage trigger](#the-engine-and-the-stage-trigger) · [Reading a verdict](#reading-a-verdict) · [Series used by the alerts](#series-used-by-the-alerts)
- Alerts: [BecEngineFailuresHigh](#becenginefailureshigh) · [BecScanQueueBacklog](#becscanqueuebacklog) · [BecStageTriggerStall](#becstagetriggerstall) · [BecInputsUnavailableHigh](#becinputsunavailablehigh) · [BecLlmErrorsHigh](#becllmerrorshigh) · [BecLlmBudgetExhausted](#becllmbudgetexhausted) · [BecMaliciousRateSpike](#becmaliciousratespike)
- Procedures: [profiles and trusted senders](#profiles-and-trusted-senders) · [false positives and suppressions](#false-positives-and-suppressions) · [history opt-in, purge and key rotation](#history-opt-in-purge-and-key-rotation) · [LLM enablement](#llm-enablement) · [budgets](#budgets) · [data handling](#data-handling) · [model rollout (active / shadow, model:check)](#model-rollout) · [checking the alert rules](#checking-the-alert-rules)

## The engine and the stage trigger

**Trigger (B2).** Engines declare `dependsOn` in the catalog; `bec` depends on `rspamd` and `url`. In the finalize transaction of every engine final (message row and scan row locked, finals read after the locks) the scan stage checks: is there a required engine with dependencies, without a final, whose required dependencies all have finals, and was one of those dependencies the final this transaction inserted? Then it writes one `mail.message.scan_stage_ready.v1` outbox row (`{ messageId, receivedAt, direction, emlS3Key, lifecycleRound, scanId, scanKind, engine: 'bec', dependencies: [{engine, outcome}], readyAt }`, ids and codes only). Exactly one transaction — the one inserting the last dependency final — writes it; redeliveries and the deadline sweeper never do (`scan_stage_triggers_total{engine="bec"}`). The event-relay publishes it to `email.security` (`org.<id>.mail.message.scan_stage_ready.v1`); `scan.bec` binds only that key. A delivery for another engine is a ledger no-op (`scan_events_skipped_total{reason="other_stage_engine"}`); a delivery whose `scanId` is not the round's row is a no-op too (`reason="stage_round_missing"`, warned) — a stage trigger never opens a round. A rescan re-runs `rspamd`/`url` and triggers `bec` for the new round (new `scan_id`).

**One call (B4)**, bounded by `SCAN_BEC_TIMEOUT_MS`: writer reads with echo checks (the round row, the `rspamd`/`url` finals, the `email_auth_results` row, the round's `url_scan_results` joined with `message_urls`, ≤ 200 stored headers, the parse row and the subject; a mismatch is the retried attempt failure `inconsistent_read`, `scan_bec_inconsistent_reads_total{read}`), the tenant data (active domains, enabled executive/vendor profiles, unexpired trusted senders and suppressions, the url settings' extra protected domains; cached per organization for `BEC_TENANT_DATA_CACHE_TTL_MS`), the stored text and HTML bodies from S3 (`org/<org>/part/` keys; full reads SHA-256-verified; a body above `BEC_TEXT_MAX_BYTES` is read as a prefix without a hash check and the text is `incomplete`), the history rows (opted-in tenants), `bec-map/1`, the AI layer, aggregation. Outbound and internal mail is `skipped` with `bec.not_inbound` (and history pair updates for opted-in tenants). Input states (`bec_scan_results.inputs`): `auth` available | failed (rspamd final timeout/error) | missing (rspamd definite without an auth row) | not_in_round; `url` available (definite or skipped) | failed | not_in_round; `text` complete | incomplete | absent; `history` enabled | disabled | error.

Attempt failures: retried `inconsistent_read`, `extract_timeout` (the text time budget `BEC_TEXT_TIMEOUT_MS`), `timeout`; final `parse_row_missing`, `part_unavailable`, `part_integrity`, `part_key_mismatch`. MySQL / S3 / network errors are thrown (transient, no attempt consumed). AI problems never fail an attempt.

## Reading a verdict

Tenant-scoped through `GET /api/v1/messages/{messageId}/scans` (engine `bec`: rules with evidence, inputs, thresholds, AI assessments without hashes or durations). On the replica:

```sql
-- The engine's final and its codes.
SELECT scan_id, attempt, outcome, error_code, reason_codes, engine_version, settings_version
FROM scan_engine_results WHERE message_id = ? AND received_at = ? AND engine = 'bec' ORDER BY scan_id, attempt;
-- The result: deterministic vs final verdict and score, inputs, fired rules, AI.
SELECT lifecycle_round, deterministic_verdict, deterministic_score, verdict, score, inputs,
       JSON_LENGTH(rules) AS rules, rules_version, lexicon_version, text_version, engine_version
FROM bec_scan_results WHERE message_id = ? AND received_at = ? ORDER BY scan_id;
SELECT JSON_EXTRACT(rules, '$[*].code') AS codes, JSON_EXTRACT(rules, '$[*].suppressed') AS suppressed
FROM bec_scan_results WHERE message_id = ? AND received_at = ? AND scan_id = ?;
SELECT ai, ai_shadow FROM bec_scan_results WHERE message_id = ? AND received_at = ? AND scan_id = ?;
-- The stage trigger of each round (ids only).
SELECT event_id, JSON_EXTRACT(payload, '$.lifecycleRound') AS round, JSON_EXTRACT(payload, '$.dependencies') AS deps,
       created_at, published_at
FROM message_outbox WHERE organization_id = ? AND aggregate_id = ? AND event_type = 'mail.message.scan_stage_ready.v1';
```

`rules` entries are `{ id, code, category, severity, weight, suppressed: null|'trust'|'feedback', evidence: [≤ 5 entries] }` (evidence: header, address/display name/domain of the tenant's own headers, profile public id and match kind, lookalike rule and target, auth outcomes, lexicon ids and span offsets, URL seqs, history bucket, trusted / suppression id). `deterministic_verdict ≠ verdict` only through the AI layer (`bec.ai.flagged` raised to suspicious, `bec.ai.corroborated` to malicious). `ai` holds applied assessments (≤ 2, with `effect`), `ai_shadow` shadow ones (≤ 3): labels, confidence, enumerated indicators, cited features, span offsets, model ids/versions, response hash — never text.

## Series used by the alerts

`scan_bec_results_total{verdict,deterministic_verdict}`, `scan_bec_rules_total{code}` (BEC_REASON_CODES, anything else `other`), `scan_bec_inputs_total{input,state}`, `scan_bec_ai_total{layer,mode,status,effect}` (status adds `gated` when the LLM was not asked), `bec_llm_request_duration_seconds{status}`, `bec_llm_tokens_total{direction}`, `bec_llm_budget_total{result}` (`allowed`, `tenant_exhausted`, `platform_exhausted`, `unavailable`), `bec_llm_breaker_state` (0 closed, 1 half open, 2 open), `bec_model_info{layer,model,version,mode}`, `scan_bec_inconsistent_reads_total{read}`, `bec_history_updates_total{result}`, `bec_history_rows_deleted_total`, `bec_history_sweeper_errors_total`; the generic `scan_stage_triggers_total{engine}`, `scan_engine_results_total{engine="bec"}`, `scan_deadline_finalized_total{engine="bec"}`, `scan_events_skipped_total{engine="bec",reason}`, `scan_engine_info{engine="bec"}`; queue depth `rabbitmq_detailed_queue_messages_ready{queue="scan.bec"}`.

## BecEngineFailuresHigh

More than 5 % of the final bec results of 10 minutes are `timeout` or `error`. Break down by `error_code` (query above, or `scan_engine_failures_total{engine="bec",reason}`): `inconsistent_read` → database connections (scan pipeline runbook, Prisma wrong-read mitigation; `scan_bec_inconsistent_reads_total{read}` names the read); `part_unavailable` / `part_integrity` → the mail bucket (parts gone or altered; rescan after restoring); `extract_timeout` / `timeout` → CPU starvation or very large texts (raise CPU requests, lower `SCAN_BEC_CONCURRENCY`; `BEC_TEXT_MAX_CHARS` bounds the analysis); `parse_row_missing` → the message was never parsed (MIME stage). The rounds end `scan_failed`; rescan after the cause is fixed.

## BecScanQueueBacklog

`scan.bec` has had more than 1 000 ready triggers for 10 minutes. Check that `email-worker-bec` runs and consumes (`amqp_consumer_active{queue="scan.bec"}`), its readiness (`bec-engine`), the engine duration (`scan_engine_duration_seconds{engine="bec"}`) and the LLM (`bec_llm_request_duration_seconds`: a slow LLM holds a consumer slot for up to `BEC_LLM_TIMEOUT_MS`; set `BEC_LLM_MODE=shadow` or `off` platform-wide to shed it). Scale `email-worker-bec` (HPA / KEDA on `scan.bec`). Each queued trigger is a round waiting in `scanning`; the round deadline (`SCAN_ROUND_DEADLINE_SECONDS`) bounds the wait.

## BecStageTriggerStall

The deadline sweeper finalized a bec result as `timeout`/`deadline_exceeded` in the last 15 minutes: the round's trigger was not written, not relayed or not consumed. In order: (1) no `email-worker-bec` consumer on `scan.bec` (topology check, Deployment status); (2) the trigger row exists but `published_at IS NULL` (event-relay down or `scan.bec` missing from `RECONCILE_QUEUES` re-drives) — see the outbox query above; (3) no trigger row although both `rspamd` and `url` finals exist — first rule out a **wrong-order rollout** (a replica of an image older than step 4.4 inserted the last dependency final, see [deployment, rollout order](../deployment/bec-detection.md#rollout-order-upgrading-from-step-43)); the rounds at risk right now:

```sql
SELECT s.id AS scan_id, s.message_id, s.received_at, s.deadline_at
FROM email_scans s
WHERE s.status = 'running'
  AND JSON_CONTAINS(s.required_engines, '"bec"')
  AND (SELECT COUNT(*) FROM scan_engine_results r
       WHERE r.scan_id = s.id AND r.received_at = s.received_at AND r.is_final = 1
         AND r.engine IN ('rspamd', 'url')) = 2
  AND NOT EXISTS (SELECT 1 FROM scan_engine_results r
       WHERE r.scan_id = s.id AND r.received_at = s.received_at AND r.is_final = 1
         AND r.engine = 'bec')
  AND NOT EXISTS (SELECT 1 FROM message_outbox o
       WHERE o.event_type = 'mail.message.scan_stage_ready.v1'
         AND CAST(o.aggregate_id AS UNSIGNED) = s.message_id
         AND CAST(JSON_UNQUOTE(JSON_EXTRACT(o.payload, '$.scanId')) AS UNSIGNED) = s.id)
  AND s.completed_at IS NULL
ORDER BY s.deadline_at
LIMIT 100;
```

(rows older than a few seconds are stuck: they end `scan_failed` at their deadline; rescan them after the rollout). Otherwise it is a bug: capture `message_id`/`scan_id`, the finals (`SELECT engine, outcome, attempt, completed_at FROM scan_engine_results WHERE scan_id = ? AND is_final = 1`) and escalate; (4) `scan_events_skipped_total{engine="bec",reason="stage_round_missing"}` rising — triggers name rows that do not exist (check for restored backups or manual edits). The affected rounds are `scan_failed`; rescan them after the fix.

## BecInputsUnavailableHigh

More than 10 % of the bec results of 30 minutes had one input unavailable (`input` label). `auth`: Rspamd finals failing (`scan_engine_results_total{engine="rspamd",final="true",outcome=~"timeout|error"}`) or Rspamd answering without authentication results (R1 too large) → see [scan-pipeline.md](scan-pipeline.md); `not_in_round` means `rspamd` is not in `SCAN_ENGINES`. `url`: url finals failing → [url-scanning.md](url-scanning.md). `text`: `incomplete` grows with messages above `BEC_TEXT_MAX_BYTES` or MIME limits (`mime_limit_exceeded_total`); raise the cap only with the memory budget in mind. `history`: `error` = history reads failing (MySQL). Those verdicts are at least `unknown`; the share of `unknown` rises, which policy (5.2) must treat as not clean.

## BecLlmErrorsHigh

More than 20 % of LLM assessments end `error`, `timeout` or `invalid_output`. Verdicts are unaffected (P6). Check: provider status page; the API key (`401/403` show as `error`; rotate per [LLM enablement](#llm-enablement)); `bec_llm_breaker_state` (opens after `BEC_LLM_BREAKER_THRESHOLD` consecutive errors/timeouts, refuses calls for `BEC_LLM_BREAKER_RESET_MS` → `circuit_open`); `bec_llm_request_duration_seconds` against `BEC_LLM_TIMEOUT_MS`; `invalid_output` = the model's JSON failed the strict schema (spans outside the excerpt, unknown enums) — if persistent after a model change, set the model back (`BEC_LLM_MODEL`). To stop calls at once: `BEC_LLM_MODE=off` in `email-gateway-config` and roll out `email-worker-bec` and the api (the api uses the mode as the tenant cap).

## BecLlmBudgetExhausted

LLM calls were refused by a budget window (info). `tenant_exhausted`: the tenant's daily window `eg:bec:llm:t:<org>:<yyyymmdd>` (UTC) reached its `ai.llmDailyCallLimit` (≤ `BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY`); `platform_exhausted`: the platform minute window `eg:bec:llm:m:<epochMinute>` reached `BEC_LLM_MAX_CALLS_PER_MINUTE`. Assessments are `budget_exceeded`; verdicts are deterministic. Raise limits only with the cost owner's agreement ([budgets](#budgets)). `bec_llm_budget_total{result="unavailable"}` means Redis did not answer: the LLM is skipped (never called without a passed check).

## BecMaliciousRateSpike

Malicious verdicts per hour are above three times the 1-day average (info). Compare `scan_bec_rules_total` by `code` with the previous day: a campaign shows identity + intent codes from a few senders; a false-positive wave usually shows one rule (e.g. a new executive profile matching a common name — `bec.impersonation.executive_name`, or a new vendor domain producing `bec.lookalike.sender_vendor`). Check recent changes: profiles (audit `bec_executive.*`, `bec_vendor.*`), settings (`scan_settings.updated` with engine `bec`), model rollout (`bec_model_info`), lexicon / engine version (`scan_engine_info{engine="bec"}`). Corrective levers are tenant-side (profiles, trusted senders, suppressions of suppressible codes) or a platform rollback of the image.

## Profiles and trusted senders

Executive profiles (display name, aliases, known addresses) drive X1–X3; vendor profiles (name, aliases, domains, known senders, payment-change sensitivity) drive V1–V4 and L2. Both are tenant data through `/api/v1/bec/executives` and `/api/v1/bec/vendors` (`bec:manage`, audited); the worker sees changes within `BEC_TENANT_DATA_CACHE_TTL_MS`. Keep known addresses complete (an executive mailing from a known, authenticated address fires nothing). Trusted senders (`/api/v1/bec/trusted-senders`, address or registrable domain, never a free-mail domain, optional expiry ≤ 365 days) neutralize identity, history and content rules **only when the message authenticates as From** (T1); without authentication T2 fires and nothing is neutralized. Trust never neutralizes A1–A6, L1–L4, R3, X1–X3, K1–K4 or E-codes.

## False positives and suppressions

Analysts record feedback on a bec result (`POST /api/v1/messages/{messageId}/scans/{scanId}/bec-feedback`, `bec:feedback`); a false positive may suppress **suppressible** codes for the sender address or registrable domain for 1–90 days (`bec_suppression_rules`, ≤ `BEC_SUPPRESSIONS_MAX_PER_TENANT` active rows). At use the total suppressed weight per message is capped at `BEC_SUPPRESSION_MAX_WEIGHT`; suppressed rules appear with `suppressed: 'feedback'` and S1 (`bec.feedback_suppressed`) fires. Non-suppressible codes (A*, L*, R3, X*, V1, V2, V4, C2, C3, C6, C9, K*, E*, T2, AI codes) are refused by the api and ignored by the worker even if a row exists. List / delete suppressions through `/api/v1/bec/suppressions`. False negatives are recorded only (no automatic raising rule).

## History opt-in, purge and key rotation

- **Opt-in** per tenant: scan settings `bec` → `history.enabled: true`, `history.retentionDays` 30..`BEC_HISTORY_MAX_RETENTION_DAYS` (default `BEC_HISTORY_DEFAULT_RETENTION_DAYS`). Disabled: no reads, no writes, H-rules never fire (`inputs.history = 'disabled'`). Rows are written only with the bec final of **round 0** of an initial scan (rescans see the same history and write nothing): sender rows (inbound) and (external, internal) pair rows, keyed by HMAC-SHA256 under `BEC_CONTEXT_HMAC_KEY`; counts and first/last seen only; the sender row keeps ≤ 8 infrastructure fingerprints (16-hex HMACs). No plaintext address, domain, IP or name is stored.
- **Retention:** the sweeper (`email-worker-bec`, lock `scan:bec-history`, every `BEC_HISTORY_SWEEP_INTERVAL_MS`) deletes, per organization, rows with `last_seen_at` older than the tenant's retention, in batches of 1 000 (`bec_history_rows_deleted_total`). Turning history off deletes nothing immediately; the rows age out with the same retention.
- **Purge:** `DELETE /api/v1/bec/history` (`bec:manage`, MFA, audited `bec_history.purged`) deletes the tenant's rows in batches. Organization deletion removes them too ([organization-deletion.md](organization-deletion.md)).
- **Key rotation:** replace `hmac-key` in the Secret `email-gateway-bec-context-key` (≥ 32 random bytes, e.g. `openssl rand -base64 32`, never echoed into a ticket) and roll out `email-worker-bec`. Old rows become unreachable (different hashes): history restarts (first-contact rules fire again for known senders for a while) and the old rows expire by retention; purge them earlier per tenant if required. Rotate after a suspected key exposure; there is no dual-key period.

## LLM enablement

The LLM layer is off by default (`BEC_LLM_MODE=off`, the platform cap). To enable it: complete the checklist of [bec-detection.md (deployment)](../deployment/bec-detection.md#llm-enablement) (data-processing terms, retention, egress), create the Secret `email-gateway-bec-llm` with key `api-key` (operator-supplied Anthropic key; never in Git, never echoed), set `BEC_LLM_MODE=shadow` (or `active`) in `email-gateway-config`, roll out `email-worker-bec` and the api. The worker refuses to start with a mode other than `off` and no key. Tenants then opt in within the cap (`ai.llm` in their `bec` settings; default `off`). Start in **shadow** (stored in `ai_shadow`, never applied) and compare `scan_bec_ai_total{layer="llm",mode="shadow"}` labels against deterministic verdicts before allowing `active`. **Key rotation:** create the new key at the provider, update the Secret, roll out `email-worker-bec`, then revoke the old key. `BEC_LLM_PROVIDER=fake` is a test stand-in and is refused with `NODE_ENV=production`.

## Budgets

Per-tenant daily calls (`ai.llmDailyCallLimit` ≤ `BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY`) and platform calls per minute (`BEC_LLM_MAX_CALLS_PER_MINUTE`) are Redis fixed windows checked atomically before every call (shadow and active calls both count). Gating keeps calls to borderline or intent-bearing messages (score in [`BEC_LLM_MIN_SCORE`, malicious threshold) or an intent rule fired; never for malicious, skipped or empty messages). Cost estimate: calls/day × (input ≈ excerpt ≤ `BEC_LLM_MAX_EXCERPT_CHARS` + features + prompt; output ≤ `BEC_LLM_MAX_OUTPUT_TOKENS`); watch `bec_llm_tokens_total`. To reset a tenant's window early (after raising its limit): `redis-cli -u "$REDIS_URL" UNLINK eg:bec:llm:t:<org>:<yyyymmdd>` — never `FLUSHDB`.

## Data handling

What the engine stores: `bec_scan_results` (codes, weights, scores, span offsets, profile public ids, the tenant's own parsed header identities, model ids/versions, response hashes), `bec_contact_history` (keyed hashes and counts only), the standard `scan_engine_results` row. It never stores body text, span text or excerpts. What leaves the platform (LLM enabled only): a redacted excerpt (≤ 3 windows, ≤ `BEC_LLM_MAX_EXCERPT_CHARS`; addresses, URLs and domain-like tokens, digit runs, phones, profile names and tenant domain labels replaced) plus the feature vector and categorical identity facts. Never sent: addresses, display names, domains, header values, attachments, full bodies, organization or message ids, secrets. Retention: `bec_scan_results` 6 months (partitioned), feedback 24 months, history per tenant setting. Details and the provider's retention terms: [deployment doc](../deployment/bec-detection.md#data-handling-and-retention).

## Model rollout

Local models are code: `packages/bec/models/manifest.json` lists them (id, version, file, SHA-256); `BEC_LOCAL_MODEL` is the active one, `BEC_LOCAL_MODEL_SHADOW` an optional second one run in shadow. The worker refuses to start if either is not in the manifest or its file hash differs (readiness `bec-engine` shows the versions; `bec_model_info`). Rollout of a new model `bec-lr/2`: (1) `pnpm --filter @email-gateway/bec model:check` passes in CI (retraining reproduces the committed weights, manifest hash, held-out precision/recall); (2) deploy with `BEC_LOCAL_MODEL_SHADOW=bec-lr/2` and compare `ai_shadow` against the active model and the deterministic verdicts for at least a week; (3) switch `BEC_LOCAL_MODEL=bec-lr/2` (and clear the shadow); (4) roll back by setting the previous version. The platform cap `BEC_LOCAL_MODEL_MODE` (`shadow` by default) decides whether any tenant's local model is applied. Retraining from feedback exports is an offline procedure (design B11).

## Checking the alert rules

```sh
cd infrastructure/monitoring
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 check rules rules/bec-scanning.rules.yml
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 test rules tests/bec-scanning.rules.test.yml
```
