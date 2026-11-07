# Runbook: security scan pipeline (Rspamd, rounds, breaker, deadlines, training)

Step 4.1 ([design](../plan/steps/09-rspamd.md), [ADR-0026](../architecture/adr/0026-security-scan-pipeline.md), [ADR-0027](../architecture/adr/0027-rspamd-milter-policy.md), Rspamd deployment: [rspamd.md](../deployment/rspamd.md)). The scan stage is the **scan role** of the email-worker (`SCAN_ENABLED`; production Deployment `email-worker-scan`). Every alert of `infrastructure/monitoring/rules/scanning.rules.yml` links a section of this page.

**Attachment engine (step 4.2):** ClamAV, YARA, the inspector, the content cache, signature updates and rescan jobs have their own runbook, [attachment-scanning.md](attachment-scanning.md) (alerts of `attachment-scanning.rules.yml`). The generic alerts below apply to it with `engine="attachment"`; since step 4.2 both `rspamd` and `attachment` are required in every round. **URL engine (step 4.3):** extraction, reputation providers, the SSRF-guarded fetcher, rewriting and dynamic inspection have their own runbooks — [url-scanning.md](url-scanning.md) (alerts of `url-scanning.rules.yml`), the time-of-click [click-service.md](click-service.md) and the isolated [url-browser-worker.md](url-browser-worker.md); since step 4.3 `rspamd`, `attachment` and `url` are required in every round. **Phishing/BEC engine (step 4.4):** the stage-2 `bec` engine on `scan.bec` (triggered by `mail.message.scan_stage_ready.v1` once rspamd and url finalized), profiles, trusted senders, feedback and suppressions, the opt-in communication history and the optional AI/LLM layer have their own runbook, [bec-detection.md](bec-detection.md) (alerts of `bec-scanning.rules.yml`, incl. `BecStageTriggerStall`); since step 4.4 `rspamd`, `attachment`, `url` and `bec` are required in every round, and a round whose rspamd or url final exists but whose bec final is missing waits for the stage trigger (outbox → relay → `scan.bec`, re-driven by the reconciler) or ends `scan_failed` at its deadline — never `scanned`. **DLP engine (step 4.5):** detection, attachment text extraction in the isolated extractor children, tenant policies and exceptions, evidence access and purge, Aadhaar enablement and the dev pass-through holds have their own runbook, [dlp.md](dlp.md) (alerts of `dlp-scanning.rules.yml`); since step 4.5 five engines are required in every round (`rspamd`, `attachment`, `url`, `bec`, `dlp`), and `dlp` never makes a round `malicious` (its action holds mail, not its verdict).

**Rules that hold in every procedure below:**

- **Never clean by accident.** A timeout, error, open breaker, missing EML, unparseable reply or deadline is never `clean`. A round whose required engine failed ends `scan_failed` and waits for policy (the 5.2 fail-safe). Do not "fix" a failed round by editing rows: rescan it.
- **One door.** The scan stage changes the lifecycle only through the transition service (E3 `persisted → scanning`, E6 `scanning → scanned`, E7 `scanning → scan_failed`). Never `UPDATE email_messages SET status …` or edit `email_scans` / `scan_engine_results` by hand.
- **No content.** Results hold scores, symbol names and bounded symbol options (which can contain addresses and URLs: they stay in `scan_engine_results.evidence`, tenant-scoped). Logs, events and metrics carry ids, codes, counts and versions only. Do not paste evidence options, subjects or addresses into tickets.
- **Engines classify, policy decides.** The scan stage never rejects, quarantines or delivers.
- Read on the **replica** for investigations (or the read API); the writer is for the services.

## Contents

- [How a scan runs](#how-a-scan-runs) · [Reading results](#reading-results) · [Series used by the alerts](#series-used-by-the-alerts)
- Alerts: [ScanEngineCircuitOpen](#scanenginecircuitopen) · [ScanEngineFailureRateHigh](#scanenginefailureratehigh) · [ScanRoundsFailing](#scanroundsfailing) · [ScanQueueBacklog](#scanqueuebacklog) · [ScanLatencyHigh](#scanlatencyhigh) · [ScanDeadlineFinalizations](#scandeadlinefinalizations) · [ScanEngineVersionChanged](#scanengineversionchanged)
- Procedures: [Rspamd down or slow](#rspamd-down-or-slow) · [breaker states](#breaker-states) · [stuck scanning messages](#stuck-scanning-messages) · [rescan after an outage](#rescan-after-an-outage) · [Bayes and fuzzy training](#bayes-and-fuzzy-training) · [threshold changes](#threshold-changes) · [checking the alert rules](#checking-the-alert-rules)

## How a scan runs

1. The MIME stage commits `mail.message.parsed.v1`; the event-relay publishes it to `email.ingestion`, bound to `scan.spam` (one work queue per engine; Rspamd is the only engine in 4.1). An administrative rescan (`POST /api/v1/messages/{id}/rescan`, E19, new round) publishes `mail.message.rescan_requested.v1` to `email.security`, bound to the same queue.
2. The engine consumer (`email-worker.scan.rspamd`, prefetch `SCAN_RSPAMD_CONCURRENCY`) loads the writer row of the envelope's organization, opens the **round** (`email_scans` row per `(message, lifecycle_round)`; E3 for round 0), streams the EML from S3 to Rspamd `/checkv2` with the trusted envelope (client IP, HELO, client host name, envelope sender, recipients, queue id), and maps the reply to a verdict (rules R0–R10).
3. A transport failure (timeout, connection refused, HTTP error, protocol error, soft reject, open breaker) is recorded as a **non-final attempt** row and retried with hold backoff (`SCAN_RETRY_BASE_MS` → `SCAN_RETRY_MAX_MS`), up to `SCAN_RSPAMD_MAX_ATTEMPTS` (default 6) or the round deadline. The last failure, or a definite result, is the **final** row (one per engine and round). An S3 or MySQL outage is transient: no row, retried without consuming an attempt.
4. When every required engine has a final row the round completes in the same transaction: `email_scans.status/scan_verdict/reason_codes`, E6 or E7, and a `mail.message.scanned.v1` outbox row (bound to `email.policy.evaluate`, dormant until 5.2).
5. The **deadline sweeper** (one leader per cluster, MySQL lock `scan:deadline`) finalizes rounds still `running` after `deadline_at` (`SCAN_ROUND_DEADLINE_SECONDS`, default 30 min) with `timeout` / `deadline_exceeded` rows → `scan_failed`.

With the defaults a message survives an Rspamd outage of about one minute when Rspamd is down (6 attempts, hold delays of 2, 4, 8, 16 and 32 s; the stack `scan-resilience` suite measured the final `error` 56 s after the first attempt), and somewhat longer (up to about 2.5 minutes) when calls hang until `SCAN_RSPAMD_TIMEOUT_MS` before the breaker opens; longer outages end `scan_failed` and need a [rescan](#rescan-after-an-outage).

## Reading results

Through the api (tenant-scoped, replica): `GET /api/v1/messages/{messageId}/scans` lists the rounds newest first, with the aggregate verdict and reason codes, the authentication results and, per engine, the final result (score, action, reason codes, symbols with options, version, `settingsVersion`) and its attempts.

In SQL (replica; always with `received_at` for partition pruning):

```sql
-- Rounds of one message
SELECT id, lifecycle_round, scan_kind, status, scan_verdict, reason_codes, required_engines,
       started_at, deadline_at, completed_at
FROM email_scans WHERE message_id = ? AND received_at = ? ORDER BY lifecycle_round;

-- Engine attempts and finals of one round
SELECT engine, attempt, is_final, outcome, error_code, score, required_score, action,
       reason_codes, engine_version, settings_version, duration_ms
FROM scan_engine_results WHERE scan_id = ? AND received_at = ? ORDER BY engine, attempt;

-- SPF / DKIM / DMARC / ARC of the round
SELECT spf, spf_domain, dkim, dkim_signatures, dmarc, dmarc_policy, dmarc_domain, arc
FROM email_auth_results WHERE scan_id = ? AND received_at = ?;
```

| Field                   | Meaning                                                                                                                                                                                                                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan_verdict`          | `clean`, `spam`, `suspicious`, `malicious`, `unknown` (a skipped scan, a pre-filter reply that raised no verdict, a message above `SCAN_RSPAMD_MAX_BYTES`), `timeout`, `error` (a required engine failed)                                                                                     |
| `reason_codes`          | e.g. `spam.score`, `spam.gtube`, `phishing.known_bad_url`, `phishing.link_mismatch`, `auth.dmarc_reject`, `auth.spf_fail`, `reputation.ip_listed`, `header.anomaly`, `bayes.spam`, `fuzzy.spam`, `engine.timeout`, `engine.circuit_open`, `engine.deadline_exceeded`, `clean.below_threshold` |
| `error_code` (failures) | `timeout`, `unavailable`, `http_error`, `protocol_error`, `soft_reject`, `circuit_open`, `invalid_request`, `eml_unavailable`, `eml_key_mismatch`, `max_attempts_exceeded`, `deadline_exceeded`                                                                                               |
| `evidence.signals`      | Rspamd symbols (≤ 200, sorted by \|score\|) with ≤ 5 options of ≤ 200 characters: why the verdict is what it is                                                                                                                                                                               |
| `settings_version`      | `rspamd-map/2;p=<hash of the platform thresholds>;t=<tenant settings version or none>`: which thresholds produced the verdict (`rspamd-map/1` on results recorded before review round 2 of step 4.1, with the old ARC rule)                                                                   |
| `engine_version`        | The Rspamd version that answered (from its `Server` header)                                                                                                                                                                                                                                   |

Logs of the scan stage (component `scan-round`, `scan-deadline-sweeper`, `scan-settings`) carry `eventId`, `messageId`, `organizationId`, `round`, `attempt`, `outcome`, `errorCode` and reason codes.

## Series used by the alerts

`scan_engine_results_total{engine,outcome,final}`, `scan_engine_duration_seconds{engine,outcome}`, `scan_engine_failures_total{engine,reason}`, `scan_engine_circuit_state{engine}` (0 closed, 1 half-open, 2 open), `scan_engine_circuit_transitions_total{engine,to}`, `scan_rounds_completed_total{outcome,verdict,scan_kind}`, `scan_round_duration_seconds{outcome}`, `scan_event_lag_seconds{engine}`, `scan_events_skipped_total{engine,reason}`, `scan_rounds_superseded_total{engine}`, `scan_deadline_finalized_total{engine}`, `scan_settings_cache_total{result}`, `scan_settings_invalid_total{engine}`, `scan_engine_info{engine,version}`, `scan_deadline_sweeper_errors_total` (job `email-worker`), `rabbitmq_detailed_queue_messages_ready{queue="scan.spam"}` (job `rabbitmq-detailed`) and Rspamd's own `rspamd_*` series (job `rspamd`, the controller's `/metrics` with its read password).

## ScanEngineCircuitOpen

**Critical.** A worker's breaker for the engine has been open (state 2) for 2 minutes: it opened after `SCAN_BREAKER_FAILURE_THRESHOLD` consecutive transport failures or a failure ratio ≥ `SCAN_BREAKER_FAILURE_RATIO` over `SCAN_BREAKER_WINDOW` calls. While open, every scan attempt fails fast as `circuit_open` (retried with backoff, never clean).

1. Check Rspamd: [Rspamd down or slow](#rspamd-down-or-slow).
2. `scan_engine_failures_total{reason}` tells which failure tripped it (`timeout` → slow, `error` → unreachable or HTTP errors, `protocol_error` → reply changed, e.g. after an upgrade).
3. The breaker probes again after `SCAN_BREAKER_OPEN_MS` (15 s) by itself; it closes on the first successful probe. No restart is needed. See [breaker states](#breaker-states).
4. Messages whose attempts ran out meanwhile are `scan_failed`: [rescan after an outage](#rescan-after-an-outage).

## ScanEngineFailureRateHigh

More than 5 % of the engine's **final** results over 10 minutes are `timeout` or `error` (attempts that later succeeded are not counted). Each such round ended `scan_failed`.

1. Split by cause: `sum by (reason) (increase(scan_engine_failures_total{engine="rspamd"}[15m]))`.
2. `eml_unavailable`: the stored EML is missing (S3 lifecycle rule, a deleted object, a wrong bucket). Check `S3_BUCKET_MAIL` and the bucket's lifecycle; it is not an Rspamd problem.
3. `timeout` / `error` / `circuit_open`: [Rspamd down or slow](#rspamd-down-or-slow).
4. `protocol_error`: the reply no longer matches `rspamdCheckReplySchema` (an Rspamd upgrade, a proxy in between returning HTML). Compare the version (`scan_engine_info`) and the logs (`errName`, issue paths only).
5. `invalid_request`: an envelope value the client refuses (e.g. an envelope sender that is not a mailbox): find the message ids in the logs (warn "scan engine result recorded" with `errorCode`).
6. After the cause is fixed, [rescan](#rescan-after-an-outage).

## ScanRoundsFailing

More than 1 % of the completed rounds over 15 minutes ended `scan_failed`. Same causes as [ScanEngineFailureRateHigh](#scanenginefailureratehigh) plus deadline finalizations ([ScanDeadlineFinalizations](#scandeadlinefinalizations)) and `eml_key_mismatch` (an EML key outside the message's organization prefix: a data bug, never retried; open an incident). Distribution: `sum by (verdict) (increase(scan_rounds_completed_total{outcome="scan_failed"}[1h]))`.

## ScanQueueBacklog

`scan.spam` has had more than 1000 ready messages, or the p95 age of triggers at handling start (`scan_event_lag_seconds`) has been above 120 s, for 10 minutes.

1. Consumers: `rabbitmq_detailed_queue_consumers{queue="scan.spam"}` must equal the number of scan replicas. Zero → the scan role is not running (Deployment `email-worker-scan` scaled to 0, `SCAN_ENABLED=false`, readiness `rabbitmq-scanner` failing: check the `eg-scanner` user and `RABBITMQ_SCANNER_URL`).
2. Throughput: `sum(rate(scan_engine_results_total{final="true"}[5m]))` versus the inflow (`rate(rabbitmq_detailed_queue_messages_published_total{queue="scan.spam"}[5m])` if scraped, or `mime_parse_messages_total`).
3. Slow engine → [ScanLatencyHigh](#scanlatencyhigh). Many held retries keep prefetch slots during an Rspamd outage (by design: backpressure); the backlog drains once Rspamd is back.
4. Scale `email-worker-scan` (each replica handles `SCAN_RSPAMD_CONCURRENCY` deliveries at a time) and the Rspamd normal workers (`RSPAMD_NORMAL_WORKERS`, more Rspamd pods) together: more workers than Rspamd capacity only moves the queue into Rspamd.

## ScanLatencyHigh

The p95 engine call duration has been above 10 s for 15 minutes (the per-call timeout is `SCAN_RSPAMD_TIMEOUT_MS` = 20 s; Rspamd's own `task_timeout` is 15 s).

1. Rspamd side (`rspamd_*` series, controller `/stat`): CPU saturation (scale `RSPAMD_NORMAL_WORKERS` / pods), slow DNS (`RSPAMD_DNS_SERVERS` must be a local caching recursive resolver; DNSBL lookups dominate), slow Redis (Bayes, fuzzy, reputation in `RSPAMD_REDIS_DB`).
2. Large messages: `scan_engine_duration_seconds` by outcome; messages above `SCAN_RSPAMD_MAX_BYTES` are not sent at all (`engine.too_large`).
3. S3 latency counts too (the EML is streamed while Rspamd reads it): check MinIO/S3 latency.

## ScanDeadlineFinalizations

The deadline sweeper finalized required engines as `timeout` (`deadline_exceeded`) in the last 15 minutes: a round stayed `running` past `SCAN_ROUND_DEADLINE_SECONDS`.

1. Is the engine's queue consumed at all ([ScanQueueBacklog](#scanqueuebacklog) step 1)? An engine enabled in `SCAN_ENGINES` but not deployed fails every round at its deadline (fail-safe).
2. Was a worker stuck (deliveries unacknowledged for a long time: `amqp_consumer_in_flight{queue="scan.spam"}` flat at prefetch, no results)? Restart it; its deliveries return to the queue.
3. Dead-lettered triggers (`email.dead-letter` with `x-eg-source-queue: scan.spam`) never complete their round: inspect and replay them (`POST /api/v1/platform/dead-letters/replay`), or rescan the messages.
4. The finalized messages are `scan_failed`: [rescan](#rescan-after-an-outage) them after the cause is fixed.

## ScanEngineVersionChanged

**Info.** More than one version of an engine reported results within 30 minutes: an upgrade or a mixed fleet. Expected during a rollout. Afterwards compare the verdict distribution (`scan_rounds_completed_total` by verdict) and `protocol_error` failures before and after; the corpus suite (`pnpm --filter @email-gateway/email-worker test:integration`) and `packages/rspamd` integration recalibrate symbol names (docs/deployment/rspamd.md).

## Rspamd down or slow

- Health: `docker compose ps rspamd` (locally) / the Rspamd pods; `curl -s http://<rspamd>:11333/ping` → `pong`.
- Controller (read password, never echo it): `GET /stat` shows the version, scanned and learned counts.
- What the stage does meanwhile: attempts fail (`unavailable`, `timeout`), the breaker opens and attempts fail fast, deliveries are held with backoff (no spinning), and after `SCAN_RSPAMD_MAX_ATTEMPTS` the round ends `scan_failed` (never clean). SMTP keeps accepting mail (the milter fails open, ADR-0027); accepted-but-unscanned mail is always scanned post-queue.
- Restart Rspamd if it is wedged; Hyperscan caches in its volume make restarts fast after the first start.

## Breaker states

`scan_engine_circuit_state{engine}` per worker: **0 closed** (calls pass; failures counted), **2 open** (calls refused for `SCAN_BREAKER_OPEN_MS`, each attempt recorded as `circuit_open`), **1 half-open** (one probe call at a time, `SCAN_BREAKER_HALF_OPEN_PROBES`; success closes, failure re-opens). Breakers are per worker and in memory: replicas open and close independently and a restart starts closed. Only transport failures count (definite results, `unknown` included, are successes; a missing EML or an S3 outage counts neither way). Transitions: `scan_engine_circuit_transitions_total{to}` and the warn log "scan engine circuit opened".

## Stuck scanning messages

A message in `scanning` longer than the round deadline should not exist: the sweeper finalizes it. If `LifecycleStuckMessages{state="scanning"}` fires:

1. Is the sweeper running? Every scan replica runs it, one holds the lock (`SELECT IS_USED_LOCK('scan:deadline')` on the writer returns the holder's connection id); `scan_deadline_sweeper_errors_total` counts its database errors (the pass stops and backs off, 1 s doubling to 60 s) and the rounds whose finalization failed non-transiently (logged by round id, passed over in that pass and retried on the next, so one such round never blocks the other overdue rounds; it stays `running` until the cause is fixed or the lifecycle deadline expires the message).
2. Rounds past their deadline: `SELECT id, message_id, received_at, deadline_at FROM email_scans WHERE status = 'running' AND deadline_at < NOW(3) - INTERVAL 5 MINUTE ORDER BY deadline_at LIMIT 50` (index `(status, deadline_at)`). Rounds whose `deadline_at` is older than `SCAN_SWEEP_LOOKBACK_HOURS` (48 h; the bound is the round's deadline, so rescans of old messages are inside it) are outside the sweeper's window: the lifecycle expiry (`LIFECYCLE_DEADLINE_SCANNING_HOURS`, 24 h) expires those messages; rescan them if needed.
3. A message in `scanning` without any `email_scans` row of its round: its trigger never reached the engine (lost or dead-lettered event). The event-relay reconciler re-drives lost `parsed.v1` copies (`RECONCILE_QUEUES` includes `scan.spam`); otherwise rescan.

## Rescan after an outage

Messages that ended `scan_failed` (or `expired`) during an outage are rescanned by operators through the api (step 4.1 does no automatic rescan): `POST /api/v1/messages/{messageId}/rescan` per message (E19: new round; the old round's rows are kept unchanged). Find them on the replica within the outage window:

```sql
SELECT m.public_id, m.organization_id, s.lifecycle_round, s.scan_verdict, s.completed_at
FROM email_scans s JOIN email_messages m ON m.id = s.message_id AND m.received_at = s.received_at
WHERE s.received_at >= ? AND s.status IN ('failed', 'timed_out')
  AND s.completed_at BETWEEN ? AND ? AND m.status = 'scan_failed'
ORDER BY s.completed_at;
```

Rescan in batches of a few hundred and watch [ScanQueueBacklog](#scanqueuebacklog). A rescan of a message that moved on (e.g. already evaluated by policy) is refused by the lifecycle where E19 does not apply.

## Bayes and fuzzy training

Shared by all tenants, so only **platform administrators** train (`platform:scan_training`, MFA, audited): `POST /api/v1/platform/organizations/{organizationId}/messages/{messageId}/scan-training` with `{ operation: learn_spam | learn_ham | fuzzy_add | fuzzy_delete, fuzzyFlag?: spam | phishing, reason }`. Bayes is explicit-learning only (`autolearn = false`) and classifies after `RSPAMD_BAYES_MIN_LEARNS` messages per class; fuzzy hashes (flag 11 → `EG_FUZZY_SPAM` → `spam`, flag 12 → `EG_FUZZY_PHISH` → `malicious`) apply to later scans within seconds (storage sync 5 s) and expire after 90 days. Training does not rescan: rescan the message afterwards to see the effect. Learning mistakes are undone by learning the other class (`learn_ham` after a wrong `learn_spam`) or `fuzzy_delete`.

## Threshold changes

- **Platform** (`SCAN_RSPAMD_SPAM_SCORE`, `_SUSPICIOUS_SCORE`, `_SCORE_MIN`, `_SCORE_MAX`, `_PHISHING_VERDICT`, `_DMARC_REJECT_VERDICT`, `_AUTH_FAILURE_VERDICT`): set the same values on the api and every scan worker (ConfigMap `email-gateway-config`) and roll both; the worker refuses inconsistent values at start. Results record the platform hash in `settings_version`.
- **Tenant** (`PUT /api/v1/scan-settings/rspamd`, permission `scan:settings_manage`, version compare-and-set, audited): scores within the platform bounds, severities only raised. Workers apply a change within `SCAN_SETTINGS_CACHE_TTL_MS` (30 s). A row that became invalid after the platform bounds were tightened is ignored at use (platform settings applied, `scan_settings_invalid_total{engine}`, one warn log per row version): fix or reset it (`DELETE /api/v1/scan-settings/rspamd?expectedVersion=n`).
- Threshold changes apply to new scans only; rescan messages to re-evaluate them.

## Checking the alert rules

The rules and their promtool unit tests run in a one-off container of the Prometheus image pinned in `docker-compose.yml` (no observability profile needed):

```bash
cd infrastructure/monitoring
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 check rules rules/scanning.rules.yml
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 test rules tests/scanning.rules.test.yml
```

`scan_engine_duration_seconds` observes engine calls only: an attempt that made no call (open breaker, missing EML, refused request, exhausted budget) is counted in `scan_engine_results_total` and `scan_engine_failures_total` but is not a latency observation, so an outage does not pull the `ScanLatencyHigh` quantile toward zero.
