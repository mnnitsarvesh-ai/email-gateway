# Runbook: AI assistant

Steps AI-1 to AI-6 ([program design](../plan/steps/28-ai-chat-management.md), [AI-6 design](../plan/steps/34-ai-chat-hardening-operations.md), [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md), [ADR-0092](../architecture/adr/0092-llm-provider-abstraction-and-data-handling.md), [ADR-0096](../architecture/adr/0096-assistant-async-report-jobs-session-job-token.md), [ADR-0097](../architecture/adr/0097-assistant-provider-routing-tenant-keys-pseudonymization.md)). The assistant runs in the **api-assistant** Deployment (the api image with the assistant on; [deployment](../deployment/assistant.md)); its tool calls are ordinary requests to the **api** Deployment. Alerts: [`infrastructure/monitoring/rules/assistant.rules.yml`](../../infrastructure/monitoring/rules/assistant.rules.yml).

- Alerts: [AssistantProviderErrorRatioHigh](#assistantprovidererrorratiohigh) · [AssistantAllProvidersUnavailable](#assistantallprovidersunavailable) · [AssistantProviderFallbackActive](#assistantproviderfallbackactive) · [AssistantTurnLatencyHigh](#assistantturnlatencyhigh) · [AssistantBudgetExhaustion](#assistantbudgetexhaustion) · [AssistantConfirmationFailures](#assistantconfirmationfailures) · [AssistantReportJobsFailing](#assistantreportjobsfailing) · [AssistantReportJobsBacklog](#assistantreportjobsbacklog) · [AssistantReportJobsNoConsumer](#assistantreportjobsnoconsumer) · [AssistantJobTokenMisuse](#assistantjobtokenmisuse)
- Procedures: [disable the assistant fast](#disable-the-assistant-fast) · [provider outage](#provider-outage) · [fallback drill](#fallback-drill) · [breaker reset](#breaker-reset) · [tenant key invalid](#tenant-key-invalid) · [tenant-key encryption key rotation](#tenant-key-encryption-key-rotation) · [budget exhaustion](#budget-exhaustion) · [report jobs: backlog, expiry, consumer down](#report-jobs-backlog-expiry-consumer-down) · [job-token misuse response](#job-token-misuse-response)

Never paste a provider key, a tenant key, an access or job token, a conversation's text or a report's HTML into a ticket or chat. Conversations are private to their owner (Q9): administrators and operators look at metadata (the audit view `GET /assistant/admin/conversations…`, `ai_chat_turns`, `ai_chat_tool_executions`, `audit_logs`), never at message text.

## Metrics

All on the api registry (`GET /metrics`, job `api`; api-assistant pods are scraped under the same job). No series carries an organization or user label.

| Series                                                                                           | Meaning                                                                                                    |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `assistant_turns_total{provider,model,outcome}`, `assistant_turn_seconds`                        | Turns (completed, failed, cancelled, refused) and their duration                                           |
| `assistant_llm_requests_total{provider,role,outcome}`, `assistant_llm_seconds{provider,role}`    | Model calls per candidate role (`primary`, `fallback`, `tenant`); outcome `ok` or the failure reason       |
| `assistant_llm_errors_total{provider,reason}`, `assistant_llm_tokens_total{provider,model,kind}` | Failures by reason (`auth`, `connection`, `timeout`, `rate_limited`, `server_error`, …) and tokens by kind |
| `assistant_provider_breaker_open{provider,role}`, `assistant_provider_fallback_active`           | Breaker state of the platform candidates; 1 while turns start on the secondary                             |
| `assistant_provider_switches_total{from,to,reason}`                                              | Candidate switches (`breaker_open`, a failure reason of a same-turn switch, `tenant_key_invalid`)          |
| `assistant_active_turns`                                                                         | Turns running in the pod (limit `ASSISTANT_MAX_CONCURRENT_TURNS`)                                          |
| `assistant_budget_refusals_total{scope}`                                                         | Turns refused at start: `tenant`, `platform`, `user` (per-minute window), `user_tokens`, `concurrency`     |
| `assistant_tool_calls_total{module,access,decision,outcome}`, `assistant_tool_seconds{module}`   | Tool calls through the executor and their loopback latency                                                 |
| `assistant_confirmations_total{risk,outcome}`, `assistant_confirmation_seconds`                  | Write confirmations                                                                                        |
| `assistant_reports_total`, `assistant_report_sources_total`, `assistant_report_emails_total`     | Reports (AI-R)                                                                                             |
| `assistant_report_jobs_total{outcome}`, `assistant_report_job_seconds`                           | Background report jobs (`queued`, `succeeded`, `failed`, `expired`, `cancelled`, `retried`)                |
| `assistant_tenant_key_validations_total{outcome}`                                                | Tenant key probes (`valid`, `rejected`, `unverified`)                                                      |
| `assistant_pseudonyms_total{kind}`                                                               | New pseudonym mappings (`email`, `ip`, `domain`, `name`, `overflow`)                                       |
| `assistant_feedback_total{rating}`, `assistant_search_seconds{outcome}`                          | Ratings and content searches                                                                               |
| `api_assistant_job_token_refusals_total`                                                         | Job tokens refused outside GET on the report source routes                                                 |

Useful rows: `ai_chat_turns` (`status`, `error_code`, `provider`, `model`, `key_source`, `fallback_from`, `data_sharing`, `latency_ms`), `ai_chat_tool_executions` (`decision`, `status`, `http_status`, `error_code`, `correlation_id`), `ai_chat_action_confirmations`, `ai_chat_report_jobs` (`status`, `attempts`, `error_code`, `expires_at`), `ai_chat_provider_keys` (`status`, `last_error_code`, `key_kid`; never the ciphertext in a ticket).

## AssistantProviderErrorRatioHigh

More than 20 % of one candidate's model calls failed over 10 minutes (at least 0.05 calls/s).

1. Break `assistant_llm_requests_total` down by `outcome` for the alert's `provider` and `role`:
   - `auth`: the platform key was rejected (revoked, rotated, billing). Replace `anthropic-api-key` (or `openai-api-key`) in `email-gateway-assistant-llm` and restart api-assistant (`kubectl rollout restart deployment/api-assistant`). For `role="tenant"` see [tenant key invalid](#tenant-key-invalid).
   - `rate_limited`: the provider's quota or rate limit. Check the provider console; lower `ASSISTANT_MAX_CONCURRENT_TURNS` or the tenant budgets temporarily, or enable the fallback.
   - `connection` / `timeout`: egress. Check the provider's status page, then the NetworkPolicy ranges of the [egress component](../deployment/assistant.md#egress) (a provider that added addresses), DNS, and the turn rows (`ai_chat_turns.error_code`) of the period.
   - `server_error`: provider-side; wait, or run the [fallback drill](#fallback-drill) in reverse (make sure the secondary is healthy).
2. The breaker opens after `ASSISTANT_BREAKER_THRESHOLD` failures in `ASSISTANT_BREAKER_RESET_MS`; the router then uses the next healthy candidate (see [provider outage](#provider-outage)).

## AssistantAllProvidersUnavailable

Every configured platform candidate's breaker has been open for 5 minutes: new turns answer `503 assistant_provider_unavailable`. Mail flow and every other api route are unaffected.

1. Follow [provider outage](#provider-outage).
2. The gauge is refreshed at turn start and by `GET /assistant/status` (the portal polls it); after the outage the next turn re-tries the primary (passive half-open) and the alert clears. If it stays on while the provider is healthy again, use [breaker reset](#breaker-reset).

## AssistantProviderFallbackActive

Turns have started on the secondary provider (`ASSISTANT_FALLBACK_PROVIDER`) for 15 minutes because the primary's breaker was open. Answers come from a different model; each provider change starts a new transcript segment from the deterministic recap (conversations continue).

1. Find the primary's failure reason as in [AssistantProviderErrorRatioHigh](#assistantprovidererrorratiohigh).
2. Check the secondary's cost (`assistant_llm_tokens_total{provider=<secondary>}`) and its own error ratio.
3. When the primary is healthy, the next turn after the breaker window uses it again; no action is needed to switch back.

## AssistantTurnLatencyHigh

The p95 turn duration has been above 45 s for 15 minutes.

1. Compare `histogram_quantile(0.95, sum by (le, provider, role) (rate(assistant_llm_seconds_bucket[15m])))` (model calls) with `histogram_quantile(0.95, sum by (le, module) (rate(assistant_tool_seconds_bucket[15m])))` (tool calls).
2. Slow model calls: provider latency or long outputs; consider `ASSISTANT_EFFORT=low`, a lower `ASSISTANT_MAX_OUTPUT_TOKENS`, or the fallback.
3. Slow tool calls: the api pods (CPU, HPA at max?), MySQL replica lag, report queries (`ApiReportTimeouts`). Tool calls are ordinary api requests: the [API runbook](api-rate-limits-and-reports.md) applies.
4. `assistant_active_turns` near `ASSISTANT_MAX_CONCURRENT_TURNS` on every pod: scale api-assistant (HPA max) — CPU-based scaling under-reports waiting turns.

## AssistantBudgetExhaustion

Turns are refused with `429 assistant_budget_exhausted` by a token budget (`scope` label of the alert):

- `tenant` (severity info): one organization used its daily budget (`ai_chat_settings.daily_token_budget`, default `ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT`). See [budget exhaustion](#budget-exhaustion).
- `platform` (warning): the platform daily cap `ASSISTANT_PLATFORM_DAILY_TOKENS` is used up; every tenant on platform keys is refused until 00:00 UTC (tenant-key turns are not counted, A6-7).

The per-user budget (`scope="user_tokens"`) and the per-minute window (`user`) are expected user-level limits and do not alert.

## AssistantConfirmationFailures

More than 10 % of the confirmed write actions failed or ended `outcome_unknown` over 30 minutes.

1. `SELECT tool_name, http_status, error_code, COUNT(*) FROM ai_chat_tool_executions WHERE created_at > NOW() - INTERVAL 30 MINUTE AND status = 'failed' AND access = 'write' GROUP BY 1,2,3;`
2. The same requests fail in the portal when the cause is the api (validation, conflicts, a downstream service). `outcome_unknown` means the confirm request did not finish (a pod killed mid-write: check restarts and `terminationGracePeriodSeconds`); the write is **never** re-sent automatically; the user sees the outcome-unknown card and must check the resource.
3. A spike of `refused_digest`/`refused_token` is not part of this alert; it indicates stale cards or a client bug.

## AssistantReportJobsFailing

More than 3 background report jobs failed or expired in 30 minutes. `SELECT error_code, COUNT(*) FROM ai_chat_report_jobs WHERE finished_at > NOW() - INTERVAL 30 MINUTE AND status = 'failed' GROUP BY 1;`

| `error_code`                           | Cause and action                                                                                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `assistant_report_job_expired`         | Not processed within `ASSISTANT_REPORT_JOB_TTL_SECONDS`: no consumer or a backlog ([report jobs](#report-jobs-backlog-expiry-consumer-down))                |
| `assistant_report_session_ended`       | The user's session was revoked or expired before the job ran (I26). Expected occasionally; the user asks again                                              |
| `assistant_report_not_allowed`         | The user lost `report:read`/`assistant:use`, or the assistant was disabled for the tenant                                                                   |
| `assistant_report_sources_unavailable` | Every report source failed after 5 attempts: check the report routes (`ApiReportTimeouts`) and the replica                                                  |
| `assistant_report_storage_failed`      | S3 `PutObject` failed after 5 attempts: IRSA permissions, the egress S3 ranges, bucket policy, KMS                                                          |
| `assistant_report_purged`              | The conversation's content was purged meanwhile (cancelled jobs; not counted by this alert)                                                                 |
| `assistant_report_job_failed`          | An unexpected error (or an api-assistant crash/OOM) on all 5 attempts: check the api-assistant logs ("attempt failed unexpectedly", `errName`) and restarts |

## AssistantReportJobsBacklog

More than 50 jobs ready in `assistant.reports` for 15 minutes. See [report jobs](#report-jobs-backlog-expiry-consumer-down).

## AssistantReportJobsNoConsumer

Jobs wait in `assistant.reports` and no consumer is attached. See [report jobs](#report-jobs-backlog-expiry-consumer-down).

## AssistantJobTokenMisuse

A request with an assistant job token (claim `ajb`) was refused because it was not a `GET` on a report source route. Job tokens are minted only inside api-assistant for one job and never leave the process except as the `authorization` header of loopback reads; any refusal is a defect or a leak. Follow [job-token misuse response](#job-token-misuse-response) at once.

## Disable the assistant fast

From the narrowest to the widest switch; none of them touches mail flow, and conversations and audit rows stay:

1. **One tenant**: its administrator turns it off in Settings → AI assistant (`PUT /assistant/settings` `enabled: false`), or a platform operator turns the feature off: `PUT /api/v1/organizations/{organizationId}/features/ai_assistant` `{ "enabled": false }`. New turns answer `403 assistant_tenant_disabled` or `403 assistant_not_enabled` immediately.
2. **Every tenant**: set `ASSISTANT_ENABLED=false` on api-assistant (`kubectl set env deployment/api-assistant ASSISTANT_ENABLED=false`; a rolling restart). Turns answer `503 assistant_disabled`; history, usage, admin and audit views keep working (they do not check the platform switch).
3. **Stop all assistant traffic**: scale api-assistant to 0 and remove `API_ASSISTANT_INTERNAL_URL` from the portal (its BFF then reaches the api, which has the assistant off). Queued report jobs expire.
4. Single native tools: `ASSISTANT_REPORTS_ENABLED=false` / `ASSISTANT_REPORT_EMAIL_ENABLED=false`; long reports synchronous only: `ASSISTANT_REPORT_JOBS_ENABLED=false`.

## Provider outage

1. Confirm with the provider's status page and `assistant_llm_requests_total{outcome!="ok"}`.
2. Without a fallback, the assistant is unavailable while the breaker is open (`503 assistant_provider_unavailable` at turn start; the portal shows the status). Communicate it; nothing else degrades.
3. With a fallback configured (`ASSISTANT_FALLBACK_PROVIDER`/`_MODEL` and its key and egress ranges), turns start on the secondary as soon as the primary's breaker opens, and a first model call that fails before any output is retried once on the secondary in the same turn.
4. To add a fallback during an outage: set the two keys and the provider's key in the overlay, add its ranges to the egress component, roll out api-assistant. The fake provider is refused in production.
5. Tenant keys (`role="tenant"`) have their own breaker per organization (`as:brk:t:<organizationPublicId>`); a tenant's broken key never opens the platform breaker. Tenants that allowed it (`tenantKeyFallbackToPlatform`) continue on the platform.

## Fallback drill

Run in staging before relying on the fallback (never in production without a change window):

1. Configure the secondary (provider, model, key, egress) and roll out.
2. Open the primary's breaker without breaking the provider: set the Redis key `as:brk:<primary-provider>` to a value ≥ `ASSISTANT_BREAKER_THRESHOLD` with a TTL of a few minutes (`SET as:brk:anthropic 5 EX 300`).
3. Start a turn: `GET /assistant/status` shows `fallbackActive: true`; the turn row has `provider`/`model` of the secondary and `fallback_from` = the primary; `assistant_provider_switches_total{reason="breaker_open"}` increments; the conversation continues in a new segment.
4. Delete the key ([breaker reset](#breaker-reset)); the next turn is on the primary again.

## Breaker reset

The breaker is a Redis counter with the TTL `ASSISTANT_BREAKER_RESET_MS`; it re-closes by itself when the window expires. To close it at once (after fixing the cause): `DEL as:brk:<provider>` (primary), `DEL as:brk:<provider>:fb` (secondary) or `DEL as:brk:t:<organizationPublicId>` (one tenant key). The next turn start refreshes `assistant_provider_breaker_open`.

## Tenant key invalid

A tenant-supplied provider key (D7, write-only, I27) answered `401/403`: the router marks it `invalid` (`ai_chat_provider_keys.status`, `last_error_code` `provider_auth`), audits `assistant.provider_key_invalidated`, and continues on the platform only when the tenant enabled `tenantKeyFallbackToPlatform`; otherwise turns answer `503 assistant_tenant_key_invalid`.

1. The tenant administrator sees the status on the AI administration page and either stores a new key (`PUT /assistant/settings/provider-key`, MFA, probe first), re-validates (`POST …/provider-key/validate`), or removes it (`DELETE`, also sets `useTenantKey=false`).
2. Operators never handle the key itself. `last_error_code` values: `provider_auth`, `provider_connection`, `provider_timeout`, `provider_server_error`, `tenant_key_undecryptable` (see rotation below).
3. To stop all tenant keys platform-wide: `ASSISTANT_TENANT_KEYS_ENABLED=false` (turns fall back to platform keys; settings answer `403 assistant_tenant_keys_disabled`).

## Tenant-key encryption key rotation

`ASSISTANT_TENANT_KEY_ENCRYPTION_KEY` (Secret `email-gateway-assistant-tenant-key`, key `key`) encrypts tenant keys (AES-256-GCM, AAD bound to the organization and key version; `key_kid` = `k` + 7 hex of the key's SHA-256). `_PREVIOUS` decrypts only.

1. Generate a new key (`openssl rand -hex 32`). In the Secret, move the current value to `previous-key` and put the new one in `key`; restart api-assistant. New and re-entered tenant keys are encrypted with the new key; existing rows still decrypt with the previous key.
2. Track the rows still on the old key: `SELECT COUNT(*) FROM ai_chat_provider_keys WHERE key_kid = '<old kid>';` (the kid of the old key: `k` + the first 7 hex of `sha256(<old key hex>)`). There is **no bulk re-encryption job**: rows move to the new key when the tenant stores the key again. Ask the affected tenant administrators to re-enter their key (or remove it).
3. Remove `previous-key` only when no row uses the old kid; a row left on it becomes `tenant_key_undecryptable` (treated as invalid; the tenant must store the key again).
4. A suspected leak of the encryption key: rotate as above **and** ask every tenant with a stored key to rotate the provider key at their provider, since the ciphertexts could have been read with the old key.

## Budget exhaustion

- Tenant: the organization's administrator raises `dailyTokenBudget` (up to `ASSISTANT_TENANT_DAILY_TOKENS_MAX`) or waits for 00:00 UTC. Per-user budgets (`userDailyTokenBudget`) are a tenant decision. Usage per user and day: AI administration page (`GET /assistant/admin/usage/users`).
- Platform: raise `ASSISTANT_PLATFORM_DAILY_TOKENS` (0 = no cap) on api-assistant, after checking the spend (`assistant_llm_tokens_total`, `ai_chat_usage_daily`).
- Counters are Redis keys `as:tok:o:<organizationId>:<yyyymmdd>`, `as:tok:u:<userPublicId>:<yyyymmdd>`, `as:tok:p:<yyyymmdd>` (TTL 48 h), re-seeded from `ai_chat_usage_daily` / `ai_chat_usage_user_daily` when missing. Never edit them to "give" tokens: change the budget instead (a deleted counter is re-seeded from the rows).

## Report jobs: backlog, expiry, consumer down

Reports with a window longer than `ASSISTANT_REPORT_SYNC_MAX_HOURS` (168 h) are jobs (D5): the turn writes `ai_chat_reports` (`queued`), `ai_chat_report_jobs` and the outbox row `assistant.report.generate_requested.v1`; the event-relay publishes it to `assistant.reports`; the api-assistant consumer (`eg-assistant`, prefetch `ASSISTANT_REPORT_JOB_CONCURRENCY`) composes the report with a 5-minute GET-only job token of the user's session. Jobs expire after `ASSISTANT_REPORT_JOB_TTL_SECONDS` (30 min; the retention job fails them with `assistant_report_job_expired`).

1. **Consumer down** (`rabbitmq_detailed_queue_consumers{queue="assistant.reports"} == 0`): check that api-assistant pods run with `ASSISTANT_REPORT_JOBS_CONSUMER=true`, the `rabbitmq-assistant-url` secret key, the `eg-assistant` user and its permissions (`init.mjs`), and the pods' logs (`assistant-report-jobs` component). The api Deployment never consumes.
2. **Backlog**: compare the publish rate with `assistant_report_jobs_total{outcome="succeeded"}`; raise `ASSISTANT_REPORT_JOB_CONCURRENCY` (≤ 8) or scale api-assistant; check the report source latency (`assistant_report_sources_total`, `ApiReportTimeouts`) and the api pods.
3. **Rows not published**: `outbox_*` alerts (event-relay). An event-relay older than topology v16 does not know the event type and marks the rows poison (`OutboxPoisonRows`): roll out the current event-relay; then [replay or delete](rabbitmq-messaging.md#outboxpoisonrows) them. Expired jobs are not revived; users ask again.
4. **Dead letters** of `assistant.reports` (after 5 attempts or 30 min): inspect with the dead-letter routes; a replay after the job's expiry is acknowledged as a duplicate (the job is terminal).
5. **Emergency**: `ASSISTANT_REPORT_JOBS_ENABLED=false` makes every report synchronous again (long windows then risk the tool timeout).

## Job-token misuse response

1. Read the api's warn log of the refusal: route template and job id (`jobId`) only — the token is never logged.
2. `SELECT status, user_id, organization_id, session_id, created_at, finished_at FROM ai_chat_report_jobs WHERE public_id = '<jobId>';` A job token is valid 5 minutes and only while the user's session is live.
3. If the refusal came from an api-assistant pod's own composition (a new report source route not in `ASSISTANT_JOB_ROUTES`), it is a defect: disable report jobs (`ASSISTANT_REPORT_JOBS_ENABLED=false`) and file a bug; nothing was exposed (the request was refused).
4. If the request came from anywhere else (client IP, user agent, request id in the api access log), treat it as a token leak: revoke the user's sessions (Users → sessions in the portal, or `DELETE /api/v1/users/{id}/sessions`), which ends every job token of that session family; check `audit_logs` for the user and the job's organization in the last 5 minutes; escalate to security. If more than one job token leaked, rotate `AUTH_JWT_SECRET` (invalidates every access token platform-wide; plan it).
5. Close with the root cause; the alert resets 5 minutes after the last refusal.
