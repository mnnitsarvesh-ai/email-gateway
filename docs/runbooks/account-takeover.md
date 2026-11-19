# Runbook: account takeover (ATO) detection

Step 8.4 ([design](../plan/steps/24-account-takeover-core.md), ADR-0070..0075). Deployment and configuration: [deployment/account-takeover.md](../deployment/account-takeover.md). SMTP restrictions and the enforcement kill switch: [smtp-ato-enforcement.md](smtp-ato-enforcement.md). Alerts: `infrastructure/monitoring/rules/ato.rules.yml`.

**Ground rules.** ATO never blocks mail: `ato.mail` is lossy, the smtp-adapter reads restrictions from its own cache, the policy-engine reads ATO facts from MySQL. A stopped worker means stale scores and delayed detection, not delayed mail. Never enable `ato_detection` for an organization, or act on its accounts, to test something: use synthetic organizations (`it-ato-*`). Logs carry ids, codes and counts only (no IPs above debug, no addresses).

Useful reads (writer or replica; read-only):

```sql
-- Queues and ledgers
SELECT consumer, COUNT(*) FROM message_idempotency WHERE consumer LIKE 'ato-worker.%' AND processed_at > NOW() - INTERVAL 1 HOUR GROUP BY consumer;
-- Catch-up cursors of ATO-enabled organizations
SELECT name, position_id, last_event_at FROM stream_cursors WHERE name LIKE 'ato-mail-catchup:%';
-- Capabilities written by the maintenance role (every 5 minutes)
SELECT value, updated_at FROM system_settings WHERE `key` = 'ato.worker.capabilities';
```

Broker: `docker compose exec rabbitmq rabbitmqctl list_queues -p email-gateway name messages messages_ready messages_unacknowledged consumers | grep ato` (cluster: the management UI of the environment).

## AtoWorkerDown

A replica cannot be scraped for 5 minutes. Check the pod/container (`docker compose logs ato-worker`, `kubectl -n email-gateway logs deploy/ato-detect`), `/health/ready` (mysql, redis, rabbitmq). Common causes: Redis down (the detect role holds events and retries: nothing is processed without windows), the broker user `eg-ato` missing after a topology change (`pnpm rabbitmq:init`), `ATO_HMAC_KEY` missing (config error at start), a test seam set outside local/ci (refused at start). While `ato-detect` is down, `ato.events` grows (bounded at 1 000 000, `reject-publish` defers only ATO rows in the outbox) and `ato.mail` drops its oldest messages at 500 000; the catch-up restores them after restart. While `ato-respond` is down: no maintenance (no expiry, decay, catch-up, digests) and no provider actions; the leader lock moves to another replica if one runs.

## AtoEventsBacklog

`ato.events` holds logins, account changes and SMTP telemetry. Warning at 50 000 ready, critical at 500 000. Scale `ato-detect` (HPA on CPU; raise `maxReplicas` if CPU is the limit) and check `ato_detection_duration_seconds`, `ato_db_query_seconds{query="ledger_tx"}` (lock waits on hot accounts) and `ato_redis_operation_seconds`. A telemetry storm under a credential attack is expected (`AtoCredentialAttackCampaign`). At 1 000 000 the queue rejects publishes: the event-relay then nacks ATO rows only (they wait in the outbox, their own aggregate types), other events keep flowing. If the worker cannot catch up for hours, unbind the four `email.events` bindings of `ato.events` temporarily (the management UI) and rebind afterwards; login and telemetry events published in between are not recovered (stated loss: the telemetry contract is best effort, logins remain in `login_audit_logs`).

## AtoMailQueueNearBound

`ato.mail` (lossy, drop-head at 500 000, **no dead letters for dropped heads**) is half full. The detect role is slow or down. Dropped messages are not lost for ATO: the maintenance catch-up re-reads `email_messages` of ATO-enabled organizations (cursor `ato-mail-catchup:<org>`, `ATO_MAIL_CATCHUP_LAG_SECONDS` behind now, at most `ATO_MAIL_CATCHUP_MAX_AGE_HOURS` back for a new organization) and processes every message whose key (`atoMailKey(messageId, scanId)`) is not in the ledger, so a message is processed once whichever path sees it first. To relieve the broker you may purge the queue by name (`rabbitmqctl purge_queue -p email-gateway ato.mail`): the catch-up completes the work. Never point another consumer at `ato.mail`.

## AtoMailCatchupBehind

The catch-up had a full batch left and its cursor is more than an hour old. Check the maintenance leader (`ato_maintenance_leader{job="mail-catchup"} == 1` on exactly one replica, `ato_maintenance_runs_total{job="mail-catchup",result="error"}`), the writer, and the batch size (`ATO_MAIL_CATCHUP_BATCH`, per organization and pass). The catch-up only reads messages older than `ATO_MAIL_CATCHUP_LAG_SECONDS`; messages older than the per-organization cursor are never revisited.

## AtoDetectionLagHigh

p95 from source event to commit above 5 minutes. Usually a backlog (above) or lock contention on hot accounts: a relay connector that carries all of a tenant's outbound mail is one account whose daily row is updated by every message; `ato_db_query_seconds{query="ledger_tx"}` rises while `{query="prepare"}` stays low. More replicas do not help a single hot row; reduce `ATO_MAIL_PREFETCH` to reduce lock queueing, and see [performance/ato.md](../performance/ato.md). Events back-dated by a catch-up count as lag too (they were missed by the live feed).

## AtoDeadLetters

An ATO consumer dead-lettered events (reason in `x-eg-failure-reason`; `payload_invalid` = a producer bug, retries exhausted = a persistent dependency error). Inspect `email.dead-letter` by reason ([rabbitmq-messaging.md](rabbitmq-messaging.md)), fix the cause, then replay with `eg-ops` (the three ATO queues are replayable: `retry.ato.events.#`, `retry.ato.mail.#`, `retry.ato.responses.#`). Replays are idempotent (ledgers). A dead-lettered `ato.responses` event leaves its action `approved` (or `rollback_requested`): replay it within 25 h and it settles. Otherwise the maintenance `expiry` job settles it `failed` / `rollback_failed` with `provider_retry_exhausted` once nothing has touched it for 25 h (the queue's 24 h retry age plus margin), which raises the `response_failed` notification and frees the target for a new request; a replay after that is a no-op (`duplicate`). Analysts cannot cancel an approved action (cancel applies to `pending_approval` only).

## AtoSmtpTelemetryDropped

The smtp-adapter's in-process telemetry buffer dropped (full), expired (the outbox insert kept failing) or refused (contract) entries. Mail is unaffected; SMTP brute force (A1/A2 for connectors) and connector attribution of outbound mail are blind for the lost entries. Check the smtp-adapter's MySQL connectivity and `smtp_ato_telemetry_buffer_entries`; raise `SMTP_ATO_TELEMETRY_BUFFER_MAX` only if bursts are legitimate. Details: [smtp-ato-enforcement.md](smtp-ato-enforcement.md).

## AtoRestrictionLookupErrors

**Critical.** The smtp-adapter cannot read ATO restrictions (Redis `sa:ato:r:{org}` or MySQL `ato_smtp_restrictions`). The lookup fails closed, so authenticated submissions answer temporary failures (`4xx`) and the SASL server closes connections: outbound mail of every tenant waits in the tenants' MTAs. Restore Redis/MySQL first. If that takes long, use the **kill switch**: set `SMTP_ATO_ENFORCEMENT_ENABLED=false` on the smtp-adapter (Kubernetes: the explicit env line in `smtp-adapter.yaml`; Compose: `.env`, then recreate the container). Enforcement stops for every tenant (no lookups); restore it as soon as the dependency is back. The switch is an emergency control: record who changed it and why (deployment audit), and tell affected tenants that active restrictions were not enforced in between.

## AtoPolicyFactsErrors

The policy-engine failed to read `ato_accounts` / `security_incidents` for outbound or internal rounds of ATO-enabled organizations. Those evaluations fail and are retried by the policy consumer (the delivery gate waits for them). Check the writer and the policy-engine logs (`policy_ato_facts_total{result="error"}`, `policy_ato_facts_seconds`). The ato-worker is never involved; a stopped ato-worker does not cause this alert. Last resort for a tenant: the tenant switches ATO `mode` to `off` in its settings (facts are then absent, never a hold), or a platform operator disables the `ato_detection` feature.

## AtoGeoIpDatabaseStale

A loaded MaxMind database is older than `ATO_GEOIP_MAX_AGE_DAYS` (35). Located auth events carry `geo_status = stale`; rules keep working. Check the `geoipupdate` sidecar logs (credentials in `email-gateway-geoip`, MaxMind account status, HTTPS egress of the pod) and the worker's reload (`ato_geoip_database_age_seconds`, `ato_geoip_database_loaded`). The GeoLite2 EULA requires outdated copies to be replaced. If the file is removed, the worker keeps the last good reader until restart; after a restart without files, geography is `unavailable` (honest), never guessed.

## AtoResponseFailures

A response ended `failed` or `rollback_failed`. Nothing was claimed: `provider_status` is `failed` and the tenant's responders received a `response_failed` notification. Read the action and its attempts:

```sql
SELECT public_id, action_type, provider, status, provider_status, result_code, attempts FROM ato_response_actions WHERE status IN ('failed','rollback_failed') ORDER BY updated_at DESC LIMIT 20;
SELECT phase, attempt_no, outcome, provider_status, error_code, created_at FROM ato_response_action_logs WHERE action_id = <id> ORDER BY id;
```

`restriction_limit` = the organization has `ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG` active restrictions (lift stale ones). `provider_retry_exhausted` = the respond role never recorded a result within 25 h (its `ato.responses` message was dead-lettered or lost; see AtoDeadLetters). A succeeded restriction action with `result_code = restriction_already_active` shares the subject's running restriction (extended to the later expiry); rolling it back keeps the restriction while another succeeded action relies on it (`restriction_kept_shared`). Provider codes come from the adapter (step 8.5). An analyst may request the action again after the cause is fixed.

## AtoProviderFailures

Inactive until step 8.5 binds identity-provider adapters. Integrations (`ato_provider_integrations`) back off exponentially after failed polls and move to `status = 'error'` after `ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES`; `last_error_code` names the cause (`auth_error` = credentials revoked or consent withdrawn, `throttled` = the provider's rate limit, honoured through `retryAfterMs`). Provider actions are never claimed without confirmation: a failing provider leaves actions `failed` or `executing` (polled until confirmed). After the cause is fixed, set the integration back to `active` (step 8.5 adds the API).

## AtoFalsePositiveRateHigh — false-positive storm

More than half of at least 20 resolutions in 7 days were false positives. Calibrate before anything else: review the top rule codes of the false positives (incident `reason_codes`), the tenant's bands and weights, trusted networks and contexts. For a sudden storm across tenants (a rule or data change, e.g. a stale or wrong GeoIP database or a DNSBL zone that lists residential ranges):

1. Stop automatic restrictive actions platform-wide: `ATO_AUTOMATED_RESPONSES_ENABLED=false` on both ATO Deployments (pending approvals are created instead; low-impact alerts continue).
2. If restrictions already block legitimate senders: lift them (portal Responses → roll back; or the api), or, for a platform-wide emergency, the smtp-adapter kill switch above.
3. Remove the bad input (DNSBL zone, GeoIP database) and let scores decay (`ATO_DECAY_SWEEP_INTERVAL_SECONDS`); analysts resolve the incidents as `false_positive` with feedback (dismisses their signals and adds trusted contexts).
4. Re-enable automation once the rate is back to normal.

## AtoCredentialAttackCampaign

An IP failed against at least `ATO_IP_CAMPAIGN_MIN_ACCOUNTS` distinct accounts across the platform within `ATO_IP_CAMPAIGN_WINDOW_MINUTES` and is flagged for `ATO_IP_CAMPAIGN_FLAG_HOURS` (Redis `ato:ipflag:<ip>`; the windows hold account HMACs only, no tenant). A success from it raises T3 (strong) on that account. Consider blocking the source at the edge (load balancer/WAF; the per-IP SASL and login throttles already apply). Do not delete the flag to "unblock": it only adds evidence.

## AtoAutomationGuardTripped — automation guard

Automatic medium/high-impact responses were held for approval by the tenant hourly cap, the platform hourly cap (`ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR`) or the platform switch. This is the safety net working during a large attack or a false-positive storm. Pending approvals wait in **Account security → Responses**; they expire after `ATO_APPROVAL_TTL_HOURS`. Raise the platform cap only after confirming the detections are true positives. Other guard reasons (`tenant_monitor_mode`, `no_strong_signal`, `single_category`, `account_protected`, `benign_override`, `platform_organization`) are normal and counted by `ato_automation_guard_total{reason}` without an alert.

## Restriction lookup errors and the smtp kill switch

See [AtoRestrictionLookupErrors](#atorestrictionlookuperrors) and [smtp-ato-enforcement.md](smtp-ato-enforcement.md). Restrictions themselves are rows of `ato_smtp_restrictions` (≤ 7 days, `active | lifted | expired`); the maintenance role expires them (`ato.restriction.changed.v1` invalidates the adapters' caches within `SMTP_CACHE_INVALIDATION_POLL_MS`, at most `SMTP_ATO_RESTRICTION_CACHE_SECONDS` otherwise).

## Incident purge

Closed `account_takeover` incidents (`false_positive`, `resolved`) older than `ATO_RETENTION_INCIDENT_DAYS` (730) are deleted by the maintenance job `retention` in batches of 500, with their timeline events, links, ATO detail and response actions (action logs cascade). Action logs and cleared overrides older than 730 days, lifted/expired restrictions older than 400 days, expired trusted contexts after 30 days and old settings versions are purged in the same pass. Signals, scores, auth events and daily activity age out with their partitions (`pnpm db:partitions apply`; registry retention 13/13/3/6 months). Incidents of other categories (ATP, later) are never touched by this job. To keep an incident longer for an investigation, export its report (`GET /incidents/{id}/report`) before it reaches the retention age.

## Organization deletion

The deferred organization purge job (not built yet, step 1.2) must delete, for the organization: `ato_settings`, `ato_settings_versions`, `ato_accounts` (cascades baselines, identities, overrides, trusted contexts), `ato_account_activity_daily`, `ato_auth_events`, `ato_risk_signals`, `ato_risk_scores` (partitioned: delete by `organization_id`), `ato_incident_details`, `ato_response_actions` (cascades logs), `ato_smtp_restrictions`, `ato_provider_integrations`, `security_incidents` (cascades events and links), `notification_alert_windows` of the ATO kinds, the catch-up cursor `stream_cursors.name = 'ato-mail-catchup:<organizationId>'`, and the Redis keys `ato:*:<organizationId>:*` and `sa:ato:r:<organizationId>` (TTL-bound anyway). Until that job exists, disable `ato_detection` for the organization first so the worker stops writing, then follow the general order of the [organization-deletion runbook](organization-deletion.md).

## Local stack notes

- The Compose `ato-worker` runs every role with the TEST-ONLY synthetic GeoIP databases (documentation ranges). Build it alone (`docker compose build ato-worker`), never in parallel with other images.
- An existing `.env` keeps its `RECONCILE_QUEUES`; add `,ato.responses` by hand (the `.env.example` and Compose defaults include it).
- Integration suites (`pnpm --filter @email-gateway/ato-worker test:integration`) pause a live ato-worker while they run and create/remove `it-ato-*` organizations only.
