# Runbook: ATO identity-provider adapters

Step 8.5 ([design](../plan/steps/26-ato-provider-adapters.md), ADR-0082..0086). Deployment, permissions and keys: [deployment/ato-identity-providers.md](../deployment/ato-identity-providers.md). The ATO core: [account-takeover.md](account-takeover.md). Alerts: `infrastructure/monitoring/rules/ato-idp.rules.yml`.

**Ground rules.** Provider I/O runs only in the `ato-respond` Deployment (roles `respond,maintenance,provider`); the mail path is never involved. Never act on a real tenant to test something: the local stack and every suite use synthetic directories (`contoso-it.example`, `fabrikam-it.example`) served by local simulators. Logs carry ids, codes, families and path templates only (no tokens, addresses, query strings or provider bodies).

Useful reads (writer; read-only):

```sql
-- Integrations: status, health, last probe, failures
SELECT id, organization_id, provider, status, paused_reason, disabled_reason, health_status,
       health_checked_at, next_health_at, consecutive_failures, last_error_code
FROM ato_provider_integrations WHERE provider IN ('microsoft_entra', 'google_workspace');
-- Streams of one integration: role, status, availability, cursor progress, throttling, failures
SELECT stream, role, enabled, status, availability, availability_code, cursor_seq, watermark_at,
       next_poll_at, throttled_until, consecutive_failures, last_error_code, events_total,
       pages_total, backfill_from, backfill_completed_at, covered_from, replay_from, replay_until
FROM ato_provider_streams WHERE integration_id = ? ORDER BY stream;
-- Provider actions in flight
SELECT public_id, action_type, status, provider_status, result_code, integration_id, next_check_at
FROM ato_response_actions WHERE integration_id = ? AND status IN ('approved','executing','rollback_requested');
```

Series: `ato_idp_stream_lag_seconds`, `ato_idp_integrations{health}`, `ato_idp_throttled_total`, `ato_idp_rate_budget_waits_total`, `ato_idp_http_requests_total{status_class}`, `ato_idp_events_total{result}` (`foreign_domain`, `invalid`, `stream_disabled` are drops; `replayed` counts events a backfill skipped because an earlier ingestion of the stream already processed them), `ato_idp_probe_total`, `ato_idp_actions_total{outcome}`, `ato_idp_cursor_resets_total`, `ato_idp_backfills_active`, plus 8.4's `ato_provider_operations_total` and `ato_provider_poll_seconds`.

## Lag

`AtoIdpStreamLagHigh`: the oldest watermark of an enabled primary stream is more than an hour behind for 30 minutes. Detection latency is the provider's own log latency plus the poll interval (minutes), so an hour means the stream is not progressing. In order:

1. The stream row: `consecutive_failures` / `last_error_code` (see **Unhealthy**), `throttled_until` (see **Throttling**), `next_poll_at` far in the future (back-off after failures, capped at 1 hour).
2. The provider role: `ato_maintenance_leader` is irrelevant here (streams are claimed with `FOR UPDATE SKIP LOCKED` by every replica), but the `ato-respond` pod must be running and ready; `ato_provider_poll_seconds` shows polls happening.
3. A large backfill (`ato_idp_backfills_active`) shares the rate budget with the live window of the same integration; it ends on its own. A backfill re-reads provider history up to now but skips (`replayed`) the range the stream had already ingested (`replay_from` / `replay_until`, set when the backfill was requested; cleared and `covered_from` lowered when it completes), so requesting one on a live stream never counts sign-ins twice; the last hour before the earlier watermark is left to the 6 h seen-set.
4. Office 365 Management Activity content can arrive hours late on Microsoft's side (documented provider behaviour); the overlap window re-reads the last hour.

Pages are processed at most `ATO_PROVIDER_MAX_PAGES_PER_POLL` per claim; a stream with more pending is due again immediately.

## Throttling

`AtoIdpThrottledSustained`: the provider answers `429` / Google `rateLimitExceeded` / quota errors at more than 0.5/s for 30 minutes. Each throttled stream honours `Retry-After` (or backs off exponentially up to `ATO_IDP_MAX_BACKOFF_MS`) and records `throttled_until`; this is not a failure. Quota answers (`dailyLimitExceeded`/`quotaExceeded`) wait an hour. Lower the per-integration budgets `ATO_IDP_RATE_{GRAPH,O365,GOOGLE_REPORTS,GOOGLE_DIRECTORY,GMAIL}_PER_SECOND` if many tenants of one provider are throttled at once (one budget per integration and family, so the platform total scales with tenants); avoid starting many backfills at once. `ato_idp_rate_budget_waits_total` shows the gateway's own budget holding requests back (pages end early and resume a second later).

## Unhealthy

`AtoIdpIntegrationUnhealthy` and the tenant's `provider_unhealthy` e-mail (one per integration per 6 hours; recovery sends nothing). Health is computed by the probe (`ATO_IDP_HEALTH_INTERVAL_SECONDS`, after a bind, on **Check now**, and after three consecutive failures of any stream):

| `paused_reason` / `last_error_code`                                | Meaning                                                                                                       | Action                                                                                                                                                                                     |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `connection_inactive`                                              | 8.2 connection not active                                                                                     | Tenant completes 8.2 (tenant verification, linked domains); the probe resumes automatically                                                                                                |
| `telemetry_grant_inactive`                                         | `*.ato_telemetry` grant pending, revoked or error                                                             | Consent / delegation again, then **Verify** the grant in 8.2 (an ATO grant added before the connection was bound ends `tenant_not_bound`: verify it again once the connection is `active`) |
| `credentials_invalid`, `consent_missing`, `scope_not_granted`      | Token acquisition fails (8.2 token service)                                                                   | Customer-owned app: secret expired or consent withdrawn. Platform app: certificate expired or app deleted — affects every tenant of that profile at once                                   |
| `directory_changed`                                                | The connection's tenant is not the bound directory                                                            | Unbind and rebind; resumes automatically if the connection points back                                                                                                                     |
| `directory_in_use`                                                 | Another integration holds the directory                                                                       | One directory binds to one integration platform-wide                                                                                                                                       |
| `stream_unavailable` with `missing_permission` / `missing_license` | Some streams lack a permission or licence (health `degraded`, or `unhealthy` when every enabled stream fails) | Grant / licence; the Permissions tab lists the missing names                                                                                                                               |
| `provider_unavailable`                                             | Provider 5xx or network                                                                                       | Usually transient; check egress (NetworkPolicy, proxy) if every tenant is affected                                                                                                         |

An integration in 8.4's `error` state (`ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES` failed polls) stops polling until a probe passes; the probe then resets the stream failures and polls at once. A disabled connection (8.2) disables the integration (`connection_removed`) and fails its in-flight provider actions `integration_disabled`.

A new integration that shows **Not checked yet** for minutes and streams without a last success: check that the organization's feature `ato_detection` is on and its ATO mode is not `off`; the worker re-checks every minute while it sees ATO off (an organization context cached during the feature switch lasts `ATO_SETTINGS_CACHE_SECONDS`).

## Probe failures

`AtoIdpProbeFailures`: three or more failed probes in an hour for one provider. A probe is read-only (one cheap read per primary stream plus action prerequisites). Look at `health_detail` of the affected integrations (`streams.*.availability` and `code`, `grants[].missingPermissions`). Many tenants failing together points at the platform app (certificate, deleted app, Google service account key rotated) or egress; a single tenant at its grants or licences.

## Cursor reset

`AtoIdpCursorResets`: a stored cursor was malformed or written by another adapter version; the stream restarted at now minus its overlap window (never at the epoch) with a higher page counter, so page keys stay unique. Events between the old watermark and the restart may be missing: request a backfill (`POST /ato/providers/{id}/backfill`, bounded by `ATO_IDP_BACKFILL_MAX_DAYS` and provider retention) from the old watermark. Backfilled events older than `ATO_IDP_HISTORICAL_SIGNAL_AGE_HOURS` are historical (informational signals, no incident). Never edit `cursor` by hand; to force a restart set `cursor = NULL` only together with a backfill (`status = 'backfilling'`, `backfill_from`, `next_poll_at = NOW()`), which the api does.

## Confirmation timeouts

`AtoIdpActionsUnconfirmed`: a provider action was executed (provider `2xx`) but the read-back never showed the requested state within `ATO_IDP_CONFIRM_TIMEOUT_MINUTES`; it ended `failed`, `provider_status = 'unconfirmed'`, `result_code = 'confirmation_timeout'`. **The effect may still have happened.** An analyst verifies the account in the provider admin centre (suspended? removed from the MFA group? rule disabled?) and requests the action again if needed (provider writes are naturally idempotent; the pre-state is captured once). Frequent timeouts on Microsoft group membership or Google OU moves mean provider replication delay: the confirmation polls back off from 10 s to 5 minutes.

## Unbinding

`DELETE /ato/providers/{id}` (an `ato:configure` user with MFA) sets the integration `disabled`: polls, probes and provider actions stop at once; in-flight provider actions of the integration end `failed` `integration_disabled` through the normal completion path (timeline, audit, failure notice). Signals, auth events and actions remain under 8.4's retention; stream rows and mailbox items are deleted by the maintenance role 30 days after `disabled_at`. The directory is free for a new binding immediately. Unbinding never revokes the 8.2 grants or deletes the provider-side app consent: remove those in 8.2 and in the provider tenant if the customer leaves.

## Idempotency facts (for incident review)

- Each page is processed in one writer transaction under `processOnce('ato-worker.provider', providerPageKey(integration, stream, cursorBefore))`; the cursor moves in the same transaction (compare-and-set on the stored cursor). A crash mid-page commits nothing and the page is re-read.
- Overlap re-reads are skipped through a Redis seen-set (`ato:idp:ev:{org}:{integration}:*`, 6 hours) written after the commit; 8.4 also deduplicates auth events and signals by their keys.
- Mailbox state items written by a page count as known only once the page's cursor is committed (cursor-confirmed), so a crash re-emits the change with the same event id.
- Provider actions use the action public id as idempotency key; a redelivery finds the stored pre-state and only confirms (one provider write).
