# Runbook: API-mode protection

API-mode protection (step API-1, [design](../plan/steps/35-api-mode-protection.md) D1–D12; [ADR-0098](../architecture/adr/0098-protection-modes-and-detect-mode-copies.md), [ADR-0099](../architecture/adr/0099-mailbox-access-consent-and-custody.md), [ADR-0100](../architecture/adr/0100-api-mode-intake-mailbox-worker.md); [deployment](../deployment/mailbox-worker.md); [contracts §36](../architecture/contracts.md)). A tenant on Microsoft 365 or Google Workspace is protected **without changing its MX records**: the gateway receives a journal copy of every message through the 8.6 journal intake (the primary path), optionally reads mailbox change feeds, scans every copy in **detect mode** and records one detection per mailbox (`api_message_copies`) with its verdict, risk score and lag. Coverage and health show whether every mailbox is seen.

**Ground rules.** API mode never delivers, forwards, delays or bounces mail (N1): copies end in `journaled`, never reach the policy engine, delivery, quarantine or customer webhooks, and every gateway view excludes them. A mode change never touches inline mail flow (`inbound_enabled`, destinations, connectors; N2). Mailbox credentials stay in the 8.2 credential store (the integration-worker and the mailbox-worker decrypt them; tokens live in process memory only). Logs carry public ids, codes and counts: never search logs for addresses, subjects, delta links or tokens, use the tables and metrics below. Remediation (moving or deleting messages) is **not** part of API-1 (API-2).

## Onboarding a tenant in API mode

Prerequisites: the organization's plan has the feature `api_mode_protection` (enterprise and dedicated; an operator can enable it per organization) and `journal_intake`. Archiving is **not** required (D6). Steps are done by the customer's administrator in the admin console; the operator checks the result.

1. **Choose the mode.** Add the domain with the wizard's first step _Protection mode_ → **API (no MX change)**; or set the organization default (Organization page → _Protection mode_, needs `organization:manage`) and let domains inherit it, or change a domain (`PUT /domains/{id}/protection-mode`, `domain:manage`). Every change needs a reason (1–500 characters) and is audited (`domain.protection_mode_changed`, `organization.protection_mode_changed`). An `api` domain is created with `inbound_enabled = false`. Use **Hybrid** for a domain whose MX stays at the gateway.
   - `409 protection_mode_mx_points_to_gateway`: the domain's latest MX observation points at the gateway. Either keep it inline / switch to Hybrid, or move the MX to the provider first and let the DNS checker observe it. For an organization change the response names up to 20 conflicting domains; the whole change is refused.
   - `403 api_mode_not_enabled`: the feature is not effective (plan or operator override). `inline` is always allowed (also to leave API mode after a downgrade).
   - `422 protection_mode_inbound_conflict`: `POST /domains` with `protectionMode: api` and `inboundEnabled: true`.
2. **Provider connection** (8.2, [runbook](provider-integrations.md)): create the Microsoft 365 or Google Workspace connection, grant the read-only mail-flow profile and link the domain until the connection is `active` and bound to the tenant.
3. **Journal intake source** (8.6, [runbook](journal-intake.md)): Settings → Journaling → add a `microsoft_365_journal` or `google_workspace_copy` source **bound to that connection**, and follow its guide (Microsoft 365 journal rule; Google Workspace routing rule "Also deliver to" with the header token). With API mode active the source is entitled without archiving (the wizard's _archiving_ step shows `skipped` with reason `api_mode`), and every copy is scanned (`journal_intake_messages.scan_requested = 1`). On-premises sources also detect-scan, but their copies have no API connection and are only counted (`api_mode_copies_total{result="no_connection"}`).
4. **Mailbox access consent** (ADR-0099; optional for detection, required for coverage totals, feeds and API-2). Provider connection page → card _Mailbox access for API mode_ (profile `m365.mailbox_remediation` / `google.mailbox_remediation`; granting needs `integration:manage` **and** `remediation:write`, else `403 remediation_permission_required`):
   - **Microsoft 365:** admin consent to the platform's mailbox app (`PROVIDER_M365_MAILBOX_APP_CLIENT_ID`; Graph application permissions `Mail.ReadWrite`, `User.Read.All`), or a customer app (`customer_app_secret`) with the same permissions. Optional: Exchange Online RBAC for Applications to scope the app to some mailboxes (scoped-out mailboxes appear as coverage gaps; see the open item on verification of scoped grants in the design §14.2).
   - **Google Workspace:** domain-wide delegation of the platform service account (`PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID`) or a customer service account to `https://www.googleapis.com/auth/gmail.modify` and `https://www.googleapis.com/auth/admin.directory.user.readonly`, with a delegated administrator as subject.
   - The integration-worker verifies the grant (`verifyAuxiliary`, the bound tenant only); the grant becomes `active` with the observed permissions. `tenant_not_bound` → finish step 2 first; `permissions_missing` → the consent lacks a permission.
5. **Inventory.** _Mailbox protection_ (`/api-mode`) → Coverage → _Sync inventory_ (`POST /api-mode/connections/{id}/inventory-sync`, `remediation:write`; `409 api_mode_mailbox_access_required` without the grant). The mailbox-worker lists users (Graph `/users`, Google Directory) whose addresses are on domains linked to the connection, adopts mailboxes first seen in journal copies, and sets `mailboxes_total`; it repeats every `API_MODE_INVENTORY_INTERVAL_HOURS` (6).
6. **Feeds (optional, off by default, P3).** Coverage → connection → _Feeds_ (`PUT /api-mode/connections/{id}/settings` `{ feedsEnabled, feedMode, expectedRowVersion }`). `poll` reads the Graph Inbox delta / Gmail history every `API_MODE_FEED_POLL_SECONDS` (300). `notify` (Microsoft 365 only, needs `API_MODE_GRAPH_NOTIFICATION_URL` on the api and the mailbox-worker, else `422 api_mode_notifications_unavailable`) creates a Graph subscription per mailbox whose change notifications request a sync; the safety poll is then `API_MODE_FEED_SAFETY_POLL_SECONDS` (3 600). Feeds never backfill existing mail: they start at the moment they are enabled.
7. **Verify coverage.** The Setup tab shows the wizard (`domains`, `connection`, `journal`, `mailbox_access`, `feeds`, `monitor`) with blockers and the next action, and the setup guide (`api-mode-guide/1`, Markdown download). Done when: the journal source is verified and healthy, Coverage shows covered = total (or the gaps are understood), the connection health is `healthy`, and Detections lists new copies with a lag of minutes.

## Revoking mailbox access, and what stops

`DELETE /provider-connections/{id}/grants/m365.mailbox_remediation` (or `google.…`; `remediation:write` + `integration:manage`) marks the grant `revoked` and wipes its ciphertext; the response lists the provider-side steps (remove the enterprise application or its `Mail.ReadWrite` permission; remove the client id from domain-wide delegation). On its next claim the mailbox-worker:

- stops feeds: every mailbox `feed_status = revoked`, cursors and subscription ids cleared (Graph subscriptions expire at the provider within their lifetime; their notifications are ignored);
- stops inventory: `inventory_status = unavailable` (coverage total unknown);
- sets health `failing` (check `mailbox_access.grant` = fail) when feeds were enabled, else `degraded`, and sends one `api_mode_unhealthy` alert (at most once per `API_MODE_ALERT_MIN_INTERVAL_HOURS`).

**Journal detection continues** (it needs no grant). The mail-flow grant and the tenant binding are unaffected. To resume, grant the profile again; the maintenance sweep sets in-scope mailboxes back to `pending` and the feeds re-initialize (no backfill: messages that arrived while revoked are covered only by the journal).

## Where to look

| Question                                            | Look at                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Overall state of a tenant                           | `GET /api-mode/overview` (portal _Mailbox protection_ → Coverage): entitled/active, domains per mode, coverage, connections by health, lag p50/p95 (1 h, 24 h), throttling, copies today                                                                                                                                                                                                                                                                                                                                                                 |
| One connection                                      | `GET /api-mode/connections/{id}`: `healthChecks` (`api-mode-health/1`), wizard, 7-day counters, `throttledUntil`, `lastErrorCode`, grant status; table `api_mode_connections`                                                                                                                                                                                                                                                                                                                                                                            |
| One mailbox                                         | `GET /api-mode/mailboxes/{id}` (feed status, last sync, last error code, subscription present, last 20 detections); table `api_mailboxes` (never return `feed_cursor`, `subscription_id` or `client_state_hash` to anyone)                                                                                                                                                                                                                                                                                                                               |
| Detections                                          | `GET /api-mode/detections` (masked sender, subject withheld); table `api_message_copies` (partitioned by `received_at`)                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Hourly counters                                     | `api_mode_counters` (journal/feed copies, duplicates, skipped internal, too large, provider requests, 429/503, errors, cursor resets, lag buckets); Redis `mbx:cnt:<apiConnectionId>:<yyyymmddhh>` before the flush (`API_MODE_COUNTER_FLUSH_SECONDS`, 30)                                                                                                                                                                                                                                                                                               |
| Platform-wide metrics (job `mailbox-worker`, :3087) | `api_mode_copies_total{source,result}`, `api_mode_lag_seconds{source}`, `api_mode_provider_requests_total{provider,family,status_class}`, `api_mode_throttled_total{provider,family}`, `api_mode_feed_syncs_total{provider,result}`, `api_mode_cursor_resets_total`, `api_mode_fetch_bytes_total`, `api_mode_subscriptions{state}`, `api_mode_mailboxes{coverage}`, `api_mode_connections{health}`, `api_mode_inventory_runs_total`, `api_mode_health_transitions_total`, `api_mode_alerts_total`, `api_mode_rate_budget_waits_total`, `api_mode_leader` |
| Public callback (job `api`)                         | `api_mode_notifications_total{kind,result}` (`kind` change or lifecycle; `result` accepted, unknown_subscription, client_state_mismatch, tenant_mismatch, feed_inactive, invalid, validation, rate_limited)                                                                                                                                                                                                                                                                                                                                              |
| Is the worker up?                                   | `GET :3087/health/ready` (mysql, redis, s3, rabbitmq); consumer on `email.mailbox`; `api_mode_leader` = 1 on exactly one replica                                                                                                                                                                                                                                                                                                                                                                                                                         |

```sql
-- One connection (8.2 connection public id): API-mode state and the last 24 hours of counters.
SELECT a.public_id, a.health_status, a.health_changed_at, a.inventory_status, a.mailboxes_total,
       a.feeds_enabled, a.feed_mode, a.throttled_until, a.last_error_code,
       SUM(c.journal_copies) journal, SUM(c.feed_copies) feed, SUM(c.duplicates) dup,
       SUM(c.throttled_429) t429, SUM(c.throttled_503) t503, SUM(c.cursor_resets) resets,
       SUM(c.lag_gt_3600s) lag_over_1h
FROM api_mode_connections a
JOIN provider_connections p ON p.id = a.provider_connection_id
LEFT JOIN api_mode_counters c ON c.api_connection_id = a.id AND c.hour >= UTC_TIMESTAMP() - INTERVAL 24 HOUR
WHERE p.public_id = '<connection public id>'
GROUP BY a.id;

-- Mailboxes of a connection by feed status and coverage.
SELECT feed_status, coverage_state, COUNT(*) FROM api_mailboxes
WHERE api_connection_id = <api_mode_connections.id> AND status = 'active'
GROUP BY feed_status, coverage_state;
```

## Troubleshooting intake lag

Lag = verdict time − provider delivery time (feed copies: Graph `receivedDateTime` / Gmail `internalDate`; journal copies: the topmost `Received:` header, else the ingest time; `api_message_copies.delivered_basis` says which). Find where the time goes:

1. **Journal delays (provider side).** Microsoft 365 journaling and Google routing can deliver minutes late. Compare `email_messages.received_at` of the copy with `provider_delivered_at`: a large gap before ingest is the provider's. Check the source in [journal intake](journal-intake.md) (refusals, deferrals, `JournalIntakeSilentSources`). Nothing to tune on the gateway; feeds (`notify`) give a second, faster path for Microsoft 365.
2. **Scan backlog.** The copy waits in `email.received` / the scan queues like gateway mail: see [scan pipeline](scan-pipeline.md) (queue depth, engine latency). Copies share the scan capacity with inline mail.
3. **`email.mailbox` queue.** The copies role finalizes rows from `mail.message.copy_scanned.v1`. A backlog means the mailbox-worker is down, slow on the writer, or retrying: check the consumer count, `api_mode_copies_total{result}` and the worker log (`component` copies, codes only). Pending copy rows (`status = pending`) older than a few minutes point here.
4. **Cursor resets.** A Graph `410 syncStateNotFound` or Gmail `404` on the stored cursor re-initializes the mailbox without backfill (`api_mailboxes.last_gap_at`, counter `cursor_resets`): messages delivered in the gap are covered only by the journal.

### ApiModeLagHigh

p95 of `api_mode_lag_seconds` > 900 s for 15 min. Split by `source` (journal vs graph/gmail): journal only → step 1; every source → steps 2–3; one connection → its counters (`lag_gt_3600s`) and `throttled_until`. The health check `lag.p95_1h` warns above `API_MODE_LAG_WARN_SECONDS` (900) and fails above `API_MODE_LAG_FAIL_SECONDS` (3 600) per connection.

### ApiModeCopyQueueBacklog

More than 10 000 ready messages in `email.mailbox` for 15 min. Check the mailbox-worker pods (ready, consumer present, writer pool), dead letters of `email.mailbox` ([RabbitMQ runbook](rabbitmq-messaging.md): replay as `eg-ops`), and whether a scan burst (bulk journal backlog) is simply draining. Scale the Deployment (copies is stateless; prefetch 16 per replica; the writer pool is 20 per replica).

## Throttling

Every provider call first takes the per-connection budget of its API family (Redis `mbx:rb:<connection>:<family>:s<epoch>`): `API_MODE_GRAPH_REQUESTS_PER_SECOND` (8), `API_MODE_GMAIL_REQUESTS_PER_SECOND` (10), `API_MODE_DIRECTORY_REQUESTS_PER_SECOND` (5). A budget wait retries in 2 s (`api_mode_rate_budget_waits_total`), not a failure. A `429` (or Google rate-limit `403`, or `503` with `Retry-After`) sets the shared pause `mbx:throttle:<connection>:<family>` for `Retry-After` (capped at 600 s), writes `api_mode_connections.throttled_until`, counts `throttled_429` / `throttled_503`, and the mailbox ends `throttled` until the pause ends; every worker replica honours the pause before any call of that family. Other retryable errors back off `30 s × 2^(n−1)` up to 1 h; the third consecutive failure sets `feed_status = error`.

Keys to tune (mailbox-worker, restart to apply): the per-family budgets above (lower them when a tenant is throttled persistently; Microsoft's mailbox limits are per app and mailbox), `API_MODE_FETCH_CONCURRENCY` (16) and `API_MODE_FETCH_CONCURRENCY_PER_CONNECTION` (4), `API_MODE_FEED_BATCH` (50), `API_MODE_FEED_POLL_SECONDS` (300). The health check `throttling.1h` warns above `API_MODE_THROTTLE_WARN_PER_HOUR` (20).

### ApiModeThrottlingSustained

Throttle events above 0.1/s for 30 min for a provider/family. Find the connection(s) with `throttled_until` in the future and their counters; lower the family budget or the per-connection concurrency, and check whether a reset (many mailboxes re-initializing) or an inventory run of a large tenant is the cause. Throttling never loses mail: syncs resume after the pause and the journal path is unaffected.

## Subscriptions (Graph change notifications)

Only for `feed_mode = notify`. The mailbox-worker creates one subscription per mailbox for `API_MODE_GRAPH_SUBSCRIPTION_MINUTES` (4 230) with `notificationUrl = API_MODE_GRAPH_NOTIFICATION_URL` and `lifecycleNotificationUrl = <url>/lifecycle`, renews it by `PATCH` `API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES` (720) before expiry, re-creates it when Graph lost it (`subscriptionRemoved`, 404), and deletes it when feeds are disabled or the mailbox leaves scope. The client state is derived from `API_MODE_NOTIFICATION_SECRET` and stored only as a SHA-256 hash. Creation needs Graph's **validation handshake**: Graph (or the idp-simulator locally) POSTs `?validationToken=…` to the URL and needs the exact `text/plain` echo from the api.

- `api_mailboxes.last_error_code = subscription_failed`: the feed keeps polling at the normal poll interval. Usual causes: the URL is not publicly reachable over HTTPS, the Ingress does not route `POST /api/v1/provider-notifications/graph[/lifecycle]`, or the handshake echo is blocked by a proxy. Check `api_mode_notifications_total{kind="validation"}`.
- Rotating `API_MODE_NOTIFICATION_SECRET` makes every stored hash mismatch until the subscriptions are re-created: notifications are then counted `client_state_mismatch` and ignored (the safety poll still syncs). Plan a rotation as: rotate, then resync the mailboxes (`POST /api-mode/mailboxes/{id}/resync`) or switch the connection to `poll` and back to `notify`.
- `api_mode_subscriptions{state}` shows active vs. expiring subscriptions.

## The public notification endpoint

`POST /api/v1/provider-notifications/graph` and `…/graph/lifecycle` are **public** (no authentication; Graph cannot authenticate to us). They are unprivileged by design (N3): they never read notification content, never take a tenant from the payload, and only set `api_mailboxes.sync_requested_at` (coalesced) for a mailbox found by its stored subscription id **and** a constant-time client-state hash match **and** (when present) the connection's bound tenant id. Lifecycle events: `reauthorizationRequired` → forces a renewal, `subscriptionRemoved` → re-create, `missed` → sync. The answer is always `202` with an empty body (no oracle). Limits: body ≤ 256 KiB (`413`), `API_MODE_NOTIFICATION_RATE_PER_MINUTE` (1 200) per client IP (`429`). If the endpoint is flooded: the rate limit holds per IP; mismatches only increment `api_mode_notifications_total{result}`; a WAF rule restricting the path to Microsoft's published notification source ranges is the next step. Disabling the route is safe: feeds fall back to the safety poll.

## Coverage gaps

A mailbox is `covered` when its feed is `active` and synced within 3 poll intervals, or a journal copy addressed to it was seen within `API_MODE_JOURNAL_COVERAGE_DAYS` (7); `out_of_scope` when its domain is effective `inline` or the user is disabled or deleted; otherwise `gap`. Coverage % = covered / (covered + gap) over active mailboxes, only once the inventory is `ok` (without it the page shows covered mailboxes and "total unknown"). Health check `coverage.percent` warns below `API_MODE_COVERAGE_WARN_PERCENT` (95) and fails below `API_MODE_COVERAGE_FAIL_PERCENT` (50).

### ApiModeCoverageGaps

Gap mailboxes for 6 h. List them (`GET /api-mode/mailboxes?coverage=gap`). Typical causes: a quiet mailbox (no mail in 7 days and no feeds: expected, enable feeds to cover it), the journal rule scoped to some users or groups only, a new user not yet in the journal rule, the Exchange RBAC-for-Applications scope excluding the mailbox (feeds then fail with a missing-permission code), or a feed in `error`/`throttled` (see the mailbox's `last_error_code`).

## Health and alerts

The health role (leader-locked, one replica) evaluates every connection every `API_MODE_HEALTH_INTERVAL_MS` (60 s): `connection.active`, `intake.present`, `intake.journal_health`, `mailbox_access.grant`, `coverage.percent`, `lag.p95_1h`, `throttling.1h`, `feeds.errors`, `domains.api_mode_mx`. Worst status wins (`fail` → `failing`, `warn` → `degraded`). A transition writes the audit row `api_mode.health_changed` `{ connectionId, from, to, failingChecks }` and, for degraded/failing, the **`api_mode_unhealthy`** alert e-mail (notification-worker) to the holders of `remediation:read` and the organization's contact (severity medium/high, check titles and a link to `/api-mode?connection=<id>`, never addresses), at most once per connection per `API_MODE_ALERT_MIN_INTERVAL_HOURS` (24).

| Check                   | Fails / warns when                                                                   | Action                                                                                                                               |
| ----------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `connection.active`     | the 8.2 connection is not active or not bound                                        | [Provider integrations runbook](provider-integrations.md) (consent, binding)                                                         |
| `intake.present`        | no verified provider journal source and feeds active on < 90 % of in-scope mailboxes | Set up the journal source (onboarding step 3) or enable feeds                                                                        |
| `intake.journal_health` | the journal source is `silent` (warn) or `failing` (fail)                            | [Journal intake runbook](journal-intake.md#journalintakesilentsources)                                                               |
| `mailbox_access.grant`  | grant missing or not active (warn); revoked while feeds are enabled (fail)           | Re-grant (onboarding step 4), or disable feeds if access was withdrawn on purpose                                                    |
| `coverage.percent`      | below 95 % (warn) / 50 % (fail), with inventory                                      | [Coverage gaps](#coverage-gaps)                                                                                                      |
| `lag.p95_1h`            | p95 above 900 s (warn) / 3 600 s (fail)                                              | [Troubleshooting intake lag](#troubleshooting-intake-lag)                                                                            |
| `throttling.1h`         | more than 20 throttle events in the last hour                                        | [Throttling](#throttling)                                                                                                            |
| `feeds.errors`          | more than 10 % of feed mailboxes in `error`                                          | Mailbox `last_error_code` (`missing_permission`, `credentials_invalid`, `provider_unavailable`, …); resync one mailbox after the fix |
| `domains.api_mode_mx`   | an effective-`api` domain's MX points to the gateway again (warn; nothing changes)   | Mail now arrives inline for a domain that is not filtered inline: move the MX back to the provider or switch the domain to Hybrid    |

### ApiModeConnectionsFailing

At least one connection `failing` for 15 min (`api_mode_connections{health="failing"}`). Find it (`SELECT public_id, organization_id, health_checks FROM api_mode_connections WHERE health_status = 'failing'`), read the failing checks and follow the table above. Tell the customer (they received the alert); never change their mode or grants on their behalf.

### ApiModeCursorResets

Cursor resets in the last hour. One mailbox now and then is normal (Graph expires delta tokens after long idle periods). Many on one connection: a provider-side incident, a resync storm (`POST …/resync` re-initializes on purpose), or the worker was stopped for longer than the provider keeps cursors. Messages of the gap are covered only by the journal; nothing to replay.

## Mailbox resync and other operator actions

- **Resync one mailbox** (`POST /api-mode/mailboxes/{id}/resync`, `remediation:write`, needs the active grant): clears the cursor and re-initializes without backfill. Use after fixing a permission or a corrupted cursor.
- **Inventory now:** `POST /api-mode/connections/{id}/inventory-sync`.
- **Disable feeds:** settings `feedsEnabled: false`; the worker deletes the subscriptions and sets `feed_status = off` on its next sweep.
- **Oversized messages:** copies above `API_MODE_MAX_MESSAGE_BYTES` (50 MiB) are recorded `too_large` without content and not scanned (counter `too_large`).
- **Organization deletion:** the tenant-data purge removes the six API-mode tables (copies, dedupe keys, addresses, mailboxes, counters, connections) before the provider connections ([organization deletion](organization-deletion.md)).

## Local stack and tests

The idp-simulator (Compose profile `smtp-test`) serves the Graph mail, Gmail and Directory endpoints and pushes change notifications to `http://api:3000`; tokens come from 8.2's provider-fake. The stack suite `tests/integration/api-mode.test.ts` covers the nine §9.6 cases (journal detect mode, grant and inventory, notify feeds, GTUBE/EICAR verdicts, dedupe both orders, Gmail, throttling, revocation with the alert e-mail, mode changes and MX conflict, the overview) with synthetic `it-apimode-*` organizations; run it after `SMTP_ADAPTER_HOST=smtp-adapter docker compose up -d --no-deps --force-recreate postfix postfix-outbound` with the `apps` and `smtp-test` profiles up. Nothing in the local stack reaches Microsoft, Google or the Internet.
