# Runbook: API-mode protection

API-mode protection (step API-1, [design](../plan/steps/35-api-mode-protection.md) D1–D12; [ADR-0098](../architecture/adr/0098-protection-modes-and-detect-mode-copies.md), [ADR-0099](../architecture/adr/0099-mailbox-access-consent-and-custody.md), [ADR-0100](../architecture/adr/0100-api-mode-intake-mailbox-worker.md); [deployment](../deployment/mailbox-worker.md); [contracts §36](../architecture/contracts.md)). A tenant on Microsoft 365 or Google Workspace is protected **without changing its MX records**: the gateway receives a journal copy of every message through the 8.6 journal intake (the primary path), optionally reads mailbox change feeds, scans every copy in **detect mode** and records one detection per mailbox (`api_message_copies`) with its verdict, risk score and lag. Coverage and health show whether every mailbox is seen.

**Ground rules.** API mode never delivers, forwards, delays or bounces mail (N1): copies end in `journaled`, never reach the policy engine, delivery, quarantine or customer webhooks, and every gateway view excludes them. A mode change never touches inline mail flow (`inbound_enabled`, destinations, connectors; N2). Mailbox credentials stay in the 8.2 credential store (the integration-worker and the mailbox-worker decrypt them; tokens live in process memory only). Logs carry public ids, codes and counts: never search logs for addresses, subjects, delta links or tokens, use the tables and metrics below. Remediation (moving, tagging or deleting delivered messages, step API-2) is the one exception to "never touches mail": it acts only inside the customer's mailboxes through the provider APIs, never on mail flow; see [Remediation](#remediation-step-api-2).

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
- **Organization deletion:** the tenant-data purge removes the API-mode tables (remediation actions and policies first, then copies, dedupe keys, addresses, mailboxes, counters, connections) before the provider connections ([organization deletion](organization-deletion.md)); messages already moved inside the customer's mailboxes stay where they are.

## Remediation (step API-2)

Step API-2 ([design](../plan/steps/36-api-mode-remediation.md) R1–R17, [ADR-0101](../architecture/adr/0101-api-mode-remediation-policy-and-mailbox-actions.md), [ADR-0102](../architecture/adr/0102-mailbox-located-quarantine-entries-release-as-restore.md), [deployment](../deployment/mailbox-worker.md#remediation-step-api-2), [contracts §37](../architecture/contracts.md)). After a copy is scanned, the mailbox-worker's `copies` role decides **in the same ledger transaction** what to do with the message in that mailbox (`api_remediation_actions`, one row per copy, action and generation, unique `action_key`), and the `remediate` role executes it through Microsoft Graph (`Mail.ReadWrite`) or Gmail (`gmail.modify`) with the mailbox-access grant of onboarding step 4. Remediation happens **after delivery**, usually seconds to a minute after the verdict; a user may have seen the message before. Decisions use the copy's scan verdict and risk (level, hard blocks, score) only: tenant policies (5.2, DLP, BEC, custom rules) are **not** evaluated on copies (product-owner decision, deferred).

### Policy and presets

One policy per organization (`api_remediation_policies`, domain NULL) with optional per-domain overrides; without a row the platform default **P1** applies. A policy is a mode (`detect_only` | `enforce`) plus an ordered list of up to 16 rules (`api-remediation-policy/1`; first match wins): `when { verdicts, minLevel?, maxLevel?, hardBlock?, minScore? }` → `move_quarantine | move_junk | tag | soft_delete | hard_delete | none`. Edit it in the portal (_Mailbox protection_ → **Remediation**) or with `PUT /api-mode/remediation-policy` / `PUT|DELETE …/domains/{domainId}` (`remediation:write`, Idempotency-Key, CAS `expectedRowVersion`, a reason; audited as `api_mode.remediation_policy_updated` with the before/after mode and document hash). `409 api_mode_remediation_policy_conflict` = someone else saved first: reload and re-apply. A saved policy takes effect **within 30 seconds**: each mailbox-worker keeps an organization's effective policy for 30 s (R2.6), so copies decided in that window still follow the previous one; decisions already taken are not re-run.

| Preset                | Rules                                                                                                                                                                                                                | Mode          |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| **P1** (default)      | malware/phishing with a hard block → quarantine folder; malware/phishing at level `critical` → quarantine folder; other malware/phishing → tag; suspicious/BEC → tag; spam, bulk, DLP → nothing (provider filtering) | `enforce`     |
| **Detect-only start** | the P1 rules                                                                                                                                                                                                         | `detect_only` |
| **Strict**            | P1 + spam → Junk                                                                                                                                                                                                     | `enforce`     |

What each action does in the customer tenant (details: [Microsoft 365](../integrations/api-mode-microsoft-365.md), [Google Workspace](../integrations/api-mode-google-workspace.md)): `move_quarantine` → a **hidden** folder `API_MODE_QUARANTINE_FOLDER_NAME` ("Email Gateway Quarantine") under the mailbox root / a hidden label `API_MODE_GMAIL_QUARANTINE_LABEL` with `INBOX` removed; `move_junk` → Junk Email / `SPAM`; `tag` → the category / label `API_MODE_TAG_NAME` (message stays in the Inbox); `soft_delete` → Recoverable Items Deletions / Trash (recoverable); `hard_delete` → Graph `permanentDelete` (irreversible). Quarantine-folder, Junk and soft-delete moves create a **mailbox-located quarantine entry** ([quarantine runbook](quarantine.md#mailbox-located-entries-step-api-2)); tags and hard deletes do not.

### Starting a tenant in detect-only

Recommended for every new tenant: apply the **Detect-only start** preset before (or right after) granting mailbox access. Decisions are recorded as `simulated` (History tab, `api_remediation_actions.status = simulated`, copy `remediation_state = simulated`, counter `remediation_simulated`) and **no provider call is made**. Review a few days of simulated decisions with the customer (which mailboxes, which verdicts, how many), then switch the mode to **Enforce** (same rules). Nothing is replayed when switching: only copies scanned after the switch are acted on (late verdicts are not re-decided in API-2).

### Pausing a connection (emergency stop)

_Coverage_ → connection → **Pause remediation** (`PUT /api-mode/connections/{id}/settings` with `remediationPaused: true`; audited, `remediation_paused_at` set). While paused, new policy decisions are recorded as `skipped` (`remediation_paused`) and already queued **policy** actions wait (re-checked every 300 s); **admin, release and end-user actions still run**, so restores keep working. The health check `remediation.paused` warns while it is on. Resume with `remediationPaused: false`; skipped decisions are not re-run (remediate those copies manually from _Detections_ if needed). To stop everything for an organization instead, set the policy to detect-only.

### Failures

Each action ends `succeeded` (also `already_in_target` when the message was already there), `failed`, `skipped` or `cancelled`. Look at the History tab (`GET /api-mode/remediations?status=failed`, detail with attempts, `lastErrorCode`, `lastHttpStatus`) or:

```sql
SELECT reason_code, last_error_code, action, COUNT(*) FROM api_remediation_actions
WHERE organization_id = ? AND status = 'failed' AND created_at >= UTC_TIMESTAMP() - INTERVAL 1 DAY
GROUP BY 1, 2, 3;
```

| `reason_code`                      | Meaning                                                                                                                                            | Action                                                                                                                               |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `mailbox_access_revoked`           | The `*.mailbox_remediation` grant is not active (revoked, expired) when the action was claimed                                                     | Re-grant (onboarding step 4), then **Retry** the failed rows (`POST /api-mode/remediations/{id}/retry`)                              |
| `message_not_found`                | The message could not be located by Internet Message-ID after `API_MODE_REMEDIATION_LOCATE_ATTEMPTS` (6, ≈ 1 h; drafts and Sent Items are ignored) | Usually the user deleted or moved it already; nothing to do. Many on one connection: journal rule covers mailboxes outside the grant |
| `provider_forbidden`               | `401/403` after the token retry (permission withdrawn, RBAC for Applications scope excludes the mailbox)                                           | Check the app's permissions / the scope; retry                                                                                       |
| `provider_rejected`                | `400` from the provider                                                                                                                            | Record the `last_http_status`; retry once; open an issue with the action public id if it persists                                    |
| `provider_unavailable`             | Retryable errors (5xx, timeouts) for `API_MODE_REMEDIATION_MAX_ATTEMPTS` (8; 30 s doubling to `API_MODE_REMEDIATION_BACKOFF_MAX_SECONDS`, 1 h)     | Provider incident: retry when it is over                                                                                             |
| `integrity_mismatch`               | Action, copy, mailbox and connection did not belong to one organization (error log)                                                                | Should never happen: escalate with the action public id                                                                              |
| `hard_delete_unsupported_provider` | (succeeded) a Gmail hard delete ran as Trash                                                                                                       | Expected (see Gmail limitations)                                                                                                     |

Skipped decisions (`status = skipped`) are not failures: `inline_authority` (hybrid copy the gateway already decided inline), `out_of_scope` (domain not api/hybrid, mailbox disabled or deleted), `hard_delete_disabled`, `remediation_paused`, `no_mailbox_access` (no active grant at decision time). Every executed action writes the system audit row `api_mode.remediation_executed` (ids and codes only).

### Throttling and the backlog

Remediation calls take the **same** per-connection provider budget as feeds and inventory (`mbx:rb:<connection>:graph|gmail`), so a tenant's total call rate stays within one limit. A `429` (or `503` with `Retry-After`) sets the shared pause (see [Throttling](#throttling)); the action waits until `throttled_until` **without counting an attempt** (counter `remediation_throttled`). Concurrency: `API_MODE_REMEDIATION_CONCURRENCY` (8) per replica and `API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION` (2) across replicas; batches of `API_MODE_REMEDIATION_BATCH` (50) every `API_MODE_REMEDIATION_TICK_MS` (2 s). The backlog is visible on _Coverage_ (pending count and oldest age) and in `GET /api-mode/overview` → `remediation.backlog`:

```sql
SELECT a.api_connection_id, COUNT(*) pending, MIN(a.next_attempt_at) oldest_due, MAX(c.throttled_until) throttled_until
FROM api_remediation_actions a JOIN api_mode_connections c ON c.id = a.api_connection_id
WHERE a.status IN ('pending', 'in_progress') GROUP BY a.api_connection_id ORDER BY pending DESC LIMIT 20;
```

A large first-day backlog after enabling a big tenant drains at the budget rate; lowering other traffic (feeds poll interval) or raising the family budget within the provider's limits is the lever, not more replicas.

### Restoring and releasing

- **A quarantine-folder, Junk or soft-delete action:** release the mailbox entry from _Quarantine_ (button **Restore to inbox**) or from _Mailbox protection_ → Detections → **Restore** (which delegates to the same release and needs `quarantine:release` too). The quarantine rules apply: a hard-blocked message needs a second approver (or is refused when the tenant disallows hard-block releases), end users can self-release within their settings. The `remediate` role moves the message back to the **Inbox** (never the original folder) and removes the gateway tag; the entry becomes `released`, the release log `restored`. Details and failure handling: [quarantine runbook](quarantine.md#mailbox-located-entries-step-api-2).
- **A tag:** Detections → **Remove tag** (`POST /api-mode/detections/{id}/restore` queues `remove_tag`).
- **Manual remediation:** Detections → **Remediate…** (`POST /api-mode/detections/{id}/remediate`, `remediation:write`; quarantine folder, Junk, tag or soft delete; never hard delete). Works for any scanned copy, also hybrid copies and clean ones (an admin decision, audited `api_mode.remediation_requested`).
- **After a restore** the copy's generation increases, so remediating it again is a new action (a new entry), not a collision with the old one.
- **Hard deletes cannot be restored** (`409 api_mode_restore_not_possible`).

### Hard delete (platform setting)

`API_MODE_HARD_DELETE_ENABLED` (default **false**, read by the api and the mailbox-worker) is a **platform** setting, not a tenant one. While false, a policy with a `hard_delete` rule is refused (`422 api_mode_hard_delete_disabled`), pending hard deletes are cancelled when claimed, and the portal does not offer the action. Even when true, hard delete is only executed for an explicit tenant rule: never in a default or preset, never manual, never from the assistant. On Microsoft 365 it calls `permanentDelete` (irreversible, not even in Recoverable Items). Turn it on only on written customer request and restart the api and mailbox-workers.

### Gmail limitations

- `gmail.modify` (the consented scope, ADR-0099) cannot delete permanently: a Gmail `hard_delete` moves the message to Trash (recoverable for 30 days) and records `hard_delete_unsupported_provider`.
- The quarantine "folder" is a label hidden from the label list and message list (`labelHide` / `hide`), but users can still find the message by searching (for example `label:` or `in:anywhere`). Tell customers so; P1 moves only high-confidence threats.
- Restoring adds `INBOX` and removes `SPAM` and the gateway labels (and untrashes); labels the user added meanwhile stay.

### ApiModeRemediationFailing

More than 20 % of the remediation actions of a provider completed in 15 minutes failed. Group the failures by `reason_code` (query under [Failures](#failures)): `mailbox_access_revoked` on one connection → the customer withdrew consent (health check `mailbox_access.grant` also fails; contact them); `provider_forbidden` → permission or RBAC scope; `provider_unavailable` across tenants → a provider incident (watch the status page; retry the failed rows afterwards); `message_not_found` dominating → journal copies for mailboxes the grant cannot see. Detected threats stay in the mailboxes while this fires. Connection-level check: `remediation.failures_1h` (warn > `API_MODE_REMEDIATION_FAILURE_WARN_PERCENT` 10 %, fail > `…_FAIL_PERCENT` 50 % with ≥ 5 attempts).

### ApiModeRemediationBacklog

More than 500 pending actions, or the oldest pending older than 1 h, for 15 minutes (`api_mode_remediation_backlog`, `api_mode_remediation_oldest_pending_seconds`). Run the backlog query: rows with `throttled_until` in the future → throttling (see above); policy rows of a **paused** connection wait by design (the pause has its own warning); otherwise check that `remediate` runs on enough replicas (`MAILBOX_WORKER_ROLES`) and their logs. Connection-level check: `remediation.backlog` (warn 15 min, fail 60 min).

### ApiModeRemediationStalled

Actions are pending and none succeeded for 30 minutes (critical). Check: is any mailbox-worker running the `remediate` role and ready (`GET :3087/health/ready`)? Are claims progressing (`api_mode_remediation_attempts_total{outcome}`)? Is every connection throttled (`throttled_until`)? Can the worker reach the provider endpoints (egress, DNS) and the writer? Restarting a replica is safe: leases expire after `API_MODE_REMEDIATION_LEASE_SECONDS` (120) and another replica re-claims the row; the provider state is re-read before acting, so nothing is applied twice.

### Health checks of remediation

| Check                     | Warns / fails when                                                                            | Action                                                  |
| ------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `remediation.failures_1h` | failed / (succeeded + failed) in the last hour > 10 % (warn) / 50 % (fail), with ≥ 5 attempts | [ApiModeRemediationFailing](#apimoderemediationfailing) |
| `remediation.backlog`     | oldest pending policy/admin/release action older than 15 min (warn) / 60 min (fail)           | [ApiModeRemediationBacklog](#apimoderemediationbacklog) |
| `remediation.access`      | the effective policy is `enforce` for a domain of the connection but no active mailbox grant  | Grant mailbox access, or set the policy to detect-only  |
| `remediation.paused`      | remediation is paused on the connection                                                       | Resume when the reason for the pause is resolved        |

Transitions use the same audit row and `api_mode_unhealthy` alert as the other checks. Metrics (job `mailbox-worker`): `api_mode_remediations_total{provider,action,result}`, `api_mode_remediation_latency_seconds{provider}`, `api_mode_remediation_backlog{provider}`, `api_mode_remediation_oldest_pending_seconds{provider}`, `api_mode_remediation_attempts_total{provider,outcome}`; hourly counters `api_mode_counters.remediation_*` / `restores_*`.

## Local stack and tests

The idp-simulator (Compose profile `smtp-test`) serves the Graph mail, Gmail and Directory endpoints and pushes change notifications to `http://api:3000`; tokens come from 8.2's provider-fake. The stack suite `tests/integration/api-mode.test.ts` covers the nine §9.6 cases (journal detect mode, grant and inventory, notify feeds, GTUBE/EICAR verdicts, dedupe both orders, Gmail, throttling, revocation with the alert e-mail, mode changes and MX conflict, the overview) with synthetic `it-apimode-*` organizations; run it after `SMTP_ADAPTER_HOST=smtp-adapter docker compose up -d --no-deps --force-recreate postfix postfix-outbound` with the `apps` and `smtp-test` profiles up. The step API-2 stack suite `tests/integration/api-mode-remediation.test.ts` (organizations `it-apirem-*`) covers the §9.6 remediation cases: P1 quarantine-folder move of an EICAR journal copy and its mailbox entry, restore through an approved release, tag and tag removal, detect-only, the hybrid `inline_authority` skip, a `429 Retry-After` on the move, the Gmail Junk move with an end-user self-release, a revoked grant with the alert e-mail, and the overview block; the simulator's `GET /admin/mailboxes/{user}/messages/{id}` shows where a message is. Nothing in the local stack reaches Microsoft, Google or the Internet.
