# Runbook: webhooks and security alerts

Step 6.2 ([design](../plan/steps/19-webhooks-notifications.md), ADR-0054 event model, ADR-0055 signing and delivery, ADR-0056 security alerts, [ADR-0057](../architecture/adr/0057-idempotent-secret-bearing-routes-redacted-replay.md); deployment [webhooks.md](../deployment/webhooks.md); service [webhook-worker](../../apps/webhook-worker/README.md); alert e-mails [policy-notifications.md](policy-notifications.md)).

The **webhook-worker** has two roles. `fanout` consumes `email.webhooks` (topology v11, broker user `eg-webhook`) and projects eight internal events into public webhook events (`webhook_events`, the stored envelope), deliveries (`webhook_deliveries`, one per matching subscription) and security alert requests (`notification_alert_windows` + `notification.alert_requested.v1` outbox rows). `delivery` claims due deliveries fairly per organization and subscription, signs them (`EG-Signature`), POSTs them through the SSRF-guarded client, records each attempt (`webhook_delivery_attempts`), retries, dead-letters, auto-disables failing subscriptions, runs range replays and the leader-elected maintenance.

- Alerts: [WebhookFanoutBacklog](#webhookfanoutbacklog) · [WebhookDeliveryStalled](#webhookdeliverystalled) · [WebhookOldestDueAge](#webhookoldestdueage) · [WebhookDeadLetters](#webhookdeadletters) · [WebhookSsrfBlockedSpike](#webhookssrfblockedspike) · [WebhookFanoutErrors](#webhookfanouterrors) · [WebhookRateLimitStoreErrors](#webhookratelimitstoreerrors) · [SecurityAlertNotificationFailures](#securityalertnotificationfailures)
- Procedures: [reading a delivery](#reading-a-delivery-and-its-attempts) · [retries and Retry-After](#retries-and-retry-after) · [dead deliveries and replay](#dead-deliveries-and-replay) · [auto-disabled subscriptions](#auto-disabled-subscriptions-and-re-enabling) · [SSRF blocks](#webhookssrfblockedspike) · [fanout backlog and the unbind procedure](#webhookfanoutbacklog) · [secret rotation](#signing-secret-rotation) · [encryption-key rotation](#encryption-key-rotation-webhook_secret_encryption_key_previous) · [cache TTL](#cache-ttl-behaviour) · [metrics](#metrics)

Never paste a signing secret (`whsec_…`), a full endpoint URL (its query string may carry a receiver token) or a payload into a ticket. Logs, metrics and audit rows carry ids, codes and counts only.

## Delivery states

| `webhook_deliveries.status` | Meaning                                                                                                                                                                                                                                                                                                          | Next                                                          |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `pending`                   | due at `next_attempt_at` (a claimed delivery holds a lease: `now + total timeout + 60 s`); `next_attempt_at IS NULL` = parked while its subscription is paused (due again on resume)                                                                                                                             | `succeeded`, `failed`, `dead`, `cancelled`, `pending` (retry) |
| `succeeded`                 | the endpoint answered 2xx                                                                                                                                                                                                                                                                                        | —                                                             |
| `failed`                    | the SSRF guard refused the endpoint (`last_error = blocked:<reason>`) or the stored event expired (`event_expired`); never retried                                                                                                                                                                               | — (replayable after a fix)                                    |
| `dead`                      | retries exhausted (`WEBHOOK_MAX_ATTEMPTS`, `WEBHOOK_MAX_RETRY_AGE_HOURS`) or inserted dead by the backlog bound (`backlog_exceeded`)                                                                                                                                                                             | — (replayable)                                                |
| `cancelled`                 | the subscription is disabled or deleted (`subscription_disabled` / `subscription_deleted`, api: `cancelled:disabled` / `cancelled:deleted`), or the organization is not `active` / lacks the `webhooks` feature when the row came due (`organization_inactive` / `webhooks_not_enabled`: nothing is sent for it) | — (replayable after re-enabling)                              |

`trigger` is `event` (the fanout), `replay` (single or range replay; `replay_id` names a range replay) or `test` (`POST /webhooks/{id}/test`). `delivery_seq` is 0 for the original delivery and counts up per replay.

## Reading a delivery and its attempts

- Api: `GET /api/v1/webhooks/{webhookId}/deliveries?from=…&to=…&status=…` and `GET …/deliveries/{deliveryId}` (attempts with outcome, status, latency, sanitized response snippet, `Retry-After`, error code, signature count, and the stored envelope).
- SQL (writer; partition-prune by `event_occurred_at`):

```sql
SELECT d.public_id, d.event_id, d.event_type, d.status, d.trigger, d.delivery_seq, d.attempt_count,
       d.first_attempt_at, d.last_attempt_at, d.next_attempt_at, d.last_response_code,
       d.last_latency_ms, d.last_error, d.completed_at
FROM webhook_deliveries d
WHERE d.public_id = '<delivery id>';

SELECT attempt_no, attempted_at, outcome, http_status, latency_ms, response_snippet,
       retry_after_seconds, error_code, signature_count, next_attempt_at
FROM webhook_delivery_attempts
WHERE delivery_id = <d.id> AND delivery_event_occurred_at = '<d.event_occurred_at>'
ORDER BY attempt_no;
```

`response_snippet` is untrusted text: the first ≤ 512 characters of the response, control characters replaced, anything that looks like a secret, bearer token or long base64/hex run redacted. Response headers are never stored. `error_code` is a bounded code: `http_<status>`, a socket code (`ECONNREFUSED`, `ECONNRESET`), `timeout`, `connect_timeout`, `dns_<kind>`, a TLS code (`ERR_TLS_CERT_ALTNAME_INVALID`, `CERT_HAS_EXPIRED`, …), `header_limit`, `remote_address_mismatch`, `blocked:<reason>` or `secret_unavailable`.

The envelope sent is `webhook_events.payload_json`, byte-identical on every attempt and replay (`payload_sha256`). Receivers dedupe on `EG-Event-Id` / `Idempotency-Key` (the envelope id); `EG-Delivery-Id` is new per replay.

## Retries and Retry-After

- Retried: every non-2xx status, `redirect` (3xx is never followed; `Location` is not stored), `timeout`, `dns_error`, `connection_error`, `tls_error`, `too_large`, `secret_unavailable`. Not retried: `blocked`.
- Schedule after attempt `n`: `min(WEBHOOK_RETRY_MAX_DELAY_SECONDS, WEBHOOK_RETRY_BASE_SECONDS × 2^(n−1))` × jitter 0.8–1.2 (defaults: ≈ 30 s, 1 min, 2 min, 4 min, 8 min, 16 min, 32 min; 8 attempts).
- `Retry-After` (delta-seconds or HTTP-date) on any non-2xx: `delay = max(backoff, Retry-After)`, clamped at `WEBHOOK_RETRY_AFTER_MAX_SECONDS` (default 3 600). The attempt row keeps `retry_after_seconds`.
- A delivery older than `WEBHOOK_MAX_RETRY_AGE_HOURS` since its first attempt (default 24 h) becomes `dead` at its next failure.
- A crash during an attempt leaves the lease to expire (`next_attempt_at` = claim + total timeout + 60 s); the attempt counted (at least once). A result recorded after the row changed (cancelled, re-claimed) is dropped (`webhook_inconsistent_reads_total{read="delivery_cas"}`).

## Dead deliveries and replay

Dead deliveries are the webhook dead-letter store (kept with their monthly partition, retention 2 months). They are replayed by the tenant or support through the api, never by editing rows:

- **One delivery**: `POST /api/v1/webhooks/{webhookId}/deliveries/{deliveryId}/replay` → a new `pending` delivery (`delivery_seq + 1`, `trigger = replay`); at most `WEBHOOK_REPLAY_MAX_PER_DELIVERY` per event; the subscription must be `active`.
- **A time range**: `POST /api/v1/webhooks/{webhookId}/replays { from, to, statuses?, eventTypes? }` → a `webhook_replays` row (`queued`); the delivery role processes it in batches of 500 original deliveries (keyset cursor, resumable after a crash, idempotent), at most `WEBHOOK_REPLAY_MAX_EVENTS` matches (then `completed` with `truncated = true`). Progress: `GET …/replays/{replayId}` or

```sql
SELECT public_id, status, matched_count, created_count, truncated, error_code, cursor_occurred_at,
       started_at, completed_at
FROM webhook_replays WHERE public_id = '<replay id>';
```

A replay that finds its subscription not `active` ends `failed` with `error_code = webhook_not_active`; one whose organization is suspended, pending deletion or deleted, or lacks the `webhooks` feature, ends `failed` with `organization_inactive` / `webhooks_not_enabled`. Events that already have `WEBHOOK_REPLAY_MAX_PER_DELIVERY` replays (single or range) are skipped: they count in `matched_count`, not in `created_count` (`webhook_replay_events_skipped_total{reason="replay_limit"}`). The batch locks the subscription row like the api's single replay, so the two never race for the same `delivery_seq`. Events that occurred while a subscription was paused or disabled were never recorded for it and cannot be replayed. Poison **source** events of the fanout go to `email.dead-letter` (operator replay: `POST /api/v1/platform/dead-letters/replay`, see [rabbitmq-messaging.md](rabbitmq-messaging.md)).

## Auto-disabled subscriptions and re-enabling

A subscription is disabled by the worker when `consecutive_failures ≥ WEBHOOK_DISABLE_AFTER_FAILURES` (default 50) **and** the failure streak began at least `WEBHOOK_DISABLE_AFTER_HOURS` ago (default 24). Blocked (SSRF) attempts count; `secret_unavailable` (a platform fault) does not. In the same transaction: `status = disabled`, `disabled_reason = sustained_failure`, an `audit_logs` row (`actor_type = system`, `action = webhook.auto_disabled`, metadata `subscriptionId`, `consecutiveFailures`, `failingSince`) and one `webhook_disabled` alert request (throttled per subscription, default once a day). Pending deliveries become `cancelled` (claim or maintenance pass).

```sql
SELECT public_id, status, disabled_reason, disabled_at, consecutive_failures, failing_since,
       last_success_at, last_failure_at
FROM webhook_subscriptions WHERE public_id = '<webhook id>';
```

Re-enable only after the endpoint is fixed: `PATCH /api/v1/webhooks/{id} { status: "active", expectedRowVersion }` (audited; resets the failure counters). Then replay the dead and cancelled deliveries of the outage with a range replay (`statuses: ["dead","cancelled"]`).

## WebhookFanoutBacklog

`email.webhooks` receives ~10 internal events per message. Its policy is `work` (reject-publish at 1 000 000): when full, the broker **nacks the relay's publishes**, which stalls the outbox relay for every queue of those publishes. The warning fires at 100 000 ready messages for 10 minutes, critical at 500 000.

1. Is the fanout running and ready? Kubernetes: `kubectl -n email-gateway get deploy webhook-fanout`, `/health/ready` (mysql, rabbitmq). Compose: `docker compose ps webhook-worker`.
2. Consumers and rates: `rabbitmqctl -p email-gateway list_queues name messages_ready messages_unacknowledged consumers | grep email.webhooks`; `rate(webhook_fanout_events_total[5m])` by `result`.
3. Scale: `kubectl -n email-gateway scale deploy webhook-fanout --replicas=<n>` (each replica takes `WEBHOOK_FANOUT_PREFETCH` events). Check the writer (fanout transactions) is healthy.
4. **Unbind procedure** (last resort, before reject-publish nacks the relay; webhooks for the unbound period are lost for subscribers, alerts too): remove the eight source bindings of `email.webhooks` so the relay stops routing to it, drain, then restore them.

```bash
# As the administrator, vhost email-gateway. List the bindings first.
rabbitmqctl -p email-gateway list_bindings source_name destination_name routing_key | grep email.webhooks
# Unbind each source binding (keep retry.email.webhooks.#):
for b in "email.ingestion org.*.mail.message.received.v1" \
         "email.security org.*.mail.message.scanned.v1" \
         "email.security org.*.mail.attachment.sandbox_completed.v1" \
         "email.policy org.*.mail.policy.decided.v1" \
         "email.delivery org.*.mail.delivery.approved.v1" \
         "email.events org.*.mail.message.state_changed.v1" \
         "email.events org.*.domain.status.changed.v1" \
         "email.events org.*.domain.dns.records_changed.v1"; do
  set -- $b
  rabbitmqadmin -V email-gateway delete binding source="$1" destination=email.webhooks \
    destination_type=queue properties_key="$2"
done
# Restore: re-apply the topology (idempotent, recreates every binding of TOPOLOGY v11).
docker compose up rabbitmq-init      # Compose
node infrastructure/rabbitmq/init.mjs   # elsewhere: the same import, as for every topology change
```

Record the unbound window in the incident; tell affected tenants that events of that window were not delivered (they cannot be replayed: they were never projected).

## WebhookDeliveryStalled

Due deliveries exist (`webhook_due_backlog > 0`) but no attempt was recorded for 20 minutes. Paused subscriptions never count here: their pending deliveries are parked (`next_attempt_at IS NULL`) and the gauges exclude paused work.

1. `webhook-delivery` pods ready? Readiness checks mysql and redis.
2. `webhook_rate_limit_store_errors_total` rising → Redis is down: the loop sends nothing by design ([WebhookRateLimitStoreErrors](#webhookratelimitstoreerrors)).
3. Logs: `webhook claim failed` (lock waits on the writer), `due organizations query failed`.
4. Nothing is lost: deliveries stay `pending` and are claimed when the role recovers.

## WebhookOldestDueAge

The oldest due delivery waits more than 15 minutes past `next_attempt_at`. Causes: the replicas are saturated (`WEBHOOK_DELIVERY_CONCURRENCY` slots held by slow endpoints that time out after `WEBHOOK_HTTP_TOTAL_TIMEOUT_MS`), per-organization or per-subscription caps (`webhook_rate_limited_total{scope}`), or a large number of organizations with due work (the claimer visits at most 200 per tick, rotating through `organization_id`). Slots of crashed pods expire one lease after their reservation, whatever the traffic. Paused subscriptions are excluded from the gauge. Scale `webhook-delivery`; check `webhook_delivery_duration_seconds` by outcome for timeouts.

## WebhookDeadLetters

More than 100 deliveries became dead in an hour. Find the subscriptions:

```sql
SELECT s.public_id, COUNT(*) AS dead, MAX(d.last_error) AS last_error
FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id = d.subscription_id
WHERE d.status = 'dead' AND d.event_occurred_at >= NOW() - INTERVAL 2 HOUR
GROUP BY s.public_id ORDER BY dead DESC LIMIT 20;
```

`backlog_exceeded` means the subscription had more than `WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION` pending deliveries (a dead endpoint): new deliveries go straight to `dead` until the backlog drains. Tenants replay after fixing the endpoint.

## WebhookSsrfBlockedSpike

The guard refused more than 50 attempts in 15 minutes (`webhook_ssrf_blocked_total{reason}`). Every resolved address of an endpoint must be public (loopback, private, CGNAT, link-local, metadata `169.254.169.254` / `fd00:ec2::254`, ULA, NAT64/mapped and reserved ranges are refused; one blocked answer blocks the attempt, which defeats DNS rebinding). Blocked deliveries fail at once (`last_error = blocked:<reason>`), count toward auto-disable and **no connection is made**. Find the subscriptions with `last_error LIKE 'blocked:%'`; a tenant probing internal addresses is a security event (escalate). `port` / `scheme` reasons mean a URL outside `WEBHOOK_ALLOWED_PORTS` or not https.

## WebhookFanoutErrors

- `unsafe`: a built envelope failed the payload guard (a programming error: a public payload would have carried content). The source event was dead-lettered (`x-eg-failure-reason = webhook_payload_unsafe`); the log line names the event id, type, guard code and path. Do not replay it until the cause is fixed.
- `error`: retried failures (`InconsistentReadError` of an echo check, writer or broker outages); `webhook_inconsistent_reads_total{read}` names the read. Sustained errors dead-letter after the queue's retry policy (10 attempts, 24 h).

## WebhookRateLimitStoreErrors

The delivery loop found Redis unavailable and sent nothing (fail closed: the in-flight and rate caps cannot be enforced without it). Restore Redis; deliveries resume on the next tick. In-flight slots (`wh:slots:org:<id>`, `wh:slots:sub:<id>`, sorted sets with one member per reservation scored by its lease expiry) expire member by member one lease after the reservation, rate keys (`wh:rate:sub:<id>:<minute>`) after two minutes.

## SecurityAlertNotificationFailures

The notification-worker could not send security alert e-mails (`notification_alert_messages_total{result="failed"}`). See [policy-notifications.md](policy-notifications.md) for the relay (postfix-notify). Alert requests stay in `email.notifications` and are retried; throttle windows (`notification_alert_windows`) are not affected.

## Signing secret rotation

Tenants rotate with `POST /api/v1/webhooks/{id}/rotate-secret { overlapHours }` (0–168, default 24). During the overlap every attempt carries two `v1=` signatures (current first, then the previous secret); receivers accept any matching `v1`. A second rotation during an overlap replaces the previous secret with the one being retired. The worker caches decrypted secrets ≤ 60 s keyed by `(subscription, secret_version)`, so a rotation takes effect at the next attempt. A secret is shown once and never logged, audited, stored by idempotency or returned again.

## Encryption-key rotation (`WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS`)

`secret_ciphertext` is AES-256-GCM under `WEBHOOK_SECRET_ENCRYPTION_KEY` (api encrypts, webhook-delivery decrypts; nobody else holds it). To rotate the key:

1. Generate a new 64-hex key in the secret store; set the old one as `previous-key` and the new one as `key` of `email-gateway-webhook-secret-key` (Compose: `WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS` / `WEBHOOK_SECRET_ENCRYPTION_KEY`).
2. Roll out **webhook-delivery first, then the api** (both decrypt with either key; the api encrypts new secrets with the new key).
3. Existing ciphertexts stay decryptable through the previous key. They are re-encrypted only when a secret is rotated; keep `previous-key` until every subscription has rotated or been recreated (`secret_rotated_at` after the key change), then remove it and roll out again.

A missing or wrong key makes attempts end `secret_unavailable` (retried; `webhook_delivery_attempts_total{outcome="secret_unavailable"}`), never a log line with key material.

## Cache TTL behaviour

The fanout caches each organization's active subscriptions, the `webhooks` feature and the notification settings for `WEBHOOK_SUBSCRIPTION_CACHE_SECONDS` (default 5). A new, re-enabled or edited subscription takes effect within that TTL; an event is delivered only to subscriptions whose `created_at ≤` the event's `occurredAt` (no back-fill). Paused, disabled or deleted subscriptions stop receiving new deliveries within the TTL; deliveries already pending for a paused subscription stay pending (not sent) until it is resumed.

## Metrics

| Series                                                                             | Meaning                                                                                          |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `webhook_fanout_events_total{source_type,result}`                                  | `noop` (nothing matched, no transaction), `projected`, `duplicate`, `unsafe`, `invalid`, `error` |
| `webhook_events_created_total{type}`                                               | stored public events                                                                             |
| `webhook_deliveries_created_total{type,trigger}`                                   | deliveries inserted (`event`, `replay`)                                                          |
| `webhook_delivery_attempts_total{outcome}`                                         | attempts by outcome                                                                              |
| `webhook_delivery_duration_seconds{outcome}`                                       | attempt duration                                                                                 |
| `webhook_deliveries_dead_total`                                                    | deliveries that became dead                                                                      |
| `webhook_deliveries_cancelled_total{reason}`                                       | pending deliveries cancelled (disabled / deleted subscription)                                   |
| `webhook_subscriptions_disabled_total{reason}`                                     | automatic disables (`sustained_failure`)                                                         |
| `webhook_due_backlog`, `webhook_oldest_due_age_seconds`                            | maintenance leader gauges (0 on other replicas; use `max()`)                                     |
| `webhook_ssrf_blocked_total{reason}`                                               | guard refusals                                                                                   |
| `webhook_rate_limited_total{scope}`                                                | due deliveries left for a later tick (`organization`, `subscription`, `subscription_rate`)       |
| `webhook_rate_limit_store_errors_total`                                            | ticks without Redis (nothing sent)                                                               |
| `webhook_replays_total{result}`                                                    | range replays finished (`completed`, `truncated`, `failed`)                                      |
| `webhook_replay_events_skipped_total{reason}`                                      | range-replay matches not re-sent (`replay_limit`, `sequence_exhausted`)                          |
| `webhook_alert_requests_total{kind,result}`                                        | alert requests (`requested`, `throttled`, `disabled`)                                            |
| `webhook_inconsistent_reads_total{read}`                                           | echo-check failures and lost CAS (retried)                                                       |
| `webhook_maintenance_leader`, `webhook_maintenance_last_success_timestamp_seconds` | maintenance leadership                                                                           |
| `amqp_*`                                                                           | the fanout's queue consumer (shared messaging series)                                            |
