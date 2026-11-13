# Runbook: API rate limits, idempotency, cursors and reports

Step 6.1 ([design](../plan/steps/18-rest-api.md), [ADR-0051](../architecture/adr/0051-pagination-cursor-filtering-sorting.md), [ADR-0052](../architecture/adr/0052-rate-limiting-and-idempotency.md), [ADR-0053](../architecture/adr/0053-public-internal-api-boundary.md), [API guide](../api/README.md#rate-limits)). Everything here runs in the **api** only: the global rate limiter (Redis), the Idempotency-Key store (`api_idempotency_keys`, writer), the signed v1 list cursors (`API_CURSOR_KEY`) and the reports (replica, Redis cache).

Step 7.1 ([design](../plan/steps/20-admin-portal.md) §3.3, §3.4, [ADR-0060](../architecture/adr/0060-portal-ingress-and-trusted-client-ip-forwarding.md)) adds the delivery, processing and top-domains reports and the trusted client-IP forwarder of the admin portal.

- Alerts: [ApiHighServerErrorRatio](#apihighservererrorratio) · [ApiRateLimitStoreErrors](#apiratelimitstoreerrors) · [ApiReportTimeouts](#apireporttimeouts) · [ApiTrustedForwarderRejected](#apitrustedforwarderrejected)
- Procedures: [429 storms](#429-storms) · [tenant limit overrides](#tenant-limit-overrides) · [Redis down](#redis-down-503-on-every-authenticated-route) · [report timeouts](#apireporttimeouts) · [step 7.1 reports](#step-71-reports-delivery-processing-top-domains) · [trusted forwarder](#trusted-client-ip-forwarder-admin-portal) · [cursor key rotation](#cursor-key-rotation) · [idempotency in-progress rows](#idempotency-in-progress-rows) · [legacy warn switch](#legacy-idempotency-warn-switch)

Every response carries `X-Request-Id`; ask the client for it (or the error body's `requestId`): it finds the request's log lines (`requestId` field) and its audit rows (`audit_logs.metadata.requestId`).

## Metrics

| Series (api `/metrics`, job `api`)                                                                                   | Meaning                                                                                                 |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `api_http_requests_total{method,route,status_class}`                                                                 | Requests by route template (`unmatched` for unknown paths) and `2xx`/`4xx`/`5xx`                        |
| `api_http_request_duration_seconds{method,route}`                                                                    | Latency histogram                                                                                       |
| `api_rate_limited_total{scope}`                                                                                      | `429`s by scope: `principal`, `tenant`, `sensitive`, `expensive`, `route`                               |
| `api_rate_limit_store_errors_total`                                                                                  | Redis failures of the limiter (each answered `503`)                                                     |
| `api_idempotency_total{outcome}`                                                                                     | `stored`, `replayed`, `reused` (422), `in_progress` (409), `missing_legacy` (warn mode without a key)   |
| `api_cursor_rejected_total`                                                                                          | v1 cursors refused (`400 cursor_invalid`)                                                               |
| `api_list_scan_budget_exhausted_total{resource}`                                                                     | v1 list pages that ended short at the scan budget                                                       |
| `api_report_duration_seconds{report}`, `api_report_cache_total{report,outcome}`, `api_report_timeouts_total{report}` | Report computations (cache misses), cache hits/misses/errors, `503 report_timeout`                      |
| `api_trusted_forwarder_total{outcome}`                                                                               | Step 7.1: requests with the portal's `X-EG-*` headers: `accepted`, `rejected`, `invalid_ip`, `disabled` |

No series carries a tenant, principal, address or id label. Which tenant is affected is in the logs (`organizationId` of the request context) and the audit rows, never in Prometheus.

## 429 storms

1. Which limit: `sum by (scope) (rate(api_rate_limited_total[5m]))`.
   - `tenant`: one organization exceeds its `api_requests_per_minute` (all its users and keys together). Find it in the logs (`code: rate_limited`, `scope: tenant`) or ask the customer for a `requestId`. Usually a runaway integration with an API key: identify the key (`principal` in the log context), ask the customer to back off (`Retry-After`), or revoke the key (`DELETE /api/v1/api-keys/{id}`) if it is abusive. Raise the limit only as described [below](#tenant-limit-overrides).
   - `principal`: one user or key exceeds `API_RATE_PRINCIPAL_PER_MINUTE` (600). Same procedure; the tenant's other principals are unaffected.
   - `sensitive` / `expensive`: the class buckets (`API_RATE_SENSITIVE_PER_MINUTE` 30, `API_RATE_EXPENSIVE_PER_MINUTE` 60 per principal; the admin dashboard spends 5 per load). A dashboard polling reports too often hits `expensive`: reports are cached for `REPORTS_CACHE_TTL_SECONDS`, polling faster gains nothing.
   - `route`: a route-specific limit (authentication per IP and account, BEC feedback, DLP tests, domain checks, quarantine bulk/preview/download). These are deliberate and unchanged by 6.1.
2. The limiter counts denied requests too (it runs before the permission check): a client retrying `403`s in a loop also exhausts its budget.
3. Windows are fixed 60 s windows (`RateLimit-Reset` tells the client when the current one ends). There is no manual reset other than waiting for the window or deleting the Redis key (`rl:api:t:<organizationId>`, `rl:api:p:<principal>`; never needed in practice).

## Tenant limit overrides

The tenant limit is `organization_limits.api_requests_per_minute` (plan defaults 60 / 300 / 1 200 / 3 000), changed only by platform staff through the organization catalog (`platform:organizations`, audited):

```bash
# Set an override (source "override"); value 0 or anything below the minimum is clamped.
curl -s -X PUT "$API/api/v1/organizations/$ORG_ID/limits/api_requests_per_minute" \
  -H "Authorization: Bearer $PLATFORM_TOKEN" -H 'Content-Type: application/json' -d '{"value": 6000}'
# Back to the plan value.
curl -s -X DELETE "$API/api/v1/organizations/$ORG_ID/limits/api_requests_per_minute" \
  -H "Authorization: Bearer $PLATFORM_TOKEN"
```

- The effective limit is **clamped** to `[API_RATE_TENANT_MIN_PER_MINUTE, API_RATE_TENANT_MAX_PER_MINUTE]` (10, 10 000): an override above the maximum gives the maximum, not "unlimited". Raising the clamp is a configuration change of the api (and a capacity decision), not a tenant setting.
- Without a row the api uses `API_RATE_TENANT_DEFAULT_PER_MINUTE` (300).
- The value is read from the **replica** and cached in each api process for `API_RATE_LIMIT_CACHE_SECONDS` (60): a change applies within about a minute plus replica lag, per pod. A failed lookup uses the default for at most 5 s (logged), never "unlimited".
- Tenants cannot change their own limit; `GET /api/v1/billing/plan` and `GET /api/v1/usage` show it with its source.

## Redis down: 503 on every authenticated route

The limiter **fails closed**: when Redis does not answer, every authenticated request is `503 service_unavailable` and `api_rate_limit_store_errors_total` grows (alert [ApiRateLimitStoreErrors](#apiratelimitstoreerrors)). Authentication itself also depends on Redis (session deny-lists), so the effect is the same as a Redis outage before 6.1. Public routes with per-IP limits fail closed the same way.

1. `GET /health/ready` of an api pod lists `redis` as failing.
2. Check the Redis endpoint (`REDIS_URL`), memory (`noeviction`: a full Redis refuses writes), connection count and network policy. Locally: `docker compose ps redis`, `docker compose logs redis`.
3. Nothing needs to be repaired after Redis returns: counters are rebuilt from zero (a short burst above the limits is possible in the first window), report caches refill on demand.

Do not switch the limiter off to "keep the API up": there is no such switch by design (ADR-0052).

## Idempotency in-progress rows

A legacy sensitive route (interceptor, `x-eg-idempotency: legacy`) first writes a `pending` reservation, then runs the handler, then stores the 2xx response (`completed`) or deletes the reservation on an error. A client that repeats the request while the first one runs gets `409 idempotency_request_in_progress` with `Retry-After`.

A process crash (OOM, kill) between the handler and the stored response leaves the `pending` row until `expires_at` (`API_IDEMPOTENCY_PENDING_TTL_SECONDS`, 300 s); retries with the same key get `409` until then, and a retry after the expiry **may run the effect again** (the documented at-most-once window). Inspect, on the writer:

```sql
SELECT id, operation, resource_id, principal, state, created_at, expires_at
FROM api_idempotency_keys
WHERE organization_id = <org id> AND state = 'pending'
ORDER BY created_at DESC LIMIT 50;
```

- Before telling the client to retry, check whether the effect happened (the resource itself, or `audit_logs` rows with the request's `requestId`/`correlationId`). If it did, the client should not repeat it with a new key.
- Do not delete pending rows by hand unless the effect is known not to have happened; deleting one re-opens the key immediately. Expired rows (pending and completed) are purged by `pnpm db:partitions apply` one day after expiry.
- The transactional routes (`x-eg-idempotency: required`: rescan, release, quarantine, suppressions) never leave pending rows: effect, audit and stored response commit together.
- `422 idempotency_key_reused`: the client reused a key for a different request (body, path, operation or caller). This is a client bug; the key cannot be reused for 24 h.

## Legacy idempotency warn switch

`API_IDEMPOTENCY_LEGACY_MODE` (`enforce` by default) decides what the 22 legacy sensitive routes do without an `Idempotency-Key`: `enforce` → `400 idempotency_key_required`; `warn` → processed as before 6.1 with `Deprecation: true` and a `Link rel="deprecation"` header, counted in `api_idempotency_total{outcome="missing_legacy"}`.

- Use `warn` only as a transition for a client that cannot send keys yet (set it in the api's environment, restart the api pods). It affects every tenant. Watch `missing_legacy` and return to `enforce` once it is zero.
- The transactional routes (quarantine, rescan/release, suppressions) always require a key, whatever the switch says.

## Cursor key rotation

`API_CURSOR_KEY` (64 hex) signs the v1 list cursors; the api is its only holder (Kubernetes Secret `email-gateway-api-cursor-key`, key `key`, read through `API_CURSOR_KEY_FILE`). Cursors are short-lived (`API_CURSOR_TTL_SECONDS`, 24 h), so a rotation is cheap:

1. Generate a new key: `openssl rand -hex 32`.
2. Put the **current** key into `API_CURSOR_KEY_PREVIOUS` (Secret key `previous-key`, mounted as an optional environment variable) and the new key into `API_CURSOR_KEY`; roll the api pods.
3. After one `API_CURSOR_TTL_SECONDS`, remove `previous-key` and roll again.

Rotating without step 2 makes every outstanding v1 cursor `400 cursor_invalid` (`api_cursor_rejected_total` jumps); clients restart their list from the first page, nothing else breaks. A suspected key leak is handled the same way, without keeping the previous key: a leaked key lets a caller forge cursors only for their own organization (the tenant scope is re-applied on every page). The legacy v0 cursors are unsigned and unaffected.

## Alerts

### ApiHighServerErrorRatio

More than 5 % of the api's requests answered `5xx` for 10 minutes (with at least 1 request per second). Break down: `sum by (route) (rate(api_http_requests_total{status_class="5xx"}[10m]))`.

- `503` on every route: the rate-limit store (Redis, [above](#redis-down-503-on-every-authenticated-route)) or the MySQL writer/replica is unreachable; `GET /health/ready` names the dependency.
- `503` on report routes only: report timeouts ([ApiReportTimeouts](#apireporttimeouts)).
- `503 inconsistent_read`: a repository echo check refused a row that did not belong to the query (Prisma wrong-read mitigation, step 4.2 §6); look for `InconsistentReadError` in the logs and the writer's health; never served.
- `500`: a programming error; the log line with the `requestId` has the stack. A `500` on a legacy sensitive route that names a credential-like key means a response DTO grew a field matching the audit credential pattern and the interceptor refused to store it (by design); fix the DTO or its verified `publicFields`.

### ApiRateLimitStoreErrors

The limiter could not read or increment its counters for 5 minutes: authenticated requests are `503`. Follow [Redis down](#redis-down-503-on-every-authenticated-route).

### ApiReportTimeouts

More than 5 report queries in 15 minutes were stopped by `MAX_EXECUTION_TIME` (`REPORTS_QUERY_TIMEOUT_MS`, 10 s) and answered `503 report_timeout`. Which report: `sum by (report) (increase(api_report_timeouts_total[15m]))` (`traffic`, `threats`, `url_clicks`, `billing_usage`, and since step 7.1 `delivery`, `processing`, `top-domains`).

1. Replica health first: replication lag (`SHOW REPLICA STATUS`, the api's `mysql-reader` readiness details), CPU and I/O of the replica. Reports read only the replica; a lagging or overloaded replica slows every one.
2. The counts are index-only over their covering index; check the plan with `EXPLAIN FORMAT=JSON` of the logged query shape (`using_index: true`, pruned partitions). A missing index (failed migration) shows up as a full scan. Message reports (traffic, threats, top-domains, billing): `email_messages_org_received_dir_verdict_idx (organization_id, received_at, direction, final_verdict, final_action, domain_id)`; delivery: `email_deliveries_org_received_status_idx`; processing: `email_scans_org_received_kind_status_idx` (step 7.1 migration `admin_portal_reports`). The report SQL names them with `FORCE INDEX`: a missing index makes the statement fail (`500`), not slow.
3. Very large tenants over the full `REPORTS_MAX_RANGE_DAYS` (31) window scan tens of millions of index entries on a cold cache; ask the customer for narrower windows or `day` granularity, or raise `REPORTS_QUERY_TIMEOUT_MS` (≤ 30 000) knowing it moves load onto the replica. Long-range reporting belongs to an analytics store (not built).
4. Nothing is cached for a timed-out query; a successful one is cached per organization and normalized window for `REPORTS_CACHE_TTL_SECONDS`. A Redis failure of the cache (`api_report_cache_total{outcome="error"}`) only makes every request compute.

### ApiTrustedForwarderRejected

For 10 minutes the api received requests carrying `X-EG-Client-IP` / `X-EG-Forwarder-Token` whose token did not match `API_TRUSTED_FORWARDER_TOKEN` (`api_trusted_forwarder_total{outcome="rejected"}`). Nothing is attributed to the forged address (the socket / `HTTP_TRUST_PROXY` address is used), so this is not an outage, but follow [trusted forwarder](#trusted-client-ip-forwarder-admin-portal):

- Right after a rotation: the api and the admin portal hold different tokens. Every portal user then shares the portal pod's per-IP limits (login 20/min) and audit rows show the portal's address. Restart the workload that still has the old Secret content.
- No rotation: an internal caller sends the headers without the token (or a stale copy). The api's warn log `Trusted forwarder token rejected` names the outcome only (never a header value; it runs before the request id is minted). Narrow the source with `sum by (instance) (rate(api_trusted_forwarder_total{outcome="rejected"}[5m]))` and the cluster's network flow logs to the api pods; only the portal should send these headers.

## Step 7.1 reports (delivery, processing, top-domains)

`GET /reports/delivery`, `/reports/processing` and `/reports/top-domains` (class `expensive`, `report:read`) follow the same rules as the 6.1 reports: replica only, `MAX_EXECUTION_TIME`, cached per organization and normalized parameters in Redis (`rpt:v1:<organizationId>:<delivery|processing|top-domains>:<sha256>`, `REPORTS_CACHE_TTL_SECONDS`), `503 report_timeout` on a timeout (nothing cached), metrics with `report="delivery|processing|top-domains"`.

- **Timeouts:** delivery and processing scan one index range per window like traffic (`email_deliveries` has about 1.5 rows per message, `email_scans` one initial round per message plus rescans, filtered in the index); top-domains reads the message index once. Same procedure as [ApiReportTimeouts](#apireporttimeouts).
- **`503 inconsistent_read` on top-domains only:** a message's `domain_id` does not resolve to a domain of the same organization on the replica (or a row failed an echo check). The domain is never shown. Check the replica lag first (a domain row created moments ago may not be replicated yet), then the data: `SELECT DISTINCT m.domain_id FROM email_messages m LEFT JOIN domains d ON d.id = m.domain_id AND d.organization_id = m.organization_id WHERE m.organization_id = ? AND d.id IS NULL AND m.domain_id IS NOT NULL` (bounded by `received_at`).
- **"Why is p95 null?":** the percentile is a histogram upper bound; `null` means no sample in the window or the percentile lies above the last bound (processing 15 min, delivery 24 h). Not an error.
- **Cache:** a dashboard refresh within `REPORTS_CACHE_TTL_SECONDS` returns the same `generatedAt`; to force a recomputation for an investigation, delete the organization's keys `eg:rpt:v1:<organizationId>:*` in Redis (harmless; the next request recomputes).

## Trusted client-IP forwarder (admin portal)

The portal's BFF calls the api over the internal network with `X-EG-Client-IP` (the browser's address) and `X-EG-Forwarder-Token` (the shared secret). The api's first middleware accepts the address only with the right token and a valid IP and always strips both headers ([ADR-0060](../architecture/adr/0060-portal-ingress-and-trusted-client-ip-forwarding.md)).

- **Check:** `sum by (outcome) (rate(api_trusted_forwarder_total[5m]))`. Healthy: `accepted` while portal users are active, no `rejected`. `invalid_ip`: the portal could not determine the browser address (wrong `PORTAL_TRUST_PROXY_HOPS` behind the ingress) or sent a malformed one. `disabled`: the api has no token (empty `API_TRUSTED_FORWARDER_TOKEN`, a startup warning in production) while the portal sends the headers.
- **Symptom of a broken forwarder:** many portal users get `429` on login at once, or `login_audit_logs.ip_address` shows the portal pods' addresses.
- **Rotation of the Secret** (`email-gateway-api-trusted-forwarder`, key `token`, 32–256 characters; mounted only in `api` and `admin-portal` as `API_TRUSTED_FORWARDER_TOKEN_FILE`): (1) update the Secret with a new random value (`openssl rand -hex 24`); (2) restart **api** and **admin-portal** (`kubectl rollout restart deployment/api deployment/admin-portal -n email-gateway`). During the rollout old and new pods disagree for a moment: affected requests are `rejected` and use the portal address (shared per-IP limits for a minute or two), nothing fails. Locally: change `API_TRUSTED_FORWARDER_TOKEN` in `.env` and restart both processes / containers.
- **Leak:** a leaked token lets an internal caller choose the IP the api attributes to its requests (per-IP limits and audit IP attribution only; per-principal and per-tenant limits are unaffected). Rotate immediately as above.

## What 6.1 does not do

- No per-IP limit at the Ingress (API clients share NAT addresses); no manual "unblock" of a tenant other than a limit override.
- No signed v0 cursors (the pre-6.1 lists); no totals or offsets.
- No long-range reports (analytics store), no rollup tables; production-scale timing (1M messages per tenant and day) is not verified, only EXPLAIN plans on local volumes.
