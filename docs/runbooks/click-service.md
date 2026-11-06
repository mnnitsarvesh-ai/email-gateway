# Runbook: click-service (time-of-click protection)

Step 4.3 U14 ([design](../plan/steps/11-url-protection.md), [ADR-0030](../architecture/adr/0030-url-rewriting-and-click-tokens.md), [ADR-0031](../architecture/adr/0031-time-of-click-service.md), deployment: [url-protection.md](../deployment/url-protection.md)). The URL engine rewrites links in delivered mail to `<URL_CLICK_BASE_URL>/c/<token>`; the click-service verifies the token, re-checks the stored URL and redirects (302), warns (interstitial) or blocks (403). Every alert of `infrastructure/monitoring/rules/click-service.rules.yml` links a section of this page. Scan-time findings are in [url-scanning.md](url-scanning.md); the browser worker in [url-browser-worker.md](url-browser-worker.md).

**Rules that hold in every procedure below:**

- **Never an open redirect.** The service redirects only to `message_urls.url` of a token whose MAC it verified, re-parsed as http(s). Never add a "redirect to this URL" workaround, a query parameter or an allow-all switch.
- **Tenant only from a verified token.** The organization, message, `received_at` and URL sequence come from the token's MAC-checked claims; every row is read with them and echo-checked.
- **Never clean by accident.** Anything not answered within `CLICK_RECHECK_BUDGET_MS` (reputation, chain, stored results) makes the verdict at most `unknown` (tenant policy `click.unknown`, default warn). The database being down is a 503 page, never a blind redirect.
- **No URLs, tokens or IP addresses in logs or tickets.** Logs carry ids, decision and verdict; the client is stored only as a `/24` / `/48` network (`CLICK_STORE_CLIENT_NETWORK`). Investigate with the reference id.
- **Token keys are secrets** (Kubernetes Secret `email-gateway-url-token-keys`, mounted only by the click-service and `email-worker-url`). Never paste them, never log them, never put them in the shared ConfigMap.

## Contents

- [How a click is decided](#how-a-click-is-decided) · [Listeners and endpoints](#listeners-and-endpoints) · [Series](#series)
- Alerts: [ClickServiceDown](#clickservicedown) · [ClickServiceErrorsHigh](#clickserviceerrorshigh) · [ClickLatencyHigh](#clicklatencyhigh) · [ClickInvalidTokensSpike](#clickinvalidtokensspike) · [ClickEventWriteFailures](#clickeventwritefailures)
- Procedures: [availability](#availability) · [token key rotation](#token-key-rotation) · [rate limits](#rate-limits) · [investigating a click by reference id](#investigating-a-click-by-reference-id) · [false blocks and warn complaints](#false-blocks-and-warn-complaints) · [checking the alert rules](#checking-the-alert-rules)

## How a click is decided

`GET /c/:token` (and `/c/:token/continue?n=<nonce>` from the warn page):

1. **Rate limits** (Redis fixed windows, `eg:click:rl:v1:*`): per client `/24`/`/48` (`CLICK_RATE_LIMIT_IP_PER_MINUTE`), per token (`…_TOKEN_PER_MINUTE`), invalid tokens per network (`…_INVALID_PER_MINUTE`) → 429. Redis down → limits fail **open** (counted `click_rate_limiter_errors_total`), never the decision.
2. **Token** (U12): length/alphabet, version, key id, constant-time MAC, expiry. Invalid → 404 "link not valid" without any database access (`click_token_invalid_total{reason}`). Expired → 410 and an `expired` event.
3. **Lookup** `message_urls` with the claims (echo-checked; one retry on a shifted read, then 503). Missing → 404 and a `not_found` event.
4. **Live settings** `scan_engine_settings` (engine `url`) through `resolveUrlSettings`; an override that no longer validates falls back to the platform settings (warning log `invalid url settings override`).
5. **Recheck** within `CLICK_RECHECK_BUDGET_MS`: latest `url_scan_results` (lookalike, stored fetch), latest finished `url_dynamic_inspections`, fresh reputation (local feed uncached; dnsbl/rdap through the shared HMAC cache) of the URL and of the public addresses its host resolves to, and the redirect chain of **every** URL that may be fetched (not truncated) through the guarded fetcher (chain cache; a clean chain is reused for at most `URL_CACHE_CLEAN_TTL_SECONDS`): its final URL, later hop hosts and their addresses go through reputation, and a final host that differs gets lookalike detection merged with the stored findings. No readable scan result → lookalike recomputed with the tenant's active domains. Mapped with `url-map/1`. Because every click fetches the destination first, a destination that is unreachable, answers 5xx, has a certificate the fetcher does not trust or is slower than the budget is `unknown` (`url.fetch_*`) and follows `click.unknown` (default warn, continue allowed); one-time links are requested twice (by the service, then by the browser). Incoming `/c/` requests are never traced (`startTracing(…, { untracedIncomingPaths: ['/c/'] })`), and the fetcher suppresses tracing, so neither tokens, nonces nor destination paths reach the OTLP collector.
6. **Decide**: clean → 302; malicious → 403 block page with a **reference id**; suspicious/unknown → tenant `click.suspicious` / `click.unknown` (warn page with the destination's registrable domain and, if `click.allowContinue`, a continue link signed with a 10-minute nonce).
7. **Log**: one `url_click_events` row + one `mail.url.clicked.v1` outbox row in one transaction (`CLICK_DB_TX_TIMEOUT_MS`, maxWait 10 s); the response waits at most `CLICK_EVENT_WRITE_WAIT_MS`; above `CLICK_EVENT_MAX_PENDING` in-flight writes, events are dropped and counted.

## Listeners and endpoints

| Port                    | Paths                                                                              | Exposure                           |
| ----------------------- | ---------------------------------------------------------------------------------- | ---------------------------------- |
| `CLICK_HTTP_PORT` 3080  | `GET /c/:token`, `GET /c/:token/continue`, `GET /static/click.css`                 | Ingress `protect.<domain>` (TLS)   |
| `CLICK_ADMIN_PORT` 3081 | `/health/live`, `/health/ready` (`mysql` via `gateway_click`, `redis`), `/metrics` | kubelet probes and Prometheus only |

Every public response (including 404/429/503) carries the U14 headers: the CSP `default-src 'none'; style-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'`, `Referrer-Policy: no-referrer`, `nosniff`, `X-Frame-Options: DENY`, COOP/CORP `same-origin`, a deny-all `Permissions-Policy`, `Cache-Control: no-store`, HSTS in production, no `X-Powered-By`. Pages contain no JavaScript and no tenant data.

Locally: `docker compose --profile apps up -d click-service` (`127.0.0.1:${CLICK_SERVICE_HOST_PORT}` / `${CLICK_SERVICE_ADMIN_HOST_PORT}`), or host-run `pnpm --filter @email-gateway/click-service dev` (reads `../../.env`).

## Series

`click_requests_total{decision}` (`allowed`, `warned`, `blocked`, `continued`, `expired`, `invalid`, `not_found`, `rate_limited`, `unavailable`), `click_request_duration_seconds{decision}`, `click_token_invalid_total{reason}`, `click_events_total{result}` (`written`, `error`, `dropped`), `click_events_pending`, `click_recheck_total{part,result}` (parts `scan_result`, `dynamic`, `reputation`, `chain`, `settings`; results `ok`, `error`, `timeout`, `skipped`), `click_rate_limiter_errors_total`, and with `component="click"`: `url_fetch_total`, `url_fetch_duration_seconds`, `url_fetch_blocked_total{reason}`, plus `url_reputation_lookups_total{provider,result}`, `url_reputation_duration_seconds`, `url_provider_breaker_state{provider}`, `url_cache_total{cache,result}`.

## ClickServiceDown

A replica stopped answering its admin port. Check `kubectl -n email-gateway get pods -l app.kubernetes.io/name=click-service`, events and logs (`click-service failed to start` names the error class; a `ConfigValidationError` names the offending keys). Startup needs MySQL (the `gateway_click` account) and Redis; a missing/rotated `email-gateway-click-db` Secret or a token key file that does not exist stops startup. With all replicas down every rewritten link fails: restore at least one replica first (roll back the last deploy if it caused it), then investigate. See [availability](#availability).

## ClickServiceErrorsHigh

More than 2 % of clicks answered 503. The service could not read `message_urls` or `scan_engine_settings`:

- **Writer down / failover:** `/health/ready` shows `mysql` failing. Clicks recover by themselves when the writer is back.
- **Grants missing** (after a fresh database or a restored snapshot): `gateway_click` needs SELECT on `message_urls`, `url_scan_results`, `url_dynamic_inspections`, `scan_engine_settings`, `threat_indicators`, `domains` and INSERT on `url_click_events`, `message_outbox` (`infrastructure/mysql/init/01-users.sh`; Compose `mysql-grants`). Logs show `click lookup failed` with `errCode` (e.g. `P2010` with MySQL 1142).
- **Shifted reads** (`inconsistent read; retrying once` warnings): the Prisma wrong-read defect after a database stall (4.2 §6). The retry absorbs single cases; a steady rate means the pool keeps poisoned connections: restart the replicas one by one.

## ClickLatencyHigh

p95 above 1.5 s. The recheck budget bounds a click (`CLICK_RECHECK_BUDGET_MS`, default 2.5 s): look at `click_recheck_total{result="timeout"}` by part. `chain` timeouts → the egress proxy or target sites are slow (`url_fetch_duration_seconds{component="click"}`); `reputation` → a provider or the resolver (`url_reputation_duration_seconds`, breaker state); `scan_result`/`dynamic`/`settings` → MySQL. Clicks that hit the budget end `unknown` and follow `click.unknown`. Lowering the budget trades latency for more `unknown` warnings.

## ClickInvalidTokensSpike

More than 5 invalid tokens per second. By `reason`: `malformed`/`bad_mac` → scanning or guessing (the invalid-token limit per network answers 429 after `CLICK_RATE_LIMIT_INVALID_PER_MINUTE`; add a WAF rule if one network dominates — the Ingress logs have the client address, the service does not); `unknown_kid` → a key id no longer configured: a rotation removed the previous key while its tokens are still in mailboxes (see [token key rotation](#token-key-rotation); restore the previous slot); `bad_version` → a client mangles links (mail filters that rewrite URLs again).

## ClickEventWriteFailures

Clicks were answered but their event was not written: `result="error"` (the transaction failed: MySQL, grants, partition missing for the current month — `pnpm db:partitions apply` / the `db-maintenance` CronJob), `result="dropped"` (more than `CLICK_EVENT_MAX_PENDING` writes in flight: the writer is slow; `click_events_pending` shows the backlog). Dropped events are lost by design (logging never blocks a click); the outbox relay delivers `mail.url.clicked.v1` only for written events.

## Availability

- Base: 3 replicas spread over zones, PDB `minAvailable: 2`, HPA on CPU and `click_requests_per_second` (prometheus-adapter), rolling update `maxUnavailable: 0`.
- The service is stateless; its only hard dependency for a decision is MySQL (reads). Redis down → rate limits fail open and the cache is bypassed (more provider lookups, slower clicks). Egress proxy down → chain rechecks fail → affected clicks `unknown` (warn by default).
- Planned database maintenance: clicks answer 503 during the outage. There is no degraded "redirect anyway" mode on purpose.
- The service has no RabbitMQ dependency: click events reach the broker through the outbox relay.

## Token key rotation

Keys: `URL_TOKEN_KEY_CURRENT` + `URL_TOKEN_KEY_CURRENT_ID` (signs, at the URL engine) and the optional `URL_TOKEN_KEY_PREVIOUS` + `_ID` (verification only, at the click-service). Both deployments read Secret `email-gateway-url-token-keys` (keys `current`, `current-id`, `previous`, `previous-id`). Tokens live up to the tenant's `rewrite.expiryDays` ≤ `URL_TOKEN_MAX_EXPIRY_DAYS` (default **90 days**).

1. Generate a new key: 32 random bytes as 64 hex characters (`openssl rand -hex 32`) and a new id (1..255, different from the current id; increment, wrap 255 → 1 skipping the current one). Never print it in a shared terminal session.
2. Update the Secret: `previous` ← old `current`, `previous-id` ← old `current-id`, `current` ← new key, `current-id` ← new id.
3. Roll the **click-service first** (it now verifies both ids), then `email-worker-url` (starts signing with the new key). Order matters: a token signed with a key the click-service does not know yet is `unknown_kid` (404).
4. Watch `click_token_invalid_total{reason="unknown_kid"}`: it must stay flat.
5. **The 90-day rule:** keep the previous slot for at least `URL_TOKEN_MAX_EXPIRY_DAYS` days after step 3 (tokens signed with the old key until then are still valid). Only then remove `previous`/`previous-id` from the Secret and roll the click-service. Removing it earlier breaks every link signed with the old key (404 "link not valid").
6. Compromise: rotate at once and remove the old key immediately; links signed with it stop working (accepted cost). Record the incident.

Locally (`.env`): the same two slots; `docker compose up -d --force-recreate click-service email-worker`.

## Rate limits

Fixed one-minute windows in Redis, keys `eg:click:rl:v1:ip:<network>:<window>`, `…:tok:<sha256(token) prefix>:<window>`, `…:inv:<network>:<window>` (TTL 60 s). The client network comes from `CLICK_TRUST_PROXY` reverse-proxy hops (`X-Forwarded-For`): set it to the number of proxies in front of the pods (ingress controller = 1; +1 per CDN/WAF layer); a wrong value either trusts spoofed headers (too high) or limits the ingress controller itself (too low: every client shares one network). A corporate NAT behind one `/24` may hit `CLICK_RATE_LIMIT_IP_PER_MINUTE` during a mass mailing: raise it per environment. To lift a limit now: `redis-cli --scan --pattern 'eg:click:rl:v1:ip:<network>:*' | xargs redis-cli unlink`.

## Investigating a click by reference id

The block page shows the click's reference id (`url_click_events.public_id`, = `clickId` of `mail.url.clicked.v1`). On the **replica**:

```sql
-- The click (organization, message, decision, verdict, reasons, what was re-checked).
SELECT id, clicked_at, organization_id, message_id, message_received_at, url_seq, decision,
       verdict, reason_codes, recheck, token_kid, client_network, duration_ms
FROM url_click_events
WHERE public_id = ?;

-- The URL and its scan-time results (one organization; the URL is internal data, do not paste it
-- into tickets: use url_sha256).
SELECT u.url_sha256, u.host, u.registrable_domain, u.flags, r.scan_id, r.verdict, r.reason_codes,
       r.reputation, r.lookalike, r.fetch_status, r.final_host
FROM message_urls u
LEFT JOIN url_scan_results r
  ON r.message_id = u.message_id AND r.received_at = u.received_at AND r.url_seq = u.url_seq
WHERE u.organization_id = ? AND u.message_id = ? AND u.received_at = ? AND u.url_seq = ?
ORDER BY r.scan_id DESC;
```

`url_click_events` is partitioned by `clicked_at`: add `AND clicked_at BETWEEN …` when the date is known. The tenant sees the same click in the scans read API (`clicks: { total, lastDecision, lastAt }`).

## False blocks and warn complaints

1. Find the click (reference id above) and read `reason_codes`.
2. **Platform feed** (`url.feed_malicious`/`url.feed_suspicious`): check the indicator (`GET /api/v1/platform/threat-indicators?value=…`); remove a wrong one with `DELETE …?reason=` (audited). Effective on the next click (the feed is never cached).
3. **DNSBL** (`url.dnsbl_*`): third-party data; answers are cached up to `URL_CACHE_MALICIOUS_TTL_SECONDS`. Delist with the provider; flush the cached answer (see [url-scanning.md](url-scanning.md) "cache flush", keys `eg:url:rep:v1:dnsbl:*`).
4. **Tenant lists**: `url.tenant_blocked` → the tenant's own `blockedDomains`. Lookalike / structure / landing findings (`url.lookalike_*`, `url.credential_form`, `url.redirect_*`, …) → the tenant may add the domain to `allowedDomains` (`PUT /api/v1/scan-settings/url`, audited). `allowedDomains` never overrides the feed or the DNSBL malware/phishing answers (M1/M2).
5. **`unknown`** (`url.reputation_unavailable`, `url.fetch_*`): an outage or the budget, not a finding; the tenant may set `click.unknown=allow` (trading safety for convenience) — explain the trade-off first.
6. Never "fix" a decision by editing `url_scan_results` or `url_click_events`.

## Checking the alert rules

```sh
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 check rules /m/rules/click-service.rules.yml
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 test rules /m/tests/click-service.rules.test.yml
```
