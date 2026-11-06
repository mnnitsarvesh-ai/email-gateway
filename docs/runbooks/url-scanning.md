# Runbook: URL scanning (extraction, reputation, fetches, rewriting, dynamic inspection)

Step 4.3 ([design](../plan/steps/11-url-protection.md), [ADR-0029](../architecture/adr/0029-url-security-engine.md), [ADR-0030](../architecture/adr/0030-url-rewriting-and-click-tokens.md), deployment: [url-protection.md](../deployment/url-protection.md)). The url engine is one engine of the [scan pipeline](scan-pipeline.md) (queue `scan.url`, ledger consumer `email-worker.scan.url`, production Deployment `email-worker-url`, `SCAN_CONSUMERS=url`). It is **required** in every round: a round whose url engine cannot decide ends `scan_failed`. The same replicas run the results consumer (`scan.url.results`, ledger `email-worker.scan.url.results`) and the pending-inspection sweeper (lock `scan:url-inspections`). Every alert of `infrastructure/monitoring/rules/url-scanning.rules.yml` links a section of this page; the generic scan alerts (`ScanEngineCircuitOpen`, `ScanRoundsFailing`, `ScanDeadlineFinalizations`, …) apply with `engine="url"` too. Time-of-click is in [click-service.md](click-service.md), the browser in [url-browser-worker.md](url-browser-worker.md).

**Rules that hold in every procedure below:**

- **Never clean by accident.** A provider error or open breaker, a fetch that was attempted and did not complete, an SSRF block, an incomplete extraction (body not stored, limits) and a cache error are never `clean`. `clean` is reachable only through rule C1 (every provider answered, every attempted fetch completed, nothing raised).
- **Never open a reported URL** from a laptop, a jump host or a cluster pod. Investigate with the stored hashes, hosts, codes and chains; fetch only through the platform (a rescan, or the browser worker). The engine's own fetcher dials only addresses the SSRF guard validated.
- **URLs are not logged.** Logs carry ids, counts, codes and 12-character hash prefixes (`url_sha256`); metrics never carry a URL or host. Do not add URLs to tickets or chat; reference `message_id`, `url_seq` and the hash prefix.
- **Engines classify, policy decides.** The url engine records verdicts and writes a rewritten copy; it never blocks or quarantines a message. The click-service decides only about clicks.
- **One door.** Rescans go through the lifecycle (api `admin_rescan`). Never edit `message_urls`, `url_scan_results`, `url_rewrites`, `url_dynamic_inspections` or `scan_engine_results` by hand.
- Read on the **replica** for investigations (or the scans read API); the writer is for the services.

## Contents

- [How a message's URLs are scanned](#how-a-messages-urls-are-scanned) · [Reading results](#reading-results) · [Series used by the alerts](#series-used-by-the-alerts)
- Alerts: [UrlEngineFailuresHigh](#urlenginefailureshigh) · [UrlScanQueueBacklog](#urlscanqueuebacklog) · [UrlReputationProviderDown](#urlreputationproviderdown) · [UrlFetchInternalTargetsSpike](#urlfetchinternaltargetsspike) · [UrlRewriteErrors](#urlrewriteerrors) · [UrlCacheErrors](#urlcacheerrors) · [UrlDynamicInspectionBacklog](#urldynamicinspectionbacklog) · [UrlDynamicInspectionsExpiring](#urldynamicinspectionsexpiring)
- Procedures: [provider outages and breakers](#provider-outages-and-breakers) · [DNSBL and RDAP configuration](#dnsbl-and-rdap-configuration) · [local feed management](#local-feed-management) · [cache flush](#cache-flush) · [rewrite skip reasons](#rewrite-skip-reasons) · [SSRF block spikes](#ssrf-block-spikes) · [dynamic inspection backlog](#dynamic-inspection-backlog) · [token key rotation](#token-key-rotation) · [checking the alert rules](#checking-the-alert-rules)

## How a message's URLs are scanned

Per round (U3): the parse row, the html/text attachment rows, the `message_urls` rows of earlier rounds and the tenant's active domains are read on the writer for the envelope's organization (echo-checked; a mismatch is the retried attempt failure `inconsistent_read`, `scan_url_inconsistent_reads_total{read}`). The stored text and HTML bodies and at most `URL_MAX_EXTRA_PARTS` small text/html attachments are read from S3 (key under `org/<org>/part/`, size and SHA-256 verified). URLs are extracted (`url-extract/1`: `a`/`area` hrefs, form actions, `src`/`srcset`, meta refresh, plain-text URLs, `www.`) and normalized (identity form for hashes, redirect form for storage); each keeps its `url_seq` across rescans. Static analysis: lookalikes of the platform brands, `URL_PROTECTED_EXTRA_DOMAINS`, the tenant's active domains and `lookalike.extraProtectedDomains` (homoglyph, edit distance, combosquat, mixed script, TLD swap), obfuscations, IP hosts, text mismatches. Reputation: every URL, host, literal IP and public address a domain host resolves to (restricted resolver, ≤ 4 per host, resolved on every scan — DNS answers are not cached by the gateway; internal answers are dropped, a failed resolution gives no address) goes to the providers of `URL_REPUTATION_PROVIDERS` (`local_feed`, `dnsbl`, `rdap`), each behind its own breaker and timeout; `dnsbl`/`rdap` answers go through the authenticated Redis cache, the local feed never does. Fetches (U8, U9): `scanTimeFetch` (platform `URL_SCAN_TIME_FETCH`, tenant may only lower it) selects shorteners first, then risky URLs, at most `URL_FETCH_MAX_PER_MESSAGE`; the guarded fetcher follows redirects (each hop validated by the SSRF guard before it is requested, at most `URL_FETCH_MAX_HOPS`), reads at most `URL_FETCH_MAX_BODY_BYTES` of a final HTML page for landing features (password fields, forms, cross-origin actions, brand titles) and caches the chain; final URLs, chain hops and the addresses of their hosts go through reputation too. The verdict map `url-map/1` gives each URL a verdict (`malicious > suspicious > unknown > clean`); the engine result is the most severe one, plus `url.content_incomplete` (body not stored or a structural parse limit), `url.script_scheme` / `url.data_uri` / `url.unsafe_scheme`, `limit.url_count`; no URLs on a complete parse → `skipped` (`url.none`). When eligible, the EML is streamed through the rewriter into a new S3 object (`org/<org>/rewrite/<yyyy>/<mm>/<dd>/<message>/r<round>-<uuid>.eml`, tag `eg-object=rewrite` set in the creating PutObject/CreateMultipartUpload, so the object never exists untagged; a failed upload deletes the key), every eligible link pointing at `URL_CLICK_BASE_URL/c/<token>`. Up to `URL_DYNAMIC_MAX_PER_MESSAGE` suspicious/unknown URLs get a `url_dynamic_inspections` row and a `mail.url.inspection_requested.v1` event. Everything is written in the finalize transaction of the engine's final row.

Failure classes: internal infrastructure (S3 part read or rewrite upload, MySQL including the local-feed query, a wrong read) → attempt failure or a thrown transient error, retried; external problems (a site, a DNSBL or RDAP outage, an open provider breaker) → a definite `unknown` per URL with its code. Attempt failures: `inconsistent_read`, `extract_timeout` (retried), `timeout` (the engine call exceeded `SCAN_URL_TIMEOUT_MS`), and not retried: `parse_row_missing`, `part_unavailable`, `part_integrity`, `part_key_mismatch`, `eml_unavailable`.

## Reading results

Tenant-scoped through `GET /api/v1/messages/{messageId}/scans` (engine `url` carries `urls[]` and `rewrite`). Tenants never see cache flags or per-URL durations (the cache is shared across organizations). On the replica (URLs are tenant data: select them only when the case needs them):

```sql
-- The engine's final and its codes.
SELECT scan_id, outcome, error_code, reason_codes, engine_version, settings_version
FROM scan_engine_results WHERE message_id = ? AND received_at = ? AND engine = 'url' ORDER BY scan_id, attempt;
-- Per URL of a round: verdict, codes, providers, chain (hosts only), landing counts.
SELECT r.url_seq, m.host, m.host_kind, LEFT(r.url_sha256, 12) AS url_hash, r.verdict, r.reason_codes,
       r.fetch_status, r.fetch_error, r.hop_count, r.redirect_chain, r.final_host, r.final_status,
       r.landing, r.reputation, r.lookalike, r.rewritten, r.dynamic_requested, r.fetch_cache
FROM url_scan_results r JOIN message_urls m
  ON m.message_id = r.message_id AND m.received_at = r.received_at AND m.url_seq = r.url_seq
WHERE r.message_id = ? AND r.received_at = ? AND r.scan_id = ? ORDER BY r.url_seq;
-- The rewrite of each round and the dynamic inspections.
SELECT lifecycle_round, status, skip_reason, object_key, links_rewritten, links_unmapped,
       parts_rewritten, parts_skipped, dkim_signed, token_kid, expires_at
FROM url_rewrites WHERE message_id = ? AND received_at = ? ORDER BY scan_id;
SELECT url_seq, status, verdict, reason_codes, error_code, worker_version, created_at, completed_at
FROM url_dynamic_inspections WHERE message_id = ? AND received_at = ? ORDER BY scan_id, url_seq;
```

`reputation` entries are `{provider, version, kind, status, category, severity, cache}` (listed first, then errors, at most 12); `lookalike` entries are `{rule, targetKind, targetDomain, score, distance}` (L4 mixed script and L6 IDN without a target); `redirect_chain` hops are `{host, port, status, kind, blocked}` (never a path or query). A `rewritten` round is delivered from `url_rewrites.object_key`; a `skipped` one from the original EML.

## Series used by the alerts

`scan_url_urls_total{verdict}`, `scan_url_extracted_total{source}`, `scan_url_findings_total{code}`, `url_reputation_lookups_total{provider,result}` / `url_reputation_duration_seconds`, `url_provider_breaker_state{provider}` (0 closed, 1 half open, 2 open), `url_fetch_total{result,component}` / `url_fetch_duration_seconds`, `url_fetch_blocked_total{reason,component}`, `url_cache_total{cache,result}`, `scan_url_rewrites_total{result}`, `scan_url_rewritten_links_total{part}`, `scan_url_dynamic_inspections_total{status}`, `scan_url_inconsistent_reads_total{read}`; the generic `scan_engine_results_total{engine="url"}`, `scan_event_lag_seconds{engine="url"}`; queue depths `rabbitmq_detailed_queue_messages_ready{queue=~"scan.url|scan.url.inspect|scan.url.results"}`.

## UrlEngineFailuresHigh

More than 5 % of the final url results of 10 minutes are `timeout` or `error`. Break down by `error_code` (query above, or `scan_engine_failures_total{engine="url",reason}`): `inconsistent_read` → database connections (see the scan pipeline runbook, Prisma wrong-read mitigation); `part_unavailable` / `part_integrity` → S3 lifecycle or a replication problem of the mail bucket (the message's parts are gone or altered; the round stays `scan_failed`, rescan after restoring); `timeout` → the engine call ran out of `SCAN_URL_TIMEOUT_MS` (slow providers or fetches: check `url_reputation_duration_seconds`, `url_fetch_duration_seconds`, provider breakers); `extract_timeout` → CPU starvation of the pod (raise CPU requests, lower `SCAN_URL_CONCURRENCY`). An S3/MySQL outage shows as retried transient errors first; fix the dependency, then rescan the `scan_failed` rounds.

## UrlScanQueueBacklog

`scan.url` above 1 000 ready messages or the p95 trigger age above 180 s. Scale `email-worker-url` (KEDA on `scan.url` ready, 200 per replica). If replicas are busy but slow, the time goes into providers or fetches: lower `URL_PROVIDER_TIMEOUT_MS` / `URL_FETCH_TOTAL_TIMEOUT_MS` only within the validated bounds, check whether one provider is slow (breaker half-open probing) and whether `URL_SCAN_TIME_FETCH` was raised to `all`.

## UrlReputationProviderDown

The breaker of `{{provider}}` has been open for 5 minutes: its lookups are answered `error` (`url.reputation_unavailable`), URLs end `unknown`, clicks are warned. See [provider outages and breakers](#provider-outages-and-breakers).

## UrlFetchInternalTargetsSpike

The SSRF guard refuses more than one internal target per second (any reason but `port`/`scheme`). See [SSRF block spikes](#ssrf-block-spikes).

## UrlRewriteErrors

Rewrites ending `skip_reason = error` (an unexpected rewriter exception; the message is delivered unrewritten). The worker logs `url rewrite failed unexpectedly` with the message id and the error class/code only. Collect the message ids of the last hour (`url_rewrites` with `skip_reason = 'error'`), check whether they share a MIME shape (`email_message_parses.structure`: charsets, transfer encodings, nesting), reproduce with a synthetic EML of the same shape in a test environment (never with the customer EML outside S3), and file a bug against `@email-gateway/url-security` `rewrite/`. Messages keep flowing; no action is needed per message.

## UrlCacheErrors

Cache operations failing (`result="error"`: Redis down or slower than `URL_CACHE_TIMEOUT_MS`) or rejected (`result="rejected"`: wrong MAC or shape). Errors bypass the cache: every lookup and chain goes to the providers and sites (more DNS/RDAP traffic, slower scans), never a verdict change. Rejections after a `URL_CACHE_HMAC_KEY` rotation are expected until the old entries expire (or flush them, [cache flush](#cache-flush)); rejections without a rotation mean a client of the shared Redis wrote `eg:url:` keys — find it (`CLIENT LIST`, Redis ACL logs) and treat it as a security incident.

## UrlDynamicInspectionBacklog

`scan.url.inspect` holds more than 1 000 requests for 15 minutes. See [dynamic inspection backlog](#dynamic-inspection-backlog).

## UrlDynamicInspectionsExpiring

The sweeper expires more than 0.1 pending inspections per second: results never arrive (browser worker down, requests dropped at the 10 000 bound). Clicks still work with the static signals. See [dynamic inspection backlog](#dynamic-inspection-backlog).

## Provider outages and breakers

Each provider has its own breaker (`URL_PROVIDER_BREAKER_THRESHOLD` consecutive whole-provider failures open it; after `URL_PROVIDER_BREAKER_RESET_MS` one probe is let through). `url_reputation_lookups_total{provider,result="error"}` and `url_provider_breaker_state{provider}` show it.

- **dnsbl**: the restricted resolver (`URL_DNS_SERVERS`) cannot reach the DNS servers or the lists answer error codes (`URL_DNSBL_ERROR_CODES`, e.g. Spamhaus "query via public resolver refused"). Check the readiness detail `url-engine.dns` of a pod (`unreachable` = no answer at all), resolve a list test entry from a debug pod on the same network, verify the DQS key (part of the zone name) has not expired.
- **rdap**: the RDAP base URL (`URL_RDAP_BASE_URL`) is fetched through the guarded fetcher (and the egress proxy in proxy mode): check `url_fetch_total{component="rdap"}`, the proxy's health and rate limits of the RDAP service.
- **local_feed**: a MySQL failure is internal, not an outage: the attempt fails and is retried; a persistent failure appears as `UrlEngineFailuresHigh`. After `URL_PROVIDER_BREAKER_THRESHOLD` consecutive failed lookups its breaker opens and the feed is answered `error` without a query (URLs `unknown`, never clean) until a probe succeeds.
- Do not disable a provider to "unblock" mail: mail is not blocked by `unknown`. Removing a provider from `URL_REPUTATION_PROVIDERS` changes the engine version and lowers protection; record the change.

## DNSBL and RDAP configuration

`URL_DNSBL_DOMAIN_ZONES` / `URL_DNSBL_IP_ZONES`: `zone=code:category[,code:category…]`, zones separated by `;` (categories `phishing`, `malware`, `c2` → malicious; `spam`, `scam`, `other` → suspicious). Spamhaus DQS: put the DQS key into the zone name (`<key>.dbl.dq.spamhaus.net=127.0.1.2:spam,127.0.1.4:phishing,127.0.1.5:malware,127.0.1.6:c2`); the configuration error message never echoes zone names, but treat the value as a secret (External Secret into the ConfigMap source). SURBL/URIBL work the same way with their return codes. Answers in `URL_DNSBL_ERROR_CODES` and answers outside `127.0.0.0/8` are `error`, never clear. RDAP: `URL_RDAP_BASE_URL` (e.g. `https://rdap.org`), `URL_NEW_DOMAIN_DAYS` (default 30) → `url.new_domain` (suspicious); RDAP is enabled only when listed in `URL_REPUTATION_PROVIDERS` and the base URL is set. Changing any zone or code changes the provider version (`dnsbl/1;<hash>`) and therefore the cache keys: old entries are simply unused.

## Local feed management

The platform feed is `threat_indicators` with `organization_id` NULL (`org_scope = 0`), types `url` (identity form), `domain` (matches the host and its parents down to the registrable domain), `ip` (canonical). It is never cached: an addition or removal applies to the next scan and the next click. Manage it only through the api (`GET/POST /api/v1/platform/threat-indicators`, `DELETE /api/v1/platform/threat-indicators/{id}?reason=`; permission `platform:threat_intel_manage`, MFA, audited `threat_indicator.added` / `.removed`), which normalizes values with `@email-gateway/url-security` and refuses public suffixes. Severity `high`/`critical` → `url.feed_malicious` (malicious, never overridden by a tenant allow list); `low`/`medium` → `url.feed_suspicious`. Messages already delivered are re-evaluated at click time; to change the recorded verdict of a message, rescan it.

## Cache flush

The URL cache lives in the shared app Redis under `eg:url:` (`rep:v1` provider answers, `chain:v1` redirect chains, `dyn:v1` dynamic results). Entries expire on their own (clean ≤ `URL_CACHE_CLEAN_TTL_SECONDS`, malicious ≤ `URL_CACHE_MALICIOUS_TTL_SECONDS`, errors ≤ 120 s). To flush (after a `URL_CACHE_HMAC_KEY` rotation, a wrong DNSBL configuration, or a poisoned entry) delete **only** `eg:url:` keys with `SCAN` + `UNLINK` — **never `FLUSHDB`/`FLUSHALL`** (the database also holds rate limits, sessions and the attachment cache):

```sh
redis-cli -u "$REDIS_URL" --scan --pattern 'eg:url:rep:v1:*' --count 1000 | xargs -r -n 500 redis-cli -u "$REDIS_URL" UNLINK
# narrower: one provider, e.g. 'eg:url:rep:v1:dnsbl:*'; chains: 'eg:url:chain:v1:*'; dynamic: 'eg:url:dyn:v1:*'
```

(`REDIS_URL` from the secret, never echoed into a ticket.) After a flush the next scans query the providers again (more DNS/RDAP load for some minutes).

## Rewrite skip reasons

`url_rewrites.skip_reason` (also `scan_url_rewrites_total{result}`); skipping is never a failure and the original EML is delivered:

| Reason                                    | Meaning / action                                                                                                                                                                   |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `disabled`                                | Platform `URL_REWRITE_ENABLED=false`, tenant `rewrite.enabled=false`, or no token key.                                                                                             |
| `direction`                               | The message direction is not in `rewrite.directions` (default `inbound`).                                                                                                          |
| `no_urls`                                 | No eligible link (only images, forms, excluded/allowed domains, attachment URLs, or no URLs).                                                                                      |
| `parse_incomplete`                        | A body was not stored or a structural parse limit was hit.                                                                                                                         |
| `too_large`                               | EML above `URL_REWRITE_MAX_MESSAGE_BYTES`.                                                                                                                                         |
| `signed_smime`, `signed_pgp`, `encrypted` | Rewriting would break the signature/encryption: the whole message is left untouched (expected).                                                                                    |
| `dkim_policy`                             | DKIM-signed and the tenant chose `rewrite.dkimSignedPolicy=skip`.                                                                                                                  |
| `structure_mismatch`                      | The rewriter's MIME nodes differ from the parse `structure` (or no structure): a parser/rewriter disagreement; collect the ids, report like [UrlRewriteErrors](#urlrewriteerrors). |
| `error`                                   | Unexpected rewriter error: [UrlRewriteErrors](#urlrewriteerrors).                                                                                                                  |

`links_unmapped` counts occurrences the rewriter found but the scan did not map (left untouched); `parts_skipped` counts parts above `URL_REWRITE_MAX_PART_BYTES` or with a charset that does not round-trip. Rewritten objects of aborted or duplicate attempts are orphans; the bucket lifecycle rule `eg-rewrite-expiry` (tag `eg-object=rewrite`, `URL_REWRITE_OBJECT_RETENTION_DAYS`) removes them.

## SSRF block spikes

`url_fetch_blocked_total{reason,component}`: reasons `loopback`, `private`, `link_local`, `cgnat`, `multicast`, `reserved`, `documentation`, `metadata`, `ula`, `unspecified`, `mapped`, `name`, `deny_list` are internal targets (a link or a redirect hop into the platform, a name resolving to an internal address, DNS rebinding). Nothing was connected: the guard decides before dialing and re-checks the connected address. A spike usually means a phishing campaign probing internal addresses (the URLs are `suspicious`, `url.redirect_blocked_internal`); find the messages (`url_scan_results` with that code in the last hour) and add confirmed attacker domains to the [local feed](#local-feed-management). A sudden spike of `private`/`reserved` for ordinary domains means the resolver serves internal zones or rewrites answers (split horizon): `URL_DNS_SERVERS` must be a recursive resolver that does **not** serve internal zones. `metadata` hits from the click component are covered by the click-service runbook. Never relax `URL_FETCH_DENY_CIDRS` or use the TEST-ONLY `URL_FETCH_TEST_ALLOW_CIDRS` outside APP_ENV local/ci (the config refuses it).

## Dynamic inspection backlog

`scan.url.inspect` is a bounded lossy queue (10 000, drop-head) consumed by the optional `url-browser-worker`. A backlog means the browser worker is not running, crash-looping or too slow (see its runbook); results arrive on `scan.url.results` and are applied by this worker (`scan_url_dynamic_inspections_total{status="completed|failed"}`; `dropped` = a result for an unknown inspection id or another organization, logged as a warning — a steady rate of drops is a forged-result attempt or a stale browser worker version). The sweeper expires rows still `pending` after `URL_DYNAMIC_PENDING_TTL_SECONDS` (`expired`). Disabling dynamic inspection (`URL_DYNAMIC_INSPECTION=off`, or per tenant) stops new requests; it does not change scan verdicts. Pending rows of a tenant can be expired early only by the sweeper (never by hand).

## Token key rotation

Click tokens are signed with `URL_TOKEN_KEY_CURRENT` (id `URL_TOKEN_KEY_CURRENT_ID`) by this Deployment and verified by the click-service (current or previous key). Rotation: put the new key into `email-gateway-url-token-keys` as `current` with a new `current-id`, move the old one to `previous` / `previous-id`, roll out the click-service **first**, then `email-worker-url`; remove `previous` only after `URL_TOKEN_MAX_EXPIRY_DAYS`. Details and verification in [click-service.md](click-service.md).

## Checking the alert rules

```sh
cd infrastructure/monitoring
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 check rules rules/url-scanning.rules.yml
docker run --rm --entrypoint promtool -v "$PWD":/m:ro -w /m prom/prometheus:v3.6.0 test rules tests/url-scanning.rules.test.yml
```
