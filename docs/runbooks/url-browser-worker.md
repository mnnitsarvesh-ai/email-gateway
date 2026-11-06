# Runbook: url-browser-worker and url-egress-proxy (isolated dynamic inspection)

Step 4.3 U15 ([design](../plan/steps/11-url-protection.md), [ADR-0032](../architecture/adr/0032-url-browser-isolation.md), deployment: [url-protection.md](../deployment/url-protection.md); related runbooks: [url-scanning.md](url-scanning.md) (the engine that requests inspections, the results consumer and sweeper), [click-service.md](click-service.md) (where the results are used)). The URL engine requests a dynamic inspection (`mail.url.inspection_requested.v1`, queue `scan.url.inspect`) for up to `URL_DYNAMIC_MAX_PER_MESSAGE` suspicious/unknown URLs. The **url-browser-worker** opens each URL in a fresh incognito context of headless Chromium (Playwright `chromium-headless-shell`, pinned with `playwright-core`) and publishes `mail.url.inspection_completed.v1` (counts, booleans, hosts, brand ids — never page content). All browser traffic goes through the **url-egress-proxy** (authenticated forward proxy with the same SSRF guard and restricted resolver as every fetcher). Results act at click time (U10 M5/S9/U3); the mail round never waits for them.

**Rules that hold in every procedure below:**

- **No secrets in the browser container.** No database, S3, Redis, token or cache key: the process refuses to start when `DATABASE_URL`, `CLICK_DATABASE_URL`, `S3_*`, `REDIS_URL`, `URL_TOKEN_*`, `URL_CACHE_HMAC_KEY` (or their `_FILE` variants) are set. Its only credentials are the `eg-url-browser` broker user and the proxy token. Never "debug" by giving it more.
- **No direct network.** The worker reaches only RabbitMQ and the proxy (Compose: internal network `url-sandbox`; Kubernetes: NetworkPolicy). Chromium maps every name except the proxy to NOTFOUND (`--host-resolver-rules`), QUIC and non-proxied WebRTC UDP are off, loopback goes through the proxy.
- **Never open an inspected URL yourself** (not in a workstation browser, not with curl from a laptop). Use the hash (`url_sha256`) and the hosts in the results.
- The worker is **optional** and **lossy by design**: `scan.url.inspect` is bounded (10 000, drop-head); requests nobody handles are expired by the email-worker sweeper (`url_dynamic_inspections.status = expired`).

## Contents

- [Components](#components) · [Series](#series) · [Profile usage on the 8 GB VM](#profile-usage-on-the-8-gb-vm)
- Alerts: [UrlBrowserWorkerRestarts](#urlbrowserworkerrestarts) · [UrlEgressProxyDown](#urlegressproxydown) (and `UrlDynamicInspectionBacklog` / `UrlDynamicInspectionsExpiring` in [url-scanning.md](url-scanning.md))
- Procedures: [isolation checks](#isolation-checks) · [restarts](#restarts) · [Chromium update cadence](#chromium-update-cadence) · [the focused container suite](#the-focused-container-suite)

## Components

| Container            | Entry point          | Ports                                                      | Credentials                                          |
| -------------------- | -------------------- | ---------------------------------------------------------- | ---------------------------------------------------- |
| `url-browser-worker` | `dist/main.js`       | `URL_BROWSER_HTTP_PORT` 3090 (health, metrics)             | `RABBITMQ_URL_BROWSER_URL`, `URL_EGRESS_PROXY_TOKEN` |
| `url-egress-proxy`   | `dist/proxy-main.js` | `URL_EGRESS_PORT` 3128, admin `URL_EGRESS_ADMIN_PORT` 3091 | `URL_EGRESS_PROXY_TOKEN`                             |

One image (`infrastructure/docker/url-browser-worker.Dockerfile`). Per job: strict schema of the request, deadline check (`failed`/`deadline_passed` without navigating), new context (`acceptDownloads: false`, `serviceWorkers: 'block'`, no permissions, TLS errors not ignored, 1280×800, `en-US`), dialogs dismissed, downloads cancelled and reported, `load` + up to `URL_BROWSER_SETTLE_MS` (3 s) of further navigations, DOM read through Playwright's isolated utility world (password fields, forms and their action hosts, title brand matches), result published with publisher confirms, request acked **after** the confirm. Error codes: `navigation_timeout`, `proxy_refused` (the main document was refused by the proxy), `browser_crash`, `job_timeout`, `navigation_failed`, `deadline_passed`, `invalid_url`.

Readiness (`/health/ready`): `rabbitmq` (connected, `scan.url.inspect` and the exchanges verified passively) and `browser` (launched; details `chromiumSandbox`, `browserVersion`, `jobsSinceLaunch`). The proxy's readiness: `egress-proxy` listening.

## Series

Worker: `url_browser_jobs_total{result}` (`completed` or the error code), `url_browser_job_duration_seconds`, `url_browser_restarts_total{reason}` (`max_jobs`, `crash`, `rss`, `launch_failed`), `url_browser_rss_bytes` (process tree from `/proc`), plus the AMQP consumer series (`amqp_*`). Proxy: `url_egress_connections_total{result}` (`allowed`, `blocked`, `unauthorized`, `bad_request`, `method_not_allowed`, `dns_error`, `connect_error`, `overloaded`, `limit`), `url_egress_blocked_total{reason}` (U8 reasons), `url_fetch_blocked_total{reason,component="proxy"}`, `url_egress_bytes_total{direction}`, `url_egress_active_connections`.

## Profile usage on the 8 GB VM

The two containers are in Compose profile **`url-browser` only** (never in `apps`). Chromium needs up to 1 GiB (`mem_limit: 1g`, `URL_BROWSER_MAX_RSS_MB` 768).

- **Never** run `url-browser` together with the `analytics` or `observability` profiles on the 8 GB Docker VM.
- Build the image **alone** (no other image build in parallel): `docker compose --profile url-browser build url-browser-worker` (the Playwright installer downloads the headless shell, ~100 MB).
- If memory is tight, stop idle apps first: `docker compose stop admin-portal archive-worker notification-worker policy-engine`.
- Start: `docker compose --profile smtp-test --profile url-browser up -d url-egress-proxy url-browser-worker` (smtp-test brings dns-sink and url-test for local targets). The first `up` after step 4.3 also recreates `rabbitmq` (it joins `url-sandbox` with alias `rabbitmq`). To avoid recreating the broker under running apps: `up -d --no-deps url-egress-proxy`, then `docker network connect --alias rabbitmq email-gateway_url-sandbox email-gateway-rabbitmq-1`, then `up -d --no-deps url-browser-worker`. The broker user's password comes from `.env` through `docker compose run --rm --no-deps rabbitmq-init`.
- Stop when done: `docker compose --profile url-browser stop url-browser-worker url-egress-proxy`. Requests published meanwhile wait in `scan.url.inspect` (bounded) and expire.
- The worker's published port (`127.0.0.1:${URL_BROWSER_HOST_PORT}`) does **not** answer: Docker does not publish ports of a container attached only to an internal network. Use `docker compose exec url-browser-worker node -e "fetch('http://127.0.0.1:3090/health/ready').then(r=>r.text()).then(console.log)"`. The proxy admin port (3091) is published.

## UrlBrowserWorkerRestarts

More than 0.05 restarts per second over 15 minutes. By `reason`:

- `crash`: Chromium or a renderer died (hostile page, OOM inside the container, a Chromium regression after an image update). Check `docker logs` / `kubectl logs` for `browser launched` lines and the container's OOM kills; roll back the image if it started with an update.
- `rss`: the process tree exceeded `URL_BROWSER_MAX_RSS_MB` between jobs (memory-hungry pages). Expected occasionally; frequent → lower `URL_BROWSER_CONCURRENCY` or raise the memory limit together with `URL_BROWSER_MAX_RSS_MB` (keep ~25 % head-room under the container limit).
- `launch_failed`: the browser does not start (missing libraries after an image change, `/tmp` full or read-only, pids limit). Readiness turns red; the logs say `browser launch failed`.
- `max_jobs`: planned (every `URL_BROWSER_MAX_JOBS_PER_BROWSER` jobs); only a very high job rate makes it alert.

## UrlEgressProxyDown

The proxy instance is not scraped. Dynamic inspections fail (`navigation_failed`/`proxy_refused`), and in egress mode 2 the URL engine and the click-service fetches error → those URLs are `unknown` (never clean). Check the pod/container, its logs (`egress proxy listening`), its Secret `email-gateway-url-egress-token` and the resolver (`URL_DNS_SERVERS`). A proxy that is up but refuses everything shows `url_egress_connections_total{result="unauthorized"}` (token mismatch between clients and proxy: both read the same Secret; restart both after a rotation) or `dns_error` (resolver).

## Isolation checks

Run after every change to the image, Compose file or NetworkPolicies (the focused suite automates all of them):

1. **No secrets:** `docker compose exec url-browser-worker node -e "console.log(Object.keys(process.env).join('\n'))"` lists names only; none of the forbidden keys may appear. Kubernetes: `kubectl exec deploy/url-browser-worker -- node -e …`.
2. **No direct egress:** from the worker, TCP to `203.0.113.10:80`, `1.1.1.1:443`, the DNS sink and a `dns.lookup` must all fail.
3. **Proxy refusals:** through the proxy (with the token) `http://127.0.0.1/`, `http://169.254.169.254/latest/meta-data/`, `http://10.0.0.5/` and a name resolving to loopback answer `403` with `x-egress-blocked-reason` (`loopback`, `metadata`, `private`); a public target answers 200. Without the token: `407`.
4. **Broker user:** `eg-url-browser` cannot consume any queue but `scan.url.inspect` and cannot publish anything but `org.<id>.mail.url.inspection_completed.v1` and the inspect queue's retry/dead-letter keys (`ACCESS_REFUSED`).
5. **Sandbox mode:** readiness details `chromiumSandbox`. Docker's default seccomp profile blocks unprivileged user namespaces, so locally the worker runs with `chromiumSandbox: false` and relies on the container controls (non-root uid 1000, read-only root, `/tmp` tmpfs 256 MiB, `cap_drop: ALL`, `no-new-privileges`, `pids_limit: 256`, `mem_limit: 1g`, `cpus: 1`). In production prefer gVisor (`runtimeClassName: gvisor`, commented in `url-browser-worker.yaml`) — not verified locally.

## Restarts

- Restart the browser of one replica: restart the container/pod (`docker compose restart url-browser-worker`, `kubectl rollout restart deploy/url-browser-worker`). In-flight jobs are not acked and are redelivered (stateless; results are deduplicated by `inspectionId` in `scan.url.results`).
- Many `job_timeout`/`navigation_timeout` results: slow targets or a slow proxy/resolver; `URL_BROWSER_JOB_TIMEOUT_MS` (20 s) bounds each job, `URL_BROWSER_CONCURRENCY` (1..4) the parallelism per replica. Scale replicas, not concurrency, first (each context shares one browser).
- A backlog in `scan.url.inspect` is harmless for mail flow; the sweeper expires requests older than `URL_DYNAMIC_PENDING_TTL_SECONDS`.

## Chromium update cadence

The browser version is pinned by the `playwright-core` version in `apps/url-browser-worker/package.json` (the Dockerfile installs exactly that version's headless shell). Chromium ships security fixes every ~1–2 weeks:

1. **Monthly** (and within **72 hours** of a Chromium security release marked critical/high with an in-the-wild exploit): bump `playwright-core` to the newest release that is at least 14 days old (repository dependency rule), `pnpm install`, rebuild the image (alone), run the unit tests and the focused container suite, deploy.
2. Record the new `browserVersion` (readiness details / `inspection_completed.v1.browserVersion`).
3. Watch `url_browser_restarts_total{reason=~"crash|launch_failed"}` and the job results for a day after the rollout; roll back the image on a crash regression.
4. The base image (`node:22-bookworm-slim`) and its Debian libraries are updated with the same rebuild.

## The focused container suite

`apps/url-browser-worker/integration/browser.integration.test.ts` (host-run, against the live containers; never with analytics/observability):

```sh
docker compose --profile url-browser build url-browser-worker          # alone
URL_BROWSER_MAX_JOBS_PER_BROWSER=3 URL_BROWSER_JOB_TIMEOUT_MS=10000 \
  docker compose --profile smtp-test --profile url-browser up -d url-egress-proxy url-browser-worker
pnpm --filter @email-gateway/url-browser-worker test:integration
```

It publishes requests for a random test organization with the admin user, reads the results from a temporary exclusive queue, and checks: password form + cross-origin form, JS redirect, download blocked, JS requests to `169.254.169.254` and `127.0.0.1` refused by the proxy, a redirect into an internal address refused, job timeout, deadline passed, browser restart after max jobs, no direct egress from the worker, proxy refusals, no secrets in the worker environment, readiness details, broker user refusals. The results also reach `scan.url.results` (the email-worker drops them: unknown inspection ids).
