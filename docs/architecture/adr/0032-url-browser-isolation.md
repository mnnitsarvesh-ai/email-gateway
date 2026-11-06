# ADR-0032: Dynamic URL inspection in an isolated headless-Chromium worker behind a guarded egress proxy

**Status:** Accepted. Design: [step 4.3](../../plan/steps/11-url-protection.md) U15.

**Context.** Static fetching cannot see JavaScript redirects, client-side rendered credential forms or download triggers. Running a browser on hostile pages is the riskiest operation of the platform. The local Docker VM has 8 GB of RAM.

**Decision.**

1. **Real headless Chromium** (`playwright-core` with Playwright's `chromium-headless-shell`, pinned) in a separate deployable `apps/url-browser-worker`, in an optional Compose profile `url-browser` and its own Kubernetes Deployment.
2. **Isolation:** its own broker user (read `scan.url.inspect`, publish only `inspection_completed.v1`); no MySQL, S3, Redis or token/cache secrets (refuses to start if any is present); a network with no route except the egress proxy and RabbitMQ; Chromium configured to send all traffic to the proxy and to resolve nothing itself; a fresh incognito context per job, downloads and service workers blocked, no permissions; navigation and job timeouts; browser restart after a job count, a crash or an RSS limit; non-root, read-only root filesystem with a size-limited tmpfs for the ephemeral profile, all capabilities dropped, no-new-privileges, pids and memory limits. Chromium's own sandbox is used when the kernel allows it; otherwise the container controls apply and production should add a gVisor runtime class (documented, not verified locally).
3. **Egress proxy** (`url-egress-proxy`, same image, different entrypoint): an authenticated HTTP/CONNECT forward proxy that applies the same SSRF guard and restricted resolver to every request, dials validated IPs, and caps connections, bytes and time. It is also the production egress path for the other fetchers.
4. **Asynchronous:** the URL engine requests inspections for suspicious/unknown URLs through the outbox; the round never waits; results update `url_dynamic_inspections` and the cache and act at click time. The request queue is a bounded lossy buffer; unanswered requests expire.

**Alternatives considered.** jsdom or similar DOM emulation (runs attacker JavaScript in Node without a browser sandbox: weaker isolation), a browser inside the email-worker (a browser exploit would reach the writer database, S3 and token keys), request interception without network isolation (misses WebSocket, WebRTC and DNS paths), remote browser services (sends customer URLs to a third party).

**Consequences.** About 1 GB of memory per worker; on the 8 GB VM the profile runs only for its focused test suite, without the analytics/observability profiles. Chromium needs a regular update cadence (runbook). The feature is complete only when the focused suite has run against a real browser.
