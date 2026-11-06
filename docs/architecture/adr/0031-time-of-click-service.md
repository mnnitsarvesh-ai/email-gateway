# ADR-0031: Time-of-click protection in a separate public `click-service`

**Status:** Accepted. Design: [step 4.3](../../plan/steps/11-url-protection.md) U14.

**Decision.**

1. A new NestJS deployable `apps/click-service`, separate from the api: anonymous, Internet-facing, rate limited per client network and per token, public port for `/c/{token}` only, health and metrics on a separate admin port.
2. It verifies the token (format, key, MAC, expiry), looks up the stored original URL with echo checks, re-evaluates with the latest scan result, dynamic inspection results, fresh reputation (local feed uncached, providers through the shared authenticated cache) and, for shorteners and non-clean URLs, the redirect chain through the same SSRF-guarded fetcher, all within a time budget whose misses count as `unknown`. It applies the tenant's click policy (clean allow, malicious block, suspicious/unknown configurable warn/block/allow) and returns a 302 to the stored URL only (never an open redirect), a warning page with a signed short-lived continue link, or a block page.
3. Every decision about a verified token is logged as a `url_click_events` row and a `mail.url.clicked.v1` outbox event in one transaction with a long budget (Prisma wrong-read mitigation), bounded and not blocking the response for long. Invalid tokens are counted, not stored.
4. Least privilege: its own MySQL account with table grants (read the URL tables, settings, feed and domains; insert click events and outbox rows), Redis, no broker user, no S3, no other secrets. Pages contain no tenant data, no JavaScript, strict CSP, `Referrer-Policy: no-referrer`, `no-store`.

**Alternatives considered.** Serving clicks from the api (mixes an anonymous high-rate endpoint with the authenticated control plane and its secrets); publishing click events to RabbitMQ only (loses the record when the broker is down and needs a broker user on a public service); reading from the replica with the shared reader account (SELECT on every tenant table from a public service).

**Consequences.** The click-service is critical for mail usability: if it is down, every rewritten link fails, so it runs with at least three replicas, a PDB and a critical alert. A new database account must be provisioned per environment.

**Review round 1 (2026-11-06).** Point 2 is widened: the redirect chain is re-resolved at click time for **every** URL that may be fetched (not truncated), not only shorteners and non-clean URLs, through the chain cache; the chain's final URL gets lookalike detection (merged with the stored findings), its later hop hosts and the public addresses of the URL and chain hosts get reputation. An attempted fetch that fails stays never-clean, so an unreachable, slow (beyond the budget) or broken-TLS destination follows the tenant's `click.unknown` policy (default warn). Incoming `/c/` requests are never traced (tokens and nonces stay out of spans). Recorded in [§12 "Review round 1"](../../plan/steps/11-url-protection.md#review-round-1-security-correctness-completeness-findings-2026-11-06).
