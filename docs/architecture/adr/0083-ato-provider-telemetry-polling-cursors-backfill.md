# ADR-0083: ATO provider telemetry: polling, per-stream cursors, backfill and mailbox state snapshots

**Status:** Accepted (2026-11-20, after the step 8.5 local verification against the provider simulators: the stack suite `ato-idp` 7/7 on the live api, ato-worker, integration-worker, provider-fake and idp-simulator, the library, worker, api, notification and 8.2 integration suites, the 8.4 contract kit for both adapters, Playwright `ato-providers.spec.ts` 5/5 with the ATO, incident, provider-connection and navigation specs; record [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md) §16 WP6, §17; live verification against real Microsoft and Google tenants (PQ7), CI and a cluster apply not done). Proposed by the step 8.5 architect on 2026-11-17. Design: [docs/plan/steps/26-ato-provider-adapters.md](../../plan/steps/26-ato-provider-adapters.md). Supersedes nothing.

**Context.** Sign-in, risk, consent and audit logs are available through polling APIs with different latencies, paging, retention and limits; Graph change notifications do not cover sign-in logs, push channels need public endpoints; Google Gmail settings have no change feed; providers throttle; events arrive late; a crash must lose nothing.

**Decision.**

1. Polling only; no inbound push endpoint.
2. One state row per integration and stream; streams are `primary` (polled, own cursor) or `companion` (filled by a primary's feed); cursors are versioned, bounded and strictly monotonic; each poll covers `[watermark − overlap, now − settle]` paged to completion; duplicates are dropped by provider event id.
3. Pages are processed in 8.4's page transaction with deterministic page keys; throttling and quota answers honour `Retry-After` or exponential backoff with jitter; per-integration rate budgets in Redis keep requests below provider limits.
4. Backfill is bounded by setting, platform maximum and provider retention, and runs in historical mode: it builds history and baselines, records signals as informational and never opens incidents, proposes actions or notifies.
5. Mailbox state (forwarding, rules, filters, delegates, permissions) is kept as hashed items with domains and traits only; diffs become events; items written by a page count as known only once the runner committed that page's cursor (cursor-confirmed state), so a crash re-emits the change with the same event id.

**Alternatives considered.** Graph change notifications and Google push channels (need a public receiver and lifecycle management; sign-in logs not covered). Advancing watermarks to the newest event (loses late events). One global cursor per integration (one slow feed blocks the others). Diff state written after the commit (needs a port change) or inside the page transaction (provider I/O inside a transaction).

**Consequences.** Detection latency is the provider's log latency plus the poll interval (minutes); re-reading the overlap costs requests; backfilled history does not alert; snapshot sweeps cost per-user API calls (bounded per poll).
