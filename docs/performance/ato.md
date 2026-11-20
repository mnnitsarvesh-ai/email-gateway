# Performance: account takeover worker (step 8.4) — laptop baseline

Scenario 18 of [the design](../plan/steps/24-account-takeover-core.md) §10.3: `apps/ato-worker/integration/volume.test.ts`. **These are local numbers on one developer laptop. The production estimate of D22 (1M messages/day, 50 000 sending mailboxes, 200 000 SMTP AUTHs/day) is not verified locally**; sizing is a step 10.x task on production-like infrastructure.

## Setup (2026-11-18)

- One in-process ato-worker (detect role) with the production prefetch (`ATO_EVENTS_PREFETCH=32`, `ATO_MAIL_PREFETCH=32`), consuming a throwaway RabbitMQ vhost with topology v13.
- Docker Desktop on macOS (15 CPUs, 16 GB VM): MySQL 8.4 writer (+ replica running), Redis, RabbitMQ; the worker on the host. The local MySQL commits on the Docker Desktop volume (slow `fsync`).
- 20 synthetic organizations, each with 25 mailboxes, 2 SASL connectors and 1 domain; ATO enabled, no learning period, synthetic GeoIP databases.
- 50 000 outbound `mail.message.scanned.v1` events (2 500 per organization, 1–3 external recipients, 10 % with an internal recipient, 0.5 % phishing) spread over 15 minutes of `received_at`; 1 000 messages per organization are attributed to a connector by submission telemetry.
- 24 000 telemetry entries in 120 batches of 200: 20 000 submissions and 4 000 SMTP AUTH decisions (20 % failures).
- The backlog was published at once (worst case: the queues hold everything before consumption starts).

## Results

| Measure                                                             | Value                                                                                                                    |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Seeding (messages, recipients, scans; bulk inserts)                 | 9 s                                                                                                                      |
| Telemetry processed (24 000 entries)                                | 153 s — **157 entries/s**                                                                                                |
| Scanned events published                                            | 10 s                                                                                                                     |
| Scanned events processed (50 000, two accounts for 20 000 of them)  | 420 s — **119 events/s**                                                                                                 |
| Per-event detection duration (all sources), p50 / p95               | ≤ 0.1 s / ≤ 1 s (histogram buckets)                                                                                      |
| Unlocked phase (`ato_db_query_seconds{query="prepare"}`), p50 / p95 | ≤ 0.05 s / ≤ 0.1 s                                                                                                       |
| Ledger transaction (`{query="ledger_tx"}`), p50 / p95               | ≤ 0.1 s / ≤ 1 s                                                                                                          |
| Detection lag (event time → commit), p50 / p95                      | ≤ 30 min / ≤ 30 min (bucket; see below)                                                                                  |
| Events retried after an error                                       | 0                                                                                                                        |
| Loss / duplicates                                                   | none (day rows count 50 000 mailbox messages and 20 000 attributed connector messages exactly; SMTP AUTH attempts 4 000) |
| Resulting rows                                                      | 540 accounts, 5 122 signals, 60 incidents                                                                                |

The lag figure reflects the test design (a 15-minute back-dated window plus a 7-minute drain of a full backlog), not steady-state latency: with traffic arriving at the rate it is produced, the lag is the per-event duration.

## Observations

- **Hot accounts dominate.** A relay connector that carries all of a tenant's outbound mail is one account whose daily activity row is updated by every message; the ledger transaction waits for that row lock (`ledger_tx` p95 ≈ 1 s while `prepare` stays ≤ 0.1 s). Throughput grows with the number of distinct hot accounts (2 organizations: ≈ 55 events/s; 20 organizations: 119 events/s). More replicas do not help one hot row.
- **The two-phase pipeline** (Redis windows, reads and rule evaluation outside the transaction) cut the per-event transaction from ≈ 250 ms to ≈ 50 ms at p50 in the 2-organization run.
- **A deadlock in the daily-row upsert** (`INSERT IGNORE` + `SELECT … FOR UPDATE`) retried 11 % of the events of the first run; fixed in `AtoStore.upsertActivityDay` (exclusive lock at once), now 0.
- SMTP telemetry batches are processed entry by entry (one short transaction each); 120 batches over 32 concurrent consumers give 157 entries/s here.

## Rough projection (not verified)

D22's peak of ≈ 5 outbound messages/s and ≈ 2.3 SMTP AUTHs/s on average is well inside these laptop numbers; bursts of a single tenant's connector are bounded by the row-lock throughput of that connector's daily row. If a single connector exceeds a few hundred messages per second in production, the per-message connector day-row update is the first thing to aggregate (an in-memory or Redis pre-aggregation flushed per minute). Re-measure on production-like MySQL (faster commits) before sizing.

## Reproduce

```sh
pnpm --filter @email-gateway/ato-worker build
pnpm --filter @email-gateway/ato-worker exec vitest run --config vitest.integration.config.ts integration/volume.test.ts
# smaller: IT_ATO_VOLUME_ORGS=2 IT_ATO_VOLUME_MESSAGES_PER_ORG=1000
```

The test prints one `ATO-PERF {…}` line with the measures above and removes every synthetic row afterwards.

# Provider ingestion (step 8.5) — laptop baseline

Volume run of [the 8.5 design](../plan/steps/26-ato-provider-adapters.md) §11.3: `apps/ato-worker/integration/idp-volume.test.ts`. **Local numbers on one developer laptop against in-process provider simulators; not a production estimate.** The provider APIs' own limits and latency are not measured (rate budgets were raised for the simulators), and no real Microsoft or Google tenant was involved.

## Setup (2026-11-20)

- One in-process ato-worker `provider` role (`IdpStreamRunner`): claim batch `ATO_IDP_CLAIM_BATCH=10`, `ATO_PROVIDER_MAX_PAGES_PER_POLL=10`, pages of `ATO_IDP_PAGE_MAX_EVENTS=200`, four integrations polled in parallel, the streams of one integration one after the other.
- Same Docker Desktop stack as the 8.4 baseline (MySQL 8.4 writer with replica, Redis), the worker on the host; Graph and Office 365 Management simulators on 127.0.0.1.
- 10 synthetic organizations, each with its own Entra directory (1 000 users) and integration, bound with a 2-day backfill (`risk_events`, `session_events`, `oauth_consents` disabled to isolate sign-ins and mailbox audit).
- 100 000 sign-ins (10 000 per directory, 90 % successes in sessions of five per user, IP and device; 10 % failures from documentation ranges) over the last 20 hours: **live mode**.
- 10 000 Exchange `Set-Mailbox` forwarding audits (1 000 per directory, 26–30 hours old) in Office 365 Management content blobs of 200: **historical mode** (older than `ATO_IDP_HISTORICAL_SIGNAL_AGE_HOURS`).

## Results

| Measure                                   | Value                                                                                                                                                      |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Wall time until every stream caught up    | 739 s                                                                                                                                                      |
| Throughput (sign-ins + mailbox items)     | **149 events/s** (≈ 135 sign-ins/s)                                                                                                                        |
| Pages processed (all primaries)           | 720                                                                                                                                                        |
| `ato_auth_events` rows / attempts counted | 30 000 rows for 100 000 sign-ins (successes aggregated per account, IP, device hash and hour; failures individual); `SUM(attempt_count)` = 100 000 exactly |
| Mailbox items                             | 10 000 (`forwarding`, target domains only)                                                                                                                 |
| Signals                                   | 10 600, of which 10 000 informational (the historical forwarding audits); 0 incidents                                                                      |
| Sign-in watermark lag after the run       | 120 s (the settle time of Graph sign-ins)                                                                                                                  |
| Failures / duplicates                     | 0 stream failures after the deadlock fix below; every sign-in counted exactly once despite overlap re-reads                                                |

## Observations

- **Streams of one integration must not run in parallel.** Sign-ins and mailbox audit of one directory create the same new accounts and identities; polled concurrently they deadlocked MySQL (1213) at a few thousand events. The runner now polls one integration's streams sequentially per pass (integrations stay parallel) and retries a page transaction that loses a deadlock; throughput scales with the number of integrations, not of streams.
- **Overlap re-reads cost requests, not work:** every poll re-reads its overlap window (15 minutes for Graph sign-ins, 60 for Office 365 Management); a Redis seen-set skips events already processed, so aggregated successes are never double counted.
- **Historical mode is cheap:** informational signals skip correlation, rescoring and the incident policy; the 10 000 historical audits added little to the wall time compared with the sign-ins.
- The per-event cost is the 8.4 pipeline's (≈ 120–160 events/s on this laptop for both 8.4 sources and provider events); D22's reference load (≈ 250 000 provider events/day ≈ 3/s) is far inside it. Production sizing still needs production-like MySQL and the real providers' latency and throttling (a Graph page of 200 sign-ins typically takes seconds, not milliseconds).

## Reproduce

```sh
pnpm --filter @email-gateway/ato-worker exec vitest run --config vitest.integration.config.ts integration/idp-volume.test.ts
# smaller: IT_ATO_IDP_VOLUME_INTEGRATIONS=2 IT_ATO_IDP_VOLUME_SIGNINS=4000 IT_ATO_IDP_VOLUME_ITEMS=400
```

The test prints one `ATO-IDP-PERF {…}` line and removes every synthetic row afterwards.
