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
