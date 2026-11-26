# AI assistant load test (step AI-6)

Results of the opt-in load test `apps/api/integration/assistant-load.test.ts` ([step AI-6 D11](../plan/steps/34-ai-chat-hardening-operations.md#d11-load-test-fake-provider-only), A6-11), run beside the SMTP benchmark of [smtp-concurrency.md](smtp-concurrency.md). It is a **functional capacity indication on a developer laptop with the fake provider**, not a production capacity figure: real model latency, provider rate limits and real-model behaviour (program risk R10) are not measured.

## What the test does

- The api runs **in-process** (vitest) on its ephemeral loopback port: the real `/api/v1` pipeline (guards, RBAC, tenant scope, the API rate classes, the assistant's limits), MySQL writer and replica, Redis and MinIO of the local stack. The model is the deterministic **fake provider** only (`assertFakeProvider`), a `FakeProvider` subclass (`support/assistant-load.ts`) that waits `ASSISTANT_LOAD_LATENCY_MS` (300 ms) before every model round and streams the answer in chunks, and adds a `/chain a,b,c` directive for multi-round reads. Nothing reaches the internet.
- Limits are the **production defaults**: `ASSISTANT_TURNS_PER_USER_PER_MINUTE` 6, `ASSISTANT_MAX_CONCURRENT_TURNS` 20 (one process), API rate classes 600/min per principal and the `standard` plan's 300/min per tenant (sensitive 30, expensive 60). Users are spread over synthetic `it-load-*` organizations, 2 per organization (`ASSISTANT_LOAD_USERS_PER_ORG`), so a tenant stays under 300 requests/min (each turn is 1 request plus one loopback request per tool call). Each organization has the per-user daily token budget set, so the user token counters are exercised.
- Scenarios, one printed line each:
  1. **mixed**: every user runs `ASSISTANT_LOAD_TURNS` JSON turns in its own conversation, all users at once (or paced). The default plan per user is `read > read > chain > write > report`: one-round reads (demo intents `show policies`, `list the domains`, `list users`, `/tool roles_list`), a three-round read (`/chain users_list,domains_list,policy_management_list`), a write proposal (the first user of an organization: the fake's create-policy plan, two read rounds and the proposal; others: `add dlp dictionary …`) **confirmed at once**, and one report of 30 days, which is queued as a **background job** (D5).
  2. **report-jobs**: the queued jobs run through `ReportJobProcessor.handle` with the envelopes of their outbox rows, `ASSISTANT_REPORT_JOB_CONCURRENCY` (2) at a time: job token of the user's session, authority re-check, up to 9 loopback GETs, render, S3 put, commit.
  3. **burst**: in a fresh minute, min(users × 5, 20 + 10) = 30 one-round turns at once in separate conversations.
  4. **consistency**: one execution row per tool call the client saw and exactly one `assistant.tool_executed|tool_denied` audit row per execution; every confirmed write sent exactly once (matched by the result execution's correlation id) and audited once (`assistant.confirmation_executed`); the Redis token counters (tenant `as:tok:o:*`, user `as:tok:u:*`) equal the sums of `ai_chat_usage_daily` / `ai_chat_usage_user_daily`; the usage rows' `turns` equal the finished turns; no turn left `running`; every job succeeded with its object stored and one `assistant.report_generated` audit row.
- Measured per scenario: wall time, turns/s, client-side turn latency p50/p95/p99 (the whole JSON turn), tool calls/s, confirm latency, error codes by count, event-loop delay (`monitorEventLoopDelay`) and the process RSS. The api and the load client share one Node process, so loop delay and RSS include the client.
- **Acceptable errors** under load are only `429 rate_limited` (per-user window) and `503 assistant_busy` (per-process concurrency); anything else fails the test.
- The live `event-relay` container is paused for the run (`support/live-relay.ts`): the running relay image predates topology v16 and would mark the `assistant.report.generate_requested.v1` rows poison. The RabbitMQ hop (relay → `assistant.reports` → consumer) is therefore **not** part of this measurement; the job composition is.

## Environment

- 2026-11-26 (UTC evening of 2026-11-25), branch `build/platform`, working tree of step AI-6 (not committed).
- MacBook on **AC power** (battery 100 %, charged; `pmset -g batt` before each run), 15 CPU cores, 24 GiB RAM, macOS. Docker Desktop VM: **8 CPUs, 15.5 GiB** (`docker info`), shared with another project's containers (about 10) and the full `apps` profile of this repository (api, workers, admin-portal) plus the `smtp-test` profile's `smtp-tools`.
- The api under test runs on the host (Node 22, `NODE_ENV=development`, `LOG_LEVEL=warn`). MySQL 8.4 writer + GTID replica, Redis 7, MinIO in the VM.
- SMTP benchmark: `smtp-source` in `smtp-tools` → `postfix:25` → LMTP to **smtp-adapter on the host** (`SMTP_ADAPTER_HOST=host.docker.internal` in the local `.env`; started with `HTTP_PORT=3011 node --env-file=../../.env dist/main.js` because the container's adapter publishes 3010), 40 sessions × 1 000 messages.

## Results

### Assistant scenarios

| Run                                         | Users × turns (pace) | Scenario    | Wall   | Turns (rate)               | Turn p50 / p95 / p99       | Tool calls (rate) | Confirm p50 / p95 (n) | Errors                     | Loop delay p99 / max | RSS max |
| ------------------------------------------- | -------------------- | ----------- | ------ | -------------------------- | -------------------------- | ----------------- | --------------------- | -------------------------- | -------------------- | ------- |
| Default profile                             | 20 × 5               | mixed       | 6.0 s  | 100 (16.7/s)               | 991 / 1 500 / 1 517 ms     | 160 (26.7/s)      | 104 / 138 ms (20)     | none                       | 18.7 / 39.9 ms       | 317 MiB |
|                                             |                      | report-jobs | 1.8 s  | 20 jobs                    | job 115 / 820 ms (p50/p95) | —                 | —                     | none (20/20 succeeded)     | 42.6 / 60.2 ms       | 219 MiB |
|                                             |                      | burst       | 0.9 s  | 30 (34.8/s)                | 843 / 862 / 862 ms         | 20                | —                     | `503 assistant_busy` × 10  | 16.5 / 19.9 ms       | 286 MiB |
| Over the concurrency limit                  | 60 × 5               | mixed       | 5.6 s  | 300 (53.7/s), 100 answered | 165 / 1 384 / 1 434 ms     | 160 (28.6/s)      | 116 / 224 ms (20)     | `503 assistant_busy` × 200 | 15.2 / 46.0 ms       | 348 MiB |
|                                             |                      | report-jobs | 0.7 s  | 20 jobs                    | job 63 / 125 ms            | —                 | —                     | none (20/20)               | 14.1 / 30.2 ms       | 355 MiB |
| Sustained, paced, alone                     | 40 × 6 (10 s)        | mixed       | 60.4 s | 240 (4.0/s)                | 682 / 1 311 / 1 452 ms     | 360 (6.0/s)       | 47 / 64 ms (40)       | none                       | 12.2 / 28.1 ms       | 299 MiB |
|                                             |                      | report-jobs | 1.6 s  | 40 jobs                    | job 69 / 148 ms            | —                 | —                     | none (40/40)               | 13.3 / 20.9 ms       | 306 MiB |
| Sustained, paced, **beside SMTP** (round 2) | 40 × 6 (10 s)        | mixed       | 60.5 s | 240 (4.0/s)                | 686 / 1 402 / 1 451 ms     | 360 (6.0/s)       | 52 / 137 ms (40)      | none                       | 12.3 / 34.4 ms       | 333 MiB |
| Sustained, paced, **beside SMTP** (round 3) | 40 × 6 (10 s)        | mixed       | 60.5 s | 240 (4.0/s)                | 727 / 1 384 / 1 520 ms     | 360 (6.0/s)       | 74 / 191 ms (40)      | none                       | 12.6 / 54.5 ms       | 290 MiB |

Every run's **burst** scenario answered 20 turns and refused exactly 10 with `503 assistant_busy` (30 concurrent, limit 20; turn p50 832–900 ms). Every run's **consistency** check passed: executions = tool calls seen by the client (200 or 420), one audit row each, each confirmed write sent once, Redis token counters equal to the usage rows, no orphan `running` turn, every report job succeeded.

Reading the turn latencies: with 300 ms per model round, a one-round read needs two model rounds (≥ 600 ms), the `/chain` read four (≥ 1.2 s) and the policy plan four. The p50 of 0.7–1.0 s and p95 of 1.3–1.5 s are therefore mostly the fake's simulated model time; the pipeline overhead per turn (auth, limits, settings, transcript and usage writes, the loopback tool calls) is in the order of 100–300 ms on this laptop. In the 60-user run the p50 of 165 ms is the fast `503 assistant_busy` refusals: two thirds of the turns were refused because 60 users started at the same instant and the client does not retry (the portal shows the error; `Retry-After: 5`).

### SMTP benchmark beside the assistant load (I7)

All runs in the same session, 40 sessions × 1 000 messages, zero loss in every run. "Acceptance" = `smtp-source` done (Postfix queued every message), "stored" = every row and object exists.

| Run                                                           | Event-relay | Assistant load                                    | SMTP acceptance         | All stored              | Loss |
| ------------------------------------------------------------- | ----------- | ------------------------------------------------- | ----------------------- | ----------------------- | ---- |
| Baseline 0                                                    | running     | none                                              | 8.7 s (114.6 msg/s)     | 28.8 s (34.7 msg/s)     | 0    |
| Baseline 1                                                    | stopped     | none                                              | 5.5 s (180.2 msg/s)     | 23.6 s (42.4 msg/s)     | 0    |
| Baseline 1b (the assistant run of that attempt did not start) | stopped     | none                                              | 4.6 s (219.3 msg/s)     | 16.6 s (60.3 msg/s)     | 0    |
| Side by side, round 1 (discarded: users started in lockstep)  | stopped     | 40 × 6, 120 `assistant_busy`                      | 5.5 s (181.7 msg/s)     | 5.5 s (181.5 msg/s)     | 0    |
| **Side by side, round 2**                                     | stopped     | 40 × 6 paced, sustained 4 turns/s, 6 tool calls/s | **4.0 s (253.0 msg/s)** | **18.0 s (55.6 msg/s)** | 0    |
| Baseline 2                                                    | stopped     | none                                              | 4.0 s (251.3 msg/s)     | 18.0 s (55.5 msg/s)     | 0    |
| **Side by side, round 3**                                     | stopped     | 40 × 6 paced                                      | **5.1 s (195.4 msg/s)** | **23.2 s (43.1 msg/s)** | 0    |
| Baseline 3                                                    | stopped     | none                                              | 4.2 s (237.5 msg/s)     | 18.2 s (54.8 msg/s)     | 0    |

The SMTP benchmark started 5 s after the assistant's mixed scenario and finished well within its 60 s, so the whole SMTP run overlapped the chat load. Comparable baselines (event-relay stopped, as during the load test) ranged 4.0–5.5 s acceptance and 16.6–23.6 s stored; the side-by-side runs (4.0–5.1 s, 18.0–23.2 s) are inside that range. **No effect of the chat load on the mail path beyond run-to-run noise was measurable** at this load. In the other direction, the assistant's turn latencies beside SMTP (p50 686–727 ms, p95 1.38–1.40 s) match the paced run alone (682 ms, 1.31 s) within noise; the confirm p95 rose from 64 ms to 137–191 ms (MySQL shared with the SMTP writes). Side-by-side round 1 is discarded: all 40 users started their turns at the same instants (fixed afterwards by staggering paced users), and its "stored" time equal to the acceptance time is an outlier the other runs do not repeat.

Baseline 0 (relay running) is slower because the relay then publishes the 1 000 new outbox rows and the email-worker and later stages process them during the run; it is not comparable with the relay-stopped runs.

## Limits and what bounds the numbers

- **Per process:** `ASSISTANT_MAX_CONCURRENT_TURNS` = 20 running turns; beyond it `503 assistant_busy` at once (burst: exactly 10 of 30). With real models a turn lasts seconds to tens of seconds, so this limit, not CPU, decides how many api-assistant pods are needed: concurrent turns ≈ turns/s × mean turn seconds; pods ≈ that / 20 (plus headroom). This laptop run says nothing about real turn durations.
- **Per user:** 6 turns per minute (`429 rate_limited`); a sustained load needs ≥ 10 s between a user's turns (the paced profile).
- **Per tenant:** every turn and every loopback tool call counts against the tenant's API rate (300/min on `standard`, 1 200 on `enterprise`); in this mix a turn costs about 2.7 requests (the turn, 1.5 tool calls on average, the occasional confirm), so a user at the maximum of 6 turns per minute uses about 16 requests per minute and a `standard` tenant reaches its limit with about 18 users chatting at that pace at the same time (beyond it, tool calls fail with `429` inside the turns).
- **Token budgets:** not reached here (generous test budgets); they refuse with `429 assistant_budget_exhausted` in production.
- **Bottlenecks seen:** none saturated at 4–17 turns/s. MySQL (writer: turn, message, execution, audit, usage upserts; replica: tool reads) and Redis (limits, counters, turn locks) are shared with the mail path; the event-loop delay stayed ≤ 20 ms at p99 (max 60 ms during report rendering). The report jobs are fast here because the synthetic organizations have little data; real tenants' report queries are bounded by `REPORTS_QUERY_TIMEOUT_MS`.

## What was not measured

- Real providers (latency, rate limits, streaming behaviour, cost) and real-model tool accuracy (program risk R10; needs a spend approval).
- The RabbitMQ hop of report jobs (relay → `assistant.reports` → `ReportJobConsumer`): covered functionally by `assistant-report-jobs.test.ts`, not timed here; the running local event-relay image predates topology v16.
- SSE streaming through the ingress and the portal BFF, several api/api-assistant pods, Kubernetes (manifests rendered, never applied).
- Production capacity of any kind.

## How to re-run

Prerequisites: the Compose infrastructure (and `pnpm db:seed` once), AC power (on battery use a reduced profile such as `ASSISTANT_LOAD_USERS=5 ASSISTANT_LOAD_TURNS=2` and record it), no other integration suite running against the same database.

```bash
cd apps/api
# default profile: 20 users x 5 turns, 300 ms per model round
ASSISTANT_LOAD_TEST=1 npx vitest run --config vitest.integration.config.ts integration/assistant-load.test.ts
# sustained profile for the side-by-side run (about 60 s of 4 turns/s)
ASSISTANT_LOAD_TEST=1 ASSISTANT_LOAD_USERS=40 ASSISTANT_LOAD_TURNS=6 ASSISTANT_LOAD_PACE_MS=10000 \
  npx vitest run --config vitest.integration.config.ts integration/assistant-load.test.ts
```

Parameters: `ASSISTANT_LOAD_USERS` (20), `ASSISTANT_LOAD_TURNS` (5), `ASSISTANT_LOAD_MIX` (`read=2,chain=1,write=1,report=1`; at most one report per user), `ASSISTANT_LOAD_LATENCY_MS` (300), `ASSISTANT_LOAD_USERS_PER_ORG` (2), `ASSISTANT_LOAD_PACE_MS` (0), `ASSISTANT_LOAD_SIGNAL_PATH` (a file written when the mixed scenario starts).

Side by side with the SMTP benchmark (the smtp-adapter must be reachable at `SMTP_ADAPTER_HOST`, see [smtp-concurrency.md](smtp-concurrency.md); `docker compose --profile smtp-test up -d --wait mail-sink dns-sink smtp-tools`):

```bash
SIG=$(mktemp -u)
(cd apps/api && ASSISTANT_LOAD_TEST=1 ASSISTANT_LOAD_USERS=40 ASSISTANT_LOAD_TURNS=6 ASSISTANT_LOAD_PACE_MS=10000 \
  ASSISTANT_LOAD_SIGNAL_PATH=$SIG npx vitest run --config vitest.integration.config.ts integration/assistant-load.test.ts) &
while [ ! -f "$SIG" ]; do sleep 1; done; sleep 5
(cd tests && npx vitest run integration/smtp-concurrency.test.ts)
wait
# then a baseline in the same conditions (stop the event-relay as the load test does):
docker compose stop event-relay && (cd tests && npx vitest run integration/smtp-concurrency.test.ts); docker compose start event-relay
```

Compare acceptance and stored times with baselines of the **same session and conditions**; run each at least twice (the numbers vary by ±30 % between runs on a laptop).
