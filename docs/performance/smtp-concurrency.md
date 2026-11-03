# SMTP gateway concurrency results (step 2.2)

Results of the `smtp-source` zero-loss test (`tests/integration/smtp-concurrency.test.ts`, [step 2.2 §9 item 9](../plan/steps/04-smtp-gateway.md#9-test-plan)). It is a **functional durability check on a developer laptop**, not a capacity figure: capacity is measured in step 9.x on production-like hardware.

## What the test does

- `smtp-source -d -s <sessions> -m <messages>` runs in the `smtp-tools` container against the inbound MX `postfix:25`, which runs postscreen, the Rspamd milter and the `inbound` policy check. Each message is about 2 KiB and has one recipient at a fresh fixture domain.
- Postfix delivers every message over LMTP 10050 to smtp-adapter (`lmtp_destination_concurrency_limit = 20`). The adapter stores the EML in MinIO and commits the rows to the MySQL writer.
- **Zero loss** means: no queue entry left for the domain, exactly `<messages>` rows in `email_messages`, `message_identities`, `email_recipients` and `message_outbox`, exactly `<messages>` S3 objects, and `<messages>` distinct Postfix queue ids.
- Sessions and messages come from `SMTP_LOAD_SESSIONS` (default 40) and `SMTP_LOAD_MESSAGES` (default 1 000). The test prints one line, for example `[smtp-concurrency] sessions=40 messages=1000 smtp_accept=9.8s (102.6 msg/s) stored=61.9s (16.2 msg/s end to end) loss=0`.

Run it on its own:

```bash
cd tests && npx vitest run integration/smtp-concurrency.test.ts
```

## Environment

All runs were on 2026-11-02, on macOS with Docker Desktop and an 8 GB VM shared with another project's containers. The branch was `build/platform`, and the Compose infrastructure plus the `smtp-test` profile were running. The target of 40 sessions × 1 000 messages was reached without scaling down.

## Results

"SMTP acceptance" is the time until `smtp-source` exits, when every message has been queued by Postfix. "All stored" is the time until every row and object exists.

| Run                                                   | Adapter                          | Sessions | Messages | SMTP acceptance      | All stored          | Loss |
| ----------------------------------------------------- | -------------------------------- | -------- | -------- | -------------------- | ------------------- | ---- |
| WP6 isolated                                          | host (`host.docker.internal`)    | 40       | 1 000    | 8.5 s (117.7 msg/s)  | 60.6 s (16.5 msg/s) | 0    |
| WP6 full suite run 1                                  | host                             | 40       | 1 000    | 10.8 s (93.0 msg/s)  | 46.8 s (21.4 msg/s) | 0    |
| WP6 full suite run 2                                  | host                             | 40       | 1 000    | 12.5 s (80.1 msg/s)  | 88.8 s (11.3 msg/s) | 0    |
| WP6 final gate                                        | host                             | 40       | 1 000    | 9.6 s (104.5 msg/s)  | 59.7 s (16.8 msg/s) | 0    |
| Verification round 1, `pnpm test:integration`         | host                             | 40       | 1 000    | 10.2 s (97.6 msg/s)  | 44.3 s (22.6 msg/s) | 0    |
| Verification round 1, stack suites                    | container (`smtp-adapter`, apps) | 40       | 1 000    | 10.0 s (100.1 msg/s) | 46.1 s (21.7 msg/s) | 0    |
| Verification round 1, `pnpm test:integration`         | container                        | 40       | 1 000    | 9.8 s (102.6 msg/s)  | 61.9 s (16.2 msg/s) | 0    |
| Verification round 1, `pnpm test:integration` (final) | container                        | 40       | 1 000    | 10.6 s (94.7 msg/s)  | 60.7 s (16.5 msg/s) | 0    |
| Review round (§12.7), `pnpm test:integration`         | host                             | 40       | 1 000    | 9.9 s (101.1 msg/s)  | 52.0 s (19.2 msg/s) | 0    |
| Review round (§12.7), `pnpm test:integration`         | container                        | 40       | 1 000    | 11.3 s (88.6 msg/s)  | 45.4 s (22.0 msg/s) | 0    |

In the container runs the whole `apps` profile was up as well (api, five workers, admin-portal, about 3.6 GB in total across all containers).

## Reading the numbers

- Postfix accepts mail about 6× faster than it can be stored, because SMTP acceptance only writes to the Postfix queue. The difference shows up as queue backlog, and that backlog is always durable (invariant 2: `250` at LMTP only after S3 and the commit).
- End-to-end throughput is bounded by the shared VM: MySQL, MinIO, ClamAV, Rspamd and the apps profile all run in the same 8 GB VM. Running the adapter as a container instead of on the host did not change the result noticeably.
- No run lost a message, and none produced a duplicate row or object.
