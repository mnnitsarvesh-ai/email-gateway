# Runbook: SMTP ingestion persistence failure (S3 or MySQL)

For platform operators. smtp-adapter's LMTP ingestion cannot store messages: the EML upload to S3 (MinIO locally) or the writer transaction fails. Design: [step 2.2 D7/D8](../plan/steps/04-smtp-gateway.md#d7-durable-lmtp-ingestion).

## Detection

- smtp-adapter metrics: `smtp_ingest_s3_errors_total` or `smtp_ingest_db_errors_total` rising; `smtp_ingest_messages_total{outcome="tempfail"}` rising while `stored` stalls.
- smtp-adapter logs: ingestion `outcome: tempfail` with `queueId` and the failing step (never addresses at info level).
- Postfix logs: `status=deferred (host …[…] said: 451 4.3.0 Temporary failure, please retry (in reply to end of DATA command))` with `relay=…:10050`/`:10051`.
- `/health/ready` of smtp-adapter names the failing dependency (`mysql`; S3 is checked by ingestion itself).
- Queue growing: [smtp-queue-backlog.md](smtp-queue-backlog.md).

## Impact

No mail is lost and none is accepted twice: `250` is returned per recipient **only after** the EML is in S3 and the transaction has committed (invariant 2). Postfix keeps the message queued and retries. Partial failures are per organization: only the failed organization's recipients are retried. Orphan S3 objects (upload done, commit failed) are possible; a retry on the same day overwrites the same deterministic key, older ones are reconciled by step 3.2.

## Recovery

1. Identify the store: S3 errors → step 2; DB errors → step 3.
2. **S3 / MinIO**: locally `docker compose ps minio` / `docker compose start minio`; in AWS check the bucket policy, KMS key policy (SSE-KMS), VPC endpoint and the adapter's IAM role (`s3:PutObject`, `s3:CopyObject` source read, `s3:DeleteObject` for duplicate clean-up, `kms:GenerateDataKey`). Check `INGEST_S3_TIMEOUT_MS` is not below the time large messages need.
3. **MySQL writer**: check the writer endpoint, failover state (Aurora/RDS events), connection limits, lock waits (`SHOW ENGINE INNODB STATUS`), and partitions: inserts into `email_messages`/`email_events`/`message_outbox` fail when no partition covers today (`pnpm db:partitions apply`, or the `db-migrate` job). `INGEST_DB_TIMEOUT_MS` bounds each transaction.
4. When the store is back, retry immediately: `docker compose exec postfix postqueue -f` and `docker compose exec postfix-outbound postqueue -f` (otherwise retries follow the backoff).

## Verification

- Postfix logs `status=sent (250 2.0.0 Ok …)` for the previously deferred queue ids; `postqueue -j | wc -l` back to normal.
- Each recovered message stored exactly once: `SELECT organization_id, COUNT(*) FROM email_messages WHERE mta_queue_id = ? GROUP BY organization_id` = one row per organization (the ingest key is per organization and recipient set); a retry after a lost `250` counts as `outcome="duplicate"`, not a new row. A second row for one organization is expected only when Postfix retried a subset of its recipients (one RCPT was deferred while the others were stored, §12.7 of the step design): each recipient is then stored exactly once across the rows.
- `smtp_ingest_messages_total{outcome="stored"}` rising again.

## Never

- Delete queued mail (`postsuper -d`) to "clear" the incident: it is the only copy until ingestion succeeds.
- Switch Postfix's `relay_transport`/`content_filter` to `discard:` or a local file to "unblock" the queue.
- Make ingestion answer `250` before both writes succeed, or `5xx` on infrastructure errors (that bounces customers' mail).
- Delete S3 objects under `org/*/eml/` by hand while messages are queued: their keys are deterministic and may be about to be committed.

## Recorded drill (local stack, 2026-11-02)

This drill was run once by hand during the step 2.2 verification. The `apps` profile was up, smtp-adapter ran as the Compose container and Postfix reached it at `SMTP_ADAPTER_HOST=smtp-adapter`. Mail went to the demo tenant `gateway.test` (organization 2). The recipient address is not shown here. The automated version is `tests/integration/smtp-durability.test.ts`.

1. `docker compose stop minio` at 16:05:48 UTC.
2. `docker compose exec smtp-tools swaks --server postfix --port 25 --to <tag>@gateway.test …`: the inbound MX answered `250 2.0.0 Ok: queued as 4jJGlJ4Ht7z1Yx`. Postfix accepts into its own durable queue first.
3. Postfix log: `postfix/lmtp[896]: 4jJGlJ4Ht7z1Yx: … relay=smtp-adapter[172.23.0.19]:10050, … dsn=4.3.0, status=deferred (host smtp-adapter[…] said: 451 4.3.0 Temporary failure, please retry (in reply to end of DATA command))`.
   - Adapter log: `getaddrinfo ENOTFOUND minio`, then `lmtp ingestion result` with `outcome: tempfail` and `queueId 4jJGlJ4Ht7z1Yx`.
   - `postqueue -j`: `4jJGlJ4Ht7z1Yx deferred host smtp-adapter[…] said: 451 4.3.0 Temporary failure, please retry`.
   - `email_messages WHERE mta_queue_id = '4jJGlJ4Ht7z1Yx'`: 0 rows.
4. `docker compose up -d --wait minio`, then `docker compose exec postfix postqueue -f` at 16:06:14 UTC.
5. Postfix log: `4jJGlJ4Ht7z1Yx: … dsn=2.0.0, status=sent (250 2.0.0 Ok)` with `delay=26`, then `4jJGlJ4Ht7z1Yx: removed`. `postqueue -j` has no entry for the queue id.
6. Exactly one stored copy:

| Check                                                                               | Result                                                                                                                                 |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `email_messages` for the queue id                                                   | 1 row (id 8469, organization 2, 508 bytes, 1 recipient)                                                                                |
| `message_identities` / `email_recipients` / `email_events` for that message         | 1 / 1 / 1                                                                                                                              |
| `message_outbox` for that message                                                   | 1 × `mail.message.received.v1`                                                                                                         |
| S3 objects under the stored `eml_object_key` (`org/2/eml/2026/11/02/fdfedb51….eml`) | 1, `message/rfc822`, 508 bytes. Its SHA-256 `acf9372b…7fcc` equals `email_messages.eml_sha256`, and it contains the test's Subject tag |

The drill message was left in the demo tenant as evidence. It is ordinary local demo data.
