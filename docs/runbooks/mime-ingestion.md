# Runbook: MIME ingestion (post-queue parsing)

For platform operators. The email-worker parses every received message after the SMTP `250`: it streams the EML from S3, stores bodies and attachments under `org/{organizationId}/part/…` and commits `email_message_parses`, `email_headers`, `email_attachments`, an `email_events` row and a `mail.message.parsed.v1` or `mail.message.parse_failed.v1` outbox event. Background: [email-worker README](../../apps/email-worker/README.md), design [step 3.1](../plan/steps/06-mime-ingestion.md) M2, M3, M12, M13, [ADR-0022](../architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md), [failure handling](../architecture/failure-handling.md#email-worker-mime-ingestion-step-31).

Parsing never affects mail acceptance, and until step 3.3 it does not change `email_messages.status`. Under the step 2.3 development pass-through (local/CI only), delivery runs independently of parsing.

## Detection

- Metrics on the email-worker's `GET /metrics`:
  - `mime_parse_messages_total{status}`: the outcomes;
  - `mime_parse_failures_total{reason}`: the `parse_failed` reasons;
  - `mime_limit_exceeded_total{limit}`;
  - `mime_retries_total{class}`: failed attempts by dependency (`s3`, `db`, `other`); the log line says `transient: true|false`;
  - `mime_outbox_poll_lag_seconds{consumer}`: how far the feed is behind, the maximum over every shard, including a shard no replica runs (measured from its cursor).
- Logs carry `eventId`, `messageId`, `organizationId`, `status`, codes, counts and `errName`/`errCode`. They never carry content, so search by these ids.
- The parse state of recent messages. Use the writer and a bounded `received_at` range so the partitions prune:

  ```sql
  SELECT status, failure_reason, COUNT(*) AS messages, MIN(started_at) AS oldest_start
    FROM email_message_parses
   WHERE received_at >= NOW() - INTERVAL 2 DAY
   GROUP BY status, failure_reason ORDER BY messages DESC;
  ```

- Received messages without a parse row (not read yet, or the worker is down or behind):

  ```sql
  SELECT m.organization_id, COUNT(*) AS unparsed, MIN(m.received_at) AS oldest
    FROM email_messages m
    LEFT JOIN email_message_parses p ON p.message_id = m.id AND p.received_at = m.received_at
   WHERE m.received_at >= NOW() - INTERVAL 1 DAY AND m.received_at < NOW() - INTERVAL 5 MINUTE
     AND p.id IS NULL
   GROUP BY m.organization_id;
  ```

## Stuck `parsing` rows

A row stays `parsing` only when an attempt did not finish: a crash, an OOM kill, a hang, a deploy during the parse, or a failed attempt that the feed retries with backoff (`MIME_RETRY_BASE_MS`…`MIME_RETRY_MAX_MS`). A transient failure (S3, MySQL or network outage, `S3Stalled`) gives the attempt back, so an outage never fails a message. Any other failed attempt (log line `MIME ingestion attempt failed; it will be retried and counts toward MIME_MAX_ATTEMPTS`, `transient: false`, with `errName`/`errCode`) keeps its attempt: a failure that repeats on every attempt ends as `parse_failed / max_attempts_exceeded` after `MIME_MAX_ATTEMPTS` attempts instead of freezing the cursor.

```sql
SELECT message_id, organization_id, received_at, attempts, started_at, event_id
  FROM email_message_parses
 WHERE status = 'parsing' AND updated_at < NOW() - INTERVAL 10 MINUTE
   AND received_at >= NOW() - INTERVAL 7 DAY
 ORDER BY updated_at LIMIT 100;            -- index (status, updated_at)
```

1. **Check the worker first.** Look at `/health/ready` (mysql, rabbitmq, redis, s3), the restarts of the container or pod, and `mime_retries_total` rising, which points to an S3 or MySQL outage. Fix the dependency. The feed retries the frozen row and the backlog drains by itself, because the cursor never passes a failing row.
2. **A crash loop on one message** shows `attempts` growing with restarts. After `MIME_MAX_ATTEMPTS` (5) started attempts, the next delivery finalizes it as `parse_failed / max_attempts_exceeded` without parsing. Nothing needs to be done, but keep the `message_id` for the parser triage below (a crash on content is a parser bug).
3. **After a crash** the next lock holder re-reads from the cursor, which never moves past a row that was not handled. So the event is delivered again and resumes the row (`attempts + 1`). A row that stays `parsing` while the cursor is already past its outbox row should not happen. It would mean that the outbox row was removed, or that a cursor was edited by hand. To re-drive such a row, reset the cursor (below) while its outbox row still exists. Messages with a final parse row are skipped as duplicates, so only the unfinished ones are parsed. Never set `status` by hand. The worker never changes a final row, so a hand-written final status would hide the message from scanning.

## Cursor reset and shard-count changes

The feed's cursors are in `stream_cursors`:

- with `MIME_OUTBOX_SHARDS = 1`: `outbox:email-worker.mime-parser`, lock `ew:outbox:email-worker.mime-parser`;
- with `n > 1` shards: `outbox:email-worker.mime-parser#<i>/<n>`.

```sql
SELECT name, position_id, updated_at FROM stream_cursors
 WHERE name = 'outbox:email-worker.mime-parser' OR name LIKE 'outbox:email-worker.mime-parser#%';
```

**Reset (re-read from the oldest retained outbox row).** The ledger (`message_idempotency`) and the final parse rows make a re-read free of effects.

1. Stop every email-worker replica. With the apps profile, run `docker compose stop email-worker`. In Kubernetes, scale the deployment to 0.
2. Delete the consumer's cursors:

   ```sql
   DELETE FROM stream_cursors
    WHERE name = 'outbox:email-worker.mime-parser' OR name LIKE 'outbox:email-worker.mime-parser#%';
   ```

3. Start the replicas again. The initial position is `oldest`. Watch `mime_parse_messages_total{status="duplicate"}` climb while the re-read passes the handled rows.

To re-read only from a known point, set `position_id` of the cursor(s) to the outbox id just below it, instead of deleting the cursor(s). Do this while the worker is stopped.

**Changing `MIME_OUTBOX_SHARDS`.** Set the new `MIME_OUTBOX_SHARDS` (and `MIME_OUTBOX_MAX_HELD_SHARDS ≤ MIME_OUTBOX_SHARDS`) and roll the replicas. Each new shard cursor starts at the **minimum** position of the consumer's existing cursors, so rows are re-read, never skipped. When every new shard cursor has moved past that minimum, delete the old cursors:

```sql
DELETE FROM stream_cursors
 WHERE name = 'outbox:email-worker.mime-parser' OR name LIKE 'outbox:email-worker.mime-parser#%/<old n>';
```

Each replica holds at most `MIME_OUTBOX_MAX_HELD_SHARDS` shard locks, so replicas spread the shards. Replicas without a lock idle. **Every shard needs a runner:** keep `replicas × MIME_OUTBOX_MAX_HELD_SHARDS ≥ MIME_OUTBOX_SHARDS` (with rolling deploys and failures in mind). A shard that no replica runs is never parsed; it shows up as a growing `mime_outbox_poll_lag_seconds`, because every poller that does not hold its shard measures that shard's lag from its durable cursor (the age of the oldest row past the cursor beyond the safety lag, at most every 10 s). Raise `MIME_OUTBOX_MAX_HELD_SHARDS` or the replica count (the memory refusal multiplies by `MIME_OUTBOX_MAX_HELD_SHARDS`).

## `parse_failed` triage

`parse_failed` is a recorded content-side outcome. It is never caused by an outage: infrastructure errors are retried, not recorded. The reason is on the parse row (`failure_reason`), the `email_events` `parse_failed` row and the `mail.message.parse_failed.v1` event.

| Reason                  | Meaning                                                                                                        | Action                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eml_missing`           | `GetObject` answered `NoSuchKey` for `eml_object_key`                                                          | The EML was deleted (versioning keeps the old versions: `aws s3api list-object-versions --prefix <key>`) or the key is wrong. Ingestion writes the object before its commit, so treat this as an incident: check bucket lifecycle rules and deletions in the access log                                                                                                                 |
| `eml_key_mismatch`      | `eml_object_key` is not under `org/{organizationId}/`                                                          | A data-integrity or tenant-isolation incident: the row points outside its tenant prefix. Escalate to security. Do not re-drive. A key without any `org/<id>/` prefix is published as `emlS3Key: null` (read the key from the row)                                                                                                                                                       |
| `integrity_mismatch`    | The SHA-256 or byte count of the object differs from `email_messages.eml_sha256` / `size_bytes`                | The object changed after ingestion (an overwrite, or corruption). Compare the object versions. Nothing of the content was recorded. Escalate as an integrity incident                                                                                                                                                                                                                   |
| `max_attempts_exceeded` | `MIME_MAX_ATTEMPTS` attempts started without finishing (crash, OOM, hang) or failed with a non-transient error | Probably a parser defect, a data error (look for the `transient: false` retry lines and their `errCode`, for example `P2000`) or a resource limit. Check the worker's restarts and memory around `started_at`. Reproduce offline with `@email-gateway/mime-parser` on a copy of the EML, inside a secured environment only (the content is untrusted). Never attach the EML to a ticket |
| `parser_error`          | A library exception that the parser did not map to a defect or limit. What was extracted is kept               | A parser bug. Record the `message_id` and parser version, and reproduce offline as above. A fix bumps `PARSER_VERSION`. Re-parsing existing messages is out of scope for step 3.1                                                                                                                                                                                                       |

`parse_limit_exceeded` (`limits_exceeded` on the row) and `parsed_with_defects` (`defects`) are not failures: the message was parsed as far as allowed and the codes go to scanning and policy (4.x, 5.x). `parse_timeout` is recorded only when the message itself was slow: when the parse budget runs out while an S3 call had been pending for at least `min(1 s, budget / 4)`, or after half the budget went to S3 waits, the attempt is retried as `S3Stalled` instead (and `MIME_S3_TIMEOUT_MS`, which must be below `MIME_PARSE_TIMEOUT_MS`, fails a single stalled S3 call first). A wave of `S3Stalled` / `UploadTimedOut` retries (`mime_retries_total{class="s3"}`) means a slow or hung S3; a wave of `parse_timeout` limits points at content or CPU starvation. Compare `mime_parse_duration_seconds` and the S3 latency.

## Do not

- Do not delete `email_message_parses` rows to force a re-parse. The part keys depend on the parser version, and re-parsing is out of scope for step 3.1.
- Do not copy bodies, attachments, subjects or filenames into tickets or logs. Use the ids and codes.
- Do not run the email-worker with `MIME_OUTBOX_SAFETY_LAG_MS` below 30 000. The config refuses it, because the lag must exceed smtp-adapter's ingestion transaction budget.
