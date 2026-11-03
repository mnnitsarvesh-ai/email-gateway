# Runbook: delivery status log (postfix-outbound maillog → delivery-worker)

For platform operators. Per-recipient delivery status (`delivered`, `deferred`, `bounced`, `expired`) comes from postfix-outbound's delivery log, read by the delivery-worker's status tailer (`PostfixLogTailer`, role `DELIVERY_STATUS_LOG_ENABLED`). This runbook covers a tailer that lags, lines it cannot match, deliveries stuck in `unknown`, log rotation, and a missing log file or volume. Background: [mail routing and delivery tracking](../deployment/mail-routing.md) (log format, rotation, the production sidecar, every line type), design [step 2.3](../plan/steps/05-routing.md) R9/R12/R14.

Commands use Compose service names. On EC2 the log is on the postfix-outbound instance (`/var/log/postfix-outbound/maillog` on the host volume) and the tailer is the delivery-worker **sidecar** of that instance; run the same commands there with `docker exec`.

## How it works (one paragraph)

postlogd appends every delivery attempt to `maillog_file` (`/var/log/postfix-outbound/maillog`, mode 0644). The tailer (one per source id, `GET_LOCK('dw:postfix-log:<DELIVERY_STATUS_LOG_SOURCE_ID>')`) reads appended lines, binds Postfix queue ids to reinjections through the `client=… orig_queue_id=dw1-…` line, applies `sent`/`deferred`/`bounced`/`expired` signals, and commits its cursor (`stream_cursors`: file identity, byte offset, last event time) after the signals. Everything is idempotent (signal keys), so re-reading is safe. Lines of queue ids that are not bound to a reinjection are ignored. Postmaster DSN copies (LMTP 10052) are a second source for failures and delays; the reconciler turns deliveries without any signal for `DELIVERY_STATUS_STALE_AFTER_SECONDS` (6 days) into `unknown`.

## Detection

- `delivery_status_log_lag_seconds` (age of the newest applied line versus now) grows while postfix-outbound keeps logging. Normal: a few seconds; alert above 5 minutes for 10 minutes.
- `delivery_status_signals_total{source="postfix_log",result="unmatched"}` rate rises (lines whose queue id or address has no delivery after `DELIVERY_STATUS_UNMATCHED_RETRY_SECONDS`).
- `delivery_reconciler_actions_total{action=…}` for stale deliveries, and the count of `unknown` deliveries:

  ```sql
  -- reader (replica); last 7 days so partitions prune
  SELECT organization_id, last_error_class, COUNT(*) FROM email_deliveries
   WHERE status = 'unknown' AND received_at >= NOW() - INTERVAL 7 DAY
   GROUP BY organization_id, last_error_class ORDER BY 3 DESC;
  ```

- delivery-worker logs: `warn`/`error` lines from the tailer (file not readable, identity changed, cursor ahead of the file), from the reconciler (`status_signal_missing`).
- The cursor itself: `SELECT name, file_id, file_offset, last_event_at, updated_at FROM stream_cursors WHERE name LIKE 'postfix-log:%';`

## Impact

Mail is not affected: Postfix delivers and retries independently of the tailer. Only the **status** is late: deliveries stay `queued`/`deferred` in the API and the message aggregate does not become `delivered`. After `DELIVERY_STATUS_STALE_AFTER_SECONDS` the reconciler marks them `unknown` (never a guessed `delivered`/`bounced`). Failures and delays still arrive through the postmaster copies (bounce handler), so a lagging tailer hides successes first.

## Recovery

### 1. Tailer lag

1. Is the tailer running at all? `curl -s 127.0.0.1:3040/health/ready` (local) or the sidecar's health; check `DELIVERY_STATUS_LOG_ENABLED=true` on exactly the process that should read this host's log, and that it holds the lock (only one reader per source id; a second one idles by design).
2. Is the file growing? `docker compose exec postfix-outbound sh -c 'ls -li /var/log/postfix-outbound; tail -n 3 /var/log/postfix-outbound/maillog'`. If the file is idle, there is no lag (the metric measures applied lines; check that the lag alert compares with Postfix activity).
3. Is the database the bottleneck? The tailer commits signals in batches through the MySQL **writer**; check writer latency, lock waits on `email_deliveries` and `delivery_status_events`, and the worker's DB errors. A DB outage makes the tailer retry the same batch (at-least-once); it catches up when the writer is back.
4. Restart the tailer process if it is stuck (it resumes from the committed cursor; re-read lines are deduplicated by signal key).

### 2. Unmatched lines

An unmatched line has a queue id or an address that no delivery knows after the retry window.

- **Expected**: lines of messages the worker did not reinject (submissions and relay to the ingestion LMTP hop, DSNs, postmaster copies, mail injected by operators) are **ignored**, not counted as unmatched. Only lines of **bound** queue ids (a `client=… orig_queue_id=dw1-…` line was seen) whose address is not one of the reinjection's recipients count.
- **Binding committed late** (worker crashed after the `250`, reconciler not yet run): retried for `DELIVERY_STATUS_UNMATCHED_RETRY_SECONDS`, then dropped; the reconciler binds the reinjection from the `client=` line it already stored, and the bounce notice or the stale check covers the recipient.
- **Address differs**: Postfix logs the envelope address exactly as received (case preserved; no rewriting on the reinjection listeners, `no_address_mappings`). Matching is case-insensitive on the whole address; a mismatch beyond case is a bug: collect the line and the reinjection row (`delivery_reinjections` by `queue_id`) and open an incident.
- **Parser does not know the line**: unknown formats are ignored and counted, never guessed. Compare with the [line reference](../deployment/mail-routing.md#delivery-log-line-reference) (Postfix upgrade? new `status=` text?).

### 3. Deliveries in `unknown`

`unknown` means "no trustworthy signal": the tailer missed the lines (outage across a rotation, lost file) or the queue file was removed without a final line (`postsuper -d`, a `removed` line while the delivery was not final).

1. Find the queue id: `SELECT outbound_queue_id, status, last_error_class, failure_reason FROM email_deliveries WHERE id = … AND received_at = …;` (or via the API `GET /messages/{id}/deliveries`).
2. Look for it in the current and rotated logs: `zgrep -h '<QID>' /var/log/postfix-outbound/maillog /var/log/postfix-outbound/maillog.*.gz`.
3. If the log has a final line (`status=sent|bounced`, or `status=expired, returned to sender`), the tailer will apply it when it re-reads that file; otherwise the evidence is gone. A late real signal always wins over `unknown` (R9.1), so re-reading is safe: point the cursor of this source back to the start of the uncompressed file that still contains the lines (`UPDATE stream_cursors SET file_offset = 0 WHERE name = 'postfix-log:<source id>';` while the tailer is stopped) and restart it. Rotated `.gz` files are not read by the tailer and step 2.3 has no replay tool for them: if the only final line is inside a `.gz`, the delivery stays `unknown`; use the line as evidence for the tenant (support case) and leave the record as it is.
4. Never set `delivered` by hand. `unknown` is the honest state.

### 4. Rotation

`postfix logrotate` (daily timer on each host) renames `maillog` to `maillog.<YYYYMMDD-HHMMSS>`, HUPs Postfix, and one second later runs `maillog_file_compressor` (`maillog-compress`: makes the new `maillog` 0644, then gzips the old file).

- The tailer keeps its descriptor open, drains the old inode to its end after the rename (even after gzip unlinked it), then switches to the new file at offset 0. A short window where the new file does not exist yet or is still 0600 is retried.
- **New file is 0600** (`EACCES` in the worker log after a rotation): the compressor wrapper did not run (an old image, or a manual `mv` instead of `postfix logrotate`). Fix: `docker compose exec postfix-outbound chmod 0644 /var/log/postfix-outbound/maillog`; then rebuild/redeploy the image. Never make the directory writable for the reader.
- **The tailer was down during a rotation**: lines after its cursor are in `maillog.<suffix>.gz`. See step 3 above; postmaster copies cover failures meanwhile.
- **Disk**: Postfix never deletes rotated files. Keep 7 days: `find /var/log/postfix-outbound -name 'maillog.*.gz' -mtime +7 -delete` (same timer). A full disk stops postlogd from writing (Postfix keeps delivering; status goes `unknown` after the stale window).

### 5. Missing log file or volume

- **Compose**: the directory is a bind mount `${POSTFIX_OUTBOUND_LOG_DIR:-./.local/postfix-outbound-log}`, read-write in postfix-outbound and read-only in the delivery-worker. If the host directory was deleted while the containers ran, postlogd keeps writing to the deleted inode and nobody can read it: `docker compose up -d --force-recreate postfix-outbound` (the entrypoint recreates the directory and the 0644 file), then restart the worker. A worker on the host reads `../../.local/postfix-outbound-log/maillog` relative to `apps/delivery-worker`; check `DELIVERY_STATUS_LOG_PATH` in the local `.env`.
- **EC2**: the host directory must be the same path for postfix-outbound (read-write) and the sidecar (read-only). After an instance replacement the new instance starts a new file: the cursor's file identity no longer matches, the tailer starts the new file from offset 0 under the same source id (or a new id if the instance id is used). Deliveries of the old instance's queue (moved spool, [smtp-gateway.md](../deployment/smtp-gateway.md#drain-and-instance-refresh)) keep their queue ids, so the new instance's lines still match.
- **`maillog_file` not set** (an old image logging to stdout only): nothing to tail. Redeploy the step 2.3 image; until then status comes only from postmaster copies and ends in `unknown`.

## Verification

- `delivery_status_log_lag_seconds` back to a few seconds, `unmatched` rate near zero.
- A test delivery shows `delivered` in `GET /messages/{id}/deliveries` within seconds of its `status=sent` line.
- `stream_cursors.updated_at` advances.

## Never

- Write to, truncate or delete `/var/log/postfix-outbound/maillog` (or make the reader's mount writable). Rotate only with `postfix logrotate`.
- Run two tailers with the same `DELIVERY_STATUS_LOG_SOURCE_ID` against different files (the lock serializes them, but the cursor would flip between files), or give two hosts the same source id.
- Mark deliveries `delivered` or `bounced` in SQL. Use re-reading; `unknown` stays when evidence is gone.
- Delete queue files to "fix" status (`postsuper -d` produces `removed` lines and `unknown` deliveries).
