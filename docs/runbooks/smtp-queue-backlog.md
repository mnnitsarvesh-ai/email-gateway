# Runbook: SMTP queue backlog

For platform operators. A Postfix queue (inbound `postfix` or `postfix-outbound`) grows instead of draining. Background: [SMTP gateway deployment](../deployment/smtp-gateway.md), design [step 2.2](../plan/steps/04-smtp-gateway.md).

Commands use Compose service names; on EC2 run the same commands on the instance (without `docker compose exec <service>`).

## Detection

- Queue size: `docker compose exec postfix postqueue -j | wc -l` (and `postfix-outbound`). Alert on sustained growth, not on a single spike.
- Why mail waits: `docker compose exec postfix postqueue -j | jq -r '.recipients[].delay_reason' | sort | uniq -c | sort -rn | head`.
- Logs: `status=deferred` lines with the reason, e.g. `connect to host.docker.internal[…]:10050: Connection refused` (ingestion down), `451 4.3.0 Temporary failure` (ingestion failed: S3/DB), `Signing key not available` (rspamd-outbound), `Connection timed out` to a tenant server.
- smtp-adapter metrics: `smtp_ingest_messages_total{outcome="tempfail"}`, `smtp_ingest_s3_errors_total`, `smtp_ingest_db_errors_total`, `/health/ready`.

## Impact

Mail is safe: each message is in Postfix's fsynced spool and is retried with `minimal_backoff_time` … `maximal_backoff_time`. Latency grows. After `maximal_queue_lifetime` (5 days) Postfix returns undeliverable mail (inbound: the recipient is returned to the sender; outbound: DSN to the tenant sender plus a bounce notice). The spool disk can fill; Postfix then stops accepting (`452 4.3.1 Insufficient system storage`).

## Recovery

1. **Classify the backlog** with the `delay_reason` summary above.
2. **Ingestion unavailable** (`:10050`/`:10051` refused, `451 4.3.0`): follow [smtp-persistence-failure.md](smtp-persistence-failure.md) or [smtp-policy-service-down.md](smtp-policy-service-down.md). Do not touch the queue.
3. **Unsigned outbound** (`Signing key not available`): follow [smtp-dkim-signing.md](smtp-dkim-signing.md).
4. **One tenant destination down** (outbound reinject-inbound to `smtp:[host]:port`): nothing to do on the gateway; Postfix keeps retrying. Inform the tenant. Check the destination with `docker compose exec postfix-outbound postqueue -j | jq -r 'select(.recipients[].delay_reason | test("HOST")) | .queue_id'`.
5. **Disk space**: check `df -h /var/spool/postfix`; grow the EBS volume (online resize, `resize2fs`/`xfs_growfs`). Do not delete queue files to make room.
6. **Retry now** once the cause is fixed: `docker compose exec postfix postqueue -f` (all) or `postqueue -s <domain>` / `postqueue -i <queue id>` for one destination or message.
7. **Throughput**: if the cause is volume, scale the ASG out (new instances take new sessions; the existing queues drain where they are) and check `lmtp_destination_concurrency_limit` (20) against adapter capacity (`LMTP_MAX_CLIENTS`).

## Verification

- `postqueue -j | wc -l` decreases to the normal level; `status=sent` lines with `relay=…:10050` (or `:10051`, `:10052`) dominate the log.
- smtp-adapter: `smtp_ingest_messages_total{outcome="stored"}` rises, tempfail rate back to ~0.

## Never

- `postsuper -d ALL` (or `-d ALL deferred`): permanently destroys customers' mail that the gateway already accepted with `250`.
- Deleting files under `/var/spool/postfix` or recreating the spool volume (`docker compose down -v`) on a gateway with mail in it.
- `postsuper -r ALL` without a reason: requeues through cleanup again (duplicate milter passes); `postqueue -f` is what you want.
- Raising `maximal_queue_lifetime` on a running incident without understanding why mail is stuck.
