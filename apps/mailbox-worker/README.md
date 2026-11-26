# @email-gateway/mailbox-worker

API-mode protection worker (step API-1, [design](../../docs/plan/steps/35-api-mode-protection.md) D4, D5, D7, D10, D11; [ADR-0100](../../docs/architecture/adr/0100-api-mode-intake-mailbox-worker.md)). Records one detection copy per mailbox for journal copies and mailbox change feeds, deduplicates them by Message-ID and mailbox, measures the lag from provider delivery to verdict, keeps the mailbox inventory, and evaluates coverage and connection health. API mode never delivers, forwards or bounces mail (N1); this worker only reads mailboxes in API-1. Deployment: [docs/deployment/mailbox-worker.md](../../docs/deployment/mailbox-worker.md).

Data plane: the MySQL **writer** only (ADR-0014), Redis (budgets, throttle pauses, counters), RabbitMQ as `eg-mailbox` (copies role), the mail bucket (fetched copies; bounded header range reads), provider HTTPS through [`@email-gateway/mailbox-api`](../../packages/mailbox-api/README.md). HTTP `MAILBOX_WORKER_HTTP_PORT` (3087): `/health/live`, `/health/ready`, `/metrics` only.

## Roles (`MAILBOX_WORKER_ROLES`, default `copies,feeds,inventory,health`)

| Role        | Module                                                     | Writes                                                                                                                                                                                  |
| ----------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `copies`    | `src/copies/copies.handler.ts` (queue `email.mailbox`)     | `api_message_copies` (journal copies upserted on UNIQUE (message, received_at, mailbox); feed copies finalized), `api_copy_dedupe_keys`, discovered `api_mailboxes` + addresses, ledger |
| `feeds`     | `src/feeds/feed-runner.ts`, `mailbox-copy.repository.ts`   | mailbox cursors, leases, subscriptions; per fetched copy: `message_identities`, `email_messages` (`mailbox_api`), recipient, history E1/E2, event, pending copy, dedupe ref, outbox     |
| `inventory` | `src/inventory/inventory-runner.ts`, `directory.ts`        | `api_mailboxes` (upsert, adoption, disabled/deleted), `api_mailbox_addresses`, `api_mode_connections.inventory_*` / `mailboxes_total`                                                   |
| `health`    | `src/health/health-job.ts`, `maintenance.ts` (leader lock) | `coverage_state`, `health_*`, audit `api_mode.health_changed`, `notification_alert_windows` + `notification.alert_requested.v1` (`api_mode_unhealthy`), pruning, `api_mode_counters`    |

Shared: `src/domain/` (API-mode state and effective modes, connection context and D4 revocation, mailbox resolution and the hybrid inline lookup), `src/runtime/` (Redis budget `mbx:rb:*`, throttle gate `mbx:throttle:*`, counters `mbx:cnt:*`; the provider runtime with 8.2's token service over the decrypted `*.mailbox_remediation` grant).

## Idempotency (N8)

- Copies: `processOnce` ledger row and every effect in one writer transaction (also for skipped events: the queue is reconciled); copy rows are upserts; the dedupe key is unique per (mailbox, Message-ID hash).
- Feeds: the ingest key `v2:mbx:<sha256(connection|mailbox|provider message)>` makes a replayed page a no-op; the next link is stored after every page; the EML key is deterministic; a dedupe claim of a crashed attempt is taken over.
- Inventory: upserts by (connection, provider user id); address rows replaced with `INSERT IGNORE`.
- Health: transitions with a CAS on the previous status; alerts throttled through `notification_alert_windows` and `health_alerted_at`.
- Counters: Redis `HINCRBY`, flushed by taking each hash atomically and adding it to `api_mode_counters` (failed writes are put back). Counters are best effort (a crash between a commit and the increment loses that increment, never a row).

## Logs

Classified codes, public ids (mailbox, connection), counts and recipient domains only: never tokens, delta links, history ids, client states, Google subjects, subjects, bodies or full addresses.

## Commands

```bash
pnpm --filter @email-gateway/mailbox-worker build typecheck lint test
pnpm --filter @email-gateway/mailbox-worker test:integration   # MySQL writer, Redis, MinIO, RabbitMQ (.env)
pnpm --filter @email-gateway/mailbox-worker dev                # host run, reads ../../.env
```

Integration suites (`integration/`): `copies` (fan-out, discovery, internal, dedupe takeover and seen-journal, hybrid link, lag and fallback, counters, redelivery, skipped events), `feeds-graph` (inventory, delta init/ingest/too large/cursor expiry, notifications and subscriptions, dedupe both orders with the simulator call log, `Retry-After` across two instances, budget isolation between two organizations, revocation), `feeds-gmail` (Directory as delegated admin, history init/continue/404, a backlog beyond the per-run page cap resumed after the processed pages, metadata-first dedupe, size pre-check), `health` (leader lock, coverage, every check, transitions with audit and throttled alerts, pruning, feed sweeps), `custody` (decrypting the grant with 8.2's grant store and token service against the TEST-ONLY fake provider) and `broker` (the copies consumer over a throwaway RabbitMQ vhost). Synthetic `it-apimode-*` organizations only; everything is removed afterwards; nothing reaches a real provider.
