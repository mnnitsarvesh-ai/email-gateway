# Runbook: RabbitMQ messaging (outbox relay, queues, dead letters, reconciliation)

Step 3.2 ([design](../plan/steps/07-rabbitmq.md), [ADR-0023](../architecture/adr/0023-outbox-relay-and-reconciliation.md), [ADR-0024](../architecture/adr/0024-rabbitmq-topology-retry-dead-letter.md)). Every alert of `infrastructure/monitoring/rules/messaging.rules.yml` links a section of this page.

**Rules that hold in every procedure below:**

- The **outbox is the source of truth**. An event exists once its `message_outbox` row commits. Never delete outbox rows, never set `published_at` by hand, never "skip" a row.
- Every consumer is idempotent (`processOnce`, ledger `message_idempotency`): republishing, re-driving or replaying an event is safe; losing one is not.
- Never print or paste credentials (`.env`, secrets). The management API needs the administrator (`RABBITMQ_USER`); services use their role users only.
- Work queues reject publishes when full; the backlog waits in MySQL. Dormant queues drop their oldest messages by design (they are never the source of truth).

## Contents

- [Topology and users](#topology-and-users)
- [Provisioning](#provisioning)
- [Series used by the alerts](#series-used-by-the-alerts)
- Alerts: [OutboxRelayLagHigh](#outboxrelaylaghigh) · [OutboxRelayNoShardOwner](#outboxrelaynoshardowner) · [OutboxPoisonRows](#outboxpoisonrows) · [OutboxUnpublishedOld](#outboxunpublishedold) · [DeadLetterQueueNotEmpty](#deadletterqueuenotempty) · [DeadLetterRateHigh](#deadletterratehigh) · [WorkQueueBacklog](#workqueuebacklog) · [WorkQueueNoConsumer](#workqueuenoconsumer) · [DormantQueueAtLimit](#dormantqueueatlimit) · [AmqpConnectionDown](#amqpconnectiondown) · [RedeliveryRateHigh](#redeliveryratehigh) · [ReconcileExhausted](#reconcileexhausted)
- Procedures: [relay lag and shard ownership](#relay-lag-and-shard-ownership) · [poison rows](#poison-rows) · [broker restart and node loss](#broker-restart-and-node-loss) · [dead-letter inspection and replay](#dead-letter-inspection-and-replay) · [reconciliation exhausted](#reconciliation-exhausted) · [dormant queues](#dormant-queues) · [first-start backlog drain](#first-start-backlog-drain) · [legacy `/` cleanup](#legacy--cleanup) · [node-failure test](#node-failure-test) · [changing shard counts](#changing-shard-counts)

## Topology and users

The full reference (six exchanges, twenty-one quorum queues since topology v11 (step 6.2; twenty since v9), bindings, policies, routing keys, headers) is [docs/architecture/messaging-topology.md](../architecture/messaging-topology.md). In short:

- Vhost **`email-gateway`** (`RABBITMQ_VHOST`). Exchanges `email.ingestion`, `email.security`, `email.policy`, `email.delivery`, `email.archive`, `email.events` (topic; the first five feed `email.events` with `org.#`, the firehose).
- Routing key of every event: `org.<organizationId>.<eventType>`; internal hops: `retry.<queue>.…`, `delay.email.delivery.pending.…`, `dead-letter.<queue>[.…]`.
- Topology **v3** (step 4.1). **Work** queues: `email.received` (email-worker MIME role, ledger `email-worker.mime-parser`), `scan.spam` (email-worker scan role, Rspamd engine, ledger `email-worker.scan.rspamd`, since v3), `email.delivery.pending` (delivery-worker, ledger `delivery-worker.planner`). **Delay**: `email.delivery.retry`. **Dead-letter**: `email.dead-letter`. **Dormant** (no consumer until their stage exists): `scan.url`, `scan.attachment`, `scan.dlp`, `scan.sandbox`, `email.policy.evaluate`, `email.quarantine`, `email.archive`, `email.analytics`; `scan.auth` is dormant and **reserved** (v3: no event binding, only `retry.scan.auth.#`; Rspamd on `scan.spam` supplies SPF/DKIM/DMARC/ARC).
- Since then (each step in [messaging-topology.md](../architecture/messaging-topology.md#status)): v4–v8 turned `scan.attachment`, `scan.url`, `scan.bec`, `scan.dlp` and the sandbox queues into work queues and added `scan.url.inspect`, `scan.url.results`, `scan.sandbox.submissions`, `scan.sandbox.results`. **Topology v9** (step 5.2, [design P15](../plan/steps/16-policy-engine.md#p15-events-and-topology-v9-adr-0044-decision-6)): `email.policy.evaluate` is a **work** queue (policy-engine, ledger `policy-engine.evaluate`, the delivery gate: never purge it), new work queue `email.notifications` (notification-worker, ledger `notification-worker.policy`), `email.archive` (still dormant, 8.1) binds `mail.message.archive_requested.v1` on `email.archive` instead of `mail.policy.decided.v1`. Dormant now: `scan.auth` (reserved), `email.quarantine`, `email.archive`, `email.analytics`.

| User (`.env` key)                                      | Used by                     | Can                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------ | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RABBITMQ_USER` (administrator)                        | init, tests, operators      | everything (management UI/API)                                                                                                                                                                                                                                                                                                               |
| `RABBITMQ_RELAY_USER` = `eg-relay`                     | event-relay                 | publish event keys `org.<id>.…` to the six exchanges                                                                                                                                                                                                                                                                                         |
| `RABBITMQ_EMAIL_WORKER_USER` = `eg-email-worker`       | email-worker                | publish `retry.email.received.…` / `dead-letter.email.received…`, read `email.received`                                                                                                                                                                                                                                                      |
| `RABBITMQ_SCANNER_USER` = `eg-scanner`                 | email-worker scan role      | publish `retry.scan.spam.…` to `email.security` / `dead-letter.scan.spam…` to `email.events`, read `scan.spam` (v3)                                                                                                                                                                                                                          |
| `RABBITMQ_DELIVERY_WORKER_USER` = `eg-delivery-worker` | delivery-worker             | publish `retry.`/`delay.email.delivery.pending.…` / `dead-letter.email.delivery.pending…`, read `email.delivery.pending`                                                                                                                                                                                                                     |
| `RABBITMQ_POLICY_ENGINE_USER` = `eg-policy-engine`     | policy-engine (v9)          | publish `retry.email.policy.evaluate.…` to `email.policy` / `dead-letter.email.policy.evaluate…` to `email.events`, read `email.policy.evaluate` (no event key: decisions and approvals go through the outbox)                                                                                                                               |
| `RABBITMQ_NOTIFICATION_USER` = `eg-notification`       | notification-worker (v9)    | publish `retry.email.notifications.…` to `email.policy` / `dead-letter.email.notifications…` to `email.events`, read `email.notifications`                                                                                                                                                                                                   |
| `RABBITMQ_WEBHOOK_USER` = `eg-webhook`                 | webhook-worker fanout (v11) | publish `retry.email.webhooks.…` / `dead-letter.email.webhooks…` to `email.events`, read `email.webhooks` (public webhook deliveries are HTTPS, not broker messages; alert requests go through the outbox)                                                                                                                                   |
| `RABBITMQ_OPS_USER` = `eg-ops`                         | api (dead-letter replay)    | publish `retry.email.received.…` to `email.ingestion`, `retry.email.delivery.pending.…` to `email.delivery`, (v3–v8) `retry.scan.<work queue>.…` to `email.security` (v9, v10) `retry.email.(policy.evaluate\|notifications\|quarantine).…` to `email.policy` and (v11) `retry.email.webhooks.…` to `email.events`, read `email.dead-letter` |

No service user can declare anything (`configure = ^$`); services verify passively and stay **not ready** while an object is missing. The routing-key limits are RabbitMQ **topic permissions** (`rabbitmqctl list_topic_permissions -p email-gateway`), set and verified exactly by `init.mjs --users` (step 3.2 review round 1): only the relay can publish an event key. A publish outside its keys closes the channel with `ACCESS_REFUSED` (a `403` in the service's log); after a credential leak, rotate the password and re-run `pnpm rabbitmq:init` (the planner still refuses approvals the gateway never issued: dead letters `approval_not_issued` / `approval_mismatch`).

## Provisioning

`infrastructure/rabbitmq/init.mjs` is the only provisioning code (idempotent; never prints credentials):

- Compose: the one-shot `rabbitmq-init` service runs `node /rabbitmq/init.mjs --users --cleanup-legacy` after `rabbitmq` is healthy; every app service waits for it.
- Host: `pnpm rabbitmq:init` (vhost, definitions from `infrastructure/rabbitmq/definitions.json`, role users and permissions from `.env`).
- Changing the topology: edit `packages/event-contracts/src/topology.ts`, run `pnpm --filter @email-gateway/event-contracts topology:export`, review the diff of `definitions.json`, re-run the init. Queue arguments are only `x-queue-type: quorum`; everything else is a policy, so a policy change never needs a re-declare.
- **Removed bindings** (since v3): after the import the init removes every binding whose destination is a topology queue or exchange and that `definitions.json` does not declare, and logs each one (`removed binding <source> -> queue:<queue> [<key>]`) and the count; bindings of objects outside the topology are never touched. To see what a run would remove without changing anything: `node --env-file=.env infrastructure/rabbitmq/init.mjs --prune-dry-run`. The verification then requires exactly the definitions' bindings.
- **Upgrading to v3** (step 4.1): the `.env` needs `RABBITMQ_SCANNER_USER` / `RABBITMQ_SCANNER_PASSWORD` (and `RABBITMQ_SCANNER_URL` for the email-worker); `pnpm rabbitmq:init` then switches `scan.spam` to the work policy, removes the two `scan.auth` event bindings, creates `eg-scanner` and extends `eg-ops`. Expected log: 2 bindings removed on the first run, 0 afterwards; `verified email-gateway: 6 exchanges, 14 quorum queues with policies, 35 bindings, 5 role users`. A `scan.spam` that held messages as a dormant buffer keeps them; the scan role consumes them and skips rounds whose message has already moved on (stale, no effect).
- **Upgrading to v11** (step 6.2): the `.env` needs `RABBITMQ_WEBHOOK_USER` / `_PASSWORD` / `_URL` (`.env.example` section "Webhooks and notifications", password `__GENERATE__`); `docker compose up rabbitmq-init` (or `pnpm rabbitmq:init`) declares `email.webhooks` with its policy and nine bindings, binds `notification.alert_requested.v1` to `email.notifications`, creates `eg-webhook` and extends `eg-ops` (write `email.events`, topic `^retry\.email\.webhooks\.`). Expected: `verified email-gateway: 6 exchanges, 21 quorum queues with policies, 58 bindings, 10 role users`. Until a webhook-worker consumes, `email.webhooks` accumulates every relayed source event (bounded at 1 000 000): start the worker, or purge `email.webhooks` **by name** if events queued before any subscription existed (nothing is lost: an event is delivered only to subscriptions that existed when it occurred). **Do not add `email.webhooks` to `RECONCILE_QUEUES`** (no-op events leave no ledger row, ADR-0055).
- **Upgrading to v9** (step 5.2): the `.env` needs `RABBITMQ_POLICY_ENGINE_USER` / `_PASSWORD` / `_URL` and `RABBITMQ_NOTIFICATION_USER` / `_PASSWORD` / `_URL` (`.env.example`, passwords `__GENERATE__`; Compose passes the user/password pairs to `rabbitmq-init`); `pnpm rabbitmq:init` (or `docker compose run --rm --no-deps rabbitmq-init`; the one-shot mounts `infrastructure/rabbitmq` read-only, no image build) then imports `email.notifications`, replaces the `eg.email.policy.evaluate` policy (dormant drop-head → work reject-publish), removes `email.archive`'s `org.*.mail.policy.decided.v1` binding, creates `eg-policy-engine` and `eg-notification` and extends `eg-ops`. Expected log: `removed binding email.policy -> queue:email.archive [org.*.mail.policy.decided.v1]`, 1 binding removed on the first run, 0 afterwards; `verified email-gateway: 6 exchanges, 20 quorum queues with policies, 47 bindings, 9 role users`. Until the policy-engine consumes, `email.policy.evaluate` accumulates `scanned.v1`/`parse_failed.v1` events (bounded at 1 000 000, `WorkQueueNoConsumer` may fire); the engine evaluates them when it starts and skips those whose message has moved on (stale lifecycle edge, ledger row only).

## Series used by the alerts

Application series (§5.3) come from `/metrics` of event-relay (`:3070`), email-worker (`:3020`), delivery-worker (`:3040`) and api. Broker series come from the Prometheus job `rabbitmq-detailed` (`rabbitmq:15692/metrics/detailed?vhost=email-gateway&family=queue_coarse_metrics&family=queue_consumer_count`). The names were verified against the running RabbitMQ 4.1.8 broker (step 3.2 WP3, `curl http://127.0.0.1:${RABBITMQ_PROMETHEUS_HOST_PORT}/metrics/detailed?...`; port 15692 needs no credentials):

| Series                                                                             | Labels                                          | Meaning                         |
| ---------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------- |
| `rabbitmq_detailed_queue_messages_ready`                                           | `vhost`, `queue`                                | ready messages                  |
| `rabbitmq_detailed_queue_messages_unacked`                                         | `vhost`, `queue`                                | delivered, not yet acknowledged |
| `rabbitmq_detailed_queue_messages`                                                 | `vhost`, `queue`                                | ready + unacked (queue depth)   |
| `rabbitmq_detailed_queue_consumers`                                                | `vhost`, `queue`                                | consumers                       |
| `rabbitmq_detailed_queue_process_reductions_total`, `rabbitmq_detailed_queue_info` | `vhost`, `queue` (+ `queue_type`, `membership`) | not used by the rules           |

Validate the configuration and rules after any change (no profile needs to run):

```sh
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool prom/prometheus:v3.6.0 check config /m/prometheus.yml
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool prom/prometheus:v3.6.0 check rules /m/rules/messaging.rules.yml
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool prom/prometheus:v3.6.0 test rules /m/tests/messaging.rules.test.yml
```

Useful read-only SQL (writer; never prints payloads):

```sql
-- Unpublished, non-poison rows per event type and their age (RELAY_MAX_ATTEMPTS = 10 by default)
SELECT event_type, COUNT(*) AS n, MIN(created_at) AS oldest
FROM message_outbox WHERE published_at IS NULL AND attempts < 10 GROUP BY event_type;
-- Poison rows (codes only)
SELECT id, created_at, event_id, organization_id, event_type, aggregate_type, aggregate_id, attempts, last_error
FROM message_outbox WHERE published_at IS NULL AND attempts >= 10 ORDER BY id LIMIT 100;
-- Rows in backoff after nacks / returns
SELECT last_error, COUNT(*), MIN(available_at), MAX(attempts)
FROM message_outbox WHERE published_at IS NULL AND attempts BETWEEN 1 AND 9 GROUP BY last_error;
-- Shard locks and the reconciler lock (holder connection ids; NULL = nobody)
SELECT IS_USED_LOCK('er:relay#0/4'), IS_USED_LOCK('er:relay#1/4'), IS_USED_LOCK('er:relay#2/4'),
       IS_USED_LOCK('er:relay#3/4'), IS_USED_LOCK('er:reconciler');
```

---

## OutboxRelayLagHigh

`max by (shard) (outbox_relay_lag_seconds) > 60` for 5 minutes: the oldest publishable row of a shard waited more than a minute.

**Diagnosis**

1. Is the relay up and does it hold the shard? See [OutboxRelayNoShardOwner](#outboxrelaynoshardowner) and `outbox_relay_shards_held` per replica.
2. Is the broker accepting publishes? `amqp_connection_up{connection="event-relay"}`, `amqp_connection_blocked` (memory/disk alarm), `amqp_publish_total{outcome}` (`nacked` = a full work queue, `timeout` = lost confirms), `outbox_relay_failures_total{reason}`.
3. Is MySQL slow or failing? `outbox_relay_failures_total{reason="database"}`, `outbox_relay_batch_seconds`.
4. Is a row in a long backoff holding back its aggregate? Rows with `attempts > 0` (query above): the lag of a shard counts from its oldest row, including rows in backoff.

**Action**

- Broker blocked or nacking: free the resource (see [WorkQueueBacklog](#workqueuebacklog); a full work queue rejects publishes by design). The relay resumes on its own.
- Broker or database down: fix it; the relay backs off (equal jitter, up to `RELAY_BROKER_BACKOFF_MAX_MS`) and drains when it returns. Nothing is lost.
- Throughput: more replicas (shards ≤ replicas × `RELAY_MAX_HELD_SHARDS`), larger `RELAY_BATCH_SIZE`, or more shards ([changing shard counts](#changing-shard-counts)).

## OutboxRelayNoShardOwner

Fewer shard locks are held (sum of `outbox_relay_shards_held`) than shards exist (distinct `shard` labels of `outbox_relay_lag_seconds`), or no event-relay target is up.

**Diagnosis:** `kubectl get pods -l app.kubernetes.io/name=event-relay` / `docker compose ps event-relay`; `/health/ready`; `RELAY_SHARDS` vs replicas × `RELAY_MAX_HELD_SHARDS`; the lock query above (a lock held by a connection that is not an event-relay, e.g. a paused test process, blocks the shard).

**Action:** restore the replicas, or raise `RELAY_MAX_HELD_SHARDS` so the running replicas can cover every shard. A lock of a dead session is released by MySQL when the session ends; `KILL <connection id>` of a stuck foreign holder releases it at once (only after confirming it is not a live relay). See [relay lag and shard ownership](#relay-lag-and-shard-ownership).

## OutboxPoisonRows

`outbox_poison_rows > 0`: rows reached `RELAY_MAX_ATTEMPTS` and are excluded from publishing. Their events never reach a consumer, and their daily partitions cannot be dropped (the drop guard refuses partitions with unpublished rows). Follow [poison rows](#poison-rows).

## OutboxUnpublishedOld

`outbox_unpublished_oldest_seconds > 900` for 5 minutes (reconciler view across all shards): the same causes as [OutboxRelayLagHigh](#outboxrelaylaghigh), seen from the outbox. Also check that the reconciler runs (`reconcile_run_seconds_count` increasing, one replica holds `er:reconciler`): without it this gauge is stale. The reconciler's unconsumed sweep stops at the oldest unpublished row, so re-drives pause until the relay catches up.

## DeadLetterQueueNotEmpty

`email.dead-letter` holds messages for 10 minutes. A consumer gave up on them (`fatal` codes, `max_attempts_exceeded`, `retry_age_exceeded`) or the broker dead-lettered a crash loop (`delivery_limit`). Follow [dead-letter inspection and replay](#dead-letter-inspection-and-replay).

## DeadLetterRateHigh

`sum(rate(amqp_consumer_dead_lettered_total[5m])) > 0.1` for 10 minutes. Break it down by `queue` and `reason`:

- `contract_invalid`, `unknown_event_type`, `unsupported_schema_version`: a producer/consumer contract mismatch (a deploy rolled one side only). Roll back or finish the rollout; then replay.
- `tenant_mismatch`: routing key, header and envelope disagree; a bug or a forged message. Do **not** replay before the cause is understood; escalate to security.
- `max_attempts_exceeded`: a stage fails deterministically for some messages; read the worker logs (`errName`, `errCode`, `eventId`) and fix the cause, then replay.
- `retry_age_exceeded`: a dependency was down longer than the queue's `maxRetryAge` (24 h / 48 h); fix the dependency, then replay.

## WorkQueueBacklog

More than 10 000 ready messages on a work queue (`email.received`, `scan.spam`, `email.delivery.pending`, …; v9: `email.policy.evaluate`, `email.notifications`) for 10 minutes. A backlog on `email.policy.evaluate` means mail is **held undelivered** (no approval without an evaluation): treat it as a delivery outage (policy-engine runbook). For `scan.spam` see also the scan pipeline runbook (`ScanQueueBacklog`, Rspamd slow or down, circuit breaker). Consumers are too slow or stalled: worker readiness, `amqp_consumer_in_flight` (≤ prefetch), `amqp_consumer_handle_seconds`, `amqp_consumer_retries_total{class="transient"}` (a dependency outage holds deliveries). Scale the worker (competing consumers) or fix the dependency. At `max-length` (1 000 000) the queue rejects publishes: the relay keeps rows unpublished with backoff (`last_error = nacked`) and drains them later. Do not purge a work queue.

## WorkQueueNoConsumer

A work queue has had no consumer for 5 minutes: the worker is down, not ready (it subscribes only while its role user can read the queue), or cannot reach the broker ([AmqpConnectionDown](#amqpconnectiondown)). Messages wait in the queue; restart or fix the worker. Check that its role user and permissions exist (`pnpm rabbitmq:init` re-applies them).

## DormantQueueAtLimit

A dormant queue (no consumer until its stage exists) holds ≥ 9 000 of its 10 000 messages: with `overflow: drop-head` the oldest are being discarded. **Expected** while the stage is not built; see [dormant queues](#dormant-queues). Act only if the queue's stage is supposed to be live (then its policy should be `work`, not `dormant`).

## AmqpConnectionDown

`amqp_connection_up == 0` for 2 minutes for a service connection. The client reconnects on its own (equal-jitter backoff, rotating through the URLs of its list); the process never exits on a broker failure. Check the broker (`docker compose ps rabbitmq`, `rabbitmq-diagnostics status`), the network, and the service's URL key (`RABBITMQ_RELAY_URL`, `RABBITMQ_EMAIL_WORKER_URL`, `RABBITMQ_DELIVERY_WORKER_URL`): an `ACCESS_REFUSED` in the logs (`errCode`) means a wrong or missing role user (re-run `pnpm rabbitmq:init`). While it lasts, producers keep writing the outbox and the relay publishes later.

## RedeliveryRateHigh

More than 10 % of a queue's deliveries are redeliveries for 10 minutes: consumers crash or lose channels mid-message, or requeue on shutdown during rolling restarts. Check worker restarts (OOM kills, crash loops) and channel errors in the logs. A crash loop on one message ends in `email.dead-letter` through the queue's `delivery-limit` (20); the MIME poison guard bounds MIME crash loops earlier.

## ReconcileExhausted

The reconciler re-drove published events `RECONCILE_MAX_REDRIVES` times and their queue's consumer still has no ledger row. Follow [reconciliation exhausted](#reconciliation-exhausted).

---

## Relay lag and shard ownership

- Rows are split into `RELAY_SHARDS` shards by `MOD(CRC32(CONCAT(aggregate_type, ':', aggregate_id)), RELAY_SHARDS)`; a replica publishes a shard only while it holds `GET_LOCK('er:relay#<i>/<n>')` on its lock connection, at most `RELAY_MAX_HELD_SHARDS` locks.
- **Shards ≤ replicas × `RELAY_MAX_HELD_SHARDS`**, else some shard has no owner. Each replica reports `outbox_relay_lag_seconds{shard}` for every shard (for unowned shards from `MIN(created_at)` every 10 s), so an unowned shard shows a growing lag everywhere.
- Rows of one shard of a given aggregate: `SELECT MOD(CRC32(CONCAT('message', ':', '<aggregate_id>')), 4);`.
- A replica that loses its lock connection loses its locks; another replica may take the shard while the first finishes its batch: duplicates only (marking is `WHERE published_at IS NULL`; ledgers absorb the copy).

## Poison rows

A poison row has `attempts ≥ RELAY_MAX_ATTEMPTS` and `published_at IS NULL`. A broker nack (a full work queue, a queue without quorum) never counts as an attempt: such rows keep `last_error = 'nacked'` with a growing `available_at` and are published once the queue accepts again (step 3.2 review round 1). `last_error` of a poison row holds a code:

| `last_error`                                                                                                          | Cause                                                                                          | Fix                                                                                           |
| --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `unknown_event_type`                                                                                                  | the type is not in the event registry, or is reserved (`mail.attachment.sandbox_requested.v1`) | deploy the producer/registry change that defines it, or the event was never valid (see below) |
| `contract_invalid`                                                                                                    | the stored payload (or envelope: correlation id, event id) fails the registry schema           | a producer bug or a schema change without a new version; fix the schema/producer              |
| `forbidden_field`, `mime_content`, `base64_blob`, `binary_value`, `oversized_string`, `too_deep`, `message_too_large` | the content guard refused it: the stored payload carries content or is too large               | a producer bug (bodies never belong on the bus or in the outbox); fix the producer            |
| `unroutable` (at the maximum)                                                                                         | the broker returned it `RELAY_MAX_ATTEMPTS` times (no binding for its key)                     | fix the bindings                                                                              |

**Procedure**

1. List the rows (query in [series](#series-used-by-the-alerts); codes only). Find the producer from `event_type` and `aggregate_type`, and the deploy that introduced it.
2. Fix the cause (deploy). Do not edit the payload by hand unless a reviewed data fix exists for that exact case.
3. Make the rows publishable again with a **reviewed** `UPDATE` (two people; record it in the incident). It changes the relay's bookkeeping only:

   ```sql
   -- Review the exact id list first; never run it without the ids.
   UPDATE message_outbox
   SET attempts = 0, available_at = NOW(3), last_error = NULL
   WHERE published_at IS NULL AND attempts >= 10 AND id IN (/* reviewed ids */);
   ```

   The relay publishes them in id order on its next pass; if they are still invalid they become poison again with the same code (nothing is published).

4. A row that can never be valid (e.g. a type that was never defined): leave it and document the decision in the incident; it keeps its partition until it ages out of the drop guard's review. Rows are never deleted by the relay or this runbook.

## Broker restart and node loss

- **Restart** (`docker compose restart rabbitmq`, upgrade): every client sees its connection close, marks itself disconnected (`amqp_connection_up = 0`, readiness red), and reconnects with backoff. The relay writes nothing for unconfirmed publishes and republishes them later (duplicates are absorbed). Consumers' unacked deliveries return to their queues (redelivered). Quorum queues are durable; nothing is lost.
- **Node loss in a cluster** (production; the local `rabbitmq-cluster` profile reproduces it): quorum queues elect a new leader among the remaining nodes (majority required). Clients rotate through the URLs of their list (`RABBITMQ_*_URL` with comma-separated nodes). Confirms of in-flight publishes may be lost → `timeout` → republished.
- **Memory/disk alarm** (`amqp_connection_blocked = 1`): the broker blocks publishers; the relay waits (backs off) instead of piling up publishes. Free memory/disk (consumers draining, larger disk); the alarm clears on its own.
- After the broker is back: `outbox_unpublished_rows` drains, `amqp_connection_up = 1` everywhere, work queues get consumers again.

## Dead-letter inspection and replay

`email.dead-letter` keeps every message until it is replayed: its policy sets `delivery-limit: -1`, so dry runs and filtered replays that return messages (`nack` with requeue counts as a delivery) never make the broker drop one (review round 1; RabbitMQ 4.x would otherwise drop a message after 20 returns). Reasons specific to approvals: `approval_not_issued` (no outbox row with that event id, type and organization: a forged approval, or one older than the 7-day outbox retention) and `approval_mismatch` (the row exists, the payload differs); never replay these without finding out who published them. It receives copies published by consumers (`dead-letter.<queue>.org.<id>.<eventType>`, headers `x-eg-source-queue`, `x-eg-failure-reason`, `x-eg-failure-class`, `x-eg-attempts`, `x-eg-dead-lettered-at`, `x-eg-dead-lettered-by`) and broker dead letters (`dead-letter.<queue>`, `x-death` / `x-first-death-reason: delivery_limit`).

1. **Count:** `GET /api/v1/platform/dead-letters` (permission `platform:operations`, user session) → `{ queue, messages, consumers }`.
2. **Inspect** without removing anything: a dry run of the replay lists the matching messages (ids, type, organization public id, source queue, failure reason):

   ```http
   POST /api/v1/platform/dead-letters/replay
   { "sourceQueue": "email.received", "limit": 100, "dryRun": true, "reason": "INC-123 inspect parse failures" }
   ```

   Filters: `eventType`, `organizationId` (organization **public id**), `failureReason`. The management UI ("Get messages", ack mode "Nack message requeue true") shows headers too; never use "Purge".

3. **Fix the cause first** (deploy, dependency). Replaying a deterministic failure just dead-letters it again.
4. **Replay:** the same call with `"dryRun": false` (permission `platform:dead_letter_replay`, **MFA**, user session only; API keys and override tokens are refused). One replay runs at a time platform-wide (409 `replay_in_progress`). Each matched, valid message is republished unchanged to the source queue's home exchange with `retry.<queue>.org.<id>.<eventType>`, attempt counters reset and `x-eg-replay-*` headers, confirmed, and only then acked out of the dead-letter queue. Everything else is requeued. Only work queues (`email.received`, `scan.spam` since topology v3, `email.delivery.pending`) are replayable.
5. Every replay (dry runs included) writes an `audit_logs` row: action `platform.dead_letters_replayed` (the api's `<resource>.<verb>` naming, D14; design Q9 wrote `platform.dead_letters.replay`), `resource_type: queue`, `resource_id: <source queue>`, metadata with `replayId`, filters, counts, `reason`, `outcome` (`complete` | `partial`) and up to 100 event ids. Find a replay with `SELECT created_at, actor_id, metadata FROM audit_logs WHERE action = 'platform.dead_letters_replayed' AND created_at >= NOW() - INTERVAL 1 DAY ORDER BY id DESC;`. Replayed events keep their `eventId`: a consumer that already applied one records a ledger duplicate.
6. Invalid dead letters (`skipped.invalid`) stay in the queue; they need a code fix or a documented decision.

## Reconciliation exhausted

The reconciler (single instance, `GET_LOCK('er:reconciler')`) re-drives a published event of a tracked queue (`RECONCILE_QUEUES`) that has no ledger row of the queue's consumer after `RECONCILE_UNCONSUMED_AFTER_SECONDS`, up to `RECONCILE_MAX_REDRIVES` times; then it logs a warning with `outboxId`, `eventId`, `eventType`, `queues`, `redriveCount` and counts `reconcile_exhausted_total{queue}`.

1. Find the ids in the reconciler log (event-relay, `component: outbox-reconciler`, message "exhausted its re-drives").
2. Was the event delivered? Search the consumer's logs by `eventId`/`correlationId`, and its progress: `SELECT consumer, state, reason, attempt, transient_retries, updated_at FROM message_consumer_progress WHERE event_id = ?;`. An event its consumer dead-lettered (`state = 'dead_lettered'`) is settled by the reconciler and never reported here, unless the reason is one a relay copy cannot produce (`contract_invalid`, `unknown_event_type`, `unsupported_schema_version`, `tenant_mismatch`, `approval_not_issued`, `approval_mismatch`): then someone published a forged or altered copy with this event id, so treat it as a security event as well; recover it with [replay](#dead-letter-inspection-and-replay).
   Not every unconsumed row is re-driven: rows whose event is still retrying (`state = 'retrying'`, recent `updated_at`) or whose queue still has ready messages, or whose depth could not be read, are **deferred** (`reconcile_skipped_total{reason="retrying"|"queue_backlog"|"queue_unknown"}`) and judged again later, so a consumer outage or a long backlog does not multiply events. A steadily growing `queue_unknown` means the relay cannot reach the broker.
3. Typical causes: the consumer was down for longer than all re-drives (fix it; then make the row due again: `UPDATE message_outbox SET published_at = NULL, available_at = NOW(3) WHERE id = ? AND created_at = ? AND published_at IS NOT NULL` — a reviewed, single-row change that lets the relay republish the same event id); a consumer path that handles an event without writing a ledger row (a bug: every handled event must leave one); the event's message was purged.
4. Planned-but-not-reinjected deliveries are the step 2.3 `DeliveryReconciler`'s, not this one's.

### `email.policy.evaluate` and `email.notifications` replay and reconciliation (step 5.2)

- **Replay.** Both are work queues (topology v9), so `REPLAYABLE_QUEUES` covers them: a dry run with `"sourceQueue": "email.policy.evaluate"` (or `"email.notifications"`) lists the dead letters; the replay republishes with `retry.email.policy.evaluate.org.<id>.<eventType>` (resp. `retry.email.notifications.…`) to `email.policy` (`eg-ops` topic permission `^retry\.email\.(policy\.evaluate|notifications)\.` since v9; never `email.quarantine`, never an event key). A replayed `scanned.v1` / `parse_failed.v1` whose round was already evaluated, or whose message has moved on (rescan, release, deadline), is a stale no-op (lifecycle edge not applied, ledger row only); one evaluation per round is guaranteed by the lifecycle transition key and the unique key of `policy_execution_logs`. A replayed notification may send its mail again (at least once; same `Message-ID`).
- **Dead letters to expect.** `email.policy.evaluate`: a policy input defect (`PolicyInputError`, non-retryable: the message stays held; fix the producer, then replay), `retry_age_exceeded` after a long database/S3 outage. Never purge either queue: the policy-engine queue is the delivery gate.
- **Reconciliation.** `trackedQueues` derives `policy-engine.evaluate` (`scanned.v1`, `parse_failed.v1`) and `notification-worker.policy` (`notification_requested.v1`) from the topology; add the queue to `RECONCILE_QUEUES` once its consumer runs (step 5.2 WP3/WP4), never before (an unconsumed queue would only produce re-drives and `ReconcileExhausted`).

### `email.webhooks` replay, backlog and reconciliation (step 6.2)

- **Replay.** A work queue (topology v11): a dry run with `"sourceQueue": "email.webhooks"` lists the fanout's dead letters (`webhook_payload_unsafe`, `webhook_payload_invalid`: programming errors, fix and redeploy first; `inconsistent_read` after the retry budget); the replay republishes with `retry.email.webhooks.org.<id>.<eventType>` on `email.events` (the `ops` topic grant). Deliveries to tenant endpoints are **not** broker messages: their dead letters are `webhook_deliveries` rows with `status = dead`, replayed by the tenant through `POST /api/v1/webhooks/{id}/deliveries/{deliveryId}/replay` or `/replays` ([webhooks runbook](webhooks.md)).
- **Not reconciled** (ADR-0055 decision 13): the fanout acks no-op events without a ledger row, so `email.webhooks` is never in `RECONCILE_QUEUES`.
- **Backlog** (`WebhookFanoutBacklog`, warning > 100 000, critical > 500 000 ready for 10 min): ~10 events per message arrive here; at 1 000 000 the broker nacks the relay's publishes (`reject-publish`), which stalls the whole publish. Scale the fanout first; as a last resort unbind the source keys temporarily with `rabbitmqctl` (procedure in [webhooks.md](webhooks.md#webhookfanoutbacklog)) and rebind before the queue is needed again (events published while unbound are not delivered as webhooks).

### `scan.spam` replay and reconciliation (step 4.1)

- **Reconciliation.** With `RECONCILE_QUEUES` including `scan.spam` (`email.received,email.delivery.pending,scan.spam`), a published `mail.message.parsed.v1` or `mail.message.rescan_requested.v1` without a ledger row of `email-worker.scan.rspamd` after `RECONCILE_UNCONSUMED_AFTER_SECONDS` is re-driven through its outbox row (the relay republishes it with its own `org.` key, so it reaches every bound queue again; the other consumers' ledgers absorb the duplicate). A scan delivery that is still retrying (Rspamd outage: non-final attempt rows, `message_consumer_progress.state = 'retrying'`) is deferred, not re-driven. A redelivered or re-driven event never creates a second final result or transition: the scan stage's ledger, the final-row unique key and the completion transition key make it a duplicate.
- **Dead letters.** `scan.spam` dead-letters only when the broker budget runs out before the stage finalizes (it never should: `SCAN_RSPAMD_MAX_ATTEMPTS` < the queue's 10 attempts, and the round deadline sweeper finalizes a stuck round as `scan_failed`), on a contract failure, or after a crash loop (`delivery_limit`). Inspect with a dry run (`"sourceQueue": "scan.spam"`); replay republishes with `retry.scan.spam.org.<id>.<eventType>` to `email.security` (`eg-ops` topic permission since v3). A replayed event of a round that has already completed (`scanned`/`scan_failed`) or that a rescan superseded is a stale no-op; to scan a message again after an outage, use the administrative rescan API, not a replay.

## Dormant queues

Since topology v9: `email.quarantine` (5.3), `email.archive` (8.1) and `email.analytics` are bound now but have no consumer until their stage is built. `scan.spam` left this list in topology v3 (step 4.1: work queue), `scan.attachment`, `scan.url`, `scan.bec`, `scan.dlp` and `scan.sandbox` in v4–v8, `email.policy.evaluate` in v9 (step 5.2: the policy-engine's work queue); `scan.auth` is reserved and unbound, so it never fills. Their policy is `max-length 10000, overflow drop-head`: a **lossy buffer**, never the source of truth. When a stage goes live, its step: switches the queue's policy to `work` (a policy change in `topology.ts` + definitions import, no re-declare), adds the role user and consumer, adds the queue to `RECONCILE_QUEUES` if it writes a ledger, and **onboards older messages from MySQL** (not from the buffer). `DormantQueueAtLimit` firing for such a queue is expected until then.

## First-start backlog drain

Before step 3.2 nothing published the outbox: every retained row is unpublished. The first relay start publishes them all in id order (locally ~3.5 k rows). Consumer names are unchanged, so the ledger rows written by the step 2.3/3.1 pollers turn them into duplicates (no second effect); dormant queues absorb (and may drop) their share. Watch `outbox_unpublished_rows` fall to 0 and `outbox_relay_lag_seconds` return to ~0. Poison rows found during the drain (pre-3.2 rows that fail today's schemas or guard) are handled with [poison rows](#poison-rows). After the drain the outbox partitions become droppable by the retention job.

## Legacy `/` cleanup

The ADR-0005 objects on vhost `/` (`mail.events`, `mail.dlx`, five `<service>.<event>` queues and their `.dlq`) are deleted by `init.mjs --cleanup-legacy` (compose `rabbitmq-init` runs it) **only when each is empty** (no messages, no consumers); a non-empty object is left with a warning. They are quorum queues, and RabbitMQ 4.x refuses `if-empty` deletes of quorum queues (HTTP 400), so the script checks the counts first and then deletes (WP5 fix; before it, every legacy queue was kept with `kept: not empty`). Nothing publishes to the legacy exchanges any more, so no message can arrive between the check and the delete. Locally they were removed on 2026-11-04. To finish by hand: inspect the remaining messages (management UI, vhost `/`); they predate the outbox relay and are not the source of truth (their events are in `message_outbox`); after a review, purge and re-run `node --env-file=.env infrastructure/rabbitmq/init.mjs --cleanup-legacy`. `RABBITMQ_URL` (administrator on `/`) is for tests and tools only.

## Node-failure test

The broker node-failure scenario (design §10) runs on the TEST-ONLY `rabbitmq-cluster` profile, never in `test:integration`. Procedure (also in the header of `tests/integration/cluster/node-failure.test.ts` and the [local stack runbook](local-stack.md#rabbitmq)):

1. Stop the app containers **by name** (`docker compose stop api admin-portal smtp-adapter email-worker policy-engine delivery-worker event-relay notification-worker webhook-worker archive-worker`); `docker compose --profile apps stop` would also stop MySQL. Stop `clamav` only if the nodes cannot become healthy for lack of memory.
2. `docker compose --profile rabbitmq-cluster up -d --wait rabbitmq-node1 rabbitmq-node2 rabbitmq-node3`
3. `node --env-file=.env infrastructure/rabbitmq/init.mjs --mgmt-url http://127.0.0.1:${RABBITMQ_CLUSTER_MGMT_HOST_PORT} --users`
4. `pnpm --filter @email-gateway/integration-tests test:cluster`: a confirm publisher (`eg-relay`) and a queue consumer of `email.received` (`eg-email-worker`) connected with all three node URLs, a `processOnce` ledger with a unique consumer name; 3 000 events at a steady rate; at one third the `email.received` leader (`rabbitmq-queues quorum_status`) is `docker kill`ed, publishing continues (unconfirmed events are republished with the same id), the node is started again; every confirmed event is handled exactly once, nothing is lost. Its ledger rows are deleted.
5. `docker compose --profile rabbitmq-cluster rm -sf rabbitmq-node1 rabbitmq-node2 rabbitmq-node3`, then `docker volume rm` exactly `email-gateway_rabbitmq-cluster-{1,2,3}-data` (never `down -v`), restart `clamav` if it was stopped, `docker compose --profile apps up -d --wait`.

Measured locally (step 3.2 §13): leader `rmq1` killed after 1 000 confirms, `rmq3` elected, 40 publishes unconfirmed and republished, 3 000/3 000 handled exactly once, 20 ledger duplicates from redeliveries, 0 lost.

## Changing shard counts

Lock names contain the count (`er:relay#<i>/<n>`), so replicas running different counts would publish overlapping rows. Procedure:

1. Scale event-relay to 0 (`kubectl scale deploy/event-relay --replicas=0`; locally `docker compose stop event-relay`). Producers keep writing; rows wait.
2. Set `RELAY_SHARDS` (1–64) and, if needed, `RELAY_MAX_HELD_SHARDS` so that `RELAY_SHARDS ≤ replicas × RELAY_MAX_HELD_SHARDS`.
3. Scale back up. The relay has no cursor (it scans `published_at IS NULL`), so nothing is skipped; watch [OutboxRelayNoShardOwner](#outboxrelaynoshardowner) clear.

If both counts ever overlap (a rolling update), the cost is duplicates, never loss.
