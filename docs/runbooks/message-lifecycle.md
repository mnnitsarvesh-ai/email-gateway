# Runbook: message lifecycle (states, history, stuck messages, expiry, recovery)

Step 3.3 ([design](../plan/steps/08-message-lifecycle.md), [ADR-0025](../architecture/adr/0025-message-lifecycle-state-machine.md), [diagram 11](../architecture/diagrams/11-message-state-machine.md)). Every alert of `infrastructure/monitoring/rules/lifecycle.rules.yml` links a section of this page.

**Rules that hold in every procedure below:**

- **One door.** `email_messages.status`, `status_changed_at`, `version`, `lifecycle_round`, `status_reason` and `email_message_status_history` are written only by `@email-gateway/message-lifecycle` (the transition service). Never `UPDATE email_messages SET status …` by hand, never insert or edit history rows: a hand-made state has no history row, no event, no outbox row, and breaks the version chain that every producer relies on. Operators change a state through the api (rescan, release) only.
- **Never backwards.** Older events (older round, stale version, a target the message already passed) are ignored and recorded (`email_events` `lifecycle.ignored`), never applied. An ignored row is evidence, not a failure to fix.
- **No content.** History, events, logs and metrics carry ids, codes, counts, versions and timestamps. Do not paste subjects, addresses or S3 object contents into tickets.
- Read on the **replica** for investigations; the writer is for the services.

## Contents

- [States](#states) · [Reading a message's lifecycle](#reading-a-messages-lifecycle) · [Series used by the alerts](#series-used-by-the-alerts)
- Alerts: [LifecycleRecoveries](#lifecyclerecoveries) · [LifecycleStuckMessages](#lifecyclestuckmessages) · [LifecycleExpiryNoShardOwner](#lifecycleexpirynoshardowner) · [LifecycleInvalidTransitions](#lifecycleinvalidtransitions)
- Procedures: [stuck messages](#stuck-messages) · [expiry](#expiry) · [recovery](#recovery) · [rescan before Phase 4](#rescan-before-phase-4) · [quarantine release](#quarantine-release) · [changing deadlines or shard counts](#changing-deadlines-or-shard-counts)

## States

Fifteen states (`MESSAGE_STATES`, the MySQL `ENUM` order). The transition table (edges E1–E26, roles, reason codes) is `packages/message-lifecycle/src/transitions.ts`; [diagram 11](../architecture/diagrams/11-message-state-machine.md) draws it.

| State              | Meaning                                                                        | Left by (producer)                                        | Expires after (default) |
| ------------------ | ------------------------------------------------------------------------------ | --------------------------------------------------------- | ----------------------- |
| `received`         | SMTP accepted the DATA (history only; never visible after the commit)          | `persisted` (smtp-adapter, same transaction)              | —                       |
| `persisted`        | Message, recipients, `received` event and `mail.message.received.v1` committed | `scanning` (4.1), `approved` (dev pass-through, local/ci) | 72 h                    |
| `scanning`         | Security stages requested                                                      | `scanned` / `scan_failed` (4.x)                           | 24 h                    |
| `scanned`          | Every required stage reported                                                  | `policy_evaluated` (5.2)                                  | 24 h                    |
| `scan_failed`      | Scanning could not complete                                                    | `policy_evaluated` (5.2 fail-safe)                        | 72 h                    |
| `policy_evaluated` | Policy decided                                                                 | `approved`, `quarantined`, `held_for_review`, `rejected`  | 24 h                    |
| `approved`         | Delivery approved; the approval event is in the outbox                         | `delivery_pending` (delivery-worker planner)              | 24 h                    |
| `quarantined`      | Held in quarantine                                                             | `approved` (release), `rejected` (5.3 delete)             | 2160 h (90 d)           |
| `held_for_review`  | Held for an administrator                                                      | `approved` (release), `quarantined`, `rejected` (5.3)     | 336 h                   |
| `delivery_pending` | Planned; a recipient is not settled, none deferred                             | derived from the recipients (recorder, lifecycle check)   | 168 h                   |
| `delivery_retry`   | A recipient is deferred and retried by Postfix                                 | derived from the recipients                               | 168 h                   |
| `delivered`        | Every recipient settled, at least one delivered (`delivery_complete/_partial`) | `archived` (8.1) only                                     | final                   |
| `rejected`         | Delivered to nobody (`delivery_failed`, policy discard/reject, delete)         | `archived` (8.1) only                                     | final                   |
| `archived`         | Retained in the archive                                                        | nothing                                                   | terminal                |
| `expired`          | Stuck past its state's deadline                                                | `scanning` (administrative rescan, new round) only        | final                   |

`version` grows by one per applied transition (0 = the `received` history row, 1 = `persisted`); `lifecycle_round` grows by one on a rescan or a release. Before Phase 4 nothing produces `scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `quarantined`, `held_for_review` or `archived` except the api's rescan; locally the dev pass-through moves `persisted → approved`.

Partial and failed delivery are **reasons**, not states: `delivered` + `delivery_partial` and `rejected` + `delivery_failed`; the per-recipient truth is `GET /api/v1/messages/{messageId}/deliveries`.

## Reading a message's lifecycle

Through the api (tenant-scoped, permission `message:read`): `GET /api/v1/messages/{messageId}/lifecycle` (state, reason, version, round, parse outcome, recipient counts, allowed actions) and `GET /api/v1/messages/{messageId}/lifecycle/history` (applied transitions oldest first, actor role/type/service/id, causation event id, correlation id, occurrence and change time). Pre-3.3 rows show `actor.role = legacy`.

In SQL (replica, operators only; `<public-id>` is the message's UUID):

```sql
SELECT m.id, m.received_at, m.organization_id, m.status, m.status_reason, m.version,
       m.lifecycle_round, m.status_changed_at
FROM message_identities i
JOIN email_messages m ON m.id = i.id AND m.received_at = i.received_at
WHERE i.public_id = '<public-id>';

SELECT version, from_status, to_status, reason_code, lifecycle_round, actor_role, actor_service,
       actor_type, event_id, correlation_id, state_event_id, occurred_at, changed_at
FROM email_message_status_history
WHERE message_id = ? AND received_at = ?
ORDER BY version;

-- Ignored requests (stale/invalid) and the applied-transition timeline entries.
SELECT event_type, occurred_at, source_service, event_id, details
FROM email_events
WHERE message_id = ? AND received_at = ? AND event_type LIKE 'lifecycle.%'
ORDER BY id;
```

What to expect: versions are contiguous from 0, `from_status` of each row is the `to_status` of the previous one (except legacy rows), the last row's `to_status` and `version` equal the message row. `transition_key` is a SHA-256 (the producer's idempotency key, e.g. `evt:<eventId>:approved`, `expire:<id>:<version>`); compare it with `SHA2('<key>', 256)`. History partitions are kept 3 months (`detail` retention).

`lifecycle.ignored` details: `requested` (target), `current`, `result` (`stale`/`invalid`), `why` (`older_round`, `version_mismatch`, `overtaken`, `final_state`, `edge_not_allowed`, `actor_not_allowed`, `reason_not_allowed`, `unexpected_from`, `future_round`), versions, rounds, reason and actor role.

## Series used by the alerts

| Series                                                                                                        | Source                                      |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `lifecycle_transitions_total{from,to,result}`, `lifecycle_transitions_ignored_total{reason}`                  | every writer (transition service)           |
| `lifecycle_version_conflicts_total`, `lifecycle_derived_skipped_total{state}`                                 | every writer                                |
| `lifecycle_expired_total{state}`, `lifecycle_expiry_overdue{state}`, `lifecycle_expiry_skipped_total{reason}` | event-relay expiry sweeper                  |
| `lifecycle_expiry_shards_held`, `lifecycle_expiry_shards`, `lifecycle_expiry_pass_seconds`                    | event-relay expiry sweeper                  |
| `lifecycle_recovered_total{from,to}`, `lifecycle_stuck_messages{state}`, `lifecycle_check_run_seconds`        | event-relay lifecycle check                 |
| `lifecycle_job_errors_total{component}`                                                                       | event-relay (database errors, with backoff) |

## LifecycleRecoveries

The lifecycle check re-derived a delivery state that should have been derived by the delivery recorder in the transaction of the signal. Nothing is lost (the check repaired it), but a code path skipped the derivation.

1. Find the messages: event-relay warn log `lost delivery-state derivation recovered` (`messageId`, `organizationId`, `from`, `to`, `reason`). History rows with `actor_role = 'recovery'`.
2. For each, list the signals (`delivery_status_events` of the message) around the recovered transition: which source (`postfix_log`, `bounce_notice`, `reinjection`, `reconciler`, `planner`) applied the last per-recipient change, and whether its delivery had the message's highest `delivery_seq` (older sequences never move the message, by design).
3. Expected one-off sources: the `delivery_pending` rows renamed by the step 3.3 migration (legacy `delivery_queued`), and messages whose derivation was lost during a crash. A steady rate is a bug: open an issue with the ids.

## LifecycleStuckMessages

More than 100 messages in one non-final state have been unchanged for longer than `LIFECYCLE_CHECK_AFTER_SECONDS` for 30 minutes. See [stuck messages](#stuck-messages).

## LifecycleExpiryNoShardOwner

Fewer expiry shard locks are held than `LIFECYCLE_EXPIRY_SHARDS`: overdue messages of the unowned shards are not expired (nothing else is affected).

1. `up{job="event-relay"}` and the replicas' `lifecycle_expiry_shards_held`. A replica with `LIFECYCLE_EXPIRY_ENABLED=false` holds none.
2. Shards must be ≤ replicas × `LIFECYCLE_EXPIRY_MAX_HELD_SHARDS`.
3. Lock connection: `SELECT * FROM performance_schema.metadata_locks WHERE OBJECT_TYPE = 'USER LEVEL LOCK' AND OBJECT_NAME LIKE 'er:lifecycle-expiry#%'` shows who holds each shard. A session that holds a lock but whose process is gone releases it when MySQL notices the connection ended.
4. `lifecycle_job_errors_total{component="expiry"}` rising: the writer is failing; see the MySQL runbooks.

## LifecycleInvalidTransitions

Producers keep requesting transitions the state machine refuses. An occasional `invalid` is a late duplicate (e.g. a redelivered approval after the message moved on); a sustained rate is a producer bug or a forged event.

1. `sum by (from, to, job) (rate(lifecycle_transitions_total{result="invalid"}[15m]))` and `lifecycle_transitions_ignored_total` by reason: which producer (`job`) and which pair.
2. The producer's warn log `invalid lifecycle transition ignored` has the ids; the message's `lifecycle.ignored` rows show `why`.
3. `future_round`: an event carries a round the message never reached: a bug or a forged event (only `eg-relay` publishes event keys; see [rabbitmq-messaging.md](rabbitmq-messaging.md#topology-and-users)). `actor_not_allowed` / `reason_not_allowed`: a producer uses the wrong role or reason (code fix). `edge_not_allowed` / `unexpected_from`: a stage ran out of order (often a missing precondition upstream).

## Stuck messages

1. Which state: `lifecycle_stuck_messages{state}`. Before Phase 4, `scanning` after a rescan is **expected** (see [rescan before Phase 4](#rescan-before-phase-4)); `persisted` is expected on stacks without the dev pass-through (no producer leaves it until 4.1 / 5.2).
2. `approved`: the planner consumes `email.delivery.pending`. Check the queue's consumers and backlog ([WorkQueueNoConsumer / WorkQueueBacklog](rabbitmq-messaging.md#workqueuenoconsumer)), the delivery-worker log for `delivery_approvals_rejected_total{reason="lifecycle_state"}` (approval for a message in another state or round), and the step 3.2 reconciler (it re-drives approvals without a ledger row).
3. `delivery_pending` / `delivery_retry`: per-recipient state (`GET …/deliveries`). Deferred recipients stay in `delivery_retry` until Postfix's queue lifetime (5 days) ends them; the lifecycle check re-derives messages whose derivation was lost.
4. Anything stuck past its deadline is expired by the sweeper ([expiry](#expiry)); nothing needs to be changed by hand.

## Expiry

The sweeper (event-relay, `LIFECYCLE_EXPIRY_ENABLED`) moves messages unchanged for longer than their state's deadline (`LIFECYCLE_DEADLINE_<STATE>_HOURS`, 0 = never) to `expired` (`deadline_exceeded`, actor `sweeper`, key `expire:<id>:<version>`), with a compare-and-set on the version it read: a message that changed in between is skipped (`lifecycle_expiry_skipped_total{reason="changed"}`, one `lifecycle.ignored` row), never overwritten.

- `expired` is final for automatic processing. Late per-recipient delivery signals still update the recipients and deliveries; the message state stays `expired`.
- Delivery deadlines must exceed Postfix's `maximal_queue_lifetime` (config refuses 1..120 hours).
- To re-run the pipeline for an expired message (EML still retained): an administrative rescan (`POST /api/v1/messages/{messageId}/rescan`, permission `message:rescan`).
- Watch: `lifecycle_expired_total{state}` (a jump means a stage stopped), `lifecycle_expiry_overdue{state}` (candidates found per pass, capped at the batch size), `lifecycle_expiry_pass_seconds`.

## Recovery

| Failure                                   | What happens                                                                                                                                                                               |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Consumer crash between consume and commit | The transition is in the consumer's transaction with its ledger row: both roll back; RabbitMQ redelivers (or the step 3.2 reconciler re-drives); the re-run applies once (transition key). |
| Writer outage mid-transition              | The transaction fails, InnoDB rolls back and releases the row lock; the consumer retries (transient), the api returns `5xx` and the client retries with the same `Idempotency-Key`.        |
| Deadlock / lock wait / concurrent writer  | `transitionMessageWithRetry` retries with jitter (`lifecycle_version_conflicts_total`); inside a consumer transaction the consumer's retry re-runs everything.                             |
| Lost delivery derivation                  | The lifecycle check re-derives it ([LifecycleRecoveries](#lifecyclerecoveries)).                                                                                                           |
| Stuck in any non-final state              | Metrics first, the sweeper after the deadline.                                                                                                                                             |

No procedure requires editing lifecycle rows. If a message's state is wrong, capture the history and events (above) and open an issue; do not "fix" the row.

## Rescan before Phase 4

`POST /api/v1/messages/{messageId}/rescan` (permission `message:rescan`, `Idempotency-Key` required, body `{ expectedVersion, reason }`) moves the message to `scanning` with a new round and publishes `mail.message.rescan_requested.v1` to `email.security`. **Until the Phase 4 scan stages exist, nothing consumes it**: the request lands in the five dormant scan queues (bounded, `drop-head`), the response carries a `note` saying so, and the message stays `scanning` until the sweeper expires it after `LIFECYCLE_DEADLINE_SCANNING_HOURS` (24 h). After expiry another rescan is allowed. This is the documented contract, not an incident; `LifecycleStuckMessages{state="scanning"}` after a burst of rescans is expected.

## Quarantine release

`POST /api/v1/messages/{messageId}/release` (permission `quarantine:release`, `Idempotency-Key`, `{ expectedVersion, reason }`) moves a `quarantined` / `held_for_review` message to `approved` with a new round and writes approval events (`source = quarantine_release`, `deliverySeq` = previous max + 1) for the `pending`/`quarantined` recipients; the planner plans them through the normal delivery path and the derived state moves the message to `delivery_pending` → `delivered`. Refused: `409 quarantine_workflow_required` when `quarantine_messages` rows exist (5.3 owns per-recipient quarantine), `409 no_releasable_recipients`, `409 message_version_conflict` (reload and retry with the current version), `409 message_state_conflict`. Every release is in `audit_logs` (`message.quarantine_released`).

## Changing deadlines or shard counts

- Deadlines are read at start: change the `LIFECYCLE_DEADLINE_*` keys and restart event-relay. The lookback must cover the longest non-zero deadline (`LIFECYCLE_EXPIRY_LOOKBACK_DAYS × 24`), or startup refuses the configuration. Both lookbacks (`LIFECYCLE_EXPIRY_LOOKBACK_DAYS`, `LIFECYCLE_CHECK_LOOKBACK_HOURS`) bound `status_changed_at` (how long the message has been in its state), not `received_at`, so a message released or rescanned months after it was received is still swept and checked; `LIFECYCLE_CHECK_LOOKBACK_HOURS` must exceed `LIFECYCLE_CHECK_AFTER_SECONDS`.
- `LIFECYCLE_EXPIRY_SHARDS` is part of the lock names (`er:lifecycle-expiry#<i>/<n>`): roll it like `RELAY_SHARDS` (scale the sweeper roles to 0, change, scale up). Two counts at once can only send the same expiry twice; the transition key and the version check make the second a no-op.
- Disabling a role: `LIFECYCLE_EXPIRY_ENABLED=false` / `LIFECYCLE_CHECK_ENABLED=false` on a replica; at least one replica must run each.
