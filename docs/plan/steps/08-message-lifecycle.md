# Step 3.3: Message lifecycle and state management

Status: **implemented and verified locally (2026-11-04), commit pending**: WP1–WP5 done; verification record in [§13](#13-verification-results), review fixes and the final green run in [§13.10](#1310-verification-round-2-review-findings-2026-11-04) (what is not complete or not verified is listed in §13.7). Administrative rescan is a state transition plus the request contract only; the scan itself is deferred to step 4.1. Owner: principal architect. Decision record: [ADR-0025](../../architecture/adr/0025-message-lifecycle-state-machine.md) (lifecycle model, ordering rule, shared transition service; amends ADR-0021 and ADR-0024; a one-time exception to the append-only enum rule).

This note is the single source of truth for the implementers of this step. It builds on step 2.2 ([04-smtp-gateway.md](04-smtp-gateway.md), `b793683`), step 2.3 ([05-routing.md](05-routing.md), `6c6497c`), step 3.1 ([06-mime-ingestion.md](06-mime-ingestion.md), `05c1465`) and step 3.2 ([07-rabbitmq.md](07-rabbitmq.md), `c8083d4`); their decisions stay in force unless a decision below names them. If a decision proves impossible (for example MySQL refuses an `ALTER` the way it is written here), the implementer:

- documents the deviation in the docs their package owns and in their final report;
- picks the closest alternative that keeps the **invariants of §2.0**.

**Nobody silently changes a decision.** Section numbers (§) and decision ids (L*n*) are stable references.

---

## 1. Starting point (inspected, commit `c8083d4`)

| Area                            | Current state                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `email_messages`                | Partitioned monthly by `received_at`, PK `(id, received_at)`, `status MessageStatus` (`received`, `scanning`, `scanned`, `policy_evaluated`, `quarantined`, `delivery_queued`, `delivered`, `partially_delivered`, `discarded`, `failed`; default `received`), `status_changed_at`, `version INT UNSIGNED` default 0, index `(status, status_changed_at)`. `mta_queue_id VARCHAR(32)` with the table collation `utf8mb4_unicode_ci`.                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `email_message_status_history`  | Partitioned monthly (retention 3 months, `detail`), append-only, `version` (after the transition), `from_status` NULL, `to_status`, `reason_code VARCHAR(64)`, `event_id CHAR(36)`, `changed_at`, unique `(message_id, version, received_at)`. No actor, no correlation id, no idempotency key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **Who writes the status today** | The brief's hand-off said "nothing advances the status past `received`". Inspection shows that is **not quite true**: step 2.3's `@email-gateway/mail-routing` recorder writes it. `markMessageDeliveryQueued` (planner, in the approval's `processOnce` transaction) moves `received`/`policy_evaluated → delivery_queued`; `recordDeliverySignal` sets the aggregate `delivered` / `partially_delivered` / `failed` once every delivery of a `delivery_seq` is terminal (`aggregateMessageStatus`). Both use `setMessageStatus`: `UPDATE … WHERE version = ?` plus a history row, `MessageVersionConflictError` retried 3 times. The SMTP commit (smtp-adapter `IngestionRepository.commit`) creates the row as `received`, version 0, **without** a history row. Step 3.1 never touches the status (M13). Local data: 1 message `received`, 8 `delivery_queued`, 8 history rows. |
| smtp-adapter commit             | One writer transaction per organization: `message_identities`, `email_messages` (`status = received`, `status_changed_at = received_at`), `email_recipients` (`pending`), `email_events` `received`, outbox `mail.message.received.v1` (correlation `lmtp:<queueId>`). The EML is already in S3 before the transaction.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| email-worker                    | `email.received` consumer (`email-worker.mime-parser`), staged handler; the finalize transaction writes `email_message_parses`, headers, attachments, `email_events` `parsed`/`parse_failed`, outbox `mail.message.parsed.v1` / `parse_failed.v1`, ledger row. Never touches `status`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| delivery-worker                 | Dev pass-through (`OutboxPoller`, `delivery-worker.dev-passthrough`, local/ci only) turns `received.v1` into `mail.delivery.approved.v1` (`source = dev_passthrough`, `deliverySeq 0`) for every `pending` recipient. Planner (`email.delivery.pending`, `delivery-worker.planner`) checks provenance (`assertApprovalIssued`), loads message and recipients from the writer, calls `markMessageDeliveryQueued`, plans deliveries/reinjections, records planner signals through the recorder. Status tailer, reinjector and `DeliveryReconciler` record signals through the recorder.                                                                                                                                                                                                                                                                                               |
| Per-recipient state             | `email_deliveries.status` (`DeliveryStatus`, step 2.3 R9.1 lattice in `transitions.ts`: rules in code, not data), `email_recipients.status` mirror (`mapRecipientStatus`), `delivery_status_events` audit (every signal, applied or not), unique `(delivery_id, signal_key, received_at)`. Lock order: reinjection → message → deliveries.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Queue-id columns                | `email_messages.mta_queue_id`, `email_deliveries.outbound_queue_id`, `email_deliveries.dsn_queue_id`, `delivery_reinjections.queue_id`, `delivery_status_events.queue_id`: all `VARCHAR(32)` `utf8mb4_unicode_ci`, so `4jKFxV5fmHz12JnW = 4jKFxV5fMHz12Jnw` in every lookup (recorder `resolveDelivery`, smtp-adapter `BouncesRepository`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Messaging                       | Topology v1 (`TOPOLOGY_VERSION = 1`), registry with nine concrete events + one reserved; scan queues `scan.{auth,spam,url,attachment,dlp}` are **dormant** (bound to `email.ingestion: org.*.mail.message.parsed.v1`, `max-length 10000`, `drop-head`, no consumer). Relay publishes every outbox row; reconciler re-drives published events without a ledger row for `email.received` and `email.delivery.pending`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| API                             | `GET /api/v1/messages/{messageId}/deliveries` (+ `/events`) and `GET /api/v1/deliveries` (permission `delivery:read`, reader through `PrismaReadService`, which falls back to the writer above the lag threshold). Messages are addressed by `message_identities.public_id`; another organization's message is `404`. `MessageStatusSchema` in `deliveries.schemas.ts` lists the old ten values. No Idempotency-Key support exists anywhere in the api. Permissions `message:read`, `quarantine:release` exist in the seed catalog; nothing uses `quarantine:release` yet. `AuditService` writes `audit_logs` in the caller's transaction.                                                                                                                                                                                                                                          |
| Quarantine tables               | `quarantine_messages` / `quarantine_actions` / `quarantine_release_logs` exist (step 1.1), no writer yet (5.3).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Diagram 11                      | `docs/architecture/diagrams/11-message-state-machine.md` shows the old ten-state machine as "PLANNED 3.3".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Tests needing care              | `apps/api/integration/common.test.ts` sends a probe to the local MX that ends deferred in postfix-outbound and leaves its S3 objects; stack suites fill dormant queues and never purge them; `tests/integration/routing-signals.test.ts` deletes the tailer cursor and waits until the whole accumulated maillog is re-read (time grows with the file).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Environment note                | At inspection time the apps profile containers were running (healthy). Implementers stop them when a test needs a host-run service (`docker compose stop <service>`), never `down -v`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

---

## 2. Decisions

### 2.0 Invariants (never traded away)

1. **One door.** Every write of `email_messages.status`, `status_changed_at`, `version`, `lifecycle_round`, `status_reason` and every row of `email_message_status_history` goes through `@email-gateway/message-lifecycle` (L5). No raw `UPDATE email_messages SET status` anywhere else (a repository test greps for it, L5.9).
2. **Atomic with the cause.** A transition commits in the same writer transaction as the effect that caused it (the stage's rows, its `processOnce` ledger row) together with its history row, its `email_events` row and its outbox row. There is never a state without its history row or an applied history row without its state.
3. **Never backwards by accident.** An older event (older round, stale version, or a target the message has already passed) never changes the state. It is recorded as ignored and counted.
4. **Idempotent by key.** The same transition request (same `transitionKey`) applied twice leaves exactly one history row and one outbox row.
5. **No fake producers.** A state whose stage is not built (`scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `quarantined`, `held_for_review`, `archived`) is valid in the machine and tested, but no code of this step sets it (except the API's administrative rescan, which really requests a scan, L10).
6. **Tenant from trusted context.** API operations take the organization from the authenticated scope only; event-driven producers check the envelope organization against the writer row (as today).
7. **Writer only for decisions.** Every transition, including the api's rescan and release, reads and writes the MySQL writer. Read APIs use the replica with the existing lag fallback.
8. **No content.** History, events, logs and API responses carry ids, codes, counts, versions and timestamps. Never subjects, addresses (beyond what the per-recipient delivery API already returns), bodies or header values.
9. **The SMTP hot path stays inside its single transaction** and adds at most one statement (L8.1).

### L1. Where the lifecycle lives: new package `@email-gateway/message-lifecycle`

`packages/message-lifecycle` (CommonJS, `tsc -p tsconfig.build.json`, Vitest, same layout as `packages/mail-routing`). Dependencies: `@email-gateway/database` (Prisma types, `Prisma.TransactionClient`), `@email-gateway/event-contracts` (event schemas), `zod`. Dev: `fast-check@3.23.2` (already in the lockfile) for property tests.

Why a package:

- Five deployables write the state (smtp-adapter, delivery-worker, event-relay, api, and the recorder inside smtp-adapter for bounce notices); 4.x (email-worker), 5.x (policy-engine), 5.3 and 8.1 (archive-worker) will. One table and one service keep them consistent.
- `packages/common` is infrastructure (database, broker, outbox, metrics). The lifecycle is domain logic; putting it there would make every service depend on mail domain rules.
- `packages/mail-routing` is delivery-specific; smtp-adapter, api and event-relay need the lifecycle without the routing module. `mail-routing` depends on `message-lifecycle` (the recorder derives the message state), not the other way round.

Exports (index): `writeInitialHistory`, `lockLifecycle`, `MESSAGE_STATES`, `MessageState`, `STATE_RANK`, `FINAL_STATES`, `EXPIRABLE_STATES`, `ACTOR_ROLES`, `ActorRole`, `LIFECYCLE_REASON_CODES`, `TRANSITIONS` (the table), `findEdge`, `decideTransition` (pure validator), `deriveDeliveryState`, `initialLifecycle` (SMTP creation helper), `transitionMessage`, `transitionMessageWithRetry`, `applyDerivedDeliveryState`, `LifecycleVersionConflictError`, `isRetryableLifecycleError`, `transitionKeyHash`, `LifecycleMetrics` (interface), `toStateChangedPayload`.

### L2. States and the mapping of the old values

Canonical states (lower-case in the database, the API and events, like every enum of the schema; the brief's UPPER_CASE names map 1:1), in this order, which is also the new MySQL `ENUM` order:

| #   | State              | Rank | Meaning                                                                                                                                      | Kind                               |
| --- | ------------------ | ---- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| 1   | `received`         | 0    | SMTP accepted the DATA; the EML is in S3 with its SHA-256 (written inside the commit transaction only)                                       | initial                            |
| 2   | `persisted`        | 1    | Message, recipients, `received` event and `mail.message.received.v1` committed (the durable hand-off; the step 3.1 parse runs in this state) | waiting for the pipeline           |
| 3   | `scanning`         | 2    | Security stages requested (4.x)                                                                                                              | in progress                        |
| 4   | `scanned`          | 3    | Every required stage reported or timed out (4.x)                                                                                             | waiting for policy                 |
| 5   | `scan_failed`      | 3    | Scanning could not complete (engine outage past budget, EML unavailable) (4.x); policy applies its fail-safe                                 | waiting for policy                 |
| 6   | `policy_evaluated` | 4    | Policy decided (5.2)                                                                                                                         | transient                          |
| 7   | `approved`         | 5    | Delivery approved for at least one recipient (policy, release, dev pass-through); the approval event is in the outbox                        | waiting for planning               |
| 8   | `quarantined`      | 5    | Held in quarantine (5.2/5.3)                                                                                                                 | resting                            |
| 9   | `held_for_review`  | 5    | Held for an administrator's decision (5.2/5.3)                                                                                               | resting                            |
| 10  | `rejected`         | 8    | Not delivered to anyone, permanently: policy discard/reject, or every recipient failed delivery                                              | final (→ `archived` only)          |
| 11  | `delivery_pending` | 6    | Planned; at least one recipient not settled and none deferred                                                                                | in progress                        |
| 12  | `delivery_retry`   | 6    | At least one recipient deferred and still being retried by Postfix                                                                           | in progress                        |
| 13  | `delivered`        | 7    | Every recipient settled, at least one delivered                                                                                              | final (→ `archived` only)          |
| 14  | `archived`         | 9    | Retained in the archive (8.1)                                                                                                                | terminal                           |
| 15  | `expired`          | 8    | Stuck past its state's deadline (L13)                                                                                                        | final (administrative rescan only) |

`FINAL_STATES = [delivered, rejected, archived, expired]` (no automatic processing leaves them). `EXPIRABLE_STATES = [persisted, scanning, scanned, scan_failed, policy_evaluated, approved, quarantined, held_for_review, delivery_pending, delivery_retry]`. `received` is never visible after commit and is not expirable.

**Where `persisted` sits.** `received` and `persisted` are both reached in the step 2.2 commit transaction (the EML reaches S3 before the transaction, the rows and the outbox event in it): `received` is recorded so that every message's history starts with the SMTP acceptance, `persisted` is the state the row is born in. The step 3.1 parse runs **within** `persisted`: it is a preparatory stage whose record is `email_message_parses` (stage table, 3.1 M13), not a lifecycle state (the brief fixes fifteen states, and a parse state would be one more). Its outcome decides the next transition, by the stage that consumes it: `mail.message.parsed.v1` → 4.1 moves `persisted → scanning`; `mail.message.parse_failed.v1` (bound to `email.policy.evaluate`) → 5.2 moves `persisted → policy_evaluated` with its fail-safe. In this step the parse outcome is visible in the lifecycle read API (L12) next to the state.

**Mapping of the old values** (migration `message_lifecycle`, L2.1 and §3.1):

| Old value                                                | New state          | `status_reason`      | Version / history                                                                                                             |
| -------------------------------------------------------- | ------------------ | -------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `received`                                               | `persisted`        | `lifecycle_backfill` | `version + 1`; history rows `NULL → received` (version 0) and `received → persisted` (new version), both `lifecycle_backfill` |
| `scanning`, `scanned`, `policy_evaluated`, `quarantined` | same name          | unchanged            | none (no rows exist locally; the rename is identity)                                                                          |
| `delivery_queued`                                        | `delivery_pending` | `delivery_planned`   | in-place rename, no version change; the lifecycle check (L14) re-derives `delivery_retry`/final states later                  |
| `delivered`                                              | `delivered`        | `delivery_complete`  | none                                                                                                                          |
| `partially_delivered`                                    | `delivered`        | `delivery_partial`   | in-place rename                                                                                                               |
| `failed`                                                 | `rejected`         | `delivery_failed`    | in-place rename                                                                                                               |
| `discarded`                                              | `rejected`         | `discarded`          | in-place rename                                                                                                               |

History rows are renamed with the same mapping (`from_status` and `to_status`), keep their versions, and get `actor_role = 'legacy'`, `actor_service = 'legacy'` (column defaults). Every message without a version-0 history row gets one `NULL → received` row (`lifecycle_backfill`, `changed_at = received_at`). Legacy rows may contain pairs the new table does not allow (`received → delivery_pending`); they are history, not decisions, and the API shows them as they are.

**Partial and failed outcomes are not states.** `delivered` with `status_reason = delivery_partial` plus the per-recipient states (`GET …/deliveries`) show a partial delivery; `rejected` with `delivery_failed` shows that every recipient failed. `discarded` (policy) becomes `rejected` with `policy_discard` once 5.2 exists.

#### L2.1 The enum change (one-time exception, ADR-0025 decision 2)

Widen (append the nine new values: in-place), backfill, narrow (exactly the fifteen values in L2 order: a table copy of `email_messages` and `email_message_status_history`). `docs/database/README.md`'s rule becomes "values are only ever appended, except the one-time `MessageStatus` replacement of step 3.3 (ADR-0025)". The Prisma enum keeps its name `MessageStatus`, so `import type { MessageStatus }` keeps working; its values become the fifteen states, with `@default(received)` unchanged (the machine's initial state; only `initialLifecycle` creates rows, L8.1).

### L3. The transition table (data)

`TRANSITIONS: readonly TransitionEdge[]` in `src/transitions.ts`:

```ts
interface TransitionEdge {
  id: string; // 'E1' … stable, used in tests and docs
  from: readonly (MessageState | null)[]; // null = creation
  to: MessageState;
  roles: readonly ActorRole[];
  reasons: readonly LifecycleReasonCode[];
  /** Re-entry edge: lifecycle_round + 1 (rescan, release). Allowed even when from = to. */
  newRound?: true;
  /** Step that builds the producer; '3.3' = this step. */
  producedBy: string;
}
```

Actor roles (`ACTOR_ROLES`): `ingestion` (smtp-adapter), `scanner` (email-worker, 4.x), `policy` (policy-engine, 5.2), `dev_passthrough` (delivery-worker, `APP_ENV` local/ci only), `delivery` (the delivery planner and the shared recorder, in delivery-worker or smtp-adapter), `operator` (api, a user or an API key), `quarantine` (5.3 workflow), `archive` (archive-worker, 8.1), `sweeper` (event-relay expiry, L13), `recovery` (event-relay lifecycle check, L14).

| Edge | From                                                                                                  | To                 | Roles                | Reason codes                                    | New round | Producer                      |
| ---- | ----------------------------------------------------------------------------------------------------- | ------------------ | -------------------- | ----------------------------------------------- | --------- | ----------------------------- |
| E1   | (creation)                                                                                            | `received`         | ingestion            | `smtp_accepted`                                 |           | **3.3** smtp-adapter          |
| E2   | `received`                                                                                            | `persisted`        | ingestion            | `committed`                                     |           | **3.3** smtp-adapter          |
| E3   | `persisted`                                                                                           | `scanning`         | scanner              | `scan_started`                                  |           | 4.1                           |
| E4   | `persisted`                                                                                           | `approved`         | dev_passthrough      | `dev_passthrough`                               |           | **3.3** delivery-worker (dev) |
| E5   | `persisted`                                                                                           | `policy_evaluated` | policy               | `parse_failed_fail_safe`                        |           | 5.2                           |
| E6   | `scanning`                                                                                            | `scanned`          | scanner              | `scan_complete`                                 |           | 4.x                           |
| E7   | `scanning`                                                                                            | `scan_failed`      | scanner              | `scan_error`, `scan_timeout`, `eml_unavailable` |           | 4.x                           |
| E8   | `scanned`                                                                                             | `policy_evaluated` | policy               | `policy_decided`                                |           | 5.2                           |
| E9   | `scan_failed`                                                                                         | `policy_evaluated` | policy               | `scan_failed_fail_safe`                         |           | 5.2                           |
| E10  | `policy_evaluated`                                                                                    | `approved`         | policy               | `policy_deliver`, `policy_tag`                  |           | 5.2                           |
| E11  | `policy_evaluated`                                                                                    | `quarantined`      | policy               | `policy_quarantine`                             |           | 5.2                           |
| E12  | `policy_evaluated`                                                                                    | `held_for_review`  | policy               | `policy_hold`                                   |           | 5.2                           |
| E13  | `policy_evaluated`                                                                                    | `rejected`         | policy               | `policy_discard`, `policy_reject`               |           | 5.2                           |
| E14  | `quarantined`                                                                                         | `approved`         | operator, quarantine | `quarantine_release`                            | yes       | **3.3** api; 5.3              |
| E15  | `held_for_review`                                                                                     | `approved`         | operator, quarantine | `review_release`                                | yes       | **3.3** api; 5.3              |
| E16  | `held_for_review`                                                                                     | `quarantined`      | quarantine           | `review_quarantined`                            |           | 5.3                           |
| E17  | `quarantined`                                                                                         | `rejected`         | quarantine           | `quarantine_deleted`                            |           | 5.3                           |
| E18  | `held_for_review`                                                                                     | `rejected`         | quarantine           | `review_rejected`                               |           | 5.3                           |
| E19  | `scanning`, `scanned`, `scan_failed`, `policy_evaluated`, `quarantined`, `held_for_review`, `expired` | `scanning`         | operator             | `admin_rescan`                                  | yes       | **3.3** api                   |
| E20  | `approved`                                                                                            | `delivery_pending` | delivery             | `delivery_planned`                              |           | **3.3** delivery-worker       |
| E21  | `delivery_pending`                                                                                    | `delivery_retry`   | delivery, recovery   | `delivery_deferred`                             |           | **3.3** recorder; event-relay |
| E22  | `delivery_retry`                                                                                      | `delivery_pending` | delivery, recovery   | `delivery_requeued`                             |           | **3.3** recorder; event-relay |
| E23  | `delivery_pending`, `delivery_retry`                                                                  | `delivered`        | delivery, recovery   | `delivery_complete`, `delivery_partial`         |           | **3.3** recorder; event-relay |
| E24  | `delivery_pending`, `delivery_retry`                                                                  | `rejected`         | delivery, recovery   | `delivery_failed`                               |           | **3.3** recorder; event-relay |
| E25  | `delivered`, `rejected`                                                                               | `archived`         | archive              | `archived`                                      |           | 8.1                           |
| E26  | every `EXPIRABLE_STATES` member                                                                       | `expired`          | sweeper              | `deadline_exceeded`                             |           | **3.3** event-relay           |

Notes:

- `LIFECYCLE_REASON_CODES` is the union of the codes above plus `lifecycle_backfill` (migration only, never accepted by `decideTransition`). Codes match `/^[a-z0-9_]{1,64}$/`.
- No edge leaves `archived`. `expired` is left only by E19 (an operator may re-run the pipeline while the EML is retained). `delivered` and `rejected` are left only by E25.
- E19 from `scanning` with a new round is the operator's "the scan request was lost" re-issue.
- Rescan from `persisted` is not allowed: a message that was never scanned is picked up by the pipeline (4.1), not re-scanned. Rescan from delivery states or `approved` is not allowed (delivery may be under way; retro scanning of delivered mail is a 4.x `scan_kind = retro` concern that does not change the lifecycle).
- `quarantined → rejected` by an operator is 5.3's delete action, not part of this step's API.

### L4. Ordering rule (rounds, versions, rank)

Each message has `version` (unsigned int, +1 per applied transition; 0 = the `received` history row, 1 = `persisted`) and `lifecycle_round` (unsigned smallint, 0 at creation, +1 on every applied `newRound` edge).

`decideTransition(current, request, table)` (pure, `src/decide.ts`) returns one of:

```ts
type Decision =
  | { result: 'apply'; edge: TransitionEdge; nextRound: number }
  | { result: 'duplicate'; why: 'same_state' }
  | { result: 'stale'; why: 'older_round' | 'version_mismatch' | 'overtaken' | 'final_state' }
  | {
      result: 'invalid';
      why:
        | 'edge_not_allowed'
        | 'actor_not_allowed'
        | 'reason_not_allowed'
        | 'unexpected_from'
        | 'future_round';
    };
```

Order of checks (the transition-key duplicate check happens before, in the database, L5):

1. `request.expectedRound !== undefined`: `< current.round` → `stale/older_round`; `> current.round` → `invalid/future_round` (a bug or a forged event).
2. `request.expectedVersion !== undefined && !== current.version` → `stale/version_mismatch`.
3. `request.expectedFrom` given and `current.state ∉ expectedFrom` → `invalid/unexpected_from`, **except** when `current.state === request.to` and the matching edge is not `newRound` → `duplicate/same_state`.
4. `current.state === request.to` and no `newRound` edge from `current.state` to `to` exists → `duplicate/same_state`.
5. No edge with `from ∋ current.state` and `to = request.to`:
   - `current.state ∈ FINAL_STATES` → `stale/final_state`;
   - `STATE_RANK[request.to] <= STATE_RANK[current.state]` → `stale/overtaken` (the message is already past the target: a late or duplicate event);
   - otherwise → `invalid/edge_not_allowed` (a skipped stage: a bug).
6. Edge found: `request.actor.role ∉ edge.roles` → `invalid/actor_not_allowed`; `request.reason ∉ edge.reasons` → `invalid/reason_not_allowed`.
7. `apply`, with `nextRound = current.round + (edge.newRound ? 1 : 0)`.

Who passes what:

| Producer                             | `expectedRound`                       | `expectedVersion`              | `expectedFrom`                                 |
| ------------------------------------ | ------------------------------------- | ------------------------------ | ---------------------------------------------- |
| smtp-adapter (creation, L8.1)        | n/a (no lock, row is new)             |                                |                                                |
| dev pass-through (E4)                | 0                                     |                                | `[persisted]`                                  |
| planner (E20)                        | `approval.lifecycleRound ?? 0`        |                                | `[approved]`                                   |
| recorder / lifecycle check (E21–E24) | none: derived from current truth (L9) |                                |                                                |
| api rescan (E19), release (E14/E15)  | none                                  | the client's `expectedVersion` | E19 sources / `[quarantined, held_for_review]` |
| sweeper (E26)                        | none                                  | the version it read            | `[the state it read]`                          |
| 4.x / 5.x (future)                   | the round in their triggering event   |                                | the edge's sources                             |

Occurrence times (`occurredAt`) are recorded in the history row (`occurred_at`) but **never compared** (different clocks: Postfix log lines, container clocks). Delivery-derived transitions cannot be "older": they are recomputed from the recipients under the message lock (L9).

### L5. The transition service

`src/service.ts`. Runs inside the caller's transaction (`Prisma.TransactionClient`); raw SQL through `tx.$queryRaw` / `tx.$executeRaw` for the lock and the compare-and-set (explicit, reviewable, independent of generated model types), Prisma model calls for inserts are fine.

```ts
export interface TransitionActor {
  role: ActorRole;
  /** Deployable, e.g. 'smtp-adapter', 'delivery-worker', 'api', 'event-relay'. */
  service: string;
  type: 'system' | 'user' | 'api_key';
  /** Public id of the user or API key (operator); null for system actors. */
  id?: string | null;
}

export interface TransitionRequest {
  message: { id: bigint; receivedAt: Date; organizationId: bigint };
  to: MessageState;
  reason: LifecycleReasonCode;
  actor: TransitionActor;
  /** Idempotency key (L5.3); hashed with SHA-256 into history.transition_key. */
  transitionKey: string;
  causationEventId?: string | null; // history.event_id
  correlationId?: string | null; // history.correlation_id, outbox correlation_id
  occurredAt?: Date; // history.occurred_at (default: now)
  expectedRound?: number;
  expectedVersion?: number;
  expectedFrom?: readonly MessageState[];
  /** Record stale/invalid outcomes as email_events `lifecycle.ignored` (default true; the api passes false). */
  recordIgnored?: boolean;
}

export interface LifecycleSnapshot {
  state: MessageState;
  version: number;
  round: number;
  statusChangedAt: Date;
  statusReason: string | null;
  direction: 'inbound' | 'outbound' | 'internal';
  emlObjectKey: string;
}

export type TransitionOutcome =
  | {
      result: 'applied';
      from: MessageState;
      to: MessageState;
      version: number;
      round: number;
      historyId: bigint;
      stateEventId: string;
      snapshot: LifecycleSnapshot;
    }
  | { result: 'duplicate'; why: 'transition_key' | 'same_state'; snapshot: LifecycleSnapshot }
  | { result: 'stale'; why: StaleReason; snapshot: LifecycleSnapshot }
  | { result: 'invalid'; why: InvalidReason; snapshot: LifecycleSnapshot }
  | { result: 'not_found' };

export function transitionMessage(
  tx: Prisma.TransactionClient,
  request: TransitionRequest,
  deps?: { metrics?: LifecycleMetrics; logger?: LifecycleLogger; now?: () => Date },
): Promise<TransitionOutcome>;

/** Own writer transaction, retried on deadlock (1213), lock wait (1205), P2034 and LifecycleVersionConflictError. */
export function transitionMessageWithRetry(
  prisma: PrismaClient,
  request: TransitionRequest,
  options: { timeoutMs: number; maxAttempts?: number /* default 5 */ },
  deps?: { metrics?: LifecycleMetrics; logger?: LifecycleLogger; now?: () => Date },
): Promise<TransitionOutcome>;
```

#### L5.1 Algorithm (one call)

1. `SELECT id, received_at, organization_id, status, version, lifecycle_round, status_changed_at, status_reason, direction, eml_object_key FROM email_messages WHERE id = ? AND received_at = ? FOR UPDATE`. No row, or `organization_id ≠ request.message.organizationId` → `not_found` (nothing written; the caller decides; tenant mismatches are never "found").
2. `transition_key = SHA-256(hex)` of `request.transitionKey`. `SELECT id FROM email_message_status_history WHERE message_id = ? AND received_at = ? AND transition_key = ?` → found → `duplicate/transition_key` (metric only).
3. `decideTransition`. Not `apply` → if `stale`/`invalid` and `recordIgnored !== false`: insert `email_events` `lifecycle.ignored` (L6); count; return. `invalid` is also logged at `warn` with ids and codes only.
4. `UPDATE email_messages SET status = ?, version = version + 1, lifecycle_round = ?, status_reason = ?, status_changed_at = ? WHERE id = ? AND received_at = ? AND version = ?` → affected rows ≠ 1 → throw `LifecycleVersionConflictError` (cannot happen under the lock unless another writer bypassed it; the backstop the brief asks for).
5. Insert the history row (§3.1 columns): `version` = new version, `from_status`, `to_status`, `reason_code`, `lifecycle_round` (new), `actor_role`, `actor_service`, `actor_type`, `actor_id`, `event_id` (causation), `correlation_id`, `transition_key`, `state_event_id` (a new UUIDv7), `occurred_at`, `changed_at` (now). A P2002 on the transition-key unique key → throw (the caller's transaction is rolled back; `transitionMessageWithRetry` re-runs and gets `duplicate`).
6. Insert `email_events`: `event_type = 'lifecycle.' + to`, `occurred_at = changed_at`, `source_service = actor.service`, `event_id = causationEventId`, `actor_type`, `actor_id`, `details = { from, to, version, round, reason, actorRole }`.
7. Insert the outbox row `mail.message.state_changed.v1` (L7): `event_id = state_event_id`, `aggregate_type 'message'`, `aggregate_id` = decimal id, `correlation_id = request.correlationId ?? 'message:<id>'`, payload validated with the schema before insert.
8. Count `lifecycle_transitions_total{from,to,result="applied"}`; return `applied`.

#### L5.2 Creation (SMTP commit)

`initialLifecycle({ messageId, receivedAt, organizationId, causationEventId, correlationId, service, at })` (pure) returns:

- `messageFields`: `{ status: 'persisted', version: 1, lifecycleRound: 0, statusReason: 'committed', statusChangedAt: at }` to spread into the existing `tx.emailMessage.create`;
- `historyRows`: two rows, written by the package function `writeInitialHistory(tx, init)` (one `createMany`; the only way a creator writes them, so the one-door test of L5.9 stays strict) (E1: `NULL → received`, version 0, reason `smtp_accepted`; E2: `received → persisted`, version 1, reason `committed`; `actor_role ingestion`, `actor_service smtp-adapter`, `actor_type system`, `event_id` = the `mail.message.received.v1` event id, `correlation_id lmtp:<queueId>`, `transition_key` = SHA-256 of `ingest:<messageId>:received` / `ingest:<messageId>:persisted`, `occurred_at = at`, `state_event_id NULL`).

No `email_events` row (the existing `received` row is the timeline entry) and no `state_changed` outbox row (`mail.message.received.v1` is the notification of `persisted`, documented in contracts). `decideTransition` is called for E1 and E2 in a unit test only (pure), not on the hot path.

#### L5.3 Transition keys (idempotency)

| Producer           | `transitionKey`                                               |
| ------------------ | ------------------------------------------------------------- |
| smtp-adapter       | `ingest:<messageId>:received`, `ingest:<messageId>:persisted` |
| dev pass-through   | `evt:<receivedEventId>:approved`                              |
| planner            | `evt:<approvalEventId>:delivery_pending`                      |
| recorder (derived) | `signal:<deliveryId>:<signalKey>:<to>`                        |
| lifecycle check    | `recover:<messageId>:<version read>:<to>`                     |
| sweeper            | `expire:<messageId>:<version read>`                           |
| api                | `api:<organizationId>:<operation>:<Idempotency-Key>`          |
| future stages      | `evt:<causing eventId>:<to>`                                  |

The key is unique per message (`(message_id, transition_key, received_at)`); history partitions are kept 3 months, so a duplicate older than that is decided by the state rules only (documented).

#### L5.4 Concurrency

- Lock order everywhere: `delivery_reinjections` row (queue-id binding only) → `email_messages` row → `email_deliveries` rows → recipients. The lifecycle lock is the existing message lock; re-locking the same row in the same transaction is free.
- Parallel writers on one message serialize on the row lock; each re-reads the committed state after the winner, so there is no lost update; losers get `duplicate`, `stale` or a different `apply`.
- `transitionMessageWithRetry` retries deadlocks, lock-wait timeouts, `P2034` and `LifecycleVersionConflictError` with equal-jitter backoff (base 20 ms, max 500 ms), at most `maxAttempts`; then rethrows (queue consumers classify these as transient, 3.2 Q8).
- Inside a caller's transaction the service never retries: the error propagates and the caller's transaction (and its consumer retry) re-runs everything.

#### L5.5 Metrics (`LifecycleMetrics`, injected; each app adapts it to its `MetricsService`)

| Series                                        | Meaning                                                                        |
| --------------------------------------------- | ------------------------------------------------------------------------------ |
| `lifecycle_transitions_total{from,to,result}` | `result` = `applied`, `duplicate`, `stale`, `invalid` (`from` = current state) |
| `lifecycle_transitions_ignored_total{reason}` | `reason` = the `why` of `stale` / `invalid`                                    |
| `lifecycle_version_conflicts_total`           | CAS failures and retried deadlocks in `transitionMessageWithRetry`             |

#### L5.6 Logging

`{ messageId, organizationId, from, to, result, why, version, round, actorRole, actorService, causationEventId }`. Never subjects, addresses or keys of S3 objects.

#### L5.7 Errors

`LifecycleVersionConflictError` (retryable), `LifecycleContractError` (programming error: unknown state/reason/role, transition key empty or > 512 characters; never retried). `isRetryableLifecycleError(e)`.

#### L5.8 Read helpers

`readLifecycle(db, message)` (no lock, for api reads) and `lifecycleHistory(db, message, page)` are **not** in the package: the api reads through its own repositories on the replica (L12).

#### L5.9 One-door test

A unit test in the package (`one-door.test.ts`) scans `apps/*/src` and `packages/*/src` (excluding `packages/message-lifecycle` and `packages/database/prisma`) for `emailMessageStatusHistory.create`, `UPDATE email_messages SET status`, and `emailMessage.update*(` calls whose `data` contains `status`/`version`, and fails with the file list. Test fixtures under `integration/` are excluded (they may set up states directly, L8.6). WP2 creates the test with an explicit allow-list containing only the step 2.3 writers that still exist in wave 2 (`packages/mail-routing/src/delivery-state/recorder.ts`); WP3 removes those writers and empties the allow-list, so after wave 3 the list is empty and stays empty.

### L6. Ignored transitions

A `stale` or `invalid` outcome of an asynchronous producer (consumer, recorder, sweeper, check) writes one `email_events` row in the caller's transaction: `event_type = 'lifecycle.ignored'`, `source_service = actor.service`, `event_id = causationEventId`, `details = { requested: to, current: state, result, why, version, round, expectedRound, expectedVersion, reason, actorRole }`, and counts `lifecycle_transitions_total{result}` and `lifecycle_transitions_ignored_total{reason}`. Duplicates only count. The api passes `recordIgnored: false` (the client receives `409`, L10.4). Because the consumer ledger de-duplicates redeliveries, an ignored event is recorded once per handled event.

### L7. Events (`packages/event-contracts`, registry, topology v2)

**`mail.message.state_changed.v1`** (`messageStateChangedV1`), exchange **`email.events`**, aggregate `message`, written by the transition service for every applied transition except creation (L5.2):

```ts
{
  messageId: decimalId, receivedAt: iso, direction,
  previousState: MessageStateValue | null,
  state: MessageStateValue,
  version: int ≥ 0, lifecycleRound: int 0..65535,
  reasonCode: /^[a-z0-9_]{1,64}$/,
  actorRole: ActorRoleValue, actorType: 'system' | 'user' | 'api_key', actorService: string 1..64,
  causationEventId: uuid | null,
  changedAt: iso,
}
```

`event-contracts` exports `MESSAGE_STATES` (the fifteen values) and `ACTOR_ROLES`; `@email-gateway/message-lifecycle` re-exports them (single list, defined once in event-contracts, which has no dependencies on the lifecycle package; a lifecycle unit test asserts the transition table uses exactly these). No actor id (public id) in the event.

**`mail.message.rescan_requested.v1`** (`messageRescanRequestedV1`), exchange **`email.security`**, aggregate `message`, written by the api's rescan (L10.2):

```ts
{
  messageId, receivedAt, direction,
  emlS3Key: 'org/<id>/…',
  lifecycleRound: int ≥ 1,
  scanKind: 'rescan',
  requestedAt: iso,
  requestedBy: 'user' | 'api_key',
}
```

**`mail.delivery.approved.v1` gains an optional `lifecycleRound: int 0..65535`** (non-breaking: absent = 0; written by the dev pass-through and the release from this step on; 5.2 must write it).

**Topology v2** (`TOPOLOGY_VERSION = 2`): unchanged six exchanges and fourteen queues; five new bindings `email.security: org.*.mail.message.rescan_requested.v1` → `scan.auth`, `scan.spam`, `scan.url`, `scan.attachment`, `scan.dlp` (dormant; their stages, 4.x, consume both `parsed.v1` and `rescan_requested.v1`). `mail.message.state_changed.v1` needs no binding: it is published to `email.events`, whose `org.#` binding feeds `email.analytics` (dormant). `infrastructure/rabbitmq/definitions.json` is regenerated; the vhost description becomes `email-gateway topology v2`; `init.mjs` imports additively (existing objects unchanged). `messaging-topology.md` documents v2. No permission change (the relay already publishes `^org\.` keys to every exchange).

### L8. Producers wired in this step

#### L8.1 smtp-adapter commit (E1, E2)

`IngestionRepository.commit`: `const init = initialLifecycle(...)`; spread `init.messageFields` into `emailMessage.create`, and after it `await writeInitialHistory(tx, init)` (one `createMany` with the two history rows). `causationEventId` = the existing `eventId` of the received event (already generated before the transaction). Nothing else changes in the hot path (no lock, no read). The smtp-concurrency regression (40 sessions × 1 000 messages, step 2.2 §12.3: 9.6 s SMTP, 59.7 s stored) must stay within 15 % of its baseline; WP5 records the numbers.

#### L8.2 email-worker (no state write; documented)

The MIME stage **does not** change the lifecycle state (L2 "Where `persisted` sits"). Rationale: the parse is a sub-stage of `persisted` with its own stage table; its consumers (4.1, 5.2) own the next transition; writing a parse state would be a sixteenth state or a fake producer of `scanning`/`scan_failed`. The email-worker README and `contracts.md` state it. No code change in `apps/email-worker` except its fixtures if WP1's enum change breaks them.

#### L8.3 Dev pass-through (E4)

`DevPassThroughApprover.approve`, in its `processOnce` transaction, **first** calls `transitionMessage(tx, { to: 'approved', reason: 'dev_passthrough', actor: { role: 'dev_passthrough', service: 'delivery-worker', type: 'system' }, transitionKey: 'evt:<receivedEventId>:approved', causationEventId, correlationId, expectedRound: 0, expectedFrom: ['persisted'] })`:

- `applied` → write the approval outbox rows (now with `lifecycleRound: 0`) and `delivery.approved` events as today;
- `duplicate` with state `approved` → write nothing more (a re-run after a crash already committed; cannot happen inside one ledger transaction, kept for safety);
- anything else (`stale`, `invalid`, `not_found`) → write no approval, log at info `{ eventId, messageId, result, why }`, count `delivery_approvals_skipped_total{reason}` (new series, reason = `lifecycle_<result>`), return.

Config validation is unchanged (refuses the pass-through outside `APP_ENV` local/ci). The edge's role `dev_passthrough` is only produced here.

#### L8.4 Delivery planner (E20)

Replace `markMessageDeliveryQueued` (removed from mail-routing) in `DeliveryPlanner.plan`, at the same place (after recipients are known, before reading existing deliveries; it takes the message lock first as today):

1. `const snap = await lockLifecycle(tx, { id, receivedAt, organizationId })` (package helper: `SELECT … FOR UPDATE`, returns the `LifecycleSnapshot` or null; it takes the message lock first, as the planner does today). `round = payload.lifecycleRound ?? 0`.
2. `snap.state === 'approved' && snap.round === round` → `transitionMessage(tx, { to: 'delivery_pending', reason: 'delivery_planned', actor { role: 'delivery', service: 'delivery-worker', type: 'system' }, transitionKey 'evt:<approvalEventId>:delivery_pending', causationEventId: approvalEventId, correlationId, expectedRound: round, expectedFrom: ['approved'] })` → `applied` → plan.
3. `snap.state ∈ {delivery_pending, delivery_retry} && snap.round === round` → plan **without** a transition (a later chunk of a multi-chunk approval, or a duplicate approval: the existing `(recipient_id, delivery_seq)` checks decide). No ignored row is written for this normal case.
4. Anything else (null, another state, another round) → return `empty('rejected', 'lifecycle_state')` (new `PlanResult.reason`), log `{ eventId, messageId, state, round, approvalRound }`, count `delivery_approvals_rejected_total{reason="lifecycle_state"}`. The ledger row commits (the approval is handled: it no longer applies). Approvals of an older round are therefore never planned.

The planner signals then derive the message state (L9) in the same transaction (an all-refused plan ends in `rejected/delivery_failed` immediately).

#### L8.5 Shared recorder (E21–E24) — see L9.

#### L8.6 Test fixtures

Integration fixtures may insert `email_messages` rows in any state directly (they set up preconditions, they are not producers) and must then insert a matching history row through `initialLifecycle` or plain inserts. No production code path may do so (L5.9).

### L9. Per-recipient delivery state and the derived message state

**Per-recipient table (mail-routing, explicit data).** `packages/mail-routing/src/delivery-state/transitions.ts` keeps `nextDeliveryState` with **identical behaviour** (every existing test passes unchanged) but expresses the non-terminal moves and source restrictions as data:

```ts
export const DELIVERY_TRANSITIONS: readonly {
  from: DeliveryStatus;
  to: DeliveryStatus;
  sources: readonly DeliverySignalSourceName[] | 'any';
  condition?: 'first_signal' | 'dsn_2xx' | 'not_older';
}[];
```

Rows (from the R9.1 rules): `pending → pending` (planner, `first_signal`); `pending|in_progress → queued|deferred` (any, `not_older`); `pending|in_progress → unknown` (reconciler); `queued → deferred|unknown` (any, `not_older`); `deferred → deferred|queued|unknown` (any, `not_older`); `pending|in_progress → delivered` (postfix_log, `dsn_2xx`); `pending|in_progress → bounced` (postfix_log, bounce_notice); `queued|deferred|unknown → delivered` (postfix_log, `dsn_2xx`); `queued|deferred|unknown → bounced` (any); `* non-terminal → expired|failed|suppressed` (any). Terminal states have no outgoing rows. `nextDeliveryState` looks rows up instead of branching. An exhaustive test iterates every `(from, to, source)` triple and asserts the table's verdict equals the step 2.3 behaviour (the old function is kept in the test file as the oracle).

**Derived message state (`deriveDeliveryState`, message-lifecycle, pure).** Input: counts of `email_recipients.status` for the message (`pending`, `deferred`, `delivered`, `bounced`, `failed`, `quarantined`, `discarded`). Output `{ state, reason } | null`:

- `pending + deferred > 0` → `deferred > 0 ? { delivery_retry, delivery_deferred } : { delivery_pending, delivery_requeued }`;
- otherwise `delivered > 0` → `{ delivered, delivered === total ? delivery_complete : delivery_partial }`;
- otherwise (and total > 0) → `{ rejected, delivery_failed }`;
- total = 0 → `null`.

`quarantined` and `discarded` recipients count as settled (5.3 partial quarantine: the message is delivered for the others, as the step 1.1 design §3.4 says). A recipient that is approved for delivery is therefore never left `quarantined`: a release (L10.3) sets its released recipients to `pending` first. `email_recipients.status` already maps `queued`/`unknown` → `pending` and `expired`/`failed`/`suppressed` → `failed`.

**`applyDerivedDeliveryState(tx, message, ctx)`** (message-lifecycle): reads the counts (`SELECT status, COUNT(*) FROM email_recipients WHERE message_id = ? AND received_at = ? GROUP BY status`; the message row is already locked by the caller), derives, and if the derived state differs from the current state and the current state is `delivery_pending` or `delivery_retry`, calls `transitionMessage` with the derived reason, the caller's actor (`delivery` or `recovery`) and key. From any other state nothing happens (no ignored row: a late per-recipient signal after expiry or a manual state is normal and stays visible per recipient; counted as `lifecycle_derived_skipped_total{state}`).

**Recorder wiring (mail-routing).** In `recordDeliverySignal`, after an applied signal whose delivery has the **highest `delivery_seq` of the message** (`SELECT MAX(delivery_seq) … (message_id, received_at)`): `applyDerivedDeliveryState(tx, …, { actor: { role: 'delivery', service: ctx.sourceService, type: 'system' }, transitionKey: 'signal:<deliveryId>:<signalKey>:<derived state>', causationEventId: ctx.eventId, correlationId: 'delivery:<deliveryId>' })`. A signal of an older `delivery_seq` (after a release) still updates its delivery and recipient but never the message state. `setMessageStatus`, `aggregateMessageStatus`, `MessageVersionConflictError`'s use for the message, `markMessageDeliveryQueued` and `QUEUEABLE` are removed; `RecordDeliverySignalResult.messageStatus` becomes `messageState?: MessageState`. The recorder's `isRetryable` adds `isRetryableLifecycleError`. `RecorderContext` gains optional `lifecycleMetrics`.

### L10. Administrative rescan and quarantine release (api)

New module `apps/api/src/modules/messages/` (controller only translates; logic in `MessageLifecycleService`; reads in `MessageLifecycleReadService`; repositories separate for writer and reader).

#### L10.1 Common rules

- Path parameter `{messageId}` = registry public id (UUID, `400` otherwise); the message is found on the **writer** with `tenantWhere(scope, …)` on both the registry row and the partitioned row; another organization's message → `404 message_not_found` (as the deliveries API; "refuse cross-tenant access" without confirming existence).
- Header **`Idempotency-Key`** required (1–128 characters, `^[A-Za-z0-9._:-]+$`), else `400 idempotency_key_required` / `idempotency_key_invalid` (L11).
- Body (zod strict): `{ expectedVersion: int ≥ 0, reason: string 10..500 (operator text, stored in the audit row only, never in history/events) }`.
- Principals: users and API keys holding the permission (`@RequirePermissions`); actor `{ role: 'operator', service: 'api', type: principal.kind, id: principal public id }`.
- One writer transaction (`TransactionRunner` / `prisma.$transaction`, timeout from config `API_TX_TIMEOUT_MS` if it exists, else 10 s): idempotency lookup → message lock → `transitionMessage(…, recordIgnored: false)` → stage effects → audit row → idempotency record.
- Outcome mapping: `applied` → `202`; `duplicate/transition_key` → cannot happen (the idempotency record answers first; if it does, treat as replay of the stored record); `stale/version_mismatch` → `409 message_version_conflict`; `invalid/*`, `stale/final_state|overtaken`, `duplicate/same_state` → `409 message_state_conflict`; `not_found` → `404`. `409` bodies: `{ statusCode, code, message, currentState, currentVersion }` (no content). `409`/`404`/`400` outcomes are **not** stored under the key (the client may fix and retry with the same key).
- Audit (`AuditService`, same transaction): `action` `message.rescan_requested` / `message.quarantine_released`, `resource_type 'message'`, `resource_id` = public id, `metadata = { fromState, toState, version, lifecycleRound, reason (operator text), idempotencyKeyHash (SHA-256 hex), eventIds, deliverySeq?, recipientCount? }`.
- Metrics (api `/metrics`): `api_message_lifecycle_operations_total{operation, outcome}` (`applied`, `replayed`, `conflict`, `not_found`, `invalid_request`).

#### L10.2 `POST /api/v1/messages/{messageId}/rescan` — permission **`message:rescan`** (new)

Edge E19. Effects in the transaction: outbox `mail.message.rescan_requested.v1` (`lifecycleRound` = the new round, `emlS3Key` = the row's key, which must start with `org/<organizationId>/` else `409 message_state_conflict` and an error log), plus the service's `state_changed` row. Response `202`:

```json
{
  "messageId": "<uuid>",
  "state": "scanning",
  "version": 7,
  "lifecycleRound": 1,
  "rescanEventId": "<uuid>",
  "note": "scan stages are not deployed before Phase 4; the message stays in scanning until they are or until its expiry deadline"
}
```

**Scope of this step: the state transition and the request contract only; executing the scan is deferred to step 4.1** (verification round 2, 13.10). `note` is present while no scan stage exists (a constant in the api, removed by 4.1). Until 4.x the request lands in the five dormant scan queues (bounded, `drop-head`), which is the documented contract; the message stays `scanning` until 4.x consumes it or the sweeper expires it (L13), after which another rescan is allowed (E19 from `expired`).

#### L10.3 `POST /api/v1/messages/{messageId}/release` — permission **`quarantine:release`** (existing)

Edges E14 (`quarantined`, reason `quarantine_release`) / E15 (`held_for_review`, reason `review_release`), `expectedFrom: [quarantined, held_for_review]`, the reason chosen from the current state.

Before the transition: if `quarantine_messages` has rows for `(message_id, message_received_at)` → `409 quarantine_workflow_required` (per-recipient quarantine with re-validation and approvals is 5.3; this operation must not bypass it). Releasable recipients: `email_recipients` of the message with status `pending` or `quarantined`, ordered by `rcpt_seq`; none → `409 no_releasable_recipients`.

In the same transaction the released recipients that are `quarantined` become `pending` (`email_recipients.status`, not a lifecycle column; verification round 2, 13.10). L9 counts `quarantined` as settled, so without this a planner refusal or a delivery of the first released recipient (or of the first 1 000-recipient chunk) would derive a final `rejected`/`delivered` while the other released recipients were still to be planned, and the planner would then refuse their approvals (`lifecycle_state`).

Effects (same transaction, after the applied transition): `deliverySeq = (MAX(email_deliveries.delivery_seq) of the message) + 1`, or `1` when there is none (releases always use ≥ 1, step 2.3 R5); approval outbox rows `mail.delivery.approved.v1` in chunks of ≤ 1 000 recipients (`source: 'quarantine_release'`, `emlS3Key` = the row's key, `lifecycleRound` = the new round, `approvedAt` = now, `event_id` = UUIDv7, `correlation_id` = `api:<request correlation id>`), one `email_events` `delivery.approved` per chunk (`details: { source, approvalEventId, deliverySeq, recipientCount }`, `actor_type`/`actor_id` = the operator). The relay publishes them to `email.delivery.pending`; the planner's provenance check passes (the outbox row exists) and its lifecycle check (L8.4) plans them: **delivery really happens** through the step 2.3 path, and the derived state moves the message to `delivery_pending` → `delivered`.

Response `202`: `{ messageId, state: 'approved', version, lifecycleRound, deliverySeq, approvalEventIds: [...], recipientCount }`.

#### L10.4 What is refused

| Case                                                           | Response                           |
| -------------------------------------------------------------- | ---------------------------------- |
| No permission                                                  | `403` (guard)                      |
| Another organization's message, or unknown id                  | `404 message_not_found`            |
| Missing/invalid Idempotency-Key, invalid body                  | `400`                              |
| Same key, different request (body, path, operation, principal) | `422 idempotency_key_reused`       |
| `expectedVersion` ≠ current version                            | `409 message_version_conflict`     |
| Source state not allowed for the operation                     | `409 message_state_conflict`       |
| Release with `quarantine_messages` rows                        | `409 quarantine_workflow_required` |
| Release without releasable recipients                          | `409 no_releasable_recipients`     |

### L11. Idempotency-Key store (api)

New table `api_idempotency_keys` (not partitioned, no FK; §3.1) and `apps/api/src/http/idempotency/` (`IdempotencyService`, `IdempotencyKeyPipe`/decorator for the header, OpenAPI header doc helper `ApiIdempotencyKey()`), reusable by 6.1:

- Request fingerprint: SHA-256 of canonical JSON `{ operation, resourceId (public id), body }`.
- `runOnce(tx, { organizationId, principal ('user:<publicId>' | 'api_key:<publicId>'), operation, key, fingerprint }, work)`: `SELECT … FOR UPDATE` by `(organization_id, idempotency_key)`; found and not expired → same principal, operation and fingerprint → return `{ replay: true, statusCode, body }` (response header `Idempotency-Replayed: true`); otherwise → `422 idempotency_key_reused`. Not found → run `work`, insert the record (`status_code`, `response` JSON, `expires_at = now + 24 h`) in the same transaction. A concurrent insert of the same key (P2002) rolls the transaction back; the service retries once, which then replays or refuses.
- Expired records are ignored (treated as absent and replaced: `DELETE … WHERE id = ?` then insert, in the same transaction).
- Purge: `db:partitions` retention purge deletes `expires_at < now − 1 day` in batches (`RETENTION_PURGES` gains `apiIdempotencyGraceDays: 1`).
- The key column is case-sensitive (`utf8mb4_bin`).

### L12. Read APIs (tenant-scoped, replica)

In the new messages module (reader: `PrismaReadService`, whose writer fallback above the lag threshold is the existing behaviour; read-after-write right after a POST may lag and is documented):

- `GET /api/v1/messages/{messageId}/lifecycle` — permission `message:read`:

  ```json
  { "messageId": "<uuid>", "receivedAt": "…", "direction": "inbound",
    "state": "delivered", "statusReason": "delivery_partial", "version": 5, "lifecycleRound": 0,
    "statusChangedAt": "…",
    "parse": { "status": "parsed", "completedAt": "…" } | null,
    "recipients": { "total": 3, "byStatus": { "delivered": 2, "bounced": 1 } },
    "deliverySeq": 0 | null,
    "actions": { "rescan": false, "release": false } }
  ```

  `actions` is derived from the state and the edges only (not from the caller's permissions).

- `GET /api/v1/messages/{messageId}/lifecycle/history?limit&cursor` — permission `message:read`: applied transitions oldest first, cursor on the history id (`(message_id, received_at)` pruning): `{ version, fromState, toState, reasonCode, lifecycleRound, actor: { role, type, service, id }, causationEventId, correlationId, occurredAt, changedAt }`. Legacy rows show `actor.role = 'legacy'`.
- `GET /api/v1/messages/{messageId}/deliveries` keeps its shape; its `message.status` becomes the fifteen states and gains `statusReason` (the enum in `deliveries.schemas.ts` is replaced by the shared `MESSAGE_STATES`).
- OpenAPI snapshot (`docs/api/openapi.json`, `apps/api/test/openapi.test.ts`) and `docs/api/README.md` updated.

### L13. Expiry sweeper (event-relay)

**Where:** `apps/event-relay` (`src/lifecycle/expiry-sweeper.ts`, role flag `LIFECYCLE_EXPIRY_ENABLED`). Why: event-relay is the reconciliation deployable (ADR-0023): writer only, no business stage of its own, already runs lock-sharded loops (`AdvisoryLocks`, `GET_LOCK`) and a single-instance reconciler, and expiry spans every stage (so neither email-worker nor delivery-worker is the natural owner). It needs no broker (it writes outbox rows; the relay publishes them).

**Algorithm** (`LIFECYCLE_EXPIRY_SHARDS` shard loops, a shard runs only while holding `GET_LOCK('er:lifecycle-expiry#<i>/<n>')` through the shared `AdvisoryLocks`, at most `LIFECYCLE_EXPIRY_MAX_HELD_SHARDS` per replica; every `LIFECYCLE_EXPIRY_INTERVAL_MS`):

1. For each state with a deadline > 0 (L13 config), read candidates: `SELECT id, received_at, organization_id, status, version FROM email_messages WHERE status = ? AND status_changed_at < NOW(3) - INTERVAL ? HOUR AND status_changed_at >= NOW(3) - INTERVAL ? DAY AND MOD(id, ?) = ? ORDER BY status_changed_at LIMIT ?` (index `(status, status_changed_at)`, one range per monthly partition; the lookback `LIFECYCLE_EXPIRY_LOOKBACK_DAYS` bounds the **state age**, not `received_at`: a message rescanned or released long after it was received must still expire; changed in verification round 2, 13.10). The per-pass total is bounded by `LIFECYCLE_EXPIRY_BATCH_SIZE` per shard.
2. Each candidate: `transitionMessageWithRetry(prisma, { to: 'expired', reason: 'deadline_exceeded', actor { role: 'sweeper', service: 'event-relay', type: 'system' }, transitionKey: 'expire:<id>:<version>', expectedVersion: version, expectedFrom: [status] }, { timeoutMs: LIFECYCLE_TX_TIMEOUT_MS, maxAttempts: 3 })`, one short transaction per message. A live transition in between changes the version → `stale/version_mismatch` → skipped (`lifecycle_expiry_skipped_total{reason="changed"}`). Under the lock the service re-reads the row, so the sweeper can never overwrite a newer state.
3. Metrics: `lifecycle_expired_total{state}`, `lifecycle_expiry_overdue{state}` (gauge: candidates found in the last pass, capped at the batch size), `lifecycle_expiry_pass_seconds` (histogram), `lifecycle_expiry_shards_held` (gauge), `lifecycle_expiry_skipped_total{reason}`.
4. A database error → backoff (`RELAY_BROKER_BACKOFF_BASE_MS`/`MAX_MS` reused) and the shard loop continues; the lock is released on stop.

Expiry from a delivery state is final for the message (the per-recipient states keep recording late signals). Delivery deadlines must exceed Postfix's `maximal_queue_lifetime` (5 d): config refuses `LIFECYCLE_DEADLINE_DELIVERY_PENDING_HOURS` / `_DELIVERY_RETRY_HOURS` in `1..120` (0 disables).

### L14. Recovery

| Failure                                                                                                                              | Recovery                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Crash between consume and transition (queue consumers)                                                                               | The transition is in the consumer's transaction with its ledger row: a crash rolls both back. RabbitMQ redelivers (unacked); if the event was acked without a ledger row (impossible by Q6) or lost, the step 3.2 reconciler re-drives it (no ledger row after `RECONCILE_UNCONSUMED_AFTER_SECONDS`). The re-run applies the transition once (transition key). |
| Crash in the dev pass-through                                                                                                        | Its outbox poller cursor stays at the unhandled row (R6); the re-read applies once.                                                                                                                                                                                                                                                                            |
| Writer outage mid-transition                                                                                                         | The transaction fails (connection lost → InnoDB rolls back, the row lock is released); the consumer classifies it transient (3.2 Q8) and retries; `transitionMessageWithRetry` retries; the api returns `503`/`500` and the client retries with the same Idempotency-Key.                                                                                      |
| Derived delivery transition lost (bug, a signal recorded through a path that skipped derivation, legacy backfill `delivery_pending`) | **Lifecycle check** (below).                                                                                                                                                                                                                                                                                                                                   |
| Stuck in any non-final state                                                                                                         | Sweeper (L13) after the deadline; metrics before that.                                                                                                                                                                                                                                                                                                         |

**Lifecycle check** (`apps/event-relay/src/lifecycle/lifecycle-check.ts`, role flag `LIFECYCLE_CHECK_ENABLED`, single active instance via `GET_LOCK('er:lifecycle-check')`, every `LIFECYCLE_CHECK_INTERVAL_MS`):

1. For `approved`, `delivery_pending`, `delivery_retry`: messages with `status_changed_at < now − LIFECYCLE_CHECK_AFTER_SECONDS` and `status_changed_at ≥ now − LIFECYCLE_CHECK_LOOKBACK_HOURS` (the state age, not `received_at`: a quarantined message may be released after up to 90 days; changed in verification round 2, 13.10), keyset on `(status_changed_at, id)` with an in-memory cursor per state (reset when a pass returns fewer than `LIFECYCLE_CHECK_BATCH_SIZE` rows).
2. Per message, in one writer transaction: lock the message (`lockLifecycle`); for `delivery_pending` / `delivery_retry`, `applyDerivedDeliveryState` with actor `{ role: 'recovery', service: 'event-relay' }`, key `recover:<id>:<version>:<derived>`. Applied → `lifecycle_recovered_total{from,to}` and a warn log (a recovery means a lost derivation). `approved` is only counted (`lifecycle_stuck_messages`): the planner moves it to `delivery_pending` in the approval's own transaction, so a stuck `approved` means the approval was not consumed, which the step 3.2 reconciler re-drives.
3. Gauges `lifecycle_stuck_messages{state}` (count of messages per non-final state older than `LIFECYCLE_CHECK_AFTER_SECONDS`, capped at 100 000, computed at most every `LIFECYCLE_CHECK_INTERVAL_MS` per state with `COUNT(*) … LIMIT`-bounded subqueries over the index).
4. Alert rules (`infrastructure/monitoring/rules/lifecycle.rules.yml`, validated with `promtool`): `LifecycleRecoveries` (increase > 0 in 1 h, warning), `LifecycleStuckMessages` (any non-final state > 100 for 30 m), `LifecycleExpiryNoShardOwner` (held shards < `LIFECYCLE_EXPIRY_SHARDS` for 10 m), `LifecycleInvalidTransitions` (rate of `result="invalid"` > 0 for 15 m). Each with `runbook_url` to `docs/runbooks/message-lifecycle.md`.

### L15. Case-sensitive Postfix queue ids (fix found in step 3.2)

Forward migration `queue_id_case_sensitive`: `email_messages.mta_queue_id`, `email_deliveries.outbound_queue_id`, `email_deliveries.dsn_queue_id`, `delivery_reinjections.queue_id`, `delivery_status_events.queue_id` → `VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL` (charset unchanged, so no data conversion; the existing secondary indexes are rebuilt by MySQL). Partitioning is kept (`ALTER TABLE … MODIFY` on a partitioned table rewrites every partition; no `PARTITION BY` clause is repeated). Other candidates checked: `bounce_events` has no queue-id column; `message_identities.ingest_key` is a hex hash. Prisma does not model column collation: the implementer verifies that `prisma migrate diff` shows no drift and documents it in `docs/database/schema-reference.md` ("collation `utf8mb4_bin`, case-sensitive, step 3.3"). Regression tests (two ids differing only in case, `4jKFxV5fmHz12JnW` / `4jKFxV5fMHz12Jnw`): recorder `queueId` match (mail-routing integration), smtp-adapter bounce notice matching (smtp-adapter integration), and `tests/integration/schema.test.ts` asserting the five collations.

### L16. Test hygiene (found in step 3.2)

- `apps/api/integration/common.test.ts`: the SmtpEmailSender probe gets a unique marker (`Message-ID`/subject token per run); `afterAll` finds the message(s) it created (writer: `email_messages` of the relay domain's organization with `created_at ≥ test start` and the run's `internet_message_id`), deletes their postfix-outbound queue files (`postsuper -d <outbound_queue_id>` through `docker compose exec`, ignoring unknown ids, and `postsuper -d ALL deferred` is **not** used) and their S3 objects (EML key and `org/<id>/parts/<messageId>/…` prefix of the mail bucket). The test still skips when Postfix or the adapter is down.
- Stack suites: a shared teardown helper (`tests/integration/support/broker.ts`, management API) purges the dormant queues (`scan.auth`, `scan.spam`, `scan.url`, `scan.attachment`, `scan.dlp`, `scan.sandbox`, `email.policy.evaluate`, `email.quarantine`, `email.archive`, `email.analytics`) in `afterAll` of every suite that sends mail; never a work, delay or dead-letter queue.
- `tests/integration/routing-signals.test.ts`: instead of deleting the tailer cursor (whole-file re-read), rewind it to the byte offset recorded before this test's mail was sent (same inode / file identity fields as the cursor stores), and wait until the cursor passes the offset recorded at the check point; the timeout no longer depends on the accumulated maillog size.

### L17. Who produces the states of later stages

| State / edge                                                                                                      | Producer step                                       | Notes                                                                                   |
| ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `scanning` (E3), `scanned` (E6), `scan_failed` (E7)                                                               | 4.1 (orchestration in email-worker), 4.2–4.5 stages | Must pass `expectedRound` from `parsed.v1` (0) or `rescan_requested.v1`                 |
| `policy_evaluated` (E5, E8, E9), `approved` (E10), `quarantined` (E11), `held_for_review` (E12), `rejected` (E13) | 5.2 policy-engine                                   | Writes `mail.delivery.approved.v1` with `lifecycleRound`; replaces the dev pass-through |
| E16–E18, operator delete                                                                                          | 5.3                                                 | Per-recipient `quarantine_messages`; release with re-validation                         |
| `archived` (E25)                                                                                                  | 8.1                                                 |                                                                                         |

### Brief requirements → decisions

| Requirement                                  | Where                       |
| -------------------------------------------- | --------------------------- |
| 15 states                                    | L2                          |
| Explicit valid transitions, prevent invalid  | L3, L4                      |
| Record every transition in MySQL             | L5.1 (history), L5.2, L6    |
| Actor/service, timestamps, reason            | §3.1 history columns, L5.1  |
| Concurrent updates, optimistic/atomic        | L5.1 (lock + CAS), L5.4     |
| Retry and recovery                           | L5.4, L14                   |
| Administrative rescan                        | L10.2                       |
| Quarantine release                           | L10.3                       |
| Per-recipient delivery state                 | L9                          |
| Idempotent transition service                | L5.3, L11                   |
| Older event never overwrites newer state     | L4, L9 (derived), L13 (CAS) |
| Tests (state machine, concurrency, recovery) | §8                          |
| Mermaid diagrams                             | diagrams 11 and 22 (WP1)    |

---

## 3. Data model

### 3.1 Migration `message_lifecycle` (WP1)

Created with `pnpm db:migrate:dev --create-only --name message_lifecycle`, SQL written by hand (Prisma cannot generate the widen/backfill/narrow sequence). Statement order:

```sql
-- 1. Widen (append new values; in place).
ALTER TABLE `email_messages` MODIFY `status` ENUM('received','scanning','scanned','policy_evaluated','quarantined','delivery_queued','delivered','partially_delivered','discarded','failed','persisted','approved','rejected','delivery_pending','delivery_retry','archived','scan_failed','held_for_review','expired') NOT NULL DEFAULT 'received';
ALTER TABLE `email_message_status_history` MODIFY `from_status` ENUM(<same 19>) NULL, MODIFY `to_status` ENUM(<same 19>) NOT NULL;

-- 2. New columns (history first, so the backfill can fill them).
ALTER TABLE `email_messages`
  ADD COLUMN `lifecycle_round` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN `status_reason` VARCHAR(64) NULL;
ALTER TABLE `email_message_status_history`
  ADD COLUMN `lifecycle_round` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN `actor_role` VARCHAR(32) NOT NULL DEFAULT 'legacy',
  ADD COLUMN `actor_service` VARCHAR(64) NOT NULL DEFAULT 'legacy',
  ADD COLUMN `actor_type` ENUM('system','user','api_key') NOT NULL DEFAULT 'system',
  ADD COLUMN `actor_id` VARCHAR(64) NULL,
  ADD COLUMN `correlation_id` VARCHAR(128) NULL,
  ADD COLUMN `transition_key` CHAR(64) NULL,
  ADD COLUMN `state_event_id` CHAR(36) NULL,
  ADD COLUMN `occurred_at` DATETIME(3) NULL;

-- 3. Backfill (L2 mapping).
INSERT INTO `email_message_status_history` (received_at, message_id, organization_id, version, from_status, to_status, reason_code, changed_at, created_at)
  SELECT m.received_at, m.id, m.organization_id, 0, NULL, 'received', 'lifecycle_backfill', m.received_at, NOW(3)
  FROM `email_messages` m
  WHERE NOT EXISTS (SELECT 1 FROM `email_message_status_history` h WHERE h.message_id = m.id AND h.received_at = m.received_at AND h.version = 0);
INSERT INTO `email_message_status_history` (… version = m.version + 1, from 'received', to 'persisted', reason 'lifecycle_backfill', changed_at NOW(3) …)
  SELECT … FROM `email_messages` m WHERE m.status = 'received';
UPDATE `email_messages` SET status = 'persisted', version = version + 1, status_reason = 'lifecycle_backfill', status_changed_at = NOW(3) WHERE status = 'received';
UPDATE `email_messages` SET status = 'delivery_pending', status_reason = 'delivery_planned' WHERE status = 'delivery_queued';
UPDATE `email_messages` SET status_reason = 'delivery_complete' WHERE status = 'delivered';
UPDATE `email_messages` SET status = 'delivered', status_reason = 'delivery_partial' WHERE status = 'partially_delivered';
UPDATE `email_messages` SET status = 'rejected', status_reason = 'delivery_failed' WHERE status = 'failed';
UPDATE `email_messages` SET status = 'rejected', status_reason = 'discarded' WHERE status = 'discarded';
UPDATE `email_message_status_history` SET from_status = <mapped> WHERE from_status IN ('delivery_queued','partially_delivered','failed','discarded');
UPDATE `email_message_status_history` SET to_status = <mapped> WHERE to_status IN (…);
-- (history rows with from/to 'received' stay 'received': it is still a state.)

-- 4. Narrow and reorder (table copy).
ALTER TABLE `email_messages` MODIFY `status` ENUM('received','persisted','scanning','scanned','scan_failed','policy_evaluated','approved','quarantined','held_for_review','rejected','delivery_pending','delivery_retry','delivered','archived','expired') NOT NULL DEFAULT 'received';
ALTER TABLE `email_message_status_history` MODIFY `from_status` ENUM(<15>) NULL, MODIFY `to_status` ENUM(<15>) NOT NULL;

-- 5. Idempotency key of transitions (partitioned table: the unique key includes received_at).
CREATE UNIQUE INDEX `email_message_status_history_message_id_transition_key_received_at_key`
  ON `email_message_status_history` (`message_id`, `transition_key`, `received_at`);

-- 6. API idempotency store (not partitioned, no FK).
CREATE TABLE `api_idempotency_keys` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `organization_id` BIGINT UNSIGNED NOT NULL,
  `idempotency_key` VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `operation` VARCHAR(64) NOT NULL,
  `principal` VARCHAR(80) NOT NULL,
  `request_sha256` CHAR(64) NOT NULL,
  `resource_id` VARCHAR(64) NOT NULL,
  `status_code` SMALLINT UNSIGNED NOT NULL,
  `response` JSON NOT NULL,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `expires_at` DATETIME(3) NOT NULL,
  UNIQUE INDEX `api_idempotency_keys_organization_id_idempotency_key_key` (`organization_id`, `idempotency_key`),
  INDEX `api_idempotency_keys_expires_at_idx` (`expires_at`),
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

The MySQL session running a migration must allow the multi-statement data part (Prisma runs the file as one script; the step 2.1 `domain_check_backfill` migration is the precedent for DML in a migration). The implementer may merge steps 2 and 4 for `email_message_status_history` into one copy `ALTER` if MySQL accepts it, and documents the algorithm MySQL chose (`INSTANT`/`INPLACE`/`COPY`) for each statement in `docs/database/schema-reference.md`.

`schema.prisma`:

- `enum MessageStatus` = the fifteen values in L2 order (doc comment: "Lifecycle states, ADR-0025; replaced once in step 3.3, append-only again from now on").
- `EmailMessage`: `lifecycleRound Int @default(0) @map("lifecycle_round") @db.UnsignedSmallInt` ("+1 on rescan/release, ADR-0025"), `statusReason String? @map("status_reason") @db.VarChar(64)`; doc comment: "status/version/lifecycle_round/status_reason are written only through @email-gateway/message-lifecycle".
- `EmailMessageStatusHistory`: the nine columns (`actorType ActorType @default(system)`), `@@unique([messageId, transitionKey, receivedAt])`; doc comment on `eventId`: "causing event id".
- `ApiIdempotencyKey` model (`@@map("api_idempotency_keys")`).
- Table count 72 → **73**, partitioned 19 (unchanged). `tests/integration/schema.test.ts`, `docs/database/*` (data dictionary, ER diagram, retention: `api_idempotency_keys` purge) updated.

### 3.2 Migration `queue_id_case_sensitive` (WP1)

Five `ALTER TABLE … MODIFY … COLLATE utf8mb4_bin` (L15), one per table, `email_deliveries` with both columns in one statement.

### 3.3 Seed

Catalog permission `message:rescan` ("Request a rescan of a message's security pipeline"), in `TENANT_PERMISSIONS` (so `organization_admin` and `super_admin` get it) and added explicitly to `security_analyst`. Not in `TENANT_READ_PERMISSIONS`. `pnpm db:seed` (idempotent) applies it.

### 3.4 Verification (WP1)

Drift check (`migrate diff` from migrations to schema = empty), `pnpm db:status`, clean-schema check on the throwaway `email_gateway_verify` (create, `migrate deploy`, `db:partitions apply`, 73 tables / 19 partitioned, enum values, collations, unique keys; drop it afterwards), upgrade over the existing local data on the main schema (`pnpm db:migrate`; before/after counts per status recorded; every message has a version-0 history row and `MAX(history.version) = email_messages.version`), `pnpm db:seed` twice. Never `migrate reset`.

---

## 4. Contracts (summary)

- Events: `mail.message.state_changed.v1` (new, `email.events`), `mail.message.rescan_requested.v1` (new, `email.security`), `mail.delivery.approved.v1` (+ optional `lifecycleRound`). Topology v2 (L7). `MESSAGE_STATES`, `ACTOR_ROLES` exported by event-contracts.
- HTTP (OpenAPI): `GET /api/v1/messages/{id}/lifecycle`, `GET /api/v1/messages/{id}/lifecycle/history`, `POST /api/v1/messages/{id}/rescan`, `POST /api/v1/messages/{id}/release` (Idempotency-Key header), `GET …/deliveries` message status values changed (+ `statusReason`).
- Library: `@email-gateway/message-lifecycle` (L1, L5).
- Metrics: L5.5, L8.3 (`delivery_approvals_skipped_total`), L8.4 (`delivery_approvals_rejected_total`), L9 (`lifecycle_derived_skipped_total`), L10.1 (`api_message_lifecycle_operations_total`), L13, L14.
- Data ownership: the lifecycle columns of `email_messages` and `email_message_status_history` are written by the transition service on behalf of the producers listed in L3 (one door, many callers, like the shared delivery recorder); `api_idempotency_keys` is owned by the api.

---

## 5. Configuration

**event-relay** (`.env.example` section "Message lifecycle (step 3.3)", Compose `event-relay` environment, `infrastructure/kubernetes/base/event-relay.yaml`, `apps/event-relay/src/config.ts`):

```dotenv
LIFECYCLE_EXPIRY_ENABLED=true
LIFECYCLE_EXPIRY_INTERVAL_MS=60000          # 1 000 .. 3 600 000
LIFECYCLE_EXPIRY_SHARDS=4                   # 1 .. 64
LIFECYCLE_EXPIRY_MAX_HELD_SHARDS=4          # 1 .. 64
LIFECYCLE_EXPIRY_BATCH_SIZE=200             # 1 .. 5 000 per shard and pass
LIFECYCLE_EXPIRY_LOOKBACK_DAYS=186          # 1 .. 400 (status_changed_at bound; ≥ the longest deadline)
LIFECYCLE_TX_TIMEOUT_MS=5000                # 1 000 .. 60 000
# Per-state deadlines in hours; 0 = never expire this state.
LIFECYCLE_DEADLINE_PERSISTED_HOURS=72
LIFECYCLE_DEADLINE_SCANNING_HOURS=24
LIFECYCLE_DEADLINE_SCANNED_HOURS=24
LIFECYCLE_DEADLINE_SCAN_FAILED_HOURS=72
LIFECYCLE_DEADLINE_POLICY_EVALUATED_HOURS=24
LIFECYCLE_DEADLINE_APPROVED_HOURS=24
LIFECYCLE_DEADLINE_QUARANTINED_HOURS=2160   # 90 days (5.3 replaces with per-tenant retention)
LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS=336
LIFECYCLE_DEADLINE_DELIVERY_PENDING_HOURS=168  # 0 or > 120 (Postfix maximal_queue_lifetime 5 d)
LIFECYCLE_DEADLINE_DELIVERY_RETRY_HOURS=168    # 0 or > 120
LIFECYCLE_CHECK_ENABLED=true
LIFECYCLE_CHECK_INTERVAL_MS=60000           # 1 000 .. 3 600 000
LIFECYCLE_CHECK_AFTER_SECONDS=900           # 300 .. 86 400
LIFECYCLE_CHECK_BATCH_SIZE=500              # 1 .. 5 000
LIFECYCLE_CHECK_LOOKBACK_HOURS=192          # 1 .. 4 464 (status_changed_at bound; > AFTER_SECONDS)
```

Cross-field: `LIFECYCLE_EXPIRY_MAX_HELD_SHARDS ≤ LIFECYCLE_EXPIRY_SHARDS`; `LIFECYCLE_EXPIRY_LOOKBACK_DAYS × 24 ≥` every non-zero deadline; `LIFECYCLE_CHECK_LOOKBACK_HOURS × 3600 > LIFECYCLE_CHECK_AFTER_SECONDS` (added in verification round 2). Errors name keys, never values. No secrets are added. The same keys with the same values are appended to the local `.env`.

No new keys for smtp-adapter, email-worker, delivery-worker or api (the api's idempotency TTL is a constant of 24 h).

---

## 6. Compose and infrastructure

- `docker-compose.yml`: event-relay environment gains the §5 keys (`${KEY:-default}`); nothing else.
- `infrastructure/rabbitmq/definitions.json` regenerated (topology v2); the running broker is updated with `pnpm rabbitmq:init` (idempotent, additive).
- `infrastructure/monitoring/rules/lifecycle.rules.yml` (+ `rule_files` in `prometheus.yml`); `promtool check rules` with the `prom/prometheus:v3.6.0` image, run once (no observability profile start).
- Images rebuilt by WP5, **one at a time**: smtp-adapter, delivery-worker, event-relay, api (email-worker only if its fixtures/package changed its build inputs; it depends on event-contracts, so yes).

---

## 7. Alternatives considered

| Alternative                                               | Why not                                                                                                                                                                              |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Ordering by event occurrence time + rank                  | Different clocks; equal-rank states; re-entry breaks monotonic rank (ADR-0025)                                                                                                       |
| Pessimistic lock only, or optimistic CAS only             | Lock alone hides a writer that bypasses it; CAS alone (read without lock) turns every hot message into retry storms. Both: lock to serialize, CAS as the backstop the brief asks for |
| Keep old enum values / retired members                    | Non-canonical states writable by typed code; partial/failed are outcomes, not states                                                                                                 |
| Parse states in the message enum                          | Brief fixes 15 states; the stage table exists                                                                                                                                        |
| `persisted` set by the 3.1 parse                          | The brief's hand-off assigns `received` and `persisted` to the SMTP commit; the commit is what makes the message durable; a parse failure would leave messages `received` forever    |
| Message delivery state as events from the delivery-worker | Derived-under-lock cannot be overtaken and needs no ordering data                                                                                                                    |
| A lifecycle microservice (RPC)                            | Extra hop, second transaction, loses atomicity with the stage effects                                                                                                                |
| Expiry in delivery-worker or email-worker                 | Expiry spans every stage; event-relay already is the reconciliation deployable with sharded loops                                                                                    |
| Idempotency-Key in Redis                                  | Must commit atomically with the transition and the audit row; Redis cannot join the MySQL transaction                                                                                |
| Store API idempotency in the history table only           | Cannot hold the response or detect key reuse with a different body; 6.1 needs a generic store                                                                                        |
| `ascii_bin` for queue ids                                 | A charset change rewrites data and differs from every other column; `utf8mb4_bin` gives the case sensitivity without conversion                                                      |
| Emit no `state_changed` event                             | Analytics (ADR-0009) and webhooks (6.2) need the transitions; outbox volume (+~4 rows/message) is acceptable (daily partitions, dropped once published)                              |

---

## 8. Risks and mitigations

| Risk                                                                                       | Mitigation                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Enum narrowing rebuilds `email_messages`                                                   | No production data; documented as a one-time exception; future enum changes append only                                                                                         |
| Outbox growth (state_changed per transition)                                               | Daily partitions, dropped after publish (3.2); relay throughput measured by the WP5 regression (smtp-concurrency backlog drained)                                               |
| SMTP latency                                                                               | One `createMany`, no lock; WP5 compares with the step 2.2 baseline (≤ 15 %)                                                                                                     |
| Hot message lock contention (1 000-recipient message, many signals)                        | Existing lock (unchanged order); derivation reads one `GROUP BY` over the message's recipients (index `(message_id, rcpt_seq, received_at)`); measured in the concurrency tests |
| Rescan before Phase 4 parks messages in `scanning`                                         | Documented in the API response `note`, runbook; sweeper expires after 24 h; rescan from `expired` allowed                                                                       |
| Sweeper expires a message right before a late signal                                       | Delivery deadlines > Postfix lifetime; CAS on the version read; per-recipient state still records the signal                                                                    |
| Legacy approvals without `lifecycleRound` or for messages left `persisted` by the backfill | Treated as round 0; planner rejects approvals of messages not `approved` (`lifecycle_state`), documented for local stacks (re-send test mail)                                   |
| Release bypassing 5.3's per-recipient quarantine                                           | `409 quarantine_workflow_required` when `quarantine_messages` rows exist                                                                                                        |
| History unique key forgotten by a future producer                                          | `transitionKey` is mandatory in the type and validated (non-empty, ≤ 512)                                                                                                       |
| Prisma drift on collations                                                                 | WP1 verifies `migrate diff`; documented                                                                                                                                         |
| Forged `rescan_requested` on the broker                                                    | Only the relay (`eg-relay`) publishes `org.` keys on `email.security`; 4.x consumers must check the lifecycle round against the writer row (contract note)                      |

---

## 9. Test plan

**Unit (package `message-lifecycle`, WP2):**

1. Exhaustive edge test: for every ordered pair `(from ∈ states ∪ {null}, to ∈ states)` (16 × 15) and every role, `decideTransition` with a valid reason applies iff an edge allows `(from, to, role)`; every forbidden pair is classified (`stale` vs `invalid`) as L4 step 5 says; every allowed edge with a wrong reason is `invalid/reason_not_allowed`.
2. Table invariants: no edge out of `archived`; `expired` only to `scanning`; every `newRound` edge has role `operator`/`quarantine`; every state reachable from creation; every non-final state has a path to a final state; reason codes match the pattern and are unique per edge; `MESSAGE_STATES` equals the Prisma enum values (type-level equality test in WP2) and event-contracts' list.
3. Ordering (table tests and `fast-check` properties): rounds (older → stale, future → invalid), version mismatch, overtaken, same state, final states; property: for random interleavings and duplications of the events of a scripted lifecycle (including a rescan or release round), applying them in any order yields the same final state as in-order application, never a state of an older round, and each event applies at most once.
4. `deriveDeliveryState`: every combination of recipient counts in a small domain (0..2 per status).
5. `initialLifecycle` rows match E1/E2 (decide-check in the test).
6. One-door test (L5.9).

**Integration against the real MySQL writer (WP2, `packages/message-lifecycle/integration`):**

7. Applied transition writes exactly: state + version + round + reason on the row, one history row with every column, one `email_events` row, one outbox row whose payload passes the schema.
8. Concurrency: (a) 64 parallel `transitionMessageWithRetry` `persisted → approved` with distinct keys → 1 applied, 63 duplicate, one history row; (b) 64 parallel with the same key → 1 applied; (c) a race of 16 workers walking `approved → delivery_pending → delivery_retry → delivery_pending → delivered` (each worker tries the next step from its view) → history versions contiguous with no gap or repeat, every step applied once, final `version` = 1 + applied rows (no lost update); (d) two transactions with the same `expectedVersion` → one applied, one `stale/version_mismatch`; (e) 200 messages × 8 writers mixed, no deadlock escapes `transitionMessageWithRetry`.
9. Failure recovery: (a) crash between consume and transition: a `processOnceHandler` whose handler applies the transition then throws → no history, no ledger, no outbox; the re-run applies once; a third run is a ledger duplicate; (b) writer outage mid-transition: a TCP proxy (copy the helper of `tests/integration/support/tcp-proxy.ts` into the package's integration support) cut after `SELECT … FOR UPDATE` → the call fails, the row is not left locked (a second connection locks it within the lock-wait timeout), the retry after restore applies exactly once; (c) P2002 on the transition key inside a transaction → `transitionMessageWithRetry` returns `duplicate`.
10. Ignored transitions write one `lifecycle.ignored` row; `recordIgnored: false` writes none.

**event-relay (WP2):** sweeper unit tests (fakes) and integration (real MySQL, short deadlines through options): expires only overdue rows of its shard, skips a row whose version changed between read and lock (race injected), bounded per pass, metrics; lifecycle check re-derives a message whose recipients were made terminal without the transition; config tests.

**Producers (WP3):** smtp-adapter integration: a committed message is `persisted`, version 1, two history rows, transaction unchanged otherwise; bounce matching with case-different queue ids. mail-routing: per-recipient exhaustive table test against the oracle; recorder integration: derived states (`delivery_retry` on deferral, back to `delivery_pending` on requeue, `delivered/delivery_complete`, `delivered/delivery_partial`, `rejected/delivery_failed`), older `delivery_seq` signals never move the message, case-different queue ids resolve the right delivery. delivery-worker: dev pass-through applies E4 and writes `lifecycleRound: 0`; skips non-`persisted` messages; planner applies E20, plans later chunks, rejects older-round and non-approved messages (`lifecycle_state`); planning integration with the real writer.

**API (WP4):** unit (service with fakes), e2e (`apps/api/test`, guards and OpenAPI), integration (`apps/api/integration`, real writer/replica): RBAC (`message:read` reads, `message:rescan` / `quarantine:release` required, an analyst without them `403`), cross-tenant `404` for reads and writes, Idempotency-Key replay (same status/body, `Idempotency-Replayed: true`, exactly one history row, one outbox row, one audit row), key reuse with another body `422`, missing key `400`, stale version `409 message_version_conflict`, invalid source state `409 message_state_conflict`, `quarantine_workflow_required`, `no_releasable_recipients`, release writes approvals with `deliverySeq` = max + 1 and the new round; rescan writes `rescan_requested.v1`; reads through the replica (and the lag fallback path with a forced writer-fallback service), history pagination, legacy rows. The `common.test.ts` cleanup (L16).

**Stack (WP5, live containers, images rebuilt one at a time):** regressions of the step 2.2 `smtp-*`, step 2.3 `routing-*`, step 3.1 `mime-ingestion` and step 3.2 `messaging-*` suites with the lifecycle checked end to end: an inbound message through Postfix is `persisted` (history `received`, `persisted`) then, with the dev pass-through, `approved → delivery_pending → delivered` with the mail in the sink; a partial delivery ends `delivered/delivery_partial`; all bounced ends `rejected/delivery_failed`; a deferral shows `delivery_retry`. New `tests/integration/lifecycle-*.test.ts`: release of a message forced into `quarantined` by test setup (direct SQL is a fixture, L8.6) is delivered to the sink through the planner; rescan lands one copy in each of the five dormant scan queues (peeked via the management API, then purged); expiry with short deadlines on a test-only event-relay instance started on the host (the container keeps its defaults); consumer crash between consume and transition (stop the delivery-worker mid-handling as in `messaging-consumer-crash`) ends with exactly one history row. Test hygiene (L16). SMTP concurrency baseline comparison. Full gate: `format:check`, `lint`, `typecheck`, `test`, `test:e2e`, `build`, `db:migrate` + `db:status` + drift, clean-schema check, `db:seed` twice, `test:integration`.

---

## 10. Not in scope

- Producers of `scanning`, `scanned`, `scan_failed` (4.x), `policy_evaluated` and policy outcomes (5.2), per-recipient quarantine, release re-validation, approval workflow, self-release, delete (5.3), `archived` (8.1).
- Consumers of `mail.message.state_changed.v1` (analytics ingestion, webhooks 6.2) and of `rescan_requested.v1` (4.x).
- Switching the dormant queues to work policies.
- Per-tenant quarantine retention for expiry (5.3).
- Portal pages for the lifecycle (7.x).
- Message list filters by state in a list API (6.1).
- Online schema change tooling for future enum changes on production data.
- Re-parsing on rescan (the parse is per message, round 0).

---

## 11. Work packages

Four sequential waves; packages in one wave touch disjoint files. **Only WP2 runs `pnpm install` and changes `pnpm-lock.yaml` or any `package.json` dependency list** (new package + workspace dependencies of the apps on it). Every other package reports a missing dependency instead of installing it.

| Wave | Package | Scope                                                                                                                                                                                                                                                                                                                                           |
| ---- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | WP1     | Migrations `message_lifecycle` + `queue_id_case_sensitive`, `schema.prisma`, retention purge, seed permission, schema/seed tests, event-contracts (events, registry, topology v2, `definitions.json`), transitional compile fixes for the enum rename, docs/database, contracts, data ownership, messaging topology, Mermaid diagrams 11 and 22 |
| 2    | WP2     | `packages/message-lifecycle` (core + service + unit/property/integration tests), workspace dependencies + lockfile, event-relay expiry sweeper + lifecycle check (config, metrics, wiring, tests, README), `.env.example` + local `.env`, Compose, Kubernetes, alert rules, runbook `message-lifecycle.md`, root `test:integration` script      |
| 3    | WP3     | Producers: smtp-adapter commit, mail-routing (per-recipient table as data, recorder derivation, removals, collation regression), delivery-worker (dev pass-through, planner), their tests and READMEs                                                                                                                                           |
| 3    | WP4     | api: messages module (lifecycle read, history, rescan, release), Idempotency-Key store, deliveries DTO, OpenAPI snapshot, unit/e2e/integration tests, `common.test.ts` hygiene, api README, `docs/api/README.md`                                                                                                                                |
| 4    | WP5     | Stack suites and regressions, test hygiene in `tests/integration`, images one at a time, full gate, README, overview, failure handling, security boundaries, diagrams README status, runbooks index, execution plan row, §13 verification record                                                                                                |

---

## 12. Deviations log

(Implementers append here: decision id, what changed, why.)

**WP1 (2026-11-04).**

- **§3.1, unique key name.** `email_message_status_history_message_id_transition_key_received_at_key` is 71 characters, above MySQL's 64-character identifier limit. The migration uses Prisma's default name for `@@unique([messageId, transitionKey, receivedAt])`, truncated by Prisma to `email_message_status_history_message_id_transition_key_recei_key`, so `migrate diff` stays empty. Columns and semantics unchanged.
- **§3.1, migration creation.** `pnpm db:migrate:dev --create-only --name message_lifecycle` refuses to run non-interactively because of its data-loss warnings (enum values removed, new unique key). As `docs/database/README.md` prescribes for that case (and step 2.3 did), the SQL Prisma would generate was taken from `migrate diff --from-migrations … --to-schema-datamodel … --shadow-database-url` for reference and the migrations were written by hand as `20261104130000_message_lifecycle` and `20261104130100_queue_id_case_sensitive`.
- **§3.1, backfill details (additions, same mapping).** Every statement names its `ALGORITHM` (INSTANT for the widen and the new columns, COPY for the narrow, INPLACE/LOCK=NONE for the unique key; recorded in `docs/database/schema-reference.md`), so MySQL refuses rather than silently rebuilding. The `UPDATE email_messages` statements also set `updated_at = CURRENT_TIMESTAMP(3)` (the column has no `ON UPDATE`; Prisma's `@updatedAt` is client-side), and the `delivered → delivery_complete` update is guarded by `status_reason IS NULL` so a re-run matches nothing.
- **§3.2.** Algorithms chosen by MySQL 8.4.13 and stated in the migration: `email_messages.mta_queue_id` and `delivery_status_events.queue_id` INPLACE (not indexed); `email_deliveries` (both columns, one statement) and `delivery_reinjections.queue_id` COPY (indexed columns). Partitioning verified unchanged with `information_schema.PARTITIONS`. Prisma reports **no** collation drift (`migrate diff` empty against the main schema, the clean schema and the migration history), so nothing else to record for L15.
- **§11 transitional fixes (WP1), behaviour beyond a literal rename.** The step 2.3 `setMessageStatus` in `packages/mail-routing/src/delivery-state/recorder.ts` now also writes `status_reason` and the history actor columns (`actor_role = 'delivery'`, `actor_service` = the recorder context's service, `actor_type = 'system'`, `occurred_at`), so rows written until WP3 removes it are not labelled `legacy`; `aggregateMessageStatus` returns `{ status, reason }`; `markMessageDeliveryQueued` moves `received`/`persisted`/`approved`/`policy_evaluated` to `delivery_pending`. All marked `step 3.3 transitional (WP1): replaced by WP3`. `tests/integration/routing-signals.test.ts` waits for `delivered` with `status_reason = delivery_partial` (the old literal was `partially_delivered`).
- **Files touched outside the WP1 list (needed to keep the gates green):** `packages/common/src/messaging/content-guard.test.ts` (registered event count 9 → 11), `apps/smtp-adapter/integration/bounces.test.ts` (one `MessageStatus` literal `failed` → `rejected`), `docs/api/openapi.json` (regenerated with `UPDATE_OPENAPI=1`: only the `message.status` enum of the deliveries response changed). WP4 still owns `statusReason` in the deliveries response and the rest of the OpenAPI work.

**WP2 (2026-11-04).**

- **L1, dependencies.** `@email-gateway/message-lifecycle` also depends on `@email-gateway/common` (runtime: `uuidv7` for `state_event_id`, the same generator as every outbox event id; integration tests: `processOnceHandler`). No cycle (`common` does not depend on the lifecycle). `fast-check@3.23.2` is a devDependency as planned.
- **L5, additions to the API (no behaviour change).** `transitionMessage` validates more of the request as `LifecycleContractError` (never retried): `causationEventId` must be a UUID (the `state_changed` schema requires it), `correlationId` 1–128 characters (the column width), `actor.service` 1–64 characters of `[a-z0-9._-]`, `actor.id` ≤ 64. `transitionMessageWithRetry` validates before opening a transaction and accepts `deps.sleep` / `deps.random` (tests). The CAS `UPDATE` also sets `updated_at` (the column has no `ON UPDATE`, WP1 precedent). Stale outcomes are logged at `debug`, invalid ones at `warn` (ids and codes only). Additional exports: `isMessageState`, `isActorRole`, `isLifecycleReasonCode`, `isTransitionKeyViolation`, `retryDelayMs`, `noopLifecycleMetrics`, `initialTransitionKeys`, `MessageRef`, `DerivedStateOutcome`.
- **L9, `applyDerivedDeliveryState(tx, message, ctx, deps?)`.** `ctx.transitionKey` is a function `(derived, current) => string`, because every L5.3 key of a derived transition contains the derived target (`signal:<deliveryId>:<signalKey>:<to>`, `recover:<id>:<version>:<to>`); the lifecycle check passes the version read **under the lock**. The result is `{ result: 'not_found' | 'skipped' | 'unchanged' | 'transition', … }` (`transition` carries the `TransitionOutcome`).
- **L5.4, P2002 detection.** MySQL reports the unique index name in `meta.target` (`email_message_status_history_message_id_transition_key_recei_key`, WP1's truncated name); a P2002 counts as a transition-key violation when the target names `transition_key`. The local writer runs **READ COMMITTED**, under which the key check always sees committed rows; the §9 item 9(c) test therefore produces the P2002 with a caller in REPEATABLE READ whose snapshot predates a concurrent commit of the same re-entry request (E19 from `scanning`), the real case the unique key backstops.
- **L5.9, one-door scan.** Stricter than listed: it also flags `emailMessageStatusHistory.createMany|update|updateMany|upsert(` and raw `INSERT INTO` / `UPDATE` of `email_message_status_history`; filters (`where: { status }`) and `emailMessage.create` (the L8.1 spread) are not flagged. `*.test.ts` files under `src/` are scanned too. Allow-list: `packages/mail-routing/src/delivery-state/recorder.ts` only, with a test that every entry still writes (so WP3 must empty it when the recorder no longer does).
- **§9 item 3, property model.** "Any order" is modelled causally: an event exists only once its cause applied (the producer writes it in the cause's transaction), copies are delivered in random order with duplicates; duplicates of round- or version-carrying events may also arrive without their key (history partition aged out), delivery-derived events only with their key (they are recomputed from the recipients under the lock, L9). Properties: same final state/version/round as in order, every event applied at most once, never an event of an older round over a newer one.
- **L13 step 1, interval unit.** The candidate query is the L13 query with `INTERVAL ? SECOND` (deadline hours × 3600) instead of `INTERVAL ? HOUR`, and also selects `status_changed_at`; same semantics, and the integration tests use second-scale deadlines through the sweeper options. The sweeper sets `correlationId = expire:<id>`, the check `recover:<id>`. Skipped candidates write the L6 `lifecycle.ignored` row (the sweeper is an asynchronous producer).
- **L13/L14 metrics, additions.** `lifecycle_expiry_shards` (gauge of the configured `LIFECYCLE_EXPIRY_SHARDS`, so `LifecycleExpiryNoShardOwner` compares held shards with it instead of a hard-coded count), `lifecycle_check_run_seconds` (histogram) and `lifecycle_job_errors_total{component}` (database errors of the jobs, which back off). `lifecycle_stuck_messages` is counted over the `(status, status_changed_at)` index without a `received_at` bound, as L14 step 3 states.
- **§5 config.** Per-state deadlines are bounded `0..9600` hours (400 days, the longest lookback; §5 gives no upper bound). The class-level validation of `LifecycleCheck` accepts `afterSeconds ≥ 1` (the config keeps `300..86400`) so integration tests need not wait.
- **§6 `prometheus.yml`.** `rule_files` already loads `rules/*.rules.yml`, so `lifecycle.rules.yml` is picked up without a new entry (an explicit entry would load the file twice); only the comment changed. Added `infrastructure/monitoring/tests/lifecycle.rules.test.yml` (promtool unit tests, outside the WP2 file list). Severity of all four alerts: `warning`.

**WP3 (2026-11-04).**

- **L8.3/L8.4/L9, additions (no rule changed).** `delivery_approvals_rejected_total{reason}` counts every planner rejection (`lifecycle_state` and the existing `eml_key_prefix`, `message_not_found`, `no_known_recipients`), not only `lifecycle_state`. The dev pass-through takes the EML key from the locked lifecycle snapshot instead of a second message read, and a message past `persisted` is refused by the service as `invalid/unexpected_from` (L4 step 3, `expectedFrom`), so the skip counter shows `lifecycle_invalid` for that case. The planner passes its clock to the E20 transition and treats a non-`applied` outcome under the lock it just took (cannot happen) as `rejected/lifecycle_state`. The recorder passes the signal's `occurredAt` as the history `occurred_at` of a derived transition. `apps/smtp-adapter/README.md` and `packages/mail-routing/README.md` did not exist and were created. Docs outside WP3's files still describing the recorder as a transitional writer (`docs/architecture/data-ownership.md`, diagram 22 legend) are left to WP5.

**WP4 (2026-11-04).**

- **L12, history order and cursor.** The history is ordered by `version` (unique per message) and the cursor encodes the last version of the page, not the history id: the migration's backfilled version-0 rows have higher ids than the legacy rows they precede, so id order would not be oldest first. Same pruning (`(message_id, received_at)`), same response shape.
- **L10.1, order inside the transaction.** After the message lock the api checks the transition key itself (a history row with `SHA-256(api:<org>:<operation>:<key>)` means a concurrent request with the same key committed first → the transaction rolls back and is retried once, which replays the stored response), then runs the pure `decideTransition` on the locked snapshot so a stale version or a wrong state answers before the release preconditions (`quarantine_workflow_required`, `no_releasable_recipients`) and the EML-prefix check; `transitionMessage` then re-decides under the same lock. Without the key check, a concurrent duplicate would answer `409 message_version_conflict` instead of a replay.
- **L11, retry once.** The single retry covers the P2002 on `(organization_id, idempotency_key)` and the transition-key race above. A second race on the same request means the effect exists without a live record (the key reused on the same message after its 24 h record expired) and answers `422 idempotency_key_reused`. The stored status is always the route's `202` (`@HttpCode`).
- **L10.1, error bodies.** Coded errors (`CodedHttpException` + a controller-scoped `CodedExceptionFilter`, `apps/api/src/http/coded-exception.ts`) render `{ statusCode, error, code, message, currentState?, currentVersion?, correlationId }`: `error` and a human `message` are kept for consistency with every other api error; `code` is the stable contract (`message_not_found`, `message_version_conflict`, `message_state_conflict`, `quarantine_workflow_required`, `no_releasable_recipients`, `idempotency_key_required`, `idempotency_key_invalid`, `idempotency_key_reused`). The write routes validate the path id, the header and the body in the service (not in pipes), so `api_message_lifecycle_operations_total{outcome="invalid_request"}` counts every `400`/`422`.
- **L16, part objects.** The probe cleanup deletes the part objects under the real step 3.1 M11 prefix `org/<id>/part/<yyyy>/<mm>/<dd>/<messageId>/` (UTC date of `received_at`), not `org/<id>/parts/<messageId>/`, and the rows of the probe's message graph (the run's unique `Message-ID` proves the test owns them). `apps/api` has no `@aws-sdk/client-s3` dependency (no `package.json` change in this package): the test helper resolves it from `@email-gateway/common`'s dependency with `createRequire`; adding it as a devDependency of the api is left to a package-owning step. The end-to-end probe path runs only with the smtp-adapter up (the apps were stopped here), so the cleanup is verified by `integration/probe-cleanup.test.ts` against MySQL, MinIO and the postfix-outbound container.

**WP5 (2026-11-04).**

- **§9 "Stack", expiry with short deadlines.** `LIFECYCLE_DEADLINE_<STATE>_HOURS` are whole hours by config (§5), so the host-run instance cannot be given second-scale deadlines through its environment. `tests/integration/lifecycle-event-relay.test.ts` gives the instance one-hour deadlines on `scanned` and `held_for_review` (every other deadline 0), a one-second sweep interval, and backdates the fixtures' `status_changed_at` by two hours; expiry then happens about one second after start. Second-scale deadlines through the sweeper options remain covered by WP2's event-relay integration suite. A guard refuses to start the instance while any message of another organization is in those states for more than one hour, so only the suite's fixtures can expire.
- **§9 "Stack", how the container keeps its defaults.** The expiry shard locks, the reconciler lock and the lifecycle-check lock are single-owner (`GET_LOCK`), so a second instance would never become active next to the container. The suite stops the `event-relay` container (`docker compose stop`), runs `apps/event-relay/dist/main.js` on the host (port 3071) with every role enabled (the outbox keeps being published) and the overrides, then starts the container again with `docker start` (unchanged environment). Organization scoping (`organizationIds`) exists only as a constructor option, not as configuration, so it was not used.
- **Reconciler re-drive (task list, L14 row 1).** The host instance runs with `RECONCILE_UNCONSUMED_AFTER_SECONDS=300` (the config minimum) and a 2 s interval. The sweep walks the outbox in id order and stops at rows published less than 300 s ago, so the test waits until the previous suites' rows are due: about 300 s in both runs.
- **Fixtures.** Stack fixtures put a message into a state by direct SQL, as L8.6 allows (`insertFixtureMessage` in `tests/integration/support/lifecycle.ts`). The v2 history row they write carries `actor_role = 'fixture'` and the reason code that state's producer would write. `messaging-replay.test.ts` now starts from `approved` instead of `received`, because the planner plans approvals of `approved` messages only (L8.4).
- **`lifecycle-consumer-crash`** sends 200 messages (`LIFECYCLE_CHAOS_MESSAGES`), not 300, to keep the run short. The exactly-once lifecycle check (`lifecycleProblems`) was added to `MessagingScenario.run`, so every `messaging-*` chaos suite asserts it too.
- **Files outside the WP5 list.** WP3 left `docs/architecture/data-ownership.md` and diagram 22's legend to WP5. WP5 also set the step 3.3 status rows of diagrams 11 and 22 to IMPLEMENTED. No production code was changed (§13.5).

## 13. Verification results

Recorded by WP5 on 2026-11-04 on the development machine (macOS, Docker Desktop VM 8 GB, which other projects' containers also use), branch `build/platform`. The stack ran the Compose infrastructure, the `smtp-test` profile and the **whole apps profile as containers built from this tree**, with `DELIVERY_DEV_PASSTHROUGH_ENABLED=true` and `APP_ENV=local`. Nothing was committed.

### 13.1 Images and stack

- Rebuilt one at a time (`docker compose --profile apps build <service>`, nothing else building): `db-migrate` 53 s, `smtp-adapter` 76 s, `email-worker` 69 s, `delivery-worker` 71 s, `event-relay` 71 s, `api` 84 s, `policy-engine` 353 s, `archive-worker` 68 s, `notification-worker` 69 s. The last three were rebuilt because the lockfile and the Prisma schema changed under them. `admin-portal` was not rebuilt: none of its inputs changed.
- `docker compose --profile apps --profile smtp-test up -d --wait`: `db-migrate` applied the two step 3.3 migrations (13 in total) and the partition maintenance; `rabbitmq-init` exited 0. MySQL was recreated during the `up`, so the api briefly restarted and `--wait` reported `api` unhealthy. Every service was healthy shortly afterwards, and replication was running (`Replica_IO_Running`/`SQL_Running` Yes, lag 0). `admin-portal`, which depends on the api, stayed exited until `up -d --wait --no-deps admin-portal` (see 13.3).
- `pnpm rabbitmq:init`: topology v2 imported (6 exchanges, 14 queues, **37 bindings**, 14 policies, 4 role users), verification passed. Management API: vhost description `email-gateway topology v2`, and the five bindings `email.security → scan.{attachment,auth,dlp,spam,url} : org.*.mail.message.rescan_requested.v1`, nothing else on `rescan_requested`.
- Local environment change: `.env` `SMTP_ADAPTER_HOST` was `host.docker.internal`, left by the step 3.2 verification round. It was set to `smtp-adapter` (the `.env.example` default) because the adapter runs as a container, and it is **left that way** with the stack running. Backup of the previous file: the session scratchpad (`env.backup`).

### 13.2 Step 3.3 stack suites (`tests/integration/lifecycle-*.test.ts`) and lifecycle assertions in the older suites

| Suite / assertion                                  | Scenario                                                                                                                                                                                                                                                      | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lifecycle-release`                                | Fixture message in `quarantined` (two recipients on a mail-sink domain, L8.6). An organization admin calls `POST …/release` with an Idempotency-Key. Also tested: a missing key, a replay with the same key, a reused key with another body, a second release | passed (3 runs): `202` `approved`, v3, round 1, `deliverySeq` 1, 2 recipients; replay identical with `Idempotency-Replayed: true`; reuse `422`; missing key `400`; both recipients delivered (1 sink file each) ~1 s after the release; path `received → persisted → quarantined → approved (quarantine_release) → delivery_pending → delivered (delivery_complete)`, rounds 1/1/1, operator actor = the user's public id; exactly 1 approval outbox row, 1 planner ledger row, 1 audit row (`message.quarantine_released`), 1 idempotency record; the read API shows `delivered`, v5, round 1; a second release → `409 message_state_conflict` |
| `lifecycle-rescan`                                 | Fixture message in `scan_failed`; a security analyst calls `POST …/rescan`                                                                                                                                                                                    | passed (3 runs): `202` `scanning`, v3, round 1; history operator/user; the relay published `rescan_requested.v1` and **exactly one copy each** appeared in `scan.auth`, `scan.spam`, `scan.url`, `scan.attachment`, `scan.dlp` (peeked through the management API: routing key `org.<id>.mail.message.rescan_requested.v1`, envelope event id, `lifecycleRound` 1, `scanKind` `rescan`, the row's EML key), none in `scan.sandbox` / `email.policy.evaluate` / `email.quarantine`, then purged; a stale `expectedVersion` → `409 message_version_conflict`, no second request                                                                   |
| `lifecycle-event-relay` (expiry)                   | Host-run event-relay (container stopped, §12 WP5), 1 h deadlines on `scanned`/`held_for_review`, fixtures backdated 2 h, 1 s interval                                                                                                                         | passed (4 runs): both overdue messages `expired/deadline_exceeded` about 1 s after the start, actor sweeper/event-relay, key `expire:<id>:2`, one `state_changed` row each, no second expiry over several passes; a fresh `scanned` and an overdue `quarantined` (deadline 0) unchanged; `lifecycle_expired_total{state}` = 1 each; `lifecycle_expiry_shards_held` = 4                                                                                                                                                                                                                                                                          |
| `lifecycle-event-relay` (lifecycle check)          | `delivery_pending` for 10 min, its only recipient already `delivered` (lost derivation)                                                                                                                                                                       | passed (4 runs): → `delivered/delivery_complete`, actor recovery, key `recover:<id>:2:delivered`, applied once; `lifecycle_recovered_total{from="delivery_pending",to="delivered"}` ≥ 1                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `lifecycle-event-relay` (re-drive)                 | `approved` fixture, its approval in the outbox marked published 10 min earlier, no planner ledger row; `RECONCILE_UNCONSUMED_AFTER_SECONDS=300`                                                                                                               | passed (3 runs; the first attempt failed on a fixture bug, see 13.5): re-driven once (`redrive_count` 1), planned once, E20 applied once with the approval as causation and key `evt:<id>:delivery_pending`, delivered, 1 delivery, 1 sink file; delivered 299.6 s after the fixture (the sweep waits until the earlier rows are due)                                                                                                                                                                                                                                                                                                           |
| `lifecycle-consumer-crash`                         | 200 messages through postfix:25; delivery-worker SIGKILLed after ≥ 50 planned (63–75 in the runs), started again after 5 s                                                                                                                                    | passed (3 runs): worker ready again after 12.1–12.2 s; 200/200 parses, approvals, planner ledger rows, deliveries, reinjections, sink files; 0 dead letters, 0 unpublished; **every message `delivered/delivery_complete` v4 with exactly 5 contiguous history rows and distinct keys, 600 `state_changed` rows** (`lifecycleProblems`); delivered 21.2 s and 24.7 s after the first send in two runs, 133.6 s in the full run 2 (recovery after the kill was slower once; still exactly once)                                                                                                                                                  |
| Lifecycle checks in the `messaging-*` chaos suites | `MessagingScenario.run` asserts `lifecycleProblems` for every message                                                                                                                                                                                         | passed in both full runs: `messaging-restart` (2 broker restarts, 300), `messaging-db-outage` (writer paused 20.2 s, 300), `messaging-consumer-crash` (email-worker SIGKILL, 300), `messaging-backlog` (500), all exactly one history row per transition                                                                                                                                                                                                                                                                                                                                                                                        |
| `routing-inbound`                                  | Inbound message through Postfix to a tenant destination                                                                                                                                                                                                       | path exactly `received (smtp_accepted) → persisted (committed) → approved (dev_passthrough) → delivery_pending (delivery_planned) → delivered (delivery_complete)`, ingestion/dev_passthrough/delivery actors, one `state_changed` row and one `lifecycle.<to>` event per transition after creation, mail in the sink                                                                                                                                                                                                                                                                                                                           |
| `routing-signals`                                  | One recipient delivered, one hard bounce, then the whole run's log lines re-read and the bounce notice redelivered                                                                                                                                            | `delivered/delivery_partial` with the delivered path; status, reason, version and history **unchanged** by the duplicates; the re-read now takes seconds (cursor rewound to the pre-send offset, L16)                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `routing-bounces`                                  | Outbound and inbound 5xx                                                                                                                                                                                                                                      | `rejected/delivery_failed` with the delivered path ending `delivery_pending → rejected`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `routing-retry`                                    | Destination down, then recovered                                                                                                                                                                                                                              | `delivery_retry/delivery_deferred` while deferred, then `delivered/delivery_complete`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `smtp-inbound`                                     | SMTP commit                                                                                                                                                                                                                                                   | history v0 `NULL → received` / v1 `received → persisted`, actor ingestion/smtp-adapter, shared causation id, `lmtp:` correlation, no `state_event_id`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `messaging-replay`                                 | Dead-lettered approval replayed through the api (fixture now `approved`)                                                                                                                                                                                      | planned once, path ends `delivered/delivery_complete`, the duplicate replay added no history row                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

### 13.3 Regressions and the full gate

| Command                                                                                                               | Result                                                                                                                                                                                                                                                                                                                                                             |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm format:check`                                                                                                   | clean (after `prettier --write` on WP5's files)                                                                                                                                                                                                                                                                                                                    |
| `pnpm turbo run lint typecheck --force`                                                                               | 50 of 50 tasks                                                                                                                                                                                                                                                                                                                                                     |
| `pnpm turbo run test --force`                                                                                         | 29 tasks, **2 891 tests** (api 1 284, smtp-adapter 332, mime-parser 233, common 210, mail-routing 144, event-relay 142, database 131, delivery-worker 114, event-contracts 81, email-worker 72, message-lifecycle 66, config 39, logger 38, admin-portal 2, policy-engine / archive-worker / notification-worker 1 each)                                           |
| `pnpm turbo run test:e2e --force`                                                                                     | api **261**                                                                                                                                                                                                                                                                                                                                                        |
| `pnpm turbo run build --force`                                                                                        | 20 of 20 tasks                                                                                                                                                                                                                                                                                                                                                     |
| `pnpm db:migrate` / `pnpm db:status` / drift (`migrate diff --from-migrations … --to-schema-datamodel … --exit-code`) | 13 migrations, nothing pending; "Database schema is up to date!"; "No difference detected"                                                                                                                                                                                                                                                                         |
| clean-schema check in `email_gateway_verify`                                                                          | `migrate deploy` of 13 migrations, `partitions apply` (19 actions), drift "No difference detected", **73 tables, 19 partitioned**, `email_messages.status` = the fifteen values in L2 order, the five queue-id columns `utf8mb4_bin`; schema dropped and grants revoked                                                                                            |
| `pnpm db:seed` twice                                                                                                  | both exit 0; 37 permissions, 8 roles, 148 role-permission rows                                                                                                                                                                                                                                                                                                     |
| `promtool` (`prom/prometheus:v3.6.0`)                                                                                 | `check rules lifecycle.rules.yml`: 4 rules SUCCESS; `test rules lifecycle.rules.test.yml`: SUCCESS                                                                                                                                                                                                                                                                 |
| `pnpm test:integration`, run 1 (1 350 s for the stack suites)                                                         | stack 40 files: **238 passed, 3 failed**, all environmental: ClamAV OOM-killed (`OOMKilled=true`, `mail-plane` PING and EICAR), and `admin-portal` not started (`services.test`). The chain stops after the stack suites. After `docker compose restart clamav` and starting admin-portal: `mail-plane` + `services` 18/18 passed                                  |
| `pnpm test:integration`, run 2 (1 327 s)                                                                              | stack 40 files: **238 passed, 3 failed**: ClamAV OOM-killed again (`mail-plane` ×2), and `smtp-inbound` counted the new `state_changed` outbox rows of the pass-through and planner as ingestion rows (a timing-dependent test bug of this step, fixed, 13.5). After the fix and a ClamAV restart: `smtp-inbound` + `mail-plane` + `smtp-concurrency` 16/16 passed |
| package integration suites (run separately, because the chain stops at the stack failures)                            | all green: api 21 files, 243 passed + 1 skipped (the "policy service down" branch of `common.test.ts`, which skips while smtp-adapter runs); smtp-adapter 66; message-lifecycle 17; mail-routing 22; delivery-worker 42; email-worker 20; event-relay 20                                                                                                           |

Across the two full runs and the targeted reruns, every step 2.2 `smtp-*`, step 2.3 `routing-*`, step 3.1 `mime-ingestion`, step 3.2 `messaging-*` and step 3.3 `lifecycle-*` suite passed with the final code, as did `services.test.ts`, `schema.test.ts` (73 tables, collations) and `seed.test.ts`. **There was no single uninterrupted all-green `pnpm test:integration` run**: ClamAV was OOM-killed during both long runs (13.7). The step 3.2 broker node-failure test (`test:cluster`) was **not** re-run in this step. Its procedure stops the app containers, and topology v2 only adds bindings.

**SMTP baseline (step 2.2 §12.3: 9.6 s SMTP accept, 59.7 s stored, 40 sessions × 1 000 messages)**

| Run                   | SMTP accept                      | Stored (end to end) | Loss |
| --------------------- | -------------------------------- | ------------------- | ---- |
| full run 1            | 9.3 s (107.3 msg/s), −3 %        | 27.4 s (36.6 msg/s) | 0    |
| full run 2            | 10.6 s (94.3 msg/s), **+10.4 %** | 12.6 s (79.3 msg/s) | 0    |
| rerun after the fixes | 10.3 s (97.1 msg/s), +7.3 %      | 21.2 s (47.1 msg/s) | 0    |

The slowest SMTP accept is within the 15 % allowance (L8.1: one `createMany` added to the commit transaction). Storing was faster than the baseline in every run. The 2.2 baseline was measured with a host-run adapter, here the adapter ran as a container.

**Observed, not explained.** `messaging-backlog` (500 received events drained after the email-worker is unpaused) took 60.0 s (8.3 msg/s) in run 1, after the worker had been paused for 80.5 s. It took 5.8 s (86.7 msg/s) when the suite ran alone and 11.8 s (42.4 msg/s) in run 2. Step 3.2 recorded 2.9–4.5 s (111–170 msg/s). The `email.received` path writes no lifecycle state (L8.2), and the email-worker logged no AMQP reconnect during the backlog phase. The suite's assertions (prefetch bound, exactly once) passed every time. The drop was not investigated further and is listed in 13.7.

### 13.4 Test hygiene (L16)

- `tests/integration/support/broker.ts`: `DORMANT_QUEUES` (the ten names, each checked at load time to be a `dormant` queue of the topology, so a work, delay or dead-letter queue can never be purged by it), `purgeDormantQueues()`, `ManagementApi.purge` / `peek`. Called in `afterAll` of every suite that sends mail: the fifteen `smtp-*`/`routing-*`/`mime-ingestion` suites directly, and the `messaging-*` and `lifecycle-*` suites through `MessagingScenario.teardown`. After the runs, the package suites (not owned by WP5) had again left 1 058 messages in `email.analytics` and 26 in each of four scan queues; these were purged by name.
- `routing-signals`: the cursor is rewound to the maillog offset recorded before the test's submission, keeping the stored file identity (`file_id`). The test then waits until the cursor passes the check-point offset, and asserts that this takes under 30 s. The whole suite took 18.2 s (run 1) and 16.8 s (run 2). Before the change, the re-read depended on the accumulated maillog: step 3.2 recorded a 180 s timeout with a 26 MB log (07-rabbitmq.md).

### 13.5 Fixes made by WP5

No production code was changed: the stack suites revealed no production defect. Test and environment changes:

1. `smtp-inbound.test.ts`: the ingestion outbox assertion now excludes `mail.message.state_changed.v1`. The pass-through and planner write those rows for the same message since step 3.3, so the count depended on timing; run 2 caught it.
2. `messaging-replay.test.ts`: the fixture message is `approved` (v2, with history) instead of `received`, because the planner rejects approvals of messages in any other state (L8.4).
3. `lifecycle-event-relay.test.ts` (WP5's own first attempt): the re-drive fixture's message was received _after_ its backdated approval, so the planner's provenance check (`created_at ≥ received_at − 5 min`) rejected it as `approval_not_issued` and dead-lettered it twice. The fixture message is now received 15 minutes earlier.
4. `smtp-concurrency.test.ts`: the comment about the case-insensitive `mta_queue_id` was out of date after L15. It is corrected, and a SQL `COUNT(DISTINCT mta_queue_id)` = 1 000 assertion was added.
5. Environment: `SMTP_ADAPTER_HOST=smtp-adapter` in `.env` (13.1); `docker compose restart clamav` twice (OOM); `admin-portal` started.

### 13.6 Deviations

See §12 "WP5". In summary: hour-scale deadlines with backdated fixtures instead of second-scale deadlines through the environment; the event-relay container is stopped (not only its lifecycle roles) while the host instance runs; the re-drive test needs about 5 minutes; the delivery-worker crash suite sends 200 messages.

### 13.7 Not complete / not verified locally

- **Commit pending**; CI has not run any of these suites.
- ~~No single uninterrupted all-green `pnpm test:integration` run.~~ WP5: ClamAV was OOM-killed in both full runs on the shared 8 GB VM. **Resolved in verification round 1 (13.9):** run 3 of the whole chain was green from start to end.
- ~~Leftover in the broker~~ (WP5's 2 dead letters of organization 7373): **removed in verification round 1 (13.9)**, together with a third one that round produced and traced to an api-suite hygiene gap, which it fixed.
- **Production MySQL:** the enum narrowing is a table copy of `email_messages` and `email_message_status_history` (WP1 `ALGORITHM=COPY`). It was verified only on local data (a few thousand rows). On a production volume it needs an online schema change plan, which is out of scope (§10).
- **Scale figures:** throughput at 1 M messages/day, lock contention on a 1 000-recipient message with many signals, and the outbox growth from `state_changed` events (about 3 rows per message) were not measured beyond the local suites.
- The `messaging-backlog` drain rate was lower than in step 3.2 (13.3, "Observed, not explained").
- Broker node-failure test (`test:cluster`) not re-run; Kubernetes manifests for the event-relay lifecycle keys rendered by WP2 but never applied; alert rules validated with promtool only (no running Prometheus/Alertmanager: the observability profile cannot run with the apps profile on this VM); `admin-portal` image not rebuilt (unchanged).
- Producers of the scan, policy, quarantine-workflow and archive edges (E3, E5–E13, E16–E18, E25) are later steps by design (L17). A rescanned message stays `scanning` until 4.x consumes the request or the sweeper expires it: **administrative rescan is a state transition plus the request contract; the scan itself is deferred to step 4.1** (13.10).

### 13.8 State left behind

The stack is running with the new images: the apps and `smtp-test` profiles healthy, ClamAV healthy after its restart, and the `event-relay` container running again with default lifecycle settings. No host relay is left on port 3071. RabbitMQ: all work, delay and dormant queues are at 0, with 1 consumer each on `email.received` and `email.delivery.pending`; `email.dead-letter` held 2 messages (13.7; purged in verification round 1, see 13.9). Postfix queues (`postfix`, `postfix-outbound`, `postfix-notify`): 0. MySQL: 0 `it-*` organizations, 0 unpublished outbox rows; the pre-3.3 local data (1 `persisted`, 8 `delivery_pending`, backfilled by WP1) is unchanged. `email_gateway_verify` was dropped.

### 13.9 Verification round 1 (independent verifier, 2026-11-04)

Same machine and branch, nothing committed. All results below come from this round's own runs, not the WP reports.

**Commands and results**

| Command                                                                                                                                                  | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm install --frozen-lockfile`, `pnpm db:generate`                                                                                                     | lockfile up to date; client generated                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `pnpm db:migrate`, `pnpm db:status`, `migrate diff --from-url <main> --to-schema-datamodel`                                                              | 13 migrations, nothing pending, "No difference detected"                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Clean schema `email_gateway_verify` (created and granted by root, `migrate deploy`, `partitions apply`, drift check, then dropped and the grant revoked) | 13 migrations applied; partitions exit 0; no drift; 73 tables (+ `_prisma_migrations`), 19 partitioned; `email_messages.status` has the 15 values with default `received`; `utf8mb4_bin` on the five queue-id columns and `api_idempotency_keys.idempotency_key`                                                                                                                                                                                                                              |
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck`                                                                                                       | clean; 30/30; 30/30 (rerun after this round's test fixes: same)                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `pnpm turbo run test --force`                                                                                                                            | 29/29 tasks, 0 cached, **2,891 tests**                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `pnpm test:e2e`                                                                                                                                          | api 261 (rerun after the fixes: 261)                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `pnpm turbo run build --force`                                                                                                                           | 20/20, 0 cached                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Images, one at a time (`docker compose --profile apps build <svc>`)                                                                                      | db-migrate 121 s, smtp-adapter 76 s, email-worker 98 s, delivery-worker 68 s, event-relay 67 s, api 74 s, policy-engine 64 s, archive-worker 65 s, notification-worker 64 s, admin-portal 42 s: all exit 0                                                                                                                                                                                                                                                                                    |
| `docker compose --profile apps --profile smtp-test up -d --wait`                                                                                         | every service healthy except ClamAV (clamd OOM-killed while the stack started; restarted, healthy); `rabbitmq-init` verified 6 exchanges, 14 quorum queues, 37 bindings                                                                                                                                                                                                                                                                                                                       |
| `docker compose exec postfix-outbound postfix logrotate`                                                                                                 | rotated (`maillog.20261104-112652.gz`); the new `maillog` is 0644                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `pnpm test:integration` run 1                                                                                                                            | **invalid**: the host went into clamshell sleep twice (`pmset` log: about 17:02 to 17:25 and 17:34 to 17:54). `lifecycle-event-relay` (2 tests) and `smtp-concurrency` timed out, measured at 345 s, 1327 s and 1207 s of wall clock. The expiry itself had taken 1.0 s. 238/241; the chain stopped at the first suite                                                                                                                                                                        |
| run 2 (`caffeinate -dims`)                                                                                                                               | 238/241: `lifecycle-consumer-crash` timed out across another lid sleep, after its scenario had passed (200/200 exactly once, delivered in 23.8 s); `mail-plane` ClamAV PING/EICAR (2) failed because clamd was OOM-killed (ClamAV unhealthy). ClamAV restarted, and both files were rerun: 8/8. Package suites run separately: api 242 + **1 failed** (`domain-jobs`, see fixes), smtp-adapter 66, message-lifecycle 17, mail-routing 22, delivery-worker 42, email-worker 20, event-relay 20 |
| **run 3 (whole chain)**                                                                                                                                  | **exit 0, green from start to end**: stack 40 files / 241 tests; api 243 + 1 skipped (by design: the policy-down probe skips while the smtp-adapter runs); smtp-adapter 66; message-lifecycle 17; mail-routing 22; delivery-worker 42; email-worker 20; event-relay 20 (**671 passed**)                                                                                                                                                                                                       |
| api `test:integration` after the fixes, twice                                                                                                            | 21 files, 243 passed + 1 skipped, both runs                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `domain-jobs.test.ts` after its fix, 5 times                                                                                                             | 9/9 each time; the api container's scheduler claimed nothing meanwhile                                                                                                                                                                                                                                                                                                                                                                                                                        |

Run 3 figures: `smtp-concurrency` 1000 messages over 40 sessions, SMTP accept 7.5 s, stored 9.5 s, loss 0 (2.2 baseline 9.6 s / 59.7 s); `messaging-backlog` drained 496 at 109.4 msg/s (inside step 3.2's 111–170 msg/s range only at its lower edge; WP5 saw 8.3–86.7). This run does not confirm the 13.7 slowdown. `lifecycle-consumer-crash` 200/200 exactly once; `lifecycle-rescan` one copy in each of the five scan queues; `lifecycle-release` delivered 1.0 s after the release; `lifecycle-event-relay` expiry 1.0 s and re-drive delivered after 299.5 s (the 300 s unconsumed threshold).

**Fixes (test hygiene only; no production code changed, no assertion weakened)**

- `apps/api/integration/domain-jobs.test.ts` (step 2.1 suite, failed in run 2): _"verifies due domains … across concurrent ticks and replicas"_ expected 6 claimed and got 2. Root cause: the running api container's own `DomainCheckScheduler` ticks every 30 s with the real clock against the same MySQL and Redis. Every domain the suite makes due at its 2001 tick time is due for that scheduler too, so at 13:42:55Z it claimed 4 of the suite's 6 domains (its log: `due 4, claimed 4`). Fix: the suite holds the shared tick lock (`fenceSchedulers`, a 300 s fence) whenever its own scheduler is not ticking. It lifts the lock only for its own `runOnce`, and deletes it in `afterAll`. Another replica's `runOnce` then returns null, as designed.
- `apps/api/integration/messages-lifecycle.test.ts` and `tenant-isolation-messages.test.ts` (WP4), with the new `apps/api/integration/support/live-relay.ts`. A release writes `mail.delivery.approved.v1` outbox rows. With the apps profile up, the live event-relay (250 ms poll) published one, and the live planner consumed it after the fixture cleanup had deleted its outbox row. The result was an `approval_not_issued` dead letter: organization 7957, event `01a1a6d2-…`, 13:49:17Z, plus its `message_consumer_progress` row. Had the planner won the race, it would have planned a fixture message. Fix: both suites stop a running `event-relay` container in `beforeAll` and start it again (waiting for `/health/ready`) in `afterAll`, after the fixture cleanup. This is the same pattern `tests/integration/lifecycle-event-relay.test.ts` uses. Without Docker, or with the container stopped, nothing changes. Verified: 2 further api runs added 0 dead letters, and no `api:` correlation reached the planner.

**Not run:** the 3-node `test:cluster`. Nothing on its path changed: no messaging client, publisher or consumer source in `packages/common/src/messaging`, only a test count; `definitions.json` gained only the five rescan bindings.

**Recorded, not product failures:** ClamAV clamd OOM-killed twice (at `up`, and before run 2's `mail-plane`). It was restarted each time, and the affected suite passed on rerun. Host sleep invalidated run 1 and one test of run 2.

**State left behind (checked after the last run):**

- `rabbitmqctl list_queues -p email-gateway`: all 14 queues at 0, 1 consumer each on `email.received` and `email.delivery.pending`. The 3 dead letters (WP5's 2 of organization 7373, and the 1 above) and the dormant queues' residue from the package suites (`email.analytics` 1060, `scan.*` 26 each) were purged by name. Vhost `/` has no queues.
- Postfix queues `postfix`, `postfix-outbound`, `postfix-notify`: 0.
- MySQL: 0 `it-*` organizations, domains and users; 0 `it.*` ledger rows; 0 `message_consumer_progress` (the dead letter's row was deleted); 0 unpublished and 0 poison outbox rows; 0 `api_idempotency_keys`. Organizations left: only platform, demo and the pre-existing `verify21-…`.
- S3 `gateway-mail`: only the demo organization's 18 objects, last written 07:29Z, before this round; `gateway-archive` empty.
- `.env`: `SMTP_ADAPTER_HOST=smtp-adapter` was used for the runs, then restored to `host.docker.internal`; `cmp` against the backup taken before WP5's change: identical.
- The stack is still running with the rebuilt images; every service is healthy.

### 13.10 Verification round 2 (review findings, 2026-11-04)

Same machine and branch, nothing committed. Three review findings (medium and above) were checked against the code.

**Findings**

| #   | Finding                                                                                      | Verdict                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | high: a release left released recipients `quarantined`, which L9 counts as settled           | **Confirmed.** `RELEASABLE = ['pending','quarantined']`, the release wrote no `email_recipients` row, and the recorder derives after every applied signal. A refusal of recipient 0 derived `rejected/delivery_failed` while recipient 1 was still `quarantined`, and that final state was never corrected. With more than 1 000 recipients, an all-refused or all-delivered chunk 1 ended the message, and the planner then refused chunk 2 (`lifecycle_state`). | `MessageLifecycleRepository.markReleasedRecipientsPending`: in the release transaction, before the approvals, the released recipients go from `quarantined` to `pending` (tenant-scoped `updateMany`; not a lifecycle column, so the one-door rule allows it). L9 and L10.3 are amended. Tests: an api unit case (statuses after release, and no change on rollback); api integration cases (4 recipients; 1 001 recipients → 2 approvals of 1000 + 1, all `pending`); a delivery-worker integration case (an all-refused chunk 1 leaves `delivery_pending` while chunk 2 is pending); and a stack case in `lifecycle-release` (inbound recipient 0 on a domain outside the organization is refused, recipient 1 is delivered, final state `delivered/delivery_partial`).                                                                                                                |
| 2   | medium: administrative rescan changes only the state; nothing consumes `rescan_requested.v1` | **Confirmed as a scope statement, not a defect.** The step already documents this (L10.2, the runbook and the response `note`), and consumers are Phase 4 by design (§10, L17). The documents did not say plainly that the feature delivers only part of the brief.                                                                                                                                                                                               | Labeled everywhere as "state transition and request contract only; the scan is deferred to step 4.1": the status header, L10.2, 13.7, README, `docs/api/README.md`, `apps/api/README.md` and the execution plan. **Rejected sub-suggestions:** (a) a "minimal real consumer" would be a mock scan, which the product owner's rules forbid, and it belongs to step 4.1. (b) Removing `drop-head` or adding an alert on queue depth would change the step 3.2 topology for the dormant queues that 4.1 owns. Requests dropped before 4.1 exists have no effect anyway, because the sweeper expires the message after 24 h and another rescan is allowed. The existing `LifecycleStuckMessages{state="scanning"}` alert already surfaces rescanned messages.                                                                                                                                |
| 3   | medium: the lifecycle check and expiry lookbacks bounded `received_at`                       | **Confirmed.** With a 90-day quarantine deadline, a message released after the 192 h check lookback was invisible to recovery. A message rescanned from `expired` near the 186-day expiry lookback was never expired again.                                                                                                                                                                                                                                       | Both queries now bound `status_changed_at` (the state age) instead of `received_at`. Each is a range on the existing index `(status, status_changed_at)`, one per monthly partition (6-month retention), so dropping partition pruning costs little. New config rule: `LIFECYCLE_CHECK_LOOKBACK_HOURS × 3600 > LIFECYCLE_CHECK_AFTER_SECONDS`. `.env.example` comments, the event-relay README, the runbook and L13/L14/§5 are updated. No key or value changed, so the local `.env` needs nothing. Tests: unit (check: received 240 h ago, changed 1 h ago → recovered; sweeper: received 60 days ago, rescanned 25 h ago → expired; config rule); event-relay integration on the writer (a message received 10 days ago, in `delivery_pending` for 1 h, is recovered with a 24 h lookback; a message received 10 days ago, in `persisted` for 60 s, is expired with a 2-day lookback). |

**Test-hygiene fixes found by this round's runs (no production code, no assertion weakened)**

- `tests/integration/lifecycle-release.test.ts`: the first draft of the new case used a suppression. Suppressions apply only to outbound mail, and the fixture is inbound, so it now uses an inbound refusal (`recipient_domain_inactive`).
- `apps/smtp-adapter`: the package integration suite was the only one that did not pause the live outbox consumers. With the apps profile up, the live event-relay published its fresh rows (`publishedAt: null` failed once) and the dev pass-through moved its messages to `approved` (history count 3 instead of 2). New globalSetup `integration/support/live-workers.ts` (the event-relay `live-relay.ts` pattern) pauses `event-relay`, `email-worker` and `delivery-worker` and resumes them afterwards. The redelivery case also counts only `actor_role = 'ingestion'` history rows. Verified 5/5 runs.
- `tests/integration/lifecycle-rescan.test.ts`: the relay marks `published_at` after the broker confirm, so the queue copies can be visible first (failed once). The suite now waits for the mark.

**Commands and results (final run of this round)**

| Command                                                                                                 | Result                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck`                                                      | clean; 30/30; 30/30                                                                                                                                                                                                                                                                                    |
| `pnpm turbo run test --force`                                                                           | 29/29 tasks, **2,894 tests** (+3 from this round)                                                                                                                                                                                                                                                      |
| `pnpm test:e2e` (and `UPDATE_OPENAPI=1 … openapi` for the release description)                          | api 261                                                                                                                                                                                                                                                                                                |
| `pnpm turbo run build --force`                                                                          | 20/20, 0 cached                                                                                                                                                                                                                                                                                        |
| `pnpm db:migrate`, `pnpm db:status`, `migrate diff --from-url <main> --to-schema-datamodel --exit-code` | nothing to apply, 13 migrations, up to date, "No difference detected" (no schema change in this round, so no clean-schema rerun)                                                                                                                                                                       |
| Images `api`, `event-relay`, one at a time (the only images with changed production code)               | exit 0 (93 s, 85 s); both recreated with `--no-deps`, healthy                                                                                                                                                                                                                                          |
| `caffeinate -dims pnpm test:integration`: runs 1 to 3                                                   | run 1: 3 failures (2 ClamAV, clamd OOM-killed again; 1 premise bug in the new stack case). Run 2: stack 242/242 and api green, then smtp-adapter 1 failed (live-consumer race). Run 3: `lifecycle-rescan` failed once (`published_at` race). Each was fixed as described above.                        |
| **run 4 (whole chain)**                                                                                 | **exit 0**: stack 40 files / 242; api 245 + 1 skipped; smtp-adapter 66; message-lifecycle 17; mail-routing 22; delivery-worker 43; email-worker 20; event-relay 22 (**677 passed**). `smtp-concurrency` 1000 messages, accept 9.5 s, stored 11.6 s, loss 0; `messaging-backlog` drained at 109.7 msg/s |

**State left behind:** every RabbitMQ queue of `email-gateway` is at 0 (the dormant `email.analytics` and `scan.*` residue was purged by name); the dead-letter queue is at 0; the Postfix queues are empty; MySQL has 0 `it-*` organizations, 0 unpublished outbox rows, 0 `message_consumer_progress` rows and 0 `api_idempotency_keys`. `.env` was set to `SMTP_ADAPTER_HOST=smtp-adapter` only for the runs and is restored byte-identical (`cmp`). `test:cluster` was not run, because nothing on its path changed.

### 13.11 Independent pre-commit verification (2026-11-04)

Re-run from a clean shell after review round 2, before the commit: `install --frozen-lockfile`, `format:check`, `lint`, `typecheck`, `test`, `test:e2e`, `build` and `db:status` pass; ten images rebuilt one at a time; `pnpm test:integration` with the adapter in its container passed the whole chain (stack 242/242, api 245 + 1 skipped, smtp-adapter 66, message-lifecycle 17, mail-routing 22, delivery-worker 43, email-worker 20, event-relay 22; smtp-concurrency 1 000 messages, loss 0). clamav came up unhealthy (OOM on the 8 GB VM) and was restarted before the run. Afterwards all three Postfix queues were empty without manual cleanup, all 14 RabbitMQ queues were at 0 after the dormant-queue purge (`rabbitmqctl list_queues`), MySQL had no `it-*` organizations or consumer-progress rows, and `.env` was restored byte-identical.
