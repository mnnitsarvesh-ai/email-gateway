# @email-gateway/mail-routing

Routing and per-recipient delivery state shared by the smtp-adapter and the delivery-worker (step 2.3, [design](../../docs/plan/steps/05-routing.md), [ADR-0021](../../docs/architecture/adr/0021-mail-routing-and-delivery-status.md)): direction classification, route plans, destination hosts, reinjection keys and tokens, and the delivery status recorder (`src/delivery-state/`). Writer only (ADR-0014).

## Per-recipient state as data (step 3.3 L9)

`src/delivery-state/transitions.ts` expresses the R9.1 lattice as `DELIVERY_TRANSITIONS` (`{ from, to, sources, condition? }` rows; conditions `first_signal`, `dsn_2xx`, `not_older`; terminal states have no outgoing rows). `nextDeliveryState` looks the rows up (`findDeliveryTransition`) and classifies what they do not allow (`duplicate`, `stale`, `conflict`) with the step 2.3 behaviour unchanged: `transitions.test.ts` keeps the step 2.3 implementation as an oracle and compares every (from, last signal, to, source, older/equal/newer time, DSN, remote attempt) combination.

## Derived message state (step 3.3 L9)

`recordDeliverySignal` no longer writes `email_messages` itself (one-door rule, [ADR-0025](../../docs/architecture/adr/0025-message-lifecycle-state-machine.md)). After an **applied** signal whose delivery has the highest `delivery_seq` of the message, it calls `applyDerivedDeliveryState` of `@email-gateway/message-lifecycle` in the same transaction, under the message lock it already holds:

| Recipients (`email_recipients.status`)           | Message state                            |
| ------------------------------------------------ | ---------------------------------------- |
| one `deferred`                                   | `delivery_retry` (`delivery_deferred`)   |
| one `pending` (queued, unknown), none `deferred` | `delivery_pending` (`delivery_requeued`) |
| all settled, all `delivered`                     | `delivered` (`delivery_complete`)        |
| all settled, some `delivered`                    | `delivered` (`delivery_partial`)         |
| all settled, none `delivered`                    | `rejected` (`delivery_failed`)           |

Only from `delivery_pending` / `delivery_retry`; a message in any other state (expired, quarantined, …) is left alone without an ignored row (`lifecycle_derived_skipped_total{state}`), and a signal of an older `delivery_seq` never moves the message; the per-recipient state is recorded either way. Actor `{ role: 'delivery', service: ctx.sourceService, type: 'system' }`, transition key `signal:<deliveryId>:<signalKey>:<state>`, causation `ctx.eventId`, correlation `delivery:<deliveryId>`. `RecordDeliverySignalResult.messageState` is set when the signal moved the message. `RecorderContext.lifecycleMetrics` (optional) receives the shared lifecycle series. In an own transaction the recorder retries `isRetryableLifecycleError` errors (CAS conflict, deadlock, lock wait, P2034, concurrent transition key) up to 3 times; in a caller's transaction they propagate. Lock order unchanged: `delivery_reinjections` → `email_messages` → `email_deliveries`.

Removed in step 3.3: `aggregateMessageStatus`, `markMessageDeliveryQueued`, `MessageVersionConflictError`, the `QUEUEABLE` list and the recorder's direct status writes (the planner applies `approved → delivery_pending` itself, L8.4).

## Tests

- `pnpm --filter @email-gateway/mail-routing test`: unit tests, including the exhaustive table-versus-oracle test.
- `pnpm --filter @email-gateway/mail-routing test:integration`: the recorder and repository against the real MySQL writer from `.env` (fixtures in `it-*` organizations; messages inserted in a lifecycle state with matching history rows, L8.6): derived `delivery_retry` on a deferral, back to `delivery_pending` on the requeue, `delivered/delivery_complete`, `delivered/delivery_partial`, `rejected/delivery_failed`, an older `delivery_seq` never moving the message, an `expired` message left alone (no ignored row, recipient still recorded), concurrent terminal signals moving the message exactly once, and queue ids differing only in case (L15) resolving to the right delivery.
