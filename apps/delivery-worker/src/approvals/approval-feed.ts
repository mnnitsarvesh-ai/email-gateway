import type { EventFeed } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';

/**
 * The transport that delivers events to a consumer (step 2.3 R5). Since step 3.1 (M2) it is
 * the shared `EventFeed` of `@email-gateway/common`, implemented by its `OutboxPoller` until the
 * outbox relay to RabbitMQ exists; **step 3.2 replaces the poller with a RabbitMQ consumer of
 * the same event behind this interface**, without touching planning. Implementations deliver
 * at least once; handlers are idempotent.
 */
export type ApprovalFeed<T> = EventFeed<T>;

/**
 * Handles one event inside the consumer's idempotency transaction (`processOnce`): every effect
 * goes through `tx`, so the ledger row and the effects commit together or not at all. Adapted
 * to an `EventHandler` with `processOnceHandler`.
 */
export type FeedHandler<T> = (
  event: EventEnvelope<T>,
  tx: Prisma.TransactionClient,
) => Promise<void>;
