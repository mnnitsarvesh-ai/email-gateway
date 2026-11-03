import type { Prisma } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';

/**
 * Handles one event inside the consumer's idempotency transaction (`processOnce`): every effect
 * goes through `tx`, so the ledger row and the effects commit together or not at all.
 */
export type FeedHandler<T> = (
  event: EventEnvelope<T>,
  tx: Prisma.TransactionClient,
) => Promise<void>;

/**
 * The transport that delivers events to a consumer (step 2.3 R5). Step 2.3 implements it with
 * the `OutboxPoller` (R6), because the outbox relay to RabbitMQ does not exist yet; **step 3.2
 * replaces the poller with a RabbitMQ consumer of the same event behind this interface**,
 * without touching planning. Implementations deliver at least once; handlers are idempotent.
 */
export interface ApprovalFeed<T> {
  /** Starts delivering events to `handler` (in the background). */
  start(handler: FeedHandler<T>): void;
  /** Stops delivering and waits for the in-flight batch. */
  stop(): Promise<void>;
}
