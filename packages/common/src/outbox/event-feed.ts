import { type Prisma, processOnce, type PrismaClient } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import { withTransactionDefaults } from './db';

/** What a handler did with one event: applied its effects, or found it already applied. */
export type HandleOutcome = 'handled' | 'duplicate';

/**
 * Handles one event. Must be idempotent (feeds deliver at least once) and throws on a failure:
 * the feed then redelivers the event later (RabbitMQ: a retry hop or, after the queue's attempt
 * limit or for a `NonRetryableError`, a dead letter) and never acks it without a result.
 */
export type EventHandler<T> = (event: EventEnvelope<T>) => Promise<HandleOutcome>;

/**
 * The transport that delivers events of one type to one consumer (step 2.3 R5, step 3.1 M2,
 * step 3.2 Q13). Since step 3.2 the production feed is the RabbitMQ `QueueConsumer`
 * (`messaging/consumer.ts`: manual acks, retry with backoff, dead-letter) fed by the outbox relay
 * (`apps/event-relay`); `OutboxPoller` remains only for the delivery-worker dev pass-through
 * (development only, not a pipeline stage). Handlers are the same for both.
 */
export interface EventFeed<T> {
  /** Starts delivering events to `handler` (in the background). */
  start(handler: EventHandler<T>): void;
  /** Stops delivering and waits for the in-flight work. */
  stop(): Promise<void>;
}

/**
 * Adapts a handler whose effects all run inside the consumer's idempotency transaction (the
 * step 2.3 shape): `processOnce(consumer, eventId)` inserts the ledger row and runs `handler`
 * in the same writer transaction (budget `txTimeoutMs`), so the ledger row and the effects
 * commit together or not at all. An event already in the ledger is `duplicate`; a throwing
 * handler rolls everything back and the error propagates (the feed retries the event).
 */
export function processOnceHandler<T>(
  prisma: PrismaClient,
  consumer: string,
  handler: (event: EventEnvelope<T>, tx: Prisma.TransactionClient) => Promise<void>,
  options: { txTimeoutMs: number },
): EventHandler<T> {
  const txPrisma = withTransactionDefaults(prisma, { timeoutMs: options.txTimeoutMs });
  return async (event) => {
    const result = await processOnce(txPrisma, consumer, event.eventId, (tx) => handler(event, tx));
    return result.status === 'duplicate' ? 'duplicate' : 'handled';
  };
}
