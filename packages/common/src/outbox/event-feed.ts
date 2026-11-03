import { type Prisma, processOnce, type PrismaClient } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import { withTransactionDefaults } from './db';

/** What a handler did with one event: applied its effects, or found it already applied. */
export type HandleOutcome = 'handled' | 'duplicate';

/**
 * Handles one event. Must be idempotent (feeds deliver at least once) and throws on a retryable
 * failure: the feed then redelivers the event later and never skips it.
 */
export type EventHandler<T> = (event: EventEnvelope<T>) => Promise<HandleOutcome>;

/**
 * The transport that delivers events of one type to one consumer (step 2.3 R5, step 3.1 M2).
 * Until step 3.2 it is the outbox poller (`OutboxPoller`, `ShardedOutboxFeed`); **step 3.2
 * replaces it with a RabbitMQ consumer of the same event behind this interface**, with the
 * handler unchanged.
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
