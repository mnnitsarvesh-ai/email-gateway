import {
  type AmqpConnection,
  type ConfirmPublisher,
  type ConsumerProgressRecorder,
  type EventFeed,
  type MessagingMetrics,
  QueueConsumer,
} from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  type DeliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  type RetryPolicy,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { PLANNER_CONSUMER } from './planner-consumer-name';

/**
 * The transport that delivers events to a consumer (step 2.3 R5): the shared `EventFeed` of
 * `@email-gateway/common`. Since step 3.2 (Q13) the planner's feed is a RabbitMQ
 * `QueueConsumer` of `email.delivery.pending` (`createApprovalFeed`); the development
 * pass-through keeps the outbox poller. Implementations deliver at least once; handlers are
 * idempotent.
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

/** The queue the planner consumes (topology v1, work policy). */
export const APPROVAL_QUEUE = 'email.delivery.pending';

/**
 * The planner's feed (step 3.2 Q13): a `QueueConsumer` of `email.delivery.pending` accepting
 * `mail.delivery.approved.v1`, prefetch `DELIVERY_APPROVAL_PREFETCH`, retry = the topology's
 * `delay-queue` policy (copies wait in `email.delivery.retry` with a per-message TTL and return;
 * 10 attempts, 5 s - 15 min, 48 h retry age), default classification (database and network
 * outages transient, `NonRetryableError` fatal, anything else retryable). `retry` overrides the
 * topology policy within its validated bounds (none in production). `progress` records retry and
 * dead-letter hops (`message_consumer_progress`) for the outbox reconciler.
 */
export function createApprovalFeed(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  prefetch: number;
  logger: Logger;
  metrics?: MessagingMetrics;
  consumer?: string;
  retry?: Partial<RetryPolicy>;
  progress?: ConsumerProgressRecorder;
}): QueueConsumer<DeliveryApprovedV1> {
  return new QueueConsumer<DeliveryApprovedV1>({
    connection: options.connection,
    publisher: options.publisher,
    queue: APPROVAL_QUEUE,
    consumer: options.consumer ?? PLANNER_CONSUMER,
    eventTypes: [EventTypes.DeliveryApproved],
    prefetch: options.prefetch,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    ...(options.retry ? { retry: options.retry } : {}),
    ...(options.progress ? { progress: options.progress } : {}),
  });
}
