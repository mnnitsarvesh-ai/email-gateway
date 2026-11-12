import {
  type AmqpConnection,
  type ConfirmPublisher,
  type ConsumerProgressRecorder,
  type EventFeed,
  type EventHandler,
  type MessagingMetrics,
  processOnceHandler,
  QueueConsumer,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import {
  EventTypes,
  type QuarantineReleaseRequestedV1,
  type RetryPolicy,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { PolicyMetrics } from '../metrics/policy-metrics';
import type { QuarantineMetrics } from '../metrics/quarantine-metrics';
import {
  QUARANTINE_RELEASE_CONSUMER,
  type ReleaseExecutor,
  type ReleaseOutcome,
} from './release-executor';

/** The executor's work queue (topology v10, Q27). */
export const QUARANTINE_QUEUE = 'email.quarantine';

/**
 * The `QueueConsumer` of `email.quarantine` (Q13.2, Q27): `mail.quarantine.release_requested.v1`,
 * prefetch `QUARANTINE_RELEASE_PREFETCH`, the topology's retry policy (`hold`, 10 attempts,
 * 2 s – 1 min, 24 h), default classification (`NonRetryableError` fatal; an inconsistent read
 * or a lock conflict retryable), `PrismaConsumerProgress` for the reconciler. Topology v10 binds
 * only the release event to the queue, so the consumer accepts only that type (step 5.3 WP3
 * deviation: a `mail.policy.decided.v1` left over from the dormant v9 buffer is rejected by the
 * codec as `unknown_event_type` and dead-lettered; docs/deployment/quarantine.md drains it).
 */
export function createQuarantineReleaseFeed(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  prefetch: number;
  logger: Logger;
  metrics?: MessagingMetrics;
  consumer?: string;
  retry?: Partial<RetryPolicy>;
  progress?: ConsumerProgressRecorder;
}): QueueConsumer<QuarantineReleaseRequestedV1> {
  return new QueueConsumer<QuarantineReleaseRequestedV1>({
    connection: options.connection,
    publisher: options.publisher,
    queue: QUARANTINE_QUEUE,
    consumer: options.consumer ?? QUARANTINE_RELEASE_CONSUMER,
    eventTypes: [EventTypes.QuarantineReleaseRequested],
    prefetch: options.prefetch,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    ...(options.retry ? { retry: options.retry } : {}),
    ...(options.progress ? { progress: options.progress } : {}),
  });
}

/** Counts a committed release outcome. */
export function recordReleaseOutcome(
  metrics: QuarantineMetrics,
  outcome: ReleaseOutcome,
  policy?: Pick<PolicyMetrics, 'copies'>,
): void {
  metrics.releases.inc({ result: outcome.result, mode: outcome.mode });
  metrics.releaseDuration.observe(outcome.durationSeconds);
  // Release copies are policy copies too (policy_copy_total, Q13.6).
  if (policy !== undefined && outcome.copy !== null) policy.copies.inc({ result: outcome.copy });
}

/**
 * Consumer `policy-engine.quarantine`: every event runs `ReleaseExecutor.execute` inside the
 * consumer's idempotency transaction (`processOnceHandler` on the writer, budget
 * `QUARANTINE_DB_TX_TIMEOUT_MS`); a duplicate delivery is absorbed by the ledger. Metrics only
 * after the commit.
 */
export class QuarantineReleaseConsumer {
  private readonly pending = new Map<string, ReleaseOutcome>();
  readonly handler: EventHandler<QuarantineReleaseRequestedV1>;

  constructor(
    private readonly feed: EventFeed<QuarantineReleaseRequestedV1>,
    executor: Pick<ReleaseExecutor, 'execute'>,
    prisma: PrismaClient,
    private readonly metrics: QuarantineMetrics,
    txTimeoutMs: number,
    consumer: string = QUARANTINE_RELEASE_CONSUMER,
    private readonly policyMetrics?: Pick<PolicyMetrics, 'copies'>,
  ) {
    const inner = processOnceHandler<QuarantineReleaseRequestedV1>(
      prisma,
      consumer,
      async (event, tx) => {
        this.pending.set(event.eventId, await executor.execute(event, tx));
      },
      { txTimeoutMs },
    );
    this.handler = async (event) => {
      this.pending.delete(event.eventId);
      try {
        const handled = await inner(event);
        const outcome = this.pending.get(event.eventId);
        if (handled === 'handled' && outcome !== undefined) {
          recordReleaseOutcome(this.metrics, outcome, this.policyMetrics);
        }
        return handled;
      } finally {
        this.pending.delete(event.eventId);
      }
    };
  }

  start(): void {
    this.feed.start(this.handler);
  }

  stop(): Promise<void> {
    return this.feed.stop();
  }
}
