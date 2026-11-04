import { processOnceHandler } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { type DeliveryApprovedV1 } from '@email-gateway/event-contracts';
import type { DeliveryPlanner } from '../planning/delivery-planner';
import type { ApprovalFeed } from './approval-feed';
import { PLANNER_CONSUMER } from './planner-consumer-name';

export { PLANNER_CONSUMER } from './planner-consumer-name';

/**
 * Consumer `delivery-worker.planner` of `mail.delivery.approved.v1` (R5, R7): hands every
 * approval to the planner inside the consumer's idempotency transaction (`processOnceHandler`
 * on the writer, budget `txTimeoutMs`). The feed is the RabbitMQ consumer of
 * `email.delivery.pending` since step 3.2 (`createApprovalFeed`; the outbox poller before), with
 * the consumer name unchanged so ledger rows of the earlier poller make re-deliveries free.
 */
export class DeliveryApprovalConsumer {
  constructor(
    private readonly feed: ApprovalFeed<DeliveryApprovedV1>,
    private readonly planner: DeliveryPlanner,
    private readonly prisma: PrismaClient,
    private readonly txTimeoutMs: number,
  ) {}

  start(): void {
    this.feed.start(
      processOnceHandler<DeliveryApprovedV1>(
        this.prisma,
        PLANNER_CONSUMER,
        async (event, tx) => {
          await this.planner.plan(event, tx);
        },
        { txTimeoutMs: this.txTimeoutMs },
      ),
    );
  }

  stop(): Promise<void> {
    return this.feed.stop();
  }
}
