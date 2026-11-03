import { type DeliveryApprovedV1 } from '@email-gateway/event-contracts';
import type { DeliveryPlanner } from '../planning/delivery-planner';
import type { ApprovalFeed } from './approval-feed';

/** `message_idempotency.consumer` of the planner (R7). */
export const PLANNER_CONSUMER = 'delivery-worker.planner';

/**
 * Consumer `delivery-worker.planner` of `mail.delivery.approved.v1` (R5, R7): hands every
 * approval to the planner inside the feed's idempotency transaction. The feed is the outbox
 * poller in step 2.3 and a RabbitMQ consumer from step 3.2 on; this class does not change.
 */
export class DeliveryApprovalConsumer {
  constructor(
    private readonly feed: ApprovalFeed<DeliveryApprovedV1>,
    private readonly planner: DeliveryPlanner,
  ) {}

  start(): void {
    this.feed.start(async (event, tx) => {
      await this.planner.plan(event, tx);
    });
  }

  stop(): Promise<void> {
    return this.feed.stop();
  }
}
