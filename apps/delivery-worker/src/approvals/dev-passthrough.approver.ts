import type { Prisma } from '@email-gateway/database';
import {
  deliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  type MessageReceivedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { SOURCE_SERVICE } from '../planning/delivery-planner';
import { uuidv7 } from '../shared/uuidv7';
import type { ApprovalFeed } from './approval-feed';

/** `message_idempotency.consumer` of the development pass-through (R5). */
export const DEV_PASSTHROUGH_CONSUMER = 'delivery-worker.dev-passthrough';

export const DEV_PASSTHROUGH_WARNING =
  'DEV PASS-THROUGH ENABLED: mail is delivered without scanning or policy (not production behaviour)';

/** `mail.delivery.approved.v1` carries at most 1000 recipients. */
const MAX_APPROVAL_RECIPIENTS = 1000;

export interface PassThroughResult {
  approvals: string[];
  recipients: number;
}

/**
 * DEVELOPMENT ONLY (step 2.3 R5): turns every `mail.message.received.v1` into
 * `mail.delivery.approved.v1` (`source = dev_passthrough`, `deliverySeq = 0`) for every recipient
 * of the message whose `email_recipients.status` is `pending`, so the stack can be tested end
 * to end before scanning (3.x) and policy (5.x) exist. **This is not production behaviour: it
 * delivers mail without scanning or policy.** Config validation refuses it unless `APP_ENV` is
 * `local` or `ci`; it starts from the outbox position at its first start (never replays old
 * mail). Step 5.x replaces it with the policy engine's approvals.
 *
 * In the feed's idempotency transaction it writes the approval outbox row(s) and one
 * `email_events` row `delivery.approved` per approval (`details.source = dev_passthrough`). The
 * message and its EML key come from the writer row of the envelope's organization, never from
 * the event payload alone.
 */
export class DevPassThroughApprover {
  private readonly logger: Logger;

  constructor(
    private readonly feed: ApprovalFeed<MessageReceivedV1>,
    logger: Logger,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.logger = logger.child({ component: 'dev-passthrough' });
  }

  start(): void {
    this.logger.warn(DEV_PASSTHROUGH_WARNING);
    this.feed.start(async (event, tx) => {
      await this.approve(event, tx);
    });
  }

  stop(): Promise<void> {
    return this.feed.stop();
  }

  async approve(
    event: EventEnvelope<MessageReceivedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<PassThroughResult> {
    const organizationId = BigInt(event.organizationId);
    const messageId = BigInt(event.payload.messageId);
    const receivedAt = new Date(event.payload.receivedAt);
    const ids = { eventId: event.eventId, messageId: event.payload.messageId };
    const message = await tx.emailMessage.findFirst({
      where: { id: messageId, receivedAt, organizationId },
      select: { emlObjectKey: true },
    });
    if (!message) {
      this.logger.warn(ids, 'received message not found for the organization; not approved');
      return { approvals: [], recipients: 0 };
    }
    const recipients = await tx.emailRecipient.findMany({
      where: { messageId, receivedAt, organizationId, status: 'pending' },
      orderBy: { rcptSeq: 'asc' },
      select: { id: true, rcptSeq: true },
    });
    const approvals: string[] = [];
    const now = this.now();
    for (let i = 0; i < recipients.length; i += MAX_APPROVAL_RECIPIENTS) {
      const chunk = recipients.slice(i, i + MAX_APPROVAL_RECIPIENTS);
      const approvalId = uuidv7(now.getTime());
      const payload = deliveryApprovedV1.parse({
        messageId: messageId.toString(),
        receivedAt: receivedAt.toISOString(),
        deliverySeq: 0,
        source: 'dev_passthrough',
        emlS3Key: message.emlObjectKey,
        recipients: chunk.map((r) => ({ recipientId: r.id.toString(), rcptSeq: r.rcptSeq })),
        approvedAt: now.toISOString(),
      });
      await tx.messageOutbox.create({
        data: {
          eventId: approvalId,
          organizationId,
          eventType: EventTypes.DeliveryApproved,
          aggregateType: 'message',
          aggregateId: messageId.toString(),
          correlationId: event.correlationId,
          payload,
        },
        select: { id: true },
      });
      await tx.emailEvent.create({
        data: {
          receivedAt,
          messageId,
          organizationId,
          eventType: 'delivery.approved',
          occurredAt: now,
          sourceService: SOURCE_SERVICE,
          eventId: approvalId,
          details: {
            source: 'dev_passthrough',
            approvalEventId: approvalId,
            deliverySeq: 0,
            recipientCount: chunk.length,
          },
        },
        select: { id: true },
      });
      approvals.push(approvalId);
    }
    if (approvals.length === 0) {
      this.logger.info(ids, 'no pending recipients; nothing approved');
    } else {
      this.logger.info(
        { ...ids, approvals: approvals.length, recipients: recipients.length },
        'dev pass-through approved the message (no scanning, no policy)',
      );
    }
    return { approvals, recipients: recipients.length };
  }
}
