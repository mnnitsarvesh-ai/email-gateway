import { processOnceHandler, uuidv7 } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import {
  deliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  type MessageScannedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { transitionMessage } from '@email-gateway/message-lifecycle';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import { SOURCE_SERVICE } from '../planning/delivery-planner';
import type { ApprovalFeed } from './approval-feed';

/**
 * `message_idempotency.consumer` and outbox cursor of the development pass-through (step 4.1
 * S15). New in step 4.1: the step 2.3 consumer `delivery-worker.dev-passthrough` read
 * `mail.message.received.v1`; this one reads `mail.message.scanned.v1` and starts at the latest
 * outbox row (never replays old mail).
 */
export const DEV_PASSTHROUGH_CONSUMER = 'delivery-worker.dev-passthrough-scanned';

export const DEV_PASSTHROUGH_WARNING =
  'DEV PASS-THROUGH ENABLED: mail is delivered after scanning but without policy (not production behaviour)';

/** `mail.delivery.approved.v1` carries at most 1000 recipients. */
const MAX_APPROVAL_RECIPIENTS = 1000;

export interface PassThroughResult {
  approvals: string[];
  recipients: number;
}

/**
 * DEVELOPMENT ONLY (step 2.3 R5, step 4.1 S15): turns every `mail.message.scanned.v1` with
 * `outcome = scanned` into `mail.delivery.approved.v1` (`source = dev_passthrough`) for every
 * recipient of the message whose `email_recipients.status` is `pending`, so the stack can be
 * tested end to end before policy (5.2) exists. **This is not production behaviour: it delivers
 * every scanned message, whatever its verdict, without policy.** Config validation refuses it
 * unless `APP_ENV` is `local` or `ci`; it starts from the outbox position at its first start
 * (never replays old mail). Step 5.2 replaces it with the policy engine's approvals.
 *
 * In the consumer's idempotency transaction (`processOnceHandler`, budget `txTimeoutMs`) it
 * first moves the message `scanned → approved` (edge E27, role `dev_passthrough`, key
 * `evt:<scannedEventId>:approved`, expected round = the event's `lifecycleRound`) through
 * @email-gateway/message-lifecycle, then writes the approval outbox row(s) with that
 * `lifecycleRound` and one `email_events` row `delivery.approved` per approval
 * (`details.source = dev_passthrough`). The verdict is logged, never acted upon.
 *
 * Never approved:
 * - `outcome = scan_failed` (a required engine timed out or failed): ledger row only,
 *   `delivery_approvals_skipped_total{reason="scan_failed"}`; the message waits for policy's
 *   fail-safe (5.2) or its deadline;
 * - a message that is not `scanned` in that round (another stage or an operator moved it, a
 *   rescan superseded the round) or that does not exist for the envelope's organization
 *   (`delivery_approvals_skipped_total{reason="lifecycle_<result>"}`);
 * - `parse_failed` messages: they never produce `scanned.v1` (they stay `persisted`).
 *
 * The message and its EML key come from the writer row of the envelope's organization, never
 * from the event payload alone.
 */
export class DevPassThroughApprover {
  private readonly logger: Logger;

  constructor(
    private readonly feed: ApprovalFeed<MessageScannedV1>,
    private readonly prisma: PrismaClient,
    private readonly txTimeoutMs: number,
    logger: Logger,
    private readonly metrics: DeliveryMetrics,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.logger = logger.child({ component: 'dev-passthrough' });
  }

  start(): void {
    this.logger.warn(DEV_PASSTHROUGH_WARNING);
    this.feed.start(
      processOnceHandler<MessageScannedV1>(
        this.prisma,
        DEV_PASSTHROUGH_CONSUMER,
        async (event, tx) => {
          await this.approve(event, tx);
        },
        { txTimeoutMs: this.txTimeoutMs },
      ),
    );
  }

  stop(): Promise<void> {
    return this.feed.stop();
  }

  async approve(
    event: EventEnvelope<MessageScannedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<PassThroughResult> {
    const organizationId = BigInt(event.organizationId);
    const payload = event.payload;
    const messageId = BigInt(payload.messageId);
    const receivedAt = new Date(payload.receivedAt);
    const round = payload.lifecycleRound;
    const ids = {
      eventId: event.eventId,
      messageId: payload.messageId,
      scanId: payload.scanId,
      round,
    };
    if (payload.outcome === 'scan_failed') {
      // Invariant 1 of step 4.1: a failed scan is never delivered by the pass-through.
      this.metrics.approvalsSkipped.inc({ reason: 'scan_failed' });
      this.logger.info(
        { ...ids, outcome: payload.outcome, verdict: payload.verdict },
        'scan failed; the dev pass-through does not approve it (waits for policy or its deadline)',
      );
      return { approvals: [], recipients: 0 };
    }
    // E27 first, in the same transaction as the approvals: they exist iff the message is approved.
    const lifecycle = await transitionMessage(
      tx,
      {
        message: { id: messageId, receivedAt, organizationId },
        to: 'approved',
        reason: 'dev_passthrough',
        actor: { role: 'dev_passthrough', service: SOURCE_SERVICE, type: 'system' },
        transitionKey: `evt:${event.eventId}:approved`,
        causationEventId: event.eventId,
        correlationId: event.correlationId,
        expectedRound: round,
        expectedFrom: ['scanned'],
      },
      { metrics: this.metrics.lifecycle, logger: this.logger },
    );
    if (lifecycle.result === 'duplicate') {
      // Already approved by an earlier run of this event (cannot happen inside one ledger
      // transaction; kept for safety): its approvals were committed with it.
      this.logger.info(
        { ...ids, result: lifecycle.result, why: lifecycle.why, state: lifecycle.snapshot.state },
        'message already approved; nothing more to approve',
      );
      return { approvals: [], recipients: 0 };
    }
    if (lifecycle.result !== 'applied') {
      const why = lifecycle.result === 'not_found' ? null : lifecycle.why;
      const state = lifecycle.result === 'not_found' ? null : lifecycle.snapshot.state;
      this.metrics.approvalsSkipped.inc({ reason: `lifecycle_${lifecycle.result}` });
      this.logger.info(
        { ...ids, result: lifecycle.result, why, state },
        'message is not scanned in this round for the organization (lifecycle); not approved',
      );
      return { approvals: [], recipients: 0 };
    }
    const emlObjectKey = lifecycle.snapshot.emlObjectKey;
    const recipients = await tx.emailRecipient.findMany({
      where: { messageId, receivedAt, organizationId, status: 'pending' },
      orderBy: { rcptSeq: 'asc' },
      select: { id: true, rcptSeq: true },
    });
    // 0 for the first delivery (what step 2.3 always wrote); after a rescan of a message that
    // already has deliveries (e.g. expired while delivering), the next sequence, so the planner
    // never mistakes the new approval for a duplicate of the old one.
    const deliverySeq = await this.nextDeliverySeq(tx, { messageId, receivedAt, organizationId });
    const approvals: string[] = [];
    const now = this.now();
    for (let i = 0; i < recipients.length; i += MAX_APPROVAL_RECIPIENTS) {
      const chunk = recipients.slice(i, i + MAX_APPROVAL_RECIPIENTS);
      const approvalId = uuidv7(now.getTime());
      const approval = deliveryApprovedV1.parse({
        messageId: messageId.toString(),
        receivedAt: receivedAt.toISOString(),
        deliverySeq,
        lifecycleRound: round,
        source: 'dev_passthrough',
        emlS3Key: emlObjectKey,
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
          payload: approval,
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
            deliverySeq,
            lifecycleRound: round,
            recipientCount: chunk.length,
          },
        },
        select: { id: true },
      });
      approvals.push(approvalId);
    }
    if (approvals.length === 0) {
      this.logger.info(
        { ...ids, verdict: payload.verdict },
        'no pending recipients; nothing approved',
      );
    } else {
      this.logger.info(
        {
          ...ids,
          verdict: payload.verdict,
          deliverySeq,
          approvals: approvals.length,
          recipients: recipients.length,
        },
        'dev pass-through approved the scanned message (no policy)',
      );
    }
    return { approvals, recipients: recipients.length };
  }

  private async nextDeliverySeq(
    tx: Prisma.TransactionClient,
    message: { messageId: bigint; receivedAt: Date; organizationId: bigint },
  ): Promise<number> {
    const result = await tx.emailDelivery.aggregate({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
      },
      _max: { deliverySeq: true },
    });
    const max = result._max.deliverySeq;
    return max === null || max === undefined ? 0 : max + 1;
  }
}
