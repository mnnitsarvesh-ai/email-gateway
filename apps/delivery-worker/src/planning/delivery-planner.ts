import { isDeepStrictEqual } from 'node:util';
import { NonRetryableError, uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  type DeliveryApprovedV1,
  deliveryApprovedV1,
  type EventEnvelope,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  type DeliverySignal,
  loadActiveSuppressions,
  loadDomainViews,
  planRecipientRoutes,
  planSignalKey,
  recipientDomain,
  recordDeliverySignal,
  reinjectionIdempotencyKey,
  type RecipientDecision,
} from '@email-gateway/mail-routing';
import { lockLifecycle, transitionMessage } from '@email-gateway/message-lifecycle';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import { retryDelayMs } from '../shared/backoff';

export const SOURCE_SERVICE = 'delivery-worker';

/**
 * Clock skew allowed between the message's `received_at` and its approval's outbox `created_at`
 * (both written by gateway services; the bound only prunes `message_outbox` partitions).
 */
export const PROVENANCE_SKEW_MS = 5 * 60_000;

/** Dead-letter reasons of an approval the gateway never issued (`NonRetryableError` codes). */
export const APPROVAL_NOT_ISSUED = 'approval_not_issued';
export const APPROVAL_MISMATCH = 'approval_mismatch';

/**
 * Provenance of an approval (step 3.2 review round 1): since approvals arrive from the broker,
 * the broker is a trust boundary. An approval is planned only when the gateway wrote it: a
 * `message_outbox` row with the same `event_id`, `event_type` and `organization_id` (index
 * `event_id`, partitions pruned by `created_at ≥ received_at − skew`) whose payload equals the
 * delivered one. A replayed or re-driven approval keeps its event id and payload, so it passes;
 * a forged one (any broker user that can publish to `email.delivery`) or an altered copy of a
 * real one is a fatal `NonRetryableError` (dead-lettered, never planned). Approvals older than
 * the outbox retention (7 days) can no longer be proven and are dead-lettered the same way.
 */
export async function assertApprovalIssued(
  tx: Prisma.TransactionClient,
  event: EventEnvelope<DeliveryApprovedV1>,
  organizationId: bigint,
  receivedAt: Date,
): Promise<void> {
  const row = await tx.messageOutbox.findFirst({
    where: {
      eventId: event.eventId,
      eventType: event.eventType,
      organizationId,
      createdAt: { gte: new Date(receivedAt.getTime() - PROVENANCE_SKEW_MS) },
    },
    select: { payload: true },
  });
  if (!row) throw new NonRetryableError(APPROVAL_NOT_ISSUED);
  const issued = deliveryApprovedV1.safeParse(row.payload);
  const delivered = deliveryApprovedV1.safeParse(event.payload);
  if (!issued.success || !delivered.success || !isDeepStrictEqual(issued.data, delivered.data)) {
    throw new NonRetryableError(APPROVAL_MISMATCH);
  }
}

export interface PlannerConfig {
  DELIVERY_BATCH_MAX_RECIPIENTS: number;
  DELIVERY_REINJECT_RETRY_BASE_SECONDS: number;
  DELIVERY_REINJECT_RETRY_MAX_SECONDS: number;
}

export interface PlanResult {
  status: 'planned' | 'duplicate' | 'rejected';
  reason?: 'eml_key_prefix' | 'message_not_found' | 'no_known_recipients' | 'lifecycle_state';
  reinjections: number;
  deliveries: number;
  refused: number;
  held: number;
  /** Approved recipient ids that are unknown or belong to another message/organization. */
  unknownRecipients: number;
  /** Recipients that already have a delivery for this delivery_seq (duplicate approval). */
  alreadyPlanned: number;
}

export interface DeliveryPlannerDeps {
  logger: Logger;
  metrics: DeliveryMetrics;
  config: PlannerConfig;
  /** Recorder context timeout (only used if the recorder had to open its own transaction). */
  recorderTimeoutMs: number;
  now?: () => Date;
}

const empty = (status: PlanResult['status'], reason?: PlanResult['reason']): PlanResult => ({
  status,
  ...(reason ? { reason } : {}),
  reinjections: 0,
  deliveries: 0,
  refused: 0,
  held: 0,
  unknownRecipients: 0,
  alreadyPlanned: 0,
});

/**
 * Planning and the per-recipient split (step 2.3 R7), consumer `delivery-worker.planner` of
 * `mail.delivery.approved.v1`. Runs inside the consumer's `processOnce` transaction, so the
 * ledger row, the delivery rows, the reinjection rows and the planner signals commit together.
 *
 * Trust: the approval must have been issued by the gateway (`assertApprovalIssued`: its outbox
 * row exists with the same payload, else a fatal dead letter); the message and the recipients
 * are loaded from the writer by `(id, received_at, organization_id)` with the envelope's
 * organization; recipient ids of another message or organization are logged and skipped, and
 * the EML key must be under `org/<organizationId>/`. Nothing in the payload is trusted alone.
 *
 * Idempotency: `(recipient_id, delivery_seq)` is unique per delivery and
 * `(message_id, idempotency_key)` per reinjection; a second approval with the same
 * `deliverySeq` finds the existing deliveries (after taking the message lock, which serializes
 * concurrent planners of one message) and plans nothing for those recipients.
 *
 * Lifecycle (step 3.3 L8.4, edge E20), under the message lock and with the approval's round
 * (`lifecycleRound`, absent = 0): an `approved` message of that round moves to
 * `delivery_pending` (key `evt:<approvalEventId>:delivery_pending`) and is planned; a
 * `delivery_pending` / `delivery_retry` message of that round (a later chunk, a duplicate) is
 * planned without a transition; anything else (another state, an older or newer round) is
 * acknowledged as `rejected/lifecycle_state` and never planned. The planner signals then derive
 * the message state through the recorder (an all-refused plan ends `rejected/delivery_failed`).
 * Every rejection counts `delivery_approvals_rejected_total{reason}`.
 */
export class DeliveryPlanner {
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly deps: DeliveryPlannerDeps) {
    this.logger = deps.logger.child({ component: 'delivery-planner' });
    this.now = deps.now ?? (() => new Date());
  }

  async plan(
    event: EventEnvelope<DeliveryApprovedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<PlanResult> {
    const result = await this.planApproval(event, tx);
    if (result.status === 'rejected' && result.reason) {
      this.deps.metrics.approvalsRejected.inc({ reason: result.reason });
    }
    return result;
  }

  private async planApproval(
    event: EventEnvelope<DeliveryApprovedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<PlanResult> {
    const payload = event.payload;
    const organizationId = BigInt(event.organizationId);
    const messageId = BigInt(payload.messageId);
    const receivedAt = new Date(payload.receivedAt);
    const deliverySeq = payload.deliverySeq;
    const ids = {
      eventId: event.eventId,
      messageId: payload.messageId,
      organizationId: event.organizationId,
      deliverySeq,
    };

    if (!payload.emlS3Key.startsWith(`org/${organizationId.toString()}/`)) {
      this.logger.error(ids, 'approval EML key is outside the organization prefix; rejected');
      return empty('rejected', 'eml_key_prefix');
    }
    // The message first: an approval of a message that does not exist (any more) has nothing to
    // plan, whoever sent it, and is acknowledged as rejected. In one transaction snapshot, a
    // message that is visible also has its approval's outbox row visible (both are retained far
    // longer than an approval waits), so the order adds no window for forged approvals.
    const message = await tx.emailMessage.findFirst({
      where: { id: messageId, receivedAt, organizationId },
      select: { id: true, direction: true },
    });
    if (!message) {
      this.logger.warn(ids, 'approved message not found for the organization; rejected');
      return empty('rejected', 'message_not_found');
    }
    try {
      await assertApprovalIssued(tx, event, organizationId, receivedAt);
    } catch (error) {
      if (error instanceof NonRetryableError) {
        this.logger.error(
          { ...ids, reason: error.code },
          'approval was not issued by the gateway (no matching outbox row or payload); dead-lettered',
        );
      }
      throw error;
    }

    const wanted = payload.recipients.map((r) => BigInt(r.recipientId));
    const recipients = await tx.emailRecipient.findMany({
      where: { id: { in: wanted }, receivedAt, messageId, organizationId },
      select: { id: true, rcptSeq: true, address: true, direction: true },
      orderBy: { rcptSeq: 'asc' },
    });
    const unknownRecipients = wanted.length - recipients.length;
    if (unknownRecipients > 0) {
      this.logger.warn(
        { ...ids, unknownRecipients },
        'approved recipient ids unknown for this message and organization; skipped',
      );
    }
    const seqById = new Map(payload.recipients.map((r) => [r.recipientId, r.rcptSeq]));
    if (recipients.some((r) => seqById.get(r.id.toString()) !== r.rcptSeq)) {
      this.logger.warn(
        ids,
        'approval rcptSeq differs from the stored recipient; stored value used',
      );
    }
    if (recipients.length === 0) {
      const result = empty('rejected', 'no_known_recipients');
      result.unknownRecipients = unknownRecipients;
      return result;
    }

    const now = this.now();
    // Lock the message first (the recorder's lock order); serializes planners of one message.
    const ref = { id: messageId, receivedAt, organizationId };
    const snapshot = await lockLifecycle(tx, ref);
    const round = payload.lifecycleRound ?? 0;
    const lifecycleIds = {
      ...ids,
      state: snapshot?.state ?? null,
      round: snapshot?.round ?? null,
      approvalRound: round,
    };
    if (snapshot?.state === 'approved' && snapshot.round === round) {
      const outcome = await transitionMessage(
        tx,
        {
          message: ref,
          to: 'delivery_pending',
          reason: 'delivery_planned',
          actor: { role: 'delivery', service: SOURCE_SERVICE, type: 'system' },
          transitionKey: `evt:${event.eventId}:delivery_pending`,
          causationEventId: event.eventId,
          correlationId: event.correlationId,
          occurredAt: now,
          expectedRound: round,
          expectedFrom: ['approved'],
        },
        { metrics: this.deps.metrics.lifecycle, logger: this.logger, now: () => now },
      );
      // Under the lock just taken the only outcome is `applied`; anything else is not planned.
      if (outcome.result !== 'applied') {
        this.logger.warn(
          { ...lifecycleIds, result: outcome.result },
          'approval not planned: the lifecycle refused delivery_pending',
        );
        return empty('rejected', 'lifecycle_state');
      }
    } else if (!(
      (snapshot?.state === 'delivery_pending' || snapshot?.state === 'delivery_retry') &&
      snapshot.round === round
    )) {
      this.logger.info(
        lifecycleIds,
        'approval not planned: the message is not approved (or not delivering) in this round',
      );
      return empty('rejected', 'lifecycle_state');
    }

    const existing = await tx.emailDelivery.findMany({
      where: { recipientId: { in: recipients.map((r) => r.id) }, receivedAt, deliverySeq },
      select: { recipientId: true },
    });
    const planned = new Set(existing.map((row) => row.recipientId));
    const candidates = recipients.filter((r) => !planned.has(r.id));
    if (candidates.length === 0) {
      this.logger.info(ids, 'duplicate approval: every recipient is already planned');
      const result = empty('duplicate');
      result.unknownRecipients = unknownRecipients;
      result.alreadyPlanned = planned.size;
      return result;
    }

    const domains = await loadDomainViews(
      tx,
      candidates
        .map((r) => recipientDomain(r.address))
        .filter((domain): domain is string => domain !== null),
    );
    const suppressed = await loadActiveSuppressions(
      tx,
      organizationId,
      candidates.map((r) => r.address),
      now,
    );
    const plan = planRecipientRoutes({
      listenerDirection: message.direction === 'inbound' ? 'inbound' : 'outbound',
      messageOrganizationId: organizationId,
      recipients: candidates.map((r) => ({
        recipientId: r.id,
        rcptSeq: r.rcptSeq,
        address: r.address,
        storedDirection: r.direction,
      })),
      domains,
      suppressedAddresses: suppressed,
      maxRecipientsPerGroup: this.deps.config.DELIVERY_BATCH_MAX_RECIPIENTS,
    });

    // One delivery_reinjections row per group.
    const reinjectionOf = new Map<bigint, bigint>();
    let held = 0;
    for (const group of plan.groups) {
      const idempotencyKey = reinjectionIdempotencyKey({
        messageId,
        deliverySeq,
        listener: group.listener,
        recipientSetSha256: group.recipientSetSha256,
      });
      const known = await tx.deliveryReinjection.findUnique({
        where: { messageId_idempotencyKey_receivedAt: { messageId, idempotencyKey, receivedAt } },
        select: { id: true },
      });
      let reinjectionId: bigint;
      if (known) {
        this.logger.warn(ids, 'reinjection key already planned; reusing the existing group');
        reinjectionId = known.id;
      } else {
        const hold = group.hold !== null;
        if (hold) held += group.recipientIds.length;
        const row = await tx.deliveryReinjection.create({
          data: {
            receivedAt,
            publicId: uuidv7(now.getTime()),
            messageId,
            organizationId,
            deliverySeq,
            listener: group.listener,
            direction: group.direction,
            destinationKey: group.destinationKey,
            emlObjectKey: payload.emlS3Key,
            recipientCount: group.recipientIds.length,
            recipientSetSha256: group.recipientSetSha256,
            idempotencyKey,
            approvalEventId: event.eventId,
            status: 'pending',
            nextAttemptAt: hold
              ? new Date(
                  now.getTime() +
                    retryDelayMs(1, {
                      baseSeconds: this.deps.config.DELIVERY_REINJECT_RETRY_BASE_SECONDS,
                      maxSeconds: this.deps.config.DELIVERY_REINJECT_RETRY_MAX_SECONDS,
                    }),
                )
              : now,
            lastErrorClass: hold ? 'gateway_hold' : null,
          },
          select: { id: true },
        });
        reinjectionId = row.id;
      }
      for (const recipientId of group.recipientIds) reinjectionOf.set(recipientId, reinjectionId);
    }

    // Every delivery row first, then the signals: each applied signal derives the message state
    // from all recipients (step 3.3 L9), so every delivery of this delivery_seq must exist.
    await tx.emailDelivery.createMany({
      data: plan.decisions.map((decision) => ({
        receivedAt,
        messageId,
        recipientId: decision.recipientId,
        organizationId,
        deliverySeq,
        status: 'pending' as const,
        direction: decision.direction,
        destinationKey: decision.kind === 'route' ? decision.destinationKey : null,
        reinjectionId:
          decision.kind === 'route' ? (reinjectionOf.get(decision.recipientId) ?? null) : null,
      })),
    });
    const rows = await tx.emailDelivery.findMany({
      where: {
        recipientId: { in: plan.decisions.map((d) => d.recipientId) },
        receivedAt,
        deliverySeq,
      },
      select: { id: true, recipientId: true },
    });
    const deliveryOf = new Map(rows.map((row) => [row.recipientId, row.id]));

    let refused = 0;
    for (const decision of plan.decisions) {
      const deliveryId = deliveryOf.get(decision.recipientId);
      if (deliveryId === undefined) continue;
      if (decision.kind === 'refusal') refused += 1;
      const signal = this.signalFor(decision, deliveryId, receivedAt, event.eventId, now);
      const result = await recordDeliverySignal(tx, signal, {
        sourceService: SOURCE_SERVICE,
        timeoutMs: this.deps.recorderTimeoutMs,
        eventId: event.eventId,
        logger: this.logger,
        lifecycleMetrics: this.deps.metrics.lifecycle,
      });
      this.deps.metrics.signal('planner', result.result, {
        direction: decision.direction,
        status: result.status,
      });
    }

    this.deps.metrics.approvals.inc({ source: payload.source });
    this.logger.info(
      {
        ...ids,
        source: payload.source,
        reinjections: plan.groups.length,
        deliveries: plan.decisions.length,
        refused,
        held,
      },
      'approval planned',
    );
    return {
      status: 'planned',
      reinjections: plan.groups.length,
      deliveries: plan.decisions.length,
      refused,
      held,
      unknownRecipients,
      alreadyPlanned: planned.size,
    };
  }

  private signalFor(
    decision: RecipientDecision,
    deliveryId: bigint,
    receivedAt: Date,
    approvalEventId: string,
    occurredAt: Date,
  ): DeliverySignal {
    const base = {
      match: { deliveryId, receivedAt },
      occurredAt,
      source: 'planner' as const,
      signalKey: planSignalKey({ approvalEventId, recipientId: decision.recipientId }),
    };
    if (decision.kind === 'refusal') {
      return {
        ...base,
        status: decision.status,
        failureReason: decision.reason,
        detail: REFUSAL_DETAIL[decision.reason],
      };
    }
    if (decision.hold !== null) {
      return {
        ...base,
        status: 'deferred',
        errorClass: 'gateway_hold',
        detail: 'recipient domain or its organization is suspended; held by the gateway',
      };
    }
    return { ...base, status: 'pending' };
  }
}

const REFUSAL_DETAIL: Readonly<Record<string, string>> = {
  direction_changed: 'routed direction changed since ingestion; not delivered',
  recipient_domain_inactive: 'recipient domain is no longer an active domain of the organization',
  suppressed: 'recipient is on the organization suppression list',
};
