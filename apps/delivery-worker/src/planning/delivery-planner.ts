import type { Prisma } from '@email-gateway/database';
import type { DeliveryApprovedV1, EventEnvelope } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  type DeliverySignal,
  loadActiveSuppressions,
  loadDomainViews,
  markMessageDeliveryQueued,
  planRecipientRoutes,
  planSignalKey,
  recipientDomain,
  recordDeliverySignal,
  reinjectionIdempotencyKey,
  type RecipientDecision,
} from '@email-gateway/mail-routing';
import type { DeliveryMetrics } from '../metrics/delivery-metrics';
import { retryDelayMs } from '../shared/backoff';
import { uuidv7 } from '../shared/uuidv7';

export const SOURCE_SERVICE = 'delivery-worker';

export interface PlannerConfig {
  DELIVERY_BATCH_MAX_RECIPIENTS: number;
  DELIVERY_REINJECT_RETRY_BASE_SECONDS: number;
  DELIVERY_REINJECT_RETRY_MAX_SECONDS: number;
}

export interface PlanResult {
  status: 'planned' | 'duplicate' | 'rejected';
  reason?: 'eml_key_prefix' | 'message_not_found' | 'no_known_recipients';
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
 * Trust: the message and the recipients are loaded from the writer by `(id, received_at,
 * organization_id)` with the envelope's organization; recipient ids of another message or
 * organization are logged and skipped, and the EML key must be under `org/<organizationId>/`.
 * Nothing in the payload is trusted alone.
 *
 * Idempotency: `(recipient_id, delivery_seq)` is unique per delivery and
 * `(message_id, idempotency_key)` per reinjection; a second approval with the same
 * `deliverySeq` finds the existing deliveries (after taking the message lock, which serializes
 * concurrent planners of one message) and plans nothing for those recipients.
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
    const message = await tx.emailMessage.findFirst({
      where: { id: messageId, receivedAt, organizationId },
      select: { id: true, direction: true },
    });
    if (!message) {
      this.logger.warn(ids, 'approved message not found for the organization; rejected');
      return empty('rejected', 'message_not_found');
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
    await markMessageDeliveryQueued(
      tx,
      { id: messageId, receivedAt },
      {
        eventId: event.eventId,
        changedAt: now,
      },
    );

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

    // Every delivery row first, then the signals: a refusal's terminal signal computes the
    // message aggregate over all deliveries of this delivery_seq.
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
