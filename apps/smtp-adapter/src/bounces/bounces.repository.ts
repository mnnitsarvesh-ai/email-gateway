import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { MessageDirection, Prisma } from '@email-gateway/database';
import { parseReinjectionToken } from '@email-gateway/mail-routing';

export interface BounceRecord {
  organizationId: bigint;
  occurredAt: Date;
  recipientAddress: string;
  bounceType: 'hard' | 'soft';
  smtpCode: number | null;
  enhancedStatus: string | null;
  diagnostic: string | null;
  reportingMta: string | null;
  dedupeKey: string;
  /** Hard-bounce suppression expiry (null: no suppression for this bounce). */
  suppressUntil: Date | null;
  /** The message of the matched reinjection (step 2.3 R9), else null. */
  messageId?: bigint | null;
  messageReceivedAt?: Date | null;
}

/** The reinjection a notice belongs to (step 2.3 R9 "Bounce notices"). */
export interface MatchedReinjection {
  id: bigint;
  receivedAt: Date;
  publicId: string;
  messageId: bigint;
  organizationId: bigint;
  direction: MessageDirection;
  /** How it was found. */
  matchedBy: 'queue_id' | 'envelope_id';
}

/** A Postfix queue id (short or long form). */
const QUEUE_ID = /^[A-Za-z0-9]{1,32}$/;

const REINJECTION_SELECT = {
  id: true,
  receivedAt: true,
  publicId: true,
  messageId: true,
  organizationId: true,
  direction: true,
} satisfies Prisma.DeliveryReinjectionSelect;

export type SuppressionResult = 'created' | 'extended' | 'kept' | 'none';

const MAX_REPORTING_MTA = 255;

/** Writer-only persistence of bounce notices (step 2.2 D13). */
@Injectable()
export class BouncesRepository {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * One writer transaction per recipient: `bounce_events` insert-if-absent on
   * `(organization_id, dedupe_key, occurred_at)` and, for suppressing hard bounces, the
   * `delivery_suppressions` upsert. `inserted` is false for a redelivered notice.
   */
  async record(
    record: BounceRecord,
    timeoutMs: number,
  ): Promise<{ inserted: boolean; suppression: SuppressionResult }> {
    return this.prisma.$transaction(
      async (tx) => {
        const existing = await tx.bounceEvent.findUnique({
          where: {
            organizationId_dedupeKey_occurredAt: {
              organizationId: record.organizationId,
              dedupeKey: record.dedupeKey,
              occurredAt: record.occurredAt,
            },
          },
          select: { id: true },
        });
        if (existing) return { inserted: false, suppression: 'none' as const };
        await tx.bounceEvent.create({
          data: {
            occurredAt: record.occurredAt,
            organizationId: record.organizationId,
            recipientAddress: record.recipientAddress,
            bounceType: record.bounceType,
            smtpCode: record.smtpCode,
            enhancedStatus: record.enhancedStatus,
            diagnostic: record.diagnostic,
            reportingMta: record.reportingMta?.slice(0, MAX_REPORTING_MTA) ?? null,
            dedupeKey: record.dedupeKey,
            messageId: record.messageId ?? null,
            messageReceivedAt: record.messageReceivedAt ?? null,
          },
          select: { id: true },
        });
        const suppression =
          record.suppressUntil === null
            ? ('none' as const)
            : await this.suppress(
                tx,
                record.organizationId,
                record.recipientAddress,
                record.suppressUntil,
              );
        return { inserted: true, suppression };
      },
      { timeout: timeoutMs, maxWait: timeoutMs },
    );
  }

  /**
   * The reinjection of a notice (writer): by `X-Postfix-Queue-ID` = `delivery_reinjections.queue_id`
   * (bound by the worker or the log tailer), then through `email_deliveries.outbound_queue_id`,
   * then by `Original-Envelope-Id` = the reinjection token (`dw1-<public id hex>`). The
   * organization of the result is the reinjection's, never derived from the notice.
   */
  async findReinjection(
    queueId: string | null,
    envelopeId: string | null,
  ): Promise<MatchedReinjection | null> {
    if (queueId !== null && QUEUE_ID.test(queueId)) {
      const byQueue = await this.prisma.deliveryReinjection.findFirst({
        where: { queueId },
        select: REINJECTION_SELECT,
        orderBy: { id: 'desc' },
      });
      if (byQueue) return { ...byQueue, matchedBy: 'queue_id' };
      const delivery = await this.prisma.emailDelivery.findFirst({
        where: { outboundQueueId: queueId, reinjectionId: { not: null } },
        select: { reinjectionId: true, receivedAt: true },
        orderBy: { id: 'desc' },
      });
      if (delivery?.reinjectionId) {
        const viaDelivery = await this.prisma.deliveryReinjection.findUnique({
          where: { id_receivedAt: { id: delivery.reinjectionId, receivedAt: delivery.receivedAt } },
          select: REINJECTION_SELECT,
        });
        if (viaDelivery) return { ...viaDelivery, matchedBy: 'queue_id' };
      }
    }
    const publicId = envelopeId === null ? null : parseReinjectionToken(envelopeId);
    if (publicId === null) return null;
    const byToken = await this.prisma.deliveryReinjection.findFirst({
      where: { publicId },
      select: REINJECTION_SELECT,
    });
    return byToken ? { ...byToken, matchedBy: 'envelope_id' } : null;
  }

  /**
   * `hard_bounce` suppression: created when absent; an existing `hard_bounce` row's expiry is
   * extended (never shortened; a permanent one stays permanent); `manual`, `complaint` and
   * `unsubscribe` rows are never shortened or replaced.
   */
  private async suppress(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    address: string,
    until: Date,
  ): Promise<SuppressionResult> {
    const existing = await tx.deliverySuppression.findUnique({
      where: { organizationId_address: { organizationId, address } },
      select: { id: true, reason: true, expiresAt: true },
    });
    if (!existing) {
      await tx.deliverySuppression.create({
        data: {
          organizationId,
          address,
          reason: 'hard_bounce',
          source: 'bounce',
          expiresAt: until,
        },
        select: { id: true },
      });
      return 'created';
    }
    if (existing.reason !== 'hard_bounce') return 'kept';
    if (existing.expiresAt === null || existing.expiresAt.getTime() >= until.getTime()) {
      return 'kept';
    }
    await tx.deliverySuppression.update({
      where: { id: existing.id },
      data: { expiresAt: until },
      select: { id: true },
    });
    return 'extended';
  }
}
