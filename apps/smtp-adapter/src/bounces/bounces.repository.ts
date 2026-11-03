import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';

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
}

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
