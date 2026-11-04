import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma, RecipientStatus } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { clampTake } from '../../tenant-data/page';

const messageSelect = {
  id: true,
  receivedAt: true,
  direction: true,
  status: true,
  statusReason: true,
  version: true,
  lifecycleRound: true,
  statusChangedAt: true,
} satisfies Prisma.EmailMessageSelect;

export type LifecycleMessageRow = Prisma.EmailMessageGetPayload<{
  select: typeof messageSelect;
}> & { publicId: string };

const historySelect = {
  id: true,
  version: true,
  fromStatus: true,
  toStatus: true,
  reasonCode: true,
  lifecycleRound: true,
  actorRole: true,
  actorType: true,
  actorService: true,
  actorId: true,
  eventId: true,
  correlationId: true,
  occurredAt: true,
  changedAt: true,
} satisfies Prisma.EmailMessageStatusHistorySelect;

export type LifecycleHistoryRow = Prisma.EmailMessageStatusHistoryGetPayload<{
  select: typeof historySelect;
}>;

export interface ParseRow {
  status: string;
  completedAt: Date | null;
}

/**
 * Read-only, tenant-scoped lifecycle reads (step 3.3 L12) on the replica (`PrismaReadService`,
 * which falls back to the writer above the lag threshold; ADR-0014). A message is found through
 * its registry public id, and both the registry row and the partitioned rows are matched on the
 * organization; partitioned tables are always read with their `received_at` (pruning).
 */
@Injectable()
export class MessageLifecycleReadRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  async findMessage(scope: TenantScope, publicId: string): Promise<LifecycleMessageRow | null> {
    const identity = await this.db.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true },
    });
    if (!identity) return null;
    const message = await this.db.emailMessage.findFirst({
      where: tenantWhere(scope, { id: identity.id, receivedAt: identity.receivedAt }),
      select: messageSelect,
    });
    return message ? { ...message, publicId: identity.publicId } : null;
  }

  /** The step 3.1 parse record (`(message_id, received_at)` unique key). */
  parseOf(scope: TenantScope, message: LifecycleMessageRow): Promise<ParseRow | null> {
    return this.db.emailMessageParse.findFirst({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      select: { status: true, completedAt: true },
    });
  }

  /** Recipient counts by `email_recipients.status`. */
  async recipientCounts(
    scope: TenantScope,
    message: LifecycleMessageRow,
  ): Promise<Map<RecipientStatus, number>> {
    const rows = await this.db.emailRecipient.groupBy({
      by: ['status'],
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      _count: { _all: true },
    });
    return new Map(rows.map((row) => [row.status, row._count._all]));
  }

  /** Highest `delivery_seq` of the message's deliveries, or null before planning. */
  async maxDeliverySeq(scope: TenantScope, message: LifecycleMessageRow): Promise<number | null> {
    const result = await this.db.emailDelivery.aggregate({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      _max: { deliverySeq: true },
    });
    return result._max.deliverySeq ?? null;
  }

  /** History rows by version (oldest first) after `afterVersion`, `(message_id, received_at)`. */
  history(
    scope: TenantScope,
    message: LifecycleMessageRow,
    page: { take: number; afterVersion?: number },
  ): Promise<LifecycleHistoryRow[]> {
    return this.db.emailMessageStatusHistory.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(page.afterVersion !== undefined && { version: { gt: page.afterVersion } }),
      }),
      select: historySelect,
      orderBy: [{ version: 'asc' }, { id: 'asc' }],
      take: clampTake(page.take),
    });
  }
}
