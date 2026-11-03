import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { DeliveryStatus, MessageDirection, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { clampTake } from '../../tenant-data/page';
import type { DeliveryCursor } from '../domain/delivery-cursor';

const messageSelect = {
  id: true,
  receivedAt: true,
  direction: true,
  status: true,
} satisfies Prisma.EmailMessageSelect;

export type DeliveryMessageRow = Prisma.EmailMessageGetPayload<{ select: typeof messageSelect }> & {
  publicId: string;
};

const deliverySelect = {
  id: true,
  receivedAt: true,
  messageId: true,
  recipientId: true,
  deliverySeq: true,
  direction: true,
  status: true,
  attemptCount: true,
  lastAttemptAt: true,
  deliveredAt: true,
  remoteHost: true,
  finalSmtpCode: true,
  enhancedStatus: true,
  finalSmtpResponse: true,
  lastErrorClass: true,
  failureReason: true,
  dsnQueueId: true,
  statusChangedAt: true,
} satisfies Prisma.EmailDeliverySelect;

export type DeliveryRow = Prisma.EmailDeliveryGetPayload<{ select: typeof deliverySelect }>;

const recipientSelect = {
  id: true,
  receivedAt: true,
  rcptSeq: true,
  address: true,
  direction: true,
} satisfies Prisma.EmailRecipientSelect;

export type RecipientRow = Prisma.EmailRecipientGetPayload<{ select: typeof recipientSelect }>;

const eventSelect = {
  id: true,
  deliveryId: true,
  source: true,
  fromStatus: true,
  toStatus: true,
  applied: true,
  occurredAt: true,
  queueId: true,
  smtpCode: true,
  enhancedStatus: true,
  remoteHost: true,
  errorClass: true,
  detail: true,
} satisfies Prisma.DeliveryStatusEventSelect;

export type DeliveryEventRow = Prisma.DeliveryStatusEventGetPayload<{
  select: typeof eventSelect;
}>;

/** Per-message reads are bounded: a message has at most 1000 recipients × a few releases. */
const MAX_DELIVERIES_PER_MESSAGE = 5000;

export interface DeliveryListFilter {
  from: Date;
  to: Date;
  status?: DeliveryStatus;
  direction?: MessageDirection;
}

/**
 * Read-only, tenant-scoped access to per-recipient delivery state (step 2.3 R13) on the
 * replica (ADR-0014: a few seconds of lag are acceptable for status pages). Every query is
 * filtered by the scope's organization; a message is found through its registry public id and
 * both the registry row and the partitioned message row must belong to the organization.
 * Partitioned tables are always read with their `received_at` (pruning).
 */
@Injectable()
export class DeliveriesRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** Registry lookup, then one partition by `(id, received_at)` and the organization. */
  async findMessage(scope: TenantScope, publicId: string): Promise<DeliveryMessageRow | null> {
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

  /** The message's deliveries (`(message_id, received_at)` index). */
  deliveriesOf(scope: TenantScope, message: DeliveryMessageRow): Promise<DeliveryRow[]> {
    return this.db.emailDelivery.findMany({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      select: deliverySelect,
      orderBy: [{ deliverySeq: 'asc' }, { id: 'asc' }],
      take: MAX_DELIVERIES_PER_MESSAGE,
    });
  }

  /** The message's recipients (`(message_id, rcpt_seq, received_at)` unique key). */
  recipientsOf(
    scope: TenantScope,
    message: DeliveryMessageRow,
    rcptSeq?: number,
  ): Promise<RecipientRow[]> {
    return this.db.emailRecipient.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(rcptSeq !== undefined && { rcptSeq }),
      }),
      select: recipientSelect,
      orderBy: { rcptSeq: 'asc' },
    });
  }

  /** The message's audit trail, oldest first, after `afterId` (`(message_id, received_at)`). */
  eventsOf(
    scope: TenantScope,
    message: DeliveryMessageRow,
    page: { take: number; afterId?: bigint; deliveryIds?: bigint[] },
  ): Promise<DeliveryEventRow[]> {
    return this.db.deliveryStatusEvent.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(page.afterId !== undefined && { id: { gt: page.afterId } }),
        ...(page.deliveryIds !== undefined && { deliveryId: { in: page.deliveryIds } }),
      }),
      select: eventSelect,
      orderBy: { id: 'asc' },
      take: clampTake(page.take),
    });
  }

  /**
   * Deliveries received in `[from, to)`, newest first, keyset-paginated on `(received_at, id)`
   * over the `(organization_id, received_at, id)` index.
   */
  list(
    scope: TenantScope,
    filter: DeliveryListFilter,
    page: { take: number; after?: DeliveryCursor },
  ): Promise<DeliveryRow[]> {
    const after = page.after;
    return this.db.emailDelivery.findMany({
      where: tenantWhere(scope, {
        receivedAt: { gte: filter.from, lt: filter.to },
        ...(filter.status !== undefined && { status: filter.status }),
        ...(filter.direction !== undefined && { direction: filter.direction }),
        ...(after && {
          OR: [
            { receivedAt: { lt: after.receivedAt } },
            { receivedAt: after.receivedAt, id: { lt: after.id } },
          ],
        }),
      }),
      select: deliverySelect,
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
      take: clampTake(page.take),
    });
  }

  /** Recipients by `(id, received_at)` within the range (partition pruning). */
  recipientsByIds(
    scope: TenantScope,
    ids: readonly bigint[],
    range: { from: Date; to: Date },
  ): Promise<RecipientRow[]> {
    if (ids.length === 0) return Promise.resolve([]);
    return this.db.emailRecipient.findMany({
      where: tenantWhere(scope, {
        id: { in: [...new Set(ids)] },
        receivedAt: { gte: range.from, lt: range.to },
      }),
      select: recipientSelect,
    });
  }

  /** Registry public ids of messages (only the organization's). */
  async messagePublicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await this.db.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((row) => [row.id, row.publicId]));
  }
}
