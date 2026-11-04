import { Injectable } from '@nestjs/common';
import type { ActorType, Prisma } from '@email-gateway/database';
import type { MessageRef } from '@email-gateway/message-lifecycle';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;

/** The registry row of a message (`message_identities`). */
export interface MessageIdentityRow {
  id: bigint;
  publicId: string;
  receivedAt: Date;
}

export interface ReleasableRecipient {
  id: bigint;
  rcptSeq: number;
}

export interface OutboxInsert {
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateId: string;
  correlationId: string;
  payload: Prisma.InputJsonValue;
}

export interface EmailEventInsert {
  message: MessageRef;
  eventType: string;
  occurredAt: Date;
  sourceService: string;
  eventId: string | null;
  actorType: ActorType;
  actorId: string | null;
  details: Prisma.InputJsonValue;
}

/** Recipient statuses a release delivers (L10.3). */
const RELEASABLE = ['pending', 'quarantined'] as const;

/**
 * Writer-side, tenant-scoped queries of the lifecycle operations (step 3.3 L10), always in the
 * operation's transaction (ADR-0014: decisions read the writer). Lifecycle columns and history
 * rows are written only by `@email-gateway/message-lifecycle` (LifecycleGateway); this
 * repository reads the message graph and writes the operation's own effects (outbox rows and
 * `email_events`). Partitioned tables are always addressed with their `received_at`.
 */
@Injectable()
export class MessageLifecycleRepository {
  /** Registry lookup by public id, matched on the organization. */
  findIdentity(tx: Tx, scope: TenantScope, publicId: string): Promise<MessageIdentityRow | null> {
    return tx.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true },
    });
  }

  /** True when the message history already holds this transition key (hex SHA-256). */
  async hasTransitionKey(tx: Tx, message: MessageRef, keyHash: string): Promise<boolean> {
    const row = await tx.emailMessageStatusHistory.findFirst({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        transitionKey: keyHash,
      },
      select: { id: true },
    });
    return row !== null;
  }

  /** Per-recipient quarantine entries of the message (5.3's workflow owns them). */
  quarantineEntryCount(tx: Tx, scope: TenantScope, message: MessageRef): Promise<number> {
    return tx.quarantineMessage.count({
      where: tenantWhere(scope, {
        messageId: message.id,
        messageReceivedAt: message.receivedAt,
      }),
    });
  }

  /** Recipients with status `pending` or `quarantined`, by `rcpt_seq`. */
  releasableRecipients(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
  ): Promise<ReleasableRecipient[]> {
    return tx.emailRecipient.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        status: { in: [...RELEASABLE] },
      }),
      select: { id: true, rcptSeq: true },
      orderBy: { rcptSeq: 'asc' },
    });
  }

  /**
   * Released recipients that are `quarantined` become `pending` again (L10.3): the derived
   * delivery state counts `quarantined` as settled, so a released recipient must read as not yet
   * delivered until its own delivery signal applies. `email_recipients.status` is not a lifecycle
   * column (one-door rule). Returns the number of rows changed.
   */
  async markReleasedRecipientsPending(
    tx: Tx,
    scope: TenantScope,
    message: MessageRef,
    recipientIds: readonly bigint[],
  ): Promise<number> {
    if (recipientIds.length === 0) return 0;
    const result = await tx.emailRecipient.updateMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        id: { in: [...recipientIds] },
        status: 'quarantined' as const,
      }),
      data: { status: 'pending' },
    });
    return result.count;
  }

  /** Highest `email_deliveries.delivery_seq` of the message, or null without deliveries. */
  async maxDeliverySeq(tx: Tx, scope: TenantScope, message: MessageRef): Promise<number | null> {
    const result = await tx.emailDelivery.aggregate({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      _max: { deliverySeq: true },
    });
    return result._max.deliverySeq ?? null;
  }

  /** One `message_outbox` row (`aggregate_type = 'message'`), validated by the caller. */
  async insertOutbox(tx: Tx, row: OutboxInsert): Promise<void> {
    await tx.messageOutbox.create({
      data: {
        eventId: row.eventId,
        organizationId: row.organizationId,
        eventType: row.eventType,
        aggregateType: 'message',
        aggregateId: row.aggregateId,
        correlationId: row.correlationId,
        payload: row.payload,
      },
      select: { id: true },
    });
  }

  /** One `email_events` timeline row of the message. */
  async insertEmailEvent(tx: Tx, event: EmailEventInsert): Promise<void> {
    await tx.emailEvent.create({
      data: {
        receivedAt: event.message.receivedAt,
        messageId: event.message.id,
        organizationId: event.message.organizationId,
        eventType: event.eventType,
        occurredAt: event.occurredAt,
        sourceService: event.sourceService,
        eventId: event.eventId,
        actorType: event.actorType,
        actorId: event.actorId,
        details: event.details,
      },
      select: { id: true },
    });
  }
}
