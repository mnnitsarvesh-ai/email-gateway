import { Injectable, NotFoundException } from '@nestjs/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { decodeCursor, encodeCursor, type Page } from '../../../http/pagination';
import {
  decodeDeliveryCursor,
  deliveryRange,
  encodeDeliveryCursor,
} from '../domain/delivery-cursor';
import type {
  DeliveryEventsQuery,
  DeliveryEventView,
  DeliveryListItem,
  DeliveryView,
  ListDeliveriesQuery,
  MessageDeliveriesView,
} from '../dto/deliveries.schemas';
import {
  DeliveriesRepository,
  type DeliveryMessageRow,
  type DeliveryRow,
  type RecipientRow,
} from '../repositories/deliveries.repository';

export const MESSAGE_NOT_FOUND = 'Message not found';

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

export function toDeliveryView(
  row: DeliveryRow,
  recipient: RecipientRow | undefined,
): DeliveryView {
  return {
    rcptSeq: recipient?.rcptSeq ?? 0,
    deliverySeq: row.deliverySeq,
    recipient: recipient?.address ?? '',
    direction: row.direction ?? recipient?.direction ?? null,
    status: row.status,
    attemptCount: row.attemptCount,
    lastAttemptAt: iso(row.lastAttemptAt),
    deliveredAt: iso(row.deliveredAt),
    remoteHost: row.remoteHost,
    finalSmtpCode: row.finalSmtpCode,
    enhancedStatus: row.enhancedStatus,
    finalSmtpResponse: row.finalSmtpResponse,
    lastErrorClass: row.lastErrorClass,
    failureReason: row.failureReason,
    dsnGenerated: row.dsnQueueId !== null,
    statusChangedAt: iso(row.statusChangedAt),
  };
}

/**
 * Per-recipient delivery status and its audit trail (step 2.3 R13), read from the replica.
 * Tenant from the scope only: another organization's message is `404`. Responses carry public
 * ids and sequence numbers, never internal ids.
 */
@Injectable()
export class DeliveriesService {
  constructor(private readonly deliveries: DeliveriesRepository) {}

  /** `GET /messages/{messageId}/deliveries`: every delivery, by rcptSeq then deliverySeq. */
  async forMessage(scope: TenantScope, messageId: string): Promise<MessageDeliveriesView> {
    const message = await this.message(scope, messageId);
    const [rows, recipients] = await Promise.all([
      this.deliveries.deliveriesOf(scope, message),
      this.deliveries.recipientsOf(scope, message),
    ]);
    const byId = new Map(recipients.map((recipient) => [recipient.id, recipient]));
    // A delivery whose recipient row is not the message's is never exposed.
    const views = rows
      .filter((row) => byId.has(row.recipientId))
      .map((row) => toDeliveryView(row, byId.get(row.recipientId)))
      .sort((a, b) => a.rcptSeq - b.rcptSeq || a.deliverySeq - b.deliverySeq);
    return {
      message: {
        id: message.publicId,
        direction: message.direction,
        status: message.status,
        statusReason: message.statusReason,
        receivedAt: message.receivedAt.toISOString(),
      },
      deliveries: views,
    };
  }

  /**
   * `GET /messages/{messageId}/deliveries/events`: the append-only audit trail of the
   * message's deliveries (`delivery_status_events`), oldest first, optionally of one recipient.
   */
  async events(
    scope: TenantScope,
    messageId: string,
    query: DeliveryEventsQuery,
  ): Promise<Page<DeliveryEventView>> {
    const afterId = query.cursor === undefined ? undefined : decodeCursor(query.cursor);
    const message = await this.message(scope, messageId);
    const [rows, recipients] = await Promise.all([
      this.deliveries.deliveriesOf(scope, message),
      this.deliveries.recipientsOf(scope, message, query.rcptSeq),
    ]);
    const recipientById = new Map(recipients.map((recipient) => [recipient.id, recipient]));
    const deliveries = new Map(
      rows
        .filter((row) => recipientById.has(row.recipientId))
        .map((row) => [row.id, { row, recipient: recipientById.get(row.recipientId)! }]),
    );
    if (query.rcptSeq !== undefined && deliveries.size === 0) {
      return { data: [], nextCursor: null };
    }
    const events = await this.deliveries.eventsOf(scope, message, {
      take: query.limit + 1,
      ...(afterId !== undefined && { afterId }),
      ...(query.rcptSeq !== undefined && { deliveryIds: [...deliveries.keys()] }),
    });
    const page = events.slice(0, query.limit);
    const last = page.at(-1);
    return {
      data: page.flatMap((event) => {
        const delivery = deliveries.get(event.deliveryId);
        if (!delivery) return [];
        return [
          {
            rcptSeq: delivery.recipient.rcptSeq,
            deliverySeq: delivery.row.deliverySeq,
            source: event.source,
            fromStatus: event.fromStatus,
            toStatus: event.toStatus,
            applied: event.applied,
            occurredAt: event.occurredAt.toISOString(),
            queueId: event.queueId,
            smtpCode: event.smtpCode,
            enhancedStatus: event.enhancedStatus,
            remoteHost: event.remoteHost,
            errorClass: event.errorClass,
            detail: event.detail,
          },
        ];
      }),
      nextCursor: events.length > query.limit && last ? encodeCursor(last.id) : null,
    };
  }

  /**
   * `GET /deliveries`: the organization's deliveries received in `[from, to)` (default the
   * last 24 h, at most 31 days), newest first, keyset-paginated on `(received_at, id)`.
   */
  async list(scope: TenantScope, query: ListDeliveriesQuery): Promise<Page<DeliveryListItem>> {
    const after = query.cursor === undefined ? undefined : decodeDeliveryCursor(query.cursor);
    const range = deliveryRange(query);
    const rows = await this.deliveries.list(
      scope,
      {
        ...range,
        ...(query.status !== undefined && { status: query.status }),
        ...(query.direction !== undefined && { direction: query.direction }),
      },
      { take: query.limit + 1, ...(after && { after }) },
    );
    const page = rows.slice(0, query.limit);
    const [recipients, publicIds] = await Promise.all([
      this.deliveries.recipientsByIds(
        scope,
        page.map((row) => row.recipientId),
        range,
      ),
      this.deliveries.messagePublicIds(
        scope,
        page.map((row) => row.messageId),
      ),
    ]);
    const recipientById = new Map(recipients.map((recipient) => [recipient.id, recipient]));
    const last = page.at(-1);
    return {
      // A delivery without its registry row or recipient of this organization is never exposed.
      data: page.flatMap((row) => {
        const recipient = recipientById.get(row.recipientId);
        const publicId = publicIds.get(row.messageId);
        if (!recipient || !publicId) return [];
        return [
          {
            messageId: publicId,
            rcptSeq: recipient.rcptSeq,
            recipient: recipient.address,
            direction: row.direction ?? recipient.direction ?? null,
            status: row.status,
            attemptCount: row.attemptCount,
            lastErrorClass: row.lastErrorClass,
            statusChangedAt: iso(row.statusChangedAt),
          },
        ];
      }),
      nextCursor:
        rows.length > query.limit && last
          ? encodeDeliveryCursor({ receivedAt: last.receivedAt, id: last.id })
          : null,
    };
  }

  private async message(scope: TenantScope, publicId: string): Promise<DeliveryMessageRow> {
    const message = await this.deliveries.findMessage(scope, publicId);
    if (!message) throw new NotFoundException(MESSAGE_NOT_FOUND);
    return message;
  }
}
