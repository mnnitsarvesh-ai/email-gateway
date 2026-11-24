import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { AiChatReportRecipientKind, Prisma } from '@email-gateway/database';
import {
  type AssistantReportEmailRequestedV1,
  assistantReportEmailRequestedV1,
  EventTypes,
} from '@email-gateway/event-contracts';
import { REPORT_DELIVERY_AGGREGATE_TYPE } from '../assistant.constants';

type Tx = Prisma.TransactionClient;

export const deliverySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  reportId: true,
  recipientAddress: true,
  recipientKind: true,
  status: true,
  errorCode: true,
  requestedAt: true,
  sentAt: true,
} satisfies Prisma.AiChatReportDeliverySelect;
export type DeliveryRow = Prisma.AiChatReportDeliveryGetPayload<{ select: typeof deliverySelect }>;

export interface DeliveryCreate {
  publicId: string;
  organizationId: bigint;
  userId: bigint;
  conversationId: bigint;
  reportId: bigint;
  confirmationId: bigint;
  /** The normalized address (content; NULL after the conversation's content purge). */
  recipientAddress: string;
  recipientSha256: string;
  recipientKind: AiChatReportRecipientKind;
  sizeBytes: number;
  correlationId: string;
  requestedAt: Date;
}

/**
 * `ai_chat_report_deliveries` (step AI-R §3, D5, D7): one row per confirmed report email, written
 * with its outbox event in the confirm transaction (unique `confirmation_id`: one confirmation,
 * at most one delivery); the notification-worker moves it to `sent` or `failed`. The UTC-day
 * counts behind the user and tenant limits read the writer inside the transaction that holds the
 * tenant's `ai_chat_settings` row lock, so concurrent confirms of one organization serialize.
 */
@Injectable()
export class ReportDeliveriesRepository {
  constructor(private readonly writer: PrismaService) {}

  /**
   * `SELECT … FROM ai_chat_settings WHERE organization_id = ? FOR UPDATE` (D5 step 13): serializes
   * the organization's confirmed sends until the transaction ends. False when the row is absent
   * (the assistant cannot be enabled without it).
   */
  async lockTenant(organizationId: bigint, tx: Tx): Promise<boolean> {
    const rows = await tx.$queryRaw<Array<{ organization_id: bigint }>>`SELECT organization_id
      FROM ai_chat_settings WHERE organization_id = ${organizationId} FOR UPDATE`;
    return rows.length === 1;
  }

  /**
   * The outbox row of `assistant.report.email_requested.v1` (§4.3): payload parsed with the
   * strict contract (ids only), `eventId` = `aggregateId` = the delivery public id.
   */
  async insertEmailRequested(
    tx: Tx,
    event: {
      organizationId: bigint;
      correlationId: string;
      payload: AssistantReportEmailRequestedV1;
    },
  ): Promise<void> {
    const payload = assistantReportEmailRequestedV1.parse(event.payload);
    await tx.messageOutbox.create({
      data: {
        eventId: payload.deliveryId,
        organizationId: event.organizationId,
        eventType: EventTypes.AssistantReportEmailRequested,
        aggregateType: REPORT_DELIVERY_AGGREGATE_TYPE,
        aggregateId: payload.deliveryId,
        correlationId: event.correlationId.slice(0, 128),
        payload,
      },
    });
  }

  async insert(data: DeliveryCreate, tx: Tx): Promise<{ id: bigint; publicId: string }> {
    return tx.aiChatReportDelivery.create({
      data: { ...data, status: 'queued' },
      select: { id: true, publicId: true },
    });
  }

  /** Deliveries of the organization since `since` (index `(organization_id, requested_at)`). */
  countTenantSince(organizationId: bigint, since: Date, tx?: Tx): Promise<number> {
    return (tx ?? this.writer).aiChatReportDelivery.count({
      where: { organizationId, requestedAt: { gte: since } },
    });
  }

  /** Deliveries of one user since `since` (index `(organization_id, user_id, requested_at)`). */
  countUserSince(organizationId: bigint, userId: bigint, since: Date, tx?: Tx): Promise<number> {
    return (tx ?? this.writer).aiChatReportDelivery.count({
      where: { organizationId, userId, requestedAt: { gte: since } },
    });
  }

  /** The deliveries of a report, newest first (§4.1 view; index `(report_id, requested_at)`). */
  listForReport(organizationId: bigint, reportId: bigint, take: number): Promise<DeliveryRow[]> {
    return this.writer.aiChatReportDelivery.findMany({
      where: { organizationId, reportId },
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
      take,
      select: deliverySelect,
    });
  }

  /**
   * D7 sweep: `queued` deliveries requested before `before` → `failed` with `code` (index
   * `(status, requested_at)`), one bounded statement.
   */
  failQueuedBefore(before: Date, code: string, batch: number): Promise<number> {
    return this.writer.$executeRaw`UPDATE ai_chat_report_deliveries
      SET status = 'failed', error_code = ${code}, updated_at = NOW(3)
      WHERE status = 'queued' AND requested_at < ${before}
      ORDER BY requested_at, id LIMIT ${batch}`;
  }
}
