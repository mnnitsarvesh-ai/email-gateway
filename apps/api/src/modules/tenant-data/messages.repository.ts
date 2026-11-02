import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { clampTake } from './page';

const messageSelect = {
  id: true,
  receivedAt: true,
  organizationId: true,
  domainId: true,
  direction: true,
  status: true,
  statusChangedAt: true,
  internetMessageId: true,
  envelopeFrom: true,
  headerFrom: true,
  subject: true,
  sizeBytes: true,
  recipientCount: true,
  attachmentCount: true,
  emlObjectKey: true,
  finalVerdict: true,
  finalAction: true,
  riskScore: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.EmailMessageSelect;

type MessageRow = Prisma.EmailMessageGetPayload<{ select: typeof messageSelect }>;

/** A message with its external id (`message_identities.public_id`). */
export type MessageRecord = MessageRow & { publicId: string };

/** Keyset position of the last row of the previous page. */
export interface MessageCursor {
  receivedAt: Date;
  id: bigint;
}

export interface MessagePageWindow {
  take: number;
  after?: MessageCursor;
}

/**
 * Read-only, tenant-scoped access to message metadata (D9, §10; query shapes Q1/Q2 of
 * docs/database/query-examples.md). A message is addressed by its registry public id; the
 * registry row and the partitioned `email_messages` row are both matched on the organization,
 * so another tenant's message is "not found". Message bodies live in S3 (`emlObjectKey`).
 */
@Injectable()
export class MessagesRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** Q2: registry lookup, then one partition by `(id, received_at)` and the organization. */
  async findByPublicId(scope: TenantScope, publicId: string): Promise<MessageRecord | null> {
    const identity = await this.prisma.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true },
    });
    if (!identity) return null;
    const message = await this.prisma.emailMessage.findFirst({
      where: tenantWhere(scope, { id: identity.id, receivedAt: identity.receivedAt }),
      select: messageSelect,
    });
    return message ? { ...message, publicId: identity.publicId } : null;
  }

  /**
   * Q1: messages received in `[from, to)`, newest first, keyset-paginated on
   * `(received_at, id)` over the `(organization_id, received_at, id)` index (reader).
   */
  async listRecent(
    scope: TenantScope,
    range: { from: Date; to: Date },
    page: MessagePageWindow,
  ): Promise<MessageRecord[]> {
    const after = page.after;
    const rows = await this.reader.client.emailMessage.findMany({
      where: tenantWhere(scope, {
        receivedAt: { gte: range.from, lt: range.to },
        ...(after && {
          OR: [
            { receivedAt: { lt: after.receivedAt } },
            { receivedAt: after.receivedAt, id: { lt: after.id } },
          ],
        }),
      }),
      select: messageSelect,
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
      take: clampTake(page.take),
    });
    if (rows.length === 0) return [];
    const identities = await this.reader.client.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: rows.map((r) => r.id) } }),
      select: { id: true, publicId: true },
    });
    const publicIds = new Map(identities.map((i) => [i.id, i.publicId]));
    // A message without a registry row of this organization is never exposed.
    return rows.flatMap((row) => {
      const publicId = publicIds.get(row.id);
      return publicId ? [{ ...row, publicId }] : [];
    });
  }
}
