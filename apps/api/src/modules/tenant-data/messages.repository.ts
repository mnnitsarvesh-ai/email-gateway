import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { assertEcho, InconsistentReadError } from '../../http/listing/echo-check';
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
  /**
   * Keyset direction (default `desc`, newest first). Step 6.1 `GET /messages?sort=receivedAt`
   * reads oldest first over the same index.
   */
  order?: 'desc' | 'asc';
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
   * Q1: messages received in `[from, to)`, newest first (or oldest first with `order: 'asc'`),
   * keyset-paginated on `(received_at, id)` over the `(organization_id, received_at, id)` index
   * (reader). Step 6.1 D5 plan 1 (the index plan of `GET /messages`) and D15: every returned row
   * must echo the organization and lie in the range, else `503 inconsistent_read`.
   */
  async listRecent(
    scope: TenantScope,
    range: { from: Date; to: Date },
    page: MessagePageWindow,
  ): Promise<MessageRecord[]> {
    return this.withPublicIds(scope, await this.listRecentRows(scope, range, page));
  }

  /** `listRecent` without the registry lookup (the rows as read, echo-checked). */
  async listRecentRows(
    scope: TenantScope,
    range: { from: Date; to: Date },
    page: MessagePageWindow,
  ): Promise<MessageRow[]> {
    const after = page.after;
    const order = page.order ?? 'desc';
    const beyond = order === 'desc' ? 'lt' : 'gt';
    const rows = await this.reader.client.emailMessage.findMany({
      where: tenantWhere(scope, {
        receivedAt: { gte: range.from, lt: range.to },
        ...(after && {
          OR: [
            { receivedAt: { [beyond]: after.receivedAt } },
            { receivedAt: after.receivedAt, id: { [beyond]: after.id } },
          ],
        }),
      }),
      select: messageSelect,
      orderBy: [{ receivedAt: order }, { id: order }],
      take: clampTake(page.take),
    });
    assertEcho('messages.listRecent', rows, { organizationId: scope.organizationId });
    const outside = rows.some(
      (row) =>
        row.receivedAt.getTime() < range.from.getTime() ||
        row.receivedAt.getTime() >= range.to.getTime(),
    );
    if (outside) throw new InconsistentReadError('messages.listRecent');
    return rows;
  }

  /**
   * The registry public ids of message rows (reader, one query); a message without a registry
   * row of this organization is never exposed (dropped).
   */
  async withPublicIds<R extends { id: bigint }>(
    scope: TenantScope,
    rows: readonly R[],
  ): Promise<Array<R & { publicId: string }>> {
    const publicIds = await this.publicIdMap(
      scope,
      rows.map((r) => r.id),
    );
    return rows.flatMap((row) => {
      const publicId = publicIds.get(row.id);
      return publicId ? [{ ...row, publicId }] : [];
    });
  }

  /** Registry public ids of the scope's messages by internal id (reader). */
  async publicIdMap(
    scope: TenantScope,
    messageIds: readonly bigint[],
  ): Promise<Map<bigint, string>> {
    const ids = [...new Set(messageIds)];
    if (ids.length === 0) return new Map();
    const identities = await this.reader.client.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: ids } }),
      select: { id: true, publicId: true },
    });
    const wanted = new Set(ids);
    return new Map(identities.filter((i) => wanted.has(i.id)).map((i) => [i.id, i.publicId]));
  }
}
