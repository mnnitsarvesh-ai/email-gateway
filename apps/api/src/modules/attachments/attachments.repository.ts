import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import type { CursorDirection } from '../../http/cursor/cursor-codec';
import { assertEcho, InconsistentReadError } from '../../http/listing/echo-check';
import type { TimeIdKey } from '../messages/domain/v1-list';
import type { MessageRef } from '../messages/repositories/message-data.repository';
import { afterKey, column, keysetOrder } from '../messages/repositories/keyset-sql';
import {
  type AttachmentResultRow,
  attachmentResultSelect,
} from '../messages/repositories/message-scans-read.repository';
import { clampTake } from '../tenant-data/page';

/**
 * Attachment metadata and verdict reads (step 6.1 WP2, D15) on the replica: never `object_key`,
 * `original_filename` or content. Every query matches the scope's organization and the
 * partition key; every row is echo-checked (`503 inconsistent_read` on a mismatch).
 */

export const ATTACHMENT_SHA256_INDEX = 'email_attachments_organization_id_sha256_idx';

const RECEIVED_AT = column('received_at');
const ID = column('id');

const partSelect = {
  id: true,
  organizationId: true,
  messageId: true,
  receivedAt: true,
  partIndex: true,
  filename: true,
  declaredContentType: true,
  detectedContentType: true,
  sizeBytes: true,
  sha256: true,
  disposition: true,
  depth: true,
} satisfies Prisma.EmailAttachmentSelect;

export type AttachmentPart = Prisma.EmailAttachmentGetPayload<{ select: typeof partSelect }>;

export type LatestResultRow = AttachmentResultRow & { organizationId: bigint };

/** Most result rows one attachments page reads (≤ 100 parts × rounds). */
const MAX_RESULT_ROWS = 4_000;

export interface AttachmentSearchInput {
  organizationId: bigint;
  sha256: string;
  range: { from: Date; to: Date };
  after?: TimeIdKey | undefined;
  direction: CursorDirection;
  take: number;
}

/**
 * `GET /attachments` (D5-style keyset): the `(organization_id, sha256, received_at, id)` index
 * (migration rest_api_index_coverage), `received_at` range pruning, `ORDER BY received_at DESC,
 * id DESC` read in index order (no filesort): a page reads about `take` index entries however
 * common the hash is, so no scan budget is needed (D6).
 */
export function attachmentSearchSql(input: AttachmentSearchInput): Prisma.Sql {
  return Prisma.sql`SELECT id, received_at, organization_id, message_id, part_index, filename,
      size_bytes, detected_content_type, sha256
    FROM email_attachments ${Prisma.raw(`FORCE INDEX (${ATTACHMENT_SHA256_INDEX})`)}
    WHERE organization_id = ${input.organizationId} AND sha256 = ${input.sha256}
      AND received_at >= ${input.range.from} AND received_at < ${input.range.to}
      AND ${afterKey(RECEIVED_AT, ID, input.after, input.direction)}
    ${keysetOrder(RECEIVED_AT, ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

export interface AttachmentSearchRow {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  messageId: bigint;
  partIndex: number;
  filename: string | null;
  sizeBytes: number;
  detectedContentType: string | null;
  sha256: string;
}

@Injectable()
export class AttachmentsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** The message's attachments with `part_index` after `afterPartIndex`, ascending. */
  async parts(
    scope: TenantScope,
    message: MessageRef,
    page: { take: number; afterPartIndex?: number | undefined },
  ): Promise<AttachmentPart[]> {
    const rows = await this.db.emailAttachment.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(page.afterPartIndex !== undefined && { partIndex: { gt: page.afterPartIndex } }),
      }),
      select: partSelect,
      orderBy: { partIndex: 'asc' },
      take: clampTake(page.take),
    });
    assertEcho('attachments.parts', rows, {
      organizationId: scope.organizationId,
      messageId: message.id,
      receivedAt: message.receivedAt,
    });
    return rows;
  }

  /** Every `attachment_scan_results` row of the given attachments of the message (all rounds). */
  async results(
    scope: TenantScope,
    message: MessageRef,
    attachmentIds: readonly bigint[],
  ): Promise<LatestResultRow[]> {
    if (attachmentIds.length === 0) return [];
    const rows = await this.db.attachmentScanResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        attachmentId: { in: [...attachmentIds] },
      }),
      select: { ...attachmentResultSelect, organizationId: true },
      orderBy: [{ scanId: 'desc' }, { partIndex: 'asc' }],
      take: MAX_RESULT_ROWS,
    });
    assertEcho('attachments.results', rows, {
      organizationId: scope.organizationId,
      attachmentId: [...attachmentIds],
    });
    return rows;
  }

  /** `GET /attachments`: the organization's attachments with this hash in the window. */
  async search(scope: TenantScope, input: Omit<AttachmentSearchInput, 'organizationId'>) {
    const raw = await this.db.$queryRaw<
      Array<{
        id: bigint;
        received_at: Date;
        organization_id: bigint;
        message_id: bigint;
        part_index: number;
        filename: string | null;
        size_bytes: number;
        detected_content_type: string | null;
        sha256: string;
      }>
    >(attachmentSearchSql({ ...input, organizationId: scope.organizationId }));
    const rows: AttachmentSearchRow[] = raw.map((r) => ({
      id: BigInt(r.id),
      receivedAt: r.received_at,
      organizationId: BigInt(r.organization_id),
      messageId: BigInt(r.message_id),
      partIndex: Number(r.part_index),
      filename: r.filename,
      sizeBytes: Number(r.size_bytes),
      detectedContentType: r.detected_content_type,
      sha256: r.sha256,
    }));
    assertEcho('attachments.search', rows, {
      organizationId: scope.organizationId,
      sha256: input.sha256,
    });
    if (
      rows.some(
        (r) =>
          r.receivedAt.getTime() < input.range.from.getTime() ||
          r.receivedAt.getTime() >= input.range.to.getTime(),
      )
    ) {
      throw new InconsistentReadError('attachments.search');
    }
    return rows;
  }

  /**
   * The verdict of the newest round per attachment of the search page (one query, pruned by the
   * messages' `received_at`).
   */
  async latestVerdicts(
    scope: TenantScope,
    rows: readonly AttachmentSearchRow[],
  ): Promise<Map<bigint, string>> {
    if (rows.length === 0) return new Map();
    const messages = new Map<string, { messageId: bigint; receivedAt: Date }>();
    for (const r of rows) {
      messages.set(`${r.messageId}:${r.receivedAt.getTime()}`, {
        messageId: r.messageId,
        receivedAt: r.receivedAt,
      });
    }
    const attachmentIds = rows.map((r) => r.id);
    const results = await this.db.attachmentScanResult.findMany({
      where: tenantWhere(scope, {
        OR: [...messages.values()],
        attachmentId: { in: attachmentIds },
      }),
      select: { attachmentId: true, scanId: true, verdict: true, organizationId: true },
      orderBy: { scanId: 'desc' },
      take: MAX_RESULT_ROWS,
    });
    assertEcho('attachments.latestVerdicts', results, {
      organizationId: scope.organizationId,
      attachmentId: attachmentIds,
    });
    const latest = new Map<bigint, string>();
    for (const r of results) if (!latest.has(r.attachmentId)) latest.set(r.attachmentId, r.verdict);
    return latest;
  }
}
