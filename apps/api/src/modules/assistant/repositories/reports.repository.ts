import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { type AiChatReportGranularity, Prisma } from '@email-gateway/database';
import { tenantWhere } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import { REPORT_ROW_CODES } from '../assistant.constants';
import type { Owner } from './conversations.repository';

type Tx = Prisma.TransactionClient;

export const reportSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  platformOverrideId: true,
  conversationId: true,
  executionId: true,
  status: true,
  title: true,
  periodFrom: true,
  periodTo: true,
  granularity: true,
  sections: true,
  figures: true,
  templateVersion: true,
  objectKey: true,
  sizeBytes: true,
  sha256: true,
  errorCode: true,
  purgedAt: true,
  objectDeletedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.AiChatReportSelect;
export type ReportRow = Prisma.AiChatReportGetPayload<{ select: typeof reportSelect }>;

/** A report with the public ids of its conversation and execution (the view). */
export type ReportWithRefs = ReportRow & {
  conversationPublicId: string;
  executionPublicId: string | null;
};

export interface ReportCreate {
  publicId: string;
  platformOverrideId: string | null;
  conversationId: bigint;
  title: string;
  periodFrom: Date;
  periodTo: Date;
  granularity: AiChatReportGranularity;
  /** `{ included, omitted, atoRange, label }` (≤ 4 KiB, metadata only). */
  sections: Prisma.InputJsonValue;
  /** The card figures (≤ 2 KiB). */
  figures: Prisma.InputJsonValue;
  templateVersion: string;
  objectKey: string;
  sizeBytes: number;
  sha256: string;
  createdAt: Date;
}

/** A report whose object a job deletes (key checked again by the object store). */
export interface ReportObjectRow {
  id: bigint;
  organizationId: bigint;
  objectKey: string | null;
}

const objectSelect = { id: true, organizationId: true, objectKey: true } as const;

/**
 * `ai_chat_reports` (step AI-R §3, D2, D6, D7; ADR-0095): metadata of the HTML reports of the
 * assistant (window, sections, omitted reasons, figures, size, SHA-256, object key, statuses);
 * the HTML itself lives only in object storage (I5). Request paths are owner-scoped (organization
 * of the scope, the user, the platform override id, as conversations and confirmations); the job
 * methods (sweeps, object purge) run across organizations and return the organization of every
 * row so each object key is checked against its own organization prefix. Writer only.
 */
@Injectable()
export class ReportsRepository {
  constructor(private readonly writer: PrismaService) {}

  private ownerWhere(
    owner: Owner,
    platformOverrideId: string | null,
  ): { organizationId: bigint; userId: bigint; platformOverrideId: string | null } {
    return tenantWhere(owner.scope, { userId: owner.userId, platformOverrideId });
  }

  /** D2 step 9: the `pending` row before the object is put (its own short statement). */
  async insertPending(owner: Owner, data: ReportCreate): Promise<bigint> {
    const row = await this.writer.aiChatReport.create({
      data: {
        ...data,
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        status: 'pending',
      },
      select: { id: true },
    });
    return row.id;
  }

  /** D2 step 9: `pending → available` with the execution, inside the execution's transaction. */
  async markAvailable(owner: Owner, id: bigint, executionRowId: bigint, tx: Tx): Promise<boolean> {
    const result = await tx.aiChatReport.updateMany({
      where: {
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        id,
        status: 'pending',
      },
      data: { status: 'available', executionId: executionRowId },
    });
    return result.count === 1;
  }

  /** D2 step 9: the put failed (`pending → failed`); the key stays for the object purge. */
  async markFailed(owner: Owner, id: bigint, errorCode: string): Promise<boolean> {
    const result = await this.writer.aiChatReport.updateMany({
      where: {
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        id,
        status: 'pending',
      },
      data: { status: 'failed', errorCode: errorCode.slice(0, 64) },
    });
    return result.count === 1;
  }

  /** D2 step 2: the user's reports since `since` (the UTC day), any status. */
  countSince(owner: Owner, since: Date): Promise<number> {
    return this.writer.aiChatReport.count({
      where: {
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        createdAt: { gte: since },
      },
    });
  }

  /** §4.1: the caller's own report (organization, user, override id), any status. */
  async findOwned(
    owner: Owner,
    platformOverrideId: string | null,
    publicId: string,
  ): Promise<ReportWithRefs | null> {
    const row = await this.writer.aiChatReport.findFirst({
      where: { ...this.ownerWhere(owner, platformOverrideId), publicId },
      select: { ...reportSelect, conversation: { select: { publicId: true } } },
    });
    if (!row) return null;
    assertEcho('assistant.report', [row], { organizationId: owner.scope.organizationId });
    const { conversation, ...report } = row;
    const execution =
      report.executionId === null
        ? null
        : await this.writer.aiChatToolExecution.findFirst({
            where: { organizationId: owner.scope.organizationId, id: report.executionId },
            select: { publicId: true },
          });
    return {
      ...report,
      conversationPublicId: conversation.publicId,
      executionPublicId: execution?.publicId ?? null,
    };
  }

  /**
   * D5 step 1: a report of the owner in THIS conversation, by public id (any status: purged and
   * oversize are refused by the caller with their own codes), or the latest `available` one.
   */
  findForConversation(
    owner: Owner,
    platformOverrideId: string | null,
    conversationId: bigint,
    publicId: string | null,
    tx?: Tx,
  ): Promise<ReportRow | null> {
    const db = tx ?? this.writer;
    return publicId === null
      ? db.aiChatReport.findFirst({
          where: {
            ...this.ownerWhere(owner, platformOverrideId),
            conversationId,
            status: 'available',
          },
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
          select: reportSelect,
        })
      : db.aiChatReport.findFirst({
          where: { ...this.ownerWhere(owner, platformOverrideId), conversationId, publicId },
          select: reportSelect,
        });
  }

  /** The objects of one conversation's purged reports (inline deletion after `DELETE`, D7). */
  objectsOfConversation(
    organizationId: bigint,
    conversationId: bigint,
  ): Promise<ReportObjectRow[]> {
    return this.writer.aiChatReport.findMany({
      where: { organizationId, conversationId, status: 'purged', objectDeletedAt: null },
      orderBy: { id: 'asc' },
      take: 1000,
      select: objectSelect,
    });
  }

  /** D7: purged reports whose object is not deleted yet (index `(status, object_deleted_at, id)`). */
  objectPurgeBatch(take: number): Promise<ReportObjectRow[]> {
    return this.writer.aiChatReport.findMany({
      where: { status: 'purged', objectDeletedAt: null },
      orderBy: { id: 'asc' },
      take,
      select: objectSelect,
    });
  }

  /** The object is gone (or never existed): `object_deleted_at = now`, `object_key = NULL`. */
  async markObjectDeleted(organizationId: bigint, id: bigint, now: Date): Promise<boolean> {
    const result = await this.writer.aiChatReport.updateMany({
      where: { organizationId, id, objectDeletedAt: null },
      data: { objectDeletedAt: now, objectKey: null },
    });
    return result.count === 1;
  }

  /** D7 sweep: `pending` reports created before `before` (index `(status, created_at)`). */
  pendingBefore(before: Date, take: number): Promise<ReportObjectRow[]> {
    return this.writer.aiChatReport.findMany({
      where: { status: 'pending', createdAt: { lt: before } },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take,
      select: objectSelect,
    });
  }

  /** D7 sweep: an abandoned `pending` report (its object deleted first) → `failed`. */
  async abandon(organizationId: bigint, id: bigint, now: Date): Promise<boolean> {
    const result = await this.writer.aiChatReport.updateMany({
      where: { organizationId, id, status: 'pending' },
      data: {
        status: 'failed',
        errorCode: REPORT_ROW_CODES.abandoned,
        objectDeletedAt: now,
        objectKey: null,
      },
    });
    return result.count === 1;
  }
}

/**
 * D7: the report transitions of a conversation content purge, inside the purge transaction (the
 * retention job at `purge_after` and `DELETE /assistant/conversations/{id}`): the reports
 * `available | pending | failed → purged` (`purged_at`), the deliveries lose their address, and
 * `queued` deliveries become `failed` (`assistant_report_purged`; the worker then finds no
 * `queued` row and sends nothing). The objects are deleted after the commit.
 */
export async function purgeReportsOfConversations(
  tx: Tx,
  organizationId: bigint,
  conversationIds: readonly bigint[],
  now: Date,
): Promise<void> {
  if (conversationIds.length === 0) return;
  const ids = [...conversationIds];
  // The deliveries by their reports (index `(report_id, requested_at)`; no conversation index).
  const reports = await tx.aiChatReport.findMany({
    where: { organizationId, conversationId: { in: ids } },
    select: { id: true },
  });
  await tx.aiChatReport.updateMany({
    where: {
      organizationId,
      conversationId: { in: ids },
      status: { in: ['available', 'pending', 'failed'] },
    },
    data: { status: 'purged', purgedAt: now },
  });
  if (reports.length === 0) return;
  const reportIds = reports.map((r) => r.id);
  await tx.aiChatReportDelivery.updateMany({
    where: { organizationId, reportId: { in: reportIds }, status: 'queued' },
    data: { status: 'failed', errorCode: REPORT_ROW_CODES.purged },
  });
  await tx.aiChatReportDelivery.updateMany({
    where: { organizationId, reportId: { in: reportIds }, recipientAddress: { not: null } },
    data: { recipientAddress: null },
  });
}
