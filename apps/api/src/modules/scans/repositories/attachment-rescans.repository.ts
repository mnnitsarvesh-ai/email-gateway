import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import { type AttachmentRescanStatus, Prisma } from '@email-gateway/database';

type Client = Prisma.TransactionClient;

const jobSelect = {
  id: true,
  publicId: true,
  trigger: true,
  status: true,
  organizationId: true,
  windowStart: true,
  windowEnd: true,
  states: true,
  component: true,
  fromVersion: true,
  toVersion: true,
  maxMessages: true,
  selectedCount: true,
  requestedCount: true,
  skippedCount: true,
  reason: true,
  lastError: true,
  startedAt: true,
  completedAt: true,
  createdAt: true,
  updatedAt: true,
  organization: { select: { publicId: true } },
  requestedBy: { select: { publicId: true } },
} satisfies Prisma.AttachmentRescanJobSelect;

export type RescanJobRow = Prisma.AttachmentRescanJobGetPayload<{ select: typeof jobSelect }>;

export interface CandidateFilter {
  windowStart: Date;
  windowEnd: Date;
  states: readonly string[];
  organizationId: bigint | null;
}

export interface NewRescanJob extends CandidateFilter {
  maxMessages: number;
  reason: string;
  requestedByUserId: bigint;
}

/** States a job can be cancelled from (A13). */
const CANCELLABLE: AttachmentRescanStatus[] = ['pending', 'running'];

/**
 * `attachment_rescan_jobs` for the platform rescan routes (step 4.2 A13). Reads (lists, the
 * dry-run estimate) use the replica (`PrismaReadService`, writer fallback above the lag
 * threshold); job creation and cancellation run on the writer transaction the service passes.
 */
@Injectable()
export class AttachmentRescansRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly writer: PrismaService,
  ) {}

  /** A non-deleted organization by public id (writer: the job references it). */
  findOrganization(publicId: string): Promise<{ id: bigint; publicId: string } | null> {
    return this.writer.organization.findFirst({
      where: { publicId, deletedAt: null },
      select: { id: true, publicId: true },
    });
  }

  /**
   * How many messages the rescan runner would select now (A13), on the replica. The predicate
   * is the one of the email-worker's `RescanJobRunner.candidates` (WP3,
   * `apps/email-worker/src/scanning/engines/attachment/rescan-runner.ts`), without its cursor:
   * received in the window, in one of the states, optionally one organization, with at least
   * one `email_attachments` row, and either `scan_failed` or without a final `malicious`
   * attachment result in the message's current round. Both must change together.
   */
  async countCandidates(filter: CandidateFilter): Promise<number> {
    const organization =
      filter.organizationId !== null
        ? Prisma.sql`AND m.organization_id = ${filter.organizationId}`
        : Prisma.empty;
    const rows = await this.reader.client.$queryRaw<{ n: bigint | number }[]>`
      SELECT COUNT(*) AS n
      FROM email_messages m
      WHERE m.received_at >= ${filter.windowStart} AND m.received_at <= ${filter.windowEnd}
        AND m.status IN (${Prisma.join([...filter.states])})
        ${organization}
        AND EXISTS (
          SELECT 1 FROM email_attachments a
          WHERE a.message_id = m.id AND a.received_at = m.received_at
            AND a.organization_id = m.organization_id
        )
        AND (
          m.status = 'scan_failed'
          OR NOT EXISTS (
            SELECT 1 FROM email_scans s
            JOIN scan_engine_results r ON r.scan_id = s.id AND r.received_at = s.received_at
            WHERE s.message_id = m.id AND s.received_at = m.received_at
              AND s.lifecycle_round = m.lifecycle_round
              AND r.engine = 'attachment' AND r.is_final = 1 AND r.outcome = 'malicious'
          )
        )`;
    return Number(rows[0]?.n ?? 0);
  }

  /** An admin job, `pending` (the runner picks it up). */
  create(tx: Client, input: NewRescanJob): Promise<RescanJobRow> {
    return tx.attachmentRescanJob.create({
      data: {
        trigger: 'admin',
        status: 'pending',
        organizationId: input.organizationId,
        windowStart: input.windowStart,
        windowEnd: input.windowEnd,
        states: [...input.states],
        maxMessages: input.maxMessages,
        requestedByUserId: input.requestedByUserId,
        reason: input.reason,
      },
      select: jobSelect,
    });
  }

  /** Newest first (id descending), below `beforeId`, optionally one status (replica). */
  list(page: {
    take: number;
    beforeId?: bigint;
    status?: AttachmentRescanStatus;
  }): Promise<RescanJobRow[]> {
    return this.reader.client.attachmentRescanJob.findMany({
      where: {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.status !== undefined && { status: page.status }),
      },
      select: jobSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  /** One job by public id (replica). */
  find(publicId: string): Promise<RescanJobRow | null> {
    return this.reader.client.attachmentRescanJob.findUnique({
      where: { publicId },
      select: jobSelect,
    });
  }

  /** The job on the writer, in the caller's transaction. */
  findOnWriter(tx: Client, publicId: string): Promise<RescanJobRow | null> {
    return tx.attachmentRescanJob.findUnique({ where: { publicId }, select: jobSelect });
  }

  /** `pending|running → cancelled`; false when the job was in another status. */
  async cancel(tx: Client, id: bigint, now: Date): Promise<boolean> {
    const { count } = await tx.attachmentRescanJob.updateMany({
      where: { id, status: { in: CANCELLABLE } },
      data: { status: 'cancelled', completedAt: now },
    });
    return count === 1;
  }
}
