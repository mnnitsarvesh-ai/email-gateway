import { Injectable } from '@nestjs/common';
import {
  type ConsumerProgressRecorder,
  PrismaConsumerProgress,
  PrismaService,
} from '@email-gateway/common';
import { type AiChatReportJobStatus, Prisma } from '@email-gateway/database';
import {
  type AssistantReportGenerateRequestedV1,
  assistantReportGenerateRequestedV1,
  EventTypes,
} from '@email-gateway/event-contracts';
import { REPORT_JOB_AGGREGATE_TYPE } from '../assistant.constants';
import { REPORT_JOB_CODES } from '../assistant.errors';
import type { Owner } from './conversations.repository';

type Tx = Prisma.TransactionClient;

export const reportJobSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  conversationId: true,
  reportId: true,
  executionId: true,
  sessionId: true,
  authMethods: true,
  homeOrganizationPublicId: true,
  platformOverrideId: true,
  arguments: true,
  organizationLabel: true,
  status: true,
  attempts: true,
  leaseUntil: true,
  errorCode: true,
  correlationId: true,
  expiresAt: true,
  reportedAt: true,
  createdAt: true,
  startedAt: true,
  finishedAt: true,
} satisfies Prisma.AiChatReportJobSelect;
export type ReportJobRow = Prisma.AiChatReportJobGetPayload<{ select: typeof reportJobSelect }>;

/** A job with the public ids the consumer needs (conversation, report, user). */
export type ReportJobWithRefs = ReportJobRow & {
  conversationPublicId: string;
  reportPublicId: string;
  reportStatus: string;
  userPublicId: string | null;
  /** The queuing `report_generate` execution's public id (header and audit). */
  executionPublicId: string | null;
};

export interface ReportJobCreate {
  publicId: string;
  conversationId: bigint;
  reportId: bigint;
  executionId: bigint;
  sessionId: string;
  authMethods: string;
  homeOrganizationPublicId: string;
  platformOverrideId: string | null;
  arguments: Prisma.InputJsonValue;
  organizationLabel: string | null;
  correlationId: string;
  expiresAt: Date;
  createdAt: Date;
}

/** An unreported terminal job for the next turn's action updates (D5). */
export interface UnreportedReportJob {
  id: bigint;
  status: AiChatReportJobStatus;
  errorCode: string | null;
  /** Sequence of the queuing `report_generate` execution (`call r<n>`). */
  executionSeq: number | null;
}

/** A job swept or cancelled by a system job. */
export interface SweptReportJob {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  reportId: bigint;
  createdAt: Date;
}

const TERMINAL: AiChatReportJobStatus[] = ['succeeded', 'failed', 'cancelled'];

/**
 * `ai_chat_report_jobs` (step AI-6 §3, D5, ADR-0096): the background job of a long-window
 * `report_generate` (the requesting session id and authentication methods, home organization,
 * override id, the validated arguments, attempts, the lease, expiry and whether the outcome was
 * reported to the model). Owner-scoped methods serve the turn; the consumer and the sweeps run
 * across organizations and always carry the row's organization on to every later statement.
 * Writer only.
 */
@Injectable()
export class ReportJobsRepository {
  constructor(private readonly writer: PrismaService) {}

  /** D5 producer: the job row (inside the execution's transaction). */
  async insert(owner: Owner, data: ReportJobCreate, tx: Tx): Promise<bigint> {
    const row = await tx.aiChatReportJob.create({
      data: {
        ...data,
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        status: 'queued',
        attempts: 0,
      },
      select: { id: true },
    });
    return row.id;
  }

  /** D5 producer: the outbox row (eventId = aggregate id = the job public id; ids only). */
  async insertGenerateRequested(
    tx: Tx,
    event: {
      organizationId: bigint;
      correlationId: string;
      payload: AssistantReportGenerateRequestedV1;
    },
  ): Promise<void> {
    const payload = assistantReportGenerateRequestedV1.parse(event.payload);
    await tx.messageOutbox.create({
      data: {
        eventId: payload.jobId,
        organizationId: event.organizationId,
        eventType: EventTypes.AssistantReportGenerateRequested,
        aggregateType: REPORT_JOB_AGGREGATE_TYPE,
        aggregateId: payload.jobId,
        correlationId: event.correlationId.slice(0, 128),
        payload,
      },
    });
  }

  /** The job of a report (report view; any status). */
  forReport(organizationId: bigint, reportId: bigint): Promise<ReportJobRow | null> {
    return this.writer.aiChatReportJob.findFirst({
      where: { organizationId, reportId },
      select: reportJobSelect,
    });
  }

  /** Terminal jobs of the conversation not yet reported to the model, oldest first (D5). */
  async unreported(
    owner: Owner,
    conversationId: bigint,
    take: number,
  ): Promise<UnreportedReportJob[]> {
    const rows = await this.writer.aiChatReportJob.findMany({
      where: {
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        conversationId,
        status: { in: TERMINAL },
        reportedAt: null,
      },
      orderBy: [{ finishedAt: 'asc' }, { id: 'asc' }],
      take,
      select: { id: true, status: true, errorCode: true, executionId: true },
    });
    if (rows.length === 0) return [];
    const executions = await this.writer.aiChatToolExecution.findMany({
      where: {
        organizationId: owner.scope.organizationId,
        id: { in: rows.map((r) => r.executionId) },
      },
      select: { id: true, seq: true },
    });
    const seqOf = new Map(executions.map((e) => [e.id, e.seq]));
    return rows.map((row) => ({
      id: row.id,
      status: row.status,
      errorCode: row.errorCode,
      executionSeq: seqOf.get(row.executionId) ?? null,
    }));
  }

  /** The updates this turn's transcript carries were reported (completed turns). */
  async markReported(owner: Owner, ids: readonly bigint[], now: Date, tx: Tx): Promise<void> {
    if (ids.length === 0) return;
    await tx.aiChatReportJob.updateMany({
      where: {
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        id: { in: [...ids] },
        reportedAt: null,
      },
      data: { reportedAt: now },
    });
  }

  /** The consumer's retry/dead-letter progress store (`message_consumer_progress`). */
  consumerProgress(): ConsumerProgressRecorder {
    return new PrismaConsumerProgress(this.writer);
  }

  // ---- consumer (D5 steps 1-5) ---------------------------------------------------------------

  /** Step 1: the job of an envelope, scoped to the envelope's organization. */
  async findForConsumer(
    organizationId: bigint,
    publicId: string,
  ): Promise<ReportJobWithRefs | null> {
    const row = await this.writer.aiChatReportJob.findFirst({
      where: { organizationId, publicId },
      select: {
        ...reportJobSelect,
        conversation: { select: { publicId: true } },
        report: { select: { publicId: true, status: true } },
      },
    });
    if (!row) return null;
    const { conversation, report, ...job } = row;
    const [user, execution] = await Promise.all([
      this.writer.user.findUnique({ where: { id: job.userId }, select: { publicId: true } }),
      this.writer.aiChatToolExecution.findFirst({
        where: { organizationId, id: job.executionId },
        select: { publicId: true },
      }),
    ]);
    return {
      ...job,
      conversationPublicId: conversation.publicId,
      reportPublicId: report.publicId,
      reportStatus: report.status,
      userPublicId: user?.publicId ?? null,
      executionPublicId: execution?.publicId ?? null,
    };
  }

  /**
   * Step 2: CAS `queued` (or `running` with an expired lease) → `running`, `attempts + 1`, the
   * lease. False when another consumer holds it (or it moved on).
   */
  async claim(organizationId: bigint, id: bigint, now: Date, leaseMs: number): Promise<boolean> {
    const result = await this.writer.aiChatReportJob.updateMany({
      where: {
        organizationId,
        id,
        expiresAt: { gt: now },
        OR: [{ status: 'queued' }, { status: 'running', leaseUntil: { lt: now } }],
      },
      data: {
        status: 'running',
        attempts: { increment: 1 },
        leaseUntil: new Date(now.getTime() + leaseMs),
        startedAt: now,
      },
    });
    return result.count === 1;
  }

  /**
   * True while another consumer holds the job: `running` with a lease that has not lapsed (the
   * lost-claim check of step 2; a redelivery then waits for the lease instead of acking).
   */
  async leaseHeld(organizationId: bigint, id: bigint, now: Date): Promise<boolean> {
    const held = await this.writer.aiChatReportJob.count({
      where: { organizationId, id, status: 'running', leaseUntil: { gte: now } },
    });
    return held > 0;
  }

  /**
   * Renews the lease of the claim that started at `claimedAt` (the claim's `started_at` is its
   * ownership token). False when the job moved on or another consumer took it over.
   */
  async renewLease(
    organizationId: bigint,
    id: bigint,
    claimedAt: Date,
    now: Date,
    leaseMs: number,
  ): Promise<boolean> {
    const result = await this.writer.aiChatReportJob.updateMany({
      where: { organizationId, id, status: 'running', startedAt: claimedAt },
      data: { leaseUntil: new Date(now.getTime() + leaseMs) },
    });
    return result.count === 1;
  }

  /**
   * A failure that leaves the job unfinished (retryable, or unexpected): back to `queued`, lease
   * cleared, so the queue's retry hop can claim it again. Only the claim that started at
   * `claimedAt` is released when given.
   */
  async requeue(
    organizationId: bigint,
    id: bigint,
    errorCode: string,
    claimedAt?: Date,
  ): Promise<boolean> {
    const result = await this.writer.aiChatReportJob.updateMany({
      where: {
        organizationId,
        id,
        status: 'running',
        ...(claimedAt !== undefined && { startedAt: claimedAt }),
      },
      data: { status: 'queued', leaseUntil: null, errorCode: errorCode.slice(0, 64) },
    });
    return result.count === 1;
  }

  /** Step 5: `running → succeeded` (inside the finalize transaction). */
  async succeed(organizationId: bigint, id: bigint, now: Date, tx: Tx): Promise<boolean> {
    const result = await tx.aiChatReportJob.updateMany({
      where: { organizationId, id, status: 'running' },
      data: { status: 'succeeded', errorCode: null, leaseUntil: null, finishedAt: now },
    });
    return result.count === 1;
  }

  /**
   * A terminal failure (`failed` with the code) of a job that is not terminal yet, and its
   * `queued` report → `failed` with the same code. False when the job was terminal already.
   */
  async fail(
    organizationId: bigint,
    job: { id: bigint; reportId: bigint },
    errorCode: string,
    now: Date,
    tx: Tx,
  ): Promise<boolean> {
    const result = await tx.aiChatReportJob.updateMany({
      where: { organizationId, id: job.id, status: { in: ['queued', 'running'] } },
      data: {
        status: 'failed',
        errorCode: errorCode.slice(0, 64),
        leaseUntil: null,
        finishedAt: now,
      },
    });
    if (result.count !== 1) return false;
    await tx.aiChatReport.updateMany({
      where: { organizationId, id: job.reportId, status: 'queued' },
      data: { status: 'failed', errorCode: errorCode.slice(0, 64) },
    });
    return true;
  }

  /**
   * The consumer ledger (`message_idempotency`, ADR-0005) of a terminal transition, inside its
   * transaction: false when this event was already recorded (a redelivery after the outcome).
   */
  async recordLedger(tx: Tx, consumer: string, eventId: string): Promise<boolean> {
    try {
      await tx.messageIdempotency.create({ data: { consumer, eventId } });
      return true;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        return false;
      }
      throw error;
    }
  }

  // ---- sweeps --------------------------------------------------------------------------------

  /** D5 sweep: unfinished jobs past `expires_at` (index `(status, expires_at)`). */
  dueToExpire(now: Date, take: number): Promise<SweptReportJob[]> {
    return this.writer.aiChatReportJob.findMany({
      where: { status: { in: ['queued', 'running'] }, expiresAt: { lte: now } },
      orderBy: [{ expiresAt: 'asc' }, { id: 'asc' }],
      take,
      select: { id: true, publicId: true, organizationId: true, reportId: true, createdAt: true },
    });
  }
}

/**
 * D5: the content purge of conversations cancels their unfinished jobs (`cancelled`, the report
 * becomes `purged` with the reports of `purgeReportsOfConversations`), inside the purge
 * transaction. Returns the cancelled jobs (metrics).
 */
export async function cancelReportJobsOfConversations(
  tx: Tx,
  organizationId: bigint,
  conversationIds: readonly bigint[],
  now: Date,
): Promise<number> {
  if (conversationIds.length === 0) return 0;
  const result = await tx.aiChatReportJob.updateMany({
    where: {
      organizationId,
      conversationId: { in: [...conversationIds] },
      status: { in: ['queued', 'running'] },
    },
    data: {
      status: 'cancelled',
      errorCode: REPORT_JOB_CODES.cancelled,
      leaseUntil: null,
      finishedAt: now,
    },
  });
  return result.count;
}
