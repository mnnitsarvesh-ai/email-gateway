import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type AiChatConfirmationRisk,
  type AiChatConfirmationStatus,
  type AiChatHttpMethod,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import type { Owner } from './conversations.repository';

type Tx = Prisma.TransactionClient;

export const confirmationSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  platformOverrideId: true,
  sessionFamilyId: true,
  conversationId: true,
  turnId: true,
  executionId: true,
  resultExecutionId: true,
  toolName: true,
  operationId: true,
  httpMethod: true,
  risk: true,
  requiresReauth: true,
  request: true,
  preconditions: true,
  summary: true,
  stateDigest: true,
  actionDigest: true,
  tokenHash: true,
  status: true,
  failedAttempts: true,
  reauthUsed: true,
  expiresAt: true,
  decidedAt: true,
  executionStartedAt: true,
  executedAt: true,
  reportedAt: true,
  resultHttpStatus: true,
  errorCode: true,
  correlationId: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.AiChatActionConfirmationSelect;
export type ConfirmationRow = Prisma.AiChatActionConfirmationGetPayload<{
  select: typeof confirmationSelect;
}>;

/** A confirmation with the public ids its view and digest need. */
export type ConfirmationWithRefs = ConfirmationRow & {
  conversationPublicId: string;
  executionPublicId: string;
  /** Sequence of the proposal execution (`call r<seq>` of the action updates). */
  executionSeq: number;
  resultExecutionPublicId: string | null;
};

export interface ConfirmationCreate {
  publicId: string;
  platformOverrideId: string | null;
  sessionFamilyId: string;
  conversationId: bigint;
  turnId: bigint | null;
  executionId: bigint;
  toolName: string;
  operationId: string;
  httpMethod: AiChatHttpMethod;
  risk: AiChatConfirmationRisk;
  requiresReauth: boolean;
  request: Prisma.InputJsonValue;
  preconditions: Prisma.InputJsonValue;
  summary: Prisma.InputJsonValue;
  stateDigest: string | null;
  actionDigest: string;
  tokenHash: string;
  expiresAt: Date;
  correlationId: string;
  createdAt: Date;
}

/** The terminal outcome of a confirmed write (D2 step 14). */
export interface ConfirmationFinish {
  status: 'executed' | 'failed';
  resultExecutionId: bigint | null;
  resultHttpStatus: number | null;
  errorCode: string | null;
  executedAt: Date | null;
}

/** An unreported terminal confirmation for the action updates of the next turn (D6). */
export interface UnreportedConfirmation {
  id: bigint;
  toolName: string;
  status: AiChatConfirmationStatus;
  callSeq: number;
  resultHttpStatus: number | null;
  errorCode: string | null;
  resultSeq: number | null;
  resultRowRef: boolean;
  /**
   * Step AI-R D5: the recipient of a `report_send_email` (the stored request's `body.to`; null
   * after the content purge and for every other tool).
   */
  recipient: string | null;
}

/** The `to` of a stored native `report_send_email` request (the action-update line). */
function recipientOf(toolName: string, request: unknown): string | null {
  if (toolName !== 'report_send_email' || request === null || typeof request !== 'object') {
    return null;
  }
  const body = (request as { body?: unknown }).body;
  const to = body !== null && typeof body === 'object' ? (body as { to?: unknown }).to : null;
  return typeof to === 'string' ? to : null;
}

/** A row a system job moved (audit per row). */
export interface SweptConfirmation {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  conversationPublicId: string;
  executionPublicId: string;
  toolName: string;
  operationId: string;
  risk: AiChatConfirmationRisk;
  requiresReauth: boolean;
  createdAt: Date;
}

const withRefsSelect = {
  ...confirmationSelect,
  conversation: { select: { publicId: true } },
  execution: { select: { publicId: true, seq: true } },
} satisfies Prisma.AiChatActionConfirmationSelect;

const sweptSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  toolName: true,
  operationId: true,
  risk: true,
  requiresReauth: true,
  createdAt: true,
  conversation: { select: { publicId: true } },
  execution: { select: { publicId: true } },
} satisfies Prisma.AiChatActionConfirmationSelect;

const TERMINAL: AiChatConfirmationStatus[] = ['executed', 'failed', 'cancelled', 'expired'];

/**
 * `ai_chat_action_confirmations` (step AI-2 §3, D1, D2, D6, D7): write proposals of the
 * assistant waiting for the user's confirmation. Request-scoped queries are scoped by the
 * caller's organization (the scope's, i.e. the override target under an override), user and
 * platform override id, like conversations; another user's or organization's confirmation is
 * invisible. Status transitions are conditional `UPDATE`s (`WHERE status = 'pending' …`), so a
 * confirmation executes at most once. Content columns (`request`, `preconditions`, `summary`)
 * are purged with their conversation's content.
 */
@Injectable()
export class ConfirmationsRepository {
  constructor(
    private readonly writer: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  private ownerWhere(owner: Owner): { organizationId: bigint; userId: bigint } {
    return tenantWhere(owner.scope, { userId: owner.userId });
  }

  async create(owner: Owner, data: ConfirmationCreate, tx: Tx): Promise<bigint> {
    const row = await tx.aiChatActionConfirmation.create({
      data: { ...data, ...this.ownerWhere(owner), status: 'pending' },
      select: { id: true },
    });
    return row.id;
  }

  /**
   * A confirmation of the caller's own, non-deleted conversation, under the same platform
   * override (or none) it was proposed under.
   */
  async findOwned(
    owner: Owner,
    platformOverrideId: string | null,
    publicId: string,
  ): Promise<ConfirmationWithRefs | null> {
    const row = await this.writer.aiChatActionConfirmation.findFirst({
      where: {
        ...this.ownerWhere(owner),
        platformOverrideId,
        publicId,
        conversation: { status: { in: ['active', 'archived'] } },
      },
      select: withRefsSelect,
    });
    if (!row) return null;
    assertEcho('assistant.confirmation', [row], { organizationId: owner.scope.organizationId });
    return (await this.flatten(owner, [row]))[0]!;
  }

  /** Re-reads one row by id (after a transition), owner-scoped. */
  async reload(owner: Owner, id: bigint): Promise<ConfirmationWithRefs | null> {
    const row = await this.writer.aiChatActionConfirmation.findFirst({
      where: { ...this.ownerWhere(owner), id },
      select: withRefsSelect,
    });
    return row ? (await this.flatten(owner, [row]))[0]! : null;
  }

  /** The confirmations of the given proposal executions (views of executions). */
  async forExecutions(
    owner: Owner,
    executionIds: readonly bigint[],
    on: 'writer' | 'replica' = 'writer',
  ): Promise<ConfirmationWithRefs[]> {
    if (executionIds.length === 0) return [];
    const db = on === 'replica' ? this.reader.client : this.writer;
    const rows = await db.aiChatActionConfirmation.findMany({
      where: { ...this.ownerWhere(owner), executionId: { in: [...executionIds] } },
      select: withRefsSelect,
    });
    assertEcho('assistant.confirmations', rows, { organizationId: owner.scope.organizationId });
    return this.flatten(owner, rows);
  }

  /** Live `pending` confirmations of a conversation (the pending cap, D1 step 1). */
  countLivePending(owner: Owner, conversationId: bigint, now: Date): Promise<number> {
    return this.writer.aiChatActionConfirmation.count({
      where: {
        organizationId: owner.scope.organizationId,
        conversationId,
        status: 'pending',
        expiresAt: { gt: now },
      },
    });
  }

  /**
   * The atomic transition `pending → executing` (D2 step 11); 0 when another request won, the
   * row is no longer pending or it expired.
   */
  async beginExecuting(owner: Owner, id: bigint, now: Date, reauthUsed: boolean): Promise<number> {
    const result = await this.writer.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: 'pending', expiresAt: { gt: now } },
      data: { status: 'executing', decidedAt: now, ...(reauthUsed && { reauthUsed: true }) },
    });
    return result.count;
  }

  /**
   * The claim of the write (D2 step 13, step AI-2 review): `executing` with no start yet gets
   * `execution_started_at`. 0 when the outcome-unknown sweep failed the row meanwhile (or another
   * request claimed it): the write must not be sent.
   */
  async claimExecution(owner: Owner, id: bigint, now: Date): Promise<number> {
    const result = await this.writer.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: 'executing', executionStartedAt: null },
      data: { executionStartedAt: now },
    });
    return result.count;
  }

  /** `executing` → `executed` | `failed` with the write's outcome (inside the result's tx). */
  async finish(owner: Owner, id: bigint, data: ConfirmationFinish, tx: Tx): Promise<number> {
    const result = await tx.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: 'executing' },
      data: {
        status: data.status,
        resultExecutionId: data.resultExecutionId,
        resultHttpStatus: data.resultHttpStatus,
        errorCode: data.errorCode?.slice(0, 64) ?? null,
        executedAt: data.executedAt,
      },
    });
    return result.count;
  }

  /**
   * The write's real outcome replaces an `assistant_confirmation_outcome_unknown` the sweep wrote
   * while the write was still running (a write slower than ASSISTANT_TOOL_TIMEOUT_MS + 60 s):
   * `failed` (outcome unknown, no result) → the outcome, reported to the model again.
   */
  async reconcileOutcomeUnknown(
    owner: Owner,
    id: bigint,
    outcomeUnknownCode: string,
    data: ConfirmationFinish,
    tx: Tx,
  ): Promise<number> {
    const result = await tx.aiChatActionConfirmation.updateMany({
      where: {
        ...this.ownerWhere(owner),
        id,
        status: 'failed',
        errorCode: outcomeUnknownCode,
        resultExecutionId: null,
        executionStartedAt: { not: null },
      },
      data: {
        status: data.status,
        resultExecutionId: data.resultExecutionId,
        resultHttpStatus: data.resultHttpStatus,
        errorCode: data.errorCode?.slice(0, 64) ?? null,
        executedAt: data.executedAt,
        reportedAt: null,
      },
    });
    return result.count;
  }

  /**
   * `pending` or `executing` → `failed` without an execution (digest recomputation mismatch,
   * tool changed, permission lost, state changed): never ran the write.
   */
  async fail(owner: Owner, id: bigint, errorCode: string, now: Date, tx: Tx): Promise<number> {
    const result = await tx.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: { in: ['pending', 'executing'] } },
      data: { status: 'failed', errorCode: errorCode.slice(0, 64), decidedAt: now },
    });
    return result.count;
  }

  /** `pending` → `cancelled` (the user, or five wrong tokens with `errorCode`). */
  async cancel(
    owner: Owner,
    id: bigint,
    now: Date,
    tx: Tx,
    errorCode: string | null = null,
  ): Promise<number> {
    const result = await tx.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: 'pending' },
      data: { status: 'cancelled', decidedAt: now, errorCode },
    });
    return result.count;
  }

  /** `pending` past `expires_at` → `expired` (confirm of an expired row, D2 step 4). */
  async expire(owner: Owner, id: bigint, now: Date, tx: Tx): Promise<number> {
    const result = await tx.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: 'pending', expiresAt: { lte: now } },
      data: { status: 'expired', decidedAt: now },
    });
    return result.count;
  }

  /** One more wrong token; returns the attempts so far (0 when the row is no longer pending). */
  async incrementFailedAttempts(owner: Owner, id: bigint): Promise<number> {
    const result = await this.writer.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: 'pending' },
      data: { failedAttempts: { increment: 1 } },
    });
    if (result.count !== 1) return 0;
    const row = await this.writer.aiChatActionConfirmation.findFirst({
      where: { ...this.ownerWhere(owner), id },
      select: { failedAttempts: true },
    });
    return row?.failedAttempts ?? 0;
  }

  // ---- turns: action updates (D6) -----------------------------------------------------------

  /** Terminal confirmations of a conversation not yet reported to the model, oldest first. */
  async unreported(
    owner: Owner,
    conversationId: bigint,
    take: number,
  ): Promise<UnreportedConfirmation[]> {
    const rows = await this.writer.aiChatActionConfirmation.findMany({
      where: {
        ...this.ownerWhere(owner),
        conversationId,
        status: { in: TERMINAL },
        reportedAt: null,
      },
      orderBy: [{ decidedAt: 'asc' }, { id: 'asc' }],
      take,
      select: {
        id: true,
        toolName: true,
        status: true,
        resultHttpStatus: true,
        errorCode: true,
        resultExecutionId: true,
        request: true,
        execution: { select: { seq: true } },
      },
    });
    const resultIds = rows
      .map((r) => r.resultExecutionId)
      .filter((id): id is bigint => id !== null);
    const results =
      resultIds.length === 0
        ? []
        : await this.writer.aiChatToolExecution.findMany({
            where: { organizationId: owner.scope.organizationId, id: { in: resultIds } },
            select: { id: true, seq: true, resultRefs: true },
          });
    const byId = new Map(results.map((r) => [r.id, r]));
    return rows.map((row) => {
      const result = row.resultExecutionId === null ? undefined : byId.get(row.resultExecutionId);
      const refs = result?.resultRefs;
      return {
        id: row.id,
        toolName: row.toolName,
        status: row.status,
        callSeq: row.execution.seq,
        resultHttpStatus: row.resultHttpStatus,
        errorCode: row.errorCode,
        resultSeq: result?.seq ?? null,
        resultRowRef:
          result !== undefined &&
          refs !== null &&
          typeof refs === 'object' &&
          !Array.isArray(refs) &&
          Object.prototype.hasOwnProperty.call(refs, `r${result.seq}.1`),
        recipient: recipientOf(row.toolName, row.request),
      };
    });
  }

  /** Marks reported confirmations (the turn that told the model completed). */
  async markReported(owner: Owner, ids: readonly bigint[], now: Date, tx: Tx): Promise<void> {
    if (ids.length === 0) return;
    await tx.aiChatActionConfirmation.updateMany({
      where: { ...this.ownerWhere(owner), id: { in: [...ids] }, reportedAt: null },
      data: { reportedAt: now },
    });
  }

  // ---- conversation delete (D7) -------------------------------------------------------------

  /** Cancels the `pending` confirmations of a conversation being deleted; returns them. */
  async cancelPendingOfConversation(
    organizationId: bigint,
    conversationId: bigint,
    now: Date,
    tx: Tx,
  ): Promise<SweptConfirmation[]> {
    const rows = await tx.aiChatActionConfirmation.findMany({
      where: { organizationId, conversationId, status: 'pending' },
      select: sweptSelect,
    });
    if (rows.length === 0) return [];
    await tx.aiChatActionConfirmation.updateMany({
      where: { organizationId, id: { in: rows.map((r) => r.id) }, status: 'pending' },
      data: { status: 'cancelled', decidedAt: now },
    });
    return rows.map(swept);
  }

  // ---- system jobs (no request scope) -------------------------------------------------------

  /** `pending` rows past `expires_at` (candidates; each is moved conditionally). */
  async dueToExpire(now: Date, take: number): Promise<SweptConfirmation[]> {
    const rows = await this.writer.aiChatActionConfirmation.findMany({
      where: { status: 'pending', expiresAt: { lte: now } },
      orderBy: [{ expiresAt: 'asc' }, { id: 'asc' }],
      take,
      select: sweptSelect,
    });
    return rows.map(swept);
  }

  /** System job: `pending` past expiry → `expired`; false when it moved meanwhile. */
  async expireById(id: bigint, now: Date, tx: Tx): Promise<boolean> {
    const result = await tx.aiChatActionConfirmation.updateMany({
      where: { id, status: 'pending', expiresAt: { lte: now } },
      data: { status: 'expired', decidedAt: now },
    });
    return result.count === 1;
  }

  /**
   * `executing` rows of a crashed api: still re-reading preconditions (no write started)
   * although decided before `cutoff.decidedBefore`, or writing since before
   * `cutoff.startedBefore`.
   */
  async staleExecuting(cutoff: StaleExecutingCutoff, take: number): Promise<SweptConfirmation[]> {
    const rows = await this.writer.aiChatActionConfirmation.findMany({
      where: staleExecutingWhere(cutoff),
      orderBy: [{ decidedAt: 'asc' }, { id: 'asc' }],
      take,
      select: sweptSelect,
    });
    return rows.map(swept);
  }

  /**
   * System job: a stale `executing` row → `failed` with `errorCode` (never re-executed); the
   * staleness is re-checked in the same conditional `UPDATE`.
   */
  async failStaleById(
    id: bigint,
    cutoff: StaleExecutingCutoff,
    errorCode: string,
    tx: Tx,
  ): Promise<boolean> {
    const result = await tx.aiChatActionConfirmation.updateMany({
      where: { id, ...staleExecutingWhere(cutoff) },
      data: { status: 'failed', errorCode },
    });
    return result.count === 1;
  }

  private async flatten(
    owner: Owner,
    rows: Array<Prisma.AiChatActionConfirmationGetPayload<{ select: typeof withRefsSelect }>>,
  ): Promise<ConfirmationWithRefs[]> {
    const resultIds = rows
      .map((r) => r.resultExecutionId)
      .filter((id): id is bigint => id !== null);
    const results =
      resultIds.length === 0
        ? []
        : await this.writer.aiChatToolExecution.findMany({
            where: { organizationId: owner.scope.organizationId, id: { in: resultIds } },
            select: { id: true, publicId: true },
          });
    const byId = new Map(results.map((r) => [r.id, r.publicId]));
    return rows.map(({ conversation, execution, ...row }) => ({
      ...row,
      conversationPublicId: conversation.publicId,
      executionPublicId: execution.publicId,
      executionSeq: execution.seq,
      resultExecutionPublicId:
        row.resultExecutionId === null ? null : (byId.get(row.resultExecutionId) ?? null),
    }));
  }
}

/** When an `executing` confirmation is stale (the outcome-unknown sweep, D7). */
export interface StaleExecutingCutoff {
  /** No write started yet: the precondition re-read began before this. */
  decidedBefore: Date;
  /** The write started before this. */
  startedBefore: Date;
}

function staleExecutingWhere(
  cutoff: StaleExecutingCutoff,
): Prisma.AiChatActionConfirmationWhereInput {
  return {
    status: 'executing',
    OR: [
      { executionStartedAt: null, decidedAt: { lt: cutoff.decidedBefore } },
      { executionStartedAt: { lt: cutoff.startedBefore } },
    ],
  };
}

function swept(
  row: Prisma.AiChatActionConfirmationGetPayload<{ select: typeof sweptSelect }>,
): SweptConfirmation {
  const { conversation, execution, ...rest } = row;
  return {
    ...rest,
    conversationPublicId: conversation.publicId,
    executionPublicId: execution.publicId,
  };
}
