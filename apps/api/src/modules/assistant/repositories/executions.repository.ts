import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type AiChatHttpMethod,
  type AiChatToolAccess,
  type AiChatToolDecision,
  type AiChatToolRisk,
  type AiChatToolStatus,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import type { Owner } from './conversations.repository';

type Tx = Prisma.TransactionClient;

export const executionSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  conversationId: true,
  turnId: true,
  parentExecutionId: true,
  seq: true,
  toolName: true,
  operationId: true,
  httpMethod: true,
  access: true,
  risk: true,
  decision: true,
  status: true,
  httpStatus: true,
  errorCode: true,
  correlationId: true,
  paramsRedacted: true,
  resourceRef: true,
  resultCard: true,
  resultRefs: true,
  nextCursor: true,
  latencyMs: true,
  createdAt: true,
} satisfies Prisma.AiChatToolExecutionSelect;
export type ExecutionRow = Prisma.AiChatToolExecutionGetPayload<{ select: typeof executionSelect }>;

/** An execution with the public ids of its conversation, turn and parent (views). */
export type ExecutionWithRefs = ExecutionRow & {
  conversationPublicId: string;
  turnPublicId: string | null;
  parentPublicId: string | null;
};

export interface ExecutionCreate {
  publicId: string;
  conversationId: bigint;
  turnId: bigint | null;
  parentExecutionId: bigint | null;
  seq: number;
  toolName: string;
  operationId: string;
  httpMethod: AiChatHttpMethod;
  access: AiChatToolAccess;
  risk: AiChatToolRisk;
  decision: AiChatToolDecision;
  status: AiChatToolStatus;
  httpStatus: number | null;
  errorCode: string | null;
  correlationId: string;
  paramsRedacted: Prisma.InputJsonValue | null;
  resourceRef: string | null;
  resultCard: Prisma.InputJsonValue | null;
  resultRefs: Prisma.InputJsonValue | null;
  nextCursor: string | null;
  latencyMs: number | null;
  createdAt: Date;
}

const withRefsSelect = {
  ...executionSelect,
  conversation: { select: { publicId: true } },
  turn: { select: { publicId: true } },
} satisfies Prisma.AiChatToolExecutionSelect;

/**
 * `ai_chat_tool_executions` (step AI-1 §3, D5, D12): one row per `call_tool`, allowed or denied,
 * and per "more" page. Scoped by the caller's organization and user; refs resolve only within
 * one conversation. Sequences are conversation-wide (refs `r<seq>`); writers hold the
 * conversation's turn lock, so `nextSeq` + insert is not raced.
 */
@Injectable()
export class ExecutionsRepository {
  constructor(
    private readonly writer: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  private ownerWhere(owner: Owner): { organizationId: bigint; userId: bigint } {
    return tenantWhere(owner.scope, { userId: owner.userId });
  }

  async nextSeq(owner: Owner, conversationId: bigint): Promise<number> {
    const row = await this.writer.aiChatToolExecution.aggregate({
      where: { organizationId: owner.scope.organizationId, conversationId },
      _max: { seq: true },
    });
    return (row._max.seq ?? 0) + 1;
  }

  async create(owner: Owner, data: ExecutionCreate, tx: Tx): Promise<bigint> {
    const row = await tx.aiChatToolExecution.create({
      data: {
        ...data,
        ...this.ownerWhere(owner),
        paramsRedacted: data.paramsRedacted ?? Prisma.DbNull,
        resultCard: data.resultCard ?? Prisma.DbNull,
        resultRefs: data.resultRefs ?? Prisma.DbNull,
      },
      select: { id: true },
    });
    return row.id;
  }

  /** The stored refs of execution `seq` of this conversation (`r<seq>.<row>` → target). */
  async refsOf(owner: Owner, conversationId: bigint, seq: number): Promise<unknown> {
    const row = await this.writer.aiChatToolExecution.findFirst({
      where: { ...this.ownerWhere(owner), conversationId, seq },
      select: { resultRefs: true },
    });
    return row?.resultRefs ?? null;
  }

  /** An execution of the caller's own, non-deleted conversation. */
  async findOwned(owner: Owner, publicId: string): Promise<ExecutionWithRefs | null> {
    const row = await this.writer.aiChatToolExecution.findFirst({
      where: {
        ...this.ownerWhere(owner),
        publicId,
        conversation: { status: { in: ['active', 'archived'] } },
      },
      select: withRefsSelect,
    });
    if (!row) return null;
    assertEcho('assistant.execution', [row], { organizationId: owner.scope.organizationId });
    return this.flatten([row])[0]!;
  }

  /** The executions of the given turns plus the "more" pages of the conversation. */
  async forTurns(
    owner: Owner,
    conversationId: bigint,
    turnIds: readonly bigint[],
    on: 'writer' | 'replica' = 'writer',
  ): Promise<ExecutionWithRefs[]> {
    if (turnIds.length === 0) return [];
    const db = on === 'replica' ? this.reader.client : this.writer;
    const rows = await db.aiChatToolExecution.findMany({
      where: {
        ...this.ownerWhere(owner),
        conversationId,
        OR: [{ turnId: { in: [...turnIds] } }, { turnId: null }],
      },
      orderBy: { seq: 'asc' },
      select: withRefsSelect,
    });
    assertEcho('assistant.executions', rows, {
      organizationId: owner.scope.organizationId,
      conversationId,
    });
    return this.flatten(rows);
  }

  /** The executions of a conversation for the recap (metadata and refs), oldest first. */
  recapRows(
    owner: Owner,
    conversationId: bigint,
    take: number,
  ): Promise<
    Array<
      Pick<
        ExecutionRow,
        | 'seq'
        | 'toolName'
        | 'decision'
        | 'status'
        | 'httpStatus'
        | 'errorCode'
        | 'resultCard'
        | 'resultRefs'
      >
    >
  > {
    return this.writer.aiChatToolExecution
      .findMany({
        where: { ...this.ownerWhere(owner), conversationId },
        orderBy: { seq: 'desc' },
        take,
        select: {
          seq: true,
          toolName: true,
          decision: true,
          status: true,
          httpStatus: true,
          errorCode: true,
          resultCard: true,
          resultRefs: true,
        },
      })
      .then((rows) => rows.reverse());
  }

  private flatten(
    rows: Array<Prisma.AiChatToolExecutionGetPayload<{ select: typeof withRefsSelect }>>,
  ): ExecutionWithRefs[] {
    const byId = new Map(rows.map((r) => [r.id, r.publicId]));
    return rows.map(({ conversation, turn, ...row }) => ({
      ...row,
      conversationPublicId: conversation.publicId,
      turnPublicId: turn?.publicId ?? null,
      parentPublicId:
        row.parentExecutionId === null ? null : (byId.get(row.parentExecutionId) ?? null),
    }));
  }

  /** Public id of an execution (a parent outside the loaded set). */
  async publicIdOf(owner: Owner, id: bigint): Promise<string | null> {
    const row = await this.writer.aiChatToolExecution.findFirst({
      where: { ...this.ownerWhere(owner), id },
      select: { publicId: true },
    });
    return row?.publicId ?? null;
  }

  /** Hard delete (execution retention): executions created before `before`, one batch. */
  deleteBefore(before: Date, batch: number): Promise<number> {
    return this.writer.$executeRaw`DELETE FROM ai_chat_tool_executions
      WHERE created_at < ${before} ORDER BY created_at, id LIMIT ${batch}`;
  }
}
