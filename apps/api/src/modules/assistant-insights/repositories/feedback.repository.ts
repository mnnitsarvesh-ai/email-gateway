import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type {
  AiChatDataSharing,
  AiChatFeedbackRating,
  AiChatFeedbackReason,
  AiChatMessageRole,
  AiChatTurnStatus,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import { FEEDBACK_TOOLS_MAX } from '../insights.constants';
import type { SearchOwner } from './search.repository';

type Tx = Prisma.TransactionClient;

/** A message of the owner's non-deleted conversation, with what the feedback rules read. */
export interface OwnedMessage {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  conversationId: bigint;
  conversationPublicId: string;
  turnId: bigint;
  role: AiChatMessageRole;
  turnStatus: AiChatTurnStatus;
}

export const feedbackSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  conversationId: true,
  turnId: true,
  messageId: true,
  rating: true,
  reason: true,
  comment: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.AiChatFeedbackSelect;
export type FeedbackRow = Prisma.AiChatFeedbackGetPayload<{ select: typeof feedbackSelect }>;

export interface FeedbackWrite {
  publicId: string;
  userId: bigint;
  conversationId: bigint;
  turnId: bigint;
  messageId: bigint;
  rating: AiChatFeedbackRating;
  reason: AiChatFeedbackReason | null;
  comment: string | null;
}

export interface FeedbackListFilter {
  from: Date;
  to: Date;
  rating?: AiChatFeedbackRating;
  reasons?: AiChatFeedbackReason[];
  userId?: bigint;
  after?: { createdAt: Date; id: bigint };
  take: number;
}

/** One admin feedback row: the stored feedback plus the public ids of its message and conversation. */
export type AdminFeedbackRow = FeedbackRow & {
  messagePublicId: string;
  conversationPublicId: string;
};

export interface TurnMeta {
  id: bigint;
  organizationId: bigint;
  provider: string;
  model: string;
  promptVersion: string;
  dataSharing: AiChatDataSharing;
}

/**
 * `ai_chat_feedback` (step AI-6 §3, D2): one rating per assistant message. The owner's writes run
 * on the writer inside the service's transaction and are scoped by the organization of the scope
 * and the caller's user id (a message of another user or organization is never found); the admin
 * list reads the replica, scoped by the organization only. The comment is content (purged with
 * the conversation's content); it is selected only by the owner's view and the
 * `assistant:configure` list, never by the audit view.
 */
@Injectable()
export class FeedbackRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async findOwnedMessage(
    owner: SearchOwner,
    publicId: string,
    tx: Tx,
  ): Promise<OwnedMessage | null> {
    const where = tenantWhere(owner.scope, {});
    const row = await tx.aiChatMessage.findFirst({
      where: {
        ...where,
        publicId,
        conversation: {
          organizationId: where.organizationId,
          userId: owner.userId,
          status: { in: ['active', 'archived'] },
        },
      },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        conversationId: true,
        turnId: true,
        role: true,
        conversation: { select: { publicId: true } },
        turn: { select: { status: true } },
      },
    });
    if (!row) return null;
    assertEcho('assistant.feedback_message', [row], { organizationId: where.organizationId });
    return {
      id: row.id,
      publicId: row.publicId,
      organizationId: row.organizationId,
      conversationId: row.conversationId,
      conversationPublicId: row.conversation.publicId,
      turnId: row.turnId,
      role: row.role,
      turnStatus: row.turn.status,
    };
  }

  /**
   * Whether the conversation's content was purged, read with a shared lock (`FOR SHARE`) on the
   * conversation row: the content purge locks the same row `FOR UPDATE` before it clears the
   * feedback comments, so a rating either sees the purge or the purge waits for (and clears)
   * the rating's comment. False for an unknown row (the caller found the message already).
   */
  async lockContentPurged(
    organizationId: bigint,
    conversationId: bigint,
    tx: Tx,
  ): Promise<boolean> {
    const rows = await tx.$queryRaw<Array<{ purged: bigint | number }>>`SELECT
        (content_purged_at IS NOT NULL) AS purged
      FROM ai_chat_conversations
      WHERE organization_id = ${organizationId} AND id = ${conversationId}
      FOR SHARE`;
    return rows.length > 0 && Number(rows[0]!.purged) === 1;
  }

  async findByMessage(scope: TenantScope, messageId: bigint, tx: Tx): Promise<FeedbackRow | null> {
    const row = await tx.aiChatFeedback.findFirst({
      where: tenantWhere(scope, { messageId }),
      select: feedbackSelect,
    });
    if (row) assertEcho('assistant.feedback', [row], { organizationId: scope.organizationId });
    return row;
  }

  /** Insert or replace the rating of a message (`message_id` is unique). */
  async upsert(scope: TenantScope, data: FeedbackWrite, tx: Tx): Promise<FeedbackRow> {
    const row = await tx.aiChatFeedback.upsert({
      where: { messageId: data.messageId },
      create: {
        publicId: data.publicId,
        organizationId: scope.organizationId,
        userId: data.userId,
        conversationId: data.conversationId,
        turnId: data.turnId,
        messageId: data.messageId,
        rating: data.rating,
        reason: data.reason,
        comment: data.comment,
      },
      update: { rating: data.rating, reason: data.reason, comment: data.comment },
      select: feedbackSelect,
    });
    assertEcho('assistant.feedback', [row], {
      organizationId: scope.organizationId,
      messageId: data.messageId,
    });
    return row;
  }

  async remove(scope: TenantScope, id: bigint, tx: Tx): Promise<boolean> {
    const deleted = await tx.aiChatFeedback.deleteMany({ where: tenantWhere(scope, { id }) });
    return deleted.count === 1;
  }

  // ---- admin list (replica) --------------------------------------------------------------------

  /** Newest first (`-createdAt`, then `-id`) inside `[from, to)`. */
  async adminList(scope: TenantScope, filter: FeedbackListFilter): Promise<AdminFeedbackRow[]> {
    const and: Prisma.AiChatFeedbackWhereInput[] = [];
    if (filter.after) {
      and.push({
        OR: [
          { createdAt: { lt: filter.after.createdAt } },
          { createdAt: filter.after.createdAt, id: { lt: filter.after.id } },
        ],
      });
    }
    const rows = await this.reader.client.aiChatFeedback.findMany({
      where: {
        ...tenantWhere(scope, {}),
        createdAt: { gte: filter.from, lt: filter.to },
        ...(filter.rating !== undefined && { rating: filter.rating }),
        ...(filter.reasons !== undefined && { reason: { in: filter.reasons } }),
        ...(filter.userId !== undefined && { userId: filter.userId }),
        ...(and.length > 0 && { AND: and }),
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: filter.take,
      select: {
        ...feedbackSelect,
        message: { select: { publicId: true } },
        conversation: { select: { publicId: true } },
      },
    });
    assertEcho('assistant.admin_feedback', rows, {
      organizationId: scope.organizationId,
      ...(filter.rating !== undefined && { rating: filter.rating }),
      ...(filter.userId !== undefined && { userId: filter.userId }),
    });
    return rows.map(({ message, conversation, ...row }) => ({
      ...row,
      messagePublicId: message.publicId,
      conversationPublicId: conversation.publicId,
    }));
  }

  /** Provider, model, prompt version and data-sharing level of the given turns. */
  async turnsMeta(scope: TenantScope, turnIds: readonly bigint[]): Promise<Map<bigint, TurnMeta>> {
    const ids = [...new Set(turnIds)];
    if (ids.length === 0) return new Map();
    const rows = await this.reader.client.aiChatTurn.findMany({
      where: tenantWhere(scope, { id: { in: ids } }),
      select: {
        id: true,
        organizationId: true,
        provider: true,
        model: true,
        promptVersion: true,
        dataSharing: true,
      },
    });
    assertEcho('assistant.feedback_turns', rows, { organizationId: scope.organizationId });
    return new Map(rows.map((r) => [r.id, r]));
  }

  /** The distinct tool names each turn called (its executions), sorted, at most 32 per turn. */
  async toolsOfTurns(
    scope: TenantScope,
    turnIds: readonly bigint[],
  ): Promise<Map<bigint, string[]>> {
    const ids = [...new Set(turnIds)];
    if (ids.length === 0) return new Map();
    const rows = await this.reader.client.aiChatToolExecution.groupBy({
      by: ['turnId', 'toolName'],
      where: tenantWhere(scope, { turnId: { in: ids } }),
      orderBy: [{ turnId: 'asc' }, { toolName: 'asc' }],
    });
    const out = new Map<bigint, string[]>();
    for (const row of rows) {
      if (row.turnId === null) continue;
      const list = out.get(row.turnId) ?? [];
      if (list.length < FEEDBACK_TOOLS_MAX) list.push(row.toolName);
      out.set(row.turnId, list);
    }
    return out;
  }
}
