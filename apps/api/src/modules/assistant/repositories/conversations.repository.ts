import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type AiChatConversationStatus,
  type AiChatDataSharing,
  type AiChatKeySource,
  type AiChatTurnStatus,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import { cancelReportJobsOfConversations } from './report-jobs.repository';
import { purgeReportsOfConversations } from './reports.repository';

type Tx = Prisma.TransactionClient;
type On = 'writer' | 'replica';

export const conversationSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  platformOverrideId: true,
  title: true,
  status: true,
  turnCount: true,
  segment: true,
  lastTurnAt: true,
  purgeAfter: true,
  contentPurgedAt: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.AiChatConversationSelect;
export type ConversationRow = Prisma.AiChatConversationGetPayload<{
  select: typeof conversationSelect;
}>;

export const turnSelect = {
  id: true,
  publicId: true,
  conversationId: true,
  organizationId: true,
  userId: true,
  seq: true,
  segment: true,
  clientTurnId: true,
  status: true,
  provider: true,
  model: true,
  responseModel: true,
  rounds: true,
  toolCalls: true,
  inputTokens: true,
  outputTokens: true,
  cacheReadTokens: true,
  cacheWriteTokens: true,
  costMicros: true,
  latencyMs: true,
  errorCode: true,
  correlationId: true,
  dataSharing: true,
  keySource: true,
  fallbackFrom: true,
  startedAt: true,
  finishedAt: true,
} satisfies Prisma.AiChatTurnSelect;
type FullTurnRow = Prisma.AiChatTurnGetPayload<{ select: typeof turnSelect }>;
/** Step AI-6 columns (always selected; optional in the type for rows built before AI-6). */
type TurnHardeningColumns = 'dataSharing' | 'keySource' | 'fallbackFrom';
export type TurnRow = Omit<FullTurnRow, TurnHardeningColumns> &
  Partial<Pick<FullTurnRow, TurnHardeningColumns>>;

export const messageSelect = {
  id: true,
  publicId: true,
  conversationId: true,
  turnId: true,
  organizationId: true,
  seq: true,
  role: true,
  content: true,
  createdAt: true,
} satisfies Prisma.AiChatMessageSelect;
export type MessageRow = Prisma.AiChatMessageGetPayload<{ select: typeof messageSelect }>;

/** The caller of every conversation query: organization from the scope, the user's own rows. */
export interface Owner {
  scope: TenantScope;
  userId: bigint;
}

export interface ConversationListFilter {
  statuses: AiChatConversationStatus[];
  titleContains?: string;
  after?: { lastTurnAt: Date; id: bigint };
  take: number;
}

export interface TurnStart {
  publicId: string;
  seq: number;
  segment: number;
  clientTurnId: string;
  provider: string;
  model: string;
  promptVersion: string;
  registryVersion: string;
  correlationId: string;
  startedAt: Date;
  userMessagePublicId: string;
  userMessage: string;
  /** Step AI-6 D3, D6: the level applied, whose key pays and the skipped first candidate. */
  dataSharing?: AiChatDataSharing;
  keySource?: AiChatKeySource;
  fallbackFrom?: string | null;
  /**
   * The conversation's content purge date from this turn on (`startedAt` + the tenant's
   * retention): new content always gets a fresh retention window, and a conversation whose
   * content was purged before is due for purging again (`content_purged_at` cleared).
   */
  purgeAfter: Date;
}

export interface TurnFinish {
  status: Exclude<AiChatTurnStatus, 'running'>;
  /** Segment of this turn. */
  segment: number;
  /** Segment the conversation's next turn continues (this one, or the next after an overflow). */
  conversationSegment: number;
  responseModel: string | null;
  rounds: number;
  toolCalls: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costMicros: bigint | null;
  latencyMs: number;
  errorCode: string | null;
  providerTranscript: string | null;
  finishedAt: Date;
  /** The assistant message (completed and cancelled turns). */
  assistantMessage: { publicId: string; content: string } | null;
  /**
   * Step AI-6 D6: the candidate actually used after a same-turn switch (provider, model, key
   * source, the failed candidate's provider id); absent = as started.
   */
  route?: {
    provider: string;
    model: string;
    keySource: AiChatKeySource;
    fallbackFrom: string | null;
  };
}

/** Message sequence numbers of a turn: the user message `2·seq − 1`, the answer `2·seq`. */
export const userMessageSeq = (turnSeq: number): number => 2 * turnSeq - 1;
export const assistantMessageSeq = (turnSeq: number): number => 2 * turnSeq;

const clip = (value: number, max: number): number => Math.max(0, Math.min(max, Math.round(value)));
const UINT = 4_294_967_295;

/**
 * `ai_chat_conversations`, `ai_chat_turns` and `ai_chat_messages` (step AI-1 §3, D7, D12). Every
 * query is scoped by the organization of the caller's scope and the caller's user id (Q9:
 * conversations are private, also from admins); a deleted conversation is invisible. Lists read
 * the replica, everything a turn or a decision depends on reads the writer.
 */
@Injectable()
export class ConversationsRepository {
  constructor(
    private readonly writer: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  private db(on: On | Tx): Tx | PrismaService | PrismaReadService['client'] {
    return on === 'replica' ? this.reader.client : on === 'writer' ? this.writer : on;
  }

  private ownerWhere(owner: Owner): { organizationId: bigint; userId: bigint } {
    return tenantWhere(owner.scope, { userId: owner.userId });
  }

  // ---- conversations -------------------------------------------------------------------------

  async create(
    owner: Owner,
    data: {
      publicId: string;
      title: string | null;
      platformOverrideId: string | null;
      now: Date;
      purgeAfter: Date;
    },
  ): Promise<ConversationRow> {
    return this.writer.aiChatConversation.create({
      data: {
        ...this.ownerWhere(owner),
        publicId: data.publicId,
        title: data.title,
        platformOverrideId: data.platformOverrideId,
        // The list orders by activity: a new conversation counts as active now.
        lastTurnAt: data.now,
        purgeAfter: data.purgeAfter,
      },
      select: conversationSelect,
    });
  }

  /** Conversations of the user that are not deleted (the per-user limit). */
  countLive(owner: Owner): Promise<number> {
    return this.writer.aiChatConversation.count({
      where: { ...this.ownerWhere(owner), status: { in: ['active', 'archived'] } },
    });
  }

  async findOwned(
    owner: Owner,
    publicId: string,
    on: On | Tx = 'writer',
  ): Promise<ConversationRow | null> {
    const row = await this.db(on).aiChatConversation.findFirst({
      where: { ...this.ownerWhere(owner), publicId, status: { in: ['active', 'archived'] } },
      select: conversationSelect,
    });
    if (row)
      assertEcho('assistant.conversation', [row], { organizationId: owner.scope.organizationId });
    return row;
  }

  /** Newest activity first (`-lastTurnAt`, then `-id`). */
  async list(owner: Owner, filter: ConversationListFilter): Promise<ConversationRow[]> {
    const and: Prisma.AiChatConversationWhereInput[] = [];
    if (filter.after) {
      and.push({
        OR: [
          { lastTurnAt: { lt: filter.after.lastTurnAt } },
          { lastTurnAt: filter.after.lastTurnAt, id: { lt: filter.after.id } },
        ],
      });
    }
    const rows = await this.reader.client.aiChatConversation.findMany({
      where: {
        ...this.ownerWhere(owner),
        status: { in: filter.statuses },
        lastTurnAt: { not: null },
        ...(filter.titleContains !== undefined && { title: { contains: filter.titleContains } }),
        ...(and.length > 0 && { AND: and }),
      },
      orderBy: [{ lastTurnAt: 'desc' }, { id: 'desc' }],
      take: filter.take,
      select: conversationSelect,
    });
    assertEcho('assistant.conversations', rows, {
      organizationId: owner.scope.organizationId,
      userId: owner.userId,
    });
    return rows;
  }

  async update(
    owner: Owner,
    id: bigint,
    data: { title?: string; status?: 'active' | 'archived' },
  ): Promise<void> {
    await this.writer.aiChatConversation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: { in: ['active', 'archived'] } },
      data: { ...data, rowVersion: { increment: 1 } },
    });
  }

  /** Soft delete + immediate content purge of one conversation (D12), inside `tx`. */
  async deleteAndPurge(owner: Owner, id: bigint, now: Date, tx: Tx): Promise<boolean> {
    const updated = await tx.aiChatConversation.updateMany({
      where: { ...this.ownerWhere(owner), id, status: { in: ['active', 'archived'] } },
      data: { status: 'deleted', rowVersion: { increment: 1 } },
    });
    if (updated.count !== 1) return false;
    await this.purgeContent(owner.scope.organizationId, [id], now, tx);
    return true;
  }

  /**
   * Clears the content columns of the given conversations (title, message content, transcripts,
   * execution cards, refs and cursors, confirmation requests, preconditions and summaries) and
   * stamps `content_purged_at`. Metadata stays. Step AI-R D7: the conversation's reports become
   * `purged` and their deliveries lose the address (`queued` ones fail); the report objects are
   * deleted after the commit (`AssistantRetentionService`, the delete route inline). Step AI-6:
   * the pseudonym mappings are deleted (D3), feedback comments cleared (D2) and unfinished report
   * jobs cancelled (D5), in the same transaction.
   */
  async purgeContent(
    organizationId: bigint,
    conversationIds: readonly bigint[],
    now: Date,
    tx: Tx,
  ): Promise<number> {
    if (conversationIds.length === 0) return 0;
    const ids = [...conversationIds];
    await tx.aiChatMessage.updateMany({
      where: { organizationId, conversationId: { in: ids } },
      data: { content: null },
    });
    await tx.aiChatTurn.updateMany({
      where: { organizationId, conversationId: { in: ids } },
      data: { providerTranscript: null },
    });
    await tx.aiChatToolExecution.updateMany({
      where: { organizationId, conversationId: { in: ids } },
      data: { resultCard: Prisma.DbNull, resultRefs: Prisma.DbNull, nextCursor: null },
    });
    // Step AI-2 D7: the stored request, preconditions and summary of their confirmations.
    await tx.aiChatActionConfirmation.updateMany({
      where: { organizationId, conversationId: { in: ids } },
      data: { request: Prisma.DbNull, preconditions: Prisma.DbNull, summary: Prisma.DbNull },
    });
    // Step AI-6: jobs first (their `queued` reports then become `purged` with the others).
    const cancelledJobs = await cancelReportJobsOfConversations(tx, organizationId, ids, now);
    await purgeReportsOfConversations(tx, organizationId, ids, now);
    await tx.aiChatPseudonym.deleteMany({ where: { organizationId, conversationId: { in: ids } } });
    await tx.aiChatFeedback.updateMany({
      where: { organizationId, conversationId: { in: ids }, comment: { not: null } },
      data: { comment: null },
    });
    await tx.aiChatConversation.updateMany({
      where: { organizationId, id: { in: ids } },
      data: { title: null, contentPurgedAt: now },
    });
    return cancelledJobs;
  }

  // ---- turns ---------------------------------------------------------------------------------

  findTurnByClientId(
    conversationId: bigint,
    organizationId: bigint,
    clientTurnId: string,
  ): Promise<TurnRow | null> {
    return this.writer.aiChatTurn.findFirst({
      where: { conversationId, organizationId, clientTurnId },
      select: turnSelect,
    });
  }

  /** A turn of the user's own, non-deleted conversation. */
  async findOwnedTurn(
    owner: Owner,
    publicId: string,
  ): Promise<(TurnRow & { conversationPublicId: string }) | null> {
    const row = await this.writer.aiChatTurn.findFirst({
      where: {
        ...this.ownerWhere(owner),
        publicId,
        conversation: { status: { in: ['active', 'archived'] } },
      },
      select: { ...turnSelect, conversation: { select: { publicId: true } } },
    });
    if (!row) return null;
    const { conversation, ...turn } = row;
    return { ...turn, conversationPublicId: conversation.publicId };
  }

  /**
   * Opens a turn (D7 "persistence at turn start"): the `running` turn, the user message and the
   * conversation's turn counter, in one writer transaction. Returns null when the
   * `(conversation, clientTurnId)` or `(conversation, seq)` pair already exists (a racing retry).
   */
  async startTurn(
    owner: Owner,
    conversation: Pick<ConversationRow, 'id' | 'rowVersion'>,
    data: TurnStart,
    tx: Tx,
  ): Promise<TurnRow | null> {
    const bumped = await tx.aiChatConversation.updateMany({
      where: {
        ...this.ownerWhere(owner),
        id: conversation.id,
        status: { in: ['active', 'archived'] },
        turnCount: data.seq - 1,
      },
      data: {
        turnCount: data.seq,
        status: 'active',
        purgeAfter: data.purgeAfter,
        contentPurgedAt: null,
        rowVersion: { increment: 1 },
      },
    });
    if (bumped.count !== 1) return null;
    try {
      const turn = await tx.aiChatTurn.create({
        data: {
          publicId: data.publicId,
          conversationId: conversation.id,
          ...this.ownerWhere(owner),
          seq: data.seq,
          segment: data.segment,
          clientTurnId: data.clientTurnId,
          status: 'running',
          provider: data.provider,
          model: data.model,
          promptVersion: data.promptVersion,
          registryVersion: data.registryVersion,
          correlationId: data.correlationId,
          ...(data.dataSharing !== undefined && { dataSharing: data.dataSharing }),
          ...(data.keySource !== undefined && { keySource: data.keySource }),
          ...(data.fallbackFrom !== undefined && {
            fallbackFrom: data.fallbackFrom?.slice(0, 32) ?? null,
          }),
          startedAt: data.startedAt,
        },
        select: turnSelect,
      });
      await tx.aiChatMessage.create({
        data: {
          publicId: data.userMessagePublicId,
          conversationId: conversation.id,
          turnId: turn.id,
          organizationId: owner.scope.organizationId,
          seq: userMessageSeq(data.seq),
          role: 'user',
          content: data.userMessage,
          createdAt: data.startedAt,
        },
        select: { id: true },
      });
      return turn;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        return null;
      }
      throw error;
    }
  }

  /**
   * Closes a turn (D7 "persistence at turn end"): turn metrics and transcript, the assistant
   * message, and the conversation's activity, purge date, segment and (when empty) title.
   * Only a `running` turn is closed (the sweeper may have abandoned it): false otherwise.
   */
  async finishTurn(
    owner: Owner,
    turn: Pick<TurnRow, 'id' | 'seq' | 'conversationId'>,
    data: TurnFinish,
    conversation: { purgeAfter: Date; lastTurnAt: Date; title: string | null },
    tx: Tx,
  ): Promise<boolean> {
    const updated = await tx.aiChatTurn.updateMany({
      where: { ...this.ownerWhere(owner), id: turn.id, status: 'running' },
      data: {
        status: data.status,
        segment: data.segment,
        responseModel: data.responseModel,
        rounds: clip(data.rounds, 255),
        toolCalls: clip(data.toolCalls, 65_535),
        inputTokens: clip(data.inputTokens, UINT),
        outputTokens: clip(data.outputTokens, UINT),
        cacheReadTokens: clip(data.cacheReadTokens, UINT),
        cacheWriteTokens: clip(data.cacheWriteTokens, UINT),
        costMicros: data.costMicros,
        latencyMs: clip(data.latencyMs, UINT),
        errorCode: data.errorCode,
        providerTranscript: data.providerTranscript,
        finishedAt: data.finishedAt,
        ...(data.route && {
          provider: data.route.provider.slice(0, 32),
          model: data.route.model.slice(0, 64),
          keySource: data.route.keySource,
          fallbackFrom: data.route.fallbackFrom?.slice(0, 32) ?? null,
        }),
      },
    });
    if (updated.count !== 1) return false;
    if (data.assistantMessage) {
      await tx.aiChatMessage.create({
        data: {
          publicId: data.assistantMessage.publicId,
          conversationId: turn.conversationId,
          turnId: turn.id,
          organizationId: owner.scope.organizationId,
          seq: assistantMessageSeq(turn.seq),
          role: 'assistant',
          content: data.assistantMessage.content,
          createdAt: data.finishedAt,
        },
        select: { id: true },
      });
    }
    await tx.aiChatConversation.updateMany({
      where: { ...this.ownerWhere(owner), id: turn.conversationId, status: { not: 'deleted' } },
      data: {
        lastTurnAt: conversation.lastTurnAt,
        purgeAfter: conversation.purgeAfter,
        // New content was written: it is due for the content purge at the new purge date.
        contentPurgedAt: null,
        segment: data.conversationSegment,
        rowVersion: { increment: 1 },
      },
    });
    if (conversation.title !== null) {
      await tx.aiChatConversation.updateMany({
        where: { ...this.ownerWhere(owner), id: turn.conversationId, title: null },
        data: { title: conversation.title },
      });
    }
    return true;
  }

  findTurn(owner: Owner, id: bigint): Promise<TurnRow | null> {
    return this.writer.aiChatTurn.findFirst({
      where: { ...this.ownerWhere(owner), id },
      select: turnSelect,
    });
  }

  /**
   * Native transcripts of the completed turns of a segment, oldest first (verbatim replay), with
   * the provider and model each used (step AI-6 D6: a different provider or model starts a new
   * segment).
   */
  async segmentTranscripts(
    owner: Owner,
    conversationId: bigint,
    segment: number,
  ): Promise<
    Array<{ seq: number; providerTranscript: string | null; provider?: string; model?: string }>
  > {
    return this.writer.aiChatTurn.findMany({
      where: { ...this.ownerWhere(owner), conversationId, segment, status: 'completed' },
      orderBy: { seq: 'asc' },
      select: { seq: true, providerTranscript: true, provider: true, model: true },
    });
  }

  /** The latest user messages of a conversation, oldest first (recap). */
  async recentUserMessages(owner: Owner, conversationId: bigint, take: number): Promise<string[]> {
    const rows = await this.writer.aiChatMessage.findMany({
      where: {
        organizationId: owner.scope.organizationId,
        conversationId,
        role: 'user',
        content: { not: null },
      },
      orderBy: { seq: 'desc' },
      take,
      select: { content: true },
    });
    return rows.reverse().map((r) => r.content ?? '');
  }

  // ---- messages ------------------------------------------------------------------------------

  /** Messages oldest first after `afterSeq`, with their turn (replica). */
  async listMessages(
    owner: Owner,
    conversationId: bigint,
    afterSeq: number | undefined,
    take: number,
  ): Promise<
    Array<MessageRow & { turn: Pick<TurnRow, 'id' | 'publicId' | 'status' | 'errorCode' | 'seq'> }>
  > {
    const rows = await this.reader.client.aiChatMessage.findMany({
      where: {
        organizationId: owner.scope.organizationId,
        conversationId,
        ...(afterSeq !== undefined && { seq: { gt: afterSeq } }),
      },
      orderBy: { seq: 'asc' },
      take,
      select: {
        ...messageSelect,
        turn: { select: { id: true, publicId: true, status: true, errorCode: true, seq: true } },
      },
    });
    assertEcho('assistant.messages', rows, {
      organizationId: owner.scope.organizationId,
      conversationId,
    });
    return rows;
  }

  /** The turn's messages (writer; the JSON answer and replays). */
  turnMessages(owner: Owner, turnId: bigint): Promise<MessageRow[]> {
    return this.writer.aiChatMessage.findMany({
      where: { organizationId: owner.scope.organizationId, turnId },
      orderBy: { seq: 'asc' },
      select: messageSelect,
    });
  }

  // ---- retention and sweeper (system jobs, no request scope) ---------------------------------

  /** Conversations whose content retention ended (`purge_after` ≤ now, not yet purged). */
  dueForContentPurge(
    now: Date,
    take: number,
  ): Promise<Array<{ id: bigint; organizationId: bigint }>> {
    return this.writer.aiChatConversation.findMany({
      where: { purgeAfter: { lte: now }, contentPurgedAt: null },
      orderBy: { purgeAfter: 'asc' },
      take,
      select: { id: true, organizationId: true },
    });
  }

  /**
   * Locks (`FOR UPDATE`) and returns the given conversations of one organization that are still
   * due for the content purge. The candidates of `dueForContentPurge` were read without a lock: a
   * turn that started meanwhile moved `purge_after` forward and its new content must survive.
   * A locking read sees the latest committed row, and a concurrent `startTurn` waits for the
   * purge transaction (or the purge waits for the turn's).
   */
  async lockDueForContentPurge(
    organizationId: bigint,
    conversationIds: readonly bigint[],
    now: Date,
    tx: Tx,
  ): Promise<bigint[]> {
    if (conversationIds.length === 0) return [];
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`SELECT id FROM ai_chat_conversations
      WHERE organization_id = ${organizationId} AND id IN (${Prisma.join([...conversationIds])})
        AND purge_after <= ${now} AND content_purged_at IS NULL
      ORDER BY id FOR UPDATE`;
    return rows.map((row) => BigInt(row.id));
  }

  /**
   * A lowered content retention (D12, `PUT /assistant/settings`) applies to the existing
   * conversations of the organization: `purge_after` moves to `COALESCE(last_turn_at,
   * created_at) + retentionDays` where that is earlier (never later; a raised retention applies
   * from each conversation's next turn). Batches of `batch` rows inside `tx`; returns the count.
   */
  async shortenRetention(
    organizationId: bigint,
    retentionDays: number,
    tx: Tx,
    batch = 1000,
  ): Promise<number> {
    let total = 0;
    for (let i = 0; i < 10_000; i += 1) {
      const changed = await tx.$executeRaw`UPDATE ai_chat_conversations
        SET purge_after = COALESCE(last_turn_at, created_at) + INTERVAL ${retentionDays} DAY
        WHERE organization_id = ${organizationId} AND content_purged_at IS NULL
          AND (purge_after IS NULL
            OR purge_after > COALESCE(last_turn_at, created_at) + INTERVAL ${retentionDays} DAY)
        ORDER BY id LIMIT ${batch}`;
      total += changed;
      if (changed < batch) break;
    }
    return total;
  }

  /** Running turns started before `startedBefore` (abandoned by a crashed api). */
  staleRunningTurns(
    startedBefore: Date,
    take: number,
  ): Promise<
    Array<{ id: bigint; publicId: string; organizationId: bigint; conversationPublicId: string }>
  > {
    return this.writer.aiChatTurn
      .findMany({
        where: { status: 'running', startedAt: { lt: startedBefore } },
        orderBy: { startedAt: 'asc' },
        take,
        select: {
          id: true,
          publicId: true,
          organizationId: true,
          conversation: { select: { publicId: true } },
        },
      })
      .then((rows) =>
        rows.map((r) => ({
          id: r.id,
          publicId: r.publicId,
          organizationId: r.organizationId,
          conversationPublicId: r.conversation.publicId,
        })),
      );
  }

  /** Marks a still-running turn `failed` with `code`; false when it finished meanwhile. */
  async abandonTurn(id: bigint, code: string, now: Date): Promise<boolean> {
    const result = await this.writer.aiChatTurn.updateMany({
      where: { id, status: 'running' },
      data: { status: 'failed', errorCode: code, finishedAt: now },
    });
    return result.count === 1;
  }

  /** Hard delete (execution retention): messages created before `before`, one batch. */
  deleteMessagesBefore(before: Date, batch: number): Promise<number> {
    return this.writer.$executeRaw`DELETE FROM ai_chat_messages
      WHERE created_at < ${before} ORDER BY created_at, id LIMIT ${batch}`;
  }

  /** Hard delete: finished turns started before `before` with no message or execution left. */
  deleteTurnsBefore(before: Date, batch: number): Promise<number> {
    return this.writer.$executeRaw`DELETE FROM ai_chat_turns
      WHERE started_at < ${before} AND status <> 'running'
        AND NOT EXISTS (SELECT 1 FROM ai_chat_messages m WHERE m.turn_id = ai_chat_turns.id)
        AND NOT EXISTS (SELECT 1 FROM ai_chat_tool_executions e WHERE e.turn_id = ai_chat_turns.id)
      ORDER BY started_at, id LIMIT ${batch}`;
  }

  /**
   * Hard delete: conversations inactive since before `before` and without turns left; step AI-R
   * D7: never one with a report whose object is not deleted yet (the job deletes those objects
   * first; the reports and deliveries then go with the conversation by FK cascade).
   */
  deleteConversationsBefore(before: Date, batch: number): Promise<number> {
    return this.writer.$executeRaw`DELETE FROM ai_chat_conversations
      WHERE COALESCE(last_turn_at, created_at) < ${before}
        AND NOT EXISTS (SELECT 1 FROM ai_chat_turns t WHERE t.conversation_id = ai_chat_conversations.id)
        AND NOT EXISTS (SELECT 1 FROM ai_chat_tool_executions e WHERE e.conversation_id = ai_chat_conversations.id)
        AND NOT EXISTS (SELECT 1 FROM ai_chat_reports r
          WHERE r.conversation_id = ai_chat_conversations.id AND r.object_key IS NOT NULL)
      ORDER BY id LIMIT ${batch}`;
  }
}
