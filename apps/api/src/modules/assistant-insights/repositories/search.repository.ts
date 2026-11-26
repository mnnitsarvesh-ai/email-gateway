import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import { isQueryTimeout } from '../../reports/domain/report-errors';
import { SearchTimeoutError } from '../insights.errors';

/** The searching owner: organization from the scope, the caller's own user id. */
export interface SearchOwner {
  scope: TenantScope;
  userId: bigint;
}

export interface SearchInput {
  /** The escaped `%q%` pattern (`likeContainsPattern`). */
  pattern: string;
  /** ASSISTANT_SEARCH_SCAN_MAX_MESSAGES: the owner's most recent messages examined. */
  scanMax: number;
  /** ASSISTANT_SEARCH_TIMEOUT_MS: `MAX_EXECUTION_TIME` of the statement. */
  timeoutMs: number;
  /** Keyset: messages with a smaller id than the cursor's. */
  beforeId?: bigint;
  take: number;
}

export interface SearchRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  conversationId: bigint;
  conversationPublicId: string;
  conversationTitle: string | null;
  userId: bigint;
  role: 'user' | 'assistant';
  seq: number;
  createdAt: Date;
  content: string;
}

interface RawSearchRow {
  id: bigint | number;
  publicId: string;
  organizationId: bigint | number;
  conversationId: bigint | number;
  conversationPublicId: string;
  conversationTitle: string | null;
  userId: bigint | number;
  role: string;
  seq: bigint | number;
  createdAt: Date;
  content: string | null;
}

function positiveInt(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1)
    throw new Error(`${name} must be a positive integer`);
  return value;
}

/**
 * The owner's content search (step AI-6 D4) on the read replica, as one statement:
 *
 * 1. `recent`: the ids of the owner's `ASSISTANT_SEARCH_SCAN_MAX_MESSAGES` most recent messages
 *    with content (purged content is NULL and never found) of the owner's non-deleted
 *    conversations: the conversations first (`ai_chat_conversations_user_id_idx`, organization,
 *    user and status filtered), then their messages by `conversation_id`
 *    (`ai_chat_messages_conversation_id_seq_key`), so another user's messages are never read.
 * 2. Matches among them: the message content contains the query, or the conversation title does
 *    (then only the conversation's first message, one row per conversation), both compared under
 *    `utf8mb4_0900_ai_ci` (case- and accent-insensitive) with an escaped `LIKE … ESCAPE '!'`.
 *    Newest first by message id (ids grow with time), keyset `id < cursor`.
 *
 * The statement carries `MAX_EXECUTION_TIME(ASSISTANT_SEARCH_TIMEOUT_MS)`; an interrupted
 * statement is `SearchTimeoutError`. The pattern and every id are bound parameters; the hint and
 * the limits are integers from configuration. Every row is echo-checked (organization, user).
 */
@Injectable()
export class SearchRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async search(owner: SearchOwner, input: SearchInput): Promise<SearchRow[]> {
    const where = tenantWhere(owner.scope, { userId: owner.userId });
    const timeout = positiveInt(input.timeoutMs, 'MAX_EXECUTION_TIME');
    const scanMax = positiveInt(input.scanMax, 'scanMax');
    const take = positiveInt(input.take, 'take');
    const hint = Prisma.raw(`/*+ MAX_EXECUTION_TIME(${timeout}) */`);
    const keyset =
      input.beforeId === undefined ? Prisma.empty : Prisma.sql`AND m.id < ${input.beforeId}`;
    const sql = Prisma.sql`SELECT ${hint} m.id AS id, m.public_id AS publicId,
        m.organization_id AS organizationId, m.conversation_id AS conversationId,
        c.public_id AS conversationPublicId, c.title AS conversationTitle, c.user_id AS userId,
        m.role AS role, m.seq AS seq, m.created_at AS createdAt, m.content AS content
      FROM (
        SELECT rm.id FROM ai_chat_conversations rc
          JOIN ai_chat_messages rm ON rm.conversation_id = rc.id
        WHERE rc.organization_id = ${where.organizationId} AND rc.user_id = ${where.userId}
          AND rc.status IN ('active', 'archived')
          AND rm.organization_id = ${where.organizationId} AND rm.content IS NOT NULL
        ORDER BY rm.id DESC
        LIMIT ${scanMax}
      ) recent
      JOIN ai_chat_messages m ON m.id = recent.id
      JOIN ai_chat_conversations c ON c.id = m.conversation_id
      WHERE (m.content COLLATE utf8mb4_0900_ai_ci LIKE ${input.pattern} ESCAPE '!'
          OR (m.seq = 1 AND c.title COLLATE utf8mb4_0900_ai_ci LIKE ${input.pattern} ESCAPE '!'))
        ${keyset}
      ORDER BY m.id DESC
      LIMIT ${take}`;
    let raw: RawSearchRow[];
    try {
      raw = await this.reader.client.$queryRaw<RawSearchRow[]>(sql);
    } catch (err) {
      if (isQueryTimeout(err)) throw new SearchTimeoutError();
      throw err;
    }
    const rows = raw.map((r): SearchRow => {
      if ((r.role !== 'user' && r.role !== 'assistant') || r.content === null) {
        throw new InconsistentReadError('assistant.search');
      }
      return {
        id: BigInt(r.id),
        publicId: r.publicId,
        organizationId: BigInt(r.organizationId),
        conversationId: BigInt(r.conversationId),
        conversationPublicId: r.conversationPublicId,
        conversationTitle: r.conversationTitle,
        userId: BigInt(r.userId),
        role: r.role,
        seq: Number(r.seq),
        createdAt: r.createdAt,
        content: r.content,
      };
    });
    assertEcho('assistant.search', rows, {
      organizationId: where.organizationId,
      userId: where.userId,
    });
    if (input.beforeId !== undefined && rows.some((r) => r.id >= input.beforeId!)) {
      throw new InconsistentReadError('assistant.search');
    }
    return rows;
  }
}
