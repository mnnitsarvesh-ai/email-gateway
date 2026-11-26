import { Injectable } from '@nestjs/common';
import type { PseudonymEntry } from '@email-gateway/assistant';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { Owner } from './conversations.repository';

type Tx = Prisma.TransactionClient;

/**
 * `ai_chat_pseudonyms` (step AI-6 §3, D3, I25): the per-conversation mapping of the
 * `pseudonymized` data-sharing level (token, kind, the real value as content, its SHA-256). Read
 * at turn start (writer: the turn lock makes the numbering race-free), the new entries of a turn
 * inserted in its finish transaction, and the rows deleted with the conversation's content
 * purge (`ConversationsRepository.purgeContent`) and the organization purge.
 */
@Injectable()
export class PseudonymsRepository {
  constructor(private readonly writer: PrismaService) {}

  /** The conversation's mapping (oldest first; at most `take` rows: the cap). */
  async load(owner: Owner, conversationId: bigint, take: number): Promise<PseudonymEntry[]> {
    const rows = await this.writer.aiChatPseudonym.findMany({
      where: { organizationId: owner.scope.organizationId, conversationId },
      orderBy: { id: 'asc' },
      take,
      select: { kind: true, token: true, value: true, valueSha256: true },
    });
    return rows.map((row) => ({
      kind: row.kind,
      token: row.token,
      value: row.value,
      valueSha256: row.valueSha256,
    }));
  }

  /** The new entries of a turn (inside its finish transaction). */
  async insert(
    owner: Owner,
    conversationId: bigint,
    entries: readonly PseudonymEntry[],
    now: Date,
    tx: Tx,
  ): Promise<void> {
    if (entries.length === 0) return;
    await tx.aiChatPseudonym.createMany({
      data: entries.map((entry) => ({
        organizationId: owner.scope.organizationId,
        conversationId,
        kind: entry.kind,
        token: entry.token,
        value: entry.value,
        valueSha256: entry.valueSha256,
        createdAt: now,
      })),
    });
  }
}
