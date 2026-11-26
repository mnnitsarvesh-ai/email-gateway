import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { MessageFeedbackView } from '../dto/assistant.schemas';
import type { Owner } from './conversations.repository';

/**
 * Step AI-6 D2: the caller's ratings of the assistant messages on a page of
 * `GET /assistant/conversations/{id}/messages` (owner view; replica, as the page). The feedback
 * routes and the admin list live in the assistant-insights module.
 */
@Injectable()
export class MessageFeedbackRepository {
  constructor(private readonly reader: PrismaReadService) {}

  /** Feedback by message id (organization, user and conversation of the owner). */
  async forMessages(
    owner: Owner,
    conversationId: bigint,
    messageIds: readonly bigint[],
  ): Promise<Map<bigint, MessageFeedbackView>> {
    if (messageIds.length === 0) return new Map();
    const rows = await this.reader.client.aiChatFeedback.findMany({
      where: {
        organizationId: owner.scope.organizationId,
        userId: owner.userId,
        conversationId,
        messageId: { in: [...messageIds] },
      },
      select: { messageId: true, rating: true, reason: true, comment: true },
    });
    return new Map(
      rows.map((row) => [
        row.messageId,
        { rating: row.rating, reason: row.reason, comment: row.comment },
      ]),
    );
  }
}
