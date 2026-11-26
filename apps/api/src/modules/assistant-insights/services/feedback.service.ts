import { Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { sanitizeUserText } from '../domain/search-text';
import { feedbackView } from '../domain/views';
import type { FeedbackView, SetFeedbackBody } from '../dto/insights.schemas';
import {
  FEEDBACK_COMMENT_MAX_CHARS,
  INSIGHTS_AUDIT,
  INSIGHTS_AUDIT_RESOURCE,
} from '../insights.constants';
import {
  assistantFeedbackContentPurged,
  assistantFeedbackNotAllowed,
  assistantMessageNotFound,
} from '../insights.errors';
import { InsightsMetrics } from '../insights-metrics';
import { FeedbackRepository, type OwnedMessage } from '../repositories/feedback.repository';

/** A stored comment: sanitized like user text, at most 500 characters; blank = none. */
export function commentOf(raw: string | undefined): string | null {
  if (raw === undefined) return null;
  const cleaned = sanitizeUserText(raw);
  if (cleaned.length === 0) return null;
  return Array.from(cleaned).slice(0, FEEDBACK_COMMENT_MAX_CHARS).join('');
}

/**
 * Ratings of assistant answers (step AI-6 D2): `PUT` / `DELETE
 * /assistant/messages/{messageId}/feedback`. Only the author rates: the message must be an
 * `assistant` message of the caller's own non-deleted conversation (owner scope as the
 * conversation routes; otherwise `404 assistant_message_not_found`) whose turn `completed`
 * (`409 assistant_feedback_not_allowed`), in a conversation whose content was not purged (the
 * same `409`: the comment is content, and a purge that already ran never clears it; checked
 * under a shared lock of the conversation row, see `lockContentPurged`). One row per message (upsert in one writer transaction
 * with the audit row). Audited `assistant.feedback_recorded` / `assistant.feedback_removed` with
 * `{ messageId, conversationId, rating, reason }`: never the comment. Metric
 * `assistant_feedback_total{rating}`.
 */
@Injectable()
export class AssistantFeedbackService {
  constructor(
    private readonly repository: FeedbackRepository,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly metrics: InsightsMetrics,
  ) {}

  async set(
    principal: UserPrincipal,
    scope: TenantScope,
    messagePublicId: string,
    body: SetFeedbackBody,
    sourceIp: string | null,
  ): Promise<FeedbackView> {
    const view = await this.runner.run(async (tx) => {
      const message = await this.ratable(principal, scope, messagePublicId, tx);
      const row = await this.repository.upsert(
        scope,
        {
          publicId: uuidv7(),
          userId: principal.userId,
          conversationId: message.conversationId,
          turnId: message.turnId,
          messageId: message.id,
          rating: body.rating,
          reason: body.reason ?? null,
          comment: commentOf(body.comment),
        },
        tx,
      );
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: INSIGHTS_AUDIT.feedbackRecorded,
          resourceType: INSIGHTS_AUDIT_RESOURCE.feedback,
          resourceId: row.publicId,
          sourceIp,
          metadata: {
            messageId: message.publicId,
            conversationId: message.conversationPublicId,
            rating: row.rating,
            reason: row.reason,
          },
        },
        tx,
      );
      return feedbackView(row, message.publicId);
    });
    this.metrics.feedback.inc({ rating: view.rating });
    return view;
  }

  async remove(
    principal: UserPrincipal,
    scope: TenantScope,
    messagePublicId: string,
    sourceIp: string | null,
  ): Promise<void> {
    await this.runner.run(async (tx) => {
      const message = await this.repository.findOwnedMessage(
        { scope, userId: principal.userId },
        messagePublicId,
        tx,
      );
      if (!message || message.role !== 'assistant') throw assistantMessageNotFound();
      const existing = await this.repository.findByMessage(scope, message.id, tx);
      if (!existing || !(await this.repository.remove(scope, existing.id, tx))) {
        throw assistantMessageNotFound();
      }
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: INSIGHTS_AUDIT.feedbackRemoved,
          resourceType: INSIGHTS_AUDIT_RESOURCE.feedback,
          resourceId: existing.publicId,
          sourceIp,
          metadata: {
            messageId: message.publicId,
            conversationId: message.conversationPublicId,
            rating: existing.rating,
            reason: existing.reason,
          },
        },
        tx,
      );
    });
  }

  /** The message the caller may rate, or the coded refusal. */
  private async ratable(
    principal: UserPrincipal,
    scope: TenantScope,
    messagePublicId: string,
    tx: Parameters<Parameters<TransactionRunner['run']>[0]>[0],
  ): Promise<OwnedMessage> {
    const message = await this.repository.findOwnedMessage(
      { scope, userId: principal.userId },
      messagePublicId,
      tx,
    );
    if (!message || message.role !== 'assistant') throw assistantMessageNotFound();
    if (message.turnStatus !== 'completed') throw assistantFeedbackNotAllowed();
    if (await this.repository.lockContentPurged(scope.organizationId, message.conversationId, tx)) {
      throw assistantFeedbackContentPurged();
    }
    return message;
  }
}
