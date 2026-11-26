import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/**
 * Stable error codes of the insights routes (contracts §35.6). Another user's or another
 * organization's messages and conversations answer like unknown ids. Messages are fixed texts.
 */
export const INSIGHTS_ERROR_CODES = {
  messageNotFound: 'assistant_message_not_found',
  feedbackNotAllowed: 'assistant_feedback_not_allowed',
  searchTimeout: 'assistant_search_timeout',
  adminConversationNotFound: 'assistant_admin_conversation_not_found',
} as const;

const C = INSIGHTS_ERROR_CODES;

/** An unknown message, one of another user, organization or a deleted conversation, a user
 * message, or (DELETE) a message without feedback. */
export const assistantMessageNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, C.messageNotFound, 'Message not found');

/** The answer's turn did not complete (failed, cancelled or still running). */
export const assistantFeedbackNotAllowed = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.feedbackNotAllowed,
    'Only answers of completed turns can be rated',
  );

/**
 * The conversation's content was purged (D2, I24): a rating (and its comment, which is content)
 * would outlive the purge that already ran.
 */
export const assistantFeedbackContentPurged = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.feedbackNotAllowed,
    'Answers of a conversation whose content was purged cannot be rated',
  );

/** The search statement hit `MAX_EXECUTION_TIME` (MySQL 3024). */
export const assistantSearchTimeout = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    C.searchTimeout,
    'The search took too long; use more specific words or retry later',
  );

export const assistantAdminConversationNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    C.adminConversationNotFound,
    'Conversation not found',
  );

/** Thrown by the search repository on a 3024; the service maps it and counts it. */
export class SearchTimeoutError extends Error {
  override readonly name = 'SearchTimeoutError';
  constructor() {
    super('assistant search exceeded MAX_EXECUTION_TIME');
  }
}
