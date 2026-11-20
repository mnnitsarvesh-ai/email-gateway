import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/**
 * Stable error codes of the assistant routes (contracts §35, design §4.1) and the turn failure
 * codes (stream `turn.failed` and stored `ai_chat_turns.error_code`). Another user's or another
 * organization's conversations and executions answer like unknown ids. Messages are fixed texts;
 * details carry codes, scopes and versions only.
 */
export const ASSISTANT_ERROR_CODES = {
  disabled: 'assistant_disabled',
  notEnabled: 'assistant_not_enabled',
  tenantDisabled: 'assistant_tenant_disabled',
  providerUnavailable: 'assistant_provider_unavailable',
  busy: 'assistant_busy',
  budgetExhausted: 'assistant_budget_exhausted',
  turnInProgress: 'assistant_turn_in_progress',
  conversationLimit: 'assistant_conversation_limit',
  conversationNotFound: 'assistant_conversation_not_found',
  executionNotFound: 'assistant_execution_not_found',
  turnNotFound: 'assistant_turn_not_found',
  noMoreResults: 'assistant_no_more_results',
  settingsConflict: 'assistant_settings_conflict',
} as const;

/** Turn failure codes (contracts §35). `assistant_internal_error` covers an unexpected fault. */
export const TURN_FAILURE_CODES = {
  sessionExpired: 'assistant_session_expired',
  turnLimit: 'assistant_turn_limit',
  refused: 'assistant_refused',
  abandoned: 'assistant_turn_abandoned',
  providerError: 'assistant_provider_error',
  internalError: 'assistant_internal_error',
} as const;
export type TurnFailureCode = (typeof TURN_FAILURE_CODES)[keyof typeof TURN_FAILURE_CODES];

/** Fixed user-facing messages of the turn failures (never provider or tool text). */
export const TURN_FAILURE_MESSAGES: Readonly<Record<TurnFailureCode, string>> = {
  assistant_session_expired: 'Your session expired during the answer. Sign in again and retry.',
  assistant_turn_limit: 'The answer needed more steps or time than one turn allows.',
  assistant_refused: 'The assistant declined to answer this request.',
  assistant_turn_abandoned: 'The answer was interrupted by a server restart. Retry the message.',
  assistant_provider_error: 'The AI provider could not answer. Retry in a moment.',
  assistant_internal_error: 'The assistant failed unexpectedly. Retry in a moment.',
};

const C = ASSISTANT_ERROR_CODES;
const err = (
  status: HttpStatus,
  code: string,
  message: string,
  details: ConstructorParameters<typeof CodedHttpException>[3] = {},
): CodedHttpException => new CodedHttpException(status, code, message, details);

/** A coded error that also asks for `Retry-After` (read by `applyCodedHeaders`). */
export class RetryableCodedException extends CodedHttpException {
  constructor(
    status: HttpStatus,
    code: string,
    message: string,
    details: ConstructorParameters<typeof CodedHttpException>[3],
    readonly retryAfterSeconds: number,
  ) {
    super(status, code, message, details);
  }
}

export const assistantDisabled = (): CodedHttpException =>
  err(HttpStatus.SERVICE_UNAVAILABLE, C.disabled, 'The AI assistant is disabled on this platform');

export const assistantNotEnabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.notEnabled,
    'The AI assistant is not enabled for this organization (feature ai_assistant)',
  );

export const assistantTenantDisabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.tenantDisabled,
    'The AI assistant is turned off in the organization settings',
  );

export const assistantProviderUnavailable = (): CodedHttpException =>
  err(
    HttpStatus.SERVICE_UNAVAILABLE,
    C.providerUnavailable,
    'The AI provider is temporarily unavailable',
  );

export const assistantBusy = (): CodedHttpException =>
  new RetryableCodedException(
    HttpStatus.SERVICE_UNAVAILABLE,
    C.busy,
    'The assistant is busy; retry in a moment',
    {},
    5,
  );

export const assistantBudgetExhausted = (
  scope: 'tenant' | 'platform',
  retryAfterSeconds: number,
): CodedHttpException =>
  new RetryableCodedException(
    HttpStatus.TOO_MANY_REQUESTS,
    C.budgetExhausted,
    'The daily AI token budget is used up',
    { scope },
    retryAfterSeconds,
  );

export const assistantTurnInProgress = (): CodedHttpException =>
  new RetryableCodedException(
    HttpStatus.CONFLICT,
    C.turnInProgress,
    'Another answer is still running in this conversation',
    {},
    2,
  );

export const assistantConversationLimit = (limit: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.conversationLimit,
    'You have the maximum number of assistant conversations; delete one first',
    { limit },
  );

export const assistantConversationNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.conversationNotFound, 'Conversation not found');

export const assistantExecutionNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.executionNotFound, 'Tool execution not found');

export const assistantTurnNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.turnNotFound, 'Turn not found');

export const assistantNoMoreResults = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.noMoreResults, 'This result has no further page');

export const assistantSettingsConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.settingsConflict,
    'expectedRowVersion is not the current version of the assistant settings',
    { currentRowVersion },
  );

/** `429 rate_limited` of the per-user turn window (`scope: route`, like other route limits). */
export const assistantUserRateLimited = (retryAfterSeconds: number): CodedHttpException =>
  new RetryableCodedException(
    HttpStatus.TOO_MANY_REQUESTS,
    'rate_limited',
    'Too many requests',
    { scope: 'route' },
    retryAfterSeconds,
  );
