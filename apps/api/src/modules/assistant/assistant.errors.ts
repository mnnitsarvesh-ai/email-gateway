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
  // Confirmations (step AI-2 §4.1).
  confirmationNotFound: 'assistant_confirmation_not_found',
  confirmationSessionMismatch: 'assistant_confirmation_session_mismatch',
  confirmationNotPending: 'assistant_confirmation_not_pending',
  confirmationExpired: 'assistant_confirmation_expired',
  confirmationTokenInvalid: 'assistant_confirmation_token_invalid',
  confirmationDigestMismatch: 'assistant_confirmation_digest_mismatch',
  confirmationToolChanged: 'assistant_confirmation_tool_changed',
  confirmationStateChanged: 'assistant_confirmation_state_changed',
  reauthRequired: 'assistant_reauth_required',
  reauthFailed: 'assistant_reauth_failed',
  // Step AI-3 D3/D10: a proposal guard refused the change at confirm (403).
  actionNotAllowed: 'assistant_action_not_allowed',
  // Step AI-R §4.1: `GET /assistant/reports/{reportId}` of another user or organization (404).
  reportNotFound: 'assistant_report_not_found',
  // Step AI-6 §4.1 (contracts §35.6).
  tenantKeysDisabled: 'assistant_tenant_keys_disabled',
  tenantKeyRejected: 'assistant_tenant_key_rejected',
  tenantKeyUnverified: 'assistant_tenant_key_unverified',
  tenantKeyNotFound: 'assistant_tenant_key_not_found',
  tenantKeyInvalid: 'assistant_tenant_key_invalid',
  messageNotFound: 'assistant_message_not_found',
  feedbackNotAllowed: 'assistant_feedback_not_allowed',
  searchTimeout: 'assistant_search_timeout',
  adminConversationNotFound: 'assistant_admin_conversation_not_found',
  reportNotReady: 'assistant_report_not_ready',
} as const;

/**
 * Step AI-6 D5: the stored `error_code` of a failed or expired report job (and its report).
 * Never the answer of a request.
 */
export const REPORT_JOB_CODES = {
  expired: 'assistant_report_job_expired',
  sessionEnded: 'assistant_report_session_ended',
  notAllowed: 'assistant_report_not_allowed',
  /** The conversation's content was purged while the job waited (report `purged`). */
  cancelled: 'assistant_report_purged',
  /**
   * An unexpected failure (or a crash) of the last attempt: the job ran REPORT_JOB_MAX_ATTEMPTS
   * times without an outcome (also the requeue code of an earlier unexpected failure).
   */
  failed: 'assistant_report_job_failed',
} as const;

/**
 * Step AI-6 D3: the executor's refusal of a tool-call argument with a placeholder unknown in this
 * conversation (decision `denied_schema`). Same value as the package's `UNKNOWN_PLACEHOLDER_CODE`.
 */
export const UNKNOWN_PLACEHOLDER_ERROR = 'assistant_unknown_placeholder';
export const unknownPlaceholderMessage = (token: string): string =>
  `Unknown placeholder ${token}; use a value from this conversation.`;

/**
 * Codes of the native report tools (step AI-R §4.1, design 31 D2, D5): the error envelope and
 * card of a failed `report_generate` / `report_send_email` execution or proposal, the `code` of a
 * `denied_budget` refusal, and the stored `error_code` of the execution. They never answer a
 * route of their own (the report route answers only `404 assistant_report_not_found`).
 */
export const REPORT_ERROR_CODES = {
  notFound: 'assistant_report_not_found',
  purged: 'assistant_report_purged',
  tooLarge: 'assistant_report_too_large',
  generationLimit: 'assistant_report_generation_limit',
  emailLimit: 'assistant_report_email_limit',
  sourcesUnavailable: 'assistant_report_sources_unavailable',
  storageFailed: 'assistant_report_storage_failed',
  invalidWindow: 'assistant_report_invalid_window',
  // Step AI-6 D5: `report_send_email` on a report that is not `available` yet.
  notReady: 'assistant_report_not_ready',
} as const;

/** The HTTP status each report code is recorded with (§4.1). */
export const REPORT_ERROR_STATUS: Readonly<Record<string, number>> = {
  assistant_report_not_found: 404,
  assistant_report_purged: 410,
  assistant_report_too_large: 413,
  assistant_report_generation_limit: 429,
  assistant_report_email_limit: 429,
  assistant_report_sources_unavailable: 503,
  assistant_report_storage_failed: 502,
  assistant_report_not_ready: 409,
};

/**
 * Guard codes of the native report tools (decision `denied_guard`, audit metadata `guard`):
 * server rules that refuse the call before anything is read, stored or sent.
 */
export const REPORT_GUARDS = {
  recipientNotAllowed: 'report_recipient_not_allowed',
  needsOrganization: 'report_needs_organization',
} as const;
export type ReportGuard = (typeof REPORT_GUARDS)[keyof typeof REPORT_GUARDS];

/** The fixed messages of the report guards (design 31 D2 step 1, D5 step 2). */
export const REPORT_GUARD_MESSAGES: Readonly<Record<ReportGuard, string>> = {
  report_recipient_not_allowed:
    'Reports can be emailed only to your own address, to active users of your organization or to addresses in its verified domains.',
  report_needs_organization:
    'Reports are built for one organization; start a platform override first.',
};

/**
 * Codes that never answer a request (step AI-2 §4.1): the error envelope of a failed proposal
 * and the `error_code` of confirmation rows.
 */
export const CONFIRMATION_ROW_CODES = {
  /** Proposal envelope: the policy definition failed `POST /policies/validate` (422). */
  definitionInvalid: 'assistant_definition_invalid',
  /** Proposal envelope: the precondition read did not return the row version to inject (502). */
  preconditionUnavailable: 'assistant_precondition_unavailable',
  /** Row: five wrong tokens cancelled the confirmation. */
  tokenLocked: 'assistant_confirmation_token_locked',
  /** Row: `executing` past the tool timeout (a crash); never re-executed. */
  outcomeUnknown: 'assistant_confirmation_outcome_unknown',
} as const;

/** `details.reason` of `401 assistant_reauth_failed` (ReauthenticationService reasons). */
export type ReauthFailureReason = 'password' | 'totp' | 'totp_required' | 'locked' | 'inactive';

/** Turn failure codes (contracts §35). `assistant_internal_error` covers an unexpected fault. */
export const TURN_FAILURE_CODES = {
  sessionExpired: 'assistant_session_expired',
  turnLimit: 'assistant_turn_limit',
  refused: 'assistant_refused',
  abandoned: 'assistant_turn_abandoned',
  providerError: 'assistant_provider_error',
  internalError: 'assistant_internal_error',
  /** Step AI-6 D6: the tenant key was refused (401/403) and no platform fallback is allowed. */
  tenantKeyInvalid: 'assistant_tenant_key_invalid',
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
  assistant_tenant_key_invalid:
    'Your organization’s AI provider key was refused by the provider. An administrator must replace it.',
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
  scope: 'tenant' | 'platform' | 'user',
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

// ---- confirmations (step AI-2 D2, §4.1) ----------------------------------------------------------

export const confirmationNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.confirmationNotFound, 'Confirmation not found');

export const confirmationSessionMismatch = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.confirmationSessionMismatch,
    'This confirmation belongs to another sign-in session; ask the assistant again here',
  );

export const confirmationNotPending = (status: string): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.confirmationNotPending, 'This confirmation is no longer pending', {
    status,
  });

export const confirmationExpired = (): CodedHttpException =>
  err(
    HttpStatus.GONE,
    C.confirmationExpired,
    'This confirmation expired; ask the assistant again to see the current state',
  );

export const confirmationTokenInvalid = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.confirmationTokenInvalid,
    'The confirmation token is not valid for this confirmation',
  );

export const confirmationDigestMismatch = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.confirmationDigestMismatch,
    'actionDigest does not match the action that was proposed',
  );

export const confirmationToolChanged = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.confirmationToolChanged,
    'The operation of this confirmation is no longer available to the assistant',
  );

export const confirmationStateChanged = (httpStatus: number | null = null): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.confirmationStateChanged,
    'The record changed since this was proposed; ask again to see the current state',
    httpStatus === null ? {} : { httpStatus },
  );

/** Step AI-3 D10: a proposal guard refused the confirmed change (I12; the row fails). */
export const assistantActionNotAllowed = (): CodedHttpException =>
  err(HttpStatus.FORBIDDEN, C.actionNotAllowed, 'This change is not allowed in chat.');

/** Step AI-R §4.1: an unknown report, or one of another user, organization or override. */
export const assistantReportNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.reportNotFound, 'Report not found');

export const assistantReauthRequired = (): CodedHttpException =>
  err(
    HttpStatus.UNAUTHORIZED,
    C.reauthRequired,
    'This change needs your password (and verification code) again',
  );

export const assistantReauthFailed = (reason: ReauthFailureReason): CodedHttpException =>
  err(
    HttpStatus.UNAUTHORIZED,
    C.reauthFailed,
    'Password or verification code is incorrect, or the account cannot re-authenticate',
    { reason },
  );

// ---- step AI-6 (contracts §35.6) ------------------------------------------------------------------

/** The platform gate `ASSISTANT_TENANT_KEYS_ENABLED` is off. */
export const assistantTenantKeysDisabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.tenantKeysDisabled,
    'Organization provider keys are not offered on this platform',
  );

/** The probe was answered 401/403: the key is not accepted by the provider (nothing stored). */
export const assistantTenantKeyRejected = (
  details: ConstructorParameters<typeof CodedHttpException>[3] = {},
): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.tenantKeyRejected,
    'The AI provider did not accept this key for the selected model',
    details,
  );

/** The probe failed for another reason (network, timeout, 5xx): nothing stored. */
export const assistantTenantKeyUnverified = (): CodedHttpException =>
  err(
    HttpStatus.BAD_GATEWAY,
    C.tenantKeyUnverified,
    'The key could not be verified with the AI provider; try again later',
  );

export const assistantTenantKeyNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.tenantKeyNotFound, 'No provider key is stored');

/** A turn whose tenant key is not usable and the tenant allows no platform fallback. */
export const assistantTenantKeyInvalid = (): CodedHttpException =>
  err(
    HttpStatus.SERVICE_UNAVAILABLE,
    C.tenantKeyInvalid,
    'Your organization’s AI provider key is not valid; an administrator must replace it',
  );

export const assistantMessageNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.messageNotFound, 'Message not found');

export const assistantFeedbackNotAllowed = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.feedbackNotAllowed,
    'Only answers of the assistant in completed turns can be rated',
  );

export const assistantSearchTimeout = (): CodedHttpException =>
  err(
    HttpStatus.SERVICE_UNAVAILABLE,
    C.searchTimeout,
    'The search took too long; use a more specific text',
  );

export const assistantAdminConversationNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.adminConversationNotFound, 'Conversation not found');
