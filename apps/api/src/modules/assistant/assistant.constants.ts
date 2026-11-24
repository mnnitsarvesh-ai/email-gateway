import type { ApiConfig } from '../../config';

/**
 * Constants of the AI assistant module (step AI-1, docs/plan/steps/28-ai-chat-management.md D2,
 * D5, D7, D11, D12, §3, §4; contracts §35; ADR-0091–0094).
 */

export const ASSISTANT_PERMISSIONS = {
  use: 'assistant:use',
  configure: 'assistant:configure',
} as const;

/** The operator-enabled organization feature (D13). */
export const ASSISTANT_FEATURE = 'ai_assistant';

/** The api config keys the module reads. */
export type AssistantConfig = Pick<
  ApiConfig,
  | 'NODE_ENV'
  | 'HTTP_PORT'
  | 'API_TRUSTED_FORWARDER_TOKEN'
  | 'AUTH_TOKEN_PEPPER'
  | 'ASSISTANT_ENABLED'
  | 'ASSISTANT_PROVIDER'
  | 'ASSISTANT_MODEL'
  | 'ASSISTANT_EFFORT'
  | 'ASSISTANT_REFUSAL_FALLBACK'
  | 'ASSISTANT_ANTHROPIC_API_KEY'
  | 'ASSISTANT_ANTHROPIC_BASE_URL'
  | 'ASSISTANT_OPENAI_API_KEY'
  | 'ASSISTANT_OPENAI_BASE_URL'
  | 'ASSISTANT_AZURE_OPENAI_ENDPOINT'
  | 'ASSISTANT_AZURE_OPENAI_API_KEY'
  | 'ASSISTANT_AZURE_OPENAI_DEPLOYMENT'
  | 'ASSISTANT_AZURE_OPENAI_API_VERSION'
  | 'ASSISTANT_TIMEOUT_MS'
  | 'ASSISTANT_TURN_DEADLINE_MS'
  | 'ASSISTANT_MAX_OUTPUT_TOKENS'
  | 'ASSISTANT_MAX_TOOL_ROUNDS'
  | 'ASSISTANT_MAX_TOOL_CALLS_PER_TURN'
  | 'ASSISTANT_TOOL_TIMEOUT_MS'
  | 'ASSISTANT_TOOL_RESULT_MAX_BYTES'
  | 'ASSISTANT_TOOL_RESULT_MAX_ROWS'
  | 'ASSISTANT_CONTEXT_MAX_TOKENS'
  | 'ASSISTANT_USER_MESSAGE_MAX_CHARS'
  | 'ASSISTANT_TURNS_PER_USER_PER_MINUTE'
  | 'ASSISTANT_MAX_CONCURRENT_TURNS'
  | 'ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT'
  | 'ASSISTANT_TENANT_DAILY_TOKENS_MAX'
  | 'ASSISTANT_PLATFORM_DAILY_TOKENS'
  | 'ASSISTANT_RETENTION_DEFAULT_DAYS'
  | 'ASSISTANT_EXECUTION_RETENTION_DAYS'
  | 'ASSISTANT_MAX_CONVERSATIONS_PER_USER'
  | 'ASSISTANT_LOOPBACK_URL'
  | 'ASSISTANT_BACKGROUND_JOBS_ENABLED'
  | 'ASSISTANT_BREAKER_THRESHOLD'
  | 'ASSISTANT_BREAKER_RESET_MS'
  | 'ASSISTANT_MODEL_PRICES'
  | 'ASSISTANT_CONFIRMATION_TTL_SECONDS'
  | 'ASSISTANT_REAUTH_WINDOW_SECONDS'
  | 'ASSISTANT_MAX_PENDING_CONFIRMATIONS'
  | 'ASSISTANT_REPORTS_ENABLED'
  | 'ASSISTANT_REPORT_EMAIL_ENABLED'
  | 'ASSISTANT_REPORTS_PER_USER_PER_DAY'
  | 'ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY'
  | 'ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY'
  | 'ASSISTANT_REPORT_MAX_HTML_BYTES'
  | 'REPORTS_MAX_RANGE_DAYS'
>;

/** Redis keys (prefix `as:`, contracts §35). */
export const assistantKeys = {
  /** Turn lock of a conversation (TTL = turn deadline + 10 s); value = the turn public id. */
  turnLock: (conversationPublicId: string): string => `as:turn:${conversationPublicId}`,
  /** Cross-pod cancellation flag of a running turn (TTL = turn deadline + 10 s). */
  turnCancel: (turnPublicId: string): string => `as:turn:cancel:${turnPublicId}`,
  /** Turns per user per minute (window of 60 s). */
  userWindow: (userPublicId: string, minute: number): string => `as:rl:u:${userPublicId}:${minute}`,
  /** Tenant tokens of a UTC day (TTL 48 h, seeded from ai_chat_usage_daily on a miss). */
  tenantTokens: (organizationId: bigint, day: string): string =>
    `as:tok:o:${organizationId}:${day}`,
  /** Platform tokens of a UTC day. */
  platformTokens: (day: string): string => `as:tok:p:${day}`,
  /** Retention purge and stale-turn sweeper (one api replica at a time). */
  jobsLock: 'as:jobs:lock',
  /**
   * The assistant re-authentication window of a session family (step AI-2 D2 step 9; value `1`,
   * TTL ASSISTANT_REAUTH_WINDOW_SECONDS): set only after a successful re-authentication of an
   * assistant confirmation, honoured only by assistant confirmations.
   */
  reauthWindow: (sessionFamilyId: string): string => `as:reauth:${sessionFamilyId}`,
} as const;

/** Breaker keys `as:brk:<provider>` (package `ProviderBreaker`). */
export const BREAKER_KEY_PREFIX = 'as:brk:';

export const TOKEN_COUNTER_TTL_SECONDS = 48 * 3600;
export const TURN_LOCK_GRACE_SECONDS = 10;
/** A running turn older than its deadline plus this is abandoned (sweeper). */
export const TURN_ABANDON_GRACE_MS = 60_000;

/** Stored text caps (D7, D9, §3). */
export const ASSISTANT_TEXT_MAX_CHARS = 16_000;
export const TRANSCRIPT_MAX_BYTES = 512 * 1024;
export const PARAMS_REDACTED_MAX_BYTES = 4096;
export const AUDIT_PARAMS_MAX_BYTES = 2048;
export const TITLE_MAX_CHARS = 200;
/** Title derived from the first user message. */
export const DERIVED_TITLE_MAX_CHARS = 80;

/** Loopback (D2). */
export const LOOPBACK_BODY_MAX_BYTES = 1024 * 1024;
export const LOOPBACK_USER_AGENT = 'eg-assistant/1';
export const EXECUTION_HEADER = 'x-eg-assistant-execution';
export const CORRELATION_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;

/** Parallel `call_tool`s of one model response (D5). */
export const TOOL_CALL_CONCURRENCY = 4;

/** Retention job (D12). */
export const RETENTION_INTERVAL_MS = 10 * 60_000;
export const RETENTION_LOCK_SECONDS = 9 * 60;
export const RETENTION_CONVERSATION_BATCH = 100;
export const RETENTION_DELETE_BATCH = 1000;

/** Usage route window (§4.1). */
export const USAGE_MAX_RANGE_DAYS = 92;
export const USAGE_DEFAULT_RANGE_DAYS = 30;

/** v1 cursor resources. */
export const CONVERSATIONS_CURSOR_RESOURCE = 'assistant_conversations';
export const MESSAGES_CURSOR_RESOURCE = 'assistant_messages';

/** Audit actions and resource types (D12; step AI-2 D11). */
export const ASSISTANT_AUDIT = {
  toolExecuted: 'assistant.tool_executed',
  toolDenied: 'assistant.tool_denied',
  conversationDeleted: 'assistant.conversation_deleted',
  settingsUpdated: 'assistant.settings_updated',
  confirmationRequested: 'assistant.confirmation_requested',
  confirmationExecuted: 'assistant.confirmation_executed',
  confirmationFailed: 'assistant.confirmation_failed',
  confirmationCancelled: 'assistant.confirmation_cancelled',
  confirmationExpired: 'assistant.confirmation_expired',
  confirmationRefused: 'assistant.confirmation_refused',
  // Step AI-R D11.
  reportGenerated: 'assistant.report_generated',
  reportEmailRequested: 'assistant.report_email_requested',
} as const;
export const AUDIT_RESOURCE = {
  execution: 'assistant_tool_execution',
  conversation: 'assistant_conversation',
  settings: 'assistant_settings',
  confirmation: 'assistant_action_confirmation',
  // Step AI-R D11.
  report: 'assistant_report',
  delivery: 'assistant_report_delivery',
} as const;

/** Reports (step AI-R, docs/plan/steps/31-ai-chat-reports.md D2, D6, D7). */
/** Concurrent source reads of one `report_generate` (D2 step 5). */
export const REPORT_SOURCE_CONCURRENCY = 4;
/** Object key prefix below `org/<organizationId>/` (D6). */
export const REPORT_OBJECT_PREFIX = 'assistant/report/';
/** Content type of a stored report (D6). */
export const REPORT_CONTENT_TYPE = 'text/html; charset=utf-8';
/** A `pending` report older than this is abandoned (crash between the put and the commit, D7). */
export const REPORT_PENDING_MAX_AGE_MS = 60 * 60_000;
/** A `queued` delivery older than this failed (beyond the notification queue's 24 h, D7). */
export const REPORT_DELIVERY_TIMEOUT_MS = 25 * 60 * 60_000;
/** Deliveries listed in a report view, newest first (§4.1). */
export const REPORT_VIEW_DELIVERIES = 20;
/** Report objects deleted per retention batch (D7). */
export const REPORT_OBJECT_BATCH = 100;
/** Outbox aggregate type of a report email (§3, §4.3). */
export const REPORT_DELIVERY_AGGREGATE_TYPE = 'assistant_report_delivery';
/** Row error codes of reports and deliveries (D2, D7; never answer a request). */
export const REPORT_ROW_CODES = {
  storageFailed: 'assistant_report_storage_failed',
  abandoned: 'assistant_report_abandoned',
  purged: 'assistant_report_purged',
  emailTimeout: 'assistant_report_email_timeout',
} as const;

/** Confirmations (step AI-2 D1, D2, D6, D7). */
/** Wrong tokens that cancel a confirmation (the fifth). */
export const CONFIRMATION_TOKEN_ATTEMPTS = 5;
/** Terminal confirmations reported to the model per turn (oldest first). */
export const CONFIRMATION_REPORT_BATCH = 20;
/** Violations of an invalid policy definition listed in the proposal's error envelope. */
export const DEFINITION_VIOLATIONS_MAX = 20;
/**
 * Grace of the outcome-unknown sweep (D7, step AI-2 review): an `executing` confirmation is
 * `failed` (outcome unknown) when its write started more than ASSISTANT_TOOL_TIMEOUT_MS plus this
 * ago, or, before the write started, when its precondition re-read began more than
 * (PRECONDITION_MAX_READS + 1) × ASSISTANT_TOOL_TIMEOUT_MS plus this ago (sequential reads).
 */
export const CONFIRMATION_EXECUTING_GRACE_MS = 60_000;
/** Stored request `{ method, path, body, params }` (JSON bytes). */
export const CONFIRMATION_REQUEST_MAX_BYTES = 256 * 1024;
/** Stored preconditions (JSON bytes). */
export const CONFIRMATION_PRECONDITIONS_MAX_BYTES = 16 * 1024;

/** UTC day `yyyymmdd` of the Redis keys and `YYYY-MM-DD` of the usage rows. */
export function utcDayKey(now: Date): string {
  return now.toISOString().slice(0, 10).replace(/-/g, '');
}
export function utcDayStart(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}
