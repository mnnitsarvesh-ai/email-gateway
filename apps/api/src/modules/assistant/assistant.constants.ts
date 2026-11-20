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

/** Audit actions and resource types (D12). */
export const ASSISTANT_AUDIT = {
  toolExecuted: 'assistant.tool_executed',
  toolDenied: 'assistant.tool_denied',
  conversationDeleted: 'assistant.conversation_deleted',
  settingsUpdated: 'assistant.settings_updated',
} as const;
export const AUDIT_RESOURCE = {
  execution: 'assistant_tool_execution',
  conversation: 'assistant_conversation',
  settings: 'assistant_settings',
} as const;

/** UTC day `yyyymmdd` of the Redis keys and `YYYY-MM-DD` of the usage rows. */
export function utcDayKey(now: Date): string {
  return now.toISOString().slice(0, 10).replace(/-/g, '');
}
export function utcDayStart(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}
