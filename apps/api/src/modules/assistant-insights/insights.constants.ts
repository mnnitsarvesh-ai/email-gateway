import type { ApiConfig } from '../../config';

/**
 * Constants of the AI assistant insights module (step AI-6 WP4,
 * docs/plan/steps/34-ai-chat-hardening-operations.md D1, D2, D4, I24; contracts §35.6): the
 * owner's content search, ratings of assistant answers, the tenant administration reads (usage per
 * user and day, feedback) and the metadata-only conversation audit view.
 */

export const INSIGHTS_PERMISSIONS = {
  use: 'assistant:use',
  configure: 'assistant:configure',
  auditRead: 'audit:read',
} as const;

/** The api config keys the module reads. */
export type InsightsConfig = Pick<
  ApiConfig,
  'ASSISTANT_SEARCH_SCAN_MAX_MESSAGES' | 'ASSISTANT_SEARCH_TIMEOUT_MS'
>;

/** Admin and audit windows (D1, D2, D4): at most 92 days; default the last 30 days. */
export const INSIGHTS_MAX_RANGE_DAYS = 92;
export const INSIGHTS_DEFAULT_RANGE_DAYS = 30;

/** Content search (D4). */
export const SEARCH_QUERY_MIN_CHARS = 2;
export const SEARCH_QUERY_MAX_CHARS = 200;
export const SEARCH_DEFAULT_LIMIT = 20;
export const SEARCH_MAX_LIMIT = 50;
export const SNIPPET_MAX_CHARS = 160;
/** The `LIKE … ESCAPE` character of the search (never a character with a SQL meaning). */
export const LIKE_ESCAPE = '!';

/** Feedback (D2). */
export const FEEDBACK_COMMENT_MAX_CHARS = 500;
export const FEEDBACK_REASONS = [
  'incorrect',
  'incomplete',
  'not_helpful',
  'wrong_action',
  'unsafe',
  'too_slow',
  'other',
] as const;
export type FeedbackReason = (typeof FEEDBACK_REASONS)[number];
export const FEEDBACK_RATINGS = ['up', 'down'] as const;
export type FeedbackRating = (typeof FEEDBACK_RATINGS)[number];

/** Rows of each array of the audit detail (D4); `truncated` tells when a conversation had more. */
export const AUDIT_DETAIL_MAX_ROWS = 1000;
/** Distinct tool names listed per feedback row (the turn's tool calls, D2). */
export const FEEDBACK_TOOLS_MAX = 32;

/** v1 cursor resources. */
export const CURSOR_RESOURCES = {
  search: 'assistant_search',
  usageByUser: 'assistant_admin_usage_users',
  feedback: 'assistant_admin_feedback',
  conversations: 'assistant_admin_conversations',
  executions: 'assistant_admin_executions',
} as const;

/** Audit actions and resource types (contracts §35.6). */
export const INSIGHTS_AUDIT = {
  feedbackRecorded: 'assistant.feedback_recorded',
  feedbackRemoved: 'assistant.feedback_removed',
  auditViewed: 'assistant.audit_viewed',
} as const;
export const INSIGHTS_AUDIT_RESOURCE = {
  feedback: 'assistant_feedback',
  conversation: 'assistant_conversation',
} as const;

/**
 * Index names the audit reads name with `FORCE INDEX` (step AI-6 WP1 deviation 4,
 * docs/database/indexing.md): the optimizer otherwise picks the owner index plus a filesort
 * (conversations) or a skip scan plus a filesort (executions, window only). Code constants only.
 */
export const AUDIT_INDEXES = {
  conversationsByActivity: 'ai_chat_conversations_organization_id_last_turn_at_id_idx',
  executionsByTime: 'ai_chat_tool_executions_organization_id_created_at_idx',
  executionsByUser: 'ai_chat_tool_executions_organization_id_user_id_created_at_idx',
  executionsByTool: 'ai_chat_tool_executions_organization_id_tool_name_created_at_idx',
} as const;

export const DAY_MS = 86_400_000;
