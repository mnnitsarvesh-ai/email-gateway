import { z } from 'zod';
import { CURSOR_MAX_LENGTH } from '../../../http/cursor/cursor-codec';
import { defineListQuery } from '../../../http/listing/list-query';
import { DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT } from '../../../http/pagination';
import {
  FEEDBACK_COMMENT_MAX_CHARS,
  FEEDBACK_RATINGS,
  FEEDBACK_REASONS,
  SEARCH_DEFAULT_LIMIT,
  SEARCH_MAX_LIMIT,
  SEARCH_QUERY_MAX_CHARS,
  SEARCH_QUERY_MIN_CHARS,
  SNIPPET_MAX_CHARS,
} from '../insights.constants';

/**
 * Request and response documents of the insights routes (step AI-6 D1, D2, D4; contracts §35.6).
 * Every admin and audit view is metadata only (I24): no conversation title, message text,
 * provider transcript, result card, report object key or HTML, or recipient address.
 */

export const PublicIdSchema = z.uuid();

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const day = z.iso.date();
const count = z.number().int().min(0);

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

const limitOf = (max: number, fallback: number) =>
  z
    .string()
    .regex(/^\d{1,3}$/, 'must be an integer')
    .transform(Number)
    .pipe(z.number().int().min(1).max(max))
    .optional()
    .transform((v) => v ?? fallback);

const cursorParam = z.string().min(1).max(CURSOR_MAX_LENGTH).optional();

/** The user of an admin or audit row; name and address only for members of the organization. */
export const InsightsUserSchema = z
  .object({
    id: z.string().describe('User public id'),
    displayName: z
      .string()
      .nullable()
      .describe('Null for a platform operator (conversations under a platform override)'),
    email: z.string().nullable().describe('Null for a platform operator'),
  })
  .describe('The user (identity columns for members of your organization only)');
export type InsightsUserView = z.output<typeof InsightsUserSchema>;

// ---- content search (D4) ------------------------------------------------------------------------

export const SearchQuerySchema = z.strictObject({
  q: z
    .string()
    .transform((v) => v.trim())
    .pipe(
      z
        .string()
        .min(SEARCH_QUERY_MIN_CHARS)
        .max(SEARCH_QUERY_MAX_CHARS)
        .refine((v) => !CONTROL_CHARS.test(v), 'must not contain control characters'),
    ),
  cursor: cursorParam,
  limit: limitOf(SEARCH_MAX_LIMIT, SEARCH_DEFAULT_LIMIT),
});
export type SearchQuery = z.output<typeof SearchQuerySchema>;

export const SEARCH_PARAMETERS: Record<string, string> = {
  q: `Text to find (${SEARCH_QUERY_MIN_CHARS}-${SEARCH_QUERY_MAX_CHARS} characters after trimming; case- and accent-insensitive; % and _ match literally)`,
  cursor: '`nextCursor` of the previous page',
  limit: `Page size, 1-${SEARCH_MAX_LIMIT} (default ${SEARCH_DEFAULT_LIMIT})`,
};

export const SearchItemSchema = z.object({
  conversationId: z.string(),
  conversationTitle: z.string().nullable(),
  messageId: z.string(),
  role: z.enum(['user', 'assistant']),
  seq: count,
  createdAt: isoInstant,
  snippet: z
    .string()
    .max(SNIPPET_MAX_CHARS)
    .describe(`At most ${SNIPPET_MAX_CHARS} characters around the first match, sanitized`),
});
export type SearchItemView = z.output<typeof SearchItemSchema>;
export const SearchPageSchema = z.object({
  data: z.array(SearchItemSchema),
  nextCursor: z.string().nullable(),
});
export type SearchPage = z.output<typeof SearchPageSchema>;

// ---- feedback (D2) ------------------------------------------------------------------------------

export const SetFeedbackBodySchema = z.strictObject({
  rating: z.enum(FEEDBACK_RATINGS),
  reason: z.enum(FEEDBACK_REASONS).optional(),
  comment: z
    .string()
    .max(FEEDBACK_COMMENT_MAX_CHARS)
    .optional()
    .describe(
      `Optional comment (≤ ${FEEDBACK_COMMENT_MAX_CHARS} characters), visible to your organization’s AI administrators`,
    ),
});
export type SetFeedbackBody = z.output<typeof SetFeedbackBodySchema>;

export const FeedbackViewSchema = z.object({
  messageId: z.string(),
  rating: z.enum(FEEDBACK_RATINGS),
  reason: z.enum(FEEDBACK_REASONS).nullable(),
  comment: z.string().nullable(),
  createdAt: isoInstant,
  updatedAt: isoInstant,
});
export type FeedbackView = z.output<typeof FeedbackViewSchema>;

// ---- admin: usage per user and day (D1) ---------------------------------------------------------

export const UsageByUserQuerySchema = z.strictObject({
  from: day.optional().describe('First UTC day (YYYY-MM-DD); default 29 days before `to`'),
  to: day.optional().describe('Last UTC day (YYYY-MM-DD); default today'),
  userId: PublicIdSchema.optional().describe('Only this user (public id)'),
  cursor: cursorParam,
  limit: limitOf(MAX_PAGE_LIMIT, DEFAULT_PAGE_LIMIT),
});
export type UsageByUserQuery = z.output<typeof UsageByUserQuerySchema>;

export const USAGE_BY_USER_PARAMETERS: Record<string, string> = {
  from: 'First UTC day (YYYY-MM-DD); default 29 days before `to`; at most 92 days',
  to: 'Last UTC day (YYYY-MM-DD, inclusive); default today',
  userId: 'Only this user (public id)',
  cursor: '`nextCursor` of the previous page',
  limit: `Page size, 1-${MAX_PAGE_LIMIT} (default ${DEFAULT_PAGE_LIMIT})`,
};

const usageFigures = {
  turns: count,
  inputTokens: count,
  outputTokens: count,
  cacheReadTokens: count,
  cacheWriteTokens: count,
  totalTokens: count,
  estimatedCostMicros: z
    .number()
    .int()
    .nullable()
    .describe('Estimated cost in micro-USD (sum of the priced models); null = no price known'),
};
export const UsageFiguresSchema = z.object(usageFigures);
export type UsageFigures = z.output<typeof UsageFiguresSchema>;

export const UserUsageRowSchema = z.object({
  day,
  user: InsightsUserSchema,
  keySource: z.enum(['platform', 'tenant']),
  ...usageFigures,
});
export type UserUsageRowView = z.output<typeof UserUsageRowSchema>;

export const UserUsagePageSchema = z.object({
  from: day,
  to: day,
  data: z.array(UserUsageRowSchema).describe('Newest day first, then by user and key source'),
  totals: z.object({
    users: z
      .array(z.object({ user: InsightsUserSchema, ...usageFigures }))
      .describe('Totals over the whole window of each user on this page'),
    overall: UsageFiguresSchema.describe('Totals over the whole window (and the userId filter)'),
  }),
  nextCursor: z.string().nullable(),
});
export type UserUsagePage = z.output<typeof UserUsagePageSchema>;

// ---- admin: feedback list (D2) ------------------------------------------------------------------

export const FeedbackListQuerySchema = defineListQuery({
  filters: {
    rating: { type: 'enum', values: FEEDBACK_RATINGS },
    reason: { type: 'enum', values: FEEDBACK_REASONS, maxValues: FEEDBACK_REASONS.length },
    userId: { type: 'publicId' },
  },
  sorts: ['-createdAt'],
  defaultSort: '-createdAt',
  range: true,
});
export type FeedbackListQuery = z.output<typeof FeedbackListQuerySchema>;

export const FEEDBACK_LIST_PARAMETERS: Record<string, string> = {
  from: 'Created at or after (ISO instant); default 30 days before `to`; at most 92 days',
  to: 'Created before (ISO instant); default now',
  rating: '`up` or `down`',
  reason: 'Comma list of reasons',
  userId: 'Only this user (public id)',
  sort: '`-createdAt` (newest first)',
  limit: `Page size, 1-${MAX_PAGE_LIMIT} (default ${DEFAULT_PAGE_LIMIT})`,
  cursor: '`nextCursor` of the previous page',
};

export const AdminFeedbackItemSchema = z.object({
  id: z.string().describe('Feedback public id'),
  conversationId: z.string(),
  messageId: z.string(),
  user: InsightsUserSchema,
  rating: z.enum(FEEDBACK_RATINGS),
  reason: z.enum(FEEDBACK_REASONS).nullable(),
  comment: z
    .string()
    .nullable()
    .describe('The user’s comment (null when none or after the content purge)'),
  createdAt: isoInstant,
  updatedAt: isoInstant,
  turn: z
    .object({
      provider: z.string(),
      model: z.string(),
      promptVersion: z.string(),
      dataSharing: z.enum(['metadata', 'pseudonymized']),
    })
    .nullable()
    .describe('The answered turn (null when its metadata was deleted)'),
  tools: z.array(z.string()).describe('Distinct names of the tools the turn called'),
});
export type AdminFeedbackItemView = z.output<typeof AdminFeedbackItemSchema>;
export const AdminFeedbackPageSchema = z.object({
  data: z.array(AdminFeedbackItemSchema),
  nextCursor: z.string().nullable(),
});
export type AdminFeedbackPage = z.output<typeof AdminFeedbackPageSchema>;

// ---- audit view (D4, I24) -----------------------------------------------------------------------

export const AUDIT_CONVERSATION_STATUSES = ['active', 'archived', 'deleted'] as const;

export const AuditConversationsQuerySchema = defineListQuery({
  filters: {
    userId: { type: 'publicId' },
    status: { type: 'enum', values: AUDIT_CONVERSATION_STATUSES, maxValues: 3 },
  },
  sorts: ['-lastTurnAt'],
  defaultSort: '-lastTurnAt',
  range: true,
});
export type AuditConversationsQuery = z.output<typeof AuditConversationsQuerySchema>;

export const AUDIT_CONVERSATIONS_PARAMETERS: Record<string, string> = {
  from: 'Last turn at or after (ISO instant); with `to` at most 92 days; no window when both are absent',
  to: 'Last turn before (ISO instant); default now when `from` is given',
  userId: 'Only this user (public id)',
  status: '`active`, `archived`, `deleted`; comma list (default all)',
  sort: '`-lastTurnAt` (newest activity first)',
  limit: `Page size, 1-${MAX_PAGE_LIMIT} (default ${DEFAULT_PAGE_LIMIT})`,
  cursor: '`nextCursor` of the previous page',
};

export const AuditConversationHeaderSchema = z.object({
  id: z.string().describe('Conversation public id'),
  user: InsightsUserSchema,
  status: z.enum(AUDIT_CONVERSATION_STATUSES),
  createdAt: isoInstant,
  lastTurnAt: nullableInstant,
  turnCount: count,
  segmentCount: count,
  contentPurged: z.boolean(),
  underPlatformOverride: z.boolean(),
  totals: z.object({
    tokens: count,
    estimatedCostMicros: z.number().int().nullable(),
    toolCalls: count,
    deniedCalls: count,
    confirmations: z.object({
      pending: count,
      executing: count,
      executed: count,
      failed: count,
      expired: count,
      cancelled: count,
    }),
    reports: count,
    feedback: z.object({ up: count, down: count }),
  }),
});
export type AuditConversationHeader = z.output<typeof AuditConversationHeaderSchema>;
export const AuditConversationPageSchema = z.object({
  data: z.array(AuditConversationHeaderSchema),
  nextCursor: z.string().nullable(),
});
export type AuditConversationPage = z.output<typeof AuditConversationPageSchema>;

export const AuditTurnSchema = z.object({
  seq: count,
  status: z.enum(['running', 'completed', 'failed', 'cancelled']),
  provider: z.string(),
  model: z.string(),
  responseModel: z.string().nullable(),
  keySource: z.enum(['platform', 'tenant']),
  dataSharing: z.enum(['metadata', 'pseudonymized']),
  fallbackFrom: z.string().nullable(),
  promptVersion: z.string(),
  registryVersion: z.string(),
  rounds: count,
  toolCalls: count,
  tokens: z.object({
    input: count,
    output: count,
    cacheRead: count,
    cacheWrite: count,
  }),
  costMicros: z.number().int().nullable(),
  latencyMs: z.number().int().nullable(),
  errorCode: z.string().nullable(),
  startedAt: isoInstant,
  finishedAt: nullableInstant,
});
export type AuditTurnView = z.output<typeof AuditTurnSchema>;

export const AUDIT_DECISIONS = [
  'allowed',
  'denied_permission',
  'denied_unknown_tool',
  'denied_disabled',
  'denied_not_applicable',
  'denied_schema',
  'denied_ref',
  'denied_budget',
  'denied_guard',
] as const;
export const AUDIT_EXECUTION_STATUSES = [
  'succeeded',
  'failed',
  'refused',
  'timeout',
  'pending_confirmation',
] as const;
export const AUDIT_RISKS = ['read', 'read_audited', 'low', 'medium', 'high', 'critical'] as const;
export const AUDIT_ACCESS = ['read', 'write'] as const;

export const AuditExecutionSchema = z.object({
  id: z.string().describe('Execution public id'),
  seq: count,
  turnSeq: z.number().int().nullable(),
  tool: z.string(),
  module: z.string().nullable().describe('Registry module of the tool (null for an unknown tool)'),
  operationId: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  access: z.enum(AUDIT_ACCESS),
  risk: z.enum(AUDIT_RISKS),
  decision: z.enum(AUDIT_DECISIONS),
  status: z.enum(AUDIT_EXECUTION_STATUSES),
  httpStatus: z.number().int().nullable(),
  errorCode: z.string().nullable(),
  paramsRedacted: z
    .unknown()
    .nullable()
    .describe('The redacted parameters exactly as stored (credential keys dropped, values masked)'),
  resourceRef: z.string().nullable(),
  latencyMs: z.number().int().nullable(),
  correlationId: z.string(),
  createdAt: isoInstant,
});
export type AuditExecutionView = z.output<typeof AuditExecutionSchema>;

export const AuditConfirmationSchema = z.object({
  id: z.string().describe('Confirmation public id'),
  operationId: z.string(),
  risk: z.enum(['low', 'medium', 'high']),
  requiresReauth: z.boolean(),
  status: z.enum(['pending', 'executing', 'executed', 'failed', 'expired', 'cancelled']),
  createdAt: isoInstant,
  expiresAt: isoInstant,
  decidedAt: nullableInstant,
  resultHttpStatus: z.number().int().nullable(),
  errorCode: z.string().nullable(),
});
export type AuditConfirmationView = z.output<typeof AuditConfirmationSchema>;

export const AuditReportSchema = z.object({
  id: z.string().describe('Report public id'),
  status: z.enum(['pending', 'queued', 'available', 'failed', 'purged']),
  period: z.object({ from: isoInstant, to: isoInstant, granularity: z.enum(['hour', 'day']) }),
  sections: z.array(z.string()),
  omitted: z.array(
    z.object({ section: z.string(), reason: z.string(), code: z.string().nullable() }),
  ),
  sizeBytes: z.number().int().nullable(),
  errorCode: z.string().nullable(),
  createdAt: isoInstant,
  async: z.boolean().describe('Generated by a background job (step AI-6 D5)'),
  jobStatus: z.enum(['queued', 'running', 'succeeded', 'failed', 'cancelled']).nullable(),
  deliveries: z.array(
    z.object({
      recipientKind: z.enum(['self', 'member', 'domain']),
      recipientDomain: z
        .string()
        .nullable()
        .describe('Domain of the recipient only (null after the content purge)'),
      status: z.enum(['queued', 'sent', 'failed']),
      errorCode: z.string().nullable(),
      requestedAt: isoInstant,
      sentAt: nullableInstant,
    }),
  ),
});
export type AuditReportView = z.output<typeof AuditReportSchema>;

export const AuditFeedbackSchema = z.object({
  messageId: z.string(),
  rating: z.enum(FEEDBACK_RATINGS),
  reason: z.enum(FEEDBACK_REASONS).nullable(),
});

export const AuditConversationDetailSchema = AuditConversationHeaderSchema.extend({
  turns: z.array(AuditTurnSchema),
  executions: z.array(AuditExecutionSchema),
  confirmations: z.array(AuditConfirmationSchema),
  reports: z.array(AuditReportSchema),
  feedback: z.array(AuditFeedbackSchema),
  truncated: z
    .boolean()
    .describe('True when a list was cut at its maximum (1000 rows each, oldest first)'),
});
export type AuditConversationDetail = z.output<typeof AuditConversationDetailSchema>;

export const AuditExecutionsQuerySchema = defineListQuery({
  filters: {
    userId: { type: 'publicId' },
    conversationId: { type: 'publicId' },
    tool: { type: 'string', maxLength: 96 },
    module: { type: 'string', maxLength: 64 },
    decision: { type: 'enum', values: AUDIT_DECISIONS, maxValues: AUDIT_DECISIONS.length },
    status: {
      type: 'enum',
      values: AUDIT_EXECUTION_STATUSES,
      maxValues: AUDIT_EXECUTION_STATUSES.length,
    },
    risk: { type: 'enum', values: AUDIT_RISKS, maxValues: AUDIT_RISKS.length },
    access: { type: 'enum', values: AUDIT_ACCESS },
    correlationId: { type: 'string', maxLength: 128 },
  },
  sorts: ['-createdAt'],
  defaultSort: '-createdAt',
  range: true,
});
export type AuditExecutionsQuery = z.output<typeof AuditExecutionsQuerySchema>;

export const AUDIT_EXECUTIONS_PARAMETERS: Record<string, string> = {
  from: 'Created at or after (ISO instant); default 30 days before `to`; at most 92 days',
  to: 'Created before (ISO instant); default now',
  userId: 'Only this user (public id)',
  conversationId: 'Only this conversation (public id)',
  tool: 'Tool name (exact)',
  module: 'Registry module of the tool (exact)',
  decision: 'Comma list of executor decisions',
  status: 'Comma list of statuses',
  risk: 'Comma list of risks',
  access: '`read` or `write`',
  correlationId: 'Correlation id (exact)',
  sort: '`-createdAt` (newest first)',
  limit: `Page size, 1-${MAX_PAGE_LIMIT} (default ${DEFAULT_PAGE_LIMIT})`,
  cursor: '`nextCursor` of the previous page',
};

export const AuditExecutionItemSchema = AuditExecutionSchema.extend({
  conversationId: z.string(),
  user: InsightsUserSchema,
});
export type AuditExecutionItemView = z.output<typeof AuditExecutionItemSchema>;
export const AuditExecutionPageSchema = z.object({
  data: z.array(AuditExecutionItemSchema),
  nextCursor: z.string().nullable(),
});
export type AuditExecutionPage = z.output<typeof AuditExecutionPageSchema>;

// ---- examples (synthetic values only) -----------------------------------------------------------

const ID = {
  conversation: '0193b5c0-4a1e-7c2d-9f00-00000000c001',
  message: '0193b5c0-4a1e-7c2d-9f00-00000000a002',
  user: '0193b5c0-4a1e-7c2d-9f00-00000000b003',
  feedback: '0193b5c0-4a1e-7c2d-9f00-00000000f004',
  execution: '0193b5c0-4a1e-7c2d-9f00-00000000e005',
  confirmation: '0193b5c0-4a1e-7c2d-9f00-00000000c006',
  report: '0193b5c0-4a1e-7c2d-9f00-00000000d007',
} as const;
const USER = { id: ID.user, displayName: 'Dana Admin', email: 'dana.admin@example.com' };
const FIGURES = {
  turns: 12,
  inputTokens: 48_200,
  outputTokens: 6_100,
  cacheReadTokens: 30_000,
  cacheWriteTokens: 4_000,
  totalTokens: 88_300,
  estimatedCostMicros: 412_500,
};
const HEADER: AuditConversationHeader = {
  id: ID.conversation,
  user: USER,
  status: 'active',
  createdAt: '2026-11-20T09:00:00.000Z',
  lastTurnAt: '2026-11-20T09:12:00.000Z',
  turnCount: 3,
  segmentCount: 1,
  contentPurged: false,
  underPlatformOverride: false,
  totals: {
    tokens: 21_400,
    estimatedCostMicros: 98_000,
    toolCalls: 4,
    deniedCalls: 1,
    confirmations: { pending: 0, executing: 0, executed: 1, failed: 0, expired: 0, cancelled: 0 },
    reports: 1,
    feedback: { up: 1, down: 0 },
  },
};
const EXECUTION: AuditExecutionView = {
  id: ID.execution,
  seq: 2,
  turnSeq: 1,
  tool: 'policy_management_list',
  module: 'policies',
  operationId: 'PoliciesController_list_v1',
  method: 'GET',
  access: 'read',
  risk: 'read',
  decision: 'allowed',
  status: 'succeeded',
  httpStatus: 200,
  errorCode: null,
  paramsRedacted: { query: { limit: 25 } },
  resourceRef: null,
  latencyMs: 84,
  correlationId: 'req-0193b5c0.t1.2',
  createdAt: '2026-11-20T09:01:05.000Z',
};

export const INSIGHTS_EXAMPLES = {
  searchPage: {
    data: [
      {
        conversationId: ID.conversation,
        conversationTitle: 'Quarantine review',
        messageId: ID.message,
        role: 'assistant',
        seq: 2,
        createdAt: '2026-11-20T09:01:10.000Z',
        snippet: '…three messages from the invoice campaign are still in quarantine; release…',
      },
    ],
    nextCursor: null,
  } satisfies SearchPage,
  feedbackSet: { rating: 'down', reason: 'incomplete', comment: 'The list missed yesterday.' },
  feedback: {
    messageId: ID.message,
    rating: 'down',
    reason: 'incomplete',
    comment: 'The list missed yesterday.',
    createdAt: '2026-11-20T09:02:00.000Z',
    updatedAt: '2026-11-20T09:02:00.000Z',
  } satisfies FeedbackView,
  usagePage: {
    from: '2026-11-01',
    to: '2026-11-20',
    data: [{ day: '2026-11-20', user: USER, keySource: 'platform', ...FIGURES }],
    totals: { users: [{ user: USER, ...FIGURES }], overall: FIGURES },
    nextCursor: null,
  } satisfies UserUsagePage,
  feedbackPage: {
    data: [
      {
        id: ID.feedback,
        conversationId: ID.conversation,
        messageId: ID.message,
        user: USER,
        rating: 'down',
        reason: 'incomplete',
        comment: 'The list missed yesterday.',
        createdAt: '2026-11-20T09:02:00.000Z',
        updatedAt: '2026-11-20T09:02:00.000Z',
        turn: {
          provider: 'anthropic',
          model: 'claude-opus-5-5',
          promptVersion: 'assistant-system/7',
          dataSharing: 'metadata',
        },
        tools: ['policy_management_list'],
      },
    ],
    nextCursor: null,
  } satisfies AdminFeedbackPage,
  conversationPage: { data: [HEADER], nextCursor: null } satisfies AuditConversationPage,
  conversation: {
    ...HEADER,
    turns: [
      {
        seq: 1,
        status: 'completed',
        provider: 'anthropic',
        model: 'claude-opus-5-5',
        responseModel: 'claude-opus-5-5',
        keySource: 'platform',
        dataSharing: 'metadata',
        fallbackFrom: null,
        promptVersion: 'assistant-system/7',
        registryVersion: '28a56d359a373381',
        rounds: 2,
        toolCalls: 1,
        tokens: { input: 9_000, output: 700, cacheRead: 6_000, cacheWrite: 1_200 },
        costMicros: 41_000,
        latencyMs: 5_400,
        errorCode: null,
        startedAt: '2026-11-20T09:01:00.000Z',
        finishedAt: '2026-11-20T09:01:10.000Z',
      },
    ],
    executions: [EXECUTION],
    confirmations: [
      {
        id: ID.confirmation,
        operationId: 'PoliciesController_update_v1',
        risk: 'medium',
        requiresReauth: false,
        status: 'executed',
        createdAt: '2026-11-20T09:05:00.000Z',
        expiresAt: '2026-11-20T09:15:00.000Z',
        decidedAt: '2026-11-20T09:06:00.000Z',
        resultHttpStatus: 200,
        errorCode: null,
      },
    ],
    reports: [
      {
        id: ID.report,
        status: 'available',
        period: {
          from: '2026-11-13T00:00:00.000Z',
          to: '2026-11-20T00:00:00.000Z',
          granularity: 'day',
        },
        sections: ['traffic', 'threats'],
        omitted: [],
        sizeBytes: 48_213,
        errorCode: null,
        createdAt: '2026-11-20T09:10:00.000Z',
        async: false,
        jobStatus: null,
        deliveries: [
          {
            recipientKind: 'member',
            recipientDomain: 'example.com',
            status: 'sent',
            errorCode: null,
            requestedAt: '2026-11-20T09:11:00.000Z',
            sentAt: '2026-11-20T09:11:04.000Z',
          },
        ],
      },
    ],
    feedback: [{ messageId: ID.message, rating: 'up', reason: null }],
    truncated: false,
  } satisfies AuditConversationDetail,
  executionPage: {
    data: [{ ...EXECUTION, conversationId: ID.conversation, user: USER }],
    nextCursor: null,
  } satisfies AuditExecutionPage,
} as const;
