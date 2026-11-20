import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';

/**
 * Request and response shapes of the assistant routes (step AI-1 §4.1, §4.2, contracts §35).
 * Request schemas are strict at every node. Cards (`assistant-card/1`) are built from real API
 * responses by `@email-gateway/assistant` and hold masked metadata only; the API cursor of a list
 * result never leaves the server (`nextCursor` of a card is a flag).
 */

export const PublicIdSchema = z.uuid();

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();

// ---- status ---------------------------------------------------------------------------------

export const STATUS_REASONS = [
  'platform_disabled',
  'feature_disabled',
  'tenant_disabled',
  'provider_unavailable',
  'budget_exhausted',
] as const;
export type StatusReason = (typeof STATUS_REASONS)[number];

export const AssistantStatusSchema = z.object({
  available: z.boolean(),
  reason: z
    .enum(STATUS_REASONS)
    .optional()
    .describe('Why the assistant is not available (absent when available)'),
  provider: z.string().describe('Configured provider: anthropic, openai, azure_openai or fake'),
  model: z.string(),
  limits: z.object({
    messageMaxChars: z.number().int(),
    turnsPerMinute: z.number().int(),
  }),
  budget: z.object({
    dailyTokens: z.number().int().describe('The organization’s daily token budget (UTC day)'),
    usedToday: z.number().int(),
  }),
});
export type AssistantStatusView = z.output<typeof AssistantStatusSchema>;

// ---- settings -------------------------------------------------------------------------------

export const AssistantSettingsSchema = z.object({
  version: z.literal('assistant-settings/1'),
  enabled: z.boolean(),
  externalProcessingAcknowledged: z.boolean(),
  externalProcessingAcknowledgedAt: nullableInstant,
  externalProcessingAcknowledgedBy: z
    .string()
    .nullable()
    .describe('Public id of the user who acknowledged the external processing'),
  dailyTokenBudget: z
    .number()
    .int()
    .nullable()
    .describe('null = the platform default (ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT)'),
  effectiveDailyTokenBudget: z.number().int(),
  retentionDays: z.number().int(),
  dataSharing: z.literal('metadata'),
  featureEnabled: z.boolean().describe('Whether the organization feature `ai_assistant` is on'),
  rowVersion: z.number().int().describe('0 when the settings were never saved'),
  updatedAt: nullableInstant,
});
export type AssistantSettingsView = z.output<typeof AssistantSettingsSchema>;

export const UpdateAssistantSettingsBodySchema = z.strictObject({
  expectedRowVersion: z
    .number()
    .int()
    .min(0)
    .describe('`rowVersion` of the settings you read (0 before the first save)'),
  enabled: z.boolean(),
  externalProcessingAcknowledged: z
    .boolean()
    .describe('Must be true to enable: user text and masked metadata go to the AI provider'),
  dailyTokenBudget: z
    .number()
    .int()
    .min(1)
    .nullable()
    .describe('Tokens per UTC day (≤ ASSISTANT_TENANT_DAILY_TOKENS_MAX); null = platform default'),
  retentionDays: z.number().int().min(1).max(365).describe('Content retention after the last turn'),
  dataSharing: z.literal('metadata').default('metadata'),
});
export type UpdateAssistantSettingsBody = z.output<typeof UpdateAssistantSettingsBodySchema>;

// ---- usage ----------------------------------------------------------------------------------

const day = z.iso.date();

export const UsageQuerySchema = z.strictObject({
  from: day.optional().describe('First UTC day (YYYY-MM-DD); default 29 days before `to`'),
  to: day.optional().describe('Last UTC day (YYYY-MM-DD); default today'),
});
export type UsageQuery = z.output<typeof UsageQuerySchema>;

export const UsageRowSchema = z.object({
  day: day,
  provider: z.string(),
  model: z.string(),
  turns: z.number().int(),
  inputTokens: z.number().int(),
  outputTokens: z.number().int(),
  cacheReadTokens: z.number().int(),
  cacheWriteTokens: z.number().int(),
  costMicros: z.number().int().nullable().describe('Advisory cost in micro-USD; null = no price'),
});
export const UsageViewSchema = z.object({
  from: day,
  to: day,
  rows: z.array(UsageRowSchema),
  totals: z.object({
    turns: z.number().int(),
    inputTokens: z.number().int(),
    outputTokens: z.number().int(),
    cacheReadTokens: z.number().int(),
    cacheWriteTokens: z.number().int(),
    costMicros: z.number().int().nullable(),
  }),
});
export type UsageView = z.output<typeof UsageViewSchema>;
export type UsageRowView = z.output<typeof UsageRowSchema>;

// ---- tools ----------------------------------------------------------------------------------

export const ToolsViewSchema = z.object({
  registryVersion: z.string(),
  tools: z.array(
    z.object({
      name: z.string(),
      module: z.string(),
      title: z.string(),
      access: z.enum(['read', 'write']),
      risk: z.enum(['read', 'read_audited', 'low', 'medium', 'high', 'critical']),
    }),
  ),
});
export type ToolsView = z.output<typeof ToolsViewSchema>;

// ---- conversations --------------------------------------------------------------------------

export const CONVERSATION_STATUSES = ['active', 'archived'] as const;

export const ConversationSchema = z.object({
  id: z.uuid(),
  title: z.string().nullable(),
  status: z.enum(CONVERSATION_STATUSES),
  turnCount: z.number().int(),
  lastTurnAt: nullableInstant,
  purgeAfter: nullableInstant.describe('When the content (title, messages, cards) is purged'),
  contentPurged: z.boolean(),
  underPlatformOverride: z.boolean(),
  rowVersion: z.number().int(),
  createdAt: isoInstant,
  updatedAt: isoInstant,
});
export type ConversationView = z.output<typeof ConversationSchema>;

export const ConversationPageSchema = z.object({
  data: z.array(ConversationSchema),
  nextCursor: z.string().nullable(),
});
export type ConversationPage = z.output<typeof ConversationPageSchema>;

export const ConversationListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: CONVERSATION_STATUSES, maxValues: 2 },
    q: { type: 'string', maxLength: 100 },
  },
  sorts: ['-lastTurnAt'],
  defaultSort: '-lastTurnAt',
});
export type ConversationListQuery = z.output<typeof ConversationListQuerySchema>;

export const CONVERSATION_LIST_PARAMETERS: Record<string, string> = {
  status: '`active`, `archived`; comma list (default both; deleted conversations are never listed)',
  q: 'Title contains (case-insensitive), at most 100 characters',
  sort: '`-lastTurnAt` (newest activity first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

const titleField = z
  .string()
  .trim()
  .min(1)
  .max(200)
  // eslint-disable-next-line no-control-regex -- control characters are what the rule refuses
  .refine((v) => !/[\u0000-\u001f\u007f]/.test(v), 'must not contain control characters');

export const CreateConversationBodySchema = z.strictObject({
  title: titleField.optional(),
});
export type CreateConversationBody = z.output<typeof CreateConversationBodySchema>;

export const UpdateConversationBodySchema = z
  .strictObject({
    title: titleField.optional(),
    status: z.enum(CONVERSATION_STATUSES).optional(),
  })
  .refine((v) => v.title !== undefined || v.status !== undefined, 'title or status is required');
export type UpdateConversationBody = z.output<typeof UpdateConversationBodySchema>;

// ---- cards, executions, messages, turns -----------------------------------------------------

const cardValue = z.union([z.string(), z.number(), z.boolean(), z.null()]);

export const CardSchema = z
  .object({
    version: z.literal('assistant-card/1'),
    executionId: z.uuid(),
    tool: z.string(),
    title: z.string(),
    status: z.enum(['ok', 'error']),
    kind: z.enum(['table', 'kv', 'series', 'message', 'error']),
    columns: z.array(z.object({ key: z.string(), label: z.string() })).optional(),
    rows: z.array(z.record(z.string(), cardValue)).optional(),
    fields: z.array(z.object({ key: z.string(), label: z.string(), value: cardValue })).optional(),
    series: z
      .object({
        x: z.array(z.string()),
        series: z.array(z.object({ name: z.string(), values: z.array(z.number().nullable()) })),
      })
      .optional(),
    total: z.number().int().optional(),
    nextCursor: z.boolean().optional().describe('A next page exists (POST …/more)'),
    portalLinks: z.array(
      z.object({ label: z.string(), href: z.string(), ref: z.string().optional() }),
    ),
    refs: z.array(z.string()),
    truncated: z.boolean().optional(),
    message: z.string().optional(),
    error: z
      .object({ httpStatus: z.number().int(), code: z.string(), message: z.string() })
      .optional(),
  })
  .describe('assistant-card/1: built from the real API response, masked metadata only');

export const EXECUTION_DECISIONS = [
  'allowed',
  'denied_permission',
  'denied_unknown_tool',
  'denied_disabled',
  'denied_not_applicable',
  'denied_schema',
  'denied_ref',
  'denied_budget',
] as const;
export const EXECUTION_STATUSES = ['succeeded', 'failed', 'refused', 'timeout'] as const;

export const ExecutionSchema = z.object({
  id: z.uuid(),
  conversationId: z.uuid(),
  turnId: z.uuid().nullable().describe('null for a "more" page'),
  parentExecutionId: z.uuid().nullable(),
  seq: z.number().int(),
  ref: z.string().describe('`r<seq>`: how the assistant refers to this result'),
  tool: z.string(),
  operationId: z.string(),
  access: z.enum(['read', 'write']),
  risk: z.enum(['read', 'read_audited', 'low', 'medium', 'high', 'critical']),
  decision: z.enum(EXECUTION_DECISIONS),
  status: z.enum(EXECUTION_STATUSES),
  httpStatus: z.number().int().nullable(),
  errorCode: z.string().nullable(),
  hasMore: z.boolean(),
  card: CardSchema.nullable().describe('null for refused calls and after the content purge'),
  latencyMs: z.number().int().nullable(),
  createdAt: isoInstant,
});
export type ExecutionView = z.output<typeof ExecutionSchema>;

export const TURN_STATUSES = ['running', 'completed', 'failed', 'cancelled'] as const;

export const TurnSchema = z.object({
  id: z.uuid(),
  conversationId: z.uuid(),
  seq: z.number().int(),
  status: z.enum(TURN_STATUSES),
  errorCode: z.string().nullable(),
  provider: z.string(),
  model: z.string(),
  responseModel: z.string().nullable(),
  rounds: z.number().int(),
  toolCalls: z.number().int(),
  usage: z.object({
    inputTokens: z.number().int(),
    outputTokens: z.number().int(),
    cacheReadTokens: z.number().int(),
    cacheWriteTokens: z.number().int(),
  }),
  latencyMs: z.number().int().nullable(),
  startedAt: isoInstant,
  finishedAt: nullableInstant,
});
export type TurnView = z.output<typeof TurnSchema>;

export const MessageSchema = z.object({
  id: z.uuid(),
  turnId: z.uuid(),
  seq: z.number().int(),
  role: z.enum(['user', 'assistant']),
  content: z.string().nullable().describe('null after the content purge'),
  createdAt: isoInstant,
});
export type MessageView = z.output<typeof MessageSchema>;

export const MessageListItemSchema = MessageSchema.extend({
  turn: z.object({
    id: z.uuid(),
    status: z.enum(TURN_STATUSES),
    errorCode: z.string().nullable(),
  }),
  executions: z
    .array(ExecutionSchema)
    .describe(
      'The turn’s tool executions (and their "more" pages) on its assistant message, or on the ' +
        'user message when the turn has no assistant message (failed or running)',
    ),
});
export type MessageListItem = z.output<typeof MessageListItemSchema>;

export const MessagePageSchema = z.object({
  data: z.array(MessageListItemSchema),
  nextCursor: z.string().nullable(),
});
export type MessagePage = z.output<typeof MessagePageSchema>;

export const MessageListQuerySchema = defineListQuery({
  filters: {},
  sorts: ['seq'],
  defaultSort: 'seq',
});
export type MessageListQuery = z.output<typeof MessageListQuerySchema>;

export const MESSAGE_LIST_PARAMETERS: Record<string, string> = {
  sort: '`seq` (oldest first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

/** IANA time zone names (`Europe/Berlin`, `UTC`), checked against the runtime's zone data. */
export function isIanaTimeZone(value: string): boolean {
  if (!/^[A-Za-z0-9_+\-/]{1,64}$/.test(value)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

/** The body of `POST …/turns`; `message` is checked against ASSISTANT_USER_MESSAGE_MAX_CHARS. */
export const CreateTurnBodySchema = z.strictObject({
  clientTurnId: z
    .uuid()
    .describe('A UUID chosen by the client; a retried POST with the same id replays the turn'),
  message: z
    .string()
    .min(1)
    .max(16_000)
    .refine((v) => v.trim().length > 0, 'must not be blank')
    .describe('The question, 1..ASSISTANT_USER_MESSAGE_MAX_CHARS characters (413 beyond)'),
  timeZone: z
    .string()
    .max(64)
    .refine(isIanaTimeZone, 'must be an IANA time zone')
    .optional()
    .describe('The browser’s IANA time zone, for relative dates'),
});
export type CreateTurnBody = z.output<typeof CreateTurnBodySchema>;

export const TurnResultSchema = z.object({
  turn: TurnSchema,
  message: MessageSchema.nullable().describe('The assistant message (null when the turn failed)'),
  executions: z.array(ExecutionSchema),
});
export type TurnResultView = z.output<typeof TurnResultSchema>;

export const CancelResultSchema = z.object({
  turnId: z.uuid(),
  status: z.enum(TURN_STATUSES),
});
export type CancelResultView = z.output<typeof CancelResultSchema>;

// ---- examples (synthetic) -------------------------------------------------------------------

const ID = {
  conversation: '0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01',
  turn: '0193a1c2-7b20-7d4f-8b62-3a1c7d2e5f02',
  user: '0193a1c2-7c30-7e50-9c73-4b2d8e3f6a03',
  assistant: '0193a1c2-7d40-7f61-8d84-5c3e9f4a7b04',
  execution: '0193a1c2-7e50-7072-9e95-6d4fa05b8c05',
  policy: '0193a1c2-7f60-7183-8fa6-7e50b16c9d06',
  acknowledger: '0193a1c2-8070-7294-90b7-8f61c27dae07',
  client: '5f0c2c1e-8b8a-4f7e-9a0e-2d3c4b5a6f70',
};

const card = {
  version: 'assistant-card/1' as const,
  executionId: ID.execution,
  tool: 'policy_management_list',
  title: 'List policies',
  status: 'ok' as const,
  kind: 'table' as const,
  columns: [
    { key: 'name', label: 'Name' },
    { key: 'status', label: 'Status' },
  ],
  rows: [{ name: 'Block executables', status: 'active', ref: 'r1.1' }],
  nextCursor: false,
  portalLinks: [
    { label: 'List policies', href: '/policies' },
    { label: 'Block executables', href: `/policies/${ID.policy}`, ref: 'r1.1' },
  ],
  refs: ['r1.1'],
};

const execution: ExecutionView = {
  id: ID.execution,
  conversationId: ID.conversation,
  turnId: ID.turn,
  parentExecutionId: null,
  seq: 1,
  ref: 'r1',
  tool: 'policy_management_list',
  operationId: 'PolicyManagementController_list_v1',
  access: 'read',
  risk: 'read',
  decision: 'allowed',
  status: 'succeeded',
  httpStatus: 200,
  errorCode: null,
  hasMore: false,
  card,
  latencyMs: 42,
  createdAt: '2026-11-20T10:00:01.000Z',
};

const conversation: ConversationView = {
  id: ID.conversation,
  title: 'Show active policies',
  status: 'active',
  turnCount: 1,
  lastTurnAt: '2026-11-20T10:00:00.000Z',
  purgeAfter: '2026-12-20T10:00:00.000Z',
  contentPurged: false,
  underPlatformOverride: false,
  rowVersion: 2,
  createdAt: '2026-11-20T09:59:00.000Z',
  updatedAt: '2026-11-20T10:00:03.000Z',
};

const turn: TurnView = {
  id: ID.turn,
  conversationId: ID.conversation,
  seq: 1,
  status: 'completed',
  errorCode: null,
  provider: 'anthropic',
  model: 'claude-opus-5-5',
  responseModel: 'claude-opus-5-5',
  rounds: 2,
  toolCalls: 1,
  usage: { inputTokens: 5120, outputTokens: 240, cacheReadTokens: 4096, cacheWriteTokens: 0 },
  latencyMs: 3150,
  startedAt: '2026-11-20T10:00:00.000Z',
  finishedAt: '2026-11-20T10:00:03.150Z',
};

const assistantMessage: MessageView = {
  id: ID.assistant,
  turnId: ID.turn,
  seq: 2,
  role: 'assistant',
  content: 'You have 1 active policy: **Block executables**.',
  createdAt: '2026-11-20T10:00:03.150Z',
};

export const ASSISTANT_EXAMPLES = {
  status: {
    available: true,
    provider: 'anthropic',
    model: 'claude-opus-5-5',
    limits: { messageMaxChars: 4000, turnsPerMinute: 6 },
    budget: { dailyTokens: 1_000_000, usedToday: 18_250 },
  } satisfies AssistantStatusView,
  settings: {
    version: 'assistant-settings/1',
    enabled: true,
    externalProcessingAcknowledged: true,
    externalProcessingAcknowledgedAt: '2026-11-20T09:30:00.000Z',
    externalProcessingAcknowledgedBy: ID.acknowledger,
    dailyTokenBudget: null,
    effectiveDailyTokenBudget: 1_000_000,
    retentionDays: 30,
    dataSharing: 'metadata',
    featureEnabled: true,
    rowVersion: 2,
    updatedAt: '2026-11-20T09:30:00.000Z',
  } satisfies AssistantSettingsView,
  settingsUpdate: {
    expectedRowVersion: 0,
    enabled: true,
    externalProcessingAcknowledged: true,
    dailyTokenBudget: 500_000,
    retentionDays: 30,
    dataSharing: 'metadata',
  },
  usage: {
    from: '2026-11-19',
    to: '2026-11-20',
    rows: [
      {
        day: '2026-11-20',
        provider: 'anthropic',
        model: 'claude-opus-5-5',
        turns: 12,
        inputTokens: 61_440,
        outputTokens: 2880,
        cacheReadTokens: 49_152,
        cacheWriteTokens: 4096,
        costMicros: 335_590,
      },
    ],
    totals: {
      turns: 12,
      inputTokens: 61_440,
      outputTokens: 2880,
      cacheReadTokens: 49_152,
      cacheWriteTokens: 4096,
      costMicros: 335_590,
    },
  } satisfies UsageView,
  tools: {
    registryVersion: 'a6537b4aefe5c48a',
    tools: [
      {
        name: 'policy_management_list',
        module: 'policies',
        title: 'List policies',
        access: 'read',
        risk: 'read',
      },
    ],
  } satisfies ToolsView,
  conversation,
  conversationPage: { data: [conversation], nextCursor: null } satisfies ConversationPage,
  conversationCreate: { title: 'Policy review' },
  conversationUpdate: { title: 'Policy review (done)', status: 'archived' },
  messagePage: {
    data: [
      {
        id: ID.user,
        turnId: ID.turn,
        seq: 1,
        role: 'user',
        content: 'Show active policies',
        createdAt: '2026-11-20T10:00:00.000Z',
        turn: { id: ID.turn, status: 'completed', errorCode: null },
        executions: [],
      },
      {
        ...assistantMessage,
        turn: { id: ID.turn, status: 'completed', errorCode: null },
        executions: [execution],
      },
    ],
    nextCursor: null,
  } satisfies MessagePage,
  turnCreate: {
    clientTurnId: ID.client,
    message: 'Show active policies',
    timeZone: 'Asia/Kolkata',
  },
  turnResult: { turn, message: assistantMessage, executions: [execution] } satisfies TurnResultView,
  cancel: { turnId: ID.turn, status: 'running' } satisfies CancelResultView,
  execution,
};
