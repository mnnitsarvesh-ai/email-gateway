import { REPORT_OMIT_REASONS, REPORT_RANGES, REPORT_SECTIONS } from '@email-gateway/assistant';
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

const reportFigure = z.object({ label: z.string(), value: z.string() });

/** The report of a `report` card (step AI-R D2 step 10; metadata only, never the HTML). */
export const CardReportSchema = z
  .object({
    reportId: z.uuid(),
    title: z.string(),
    period: z.object({
      from: isoInstant,
      to: isoInstant,
      granularity: z.enum(['hour', 'day']),
      atoRange: z.enum(REPORT_RANGES).nullable(),
      label: z.string().describe('`Last 7 days`, or the explicit window in UTC'),
    }),
    generatedAt: isoInstant,
    sizeBytes: z.number().int(),
    sections: z.array(z.enum(REPORT_SECTIONS)).describe('Sections in the report, in order'),
    omitted: z
      .array(
        z.object({
          section: z.enum(REPORT_SECTIONS),
          reason: z.enum(REPORT_OMIT_REASONS),
          code: z
            .string()
            .optional()
            .describe('The missing permission (`quarantine:read`) or the source error code'),
        }),
      )
      .describe('Requested sections that are not in the report, and why'),
    figures: z.array(reportFigure).max(8).describe('Summary figures (formatted)'),
  })
  .describe('Kind `report` (step AI-R): GET /assistant/reports/{reportId} returns the HTML');

export const CardSchema = z
  .object({
    version: z.literal('assistant-card/1'),
    executionId: z.uuid(),
    tool: z.string(),
    title: z.string(),
    status: z.enum(['ok', 'error']),
    kind: z.enum(['table', 'kv', 'series', 'message', 'error', 'report']),
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
    report: CardReportSchema.optional(),
  })
  .describe(
    'assistant-card/1: built from the real API response, masked metadata only (kind `report`: ' +
      'a generated security report, step AI-R)',
  );

export const EXECUTION_DECISIONS = [
  'allowed',
  'denied_permission',
  'denied_unknown_tool',
  'denied_disabled',
  'denied_not_applicable',
  'denied_schema',
  'denied_ref',
  'denied_budget',
  // Step AI-3 D3: a proposal guard refused the write (e.g. a change to one's own account);
  // step AI-R: also `report_needs_organization` and `report_recipient_not_allowed`.
  'denied_guard',
] as const;
export const EXECUTION_STATUSES = [
  'succeeded',
  'failed',
  'refused',
  'timeout',
  'pending_confirmation',
] as const;

// ---- confirmations (step AI-2 §4.2, D5) -----------------------------------------------------

export const CONFIRMATION_STATUSES = [
  'pending',
  'executing',
  'executed',
  'failed',
  'expired',
  'cancelled',
] as const;
export const CONFIRMATION_RISKS = ['low', 'medium', 'high'] as const;

/** A confirmation token: 32 random bytes, base64url without padding. */
export const CONFIRMATION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const ACTION_DIGEST_PATTERN = /^[0-9a-f]{64}$/;

export const ConfirmationSummarySchema = z
  .object({
    version: z.literal('assistant-confirmation/1'),
    title: z.string(),
    action: z.string().describe('One sentence: what will happen'),
    target: z.array(
      z.object({
        label: z.string(),
        value: z.string(),
        untrusted: z
          .boolean()
          .optional()
          .describe('The value comes from a message (subject, sender, file name): plain text'),
      }),
    ),
    changes: z.array(
      z.object({ label: z.string(), before: z.string().nullable().optional(), after: z.string() }),
    ),
    definition: z
      .object({
        direction: z.string(),
        priority: z.number().int(),
        rules: z.array(z.object({ id: z.string(), when: z.string(), actions: z.string() })),
      })
      .optional()
      .describe('Policy definitions, rule by rule'),
    impact: z.array(z.string()).describe('Consequences (medium and high risk have at least one)'),
    warnings: z.array(z.string()),
    reversible: z.boolean(),
    portalRoute: z.string().nullable(),
    request: z
      .object({ method: z.string(), path: z.string() })
      .describe('The request that runs on confirm (technical details)'),
  })
  .describe('assistant-confirmation/1: server-authored from the stored request, never model text');

export const ConfirmationSchema = z
  .object({
    id: z.uuid(),
    executionId: z.uuid().describe('The proposal execution (status `pending_confirmation`)'),
    resultExecutionId: z.uuid().nullable().describe('The confirmed write’s execution'),
    conversationId: z.uuid(),
    tool: z.string(),
    operationId: z.string(),
    risk: z.enum(CONFIRMATION_RISKS),
    requiresReauth: z
      .boolean()
      .describe('High risk: confirm needs `reauth` unless the session re-authenticated recently'),
    reauthFresh: z
      .boolean()
      .describe('This session re-authenticated within ASSISTANT_REAUTH_WINDOW_SECONDS'),
    status: z.enum(CONFIRMATION_STATUSES),
    summary: ConfirmationSummarySchema.nullable().describe('null after the content purge'),
    actionDigest: z
      .string()
      .regex(ACTION_DIGEST_PATTERN)
      .describe('SHA-256 of the proposed action; the confirm request sends it back'),
    expiresAt: isoInstant,
    createdAt: isoInstant,
    decidedAt: nullableInstant,
    executedAt: nullableInstant,
    result: z
      .object({ httpStatus: z.number().int().nullable(), error: z.string().nullable() })
      .nullable()
      .describe('Outcome of the confirmed write (executed or failed)'),
  })
  .describe('An action the assistant proposed; it runs only when you confirm it. Never the token.');
export type ConfirmationViewDto = z.output<typeof ConfirmationSchema>;

export const ExecutionSchema = z.object({
  id: z.uuid(),
  conversationId: z.uuid(),
  turnId: z.uuid().nullable().describe('null for a "more" page'),
  parentExecutionId: z.uuid().nullable(),
  seq: z.number().int(),
  ref: z.string().describe('`r<seq>`: how the assistant refers to this result'),
  tool: z.string(),
  title: z
    .string()
    .describe('Display title of the tool (as the stream `tool.started` event carries it)'),
  operationId: z.string(),
  access: z.enum(['read', 'write']),
  risk: z.enum(['read', 'read_audited', 'low', 'medium', 'high', 'critical']),
  decision: z
    .enum(EXECUTION_DECISIONS)
    .describe(
      'The executor decision; `denied_guard`: a proposal guard refused the write (not allowed ' +
        'in chat, e.g. a change to your own account) or a report rule refused the call ' +
        '(`report_needs_organization`: a platform user without an override; ' +
        '`report_recipient_not_allowed`: a report email to an address outside the organization)',
    ),
  status: z.enum(EXECUTION_STATUSES),
  httpStatus: z.number().int().nullable(),
  errorCode: z
    .string()
    .nullable()
    .describe(
      'The API error code of a failed call, or the executor decision of a refused one. The ' +
        'native report tools (step AI-R) add `assistant_report_not_found` (404), ' +
        '`assistant_report_purged` (410), `assistant_report_too_large` (413), ' +
        '`assistant_report_generation_limit` and `assistant_report_email_limit` (429, refused ' +
        '`denied_budget`), `assistant_report_storage_failed` (502) and ' +
        '`assistant_report_sources_unavailable` (503)',
    ),
  message: z
    .string()
    .nullable()
    .describe(
      'Fixed server-authored explanation of a refused call (decision other than `allowed`; ' +
        'for `denied_guard` the guard message); null for an allowed call. Never an argument value',
    ),
  hasMore: z.boolean(),
  card: CardSchema.nullable().describe('null for refused calls and after the content purge'),
  latencyMs: z.number().int().nullable(),
  createdAt: isoInstant,
  confirmation: ConfirmationSchema.nullable().describe(
    'The confirmation of a write proposal (status `pending_confirmation`); null otherwise',
  ),
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

export const TurnConfirmationSchema = z.object({
  confirmation: ConfirmationSchema,
  token: z
    .string()
    .nullable()
    .describe(
      'Single-use token for `POST /assistant/confirmations/{id}/confirm`; keep it in memory ' +
        'only (null when the turn is replayed by its clientTurnId)',
    ),
});

export const TurnResultSchema = z.object({
  turn: TurnSchema,
  message: MessageSchema.nullable().describe('The assistant message (null when the turn failed)'),
  executions: z.array(ExecutionSchema),
  confirmations: z
    .array(TurnConfirmationSchema)
    .describe('The write proposals of this turn, in call order'),
});
export type TurnResultView = z.output<typeof TurnResultSchema>;

export const CancelResultSchema = z.object({
  turnId: z.uuid(),
  status: z.enum(TURN_STATUSES),
});
export type CancelResultView = z.output<typeof CancelResultSchema>;

/** `POST /assistant/confirmations/{id}/confirm` (step AI-2 D2). */
export const ConfirmBodySchema = z.strictObject({
  token: z
    .string()
    .regex(CONFIRMATION_TOKEN_PATTERN)
    .describe('The token of `confirmation.required` (43 base64url characters)'),
  actionDigest: z
    .string()
    .regex(ACTION_DIGEST_PATTERN)
    .describe('The `actionDigest` the confirmation card showed'),
  reauth: z
    .strictObject({
      password: z.string().min(1).max(1024),
      totpCode: z
        .string()
        .regex(/^[0-9]{6}$/)
        .optional()
        .describe('Required when you have MFA enrolled'),
    })
    .optional()
    .describe('High risk only, unless this session re-authenticated within the window'),
});
export type ConfirmBody = z.output<typeof ConfirmBodySchema>;

export const ConfirmResultSchema = z.object({
  confirmation: ConfirmationSchema,
  execution: ExecutionSchema.describe('The execution of the confirmed write (its result card)'),
});
export type ConfirmResultView = z.output<typeof ConfirmResultSchema>;

export const CancelConfirmationResultSchema = z.object({ confirmation: ConfirmationSchema });
export type CancelConfirmationResultView = z.output<typeof CancelConfirmationResultSchema>;

// ---- reports (step AI-R §4.1) ---------------------------------------------------------------

export const REPORT_STATUSES = ['pending', 'available', 'failed', 'purged'] as const;
export const REPORT_DELIVERY_STATUSES = ['queued', 'sent', 'failed'] as const;

export const ReportDeliverySchema = z.object({
  id: z.uuid(),
  to: z.string().nullable().describe('The recipient address; null after the content purge'),
  recipientKind: z
    .enum(['self', 'member', 'domain'])
    .describe('Your own address, a user of your organization, an address in a verified domain'),
  status: z.enum(REPORT_DELIVERY_STATUSES),
  errorCode: z.string().nullable().describe('Why a delivery failed (codes only)'),
  requestedAt: isoInstant,
  sentAt: nullableInstant,
});

export const ReportViewSchema = z
  .object({
    id: z.uuid(),
    conversationId: z.uuid(),
    executionId: z.uuid().nullable().describe('The `report_generate` execution (when available)'),
    status: z.enum(REPORT_STATUSES),
    title: z.string(),
    period: z.object({
      from: isoInstant,
      to: isoInstant,
      granularity: z.enum(['hour', 'day']),
      atoRange: z.enum(REPORT_RANGES).nullable().describe('The account-takeover overview range'),
    }),
    sections: z.array(z.enum(REPORT_SECTIONS)),
    omitted: z.array(
      z.object({
        section: z.enum(REPORT_SECTIONS),
        reason: z.enum(REPORT_OMIT_REASONS),
        code: z.string().nullable(),
      }),
    ),
    figures: z.array(reportFigure),
    sizeBytes: z.number().int().nullable(),
    sha256: z.string().nullable().describe('SHA-256 (hex) of the stored HTML'),
    templateVersion: z.string(),
    createdAt: isoInstant,
    deliveries: z
      .array(ReportDeliverySchema)
      .max(20)
      .describe('Emails of this report, newest first (at most 20)'),
  })
  .describe('assistant-report-view/1: metadata of a report; the HTML is never stored in MySQL');
export type ReportView = z.output<typeof ReportViewSchema>;

export const ReportResultSchema = z.object({
  report: ReportViewSchema,
  html: z
    .string()
    .nullable()
    .describe(
      'The self-contained, inert report HTML (no script, link or external resource) for a ' +
        'sandboxed iframe (`srcdoc`, `sandbox=""`); null unless `status` is `available`',
    ),
});
export type ReportResultView = z.output<typeof ReportResultSchema>;

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
  confirmation: '0193a1c2-8180-73a5-81c8-9072d38ebf08',
  proposal: '0193a1c2-8290-74b6-92d9-a183e49fc009',
  result: '0193a1c2-83a0-75c7-83ea-b294f5a0d10a',
  report: '0193a1c2-84b0-76d8-94fb-c3a5f6b1e20b',
  reportExecution: '0193a1c2-85c0-77e9-850c-d4b6a7c2f30c',
  delivery: '0193a1c2-86d0-78fa-961d-e5c7b8d3a40d',
};

const reportPeriod = {
  from: '2026-11-13T10:00:00.000Z',
  to: '2026-11-20T10:00:00.000Z',
  granularity: 'day' as const,
  atoRange: '7d' as const,
};

const reportFigures = [
  { label: 'Messages', value: '12,480' },
  { label: 'Threats', value: '312' },
  { label: 'Quarantined', value: '148' },
  { label: 'Delivery success', value: '98.6%' },
];

/** A `report` card (step AI-R D2 step 10). */
const reportCardExample = {
  version: 'assistant-card/1' as const,
  executionId: ID.reportExecution,
  tool: 'report_generate',
  title: 'Security report: Last 7 days',
  status: 'ok' as const,
  kind: 'report' as const,
  report: {
    reportId: ID.report,
    title: 'Security report: Last 7 days',
    period: { ...reportPeriod, label: 'Last 7 days' },
    generatedAt: '2026-11-20T10:00:02.000Z',
    sizeBytes: 182_344,
    sections: [
      'summary',
      'traffic',
      'threats',
      'domains',
      'delivery',
      'processing',
      'url_clicks',
    ] as Array<(typeof REPORT_SECTIONS)[number]>,
    omitted: [
      { section: 'quarantine' as const, reason: 'permission' as const, code: 'quarantine:read' },
      { section: 'ato' as const, reason: 'not_enabled' as const },
    ],
    figures: reportFigures,
  },
  portalLinks: [{ label: 'Open full size', href: `/assistant/reports/${ID.report}` }],
  refs: ['r1.1'],
};

/** The placeholder of an HTML document (synthetic; the real one is a full dashboard). */
const EXAMPLE_REPORT_HTML =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security report: Last 7 ' +
  'days</title></head><body><main class="report"><h1>Security report</h1></main></body></html>';

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
  title: 'List policies',
  operationId: 'PolicyManagementController_list_v1',
  access: 'read',
  risk: 'read',
  decision: 'allowed',
  status: 'succeeded',
  httpStatus: 200,
  errorCode: null,
  message: null,
  hasMore: false,
  card,
  latencyMs: 42,
  createdAt: '2026-11-20T10:00:01.000Z',
  confirmation: null,
};

/** Obvious placeholders (never token- or key-shaped values). */
const EXAMPLE_TOKEN = 'example_confirmation_token_placeholder_0000';
const EXAMPLE_DIGEST = '0123456789abcdef'.repeat(4);

const confirmation: ConfirmationViewDto = {
  id: ID.confirmation,
  executionId: ID.proposal,
  resultExecutionId: null,
  conversationId: ID.conversation,
  tool: 'policy_management_disable',
  operationId: 'PolicyManagementController_disable_v1',
  risk: 'medium',
  requiresReauth: false,
  reauthFresh: false,
  status: 'pending',
  summary: {
    version: 'assistant-confirmation/1',
    title: 'Disable policy',
    action: 'Disables the policy "Block executables".',
    target: [{ label: 'Policy', value: 'Block executables' }],
    changes: [{ label: 'Status', before: 'active', after: 'disabled' }],
    impact: ['Stops evaluating this policy for new mail.'],
    warnings: [],
    reversible: true,
    portalRoute: `/policies/${ID.policy}`,
    request: { method: 'POST', path: `/api/v1/policies/${ID.policy}/disable` },
  },
  actionDigest: EXAMPLE_DIGEST,
  expiresAt: '2026-11-20T10:05:02.000Z',
  createdAt: '2026-11-20T10:00:02.000Z',
  decidedAt: null,
  executedAt: null,
  result: null,
};

const proposal: ExecutionView = {
  ...execution,
  id: ID.proposal,
  seq: 2,
  ref: 'r2',
  tool: 'policy_management_disable',
  operationId: 'PolicyManagementController_disable_v1',
  access: 'write',
  risk: 'medium',
  status: 'pending_confirmation',
  httpStatus: null,
  card: {
    version: 'assistant-card/1',
    executionId: ID.proposal,
    tool: 'policy_management_disable',
    title: 'Disable policy',
    status: 'ok',
    kind: 'message',
    message: 'Waiting for your confirmation',
    portalLinks: [],
    refs: [],
  },
  latencyMs: null,
  createdAt: '2026-11-20T10:00:02.000Z',
  confirmation,
};

const confirmed: ConfirmationViewDto = {
  ...confirmation,
  resultExecutionId: ID.result,
  status: 'executed',
  decidedAt: '2026-11-20T10:01:00.000Z',
  executedAt: '2026-11-20T10:01:00.250Z',
  result: { httpStatus: 200, error: null },
};

const resultExecution: ExecutionView = {
  ...execution,
  id: ID.result,
  turnId: null,
  parentExecutionId: ID.proposal,
  seq: 3,
  ref: 'r3',
  tool: 'policy_management_disable',
  operationId: 'PolicyManagementController_disable_v1',
  access: 'write',
  risk: 'medium',
  card: {
    version: 'assistant-card/1',
    executionId: ID.result,
    tool: 'policy_management_disable',
    title: 'Disable policy',
    status: 'ok',
    kind: 'kv',
    fields: [
      { key: 'name', label: 'Name', value: 'Block executables' },
      { key: 'status', label: 'Status', value: 'disabled' },
    ],
    portalLinks: [{ label: 'Block executables', href: `/policies/${ID.policy}` }],
    refs: ['r3.1'],
  },
  latencyMs: 250,
  createdAt: '2026-11-20T10:01:00.250Z',
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
  turnResult: {
    turn,
    message: assistantMessage,
    executions: [execution],
    confirmations: [],
  } satisfies TurnResultView,
  turnResultWithProposal: {
    turn: { ...turn, toolCalls: 2 },
    message: {
      ...assistantMessage,
      content:
        'I prepared this change. Review it in the confirmation card; nothing changes until you ' +
        'confirm it.',
    },
    executions: [execution, proposal],
    confirmations: [{ confirmation, token: EXAMPLE_TOKEN }],
  } satisfies TurnResultView,
  cancel: { turnId: ID.turn, status: 'running' } satisfies CancelResultView,
  execution,
  confirmation,
  confirm: { token: EXAMPLE_TOKEN, actionDigest: EXAMPLE_DIGEST } satisfies ConfirmBody,
  confirmHighRisk: {
    token: EXAMPLE_TOKEN,
    actionDigest: EXAMPLE_DIGEST,
    reauth: { password: '<your password>', totpCode: '123456' },
  } satisfies ConfirmBody,
  confirmResult: {
    confirmation: { ...confirmed, summary: confirmation.summary },
    execution: resultExecution,
  } satisfies ConfirmResultView,
  reportCard: reportCardExample,
  report: {
    report: {
      id: ID.report,
      conversationId: ID.conversation,
      executionId: ID.reportExecution,
      status: 'available',
      title: 'Security report: Last 7 days',
      period: reportPeriod,
      sections: [
        'summary',
        'traffic',
        'threats',
        'domains',
        'delivery',
        'processing',
        'url_clicks',
      ],
      omitted: [
        { section: 'quarantine', reason: 'permission', code: 'quarantine:read' },
        { section: 'ato', reason: 'not_enabled', code: null },
      ],
      figures: reportFigures,
      sizeBytes: 182_344,
      sha256: 'fedcba9876543210'.repeat(4),
      templateVersion: 'assistant-report/1',
      createdAt: '2026-11-20T10:00:02.000Z',
      deliveries: [
        {
          id: ID.delivery,
          to: 'analyst@example.test',
          recipientKind: 'self',
          status: 'sent',
          errorCode: null,
          requestedAt: '2026-11-20T10:02:00.000Z',
          sentAt: '2026-11-20T10:02:03.000Z',
        },
      ],
    },
    html: EXAMPLE_REPORT_HTML,
  } satisfies ReportResultView,
  reportPurged: {
    report: {
      id: ID.report,
      conversationId: ID.conversation,
      executionId: ID.reportExecution,
      status: 'purged',
      title: 'Security report: Last 7 days',
      period: reportPeriod,
      sections: ['summary', 'traffic'],
      omitted: [],
      figures: reportFigures,
      sizeBytes: 182_344,
      sha256: 'fedcba9876543210'.repeat(4),
      templateVersion: 'assistant-report/1',
      createdAt: '2026-11-20T10:00:02.000Z',
      deliveries: [],
    },
    html: null,
  } satisfies ReportResultView,
  cancelConfirmation: {
    confirmation: {
      ...confirmation,
      status: 'cancelled',
      decidedAt: '2026-11-20T10:01:00.000Z',
    },
  } satisfies CancelConfirmationResultView,
};
