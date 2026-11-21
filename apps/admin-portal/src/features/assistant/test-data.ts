import type {
  AssistantCard,
  AssistantSettings,
  AssistantStatus,
  AssistantTools,
  ConfirmationSummary,
  ConfirmationView,
  Conversation,
  Execution,
  StoredMessage,
} from './types';

/** Synthetic assistant documents for the WP5 unit tests (contracts §35 shapes). */

export const CONVERSATION_ID = '01930000-0000-7000-8000-00000000e001';
export const CONVERSATION_ID_2 = '01930000-0000-7000-8000-00000000e002';
export const TURN_ID = '01930000-0000-7000-8000-00000000e101';
export const MESSAGE_ID = '01930000-0000-7000-8000-00000000e201';
export const USER_MESSAGE_ID = '01930000-0000-7000-8000-00000000e202';
export const EXECUTION_ID = '01930000-0000-7000-8000-00000000e301';
export const EXECUTION_ID_2 = '01930000-0000-7000-8000-00000000e302';
export const POLICY_ID = '01930000-0000-7000-8000-00000000f001';
export const POLICY_ID_2 = '01930000-0000-7000-8000-00000000f002';
export const POLICY_ID_3 = '01930000-0000-7000-8000-00000000f003';

export const STATUS_AVAILABLE: AssistantStatus = {
  available: true,
  provider: 'fake',
  model: 'fake-model',
  limits: { messageMaxChars: 4000, turnsPerMinute: 6 },
  budget: { dailyTokens: 1_000_000, usedToday: 1200 },
};

export function statusUnavailable(reason: NonNullable<AssistantStatus['reason']>): AssistantStatus {
  return { ...STATUS_AVAILABLE, available: false, reason };
}

export const TOOLS: AssistantTools = {
  registryVersion: '0123456789abcdef',
  tools: [
    {
      name: 'policy_management_list',
      module: 'policies',
      title: 'List policies',
      access: 'read',
      risk: 'read',
    },
    {
      name: 'quarantine_entries_search',
      module: 'quarantine',
      title: 'Search quarantine',
      access: 'read',
      risk: 'read',
    },
    {
      name: 'reports_traffic',
      module: 'reports',
      title: 'Traffic report',
      access: 'read',
      risk: 'read',
    },
  ],
};

export const CONVERSATION: Conversation = {
  id: CONVERSATION_ID,
  title: 'Policy review',
  status: 'active',
  turnCount: 1,
  lastTurnAt: '2026-11-20T09:00:00.000Z',
  purgeAfter: '2026-12-20T09:00:00.000Z',
  contentPurged: false,
  underPlatformOverride: false,
  rowVersion: 1,
  createdAt: '2026-11-20T08:59:00.000Z',
  updatedAt: '2026-11-20T09:00:00.000Z',
};

export const TABLE_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: EXECUTION_ID,
  tool: 'policy_management_list',
  title: 'Policies',
  status: 'ok',
  kind: 'table',
  columns: [
    { key: 'name', label: 'Name' },
    { key: 'status', label: 'Status' },
  ],
  rows: [
    { name: 'Block executables', status: 'active' },
    { name: 'Tag external mail', status: 'active' },
  ],
  nextCursor: true,
  portalLinks: [
    { label: 'Policies', href: '/policies' },
    { label: 'Block executables', href: `/policies/${POLICY_ID}`, ref: 'r1.1' },
    { label: 'Tag external mail', href: `/policies/${POLICY_ID_2}`, ref: 'r1.2' },
  ],
  refs: ['r1.1', 'r1.2'],
};

export const KV_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: EXECUTION_ID_2,
  tool: 'policy_management_get',
  title: 'Policy details',
  status: 'ok',
  kind: 'kv',
  fields: [
    { key: 'name', label: 'Name', value: 'Block executables' },
    { key: 'priority', label: 'Priority', value: 10 },
    { key: 'enabled', label: 'Enabled', value: true },
    { key: 'description', label: 'Description', value: null },
  ],
  portalLinks: [{ label: 'Block executables', href: `/policies/${POLICY_ID}` }],
  refs: ['r2'],
};

export const SERIES_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: EXECUTION_ID_2,
  tool: 'reports_traffic',
  title: 'Traffic',
  status: 'ok',
  kind: 'series',
  series: {
    x: ['2026-11-18', '2026-11-19', '2026-11-20'],
    series: [
      { name: 'Delivered', values: [120, 140, null] },
      { name: 'Blocked', values: [4, 9, 2] },
    ],
  },
  portalLinks: [{ label: 'Reports', href: '/reports' }],
  refs: ['r2'],
};

export const ERROR_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: EXECUTION_ID_2,
  tool: 'policy_management_get',
  title: 'Policy details',
  status: 'error',
  kind: 'error',
  error: { httpStatus: 404, code: 'policy_not_found', message: 'Policy not found' },
  portalLinks: [{ label: 'Policies', href: '/policies' }],
  refs: [],
};

export function execution(
  card: AssistantCard | null,
  overrides: Partial<Execution> = {},
): Execution {
  return {
    id: card?.executionId ?? EXECUTION_ID,
    conversationId: CONVERSATION_ID,
    turnId: TURN_ID,
    parentExecutionId: null,
    seq: 1,
    ref: 'r1',
    tool: card?.tool ?? 'policy_management_list',
    operationId: 'PolicyManagementController_list_v1',
    access: 'read',
    risk: 'read',
    decision: 'allowed',
    status: 'succeeded',
    httpStatus: 200,
    errorCode: null,
    hasMore: card?.nextCursor === true,
    card: card as Execution['card'],
    latencyMs: 40,
    createdAt: '2026-11-20T09:00:01.000Z',
    confirmation: null,
    ...overrides,
  };
}

export function storedExchange(
  options: {
    question?: string;
    answer?: string | null;
    status?: StoredMessage['turn']['status'];
    errorCode?: string | null;
    executions?: Execution[];
  } = {},
): StoredMessage[] {
  const turn = {
    id: TURN_ID,
    status: options.status ?? 'completed',
    errorCode: options.errorCode ?? null,
  };
  const messages: StoredMessage[] = [
    {
      id: USER_MESSAGE_ID,
      turnId: TURN_ID,
      seq: 1,
      role: 'user',
      content: options.question ?? 'Which policies are active?',
      createdAt: '2026-11-20T09:00:00.000Z',
      turn,
      executions: [],
    },
  ];
  if (options.answer !== null) {
    messages.push({
      id: MESSAGE_ID,
      turnId: TURN_ID,
      seq: 2,
      role: 'assistant',
      content: options.answer ?? 'Two policies are **active**.',
      createdAt: '2026-11-20T09:00:03.000Z',
      turn,
      executions: options.executions ?? [],
    });
  }
  return messages;
}

export const SETTINGS: AssistantSettings = {
  version: 'assistant-settings/1',
  enabled: false,
  externalProcessingAcknowledged: false,
  externalProcessingAcknowledgedAt: null,
  externalProcessingAcknowledgedBy: null,
  dailyTokenBudget: null,
  effectiveDailyTokenBudget: 1_000_000,
  retentionDays: 30,
  dataSharing: 'metadata',
  featureEnabled: true,
  rowVersion: 3,
  updatedAt: '2026-11-19T10:00:00.000Z',
};

/** A `text/event-stream` body from SSE frames, split into the given chunks of text. */
export function sseFrame(type: string, data: unknown): string {
  return `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
}

export function streamOf(chunks: readonly string[], options: { failAfter?: boolean } = {}) {
  const encoder = new TextEncoder();
  let index = 0;
  // Pull-based: every chunk is delivered before the stream closes or fails (an error raised in
  // `start` would discard the queued chunks).
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const chunk = chunks[index];
      index += 1;
      if (chunk !== undefined) controller.enqueue(encoder.encode(chunk));
      else if (options.failAfter) controller.error(new TypeError('network connection was lost'));
      else controller.close();
    },
  });
}

/** The frames of a completed turn with one table result and some text. */
export function completedTurnFrames(text = 'Two policies are **active**.'): string[] {
  return [
    sseFrame('turn.started', { turnId: TURN_ID, conversationId: CONVERSATION_ID, seq: 1 }),
    ': heartbeat\n\n',
    sseFrame('tool.started', {
      executionId: EXECUTION_ID,
      tool: 'policy_management_list',
      title: 'Policies',
    }),
    sseFrame('tool.completed', {
      executionId: EXECUTION_ID,
      status: 'succeeded',
      decision: 'allowed',
      card: TABLE_CARD,
    }),
    sseFrame('text.delta', { text: text.slice(0, 10) }),
    sseFrame('text.delta', { text: text.slice(10) }),
    sseFrame('turn.completed', {
      turnId: TURN_ID,
      status: 'completed',
      usage: { inputTokens: 100, outputTokens: 20 },
      messageId: MESSAGE_ID,
    }),
  ];
}

/*
 * Step AI-2 confirmations (synthetic). The operation ids are deliberately not real
 * `<Name>Controller_<method>_v1` ids: the registry generator attributes real ids found in this
 * feature's files to the assistant feature (AI-1 §12 #10).
 */

export const CONFIRMATION_ID = '01930000-0000-7000-8000-00000000c001';
export const PROPOSAL_EXECUTION_ID = '01930000-0000-7000-8000-00000000e310';
export const RESULT_EXECUTION_ID = '01930000-0000-7000-8000-00000000e311';
/** Shape of a real token (43 base64url characters), obviously synthetic. */
export const CONFIRMATION_TOKEN = 'a'.repeat(43);
export const ACTION_DIGEST = 'ab'.repeat(32);

export const LOW_SUMMARY: ConfirmationSummary = {
  version: 'assistant-confirmation/1',
  title: 'Create policy',
  action:
    'Creates the draft policy "Quarantine inbound executables". It does not apply to mail until it is published.',
  target: [{ label: 'Policy', value: 'Quarantine inbound executables' }],
  changes: [
    { label: 'Name', before: null, after: 'Quarantine inbound executables' },
    { label: 'Status', after: 'draft' },
  ],
  definition: {
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'quarantine-executables',
        when: 'attachment.type_family in [executable] (any)',
        actions: 'QUARANTINE',
      },
    ],
  },
  impact: [],
  warnings: [],
  reversible: true,
  portalRoute: `/policies/${POLICY_ID}`,
  request: { method: 'POST', path: '/api/v1/policies' },
};

export const MEDIUM_SUMMARY: ConfirmationSummary = {
  version: 'assistant-confirmation/1',
  title: 'Publish policy',
  action: 'Publishes version 1 of "Quarantine inbound executables" and makes it active.',
  target: [{ label: 'Policy', value: 'Quarantine inbound executables' }],
  changes: [{ label: 'Status', before: 'draft', after: 'active' }],
  impact: ['Applies to new inbound mail of the organization within a minute'],
  warnings: [],
  reversible: true,
  portalRoute: `/policies/${POLICY_ID}`,
  request: { method: 'POST', path: `/api/v1/policies/${POLICY_ID}/versions/1/publish` },
};

export const HIGH_SUMMARY: ConfirmationSummary = {
  version: 'assistant-confirmation/1',
  title: 'Delete quarantined message',
  action: 'Deletes the quarantined message permanently.',
  target: [
    { label: 'Subject', value: 'Invoice 4711 overdue', untrusted: true },
    { label: 'Sender', value: 'billing@example.net', untrusted: true },
  ],
  changes: [{ label: 'Status', before: 'quarantined', after: 'deleted' }],
  impact: ['The recipient never receives this message'],
  warnings: ['Deleting cannot be undone'],
  reversible: false,
  portalRoute: '/quarantine',
  request: { method: 'DELETE', path: '/api/v1/quarantine/entries/example-entry' },
};

export function confirmationView(overrides: Partial<ConfirmationView> = {}): ConfirmationView {
  return {
    id: CONFIRMATION_ID,
    executionId: PROPOSAL_EXECUTION_ID,
    resultExecutionId: null,
    conversationId: CONVERSATION_ID,
    tool: 'policy_management_create',
    operationId: 'policy-management.create',
    risk: 'low',
    requiresReauth: false,
    reauthFresh: false,
    status: 'pending',
    summary: LOW_SUMMARY,
    actionDigest: ACTION_DIGEST,
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    createdAt: '2026-11-20T09:00:01.000Z',
    decidedAt: null,
    executedAt: null,
    result: null,
    ...overrides,
  };
}

export const HIGH_VIEW_OVERRIDES: Partial<ConfirmationView> = {
  tool: 'quarantine_entries_remove',
  operationId: 'quarantine-entries.remove',
  risk: 'high',
  requiresReauth: true,
  summary: HIGH_SUMMARY,
};

export const PROPOSAL_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: PROPOSAL_EXECUTION_ID,
  tool: 'policy_management_create',
  title: 'Create policy',
  status: 'ok',
  kind: 'message',
  message: 'Waiting for your confirmation',
  portalLinks: [],
  refs: [],
};

export const RESULT_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: RESULT_EXECUTION_ID,
  tool: 'policy_management_create',
  title: 'Created policy',
  status: 'ok',
  kind: 'kv',
  fields: [
    { key: 'name', label: 'Name', value: 'Quarantine inbound executables' },
    { key: 'status', label: 'Status', value: 'draft' },
  ],
  portalLinks: [{ label: 'Quarantine inbound executables', href: `/policies/${POLICY_ID}` }],
  refs: ['r3'],
};

export const FAILED_RESULT_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: RESULT_EXECUTION_ID,
  tool: 'policy_management_create',
  title: 'Create policy',
  status: 'error',
  kind: 'error',
  error: { httpStatus: 409, code: 'policy_conflict', message: 'A policy with this name exists' },
  portalLinks: [],
  refs: [],
};

/** The proposal execution of a write (status `pending_confirmation`). */
export function proposalExecution(view: ConfirmationView = confirmationView()): Execution {
  return execution(PROPOSAL_CARD, {
    id: view.executionId,
    ref: 'r2',
    seq: 2,
    tool: view.tool,
    operationId: view.operationId,
    access: 'write',
    risk: view.risk,
    status: 'pending_confirmation',
    httpStatus: null,
    hasMore: false,
    confirmation: view as Execution['confirmation'],
  });
}

/** The confirmed write's execution (child of the proposal, no turn). */
export function resultExecution(card: AssistantCard = RESULT_CARD, httpStatus = 201): Execution {
  return execution(card, {
    id: RESULT_EXECUTION_ID,
    turnId: null,
    parentExecutionId: PROPOSAL_EXECUTION_ID,
    ref: 'r3',
    seq: 3,
    tool: 'policy_management_create',
    operationId: 'policy-management.create',
    access: 'write',
    risk: 'low',
    status: card.status === 'ok' ? 'succeeded' : 'failed',
    httpStatus,
    errorCode: card.error?.code ?? null,
    hasMore: false,
  });
}

/** The frames of a turn that proposes one write. */
export function proposalTurnFrames(
  view: ConfirmationView = confirmationView(),
  token: string = CONFIRMATION_TOKEN,
): string[] {
  return [
    sseFrame('turn.started', { turnId: TURN_ID, conversationId: CONVERSATION_ID, seq: 1 }),
    sseFrame('tool.started', {
      executionId: view.executionId,
      tool: view.tool,
      title: view.summary?.title ?? view.tool,
    }),
    sseFrame('tool.completed', {
      executionId: view.executionId,
      status: 'pending_confirmation',
      decision: 'allowed',
      card: { ...PROPOSAL_CARD, executionId: view.executionId, tool: view.tool },
    }),
    sseFrame('confirmation.required', { confirmation: view, token }),
    sseFrame('text.delta', {
      text: 'I prepared this change. Review it in the confirmation card.',
    }),
    sseFrame('turn.completed', {
      turnId: TURN_ID,
      status: 'completed',
      usage: { inputTokens: 100, outputTokens: 20 },
      messageId: MESSAGE_ID,
    }),
  ];
}
