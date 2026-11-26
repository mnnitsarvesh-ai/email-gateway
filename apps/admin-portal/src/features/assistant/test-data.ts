import type {
  AssistantCard,
  AssistantSettings,
  AssistantStatus,
  AssistantTools,
  ConfirmationSummary,
  ConfirmationView,
  Conversation,
  Execution,
  ReportDocument,
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
  keySource: 'platform',
  fallbackActive: false,
  dataSharing: 'metadata',
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
    title: card?.title ?? 'List policies',
    operationId: 'PolicyManagementController_list_v1',
    access: 'read',
    risk: 'read',
    decision: 'allowed',
    status: 'succeeded',
    httpStatus: 200,
    errorCode: null,
    message: null,
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
    feedback?: StoredMessage['feedback'];
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
      feedback: null,
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
      feedback: options.feedback ?? null,
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
  userDailyTokenBudget: null,
  useTenantKey: false,
  tenantKeyFallbackToPlatform: false,
  tenantKey: null,
  tenantKeysOffered: { enabled: false, providers: [], models: [] },
  effectiveLimits: {
    turnsPerUserPerMinute: 6,
    messageMaxChars: 4000,
    toolRoundsPerTurn: 8,
    toolCallsPerTurn: 16,
    turnDeadlineSeconds: 300,
    platformDailyCapSet: false,
    tenantDailyTokensMax: 5_000_000,
    reportsPerUserPerDay: 20,
    reportEmailsPerUserPerDay: 10,
    reportEmailsPerTenantPerDay: 50,
    confirmationTtlSeconds: 900,
    retentionDays: { min: 1, max: 365 },
  },
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

/*
 * Step AI-3 identity and tenant administration (synthetic; operation ids again not real
 * controller ids).
 */

export const TARGET_USER_ID = '01930000-0000-7000-8000-00000000a001';
export const WEBHOOK_ID = '01930000-0000-7000-8000-00000000a101';
export const GUARD_EXECUTION_ID = '01930000-0000-7000-8000-00000000e320';

/** The server-authored `self` guard message (AI-3 D3); it names a portal location in prose only. */
export const SELF_GUARD_MESSAGE =
  'Changes to your own account, roles, status, MFA or sessions are not available in chat. Ask another administrator, or use your account pages in the portal.';

/** A role change: always `high` (AI-3 D2). */
export const ROLES_HIGH_SUMMARY: ConfirmationSummary = {
  version: 'assistant-confirmation/1',
  title: 'Replace user roles',
  action: 'Replaces the roles of Priya Raman.',
  target: [
    { label: 'User', value: 'Priya Raman', untrusted: true },
    { label: 'Email', value: 'priya.raman@example.com' },
  ],
  changes: [{ label: 'Roles', before: 'security_analyst', after: 'organization_admin' }],
  impact: ['The user gets every permission of the new roles at their next request'],
  warnings: ['Grants full administrative access to this organization.'],
  reversible: true,
  portalRoute: `/users/${TARGET_USER_ID}`,
  request: { method: 'PUT', path: `/api/v1/users/${TARGET_USER_ID}/roles` },
};

export const ROLES_VIEW_OVERRIDES: Partial<ConfirmationView> = {
  tool: 'users_replace_roles',
  operationId: 'users.replace-roles',
  risk: 'high',
  requiresReauth: true,
  summary: ROLES_HIGH_SUMMARY,
};

/** The D4 escalation warning of `webhooks_update` with `body.url`. */
export const WEBHOOK_URL_WARNING = "Sends this webhook's event data to a new address.";

/** A `webhooks_update` raised from `low` to `high` by its URL change (AI-3 D4). */
export const WEBHOOK_ESCALATED_SUMMARY: ConfirmationSummary = {
  version: 'assistant-confirmation/1',
  title: 'Update webhook',
  action: 'Updates the webhook "SIEM forwarder".',
  target: [{ label: 'Webhook', value: 'SIEM forwarder' }],
  changes: [
    {
      label: 'URL',
      before: 'https://siem.example.com/hooks/gateway',
      after: 'https://collector.example.net/ingest',
    },
  ],
  impact: [],
  warnings: [WEBHOOK_URL_WARNING],
  reversible: true,
  portalRoute: `/webhooks/${WEBHOOK_ID}`,
  request: { method: 'PATCH', path: `/api/v1/webhooks/${WEBHOOK_ID}` },
};

export const WEBHOOK_ESCALATED_VIEW_OVERRIDES: Partial<ConfirmationView> = {
  tool: 'webhooks_update',
  operationId: 'webhooks.update',
  risk: 'high',
  requiresReauth: true,
  summary: WEBHOOK_ESCALATED_SUMMARY,
};

/** Display title of `users_replace_roles` (the api's execution view `title`). */
export const GUARD_TOOL_TITLE = 'Replace the roles of a user';

/**
 * A stored execution refused by a proposal guard (`denied_guard`): no confirmation, no api call.
 * The api stores it without a card, its decision as the error code; the view carries the guard
 * message (derived from the operation's spec) and the tool's display title.
 */
export function deniedGuardExecution(): Execution {
  return execution(null, {
    id: GUARD_EXECUTION_ID,
    ref: 'r2',
    seq: 2,
    tool: 'users_replace_roles',
    title: GUARD_TOOL_TITLE,
    operationId: 'UsersController_replaceRoles_v1',
    access: 'write',
    risk: 'high',
    decision: 'denied_guard',
    status: 'refused',
    httpStatus: null,
    errorCode: 'denied_guard',
    message: SELF_GUARD_MESSAGE,
    hasMore: false,
  });
}

/** The `tool.denied` frame of a self-guarded call. */
export function deniedGuardFrame(): string {
  return sseFrame('tool.denied', {
    executionId: GUARD_EXECUTION_ID,
    tool: 'users_replace_roles',
    decision: 'denied_guard',
    message: SELF_GUARD_MESSAGE,
  });
}

// Step AI-R: a report card and its document (`GET /assistant/reports/{reportId}`).
export const REPORT_ID = '01930000-0000-7000-8000-00000000a001';
export const REPORT_EXECUTION_ID = '01930000-0000-7000-8000-00000000e320';
export const DELIVERY_ID = '01930000-0000-7000-8000-00000000d001';

/** Inert report HTML as the api renders it (constant style, inline SVG, no script or link). */
export const REPORT_HTML =
  '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
  '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">' +
  '<title>Security report</title><style>body{font-family:sans-serif}</style></head>' +
  '<body><h1>Security report</h1><p>E2E &lt;script&gt; organization</p>' +
  '<svg role="img" aria-label="Traffic" viewBox="0 0 10 10"><rect width="4" height="8"></rect></svg>' +
  '</body></html>';

export const REPORT_CARD: AssistantCard = {
  version: 'assistant-card/1',
  executionId: REPORT_EXECUTION_ID,
  tool: 'report_generate',
  title: 'Security report: Last 7 days',
  status: 'ok',
  kind: 'report',
  report: {
    reportId: REPORT_ID,
    title: 'Security report: Last 7 days',
    period: {
      from: '2026-11-16T00:00:00.000Z',
      to: '2026-11-23T00:00:00.000Z',
      granularity: 'day',
      atoRange: '7d',
      label: 'Last 7 days',
    },
    generatedAt: '2026-11-23T09:30:00.000Z',
    sizeBytes: 182_344,
    sections: ['summary', 'traffic', 'threats', 'quarantine', 'ato'],
    omitted: [
      { section: 'quarantine', reason: 'permission', code: 'quarantine:read' },
      { section: 'ato', reason: 'not_enabled' },
    ],
    figures: [
      { label: 'Messages', value: '12,480' },
      { label: 'Threats', value: '312' },
    ],
  },
  portalLinks: [{ label: 'Open full size', href: `/assistant/reports/${REPORT_ID}` }],
  refs: ['r1.1'],
};

export function reportDocument(
  overrides: Partial<ReportDocument['report']> = {},
  html: string | null = REPORT_HTML,
): ReportDocument {
  return {
    html,
    report: {
      id: REPORT_ID,
      conversationId: CONVERSATION_ID,
      executionId: REPORT_EXECUTION_ID,
      status: 'available',
      title: 'Security report: Last 7 days',
      period: {
        from: '2026-11-16T00:00:00.000Z',
        to: '2026-11-23T00:00:00.000Z',
        granularity: 'day',
        atoRange: '7d',
      },
      sections: ['summary', 'traffic', 'threats'],
      omitted: [{ section: 'quarantine', reason: 'permission', code: 'quarantine:read' }],
      figures: [
        { label: 'Messages', value: '12,480' },
        { label: 'Threats', value: '312' },
      ],
      sizeBytes: 182_344,
      sha256: 'ab'.repeat(32),
      templateVersion: 'assistant-report/1',
      createdAt: '2026-11-23T09:30:00.000Z',
      deliveries: [],
      job: null,
      ...overrides,
    },
  };
}

/** The `report_send_email` summary as the api renders it (packages/assistant impact template). */
export const REPORT_SEND_SUMMARY: ConfirmationSummary = {
  version: 'assistant-confirmation/1',
  title: 'Email security report',
  action: 'Sends the security report as an HTML email to analyst@example.test.',
  target: [
    { label: 'Report', value: 'Security report: Last 7 days' },
    { label: 'Period', value: 'Last 7 days' },
    { label: 'Recipient', value: 'analyst@example.test' },
    { label: 'Recipient type', value: 'your own address' },
    { label: 'Size', value: '178.1 KiB' },
  ],
  changes: [],
  impact: [
    'The email leaves the platform through the notification mailer; the recipient can forward it.',
    'The same HTML is attached as a file.',
  ],
  warnings: [
    'Emails cannot be recalled after sending.',
    '9 of 10 report emails left today for you (47 for your organization).',
  ],
  reversible: false,
  portalRoute: `/assistant/reports/${REPORT_ID}`,
  request: { method: 'POST', path: 'native:report_send_email' },
};

/** The four-eyes guard message of an ATO response decision (packages/assistant `ato_four_eyes`, step AI-4 D3). */
export const ATO_FOUR_EYES_MESSAGE =
  'This response needs a different person to decide it. The person who requested a response, or who created the API key that requested it, can never approve or reject it, and deciding needs a session signed in with MFA. Ask another responder to decide it in chat or on the Responses page.';

/** Step AI-5 (design 33): an eDiscovery case and its export confirmation (synthetic values). */
export const CASE_ID = '0193aaaa-0000-7000-8000-000000000083';
export const SEARCH_ID = '0193aaaa-0000-7000-8000-000000000084';

export const EXPORT_SUMMARY: ConfirmationSummary = {
  version: 'assistant-confirmation/1',
  title: 'Export eDiscovery search',
  action:
    'Builds an encrypted export of the decrypted original messages of 12 hits; download it on the case page in the portal until it expires; chat never shows its content.',
  target: [
    { label: 'Search status', value: 'completed' },
    { label: 'Hits', value: '12' },
  ],
  changes: [],
  impact: ['The export is built in the background by the archive.'],
  warnings: ['The export packages decrypted original messages.'],
  reversible: false,
  portalRoute: `/ediscovery/${CASE_ID}`,
  request: { method: 'POST', path: `/api/v1/ediscovery/cases/${CASE_ID}/exports` },
};

/** The AI-5 guard messages (packages/assistant `GUARD_MESSAGES`, step AI-5 D4). */
export const RETENTION_DEFAULT_POLICY_MESSAGE =
  'The default retention policy cannot be deleted. Choose another default in the archive settings first (Retention and lock in the portal).';
export const CAPTURE_NOT_RETRYABLE_MESSAGE =
  'Only a failed capture can be retried. A lost capture cannot be recovered, and a pending one is still being retried by the archive.';
export const CASE_ACTIVE_HOLDS_MESSAGE =
  'This case still has active legal holds, so it cannot be closed. Legal holds are released only on the Legal holds page in the portal by a person with the legal-hold permission; close the case after that.';
