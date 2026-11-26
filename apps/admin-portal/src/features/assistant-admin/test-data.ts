import type { SuccessBody } from '@/lib/api/types';
import { SETTINGS } from '@/features/assistant/test-data';
import type { AssistantSettings } from '@/features/assistant/types';

/** Synthetic documents of the AI administration routes (contracts §35.6 shapes, step AI-6). */

export const USER_A = {
  id: '01930000-0000-7000-8000-0000000a0001',
  displayName: 'Ada Analyst',
  email: 'ada@tenant.example.test',
};
export const USER_B = {
  id: '01930000-0000-7000-8000-0000000a0002',
  displayName: null,
  email: null,
};
export const AUDIT_CONVERSATION_ID = '01930000-0000-7000-8000-0000000ac001';
export const AUDIT_MESSAGE_ID = '01930000-0000-7000-8000-0000000ac201';

export const USAGE_USERS: SuccessBody<'AssistantAdminController_usageByUser_v1'> = {
  from: '2026-10-28',
  to: '2026-11-26',
  data: [
    {
      day: '2026-11-26',
      user: USER_A,
      keySource: 'platform',
      turns: 3,
      inputTokens: 1500,
      outputTokens: 400,
      cacheReadTokens: 100,
      cacheWriteTokens: 0,
      totalTokens: 2000,
      estimatedCostMicros: 12_500,
    },
    {
      day: '2026-11-25',
      user: USER_B,
      keySource: 'tenant',
      turns: 1,
      inputTokens: 700,
      outputTokens: 50,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      totalTokens: 750,
      estimatedCostMicros: null,
    },
  ],
  totals: {
    users: [
      {
        user: USER_A,
        turns: 3,
        inputTokens: 1500,
        outputTokens: 400,
        cacheReadTokens: 100,
        cacheWriteTokens: 0,
        totalTokens: 2000,
        estimatedCostMicros: 12_500,
      },
      {
        user: USER_B,
        turns: 1,
        inputTokens: 700,
        outputTokens: 50,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        totalTokens: 750,
        estimatedCostMicros: null,
      },
    ],
    overall: {
      turns: 4,
      inputTokens: 2200,
      outputTokens: 450,
      cacheReadTokens: 100,
      cacheWriteTokens: 0,
      totalTokens: 2750,
      estimatedCostMicros: 12_500,
    },
  },
  nextCursor: null,
};

export const ORG_USAGE: SuccessBody<'AssistantUsageController_get_v1'> = {
  from: '2026-10-28',
  to: '2026-11-26',
  rows: [
    {
      day: '2026-11-25',
      provider: 'fake',
      model: 'fake-model',
      turns: 1,
      inputTokens: 700,
      outputTokens: 50,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      costMicros: null,
    },
    {
      day: '2026-11-26',
      provider: 'fake',
      model: 'fake-model',
      turns: 3,
      inputTokens: 1500,
      outputTokens: 400,
      cacheReadTokens: 100,
      cacheWriteTokens: 0,
      costMicros: 12_500,
    },
  ],
  totals: {
    turns: 4,
    inputTokens: 2200,
    outputTokens: 450,
    cacheReadTokens: 100,
    cacheWriteTokens: 0,
    costMicros: 12_500,
  },
};

export const FEEDBACK_LIST: SuccessBody<'AssistantAdminController_feedback_v1'> = {
  data: [
    {
      id: '01930000-0000-7000-8000-0000000af001',
      conversationId: AUDIT_CONVERSATION_ID,
      messageId: AUDIT_MESSAGE_ID,
      user: USER_A,
      rating: 'down',
      reason: 'incomplete',
      comment: 'The quarantine count was missing.',
      createdAt: '2026-11-26T08:00:00.000Z',
      updatedAt: '2026-11-26T08:01:00.000Z',
      turn: {
        provider: 'fake',
        model: 'fake-model',
        promptVersion: 'assistant-system/7',
        dataSharing: 'pseudonymized',
      },
      tools: ['quarantine_entries_search'],
    },
  ],
  nextCursor: null,
};

const totals = {
  tokens: 2750,
  estimatedCostMicros: 12_500,
  toolCalls: 2,
  deniedCalls: 1,
  confirmations: { pending: 0, executing: 0, executed: 1, failed: 0, expired: 0, cancelled: 0 },
  reports: 1,
  feedback: { up: 0, down: 1 },
};

export const AUDIT_LIST: SuccessBody<'AssistantAdminAuditController_conversations_v1'> = {
  data: [
    {
      id: AUDIT_CONVERSATION_ID,
      user: USER_A,
      status: 'active',
      createdAt: '2026-11-26T07:59:00.000Z',
      lastTurnAt: '2026-11-26T08:00:00.000Z',
      turnCount: 2,
      segmentCount: 1,
      contentPurged: false,
      underPlatformOverride: false,
      totals,
    },
  ],
  nextCursor: null,
};

export const EXECUTION = {
  id: '01930000-0000-7000-8000-0000000ae001',
  seq: 1,
  turnSeq: 1,
  tool: 'quarantine_entries_search',
  module: 'quarantine',
  operationId: 'QuarantineEntriesController_search_v1',
  method: 'GET' as const,
  access: 'read' as const,
  risk: 'read' as const,
  decision: 'allowed' as const,
  status: 'succeeded' as const,
  httpStatus: 200,
  errorCode: null,
  paramsRedacted: { query: { status: 'held', limit: 25 } },
  resourceRef: null,
  latencyMs: 41,
  correlationId: 'req-e2e-0001.r1',
  createdAt: '2026-11-26T08:00:01.000Z',
};

/** Strings the api never returns to an administrator; the view must never show them either. */
export const CONTENT_SENTINELS = [
  'SECRET-TITLE-of-the-owner',
  'SECRET-QUESTION-text',
  'SECRET-ANSWER-text',
  'SECRET-CARD-title',
  'SECRET-REPORT-html',
] as const;

export const AUDIT_DETAIL: SuccessBody<'AssistantAdminAuditController_conversation_v1'> = {
  ...AUDIT_LIST.data[0]!,
  turns: [
    {
      seq: 1,
      status: 'completed',
      provider: 'fake',
      model: 'fake-model',
      responseModel: null,
      keySource: 'platform',
      dataSharing: 'pseudonymized',
      fallbackFrom: null,
      promptVersion: 'assistant-system/7',
      registryVersion: '0123456789abcdef',
      rounds: 2,
      toolCalls: 2,
      tokens: { input: 1500, output: 400, cacheRead: 100, cacheWrite: 0 },
      costMicros: 12_500,
      latencyMs: 2100,
      errorCode: null,
      startedAt: '2026-11-26T07:59:58.000Z',
      finishedAt: '2026-11-26T08:00:00.000Z',
    },
  ],
  executions: [
    EXECUTION,
    {
      ...EXECUTION,
      id: '01930000-0000-7000-8000-0000000ae002',
      seq: 2,
      tool: 'users_replace_roles',
      module: 'users',
      operationId: 'UsersController_replaceRoles_v1',
      method: 'PUT',
      access: 'write',
      risk: 'high',
      decision: 'denied_guard',
      status: 'refused',
      httpStatus: null,
      errorCode: 'assistant_guard_self_escalation',
      paramsRedacted: { path: { userId: USER_A.id }, body: { roleKeys: ['super_admin'] } },
    },
  ],
  confirmations: [
    {
      id: '01930000-0000-7000-8000-0000000acf01',
      operationId: 'PolicyManagementController_create_v1',
      risk: 'low',
      requiresReauth: false,
      status: 'executed',
      createdAt: '2026-11-26T08:00:02.000Z',
      expiresAt: '2026-11-26T08:15:02.000Z',
      decidedAt: '2026-11-26T08:00:10.000Z',
      resultHttpStatus: 201,
      errorCode: null,
    },
  ],
  reports: [
    {
      id: '01930000-0000-7000-8000-0000000ad001',
      status: 'available',
      period: {
        from: '2026-10-27T00:00:00.000Z',
        to: '2026-11-26T00:00:00.000Z',
        granularity: 'day',
      },
      sections: ['summary', 'traffic'],
      omitted: [{ section: 'quarantine', reason: 'permission', code: 'quarantine:read' }],
      sizeBytes: 182_344,
      errorCode: null,
      createdAt: '2026-11-26T08:00:20.000Z',
      async: true,
      jobStatus: 'succeeded',
      deliveries: [
        {
          recipientKind: 'self',
          recipientDomain: 'tenant.example.test',
          status: 'sent',
          errorCode: null,
          requestedAt: '2026-11-26T08:01:00.000Z',
          sentAt: '2026-11-26T08:01:05.000Z',
        },
      ],
    },
  ],
  feedback: [{ messageId: AUDIT_MESSAGE_ID, rating: 'down', reason: 'incomplete' }],
  truncated: false,
};

/** The detail with fields the contract does not have (a misbehaving api): never rendered. */
export const AUDIT_DETAIL_WITH_CONTENT = {
  ...AUDIT_DETAIL,
  title: CONTENT_SENTINELS[0],
  messages: [
    { role: 'user', content: CONTENT_SENTINELS[1] },
    { role: 'assistant', content: CONTENT_SENTINELS[2] },
  ],
  executions: AUDIT_DETAIL.executions.map((execution) => ({
    ...execution,
    card: { title: CONTENT_SENTINELS[3] },
  })),
  reports: AUDIT_DETAIL.reports.map((report) => ({
    ...report,
    title: CONTENT_SENTINELS[0],
    html: CONTENT_SENTINELS[4],
  })),
};

export const EXECUTIONS_LIST: SuccessBody<'AssistantAdminAuditController_executions_v1'> = {
  data: [{ ...EXECUTION, conversationId: AUDIT_CONVERSATION_ID, user: USER_A }],
  nextCursor: null,
};

export const TENANT_KEY = {
  provider: 'anthropic' as const,
  model: 'claude-sonnet-5-5',
  fingerprint: '0f1e2d3c4b5a6978',
  status: 'valid' as const,
  setAt: '2026-11-25T10:00:00.000Z',
  setBy: { id: USER_A.id, displayName: 'Ada Analyst' },
  lastValidatedAt: '2026-11-25T10:00:00.000Z',
  lastErrorCode: null,
};

export const SETTINGS_KEYS_OFFERED: AssistantSettings = {
  ...SETTINGS,
  enabled: true,
  externalProcessingAcknowledged: true,
  tenantKeysOffered: {
    enabled: true,
    providers: ['anthropic', 'openai'],
    models: ['claude-opus-5-5', 'claude-sonnet-5-5'],
  },
};

/** A synthetic key value that matches no secret-scanner pattern (design 34 §9). */
export const SYNTHETIC_KEY = 'test-tenant-key-0001-not-a-secret';
