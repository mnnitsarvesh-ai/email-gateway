import { describe, expect, it } from 'vitest';
import {
  AuditConfirmationSchema,
  AuditConversationHeaderSchema,
  AuditExecutionSchema,
  AuditReportSchema,
  AuditTurnSchema,
} from '../dto/insights.schemas';
import type {
  AuditConfirmationRow,
  AuditConversationRow,
  AuditDeliveryRow,
  AuditExecutionRow,
  AuditFeedbackRow,
  AuditReportRow,
  AuditTurnRow,
  ConversationAggregates,
} from '../repositories/audit.repository';
import type { IdentityRow } from '../repositories/identity.repository';
import {
  auditConfirmationView,
  auditExecutionView,
  auditFeedbackView,
  auditReportView,
  auditTurnView,
  conversationHeader,
  identityOf,
  reportSectionsOf,
  usageFigures,
} from './views';

const ORG = 7001n;
const at = new Date('2026-11-20T09:00:00.000Z');

/** Content and secrets a repository row might carry by mistake (I24: never in an admin view). */
const FORBIDDEN = {
  title: 'SECRET-TITLE Quarterly layoffs',
  content: 'SECRET-CONTENT the merger is on',
  providerTranscript: 'SECRET-TRANSCRIPT',
  resultCard: { title: 'SECRET-CARD' },
  resultRefs: { r1: 'SECRET-REFS' },
  nextCursor: 'SECRET-CURSOR',
  objectKey: 'org/7001/assistant/report/SECRET-OBJECT.html',
  html: '<p>SECRET-HTML</p>',
  figures: [{ label: 'SECRET-FIGURE', value: '1' }],
  recipientAddress: 'SECRET-ADDRESS@example.com',
  comment: 'SECRET-COMMENT',
  request: { body: 'SECRET-REQUEST' },
  summary: { text: 'SECRET-SUMMARY' },
  preconditions: { v: 'SECRET-PRECONDITION' },
  tokenHash: 'SECRET-TOKEN-HASH',
  sha256: 'SECRET-SHA',
};
const FORBIDDEN_KEYS = Object.keys(FORBIDDEN);

/** Every key at any depth of a JSON value. */
function keysOf(value: unknown, out = new Set<string>()): Set<string> {
  if (Array.isArray(value)) value.forEach((v) => keysOf(v, out));
  else if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      out.add(k);
      keysOf(v, out);
    }
  }
  return out;
}

function expectNoContent(view: unknown): void {
  const json = JSON.stringify(view, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));
  expect(json).not.toMatch(/SECRET/);
  const keys = keysOf(JSON.parse(json));
  for (const key of FORBIDDEN_KEYS) expect(keys.has(key), key).toBe(false);
}

const users = new Map<bigint, IdentityRow>([
  [
    501n,
    {
      id: 501n,
      publicId: 'u-501',
      organizationId: ORG,
      displayName: 'Dana',
      email: 'dana@example.com',
    },
  ],
  [
    9n,
    { id: 9n, publicId: 'u-ops', organizationId: 1n, displayName: 'Op', email: 'op@example.com' },
  ],
]);

const conversation = {
  id: 10n,
  publicId: 'c-10',
  organizationId: ORG,
  userId: 501n,
  platformOverrideId: null,
  status: 'active',
  turnCount: 2,
  segment: 1,
  lastTurnAt: at,
  contentPurgedAt: null,
  createdAt: at,
  ...FORBIDDEN,
} as unknown as AuditConversationRow;

const aggregates: ConversationAggregates = {
  tokens: new Map([[10n, { tokens: 1200, costMicros: 50, pricedTurns: 1 }]]),
  executions: new Map([[10n, { total: 3, denied: 1 }]]),
  confirmations: new Map([
    [
      10n,
      new Map([
        ['executed', 1],
        ['pending', 2],
      ]),
    ],
  ]),
  reports: new Map([[10n, 1]]),
  feedback: new Map([[10n, { up: 1, down: 0 }]]),
};

const turn = {
  id: 1n,
  organizationId: ORG,
  conversationId: 10n,
  seq: 1,
  status: 'completed',
  provider: 'fake',
  model: 'fake-1',
  responseModel: null,
  keySource: 'platform',
  dataSharing: 'metadata',
  fallbackFrom: null,
  promptVersion: 'assistant-system/7',
  registryVersion: 'r1',
  rounds: 1,
  toolCalls: 1,
  inputTokens: 10,
  outputTokens: 5,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  costMicros: 12n,
  latencyMs: 30,
  errorCode: null,
  startedAt: at,
  finishedAt: at,
  ...FORBIDDEN,
} as unknown as AuditTurnRow;

const execution = {
  id: 2n,
  publicId: 'e-2',
  organizationId: ORG,
  userId: 501n,
  conversationId: 10n,
  turnId: 1n,
  seq: 1,
  toolName: 'policy_management_list',
  operationId: 'PoliciesController_list_v1',
  httpMethod: 'GET',
  access: 'read',
  risk: 'read',
  decision: 'allowed',
  status: 'succeeded',
  httpStatus: 200,
  errorCode: null,
  correlationId: 'corr-0001',
  paramsRedacted: { query: { limit: 25 } },
  resourceRef: null,
  latencyMs: 12,
  createdAt: at,
  turnSeq: 1,
  conversationPublicId: 'c-10',
  ...FORBIDDEN,
} as unknown as AuditExecutionRow;

const confirmation = {
  id: 3n,
  publicId: 'k-3',
  organizationId: ORG,
  operationId: 'PoliciesController_update_v1',
  risk: 'medium',
  requiresReauth: false,
  status: 'executed',
  createdAt: at,
  expiresAt: at,
  decidedAt: at,
  resultHttpStatus: 200,
  errorCode: null,
  ...FORBIDDEN,
} as unknown as AuditConfirmationRow;

const report = {
  id: 4n,
  publicId: 'r-4',
  organizationId: ORG,
  status: 'available',
  periodFrom: at,
  periodTo: at,
  granularity: 'day',
  sections: {
    included: ['traffic', 'threats'],
    omitted: [{ section: 'ato', reason: 'permission', code: 'forbidden' }],
    label: 'SECRET-LABEL Acme Corp',
  },
  sizeBytes: 100,
  errorCode: null,
  createdAt: at,
  job: { status: 'succeeded' },
  ...FORBIDDEN,
} as unknown as AuditReportRow;

const delivery = {
  organizationId: ORG,
  reportId: 4n,
  recipientKind: 'member',
  recipientDomain: 'example.com',
  status: 'sent',
  errorCode: null,
  requestedAt: at,
  sentAt: at,
  ...FORBIDDEN,
} as unknown as AuditDeliveryRow;

const feedback = {
  organizationId: ORG,
  messagePublicId: 'm-1',
  rating: 'up',
  reason: 'other',
  ...FORBIDDEN,
} as unknown as AuditFeedbackRow;

describe('audit views are built from an allow-list (I24)', () => {
  it('never copies a forbidden field even when the repository row carries it', () => {
    const views = [
      conversationHeader(conversation, aggregates, users),
      auditTurnView(turn),
      auditExecutionView(execution),
      auditConfirmationView(confirmation),
      auditReportView(report, [delivery]),
      auditFeedbackView(feedback),
    ];
    for (const view of views) expectNoContent(view);
  });

  it('produces documents that match the response schemas exactly', () => {
    expect(
      AuditConversationHeaderSchema.strict().safeParse(
        conversationHeader(conversation, aggregates, users),
      ).success,
    ).toBe(true);
    expect(AuditTurnSchema.strict().safeParse(auditTurnView(turn)).success).toBe(true);
    expect(AuditExecutionSchema.strict().safeParse(auditExecutionView(execution)).success).toBe(
      true,
    );
    expect(
      AuditConfirmationSchema.strict().safeParse(auditConfirmationView(confirmation)).success,
    ).toBe(true);
    expect(AuditReportSchema.strict().safeParse(auditReportView(report, [delivery])).success).toBe(
      true,
    );
  });

  it('summarizes the header (no title; totals; override flag)', () => {
    const header = conversationHeader(
      { ...conversation, platformOverrideId: 'ovr-1', userId: 9n },
      aggregates,
      users,
    );
    expect(header).toMatchObject({
      id: 'c-10',
      underPlatformOverride: true,
      user: { id: 'u-ops', displayName: null, email: null },
      totals: {
        tokens: 1200,
        estimatedCostMicros: 50,
        toolCalls: 3,
        deniedCalls: 1,
        confirmations: { pending: 2, executed: 1, failed: 0 },
        reports: 1,
        feedback: { up: 1, down: 0 },
      },
    });
    expect('title' in header).toBe(false);
    const empty = conversationHeader(conversation, { ...aggregates, tokens: new Map() }, users);
    expect(empty.totals.estimatedCostMicros).toBeNull();
  });

  it('keeps only a bare recipient domain and the execution module from the registry', () => {
    const view = auditReportView(report, [
      delivery,
      { ...delivery, recipientDomain: 'evil.example.com\nx' },
      { ...delivery, recipientDomain: null },
    ]);
    expect(view.deliveries.map((d) => d.recipientDomain)).toEqual(['example.com', null, null]);
    expect(view).toMatchObject({
      async: true,
      jobStatus: 'succeeded',
      sections: ['traffic', 'threats'],
    });
    expect(auditExecutionView(execution).module).toBe('policies');
    expect(auditExecutionView({ ...execution, toolName: 'no_such_tool' }).module).toBeNull();
  });
});

describe('identityOf and usageFigures', () => {
  it('shows name and address only for members of the organization', () => {
    expect(identityOf(501n, users, ORG)).toEqual({
      id: 'u-501',
      displayName: 'Dana',
      email: 'dana@example.com',
    });
    expect(identityOf(9n, users, ORG)).toEqual({ id: 'u-ops', displayName: null, email: null });
    expect(identityOf(77n, users, ORG)).toEqual({ id: 'unknown', displayName: null, email: null });
  });

  it('labels the cost unknown when no summed row had a price', () => {
    const sums = {
      turns: 2,
      inputTokens: 10,
      outputTokens: 5,
      cacheReadTokens: 3,
      cacheWriteTokens: 2,
      costMicros: 0,
      pricedRows: 0,
    };
    expect(usageFigures(sums)).toMatchObject({ totalTokens: 20, estimatedCostMicros: null });
    expect(usageFigures({ ...sums, costMicros: 40, pricedRows: 1 }).estimatedCostMicros).toBe(40);
  });

  it('drops malformed section entries of a stored report', () => {
    expect(
      reportSectionsOf({ included: ['traffic', 7, 'DROP TABLE'], omitted: [{ section: 'x' }] }),
    ).toEqual({ sections: ['traffic'], omitted: [] });
    expect(reportSectionsOf(null)).toEqual({ sections: [], omitted: [] });
  });
});
