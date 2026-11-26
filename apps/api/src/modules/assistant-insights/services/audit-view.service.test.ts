import { randomBytes } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  AuditConversationDetailSchema,
  AuditConversationsQuerySchema,
  AuditExecutionItemSchema,
  AuditExecutionsQuerySchema,
} from '../dto/insights.schemas';
import type {
  AuditConversationFilter,
  AuditConversationRow,
  AuditExecutionFilter,
  AuditExecutionRow,
  AuditRepository,
} from '../repositories/audit.repository';
import type { IdentityRepository, IdentityRow } from '../repositories/identity.repository';
import { AssistantAuditViewService, toolNamesOfModule } from './audit-view.service';

const ORG = 7001n;
const auditor: UserPrincipal = {
  kind: 'user',
  userId: 500n,
  userPublicId: '0193b000-0000-7000-8000-000000000500',
  organizationId: ORG,
  organizationPublicId: '0193b000-0000-7000-8000-000000007001',
  organizationKind: 'customer',
  sessionId: '0193b000-0000-7000-8000-0000000000aa',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['audit:read']),
};
const scope = scopeFromPrincipal(auditor);
const NOW = new Date('2026-11-26T12:00:00.000Z');
const CONV = '0193b000-0000-7000-8000-00000000c010';

/** What a careless repository could return on top of the allow-list (I24). */
const LEAKS = {
  title: 'LEAK-title',
  content: 'LEAK-content',
  providerTranscript: 'LEAK-transcript',
  resultCard: { text: 'LEAK-card' },
  resultRefs: { r: 'LEAK-refs' },
  nextCursor: 'LEAK-cursor',
  objectKey: 'LEAK-object-key',
  recipientAddress: 'LEAK-address@example.com',
  comment: 'LEAK-comment',
  summary: { text: 'LEAK-summary' },
  request: { body: 'LEAK-request' },
};

const conversation = (id: number, lastTurnMinutes: number): AuditConversationRow =>
  ({
    id: BigInt(id),
    publicId: id === 10 ? CONV : `c-${id}`,
    organizationId: ORG,
    userId: 501n,
    platformOverrideId: id === 12 ? 'ovr-1' : null,
    status: 'active',
    turnCount: 1,
    segment: 1,
    lastTurnAt: new Date(NOW.getTime() - lastTurnMinutes * 60_000),
    contentPurgedAt: null,
    createdAt: NOW,
    ...LEAKS,
  }) as unknown as AuditConversationRow;

const execution = (id: number): AuditExecutionRow =>
  ({
    id: BigInt(id),
    publicId: `e-${id}`,
    organizationId: ORG,
    userId: 501n,
    conversationId: 10n,
    turnId: 1n,
    seq: id,
    toolName: 'policy_management_list',
    operationId: 'PoliciesController_list_v1',
    httpMethod: 'GET',
    access: 'read',
    risk: 'read',
    decision: 'allowed',
    status: 'succeeded',
    httpStatus: 200,
    errorCode: null,
    correlationId: `corr-${id}-0000`,
    paramsRedacted: { query: { limit: 25 } },
    resourceRef: null,
    latencyMs: 5,
    createdAt: new Date(NOW.getTime() - id * 60_000),
    turnSeq: 1,
    conversationPublicId: CONV,
    ...LEAKS,
  }) as unknown as AuditExecutionRow;

function harness() {
  const conversations = [conversation(10, 1), conversation(11, 2), conversation(12, 3)];
  const executions = [execution(1), execution(2), execution(3)];
  const conversationCalls: AuditConversationFilter[] = [];
  const executionCalls: AuditExecutionFilter[] = [];
  const scopes: TenantScope[] = [];
  const empty = {
    tokens: new Map(),
    executions: new Map(),
    confirmations: new Map(),
    reports: new Map(),
    feedback: new Map(),
  };
  const repo = {
    conversationPage: vi.fn((s: TenantScope, f: AuditConversationFilter) => {
      scopes.push(s);
      conversationCalls.push(f);
      return Promise.resolve(
        conversations
          .filter((c) => !f.after || c.lastTurnAt! < f.after.lastTurnAt)
          .slice(0, f.take),
      );
    }),
    findConversation: vi.fn((s: TenantScope, publicId: string) => {
      scopes.push(s);
      return Promise.resolve(conversations.find((c) => c.publicId === publicId) ?? null);
    }),
    aggregates: vi.fn(() => Promise.resolve(empty)),
    turns: vi.fn(() =>
      Promise.resolve([
        {
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
          registryVersion: 'r',
          rounds: 1,
          toolCalls: 1,
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          costMicros: null,
          latencyMs: 3,
          errorCode: null,
          startedAt: NOW,
          finishedAt: NOW,
          ...LEAKS,
        },
      ]),
    ),
    executionsOf: vi.fn(() => Promise.resolve(executions)),
    confirmations: vi.fn(() => Promise.resolve([])),
    reports: vi.fn(() =>
      Promise.resolve([
        {
          id: 4n,
          publicId: 'r-4',
          organizationId: ORG,
          status: 'available',
          periodFrom: NOW,
          periodTo: NOW,
          granularity: 'day',
          sections: { included: ['traffic'], omitted: [], label: 'LEAK-label' },
          sizeBytes: 10,
          errorCode: null,
          createdAt: NOW,
          job: null,
          ...LEAKS,
        },
      ]),
    ),
    deliveries: vi.fn(() =>
      Promise.resolve([
        {
          organizationId: ORG,
          reportId: 4n,
          recipientKind: 'domain',
          recipientDomain: 'example.org',
          status: 'queued',
          errorCode: null,
          requestedAt: NOW,
          sentAt: null,
          ...LEAKS,
        },
      ]),
    ),
    feedbackOf: vi.fn(() =>
      Promise.resolve([
        { organizationId: ORG, messagePublicId: 'm-2', rating: 'down', reason: null, ...LEAKS },
      ]),
    ),
    conversationIdOf: vi.fn((_s: TenantScope, publicId: string) =>
      Promise.resolve(publicId === CONV ? 10n : null),
    ),
    executionPage: vi.fn((s: TenantScope, f: AuditExecutionFilter) => {
      scopes.push(s);
      executionCalls.push(f);
      return Promise.resolve(
        executions.filter((e) => !f.after || e.createdAt < f.after.createdAt).slice(0, f.take),
      );
    }),
  };
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
  ]);
  const identities = {
    byIds: vi.fn(() => Promise.resolve(users)),
    idOfFilter: vi.fn(() => Promise.resolve(null)),
  };
  const audit = {
    record: vi.fn((_entry: unknown, _tx?: unknown) => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: auditor.userPublicId })),
  };
  const service = new AssistantAuditViewService(
    repo as unknown as AuditRepository,
    identities as unknown as IdentityRepository,
    new CursorCodec({
      API_CURSOR_KEY: randomBytes(32).toString('hex'),
      API_CURSOR_KEY_PREVIOUS: undefined,
      API_CURSOR_TTL_SECONDS: 86_400,
    }),
    audit as unknown as AuditService,
  );
  service.now = () => NOW;
  return { service, repo, audit, conversationCalls, executionCalls, scopes };
}

const cq = (raw: Record<string, string>) => AuditConversationsQuerySchema.parse(raw);
const eq = (raw: Record<string, string>) => AuditExecutionsQuerySchema.parse(raw);
const leaks = (value: unknown) =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

describe('AssistantAuditViewService (D4, I24)', () => {
  it('lists headers without content, flags overrides, cursor round trip', async () => {
    const h = harness();
    const first = await h.service.conversations(auditor, scope, cq({ limit: '2' }));
    expect(first.data.map((c) => c.id)).toEqual([CONV, 'c-11']);
    expect(h.conversationCalls[0]).toMatchObject({ window: null, take: 3 });
    const second = await h.service.conversations(
      auditor,
      scope,
      cq({ limit: '2', cursor: first.nextCursor! }),
    );
    expect(second.data).toEqual([
      expect.objectContaining({ id: 'c-12', underPlatformOverride: true }),
    ]);
    expect(second.nextCursor).toBeNull();
    expect(leaks([first, second])).not.toMatch(/LEAK/);
    expect(h.scopes.every((s) => s.organizationId === ORG)).toBe(true);
    await expect(
      h.service.conversations(auditor, scope, cq({ status: 'deleted', cursor: first.nextCursor! })),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('answers an empty page for a user filter that does not resolve', async () => {
    const h = harness();
    const page = await h.service.conversations(
      auditor,
      scope,
      cq({ userId: '0193b000-0000-7000-8000-000000009999' }),
    );
    expect(page).toEqual({ data: [], nextCursor: null });
    expect(h.repo.conversationPage).not.toHaveBeenCalled();
  });

  it('returns the detail from allow-listed fields only and audits the view', async () => {
    const h = harness();
    const detail = await h.service.conversation(auditor, scope, CONV, '198.51.100.7');
    expect(AuditConversationDetailSchema.strict().safeParse(detail).success).toBe(true);
    expect(leaks(detail)).not.toMatch(/LEAK/);
    expect(detail).toMatchObject({
      id: CONV,
      truncated: false,
      reports: [
        { id: 'r-4', deliveries: [{ recipientKind: 'domain', recipientDomain: 'example.org' }] },
      ],
      feedback: [{ messageId: 'm-2', rating: 'down', reason: null }],
    });
    expect('title' in detail).toBe(false);
    expect(h.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: ORG,
        action: 'assistant.audit_viewed',
        resourceType: 'assistant_conversation',
        resourceId: CONV,
        sourceIp: '198.51.100.7',
      }),
    );
  });

  it('answers 404 for a conversation outside the organization (no audit row)', async () => {
    const h = harness();
    await expect(
      h.service.conversation(auditor, scope, '0193b000-0000-7000-8000-00000000ffff', null),
    ).rejects.toMatchObject({ code: 'assistant_admin_conversation_not_found' });
    expect(h.audit.record).not.toHaveBeenCalled();
  });

  it('searches executions in a ≤ 92-day window with resolved filters and a cursor', async () => {
    const h = harness();
    const first = await h.service.executions(
      auditor,
      scope,
      eq({
        limit: '2',
        module: 'policies',
        decision: 'allowed,denied_guard',
        conversationId: CONV,
      }),
    );
    expect(first.data.map((e) => e.id)).toEqual(['e-1', 'e-2']);
    for (const item of first.data) {
      expect(AuditExecutionItemSchema.strict().safeParse(item).success).toBe(true);
    }
    expect(leaks(first)).not.toMatch(/LEAK/);
    expect(h.executionCalls[0]).toMatchObject({
      conversationId: 10n,
      decisions: ['allowed', 'denied_guard'],
      to: NOW,
    });
    expect(h.executionCalls[0]!.toolNames).toContain('policy_management_list');
    const second = await h.service.executions(
      auditor,
      scope,
      eq({
        limit: '2',
        module: 'policies',
        decision: 'allowed,denied_guard',
        conversationId: CONV,
        cursor: first.nextCursor!,
      }),
    );
    expect(second.data.map((e) => e.id)).toEqual(['e-3']);
    await expect(
      h.service.executions(auditor, scope, eq({ from: '2026-01-01T00:00:00Z' })),
    ).rejects.toMatchObject({ status: 400 });
  });

  it('answers empty pages for an unknown module, conversation or tool outside the module', async () => {
    const h = harness();
    expect(await h.service.executions(auditor, scope, eq({ module: 'no-such-module' }))).toEqual({
      data: [],
      nextCursor: null,
    });
    expect(
      await h.service.executions(
        auditor,
        scope,
        eq({ conversationId: '0193b000-0000-7000-8000-00000000ffff' }),
      ),
    ).toEqual({ data: [], nextCursor: null });
    expect(
      await h.service.executions(
        auditor,
        scope,
        eq({ module: 'policies', tool: 'notifications_settings' }),
      ),
    ).toEqual({ data: [], nextCursor: null });
    expect(h.repo.executionPage).not.toHaveBeenCalled();
    expect(toolNamesOfModule('policies').length).toBeGreaterThan(0);
  });
});
