import { OPERATION_TOOLS } from '@email-gateway/assistant';
import { describe, expect, it } from 'vitest';
import { policyPage, testUser } from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { ConversationListQuerySchema, MessageListQuerySchema } from '../dto/assistant.schemas';
import { ownerOf } from './conversation.service';

const ORG = 7001n;
const listQuery = (raw: Record<string, string> = {}) => ConversationListQuerySchema.parse(raw);

describe('ConversationService (§4.1, D12, Q9, Q11)', () => {
  it('creates conversations up to the per-user limit (409 with limit)', async () => {
    const h = createAssistantHarness({ ASSISTANT_MAX_CONVERSATIONS_PER_USER: '2' });
    h.world.enable(ORG);
    const a = await h.conversations.create(h.user, h.scope, { title: 'First' });
    expect(a).toMatchObject({
      title: 'First',
      status: 'active',
      turnCount: 0,
      contentPurged: false,
    });
    await h.conversations.create(h.user, h.scope, {});
    await expect(h.conversations.create(h.user, h.scope, {})).rejects.toMatchObject({
      code: 'assistant_conversation_limit',
      details: { limit: 2 },
    });
    // A new conversation needs the assistant available (tenant gate).
    h.world.settings.get(ORG)!.enabled = false;
    await h.conversations.remove(h.user, h.scope, a.id, null);
    await expect(h.conversations.create(h.user, h.scope, {})).rejects.toMatchObject({
      code: 'assistant_tenant_disabled',
    });
  });

  it('lists own conversations newest first with a v1 cursor bound to the filters', async () => {
    const h = createAssistantHarness();
    const owner = ownerOf(h.user, h.scope);
    const base = Date.parse('2026-11-20T10:00:00.000Z');
    for (let i = 0; i < 5; i += 1) {
      h.world.addConversation(owner, {
        title: i % 2 ? `Policy review ${i}` : `Quarantine ${i}`,
        lastTurnAt: new Date(base + i * 1000),
      });
    }
    h.world.addConversation({ ...owner, userId: 999n }, { title: 'Policy of someone else' });
    const page1 = await h.conversations.list(h.user, h.scope, listQuery({ limit: '2' }));
    expect(page1.data.map((c) => c.title)).toEqual(['Quarantine 4', 'Policy review 3']);
    const page2 = await h.conversations.list(
      h.user,
      h.scope,
      listQuery({ limit: '2', cursor: page1.nextCursor! }),
    );
    expect(page2.data.map((c) => c.title)).toEqual(['Quarantine 2', 'Policy review 1']);
    const search = await h.conversations.list(h.user, h.scope, listQuery({ q: 'policy' }));
    expect(search.data.map((c) => c.title)).toEqual(['Policy review 3', 'Policy review 1']);
    await expect(
      h.conversations.list(h.user, h.scope, listQuery({ q: 'policy', cursor: page1.nextCursor! })),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('deletes: invisible at once, content purged immediately, audited', async () => {
    const h = createAssistantHarness();
    h.world.enable(ORG);
    h.loopback.on('GET /api/v1/policies', () => policyPage(1));
    const c = await h.conversations.create(h.user, h.scope, { title: 'Secret plans' });
    await h.ask(c.id, '/tool policy_management_list {}');
    await h.conversations.remove(h.user, h.scope, c.id, '198.51.100.7');
    await expect(h.conversations.get(h.user, h.scope, c.id)).rejects.toMatchObject({
      code: 'assistant_conversation_not_found',
    });
    expect(h.world.conversations[0]).toMatchObject({ status: 'deleted', title: null });
    expect(h.world.messages.every((m) => m.content === null)).toBe(true);
    expect(h.world.executions[0]!.resultCard).toBeNull();
    expect(h.audit.entries.at(-1)).toMatchObject({
      action: 'assistant.conversation_deleted',
      resourceType: 'assistant_conversation',
      resourceId: c.id,
    });
  });

  it('keeps conversations private: another user (also an admin) and another organization get 404', async () => {
    const h = createAssistantHarness();
    h.world.enable(ORG);
    const c = await h.conversations.create(h.user, h.scope, {});
    const admin = testUser({ userId: 900n, userPublicId: '0193b000-0000-7000-8000-000000000900' });
    await expect(h.conversations.get(admin, scopeFromPrincipal(admin), c.id)).rejects.toMatchObject(
      {
        code: 'assistant_conversation_not_found',
      },
    );
    const foreign = testUser({ organizationId: 7002n });
    await expect(
      h.conversations.get(foreign, scopeFromPrincipal(foreign), c.id),
    ).rejects.toMatchObject({
      code: 'assistant_conversation_not_found',
    });
  });

  it('stores an override conversation in the target organization with the override id (Q11)', async () => {
    const operator = testUser({
      organizationId: 1n,
      organizationKind: 'platform',
      override: {
        id: '0193e000-0000-7000-8000-000000000001',
        reason: 'IT support case',
        targetOrganizationId: 7001n,
        targetOrganizationPublicId: '0193b000-0000-7000-8000-000000007001',
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    const h = createAssistantHarness({}, undefined, operator);
    h.world.enable(ORG);
    const c = await h.conversations.create(operator, h.scope, {});
    expect(c.underPlatformOverride).toBe(true);
    expect(h.world.conversations[0]).toMatchObject({
      organizationId: 7001n,
      platformOverrideId: '0193e000-0000-7000-8000-000000000001',
    });
  });

  it('pages messages oldest first with the turn’s executions on its answer', async () => {
    const h = createAssistantHarness();
    h.world.enable(ORG);
    h.loopback.on('GET /api/v1/policies', () => policyPage(1));
    const c = await h.conversations.create(h.user, h.scope, {});
    await h.ask(c.id, '/tool policy_management_list {}');
    await h.ask(c.id, '/text hello');
    const page = await h.conversations.messages(
      h.user,
      h.scope,
      c.id,
      MessageListQuerySchema.parse({ limit: '3' }),
    );
    expect(page.data.map((m) => [m.seq, m.role, m.executions.length])).toEqual([
      [1, 'user', 0],
      [2, 'assistant', 1],
      [3, 'user', 0],
    ]);
    expect(page.data[1]!.executions[0]).toMatchObject({
      tool: 'policy_management_list',
      ref: 'r1',
    });
    const next = await h.conversations.messages(
      h.user,
      h.scope,
      c.id,
      MessageListQuerySchema.parse({ limit: '3', cursor: page.nextCursor! }),
    );
    expect(next.data.map((m) => m.seq)).toEqual([4]);
    expect(next.nextCursor).toBeNull();
  });

  it('lists the caller’s enabled tools after the permission pre-filter', () => {
    const h = createAssistantHarness();
    const tools = h.conversations.tools(h.user).tools.map((t) => t.name);
    expect(tools).toContain('policy_management_list');
    expect(tools).not.toContain('users_list');
    const readable = OPERATION_TOOLS.filter(
      (t) =>
        t.enabled &&
        t.requirement.mode !== 'authenticated' &&
        t.requirement.permissions.includes('policy:read'),
    );
    expect(tools.length).toBeGreaterThanOrEqual(1);
    expect(readable.every((t) => t.access === 'read')).toBe(true);
  });
});
