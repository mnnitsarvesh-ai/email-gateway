import {
  GUARD_MESSAGES,
  NOT_APPLICABLE_OPERATIONS,
  OPERATION_TOOLS,
  toolNameOf,
} from '@email-gateway/assistant';
import { describe, expect, it } from 'vitest';
import { policyPage, testUser } from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { ownerOf } from './conversation.service';
import {
  type ExecutionContext,
  executionCorrelationId,
  redactParams,
  resourceRefOf,
} from './tool-executor.service';

const POLICY_ID = '0193c000-0000-7000-8000-000000000001';

function setup(principal: UserPrincipal = testUser(), env: Record<string, string> = {}) {
  const h = createAssistantHarness(env, undefined, principal);
  const owner = ownerOf(principal, scopeFromPrincipal(principal));
  const conversation = h.world.addConversation(owner);
  let seq = 1;
  const ctx = (overrides: Partial<ExecutionContext> = {}): ExecutionContext => ({
    principal,
    owner,
    conversationId: conversation.id,
    conversationPublicId: conversation.publicId,
    turnId: null,
    turnPublicId: null,
    parentExecutionId: null,
    parentExecutionPublicId: null,
    authorization: 'Bearer it-access-token',
    clientIp: '198.51.100.7',
    correlationBase: 'it-corr-0001',
    signal: new AbortController().signal,
    allocateSeq: () => seq++,
    ...overrides,
  });
  h.loopback.on('GET /api/v1/policies', () => policyPage(2));
  return { h, owner, conversation, ctx };
}

describe('ToolExecutorService decisions (D5, in order; each recorded and audited)', () => {
  it('denied_budget beyond the per-turn cap, before anything else', async () => {
    const { h, ctx } = setup(testUser(), { ASSISTANT_MAX_TOOL_CALLS_PER_TURN: '1' });
    const out = await h.executor.execute(ctx(), { name: 'no_such_tool', arguments: {} }, 1);
    expect(out.decision).toBe('denied_budget');
    expect(h.loopback.toolCalls).toHaveLength(0);
    expect(h.audit.entries[0]).toMatchObject({
      action: 'assistant.tool_denied',
      resourceType: 'assistant_tool_execution',
      resourceId: out.executionId,
    });
  });

  it('denied_unknown_tool, denied_not_applicable (with the portal page) and denied_disabled', async () => {
    const { h, ctx } = setup();
    expect(
      (await h.executor.execute(ctx(), { name: 'no_such_tool', arguments: {} }, 0)).decision,
    ).toBe('denied_unknown_tool');
    const na = NOT_APPLICABLE_OPERATIONS.find((op) => op.portalRoute !== null)!;
    const denied = await h.executor.execute(
      ctx(),
      { name: toolNameOf(na.operationId), arguments: {} },
      0,
    );
    expect(denied.decision).toBe('denied_not_applicable');
    expect(denied.envelope).toMatchObject({ status: 'denied', portalRoute: na.portalRoute });
    const write = OPERATION_TOOLS.find((t) => t.access === 'write' && !t.enabled)!;
    expect((await h.executor.execute(ctx(), { name: write.name, arguments: {} }, 0)).decision).toBe(
      'denied_disabled',
    );
    expect(h.loopback.toolCalls).toHaveLength(0);
    expect(h.world.executions.map((e) => e.status)).toEqual(['refused', 'refused', 'refused']);
  });

  it('denied_permission from the shared predicate; platform-only tools for platform users only', async () => {
    const { h, ctx } = setup(testUser({ permissions: new Set(['assistant:use']) }));
    expect(
      (await h.executor.execute(ctx(), { name: 'policy_management_list', arguments: {} }, 0))
        .decision,
    ).toBe('denied_permission');
    const platformTool = OPERATION_TOOLS.find((t) => t.platformOnly && t.enabled)!;
    const allPlatform = testUser({
      permissions: new Set(
        platformTool.requirement.mode === 'authenticated'
          ? []
          : platformTool.requirement.permissions,
      ),
    });
    const customer = setup(allPlatform);
    expect(
      (
        await customer.h.executor.execute(
          customer.ctx(),
          { name: platformTool.name, arguments: {} },
          0,
        )
      ).decision,
    ).toBe('denied_permission');
    expect(h.loopback.toolCalls).toHaveLength(0);
  });

  it('denied_schema with Ajv paths and no values; non-object arguments too', async () => {
    const { h, ctx } = setup();
    const out = await h.executor.execute(
      ctx(),
      { name: 'policy_management_list', arguments: { status: 'secret-value-x', apiToken: 'zzz' } },
      0,
    );
    expect(out.decision).toBe('denied_schema');
    expect(out.denialMessage).toContain('/status');
    expect(out.denialMessage).not.toContain('secret-value-x');
    // The audit params are scrubbed (credential-shaped keys dropped).
    const params = (h.audit.entries[0]!.metadata as { params: Record<string, unknown> }).params;
    expect(params).toEqual({ status: 'secret-value-x' });
    expect(
      (await h.executor.execute(ctx(), { name: 'policy_management_list', arguments: null }, 0))
        .decision,
    ).toBe('denied_schema');
  });

  it('denied_schema for dot-segment or empty path values (the route must stay the tool route)', async () => {
    const user = testUser({ permissions: new Set(['assistant:use', 'role:read']) });
    const { h, ctx } = setup(user);
    let seq = 0;
    for (const key of ['..', '.', '']) {
      const out = await h.executor.execute(ctx(), { name: 'roles_get', arguments: { key } }, seq++);
      expect(out.decision, JSON.stringify(key)).toBe('denied_schema');
      expect(out.denialMessage).toContain('Invalid path parameter: key');
    }
    expect(h.loopback.toolCalls).toHaveLength(0);
    // A dot inside a value is a normal (encoded) segment.
    h.loopback.on('GET /api/v1/roles/a..b', () => ({
      kind: 'response',
      status: 200,
      body: { key: 'a..b', name: 'Role', system: false },
    }));
    const ok = await h.executor.execute(
      ctx(),
      { name: 'roles_get', arguments: { key: 'a..b' } },
      seq++,
    );
    expect(ok.decision).toBe('allowed');
    expect(h.loopback.toolCalls.at(-1)!.path).toBe('/api/v1/roles/a..b');
  });

  it('resolves refs of THIS conversation only; others are denied_ref', async () => {
    const { h, ctx, owner } = setup();
    h.loopback.on(`GET /api/v1/policies/${POLICY_ID}`, () => ({
      kind: 'response',
      status: 200,
      body: { id: POLICY_ID, name: 'IT policy 1', status: 'active' },
    }));
    const list = await h.executor.execute(
      ctx(),
      { name: 'policy_management_list', arguments: {} },
      0,
    );
    expect(list.envelope).toMatchObject({ status: 'ok', ref: 'r1', returned: 2 });
    const get = await h.executor.execute(
      ctx(),
      { name: 'policy_management_get', arguments: { policyId: '@r1.1' } },
      1,
    );
    expect(get.decision).toBe('allowed');
    expect(h.loopback.toolCalls.at(-1)!.path).toBe(`/api/v1/policies/${POLICY_ID}`);
    // The same ref from another conversation of the same user does not resolve.
    const other = h.world.addConversation(owner);
    const foreign = await h.executor.execute(
      ctx({ conversationId: other.id, conversationPublicId: other.publicId }),
      { name: 'policy_management_get', arguments: { policyId: '@r1.1' } },
      0,
    );
    expect(foreign.decision).toBe('denied_ref');
    expect(
      (
        await h.executor.execute(
          ctx(),
          { name: 'policy_management_get', arguments: { policyId: '@r1.9' } },
          2,
        )
      ).decision,
    ).toBe('denied_ref');
  });

  it('denied_schema for a bound path parameter a platform user omitted (no request built)', async () => {
    const tool = OPERATION_TOOLS.find(
      (t) => t.enabled && t.platformOnly && Object.keys(t.bind).length > 0,
    )!;
    expect(tool).toBeDefined();
    const operator = testUser({
      organizationKind: 'platform',
      permissions: new Set(
        tool.requirement.mode === 'authenticated' ? [] : tool.requirement.permissions,
      ),
    });
    const { h, ctx } = setup(operator);
    const out = await h.executor.execute(ctx(), { name: tool.name, arguments: {} }, 0);
    expect(out.decision).toBe('denied_schema');
    expect(out.denialMessage).toContain('Missing path parameter');
    expect(h.loopback.toolCalls).toHaveLength(0);
    expect(h.audit.entries[0]).toMatchObject({ action: 'assistant.tool_denied' });
  });

  it('binds self_organization for customer users when the model omitted it', async () => {
    const user = testUser({ permissions: new Set(['assistant:use', 'organization:read']) });
    const { h, ctx } = setup(user);
    h.loopback.on(`GET /api/v1/organizations/${user.organizationPublicId}`, () => ({
      kind: 'response',
      status: 200,
      body: { id: user.organizationPublicId, name: 'IT Org' },
    }));
    const out = await h.executor.execute(ctx(), { name: 'organizations_get', arguments: {} }, 0);
    expect(out.decision).toBe('allowed');
    expect(h.loopback.toolCalls[0]!.path).toBe(
      `/api/v1/organizations/${user.organizationPublicId}`,
    );
    expect(h.world.executions[0]!.resourceRef).toBe(user.organizationPublicId);
  });

  it('allowed: loopback request, card, envelope, execution row and audit metadata (D8, D12)', async () => {
    const { h, ctx, conversation } = setup();
    h.loopback.on('GET /api/v1/policies', () => policyPage(2, 'next-cursor-1'));
    const out = await h.executor.execute(
      ctx({ turnPublicId: '0193d000-0000-7000-8000-0000000000t1' }),
      { name: 'policy_management_list', arguments: { status: 'active' } },
      0,
    );
    const call = h.loopback.toolCalls[0]!;
    expect(call).toMatchObject({
      method: 'GET',
      path: '/api/v1/policies?status=active',
      authorization: 'Bearer it-access-token',
      correlationId: 'it-corr-0001.1',
      clientIp: '198.51.100.7',
      executionId: out.executionId,
    });
    expect(out.card).toMatchObject({ kind: 'table', nextCursor: true, refs: ['r1.1', 'r1.2'] });
    expect(out.envelope).toMatchObject({ status: 'ok', hasMore: true });
    expect(JSON.stringify(out.envelope)).not.toContain('next-cursor-1');
    expect(h.world.executions[0]).toMatchObject({
      nextCursor: 'next-cursor-1',
      paramsRedacted: { status: 'active' },
      correlationId: 'it-corr-0001.1',
      conversationId: conversation.id,
    });
    const meta = h.audit.entries[0]!.metadata!;
    expect(meta).toMatchObject({
      conversationId: conversation.publicId,
      tool: 'policy_management_list',
      operationId: 'PolicyManagementController_list_v1',
      access: 'read',
      risk: 'read',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 200,
      error: null,
      params: { status: 'active' },
      correlationId: 'it-corr-0001.1',
    });
  });

  it('records API errors, timeouts and oversized results with coded envelopes', async () => {
    const { h, ctx } = setup();
    h.loopback.on('GET /api/v1/policies', () => ({
      kind: 'response',
      status: 403,
      body: { statusCode: 403, code: 'forbidden', message: 'Forbidden' },
    }));
    const forbidden = await h.executor.execute(
      ctx(),
      { name: 'policy_management_list', arguments: {} },
      0,
    );
    expect(forbidden).toMatchObject({
      decision: 'allowed',
      status: 'failed',
      errorCode: 'forbidden',
    });
    expect(forbidden.card).toMatchObject({ kind: 'error' });
    h.loopback.on('GET /api/v1/policies', () => ({ kind: 'timeout' }));
    const slow = await h.executor.execute(
      ctx(),
      { name: 'policy_management_list', arguments: {} },
      1,
    );
    expect(slow).toMatchObject({ status: 'timeout', errorCode: 'tool_timeout', httpStatus: null });
    h.loopback.on('GET /api/v1/policies', () => ({ kind: 'too_large', status: 200 }));
    const big = await h.executor.execute(
      ctx(),
      { name: 'policy_management_list', arguments: {} },
      2,
    );
    expect(big).toMatchObject({ status: 'failed', errorCode: 'tool_result_too_large' });
  });
});

describe('proposal guards before any loopback call (step AI-3 D3, D10; design §9 item 2)', () => {
  const SELF = testUser().userPublicId;
  const OTHER = '0193b000-0000-7000-8000-000000000502';
  const SESSION = '0193b000-0000-7000-8000-0000000005e1';
  const ORG = '0193b000-0000-7000-8000-000000007002';
  const identityUser = testUser({
    permissions: new Set(['assistant:use', 'user:manage', 'user:read', 'session:manage']),
  });
  const SELF_GUARDED: Array<[string, Record<string, unknown>]> = [
    ['users_update', { body: { displayName: 'Renamed person' } }],
    ['users_change_status', { body: { status: 'disabled', reason: 'Disabled in a test' } }],
    ['users_replace_roles', { body: { roleKeys: ['organization_admin'] } }],
    ['users_reset_mfa', {}],
    ['users_remove', {}],
    ['users_revoke_all_sessions', {}],
    ['users_revoke_session', { sessionId: SESSION }],
    ['users_resend_invitation', {}],
  ];

  /** The `assistant_tool_calls_total` value of a decision. */
  const toolCallsOf = async (h: ReturnType<typeof setup>['h'], decision: string): Promise<number> =>
    (await h.metrics.toolCalls.get()).values
      .filter((v) => v.labels.decision === decision)
      .reduce((sum, v) => sum + v.value, 0);

  it.each(SELF_GUARDED)(
    '%s with the caller’s own id (any case) → denied_guard, nothing sent or stored',
    async (name, extra) => {
      for (const id of [SELF, SELF.toUpperCase()]) {
        const { h, ctx } = setup(identityUser);
        const out = await h.executor.execute(ctx(), { name, arguments: { id, ...extra } }, 0);
        expect(out, `${name} ${id}`).toMatchObject({
          decision: 'denied_guard',
          status: 'refused',
          errorCode: 'denied_guard',
          card: null,
          confirmation: null,
          denialMessage: GUARD_MESSAGES.self,
        });
        expect(out.envelope).toEqual({
          kind: 'tool_result/1',
          tool: name,
          status: 'denied',
          decision: 'denied_guard',
          code: 'denied_guard',
          message: GUARD_MESSAGES.self,
        });
        // No loopback request at all: not even the precondition read.
        expect(h.loopback.calls).toHaveLength(0);
        expect(h.world.confirmations).toHaveLength(0);
        expect(h.world.executions).toHaveLength(1);
        expect(h.world.executions[0]).toMatchObject({
          decision: 'denied_guard',
          status: 'refused',
          errorCode: 'denied_guard',
        });
        expect(h.audit.entries).toHaveLength(1);
        expect(h.audit.entries[0]).toMatchObject({
          action: 'assistant.tool_denied',
          metadata: { decision: 'denied_guard', guard: 'not_self_user', status: 'refused' },
        });
        // The message never echoes an argument value.
        expect(out.denialMessage!.toLowerCase()).not.toContain(SELF.toLowerCase());
        expect(await toolCallsOf(h, 'denied_guard')).toBe(1);
      }
    },
  );

  it('another user’s id passes the guard (the proposal reads the target)', async () => {
    const { h, ctx } = setup(identityUser);
    h.loopback.on(`GET /api/v1/users/${OTHER}`, () => ({
      kind: 'response',
      status: 200,
      body: {
        id: OTHER,
        email: 'other@example.test',
        displayName: 'Other',
        status: 'active',
        mfaEnabled: true,
        roles: [{ key: 'security_analyst' }],
      },
    }));
    const out = await h.executor.execute(
      ctx(),
      { name: 'users_reset_mfa', arguments: { id: OTHER } },
      0,
    );
    expect(out).toMatchObject({ decision: 'allowed', status: 'pending_confirmation' });
    expect(h.loopback.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `GET /api/v1/users/${OTHER}`,
    ]);
  });

  it('the assistant’s own feature (ai_assistant) cannot be overridden or reset in chat', async () => {
    const operator = testUser({
      organizationKind: 'platform',
      permissions: new Set(['assistant:use', 'platform:organizations']),
    });
    for (const [name, extra] of [
      ['organization_configuration_override_feature', { body: { enabled: false } }],
      ['organization_configuration_reset_feature', {}],
    ] as const) {
      const { h, ctx } = setup(operator);
      const out = await h.executor.execute(
        ctx(),
        { name, arguments: { id: ORG, featureKey: 'ai_assistant', ...extra } },
        0,
      );
      expect(out, name).toMatchObject({
        decision: 'denied_guard',
        denialMessage: GUARD_MESSAGES.assistant_feature,
      });
      expect(h.loopback.calls).toHaveLength(0);
      expect(h.audit.entries[0]!.metadata).toMatchObject({ guard: 'deny_values' });
    }
  });

  it('roles_create granting assistant:configure → denied_guard before any read; without it a proposal', async () => {
    const roleAdmin = testUser({ permissions: new Set(['assistant:use', 'role:manage']) });
    const { h, ctx } = setup(roleAdmin);
    const denied = await h.executor.execute(
      ctx(),
      {
        name: 'roles_create',
        arguments: {
          body: {
            key: 'it_helpers',
            name: 'IT helpers',
            permissions: ['policy:read', 'assistant:configure'],
          },
        },
      },
      0,
    );
    expect(denied).toMatchObject({
      decision: 'denied_guard',
      denialMessage: GUARD_MESSAGES.assistant_configure,
    });
    expect(h.audit.entries[0]!.metadata).toMatchObject({ guard: 'deny_permission_change' });
    expect(h.loopback.calls).toHaveLength(0);
    const allowed = await h.executor.execute(
      ctx(),
      {
        name: 'roles_create',
        arguments: {
          body: { key: 'it_helpers', name: 'IT helpers', permissions: ['policy:read'] },
        },
      },
      1,
    );
    expect(allowed).toMatchObject({ decision: 'allowed', status: 'pending_confirmation' });
    expect(allowed.confirmation!.view).toMatchObject({ risk: 'high', requiresReauth: true });
    expect(h.loopback.calls).toHaveLength(0);
  });
});

describe('executor helpers', () => {
  it('builds correlation ids within ^[A-Za-z0-9._:-]{8,128}$', () => {
    expect(executionCorrelationId('abc-12345', 3)).toBe('abc-12345.3');
    expect(executionCorrelationId('x'.repeat(128), 12)).toHaveLength(128);
    expect(executionCorrelationId('bad id!', 1)).toBe('assistant.1');
  });

  it('scrubs credential keys and caps parameters (audit 2 KiB, row 4 KiB)', () => {
    expect(redactParams({ q: 'a', password: 'p', nested: { apiKey: 'k', ok: 1 } }, 2048)).toEqual({
      value: { q: 'a', nested: { ok: 1 } },
      exact: false,
    });
    expect(redactParams({ status: 'active' }, 2048)).toEqual({
      value: { status: 'active' },
      exact: true,
    });
    const big = redactParams({ q: 'x'.repeat(5000) }, 2048);
    expect(big).toEqual({ value: { truncated: true, keys: ['q'] }, exact: false });
  });

  it('takes the first path parameter as the resource reference', () => {
    const tool = OPERATION_TOOLS.find((t) => t.name === 'policy_management_get')!;
    expect(resourceRefOf(tool, { policyId: POLICY_ID })).toBe(POLICY_ID);
    expect(resourceRefOf(null, { policyId: POLICY_ID })).toBeNull();
  });
});
