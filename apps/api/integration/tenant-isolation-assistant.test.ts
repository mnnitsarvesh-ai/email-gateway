/**
 * Step AI-1 tenant isolation of the assistant (docs/plan/steps/28-ai-chat-management.md I4, D5,
 * D12, Q9, Q11, §9 item 4; contracts §35) on the real stack, the api listening on its ephemeral
 * loopback port (real tool calls) and the deterministic fake provider:
 *
 * - organization B's users get `404` for organization A's conversations (read, rename, delete,
 *   messages, turns), turns (cancel), executions and `more` pages, and never see them listed;
 * - refs (`@r<seq>.<row>`) resolve only inside their own conversation: another conversation's
 *   (or organization's) refs are `denied_ref`;
 * - ids of organization A's resources supplied by the model in organization B's turn reach the
 *   api, whose `404` is surfaced in the execution and the envelope;
 * - a platform override conversation is stored under the override's target organization with
 *   `platform_override_id`, its loopback calls are audited by the override auditor, and it is
 *   private to the operator;
 * - API keys get `403 user_required` on every assistant route.
 *
 * Synthetic `it-*` organizations only.
 */
// @covers get /api/v1/assistant/status
// @covers get /api/v1/assistant/settings
// @covers put /api/v1/assistant/settings
// @covers get /api/v1/assistant/usage
// @covers get /api/v1/assistant/tools
// @covers get /api/v1/assistant/conversations
// @covers post /api/v1/assistant/conversations
// @covers get /api/v1/assistant/conversations/:conversationId
// @covers patch /api/v1/assistant/conversations/:conversationId
// @covers delete /api/v1/assistant/conversations/:conversationId
// @covers get /api/v1/assistant/conversations/:conversationId/messages
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers post /api/v1/assistant/turns/:turnId/cancel
// @covers get /api/v1/assistant/executions/:executionId
// @covers post /api/v1/assistant/executions/:executionId/more
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  call,
  clearAssistantCounters,
  createAssistantApp,
  directive,
  enableAssistant,
  envelopesOf,
  member,
  type Member,
  newConversation,
  platformMember,
  turn,
  waitFor,
} from './support/assistant';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, uniqueIp } from './support/http';

const POLL = { timeout: 15_000, interval: 200 };

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Member;
let adminB: Member;
/** Organization A's conversation with a users list (r1) and a one-row page with more (r2). */
let conversationA: string;
let turnA: string;
let listA: string;
let pagedA: string;

beforeAll(async () => {
  ({ ctx } = await createAssistantApp());
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx, ['platform_admin']);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  adminA = await member(ctx, fx, orgA, [
    await fx.createCustomRole(orgA, [...ALL_TENANT_PERMISSIONS]),
  ]);
  adminB = await member(ctx, fx, orgB, [
    await fx.createCustomRole(orgB, [...ALL_TENANT_PERMISSIONS]),
  ]);
  await fx.createUser(orgA, { roles: ['read_only_user'] });
  await enableAssistant(ctx, operator, orgA, adminA);
  await enableAssistant(ctx, operator, orgB, adminB);

  conversationA = await newConversation(ctx, adminA, 'Organization A only');
  // The users list reads the replica: wait until it serves both users of A.
  await waitFor(
    async () => {
      const res = await call(ctx, adminA.headers, 'get', '/api/v1/users?limit=100');
      return (res.body.data as unknown[] | undefined)?.length;
    },
    (n) => n === 2,
  );
  const first = await turn(ctx, adminA.headers, conversationA, directive('users_list'));
  expect(first.status).toBe(200);
  turnA = first.body.turn.id as string;
  listA = first.body.executions[0].id as string;
  const second = await turn(
    ctx,
    adminA.headers,
    conversationA,
    directive('users_list', { limit: 1 }),
  );
  expect(second.body.executions[0]).toMatchObject({ ref: 'r2', hasMore: true });
  pagedA = second.body.executions[0].id as string;
}, 120_000);

afterAll(async () => {
  if (ctx)
    await clearAssistantCounters(
      ctx,
      [orgA?.id, orgB?.id].filter((v) => v !== undefined),
    );
  await fx?.cleanup();
  await ctx?.close();
});

describe('another organization’s conversations, turns and executions answer 404', () => {
  it('refuses every conversation route of organization A to organization B', async () => {
    const cases = [
      ['get', `${A}/conversations/${conversationA}`, undefined, 'assistant_conversation_not_found'],
      [
        'patch',
        `${A}/conversations/${conversationA}`,
        { title: 'taken over' },
        'assistant_conversation_not_found',
      ],
      [
        'delete',
        `${A}/conversations/${conversationA}`,
        undefined,
        'assistant_conversation_not_found',
      ],
      [
        'get',
        `${A}/conversations/${conversationA}/messages`,
        undefined,
        'assistant_conversation_not_found',
      ],
      [
        'post',
        `${A}/conversations/${conversationA}/turns`,
        { clientTurnId: randomUUID(), message: directive('users_list') },
        'assistant_conversation_not_found',
      ],
      ['post', `${A}/turns/${turnA}/cancel`, undefined, 'assistant_turn_not_found'],
      ['get', `${A}/executions/${listA}`, undefined, 'assistant_execution_not_found'],
      ['post', `${A}/executions/${pagedA}/more`, undefined, 'assistant_execution_not_found'],
    ] as const;
    for (const [method, path, body, code] of cases) {
      const res = await call(ctx, adminB.headers, method, path, body);
      expect(res.status, `${method} ${path}`).toBe(404);
      expect(res.body.code, `${method} ${path}`).toBe(code);
    }
    const listed = await call(ctx, adminB.headers, 'get', `${A}/conversations`);
    expect(listed.status).toBe(200);
    expect((listed.body.data as Array<{ id: string }>).map((c) => c.id)).not.toContain(
      conversationA,
    );

    // Nothing changed for A: the conversation, its two turns and no new execution.
    const own = await call(ctx, adminA.headers, 'get', `${A}/conversations/${conversationA}`);
    expect(own.body).toMatchObject({
      title: 'Organization A only',
      status: 'active',
      turnCount: 2,
    });
    const rows = await ctx.prisma.aiChatToolExecution.count({
      where: { conversation: { publicId: conversationA } },
    });
    expect(rows).toBe(2);
    expect(await ctx.prisma.aiChatConversation.count({ where: { organizationId: orgB.id } })).toBe(
      0,
    );
  });
});

describe('refs are scoped to their conversation (D5 step 5)', () => {
  it('resolves a ref in its own conversation and refuses it anywhere else', async () => {
    const own = await turn(
      ctx,
      adminA.headers,
      conversationA,
      directive('users_get', { id: '@r1.1' }),
    );
    expect(own.status).toBe(200);
    expect(own.body.executions[0]).toMatchObject({
      tool: 'users_get',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 200,
    });

    const otherConversation = await newConversation(ctx, adminA);
    for (const ref of ['@r1.1', '@r2.1']) {
      const res = await turn(
        ctx,
        adminA.headers,
        otherConversation,
        directive('users_get', { id: ref }),
      );
      expect(res.status).toBe(200);
      expect(res.body.executions[0], ref).toMatchObject({
        tool: 'users_get',
        decision: 'denied_ref',
        status: 'refused',
        httpStatus: null,
      });
    }
    const conversationB = await newConversation(ctx, adminB);
    const foreign = await turn(
      ctx,
      adminB.headers,
      conversationB,
      directive('users_get', { id: '@r1.1' }),
    );
    expect(foreign.body.executions[0]).toMatchObject({ decision: 'denied_ref' });
    expect(
      await ctx.prisma.auditLog.count({
        where: {
          organizationId: orgB.id,
          action: 'assistant.tool_denied',
          resourceId: foreign.body.executions[0].id as string,
        },
      }),
    ).toBe(1);
  });

  it('surfaces the api’s 404 for model-supplied ids of organization A in B’s turn', async () => {
    const conversationB = await newConversation(ctx, adminB);
    const res = await turn(
      ctx,
      adminB.headers,
      conversationB,
      directive('users_get', { id: adminA.user.publicId }),
    );
    expect(res.status).toBe(200);
    const execution = res.body.executions[0];
    expect(execution).toMatchObject({
      tool: 'users_get',
      decision: 'allowed',
      status: 'failed',
      httpStatus: 404,
    });
    expect(execution.errorCode).toEqual(expect.any(String));
    expect(execution.card).toMatchObject({ kind: 'error', status: 'error' });
    expect(res.body.message.content).toBe(`The request failed: ${execution.errorCode}.`);
    const [envelope] = await envelopesOf(ctx, res.body.turn.id as string);
    expect(envelope!.parsed).toMatchObject({
      kind: 'tool_result/1',
      tool: 'users_get',
      status: 'error',
      httpStatus: 404,
      code: execution.errorCode,
    });
    expect(envelope!.raw).not.toContain(adminA.user.email);
  });
});

describe('platform override (Q11)', () => {
  it('stores the conversation under the target organization with the override id', async () => {
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(operator.headers)
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: orgA.publicId, reason: 'Assistant isolation check' });
    expect(started.status).toBe(201);
    const overrideId = started.body.overrideId as string;
    const override = bearer(started.body.accessToken as string);
    try {
      const created = await call(ctx, override, 'post', `${A}/conversations`, {});
      expect(created.status).toBe(201);
      expect(created.body).toMatchObject({ underPlatformOverride: true });
      const id = created.body.id as string;
      const row = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
        where: { publicId: id },
      });
      expect(row).toMatchObject({
        organizationId: orgA.id,
        userId: operator.user.id,
        platformOverrideId: overrideId,
      });

      const res = await turn(ctx, override, id, directive('users_list'));
      expect(res.status).toBe(200);
      expect(res.body.executions[0]).toMatchObject({ decision: 'allowed', status: 'succeeded' });
      const execution = await ctx.prisma.aiChatToolExecution.findUniqueOrThrow({
        where: { publicId: res.body.executions[0].id as string },
      });
      expect(execution).toMatchObject({ organizationId: orgA.id, userId: operator.user.id });
      // The override auditor recorded the loopback call (its x-correlation-id).
      await expect
        .poll(
          () =>
            ctx.prisma.auditLog.count({
              where: {
                action: 'platform.override_request',
                correlationId: execution.correlationId,
              },
            }),
          POLL,
        )
        .toBe(1);
      // Platform-only tools stay absent under an override (tenant permissions only).
      const tools = await call(ctx, override, 'get', `${A}/tools`);
      const names = (tools.body.tools as Array<{ name: string }>).map((t) => t.name);
      expect(names).toContain('users_list');
      expect(names).not.toContain('dead_letters_stats');

      // Private to the operator: A's own admin and the operator's home scope get 404.
      const asMember = await call(ctx, adminA.headers, 'get', `${A}/conversations/${id}`);
      expect(asMember.status).toBe(404);
      const home = await call(ctx, operator.headers, 'get', `${A}/conversations/${id}`);
      expect(home.status).toBe(404);
    } finally {
      await ctx.http
        .delete(`/api/v1/platform/overrides/${overrideId}`)
        .set(operator.headers)
        .set('X-Forwarded-For', uniqueIp());
    }
  });
});

describe('API keys cannot use the assistant (user only)', () => {
  it('answers 403 user_required on every assistant route', async () => {
    const key = apiKeyHeader(
      await fx.createApiKey(orgA, ['assistant:use', 'assistant:configure', 'user:read']),
    );
    const routes = [
      ['get', `${A}/status`, undefined],
      ['get', `${A}/settings`, undefined],
      [
        'put',
        `${A}/settings`,
        {
          expectedRowVersion: 1,
          enabled: false,
          externalProcessingAcknowledged: false,
          dailyTokenBudget: null,
          retentionDays: 30,
        },
      ],
      ['get', `${A}/usage`, undefined],
      ['get', `${A}/tools`, undefined],
      ['get', `${A}/conversations`, undefined],
      ['post', `${A}/conversations`, {}],
      ['get', `${A}/conversations/${conversationA}`, undefined],
      ['patch', `${A}/conversations/${conversationA}`, { title: 'by key' }],
      ['delete', `${A}/conversations/${conversationA}`, undefined],
      ['get', `${A}/conversations/${conversationA}/messages`, undefined],
      [
        'post',
        `${A}/conversations/${conversationA}/turns`,
        { clientTurnId: randomUUID(), message: '/text hi' },
      ],
      ['post', `${A}/turns/${turnA}/cancel`, undefined],
      ['get', `${A}/executions/${listA}`, undefined],
      ['post', `${A}/executions/${pagedA}/more`, undefined],
    ] as const;
    expect(routes).toHaveLength(15);
    for (const [method, path, body] of routes) {
      const res = await call(ctx, key, method, path, body);
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(res.body.code, `${method} ${path}`).toBe('user_required');
    }
    const settings = await ctx.prisma.aiChatSettings.findUniqueOrThrow({
      where: { organizationId: orgA.id },
    });
    expect(settings.enabled).toBe(true);
    const own = await call(ctx, adminA.headers, 'get', `${A}/conversations/${conversationA}`);
    expect(own.status).toBe(200);
  });
});
