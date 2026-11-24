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
 * - API keys get `403 user_required` on every assistant route;
 * - step AI-2 (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md D2, §9 item 4): another
 *   organization's or another user's confirmation answers `404 assistant_confirmation_not_found`
 *   on get, confirm (even with the token) and cancel; a write that names another organization's
 *   record fails at the precondition read (the api's `404`) and stores no confirmation;
 * - step AI-3 (docs/plan/steps/30-ai-chat-identity-tenant-admin.md D6, §9 item 4): the identity
 *   and tenant administration writes naming organization A's user, role key, department,
 *   domain, webhook, SMTP connector or API key in organization B's turn fail at the precondition
 *   read with the api's `404` and store no confirmation; `api_keys_get` of A's key answers `404`.
 * - step AI-R (docs/plan/steps/31-ai-chat-reports.md §4.1, D5, D6, §9 item 5): organization A's
 *   report answers `404 assistant_report_not_found` to organization B (and to A's own admin
 *   when it was generated under a platform override), B's `report_send_email` naming A's report
 *   fails `404` at proposal with no confirmation, each organization's report object lives under
 *   its own `org/<id>/assistant/report/` prefix, and A's deliveries are never listed to B.
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
// @covers get /api/v1/assistant/confirmations/:confirmationId
// @covers post /api/v1/assistant/confirmations/:confirmationId/confirm
// @covers post /api/v1/assistant/confirmations/:confirmationId/cancel
// @covers get /api/v1/api-keys/:id
// @covers get /api/v1/users/:id
// @covers get /api/v1/roles/:key
// @covers get /api/v1/departments/:departmentId
// @covers get /api/v1/domains/:id
// @covers get /api/v1/domains/:id/destinations
// @covers get /api/v1/webhooks/:webhookId
// @covers get /api/v1/smtp-connectors/:id
// @covers get /api/v1/assistant/reports/:reportId
import { randomUUID } from 'node:crypto';
import { FAKE_EXECUTABLES_DEFINITION } from '@email-gateway/assistant';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  call,
  cancelConfirmation,
  clearAssistantCounters,
  confirm,
  confirmationRow,
  createAssistantApp,
  directive,
  enableAssistant,
  envelopesOf,
  member,
  type Member,
  newConversation,
  platformMember,
  propose,
  REPORTS,
  reportObjectKeys,
  reportRow,
  trackReports,
  turn,
  waitFor,
  waitForRead,
} from './support/assistant';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, idem, uniqueIp } from './support/http';
import { insertDomain, randomV4Network } from './support/smtp';
import { createBody, WEBHOOKS } from './support/webhooks';

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
  orgA = await fx.createOrganization({ features: { webhooks: true } });
  orgB = await fx.createOrganization();
  // Step AI-R: the reports of A and B (rows and MinIO objects).
  trackReports(ctx, fx, [orgA.id, orgB.id]);
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
      ['get', `${A}/confirmations/${randomUUID()}`, undefined],
      [
        'post',
        `${A}/confirmations/${randomUUID()}/confirm`,
        { token: 'A'.repeat(43), actionDigest: 'a'.repeat(64) },
      ],
      ['post', `${A}/confirmations/${randomUUID()}/cancel`, undefined],
      // Step AI-R §4.1.
      ['get', `${A}/reports/${randomUUID()}`, undefined],
    ] as const;
    expect(routes).toHaveLength(19);
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

describe('step AI-2 confirmations are private to their owner (D2 step 1)', () => {
  beforeAll(() => {
    fx.registerCleanup(async () => {
      const repo = ctx.get(PolicyTenantDataRepository);
      for (const org of [orgA, orgB]) await repo.purgeOrganization(systemScope(org.id));
    });
  });

  it('another organization or user gets 404 on get, confirm and cancel', async () => {
    const created = await call(ctx, adminA.headers, 'post', '/api/v1/policies', {
      name: `it isolation ${randomUUID().slice(0, 8)}`,
      definition: FAKE_EXECUTABLES_DEFINITION,
    });
    expect(created.status).toBe(201);
    const policyId = created.body.policy.id as string;
    await waitForRead(ctx, adminA, `/api/v1/policies/${policyId}`);
    const proposal = await propose(
      ctx,
      adminA,
      directive('policy_management_disable', { policyId }),
    );
    const otherA = await member(ctx, fx, orgA, [
      await fx.createCustomRole(orgA, [...ALL_TENANT_PERMISSIONS]),
    ]);
    for (const stranger of [adminB, otherA]) {
      const get = await call(
        ctx,
        stranger.headers,
        'get',
        `${A}/confirmations/${proposal.confirmation.id}`,
      );
      expect(get.status).toBe(404);
      expect(get.body.code).toBe('assistant_confirmation_not_found');
      const confirmed = await confirm(ctx, stranger, proposal);
      expect(confirmed.status).toBe(404);
      expect(confirmed.body.code).toBe('assistant_confirmation_not_found');
      const cancelled = await cancelConfirmation(ctx, stranger, proposal.confirmation.id);
      expect(cancelled.status).toBe(404);
      expect(cancelled.body.code).toBe('assistant_confirmation_not_found');
    }
    expect((await confirmationRow(ctx, proposal.confirmation.id)).status).toBe('pending');
    const policy = await ctx.prisma.emailPolicy.findFirstOrThrow({ where: { publicId: policyId } });
    expect(policy.status).toBe('draft');
    // No refusal is audited in the other organization; the owner still decides.
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgB.id, resourceId: proposal.confirmation.id },
      }),
    ).toBe(0);
    expect((await cancelConfirmation(ctx, adminA, proposal.confirmation.id)).status).toBe(200);
  });

  it('a write naming another organization’s record fails at the precondition read; nothing stored', async () => {
    const created = await call(ctx, adminA.headers, 'post', '/api/v1/policies', {
      name: `it foreign ${randomUUID().slice(0, 8)}`,
      definition: FAKE_EXECUTABLES_DEFINITION,
    });
    expect(created.status).toBe(201);
    const policyId = created.body.policy.id as string;
    await waitForRead(ctx, adminA, `/api/v1/policies/${policyId}`);
    const conversationB = await newConversation(ctx, adminB);
    for (const [tool, args] of [
      ['policy_management_disable', { policyId }],
      ['policy_management_remove', { policyId }],
      [
        'policy_management_update',
        { policyId, body: { name: 'taken over', expectedRowVersion: 1 } },
      ],
    ] as const) {
      const res = await turn(ctx, adminB.headers, conversationB, directive(tool, args));
      expect(res.status).toBe(200);
      expect(res.body.executions[0], tool).toMatchObject({
        tool,
        decision: 'allowed',
        status: 'failed',
        httpStatus: 404,
        errorCode: 'policy_not_found',
      });
      expect(res.body.confirmations).toEqual([]);
    }
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({ where: { organizationId: orgB.id } }),
    ).toBe(0);
    const policy = await ctx.prisma.emailPolicy.findFirstOrThrow({ where: { publicId: policyId } });
    expect(policy).toMatchObject({ status: 'draft', deletedAt: null });
    expect(policy.name).not.toBe('taken over');
  });
});

describe('step AI-3 writes naming another organization’s records (D6)', () => {
  it('fail at the precondition read with the api’s 404; nothing stored or changed', async () => {
    // Organization A's records.
    const userA = await fx.createUser(orgA, { roles: ['read_only_user'] });
    const roleA = await fx.createCustomRole(orgA, ['message:read']);
    const department = await call(ctx, adminA.headers, 'post', '/api/v1/departments', {
      name: `Isolation ${randomUUID().slice(0, 8)}`,
    });
    expect(department.status).toBe(201);
    const departmentA = department.body.id as string;
    const domainA = await insertDomain(ctx, orgA, { label: 'iso-chat' });
    const webhook = await call(ctx, adminA.headers, 'post', WEBHOOKS, createBody()).set(idem());
    expect(webhook.status).toBe(201);
    const webhookA = webhook.body.id as string;
    const connector = await call(ctx, adminA.headers, 'post', '/api/v1/smtp-connectors', {
      name: `iso ${randomUUID().slice(0, 8)}`,
      authType: 'source_ip',
      networks: [randomV4Network()],
    });
    expect(connector.status, JSON.stringify(connector.body)).toBe(201);
    const connectorA = connector.body.id as string;
    await fx.createApiKey(orgA, ['user:read']);
    const keyA = (
      await ctx.prisma.apiKey.findFirstOrThrow({
        where: { organizationId: orgA.id },
        orderBy: { id: 'desc' },
      })
    ).publicId;
    const snapshot = async () => ({
      user: await ctx.prisma.user.findUniqueOrThrow({
        where: { id: userA.id },
        select: { status: true, displayName: true, deletedAt: true },
      }),
      role: await ctx.prisma.role.findFirstOrThrow({
        where: { organizationId: orgA.id, key: roleA },
        include: { permissions: true },
      }),
      department: await ctx.prisma.tenantDepartment.findFirstOrThrow({
        where: { publicId: departmentA },
      }),
      domain: await ctx.prisma.domain.findUniqueOrThrow({ where: { id: domainA.id } }),
      webhook: await ctx.prisma.webhookSubscription.findUniqueOrThrow({
        where: { publicId: webhookA },
      }),
      connector: await ctx.prisma.smtpConnector.findUniqueOrThrow({
        where: { publicId: connectorA },
      }),
      key: await ctx.prisma.apiKey.findUniqueOrThrow({ where: { publicId: keyA } }),
    });
    const before = await snapshot();

    const conversationB = await newConversation(ctx, adminB);
    const cases: Array<[string, Record<string, unknown>]> = [
      ['users_change_status', { id: userA.publicId, body: { status: 'disabled' } }],
      ['users_replace_roles', { id: userA.publicId, body: { roleKeys: ['read_only_user'] } }],
      ['users_remove', { id: userA.publicId }],
      ['roles_update', { key: roleA, body: { name: 'taken over', permissions: ['message:read'] } }],
      ['roles_remove', { key: roleA }],
      [
        'departments_update',
        { departmentId: departmentA, body: { name: 'taken over', expectedRowVersion: 1 } },
      ],
      ['departments_remove', { departmentId: departmentA }],
      ['domains_remove', { id: domainA.publicId }],
      [
        'domain_destinations_replace',
        { id: domainA.publicId, body: { provider: 'google_workspace' } },
      ],
      [
        'webhooks_update',
        {
          webhookId: webhookA,
          body: { url: 'https://taken-over.webhooks-it.test/in', expectedRowVersion: 1 },
        },
      ],
      ['webhooks_test', { webhookId: webhookA }],
      ['smtp_connectors_update', { id: connectorA, body: { networks: [randomV4Network()] } }],
      ['smtp_connectors_remove', { id: connectorA }],
      ['api_keys_revoke', { id: keyA }],
    ];
    let turns = 0;
    let conversation = conversationB;
    for (const [tool, args] of cases) {
      // A fresh conversation every few turns (the pending cap never applies: nothing is pending).
      if (++turns % 5 === 0) conversation = await newConversation(ctx, adminB);
      const res = await turn(ctx, adminB.headers, conversation, directive(tool, args));
      expect(res.status).toBe(200);
      expect(res.body.executions[0], tool).toMatchObject({
        tool,
        decision: 'allowed',
        status: 'failed',
        httpStatus: 404,
      });
      expect(res.body.confirmations, tool).toEqual([]);
    }
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({ where: { organizationId: orgB.id } }),
    ).toBe(0);

    // The new read (D8): another organization's API key is a 404 too.
    const read = await turn(
      ctx,
      adminB.headers,
      await newConversation(ctx, adminB),
      directive('api_keys_get', { id: keyA }),
    );
    expect(read.body.executions[0]).toMatchObject({
      tool: 'api_keys_get',
      decision: 'allowed',
      status: 'failed',
      httpStatus: 404,
    });
    const [envelope] = await envelopesOf(ctx, read.body.turn.id as string);
    expect(envelope!.parsed).toMatchObject({ status: 'error', httpStatus: 404 });
    expect(envelope!.raw).not.toContain(before.key.keyPrefix);
    expect(await snapshot()).toEqual(before);
  });
});

describe('step AI-R reports and deliveries are private to their organization (§4.1, D5, D6)', () => {
  it('B gets 404 for A’s report, cannot email it and never sees A’s deliveries or objects', async () => {
    const conversation = await newConversation(ctx, adminA, 'Report of A');
    const generated = await turn(
      ctx,
      adminA.headers,
      conversation,
      directive('report_generate', { sections: ['traffic'] }),
    );
    expect(generated.body.executions[0]).toMatchObject({ status: 'succeeded', httpStatus: 201 });
    const reportA = generated.body.executions[0].card.report.reportId as string;
    // A emails it to A's own admin (a real queued delivery of A).
    const proposalA = await propose(ctx, adminA, 'send this report to my email', conversation);
    const confirmedA = await confirm(ctx, adminA, proposalA);
    expect(confirmedA.body.confirmation).toMatchObject({ status: 'executed' });
    const rowA = await reportRow(ctx, reportA);
    expect(rowA.organizationId).toBe(orgA.id);

    // B: the view, an emailing proposal naming A's report, and B's own report.
    const view = await call(ctx, adminB.headers, 'get', `${REPORTS}/${reportA}`);
    expect(view.status).toBe(404);
    expect(view.body.code).toBe('assistant_report_not_found');
    expect(JSON.stringify(view.body)).not.toContain(adminA.user.email);
    const conversationB = await newConversation(ctx, adminB);
    const ownB = await turn(
      ctx,
      adminB.headers,
      conversationB,
      directive('report_generate', { sections: ['traffic'] }),
    );
    const reportB = ownB.body.executions[0].card.report.reportId as string;
    const steal = await turn(
      ctx,
      adminB.headers,
      conversationB,
      directive('report_send_email', { reportId: reportA }),
    );
    expect(steal.body.executions[0]).toMatchObject({
      tool: 'report_send_email',
      status: 'failed',
      httpStatus: 404,
      errorCode: 'assistant_report_not_found',
    });
    expect(steal.body.confirmations).toEqual([]);
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({
        where: { organizationId: orgB.id },
      }),
    ).toBe(0);
    // B's own report lists none of A's deliveries; the rows and objects stay per organization.
    const viewB = await call(ctx, adminB.headers, 'get', `${REPORTS}/${reportB}`);
    expect(viewB.status).toBe(200);
    expect(viewB.body.report.deliveries).toEqual([]);
    expect(
      await ctx.prisma.aiChatReportDelivery.count({ where: { organizationId: orgB.id } }),
    ).toBe(0);
    expect(
      await ctx.prisma.aiChatReportDelivery.count({
        where: { organizationId: orgA.id, reportId: rowA.id },
      }),
    ).toBe(1);
    const keysA = await reportObjectKeys(ctx, orgA.id);
    const keysB = await reportObjectKeys(ctx, orgB.id);
    expect(keysA).toContain(rowA.objectKey);
    expect(keysB).toEqual([(await reportRow(ctx, reportB)).objectKey]);
    expect(keysB.every((k) => k.startsWith(`org/${orgB.id.toString()}/assistant/report/`))).toBe(
      true,
    );
  });

  it('a report generated under a platform override is private to the operator in that override', async () => {
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(operator.headers)
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: orgA.publicId, reason: 'Assistant report isolation check' });
    expect(started.status).toBe(201);
    const overrideId = started.body.overrideId as string;
    const override = bearer(started.body.accessToken as string);
    try {
      const created = await call(ctx, override, 'post', `${A}/conversations`, {});
      expect(created.status).toBe(201);
      const res = await turn(
        ctx,
        override,
        created.body.id as string,
        directive('report_generate', { sections: ['traffic'] }),
      );
      expect(res.status).toBe(200);
      const execution = res.body.executions[0];
      expect(execution).toMatchObject({ tool: 'report_generate', status: 'succeeded' });
      const reportId = execution.card.report.reportId as string;
      const row = await reportRow(ctx, reportId);
      expect(row).toMatchObject({
        organizationId: orgA.id,
        userId: operator.user.id,
        platformOverrideId: overrideId,
      });
      expect(row.objectKey!.startsWith(`org/${orgA.id.toString()}/assistant/report/`)).toBe(true);
      expect((await call(ctx, override, 'get', `${REPORTS}/${reportId}`)).status).toBe(200);
      for (const headers of [adminA.headers, operator.headers, adminB.headers]) {
        expect((await call(ctx, headers, 'get', `${REPORTS}/${reportId}`)).status).toBe(404);
      }
    } finally {
      await ctx.http
        .delete(`/api/v1/platform/overrides/${overrideId}`)
        .set(operator.headers)
        .set('X-Forwarded-For', uniqueIp());
    }
  });
});
