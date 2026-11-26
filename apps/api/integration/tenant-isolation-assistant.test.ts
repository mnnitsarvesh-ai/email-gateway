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
 * - step AI-4 (docs/plan/steps/32-ai-chat-security-operations.md §9 item 3): the ATO, incident,
 *   BEC, DLP and risk-scoring writes naming organization A's account, trusted context, incident,
 *   response, IdP integration and connection, executive, vendor, trusted sender, suppression,
 *   message, policy, rule, exception, pattern, dictionary or profile version in organization
 *   B's turn fail at the precondition read with the api's `404` and store no confirmation; the
 *   new single reads `bec_trusted_senders_get`, `bec_feedback_get_suppression` and
 *   `dlp_exceptions_get` answer `404` for A's ids, and `threat_indicators_get` answers `404` to
 *   a platform user for an organization's own indicator row (not the platform catalog).
 * - step AI-5 (docs/plan/steps/33-ai-chat-compliance-integrations.md §9 item 3): the archive,
 *   journaling, eDiscovery and provider-connection writes naming organization A's retention
 *   policy, captured message, intake source, case, search or provider connection in
 *   organization B's turn fail at the precondition read with the api's `404` and store no
 *   confirmation; the new read `archive_admin_capture_issue` and the mail-flow preview answer
 *   `404` for A's message and connection; nothing of A changes.
 * - step AI-6 (docs/plan/steps/34-ai-chat-hardening-operations.md §9 item 5): organization B
 *   gets `404 assistant_message_not_found` for feedback on A's assistant message (set and
 *   remove), finds none of A's text with the content search, sees none of A's users, ratings,
 *   conversations or executions in the admin and audit views (`404
 *   assistant_admin_conversation_not_found` for A's conversation, empty pages for A's ids as
 *   filters), gets `404 assistant_report_not_found` for A's queued background report (its job),
 *   and never sees or removes A's provider key (`tenantKey: null`, `404
 *   assistant_tenant_key_not_found`); API keys get `403 user_required` on the 11 new routes.
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
// @covers get /api/v1/bec/trusted-senders/:id
// @covers get /api/v1/bec/suppressions/:id
// @covers get /api/v1/dlp/exceptions/:id
// @covers get /api/v1/platform/threat-indicators/:id
// @covers get /api/v1/archive/capture-issues/:messageId
// @covers get /api/v1/archive/retention-policies/:policyId
// @covers get /api/v1/journaling/intake-sources/:sourceId
// @covers get /api/v1/ediscovery/cases/:caseId
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId
// @covers get /api/v1/provider-connections/:id
// @covers post /api/v1/provider-connections/:id/mail-flow/preview
// @covers put /api/v1/assistant/settings/provider-key
// @covers delete /api/v1/assistant/settings/provider-key
// @covers post /api/v1/assistant/settings/provider-key/validate
// @covers get /api/v1/assistant/search
// @covers put /api/v1/assistant/messages/:messageId/feedback
// @covers delete /api/v1/assistant/messages/:messageId/feedback
// @covers get /api/v1/assistant/admin/usage/users
// @covers get /api/v1/assistant/admin/feedback
// @covers get /api/v1/assistant/admin/conversations
// @covers get /api/v1/assistant/admin/conversations/:conversationId
// @covers get /api/v1/assistant/admin/executions
import { createHash, randomUUID } from 'node:crypto';
import { FAKE_EXECUTABLES_DEFINITION } from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import { defaultBindingSettings } from '@email-gateway/idp-adapters';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { IncidentStores } from '../src/modules/incidents/incident-stores';
import { BecTenantDataRepository } from '../src/modules/tenant-data/bec-tenant-data.repository';
import { DlpTenantDataRepository } from '../src/modules/tenant-data/dlp-tenant-data.repository';
import { JournalIntakeTenantDataRepository } from '../src/modules/tenant-data/journal-intake-tenant-data.repository';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import { RiskTenantDataRepository } from '../src/modules/tenant-data/risk-tenant-data.repository';
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
  directPlatform,
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
import { createCase, createHold, createIntakeSource } from './support/assistant-compliance';
import { deleteAtoRows } from './support/ato';
import { ProviderSeeder } from './support/ato-providers';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, idem, uniqueIp } from './support/http';
import { deleteLifecycleFixtures, insertLifecycleMessage } from './support/lifecycle';
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
      await fx.createApiKey(orgA, [
        'assistant:use',
        'assistant:configure',
        'audit:read',
        'user:read',
      ]),
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
      // Step AI-6 §4.1 (contracts §35.6).
      [
        'put',
        `${A}/settings/provider-key`,
        {
          provider: 'openai',
          model: 'claude-opus-5-5',
          apiKey: 'test-tenant-key-0001-not-a-secret',
          expectedRowVersion: 1,
        },
      ],
      ['delete', `${A}/settings/provider-key?expectedRowVersion=1`, undefined],
      ['post', `${A}/settings/provider-key/validate`, undefined],
      ['get', `${A}/search?q=organization`, undefined],
      ['put', `${A}/messages/${randomUUID()}/feedback`, { rating: 'up' }],
      ['delete', `${A}/messages/${randomUUID()}/feedback`, undefined],
      ['get', `${A}/admin/usage/users`, undefined],
      ['get', `${A}/admin/feedback`, undefined],
      ['get', `${A}/admin/conversations`, undefined],
      ['get', `${A}/admin/conversations/${conversationA}`, undefined],
      ['get', `${A}/admin/executions`, undefined],
    ] as const;
    expect(routes).toHaveLength(30);
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

describe('step AI-4 writes and reads naming another organization’s records (design 32 §9 item 3)', () => {
  const FEATURES = ['ato_detection', 'dlp', 'bec_detection'] as const;

  it('fail at the precondition read with the api’s 404; nothing stored or changed', async () => {
    for (const organizationId of [orgA.id, orgB.id]) {
      for (const featureKey of FEATURES) {
        await ctx.prisma.organizationFeature.upsert({
          where: { organizationId_featureKey: { organizationId, featureKey } },
          create: { organizationId, featureKey, enabled: true },
          update: { enabled: true },
        });
      }
    }
    const scopes = [systemScope(orgA.id), systemScope(orgB.id)];
    fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
    fx.registerCleanup(async () => {
      for (const scope of scopes) {
        await ctx.get(BecTenantDataRepository).purgeOrganization(scope);
        await ctx.get(DlpTenantDataRepository).purgeOrganization(scope);
        await ctx.get(RiskTenantDataRepository).purgeOrganization(scope);
      }
      await ctx.prisma.threatIndicator.deleteMany({ where: { organizationId: orgA.id } });
    });
    // The live ato-worker records sign-ins of both organizations now that ATO is on.
    fx.registerCleanup(() => deleteAtoRows(ctx.prisma, [orgA.id, orgB.id]), {
      rerunOnConflict: true,
    });
    const prov = new ProviderSeeder(ctx, fx);
    const post = async (path: string, body: object, expected = 201) => {
      const res = await call(ctx, adminA.headers, 'post', path, body).set(idem());
      expect(res.status, `${path} ${JSON.stringify(res.body)}`).toBe(expected);
      return res.body as { id: string };
    };

    // Organization A's records.
    const account = await ctx.prisma.$transaction((tx) =>
      ctx.get(IncidentStores).ato.ensureAccount(tx, {
        organizationId: orgA.id,
        subject: {
          kind: 'mailbox',
          address: `iso-${randomUUID().slice(0, 6)}@it-ato.example.test`,
        },
        at: new Date(),
      }),
    );
    const accountId = account.publicId;
    await waitForRead(ctx, adminA, `/api/v1/ato/accounts/${accountId}`);
    const incidentId = (
      await post('/api/v1/incidents', {
        category: 'account_takeover',
        subject: { type: 'ato_account', id: accountId },
        reason: 'Isolation fixture',
      })
    ).id;
    const responseId = (
      await post(`/api/v1/ato/incidents/${incidentId}/responses`, {
        actionType: 'require_mfa',
        reason: 'Isolation fixture',
      })
    ).id;
    const contextId = (
      await post(`/api/v1/ato/accounts/${accountId}/trusted-contexts`, {
        kind: 'country',
        value: 'DE',
        reason: 'Isolation fixture',
        expiresInDays: 30,
      })
    ).id;
    const connection = await prov.connection(orgA);
    const integrationId = (
      await post('/api/v1/ato/providers', { connectionId: connection.publicId })
    ).id;
    const executiveId = (await post('/api/v1/bec/executives', { displayName: 'Isolation Exec' }))
      .id;
    const vendorId = (
      await post('/api/v1/bec/vendors', {
        name: 'Isolation Vendor',
        domains: ['iso-vendor.example'],
      })
    ).id;
    const trustedId = (
      await post('/api/v1/bec/trusted-senders', {
        kind: 'address',
        value: 'ops@iso-partner.example',
        reason: 'Isolation fixture',
      })
    ).id;
    const suppressionId = uuidv7();
    await ctx.prisma.becSuppressionRule.create({
      data: {
        publicId: suppressionId,
        organizationId: orgA.id,
        reasonCode: 'bec.reply_to.freemail',
        senderScope: 'domain',
        senderValue: 'iso-partner.example',
        expiresAt: new Date(Date.now() + 86_400_000),
      },
    });
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const policyId = (await post('/api/v1/dlp/policies', { name: 'Isolation policy' })).id;
    const ruleId = (
      await post(`/api/v1/dlp/policies/${policyId}/rules`, {
        name: 'Isolation rule',
        conditions: { selectors: { categories: ['payment_card'] } },
        action: 'alert',
      })
    ).id;
    const exceptionId = (
      await post('/api/v1/dlp/exceptions', {
        scope: 'sender_address',
        value: 'iso@partner.example',
        reason: 'Isolation fixture',
        expiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString(),
      })
    ).id;
    const patternId = (
      await post('/api/v1/dlp/patterns', {
        name: 'Isolation pattern',
        pattern: `ISO${randomUUID().slice(0, 6)}-[0-9]{6}`,
        severity: 'low',
      })
    ).id;
    const dictionaryId = (
      await post('/api/v1/dlp/dictionaries', {
        name: 'Isolation terms',
        category: 'custom',
        severity: 'low',
        terms: ['isolationterm'],
      })
    ).id;
    const versionId = (await post('/api/v1/risk-scoring/profile/versions', { overrides: {} })).id;
    const indicatorValue = `tenant-iso-${randomUUID().slice(0, 8)}.example`;
    const indicator = await ctx.prisma.threatIndicator.create({
      data: {
        organizationId: orgA.id,
        indicatorType: 'domain',
        value: indicatorValue,
        valueSha256: createHash('sha256').update(indicatorValue).digest('hex'),
        source: `org:${orgA.id.toString()}`,
        severity: 'high',
        confidence: 90,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      },
      select: { id: true },
    });

    const snapshot = async () => ({
      account: await ctx.prisma.atoAccount.findUniqueOrThrow({
        where: { id: account.id },
        select: { protected: true, overrideId: true },
      }),
      response: (
        await ctx.prisma.atoResponseAction.findUniqueOrThrow({ where: { publicId: responseId } })
      ).status,
      contexts: await ctx.prisma.atoTrustedContext.count({ where: { accountId: account.id } }),
      integration: await ctx.prisma.atoProviderIntegration.findUniqueOrThrow({
        where: { publicId: integrationId },
        select: { status: true, rowVersion: true },
      }),
      incident: await ctx.prisma.securityIncident.findUniqueOrThrow({
        where: { publicId: incidentId },
        select: { status: true, rowVersion: true },
      }),
      versions: await Promise.all([
        ctx.prisma.becExecutiveProfile.findUniqueOrThrow({ where: { publicId: executiveId } }),
        ctx.prisma.becVendorProfile.findUniqueOrThrow({ where: { publicId: vendorId } }),
        ctx.prisma.becTrustedSender.findUniqueOrThrow({ where: { publicId: trustedId } }),
        ctx.prisma.dlpPolicy.findUniqueOrThrow({ where: { publicId: policyId } }),
        ctx.prisma.dlpPolicyRule.findUniqueOrThrow({ where: { publicId: ruleId } }),
        ctx.prisma.dlpException.findUniqueOrThrow({ where: { publicId: exceptionId } }),
        ctx.prisma.dlpCustomPattern.findUniqueOrThrow({ where: { publicId: patternId } }),
        ctx.prisma.dlpKeywordDictionary.findUniqueOrThrow({ where: { publicId: dictionaryId } }),
      ]).then((rows) => rows.map((r) => r.version)),
      suppression: await ctx.prisma.becSuppressionRule.count({
        where: { publicId: suppressionId },
      }),
      feedback: await ctx.prisma.becFeedback.count({ where: { organizationId: orgA.id } }),
      draft: (
        await ctx.prisma.riskScoringProfileVersion.findUniqueOrThrow({
          where: { publicId: versionId },
        })
      ).rowVersion,
    });
    const before = await snapshot();

    const reason = { reason: 'taken over from another organization' };
    const cases: Array<[string, Record<string, unknown>]> = [
      ['ato_accounts_update', { accountId, body: { protected: true, expectedRowVersion: 1 } }],
      ['ato_account_mailbox_refresh', { accountId }],
      [
        'ato_accounts_set_override',
        { accountId, body: { verdict: 'benign', expiresInHours: 24, ...reason } },
      ],
      ['ato_accounts_clear_override', { accountId, body: reason }],
      [
        'ato_accounts_add_trusted_context',
        { accountId, body: { kind: 'country', value: 'FR', expiresInDays: 30, ...reason } },
      ],
      ['ato_accounts_remove_trusted_context', { accountId, contextId }],
      [
        'ato_responses_request',
        { incidentId, body: { actionType: 'restrict_smtp_sending', ...reason } },
      ],
      ['ato_responses_approve', { responseId, body: reason }],
      ['ato_responses_reject', { responseId, body: reason }],
      ['ato_responses_cancel', { responseId, body: reason }],
      ['ato_responses_rollback', { responseId, body: reason }],
      ['ato_providers_create', { body: { connectionId: connection.publicId } }],
      [
        'ato_providers_update',
        { integrationId, body: { rowVersion: 1, settings: defaultBindingSettings() } },
      ],
      ['ato_providers_remove', { integrationId, body: reason }],
      [
        'ato_providers_backfill',
        { integrationId, body: { from: new Date(Date.now() - 86_400_000).toISOString() } },
      ],
      ['ato_providers_health_check', { integrationId }],
      ['ato_providers_pause', { integrationId, body: reason }],
      ['ato_providers_resume', { integrationId }],
      [
        'incidents_create',
        {
          body: {
            category: 'account_takeover',
            subject: { type: 'ato_account', id: accountId },
            ...reason,
          },
        },
      ],
      [
        'incidents_update',
        { incidentId, body: { status: 'investigating', expectedRowVersion: 1 } },
      ],
      ['incidents_add_note', { incidentId, body: { note: 'taken over' } }],
      ['bec_executives_update', { id: executiveId, body: { version: 1, enabled: false } }],
      ['bec_executives_remove', { id: executiveId }],
      ['bec_vendors_update', { id: vendorId, body: { version: 1, enabled: false } }],
      ['bec_vendors_remove', { id: vendorId }],
      ['bec_trusted_senders_update', { id: trustedId, body: { version: 1, reason: 'taken over' } }],
      ['bec_trusted_senders_remove', { id: trustedId }],
      ['bec_feedback_delete_suppression', { id: suppressionId }],
      [
        'bec_message_feedback_record',
        { messageId: message.publicId, scanId: '1', body: { kind: 'false_negative' } },
      ],
      ['dlp_policies_update', { id: policyId, body: { version: 1, enabled: false } }],
      ['dlp_policies_remove', { id: policyId }],
      [
        'dlp_policies_create_rule',
        {
          id: policyId,
          body: {
            name: 'taken over',
            conditions: { selectors: { categories: ['credential'] } },
            action: 'allow',
          },
        },
      ],
      ['dlp_policies_update_rule', { id: policyId, ruleId, body: { version: 1, enabled: false } }],
      ['dlp_policies_remove_rule', { id: policyId, ruleId }],
      ['dlp_exceptions_update', { id: exceptionId, body: { version: 1, enabled: true } }],
      ['dlp_exceptions_remove', { id: exceptionId }],
      ['dlp_patterns_update', { id: patternId, body: { version: 1, enabled: false } }],
      ['dlp_patterns_remove', { id: patternId }],
      ['dlp_dictionaries_update', { id: dictionaryId, body: { version: 1, enabled: false } }],
      ['dlp_dictionaries_remove', { id: dictionaryId }],
      ['risk_profiles_update_draft', { versionId, body: { overrides: {}, expectedRowVersion: 1 } }],
      ['risk_profiles_delete_draft', { versionId }],
      ['risk_profiles_publish', { versionId, body: { expectedRowVersion: 1 } }],
      // The new single reads (D8).
      ['bec_trusted_senders_get', { id: trustedId }],
      ['bec_feedback_get_suppression', { id: suppressionId }],
      ['dlp_exceptions_get', { id: exceptionId }],
    ];
    let conversation = '';
    let turns = 0;
    for (const [tool, args] of cases) {
      if (turns++ % 5 === 0) conversation = await newConversation(ctx, adminB);
      const res = await turn(ctx, adminB.headers, conversation, directive(tool, args));
      expect(res.status, tool).toBe(200);
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

    // The platform single read: an organization's own indicator row is not the platform catalog.
    const platform = await directPlatform(ctx, fx, orgB, ['super_admin']);
    const read = await platform.executor.execute('threat_indicators_get', {
      id: indicator.id.toString(),
    });
    expect(read).toMatchObject({ decision: 'allowed', status: 'failed', httpStatus: 404 });
    expect(await snapshot()).toEqual(before);
  }, 300_000);
});

describe('step AI-5 writes and reads naming another organization’s records (design 33 §9 item 3)', () => {
  it('fail at the precondition read with the api’s 404; nothing stored or changed', async () => {
    const orgs = [orgA.id, orgB.id];
    for (const organizationId of orgs) {
      for (const featureKey of ['archiving', 'journal_intake']) {
        await ctx.prisma.organizationFeature.upsert({
          where: { organizationId_featureKey: { organizationId, featureKey } },
          create: { organizationId, featureKey, enabled: true },
          update: { enabled: true },
        });
      }
    }
    const identities: bigint[] = [];
    fx.registerCleanup(async () => {
      const where = { organizationId: { in: orgs } };
      for (const id of orgs) {
        await ctx.get(JournalIntakeTenantDataRepository).purgeOrganization(systemScope(id));
      }
      await ctx.prisma.ediscoverySearchHit.deleteMany({ where });
      await ctx.prisma.ediscoveryExport.deleteMany({ where });
      await ctx.prisma.ediscoverySearch.deleteMany({ where });
      await ctx.prisma.ediscoveryCustodian.deleteMany({ where });
      await ctx.prisma.archiveLegalHold.deleteMany({ where });
      await ctx.prisma.ediscoveryCase.deleteMany({ where });
      await ctx.prisma.archiveCaptureIntent.deleteMany({ where });
      await ctx.prisma.archiveSetting.deleteMany({ where });
      await ctx.prisma.archiveRetentionPolicy.deleteMany({ where });
      await ctx.prisma.messageIdentity.deleteMany({ where: { id: { in: identities } } });
    });

    // Organization A's archive, journaling, eDiscovery and provider records.
    const policy = await ctx.prisma.archiveRetentionPolicy.create({
      data: {
        organizationId: orgA.id,
        name: 'Isolation default',
        retentionDays: 365,
        priority: 100,
      },
    });
    await ctx.prisma.archiveSetting.create({
      data: {
        organizationId: orgA.id,
        enabled: true,
        defaultRetentionPolicyId: policy.id,
        journalEnabledAt: new Date(),
        generation: 1n,
      },
    });
    await insertDomain(ctx, orgA, { label: 'iso-arch' });
    const source = await createIntakeSource(ctx, adminA, 'Isolation intake');
    const receivedAt = new Date(Date.now() - 3_600_000);
    const identity = await ctx.prisma.messageIdentity.create({
      data: {
        organizationId: orgA.id,
        ingestKey: `v2:it-iso-${randomUUID()}`,
        receivedAt,
      },
      select: { id: true, publicId: true },
    });
    identities.push(identity.id);
    await ctx.prisma.archiveCaptureIntent.create({
      data: {
        receivedAt,
        organizationId: orgA.id,
        messageId: identity.id,
        direction: 'inbound',
        sourceJournal: true,
        status: 'failed',
        lastErrorCode: 'storage_error',
        attempts: 2,
        nextCheckAt: new Date(Date.now() + 86_400_000),
        settingsGeneration: 1n,
      },
    });
    const caseId = await createCase(ctx, adminA);
    await createHold(ctx, adminA, caseId);
    const caseRow = await ctx.prisma.ediscoveryCase.findUniqueOrThrow({
      where: { publicId: caseId },
    });
    // A completed search (the archive-worker's row, written on the writer).
    const search = await ctx.prisma.ediscoverySearch.create({
      data: {
        caseId: caseRow.id,
        organizationId: orgA.id,
        criteria: {},
        criteriaSha256: 'e'.repeat(64),
        status: 'completed',
        hitCount: 0,
        indexComplete: true,
        completedAt: new Date(),
      },
    });
    const connection = await new ProviderSeeder(ctx, fx).connection(orgA);

    const snapshot = async () => ({
      policy: await ctx.prisma.archiveRetentionPolicy.findUniqueOrThrow({
        where: { id: policy.id },
        select: { rowVersion: true, retentionDays: true, deletedAt: true },
      }),
      intent: (
        await ctx.prisma.archiveCaptureIntent.findFirstOrThrow({
          where: { organizationId: orgA.id, messageId: identity.id },
        })
      ).status,
      source: await ctx.prisma.journalIntakeSource.findUniqueOrThrow({
        where: { publicId: source.id },
        select: { status: true, rowVersion: true },
      }),
      case: await ctx.prisma.ediscoveryCase.findUniqueOrThrow({
        where: { id: caseRow.id },
        select: { status: true, rowVersion: true },
      }),
      holds: await ctx.prisma.archiveLegalHold.count({ where: { organizationId: orgA.id } }),
      searches: await ctx.prisma.ediscoverySearch.count({ where: { organizationId: orgA.id } }),
      exports: await ctx.prisma.ediscoveryExport.count({ where: { organizationId: orgA.id } }),
      connection: await ctx.prisma.providerConnection.findUniqueOrThrow({
        where: { id: connection.id },
        select: { status: true, rowVersion: true, displayName: true },
      }),
      grants: await ctx.prisma.providerConnectionGrant.findMany({
        where: { connectionId: connection.id },
        select: { status: true, rowVersion: true },
      }),
    });
    const before = await snapshot();

    const id = connection.publicId;
    const profile = 'm365.mail_flow';
    const cases: Array<[string, Record<string, unknown>]> = [
      [
        'archive_retention_update',
        {
          policyId: policy.publicId,
          body: { expectedRowVersion: 1, name: 'taken over', retentionDays: 1 },
        },
      ],
      ['archive_retention_delete', { policyId: policy.publicId }],
      ['archive_admin_retry', { messageId: identity.publicId }],
      [
        'intake_sources_update',
        { sourceId: source.id, body: { expectedRowVersion: 1, status: 'paused' } },
      ],
      ['intake_sources_disable', { sourceId: source.id }],
      [
        'intake_sources_attest',
        {
          sourceId: source.id,
          body: { code: 'journal.onprem.journal_recipient_created', attested: true },
        },
      ],
      ['ediscovery_cases_update', { caseId, body: { expectedRowVersion: 1, name: 'taken over' } }],
      ['ediscovery_cases_close', { caseId }],
      [
        'ediscovery_cases_create_hold',
        { caseId, body: { name: 'taken over', reason: 'taken over' } },
      ],
      [
        'ediscovery_searches_create',
        { caseId, body: { criteria: { from: '2026-01-01', to: '2026-12-31' } } },
      ],
      [
        'ediscovery_searches_review',
        {
          caseId,
          searchId: search.publicId,
          body: { tag: 'not_relevant', messageIds: [identity.publicId] },
        },
      ],
      ['ediscovery_exports_create', { caseId, body: { searchId: search.publicId } }],
      ['provider_connections_update', { id, body: { displayName: 'taken over', rowVersion: 1 } }],
      ['provider_connections_disconnect', { id }],
      [
        'provider_attestations_record',
        { id, body: { code: 'm365.inbound_connector_created', attested: true } },
      ],
      ['provider_domains_replace', { id, body: { domainIds: [] } }],
      ['provider_grants_revoke', { id, profile }],
      ['provider_grants_verify', { id, profile, body: {} }],
      ['provider_health_check_now', { id }],
      ['provider_mail_flow_apply', { id, body: { change: { kind: 'suspend' } } }],
      // The new single read (D8) and the side-effect-free mail-flow preview (D5).
      ['archive_admin_capture_issue', { messageId: identity.publicId }],
      ['provider_mail_flow_preview', { id, body: { change: { kind: 'suspend' } } }],
    ];
    let conversation = '';
    let turns = 0;
    for (const [tool, args] of cases) {
      if (turns++ % 5 === 0) conversation = await newConversation(ctx, adminB);
      const res = await turn(ctx, adminB.headers, conversation, directive(tool, args));
      expect(res.status, tool).toBe(200);
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
    // A itself reads its own capture issue (the 404 above is the tenant boundary, not a gap).
    const own = await waitForRead(
      ctx,
      adminA,
      `/api/v1/archive/capture-issues/${identity.publicId}`,
    );
    expect(own).toMatchObject({ messageId: identity.publicId, status: 'failed' });
    expect(await snapshot()).toEqual(before);
  }, 300_000);
});

describe('step AI-6 feedback, search, admin and audit views, report jobs and provider keys (§9 item 5)', () => {
  const COMMENT_A = 'Organization A only feedback comment';

  it('B never reads, rates, finds, audits or removes anything of organization A', async () => {
    // A: an answer with a rating and a comment, a queued background report (no consumer runs
    // in this app) and a stored provider key row.
    const textA = `/text Organization A secret ${randomUUID().slice(0, 8)}`;
    const own = await turn(ctx, adminA.headers, conversationA, textA);
    expect(own.status).toBe(200);
    const answerA = own.body.message.id as string;
    expect(
      (
        await call(ctx, adminA.headers, 'put', `${A}/messages/${answerA}/feedback`, {
          rating: 'down',
          reason: 'other',
          comment: COMMENT_A,
        })
      ).status,
    ).toBe(200);
    const reportTurn = await turn(
      ctx,
      adminA.headers,
      conversationA,
      directive('report_generate', { range: '30d', sections: ['traffic'] }),
    );
    const queued = (reportTurn.body.executions as Array<Record<string, unknown>>).find(
      (e) => e.tool === 'report_generate',
    ) as { httpStatus: number; card: { report: { reportId: string; status: string } } };
    expect(queued).toMatchObject({ httpStatus: 202, card: { report: { status: 'queued' } } });
    const reportA = queued.card.report.reportId;
    await ctx.prisma.aiChatProviderKey.create({
      data: {
        organizationId: orgA.id,
        provider: 'openai',
        model: 'claude-opus-5-5',
        keyCiphertext: 'v1.k0000000.fixture.fixture.fixture',
        keyKid: 'k0000000',
        keyFingerprint: '0123456789abcdef',
        keyVersion: 1,
        status: 'valid',
        setByUserId: adminA.user.id,
        setAt: new Date(),
      },
    });
    fx.registerCleanup(() =>
      ctx.prisma.aiChatProviderKey.deleteMany({ where: { organizationId: orgA.id } }),
    );
    const executionA = (
      await ctx.prisma.aiChatToolExecution.findFirstOrThrow({
        where: { conversation: { publicId: conversationA } },
        select: { correlationId: true },
      })
    ).correlationId;

    // Feedback on A's message: 404 for set and remove.
    for (const method of ['put', 'delete'] as const) {
      const res = await call(
        ctx,
        adminB.headers,
        method,
        `${A}/messages/${answerA}/feedback`,
        method === 'put' ? { rating: 'up' } : undefined,
      );
      expect(res.status, method).toBe(404);
      expect(res.body.code).toBe('assistant_message_not_found');
    }
    // Content search: nothing of A.
    const search = await call(
      ctx,
      adminB.headers,
      'get',
      `${A}/search?q=${encodeURIComponent(textA.slice(6))}`,
    );
    expect(search.status).toBe(200);
    expect(search.body.data).toEqual([]);
    // Admin views of B: none of A's users, ratings, conversations or executions.
    const scan = JSON.stringify;
    const usage = await call(ctx, adminB.headers, 'get', `${A}/admin/usage/users`);
    expect(usage.status).toBe(200);
    expect(scan(usage.body)).not.toContain(adminA.user.publicId);
    const usageOfA = await call(
      ctx,
      adminB.headers,
      'get',
      `${A}/admin/usage/users?userId=${adminA.user.publicId}`,
    );
    expect(usageOfA.body.data).toEqual([]);
    expect(usageOfA.body.totals.overall.turns).toBe(0);
    const feedback = await call(ctx, adminB.headers, 'get', `${A}/admin/feedback`);
    expect(feedback.status).toBe(200);
    expect(scan(feedback.body)).not.toContain(answerA);
    expect(scan(feedback.body)).not.toContain(COMMENT_A);
    const conversations = await call(ctx, adminB.headers, 'get', `${A}/admin/conversations`);
    expect(conversations.status).toBe(200);
    expect(scan(conversations.body)).not.toContain(conversationA);
    const detail = await call(
      ctx,
      adminB.headers,
      'get',
      `${A}/admin/conversations/${conversationA}`,
    );
    expect(detail.status).toBe(404);
    expect(detail.body.code).toBe('assistant_admin_conversation_not_found');
    for (const filter of [
      `conversationId=${conversationA}`,
      `correlationId=${encodeURIComponent(executionA)}`,
      `userId=${adminA.user.publicId}`,
    ]) {
      const res = await call(ctx, adminB.headers, 'get', `${A}/admin/executions?${filter}`);
      expect(res.status, filter).toBe(200);
      expect(res.body.data, filter).toEqual([]);
    }
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgB.id, action: 'assistant.audit_viewed' },
      }),
    ).toBe(0);
    // A's queued background report and its job.
    const report = await call(ctx, adminB.headers, 'get', `${REPORTS}/${reportA}`);
    expect(report.status).toBe(404);
    expect(report.body.code).toBe('assistant_report_not_found');
    // A's provider key: invisible and not removable by B.
    const settingsB = await call(ctx, adminB.headers, 'get', `${A}/settings`);
    expect(settingsB.body.tenantKey).toBeNull();
    expect(scan(settingsB.body)).not.toContain('0123456789abcdef');
    const removed = await call(
      ctx,
      adminB.headers,
      'delete',
      `${A}/settings/provider-key?expectedRowVersion=${String(settingsB.body.rowVersion)}`,
    );
    expect(removed.status).toBe(404);
    expect(removed.body.code).toBe('assistant_tenant_key_not_found');

    // Nothing of A changed.
    expect(await ctx.prisma.aiChatProviderKey.count({ where: { organizationId: orgA.id } })).toBe(
      1,
    );
    const rated = await ctx.prisma.aiChatFeedback.findFirstOrThrow({
      where: { message: { publicId: answerA } },
    });
    expect(rated).toMatchObject({ rating: 'down', comment: COMMENT_A });
    expect(
      (await call(ctx, adminA.headers, 'get', `${REPORTS}/${reportA}`)).body.report,
    ).toMatchObject({ status: 'queued', job: { status: 'queued' } });
    // A's own audit view reads its conversation (the contrast).
    expect(
      (await call(ctx, adminA.headers, 'get', `${A}/admin/conversations/${conversationA}`)).status,
    ).toBe(200);
  });
});
