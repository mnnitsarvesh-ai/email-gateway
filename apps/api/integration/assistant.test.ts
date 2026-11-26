/**
 * Step AI-1 assistant on the real stack (docs/plan/steps/28-ai-chat-management.md D5, D7, D8,
 * D11, D12, D13, §4, §9 item 4; contracts §35): the api listens on its ephemeral loopback port,
 * so every tool call of a turn goes through the real `/api/v1` pipeline with the caller's bearer;
 * MySQL writer and replica and Redis are the Compose infrastructure; the provider is the
 * deterministic fake (`assertFakeProvider`), never a real LLM, and nothing reaches the internet.
 *
 * Covered: the status reasons (platform switch through a second app with ASSISTANT_ENABLED=false,
 * feature off, tenant setting off, budget), the settings CAS, acknowledgement rule and audit row,
 * the usage route, conversations (create, title search, rename, archive, per-user privacy,
 * delete with the immediate content purge and its audit row), turns as JSON and as
 * `assistant-stream/1` (event order and headers), `clientTurnId` replay, `409` while a turn runs,
 * cancellation, stored executions and `more` pages over a list tool, the tenant token budget and
 * the per-user turn window, the retention job (abandoned-turn sweep, content purge, hard delete;
 * called directly with an explicit clock, only this suite's rows are aged), the organization
 * purge of the ai_chat_* rows and the correlation of `assistant.tool_executed` with the audited
 * operation's own audit row. Synthetic `it-*` organizations only.
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
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { assistantKeys } from '../src/modules/assistant/assistant.constants';
import { TransactionRunner } from '../src/database/transaction-runner';
import { ConversationsRepository } from '../src/modules/assistant/repositories/conversations.repository';
import { AssistantRetentionService } from '../src/modules/assistant/services/assistant-retention.service';
import { AssistantTenantDataRepository } from '../src/modules/tenant-data/assistant-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  type AssistantApp,
  call,
  clearAssistantCounters,
  createAssistantApp,
  DAY_MS,
  directive,
  ENABLED_WRITES,
  enableAssistant,
  executionsOf,
  member,
  type Member,
  newConversation,
  platformMember,
  putSettings,
  setAssistantFeature,
  streamTurn,
  turn,
} from './support/assistant';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';

const POLL = { timeout: 15_000, interval: 200 };

let app: AssistantApp;
let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let orgA: FixtureOrganization;
let adminA: Member;
let otherA: Member;
let readerA: Member;
const orgIds: bigint[] = [];

async function organization(): Promise<{ org: FixtureOrganization; role: string }> {
  const org = await fx.createOrganization();
  orgIds.push(org.id);
  return { org, role: await fx.createCustomRole(org, [...ALL_TENANT_PERMISSIONS]) };
}

beforeAll(async () => {
  app = await createAssistantApp();
  ctx = app.ctx;
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  const a = await organization();
  orgA = a.org;
  adminA = await member(ctx, fx, orgA, [a.role]);
  otherA = await member(ctx, fx, orgA, ['organization_admin']);
  readerA = await member(ctx, fx, orgA, ['read_only_user']);
  await enableAssistant(ctx, operator, orgA, adminA);
}, 120_000);

afterAll(async () => {
  if (ctx) await clearAssistantCounters(ctx, orgIds);
  await fx?.cleanup();
  await ctx?.close();
});

describe('status, settings and usage (D11, D13, §4.1)', () => {
  it('reports feature_disabled, tenant_disabled and available in gate order', async () => {
    const { org, role } = await organization();
    const admin = await member(ctx, fx, org, [role]);

    const off = await call(ctx, admin.headers, 'get', `${A}/status`);
    expect(off.status).toBe(200);
    expect(off.body).toMatchObject({
      available: false,
      reason: 'feature_disabled',
      provider: 'fake',
      model: 'fake',
    });
    const blocked = await call(ctx, admin.headers, 'post', `${A}/conversations`, {});
    expect(blocked.status).toBe(403);
    expect(blocked.body.code).toBe('assistant_not_enabled');
    const settings0 = await call(ctx, admin.headers, 'get', `${A}/settings`);
    expect(settings0.body).toMatchObject({
      version: 'assistant-settings/1',
      enabled: false,
      featureEnabled: false,
      rowVersion: 0,
      dataSharing: 'metadata',
    });
    const refused = await putSettings(ctx, admin, { enabled: true });
    expect(refused.status).toBe(403);
    expect(refused.body.code).toBe('assistant_not_enabled');

    await setAssistantFeature(ctx, operator, org, true);
    const tenantOff = await call(ctx, admin.headers, 'get', `${A}/status`);
    expect(tenantOff.body).toMatchObject({ available: false, reason: 'tenant_disabled' });
    const blocked2 = await call(ctx, admin.headers, 'post', `${A}/conversations`, {});
    expect(blocked2.status).toBe(403);
    expect(blocked2.body.code).toBe('assistant_tenant_disabled');

    const on = await putSettings(ctx, admin, { enabled: true });
    expect(on.status).toBe(200);
    const status = await call(ctx, admin.headers, 'get', `${A}/status`);
    expect(status.body).toMatchObject({
      available: true,
      provider: 'fake',
      limits: { messageMaxChars: 4000, turnsPerMinute: 120 },
      budget: { dailyTokens: 50_000_000, usedToday: 0 },
    });
    expect(status.body.reason).toBeUndefined();

    // Tenant switch off again: an existing conversation can no longer get turns.
    const conversation = await newConversation(ctx, admin);
    expect((await putSettings(ctx, admin, { enabled: false })).status).toBe(200);
    const res = await turn(ctx, admin.headers, conversation, '/text hello');
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('assistant_tenant_disabled');
  });

  it('settings: acknowledgement rule, CAS on rowVersion, budget cap, audit row, permission', async () => {
    const { org, role } = await organization();
    const admin = await member(ctx, fx, org, [role]);
    await setAssistantFeature(ctx, operator, org, true);
    const put = (body: object) => call(ctx, admin.headers, 'put', `${A}/settings`, body);
    const base = { enabled: true, dailyTokenBudget: null, retentionDays: 30 };

    const noAck = await put({
      ...base,
      expectedRowVersion: 0,
      externalProcessingAcknowledged: false,
    });
    expect(noAck.status).toBe(400);
    const overCap = await put({
      ...base,
      expectedRowVersion: 0,
      externalProcessingAcknowledged: true,
      dailyTokenBudget: 50_000_001,
    });
    expect(overCap.status).toBe(400);
    const stale = await put({
      ...base,
      expectedRowVersion: 3,
      externalProcessingAcknowledged: true,
    });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'assistant_settings_conflict', currentRowVersion: 0 });

    const ok = await put({
      ...base,
      expectedRowVersion: 0,
      externalProcessingAcknowledged: true,
      dailyTokenBudget: 200_000,
      retentionDays: 14,
    });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({
      enabled: true,
      externalProcessingAcknowledged: true,
      externalProcessingAcknowledgedBy: admin.user.publicId,
      dailyTokenBudget: 200_000,
      effectiveDailyTokenBudget: 200_000,
      retentionDays: 14,
      featureEnabled: true,
      rowVersion: 1,
    });
    expect(ok.body.externalProcessingAcknowledgedAt).toEqual(expect.any(String));
    const again = await put({
      ...base,
      expectedRowVersion: 0,
      externalProcessingAcknowledged: true,
    });
    expect(again.status).toBe(409);
    expect(again.body.currentRowVersion).toBe(1);

    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'assistant.settings_updated' },
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      actorId: admin.user.publicId,
      resourceType: 'assistant_settings',
      resourceId: org.publicId,
    });
    expect(audit[0]!.metadata).toMatchObject({
      enabled: true,
      externalProcessingAcknowledged: true,
      rowVersion: 1,
    });
    expect((audit[0]!.metadata as { changed: string[] }).changed).toEqual(
      expect.arrayContaining(['enabled', 'externalProcessingAcknowledged', 'dailyTokenBudget']),
    );
    const row = await ctx.prisma.aiChatSettings.findUniqueOrThrow({
      where: { organizationId: org.id },
    });
    expect(row).toMatchObject({ enabled: true, retentionDays: 14, dailyTokenBudget: 200_000 });
    expect(row.externalProcessingAckByUserId).toBe(admin.user.id);

    // Users without assistant:configure cannot read or change the settings or the usage.
    const reader = await member(ctx, fx, org, ['read_only_user']);
    expect((await call(ctx, reader.headers, 'get', `${A}/settings`)).status).toBe(403);
    expect((await call(ctx, reader.headers, 'get', `${A}/usage`)).status).toBe(403);
    expect((await call(ctx, reader.headers, 'get', `${A}/status`)).status).toBe(200);
  });

  it('answers 503 assistant_disabled and platform_disabled when the platform switch is off', async () => {
    const off = await createAssistantApp({ env: { ASSISTANT_ENABLED: 'false' } });
    try {
      const status = await call(off.ctx, adminA.headers, 'get', `${A}/status`);
      expect(status.status).toBe(200);
      expect(status.body).toMatchObject({ available: false, reason: 'platform_disabled' });
      const conversation = await call(off.ctx, adminA.headers, 'post', `${A}/conversations`, {});
      expect(conversation.status).toBe(503);
      expect(conversation.body.code).toBe('assistant_disabled');
    } finally {
      await off.ctx.close();
    }
    // The same organization is available on the platform with the switch on.
    const on = await call(ctx, adminA.headers, 'get', `${A}/status`);
    expect(on.body.available).toBe(true);
  });
});

describe('conversations (§4.1, D12, Q9)', () => {
  it('creates, searches by title, renames, archives and keeps them private per user', async () => {
    const tag = randomUUID().slice(0, 8);
    const first = await call(ctx, adminA.headers, 'post', `${A}/conversations`, {
      title: `Quarterly review ${tag}`,
    });
    expect(first.status).toBe(201);
    expect(first.body).toMatchObject({
      title: `Quarterly review ${tag}`,
      status: 'active',
      turnCount: 0,
      contentPurged: false,
      underPlatformOverride: false,
    });
    const id = first.body.id as string;
    const createdVersion = first.body.rowVersion as number;
    const second = await newConversation(ctx, adminA, `Mail flow ${tag}`);

    const search = await expect
      .poll(async () => {
        const res = await call(ctx, adminA.headers, 'get', `${A}/conversations?q=Quarterly`);
        return (res.body.data as Array<{ id: string }>).map((c) => c.id);
      }, POLL)
      .toContain(id);
    void search;
    const found = await call(ctx, adminA.headers, 'get', `${A}/conversations?q=Quarterly`);
    expect((found.body.data as Array<{ id: string }>).map((c) => c.id)).not.toContain(second);

    const renamed = await call(ctx, adminA.headers, 'patch', `${A}/conversations/${id}`, {
      title: `Renamed ${tag}`,
      status: 'archived',
    });
    expect(renamed.status).toBe(200);
    expect(renamed.body).toMatchObject({
      title: `Renamed ${tag}`,
      status: 'archived',
      rowVersion: createdVersion + 1,
    });
    await expect
      .poll(async () => {
        const res = await call(ctx, adminA.headers, 'get', `${A}/conversations?status=archived`);
        return (res.body.data as Array<{ id: string }>).map((c) => c.id);
      }, POLL)
      .toEqual([id]);
    const active = await call(ctx, adminA.headers, 'get', `${A}/conversations?status=active`);
    expect((active.body.data as Array<{ id: string }>).map((c) => c.id)).toContain(second);
    expect((active.body.data as Array<{ id: string }>).map((c) => c.id)).not.toContain(id);
    const bad = await call(ctx, adminA.headers, 'patch', `${A}/conversations/${id}`, {});
    expect(bad.status).toBe(400);

    // Another user of the same organization (an organization admin) sees none of it.
    for (const [method, path, body] of [
      ['get', `${A}/conversations/${id}`, undefined],
      ['patch', `${A}/conversations/${id}`, { title: 'x' }],
      ['delete', `${A}/conversations/${id}`, undefined],
      ['get', `${A}/conversations/${id}/messages`, undefined],
      ['post', `${A}/conversations/${id}/turns`, { clientTurnId: randomUUID(), message: 'hi' }],
    ] as const) {
      const res = await call(ctx, otherA.headers, method, path, body);
      expect(res.status, `${method} ${path}`).toBe(404);
      expect(res.body.code).toBe('assistant_conversation_not_found');
    }
    const theirs = await call(ctx, otherA.headers, 'get', `${A}/conversations`);
    expect(theirs.status).toBe(200);
    expect((theirs.body.data as Array<{ id: string }>).map((c) => c.id)).not.toContain(id);
  });

  it('deletes with an immediate content purge and an audit row', async () => {
    const id = await newConversation(ctx, adminA, 'To be cleared');
    const res = await turn(ctx, adminA.headers, id, directive('policy_management_list'));
    expect(res.status).toBe(200);

    const del = await call(ctx, adminA.headers, 'delete', `${A}/conversations/${id}`);
    expect(del.status).toBe(204);
    const row = await ctx.prisma.aiChatConversation.findUniqueOrThrow({ where: { publicId: id } });
    expect(row).toMatchObject({ status: 'deleted', title: null });
    expect(row.contentPurgedAt).not.toBeNull();
    const messages = await ctx.prisma.aiChatMessage.findMany({ where: { conversationId: row.id } });
    expect(messages).toHaveLength(2);
    expect(messages.every((m) => m.content === null)).toBe(true);
    const turns = await ctx.prisma.aiChatTurn.findMany({ where: { conversationId: row.id } });
    expect(turns.every((t) => t.providerTranscript === null)).toBe(true);
    const executions = await executionsOf(ctx, id);
    expect(executions).toHaveLength(1);
    expect(executions[0]).toMatchObject({ resultCard: null, resultRefs: null, nextCursor: null });
    expect(executions[0]!.decision).toBe('allowed');
    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, action: 'assistant.conversation_deleted', resourceId: id },
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      actorId: adminA.user.publicId,
      resourceType: 'assistant_conversation',
    });
    expect(audit[0]!.metadata).toMatchObject({ turnCount: 1, contentPurged: true });

    expect((await call(ctx, adminA.headers, 'get', `${A}/conversations/${id}`)).status).toBe(404);
    expect((await call(ctx, adminA.headers, 'delete', `${A}/conversations/${id}`)).status).toBe(
      404,
    );
  });
});

describe('turns (D7, §4.2)', () => {
  it('answers a JSON turn with the tool execution, card and template text', async () => {
    const id = await newConversation(ctx, adminA);
    const message = directive('policy_management_list');
    const res = await turn(ctx, adminA.headers, id, message, { timeZone: 'Asia/Kolkata' });
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body.turn).toMatchObject({
      conversationId: id,
      seq: 1,
      status: 'completed',
      errorCode: null,
      provider: 'fake',
      model: 'fake',
      responseModel: 'fake',
      rounds: 2,
      toolCalls: 1,
    });
    expect(res.body.turn.usage.inputTokens).toBeGreaterThan(0);
    expect(res.body.message.content).toMatch(/^Found \d+ records?\.( More are available\.)?$/);
    expect(res.body.executions).toHaveLength(1);
    const execution = res.body.executions[0];
    expect(execution).toMatchObject({
      conversationId: id,
      turnId: res.body.turn.id,
      seq: 1,
      ref: 'r1',
      tool: 'policy_management_list',
      operationId: 'PolicyManagementController_list_v1',
      access: 'read',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 200,
      errorCode: null,
    });
    expect(execution.card).toMatchObject({
      version: 'assistant-card/1',
      executionId: execution.id,
      kind: 'table',
      status: 'ok',
    });

    // The first user message titles an untitled conversation.
    const conversation = await call(ctx, adminA.headers, 'get', `${A}/conversations/${id}`);
    expect(conversation.body).toMatchObject({ title: message.slice(0, 80), turnCount: 1 });
    expect(conversation.body.purgeAfter).toEqual(expect.any(String));

    const stored = await call(ctx, adminA.headers, 'get', `${A}/executions/${execution.id}`);
    expect(stored.status).toBe(200);
    expect(stored.body).toMatchObject({ id: execution.id, decision: 'allowed', hasMore: false });
    expect(stored.body.card).toEqual(execution.card);

    const page = await expect
      .poll(async () => {
        const r = await call(ctx, adminA.headers, 'get', `${A}/conversations/${id}/messages`);
        return (r.body.data as unknown[] | undefined)?.length;
      }, POLL)
      .toBe(2);
    void page;
    const messages = await call(ctx, adminA.headers, 'get', `${A}/conversations/${id}/messages`);
    expect(messages.body.data.map((m: { role: string }) => m.role)).toEqual(['user', 'assistant']);
    expect(messages.body.data[0]).toMatchObject({ content: message, executions: [] });
    expect(messages.body.data[1].executions.map((e: { id: string }) => e.id)).toEqual([
      execution.id,
    ]);
    expect(messages.body.nextCursor).toBeNull();

    // Validation: blank message 400, over ASSISTANT_USER_MESSAGE_MAX_CHARS 413.
    expect((await turn(ctx, adminA.headers, id, '   ')).status).toBe(400);
    const long = await turn(ctx, adminA.headers, id, 'x'.repeat(4001));
    expect(long.status).toBe(413);
    expect(long.body).toMatchObject({ code: 'payload_too_large', limit: 4000 });
  });

  it('streams assistant-stream/1 in order with the stream headers', async () => {
    const id = await newConversation(ctx, adminA);
    const { res, events } = await streamTurn(
      ctx,
      adminA.headers,
      id,
      directive('policy_management_list'),
    );
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/^text\/event-stream/);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-accel-buffering']).toBe('no');
    const names = events.map(([name]) => name);
    expect(names[0]).toBe('turn.started');
    expect(names.slice(1, 3)).toEqual(['tool.started', 'tool.completed']);
    expect(names.at(-1)).toBe('turn.completed');
    const middle = names.slice(3, -1);
    expect(middle.length).toBeGreaterThan(0);
    expect(middle.every((n) => n === 'text.delta')).toBe(true);
    const started = events[0]![1];
    expect(started).toMatchObject({ conversationId: id, seq: 1 });
    expect(events[1]![1]).toMatchObject({ tool: 'policy_management_list' });
    expect(events[2]![1]).toMatchObject({
      executionId: events[1]![1].executionId,
      status: 'succeeded',
      decision: 'allowed',
    });
    expect((events[2]![1].card as { executionId: string }).executionId).toBe(
      events[1]![1].executionId,
    );
    const text = events
      .filter(([n]) => n === 'text.delta')
      .map(([, d]) => d.text as string)
      .join('');
    const completed = events.at(-1)![1];
    expect(completed).toMatchObject({ turnId: started.turnId, status: 'completed' });
    const stored = await ctx.prisma.aiChatMessage.findUniqueOrThrow({
      where: { publicId: completed.messageId as string },
    });
    expect(stored).toMatchObject({ role: 'assistant', content: text });

    // A refused tool streams tool.denied (a platform tool for a customer user).
    const denied = await streamTurn(ctx, adminA.headers, id, directive('dead_letters_stats'));
    expect(denied.events.map(([n]) => n).slice(0, 3)).toEqual([
      'turn.started',
      'tool.started',
      'tool.denied',
    ]);
    expect(denied.events[2]![1]).toMatchObject({
      tool: 'dead_letters_stats',
      decision: 'denied_permission',
    });
    expect(denied.events.at(-1)![0]).toBe('turn.completed');
  });

  it('replays a finished clientTurnId (JSON and stream) without a new turn', async () => {
    const id = await newConversation(ctx, adminA);
    const clientTurnId = randomUUID();
    const first = await turn(ctx, adminA.headers, id, directive('policy_management_list'), {
      clientTurnId,
    });
    expect(first.status).toBe(200);
    const again = await turn(ctx, adminA.headers, id, directive('policy_management_list'), {
      clientTurnId,
    });
    expect(again.status).toBe(200);
    expect(again.body).toEqual(first.body);
    const streamed = await streamTurn(ctx, adminA.headers, id, 'ignored', { clientTurnId });
    expect(streamed.events.map(([n]) => n)).toEqual([
      'turn.started',
      'tool.started',
      'tool.completed',
      'text.delta',
      'turn.completed',
    ]);
    expect(streamed.events[0]![1].turnId).toBe(first.body.turn.id);
    const conversation = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: id },
      select: { id: true, turnCount: true },
    });
    expect(conversation.turnCount).toBe(1);
    expect(await ctx.prisma.aiChatTurn.count({ where: { conversationId: conversation.id } })).toBe(
      1,
    );
  });

  it('answers 409 while a turn runs, cancels it and releases the lock', async () => {
    const id = await newConversation(ctx, adminA);
    const clientTurnId = randomUUID();
    const held = turn(ctx, adminA.headers, id, '/hold', { clientTurnId }).then((r) => r);
    await expect.poll(() => app.provider.holding, POLL).toBe(1);
    const running = await ctx.prisma.aiChatTurn.findFirstOrThrow({
      where: { clientTurnId, conversation: { publicId: id } },
    });
    expect(running.status).toBe('running');
    expect(await ctx.kv.get(assistantKeys.turnLock(id))).toBe(running.publicId);

    const busy = await turn(ctx, adminA.headers, id, '/text other');
    expect(busy.status).toBe(409);
    expect(busy.body.code).toBe('assistant_turn_in_progress');
    expect(Number(busy.headers['retry-after'])).toBeGreaterThan(0);
    const retried = await turn(ctx, adminA.headers, id, '/hold', { clientTurnId });
    expect(retried.status).toBe(409);
    expect(retried.body.code).toBe('assistant_turn_in_progress');
    // Another user cannot cancel it.
    const foreign = await call(
      ctx,
      otherA.headers,
      'post',
      `${A}/turns/${running.publicId}/cancel`,
    );
    expect(foreign.status).toBe(404);
    expect(foreign.body.code).toBe('assistant_turn_not_found');

    const cancel = await call(ctx, adminA.headers, 'post', `${A}/turns/${running.publicId}/cancel`);
    expect(cancel.status).toBe(202);
    expect(cancel.body).toEqual({ turnId: running.publicId, status: 'running' });
    const done = await held;
    expect(done.status).toBe(200);
    expect(done.body.turn).toMatchObject({ id: running.publicId, status: 'cancelled' });
    const again = await call(ctx, adminA.headers, 'post', `${A}/turns/${running.publicId}/cancel`);
    expect(again.body).toEqual({ turnId: running.publicId, status: 'cancelled' });
    expect(await ctx.kv.get(assistantKeys.turnLock(id))).toBeNull();

    const next = await turn(ctx, adminA.headers, id, '/text after');
    expect(next.status).toBe(200);
    expect(next.body.turn).toMatchObject({ seq: 2, status: 'completed' });
    expect(next.body.message.content).toBe('after');
  });
});

describe('executions and more pages (§4.1, D8)', () => {
  it('pages a list tool through POST …/more until the last page', async () => {
    const { org, role } = await organization();
    const admin = await member(ctx, fx, org, [role]);
    await enableAssistant(ctx, operator, org, admin);
    for (let i = 0; i < 4; i += 1) await fx.createUser(org, { roles: ['read_only_user'] });
    const total = await ctx.prisma.user.count({ where: { organizationId: org.id } });
    expect(total).toBe(5);

    const id = await newConversation(ctx, admin);
    // The users list reads the replica: wait until it serves every user.
    await expect
      .poll(async () => {
        const res = await call(ctx, admin.headers, 'get', '/api/v1/users?limit=100');
        return (res.body.data as unknown[] | undefined)?.length;
      }, POLL)
      .toBe(total);
    const res = await turn(ctx, admin.headers, id, directive('users_list', { limit: 2 }));
    expect(res.status).toBe(200);
    let execution = res.body.executions[0];
    expect(execution).toMatchObject({ tool: 'users_list', decision: 'allowed', hasMore: true });
    expect(execution.card).toMatchObject({ kind: 'table', nextCursor: true });
    expect(res.body.message.content).toBe('Found 2 records. More are available.');
    const rows: unknown[] = [...execution.card.rows];
    const chain = [execution.id as string];
    while (execution.hasMore) {
      const more = await call(ctx, admin.headers, 'post', `${A}/executions/${execution.id}/more`);
      expect(more.status).toBe(200);
      expect(more.body).toMatchObject({
        conversationId: id,
        turnId: null,
        parentExecutionId: execution.id,
        tool: 'users_list',
        decision: 'allowed',
        status: 'succeeded',
        httpStatus: 200,
      });
      expect(more.body.seq).toBe(execution.seq + 1);
      execution = more.body;
      chain.push(execution.id as string);
      rows.push(...execution.card.rows);
    }
    expect(rows).toHaveLength(total);
    expect(chain).toHaveLength(3);
    const last = await call(ctx, admin.headers, 'post', `${A}/executions/${execution.id}/more`);
    expect(last.status).toBe(409);
    expect(last.body.code).toBe('assistant_no_more_results');

    const stored = await call(ctx, admin.headers, 'get', `${A}/executions/${chain[1]}`);
    expect(stored.body).toMatchObject({ parentExecutionId: chain[0], turnId: null });
    // The "more" pages are listed with their turn's assistant message, and audited.
    await expect
      .poll(async () => {
        const r = await call(ctx, admin.headers, 'get', `${A}/conversations/${id}/messages`);
        const assistant = (r.body.data as Array<{ role: string; executions: unknown[] }>)?.find(
          (m) => m.role === 'assistant',
        );
        return assistant?.executions.length;
      }, POLL)
      .toBe(3);
    const audited = await ctx.prisma.auditLog.count({
      where: {
        organizationId: org.id,
        action: 'assistant.tool_executed',
        resourceId: { in: chain },
      },
    });
    expect(audited).toBe(3);
    const unknown = await call(ctx, admin.headers, 'get', `${A}/executions/${randomUUID()}`);
    expect(unknown.status).toBe(404);
    expect(unknown.body.code).toBe('assistant_execution_not_found');
  });

  it('records the execution correlation id on the audited operation’s own audit row', async () => {
    const id = await newConversation(ctx, adminA);
    const res = await turn(ctx, adminA.headers, id, directive('audit_logs_search'));
    expect(res.status).toBe(200);
    const execution = res.body.executions[0];
    expect(execution).toMatchObject({ tool: 'audit_logs_search', status: 'succeeded' });
    const row = await ctx.prisma.aiChatToolExecution.findUniqueOrThrow({
      where: { publicId: execution.id },
    });
    expect(row.correlationId).toMatch(/^[A-Za-z0-9._:-]{8,128}$/);
    expect(row.correlationId.endsWith(`.${row.seq}`)).toBe(true);
    const executed = await ctx.prisma.auditLog.findMany({
      where: {
        organizationId: orgA.id,
        action: 'assistant.tool_executed',
        resourceId: execution.id,
      },
    });
    expect(executed).toHaveLength(1);
    expect(executed[0]).toMatchObject({
      actorId: adminA.user.publicId,
      resourceType: 'assistant_tool_execution',
    });
    expect(executed[0]!.metadata).toMatchObject({
      conversationId: id,
      turnId: res.body.turn.id,
      tool: 'audit_logs_search',
      operationId: 'AuditLogsController_search_v1',
      access: 'read',
      risk: 'read_audited',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 200,
      correlationId: row.correlationId,
    });
    // The operation's own audit row carries the x-correlation-id the loopback sent.
    const searched = await ctx.prisma.auditLog.findMany({
      where: {
        organizationId: orgA.id,
        action: 'audit.searched',
        correlationId: row.correlationId,
      },
    });
    expect(searched).toHaveLength(1);
    expect(searched[0]!.actorId).toBe(adminA.user.publicId);
  });
});

describe('budgets and limits (D11)', () => {
  it('refuses turns with 429 assistant_budget_exhausted (tenant) once the daily budget is used', async () => {
    const { org, role } = await organization();
    const admin = await member(ctx, fx, org, [role]);
    await enableAssistant(ctx, operator, org, admin, { dailyTokenBudget: 1 });
    const id = await newConversation(ctx, admin);
    const first = await turn(ctx, admin.headers, id, '/text one');
    expect(first.status).toBe(200);
    const refused = await turn(ctx, admin.headers, id, '/text two');
    expect(refused.status).toBe(429);
    expect(refused.body).toMatchObject({ code: 'assistant_budget_exhausted', scope: 'tenant' });
    expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
    const status = await call(ctx, admin.headers, 'get', `${A}/status`);
    expect(status.body).toMatchObject({ available: false, reason: 'budget_exhausted' });
    expect(status.body.budget.dailyTokens).toBe(1);
    expect(status.body.budget.usedToday).toBeGreaterThan(1);
  });

  it('refuses turns beyond the per-user window with 429 rate_limited', async () => {
    const user = await member(ctx, fx, orgA, ['security_analyst']);
    const id = await newConversation(ctx, user);
    const minute = Math.floor(Date.now() / 60_000);
    const keys = [minute, minute + 1].map((m) => assistantKeys.userWindow(user.user.publicId, m));
    for (const key of keys) await ctx.kv.set(key, '120', 120);
    try {
      const res = await turn(ctx, user.headers, id, '/text hi');
      expect(res.status).toBe(429);
      expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
      expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    } finally {
      for (const key of keys) await ctx.kv.del(key);
    }
    expect((await turn(ctx, user.headers, id, '/text hi')).status).toBe(200);
  });

  it('reports usage per day and model (assistant:configure)', async () => {
    const id = await newConversation(ctx, adminA);
    expect((await turn(ctx, adminA.headers, id, '/text usage')).status).toBe(200);
    const today = new Date().toISOString().slice(0, 10);
    const usage = await call(ctx, adminA.headers, 'get', `${A}/usage`);
    expect(usage.status).toBe(200);
    expect(usage.body.to).toBe(today);
    const row = (usage.body.rows as Array<Record<string, unknown>>).find(
      (r) => r.day === today && r.provider === 'fake' && r.model === 'fake',
    );
    expect(row).toBeDefined();
    expect(row!.turns as number).toBeGreaterThanOrEqual(1);
    expect(row!.inputTokens as number).toBeGreaterThan(0);
    expect(usage.body.totals.turns).toBeGreaterThanOrEqual(row!.turns as number);
    const db = await ctx.prisma.aiChatUsageDaily.findMany({ where: { organizationId: orgA.id } });
    expect(db.reduce((n, r) => n + r.turns, 0)).toBe(usage.body.totals.turns);
    const tooLong = await call(
      ctx,
      adminA.headers,
      'get',
      `${A}/usage?from=2026-01-01&to=2026-11-20`,
    );
    expect(tooLong.status).toBe(400);
  });
});

describe('retention and organization purge (D7, D12, ADR-0094)', () => {
  it('sweeps abandoned turns, purges due content and hard-deletes old rows', async () => {
    const now = new Date();
    // Abandoned: a turn left `running` long past its deadline, holding the conversation lock.
    const abandonedConversation = await newConversation(ctx, adminA);
    const t1 = await turn(ctx, adminA.headers, abandonedConversation, '/text crash');
    const abandoned = t1.body.turn.id as string;
    await ctx.prisma.aiChatTurn.update({
      where: { publicId: abandoned },
      data: {
        status: 'running',
        finishedAt: null,
        startedAt: new Date(now.getTime() - 3 * 3600_000),
      },
    });
    await ctx.kv.set(assistantKeys.turnLock(abandonedConversation), abandoned, 600);
    // Content due: purge_after in the past.
    const due = await newConversation(ctx, adminA, 'Due for purge');
    await turn(ctx, adminA.headers, due, directive('policy_management_list'));
    await ctx.prisma.aiChatConversation.update({
      where: { publicId: due },
      data: { purgeAfter: new Date(now.getTime() - 60_000) },
    });
    // Old: every row older than ASSISTANT_EXECUTION_RETENTION_DAYS (400).
    const old = await newConversation(ctx, adminA, 'Old');
    await turn(ctx, adminA.headers, old, directive('policy_management_list'));
    const oldRow = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: old },
    });
    const longAgo = new Date(now.getTime() - 401 * DAY_MS);
    await ctx.prisma.aiChatToolExecution.updateMany({
      where: { conversationId: oldRow.id },
      data: { createdAt: longAgo },
    });
    await ctx.prisma.aiChatMessage.updateMany({
      where: { conversationId: oldRow.id },
      data: { createdAt: longAgo },
    });
    await ctx.prisma.aiChatTurn.updateMany({
      where: { conversationId: oldRow.id },
      data: { startedAt: longAgo, finishedAt: longAgo },
    });
    await ctx.prisma.aiChatConversation.update({
      where: { id: oldRow.id },
      data: { createdAt: longAgo, lastTurnAt: longAgo, purgeAfter: longAgo },
    });
    const oldDay = new Date(Date.UTC(2025, 0, 1));
    await ctx.prisma.aiChatUsageDaily.create({
      data: { organizationId: orgA.id, day: oldDay, provider: 'fake', model: 'fake', turns: 1 },
    });

    const retention = ctx.get(AssistantRetentionService);
    expect(retention.scheduled).toBe(false);
    // Another api replica (the Compose api, whose background jobs run even with the assistant
    // off) may hold `as:jobs:lock`: it keeps the lock for 9 of every 10 minutes after its run as
    // the once-per-interval marker. Set that marker aside for this run and put it back with its
    // remaining TTL afterwards, so the other replica's schedule is unchanged.
    const foreignLock = await ctx.kv.get(assistantKeys.jobsLock);
    const foreignTtl = foreignLock === null ? -2 : await ctx.kv.ttl(assistantKeys.jobsLock);
    if (foreignLock !== null) await ctx.kv.del(assistantKeys.jobsLock);
    const result = await retention.runOnce(now);
    try {
      expect(result).not.toBeNull();
      expect(result!.abandoned).toBeGreaterThanOrEqual(1);
      expect(result!.contentPurged).toBeGreaterThanOrEqual(1);
      expect(result!.executions).toBeGreaterThanOrEqual(1);
      expect(result!.messages).toBeGreaterThanOrEqual(2);
      expect(result!.turns).toBeGreaterThanOrEqual(1);
      expect(result!.conversations).toBeGreaterThanOrEqual(1);
      expect(result!.usage).toBeGreaterThanOrEqual(1);
    } finally {
      // The job lock (`as:jobs:lock`, 9 minutes) is this run's: free it for later runs.
      if ((await ctx.kv.get(assistantKeys.jobsLock)) === now.toISOString()) {
        await ctx.kv.del(assistantKeys.jobsLock);
      }
      if (foreignLock !== null && foreignTtl > 0) {
        await ctx.kv.setIfAbsent(assistantKeys.jobsLock, foreignLock, foreignTtl);
      }
    }

    const swept = await ctx.prisma.aiChatTurn.findUniqueOrThrow({ where: { publicId: abandoned } });
    expect(swept).toMatchObject({ status: 'failed', errorCode: 'assistant_turn_abandoned' });
    expect(await ctx.kv.get(assistantKeys.turnLock(abandonedConversation))).toBeNull();
    const after = await turn(ctx, adminA.headers, abandonedConversation, '/text again');
    expect(after.status).toBe(200);

    const purged = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: due },
    });
    expect(purged).toMatchObject({ status: 'active', title: null });
    expect(purged.contentPurgedAt).not.toBeNull();
    const purgedMessages = await ctx.prisma.aiChatMessage.findMany({
      where: { conversationId: purged.id },
    });
    expect(purgedMessages.length).toBe(2);
    expect(purgedMessages.every((m) => m.content === null)).toBe(true);
    const purgedExecutions = await executionsOf(ctx, due);
    expect(purgedExecutions.every((e) => e.resultCard === null && e.decision === 'allowed')).toBe(
      true,
    );
    const view = await call(ctx, adminA.headers, 'get', `${A}/conversations/${due}`);
    expect(view.body).toMatchObject({ contentPurged: true, title: null });

    expect(await ctx.prisma.aiChatConversation.count({ where: { id: oldRow.id } })).toBe(0);
    expect(await ctx.prisma.aiChatTurn.count({ where: { conversationId: oldRow.id } })).toBe(0);
    expect(
      await ctx.prisma.aiChatUsageDaily.count({ where: { organizationId: orgA.id, day: oldDay } }),
    ).toBe(0);
  });

  it('purges a conversation again after it is used past a purge; a lowered retention reschedules', async () => {
    const { org, role } = await organization();
    const admin = await member(ctx, fx, org, [role]);
    await enableAssistant(ctx, operator, org, admin, { retentionDays: 30 });
    const repo = ctx.get(ConversationsRepository);
    const runner = ctx.get(TransactionRunner);
    // Scoped to this test's organization (the global job would also see other tenants' rows).
    const purgeDue = (at: Date, ids: bigint[]) =>
      runner.run(async (tx) => {
        const still = await repo.lockDueForContentPurge(org.id, ids, at, tx);
        await repo.purgeContent(org.id, still, at, tx);
        return still;
      });
    const contents = async (conversationId: bigint) =>
      (
        await ctx.prisma.aiChatMessage.findMany({
          where: { conversationId },
          orderBy: { seq: 'asc' },
        })
      ).map((m) => m.content);

    const reused = await newConversation(ctx, admin, 'Reused');
    expect((await turn(ctx, admin.headers, reused, '/text first')).status).toBe(200);
    const row = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: reused },
    });
    await ctx.prisma.aiChatConversation.update({
      where: { id: row.id },
      data: { purgeAfter: new Date(Date.now() - 60_000) },
    });
    expect(await purgeDue(new Date(), [row.id])).toEqual([row.id]);
    expect((await contents(row.id)).every((c) => c === null)).toBe(true);

    // Used again: new content, a fresh window, due for the purge again.
    expect((await turn(ctx, admin.headers, reused, '/text second')).status).toBe(200);
    const again = await ctx.prisma.aiChatConversation.findUniqueOrThrow({ where: { id: row.id } });
    expect(again.contentPurgedAt).toBeNull();
    expect(again.purgeAfter!.getTime()).toBeGreaterThan(Date.now() + 29 * DAY_MS);
    expect((await contents(row.id)).filter((c) => c !== null)).toHaveLength(2);
    expect(await purgeDue(new Date(), [row.id])).toEqual([]);
    expect(await purgeDue(new Date(Date.now() + 31 * DAY_MS), [row.id])).toEqual([row.id]);
    expect((await contents(row.id)).every((c) => c === null)).toBe(true);
    const turns = await ctx.prisma.aiChatTurn.findMany({ where: { conversationId: row.id } });
    expect(turns.every((t) => t.providerTranscript === null)).toBe(true);

    // A lowered retention moves existing purge dates earlier (never later when raised).
    const kept = await newConversation(ctx, admin, 'Kept');
    expect((await turn(ctx, admin.headers, kept, '/text keep')).status).toBe(200);
    const keptRow = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: kept },
    });
    const lastTurnAt = new Date(Date.now() - 3 * DAY_MS);
    await ctx.prisma.aiChatConversation.update({
      where: { id: keptRow.id },
      data: { lastTurnAt, purgeAfter: new Date(lastTurnAt.getTime() + 30 * DAY_MS) },
    });
    expect((await putSettings(ctx, admin, { retentionDays: 2 })).status).toBe(200);
    const shortened = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { id: keptRow.id },
    });
    expect(shortened.purgeAfter).toEqual(new Date(lastTurnAt.getTime() + 2 * DAY_MS));
    expect((await putSettings(ctx, admin, { retentionDays: 90 })).status).toBe(200);
    const unchanged = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { id: keptRow.id },
    });
    expect(unchanged.purgeAfter).toEqual(shortened.purgeAfter);
    expect(await purgeDue(new Date(), [keptRow.id])).toEqual([keptRow.id]);
  });

  it('purges every ai_chat_* row of an organization through the organization purge', async () => {
    const { org, role } = await organization();
    const admin = await member(ctx, fx, org, [role]);
    await enableAssistant(ctx, operator, org, admin);
    const id = await newConversation(ctx, admin);
    expect((await turn(ctx, admin.headers, id, directive('policy_management_list'))).status).toBe(
      200,
    );
    expect((await turn(ctx, admin.headers, id, directive('dead_letters_stats'))).status).toBe(200);
    const before = await ctx.prisma.aiChatToolExecution.count({
      where: { organizationId: orgA.id },
    });

    const repo = ctx.get(AssistantTenantDataRepository);
    const counts = await repo.purgeOrganization(systemScope(org.id), 1);
    expect(counts).toEqual({
      // Step AI-R: report deliveries and reports (with their objects) go first (none here).
      ai_chat_report_deliveries: 0,
      // Step AI-6: report jobs before reports, feedback and pseudonyms before messages (none
      // here), the per-user usage row of the two turns, no tenant key.
      ai_chat_report_jobs: 0,
      ai_chat_reports: 0,
      reportObjects: 0,
      ai_chat_feedback: 0,
      ai_chat_pseudonyms: 0,
      // Step AI-2: confirmations go first (none here: both tools are reads).
      ai_chat_action_confirmations: 0,
      ai_chat_tool_executions: 2,
      ai_chat_messages: 4,
      ai_chat_turns: 2,
      ai_chat_conversations: 1,
      ai_chat_usage_daily: 1,
      ai_chat_usage_user_daily: 1,
      ai_chat_provider_keys: 0,
      ai_chat_settings: 1,
    });
    const where = { where: { organizationId: org.id } };
    expect(await ctx.prisma.aiChatToolExecution.count(where)).toBe(0);
    expect(await ctx.prisma.aiChatMessage.count(where)).toBe(0);
    expect(await ctx.prisma.aiChatTurn.count(where)).toBe(0);
    expect(await ctx.prisma.aiChatConversation.count(where)).toBe(0);
    expect(await ctx.prisma.aiChatUsageDaily.count(where)).toBe(0);
    expect(await ctx.prisma.aiChatUsageUserDaily.count(where)).toBe(0);
    expect(await ctx.prisma.aiChatSettings.count(where)).toBe(0);
    // Another organization's rows stay; the tool audit rows stay (append-only).
    expect(await ctx.prisma.aiChatToolExecution.count({ where: { organizationId: orgA.id } })).toBe(
      before,
    );
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: org.id, action: { startsWith: 'assistant.tool_' } },
      }),
    ).toBe(2);
    expect(
      Object.values(await repo.purgeOrganization(systemScope(org.id))).every((n) => n === 0),
    ).toBe(true);
  });
});

describe('tools catalogue (D3, D5)', () => {
  it('lists only the caller’s enabled tools', async () => {
    const admin = await call(ctx, adminA.headers, 'get', `${A}/tools`);
    expect(admin.status).toBe(200);
    expect(admin.body.registryVersion).toMatch(/^[0-9a-f]{16}$/);
    const adminNames = (admin.body.tools as Array<{ name: string }>).map((t) => t.name);
    expect(adminNames).toContain('policy_management_list');
    expect(adminNames).not.toContain('dead_letters_stats');
    // Step AI-2: the confirmable writes are offered too (each runs only after a confirmation).
    const writes = (admin.body.tools as Array<{ name: string; access: string }>).filter(
      (t) => t.access === 'write',
    );
    expect(writes.map((t) => t.name)).toContain('policy_management_create');
    // Step AI-3: the platform-only organization writes are not offered to a customer user.
    expect(writes.length).toBe(ENABLED_WRITES.filter((t) => !t.platformOnly).length);
    expect(writes.map((t) => t.name)).not.toContain('organization_configuration_override_feature');
    expect(
      (admin.body.tools as Array<{ access: string }>).every(
        (t) => t.access === 'read' || t.access === 'write',
      ),
    ).toBe(true);
    const reader = await call(ctx, readerA.headers, 'get', `${A}/tools`);
    const readerNames = (reader.body.tools as Array<{ name: string }>).map((t) => t.name);
    expect(readerNames.length).toBeLessThan(adminNames.length);
    expect(readerNames).not.toContain('users_list_sessions');
  });
});
