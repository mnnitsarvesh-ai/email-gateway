/**
 * The step AI-1 assistant routes (docs/plan/steps/28-ai-chat-management.md §4.1, §4.2, §9 item 3)
 * over HTTP with MySQL, Redis and S3 stubbed: the assistant tables through `AssistantWorld`, the
 * deterministic fake LLM provider, and a fake loopback dispatcher in place of the api's own
 * pipeline (the real loopback runs in integration/assistant.test.ts). For every operation:
 * success, 403 without its permission, 403 `user_required` for API keys, coded errors; then a
 * turn as JSON and as `assistant-stream/1`, replay of a `clientTurnId`, cancellation, "more"
 * pages and the availability gates. Synthetic data only.
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
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ASSISTANT_EXAMPLES } from '../src/modules/assistant/dto/assistant.schemas';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import {
  AssistantWorld,
  FakeLoopback,
  overrideAssistant,
  policyPage,
  RecordingAssistantAudit,
} from './support/assistant-fixtures';

const ORG = 7001n;
const USE = 'assistant:use';
const CONFIGURE = 'assistant:configure';
const ALL = [USE, CONFIGURE, 'policy:read'];
const BASE = '/api/v1/assistant';

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

/** `assistant-stream/1` text → `[event, data]` pairs (heartbeat comments dropped). */
function parseStream(text: string): Array<[string, Record<string, unknown>]> {
  return text
    .split('\n\n')
    .filter((block) => block.startsWith('event: '))
    .map((block): [string, Record<string, unknown>] => {
      const [eventLine, dataLine] = block.split('\n') as [string, string];
      const data = JSON.parse(dataLine.slice('data: '.length)) as Record<string, unknown>;
      return [eventLine.slice('event: '.length), data];
    });
}

describe('assistant routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new AssistantWorld();
  const audit = new RecordingAssistantAudit();
  const loopback = new FakeLoopback();

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { ASSISTANT_ENABLED: 'true', ASSISTANT_PROVIDER: 'fake' },
      { override: (b) => overrideAssistant(b, world, audit, loopback) },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    loopback.reset();
    loopback.on('GET /api/v1/policies', () => policyPage(2, 'next-page-1'));
    api.kv.entries.clear();
    api.principals.organizationId = ORG;
    api.principals.apiKeyWith([USE, CONFIGURE]);
    world.enable(ORG);
  });

  const as = (permissions: string[] = ALL) =>
    api.principals.user(permissions, { mfaAuthenticated: true }).bearer();
  const send = async (method: Method, path: string, body?: object, permissions: string[] = ALL) => {
    const req = api
      .http()
      [method](path)
      .set(await as(permissions));
    return body === undefined ? req : req.send(body);
  };
  const newConversation = async (title?: string): Promise<string> => {
    const res = await send('post', `${BASE}/conversations`, title ? { title } : {});
    expect(res.status).toBe(201);
    return (res.body as { id: string }).id;
  };
  const ask = async (conversationId: string, message: string, clientTurnId = randomUUID()) =>
    send('post', `${BASE}/conversations/${conversationId}/turns`, { clientTurnId, message });

  it('every route refuses API keys (403 user_required) and callers without the permission (403)', async () => {
    const id = await newConversation();
    const routes: Array<[Method, string, string, object?]> = [
      ['get', `${BASE}/status`, USE],
      ['get', `${BASE}/settings`, CONFIGURE],
      ['put', `${BASE}/settings`, CONFIGURE, ASSISTANT_EXAMPLES.settingsUpdate],
      ['get', `${BASE}/usage`, CONFIGURE],
      ['get', `${BASE}/tools`, USE],
      ['get', `${BASE}/conversations`, USE],
      ['post', `${BASE}/conversations`, USE, {}],
      ['get', `${BASE}/conversations/${id}`, USE],
      ['patch', `${BASE}/conversations/${id}`, USE, { title: 'x' }],
      ['delete', `${BASE}/conversations/${id}`, USE],
      ['get', `${BASE}/conversations/${id}/messages`, USE],
      [
        'post',
        `${BASE}/conversations/${id}/turns`,
        USE,
        { clientTurnId: randomUUID(), message: 'x' },
      ],
      ['post', `${BASE}/turns/${randomUUID()}/cancel`, USE],
      ['get', `${BASE}/executions/${randomUUID()}`, USE],
      ['post', `${BASE}/executions/${randomUUID()}/more`, USE],
    ];
    for (const [method, path, permission, body] of routes) {
      const key = api.http()[method](path).set(api.principals.apiKeyHeaders);
      const viaKey = body ? await key.send(body) : await key;
      expect(viaKey.status, `${method} ${path} api key`).toBe(403);
      expect(viaKey.body.code, `${method} ${path} api key`).toBe('user_required');
      const others = ALL.filter((p) => p !== permission);
      const res = await send(method, path, body, others);
      expect(res.status, `${method} ${path} without ${permission}`).toBe(403);
      expect(res.body.code).toBe('forbidden');
    }
  });

  it('GET /status reports availability and its reasons', async () => {
    const ok = await send('get', `${BASE}/status`);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ available: true, provider: 'fake', model: 'fake' });
    world.settings.get(ORG)!.enabled = false;
    const off = await send('get', `${BASE}/status`);
    expect(off.body).toMatchObject({ available: false, reason: 'tenant_disabled' });
  });

  it('GET/PUT /settings: CAS, acknowledgement, feature; audited', async () => {
    world.settings.clear();
    const read = await send('get', `${BASE}/settings`);
    expect(read.status).toBe(200);
    expect(read.body).toMatchObject({ rowVersion: 0, enabled: false, featureEnabled: true });
    const noAck = await send('put', `${BASE}/settings`, {
      ...ASSISTANT_EXAMPLES.settingsUpdate,
      externalProcessingAcknowledged: false,
    });
    expect(noAck.status).toBe(400);
    expect(noAck.body.code).toBe('validation_failed');
    const saved = await send('put', `${BASE}/settings`, ASSISTANT_EXAMPLES.settingsUpdate);
    expect(saved.status).toBe(200);
    expect(saved.body).toMatchObject({ enabled: true, rowVersion: 1, dailyTokenBudget: 500000 });
    const stale = await send('put', `${BASE}/settings`, ASSISTANT_EXAMPLES.settingsUpdate);
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'assistant_settings_conflict', currentRowVersion: 1 });
    const unknown = await send('put', `${BASE}/settings`, {
      ...ASSISTANT_EXAMPLES.settingsUpdate,
      extra: 1,
    });
    expect(unknown.status).toBe(400);
    expect(audit.entries.map((e) => e.action)).toEqual(['assistant.settings_updated']);
    world.features.set(ORG, false);
    const noFeature = await send('put', `${BASE}/settings`, {
      ...ASSISTANT_EXAMPLES.settingsUpdate,
      expectedRowVersion: 1,
    });
    expect(noFeature.status).toBe(403);
    expect(noFeature.body.code).toBe('assistant_not_enabled');
  });

  it('GET /usage and GET /tools', async () => {
    const id = await newConversation();
    await ask(id, '/tool policy_management_list {}');
    const usage = await send('get', `${BASE}/usage`);
    expect(usage.status).toBe(200);
    expect(usage.body.rows).toHaveLength(1);
    expect(usage.body.totals.turns).toBe(1);
    const tooLong = await send('get', `${BASE}/usage?from=2026-01-01&to=2026-12-31`);
    expect(tooLong.status).toBe(400);
    const tools = await send('get', `${BASE}/tools`);
    expect(tools.status).toBe(200);
    expect(tools.body.tools.map((t: { name: string }) => t.name)).toContain(
      'policy_management_list',
    );
    expect(tools.body.tools.every((t: { access: string }) => t.access === 'read')).toBe(true);
  });

  it('conversations: create, list (v1, q), get, patch, delete (purge, audit), 404s, limit', async () => {
    const a = await newConversation('Policy review');
    await newConversation('Quarantine questions');
    const list = await send('get', `${BASE}/conversations?q=policy`);
    expect(list.status).toBe(200);
    expect(list.body.data.map((c: { title: string }) => c.title)).toEqual(['Policy review']);
    expect((await send('get', `${BASE}/conversations?unknown=1`)).status).toBe(400);
    expect((await send('get', `${BASE}/conversations?cursor=bogus`)).body.code).toBe(
      'cursor_invalid',
    );
    const got = await send('get', `${BASE}/conversations/${a}`);
    expect(got.body).toMatchObject({ id: a, title: 'Policy review', status: 'active' });
    const patched = await send('patch', `${BASE}/conversations/${a}`, { status: 'archived' });
    expect(patched.body.status).toBe('archived');
    expect((await send('patch', `${BASE}/conversations/${a}`, {})).status).toBe(400);
    const removed = await send('delete', `${BASE}/conversations/${a}`);
    expect(removed.status).toBe(204);
    expect((await send('get', `${BASE}/conversations/${a}`)).body.code).toBe(
      'assistant_conversation_not_found',
    );
    expect(audit.entries.at(-1)!.action).toBe('assistant.conversation_deleted');
    expect((await send('get', `${BASE}/conversations/not-a-uuid`)).status).toBe(400);
    // Another organization's conversation answers like an unknown id.
    const foreign = world.addConversation({
      scope: { organizationId: 7002n } as never,
      userId: 10n,
    });
    expect((await send('get', `${BASE}/conversations/${foreign.publicId}`)).status).toBe(404);
  });

  it('POST /turns as JSON: the answer, its execution and card; replay by clientTurnId; messages', async () => {
    const id = await newConversation();
    const clientTurnId = randomUUID();
    const res = await ask(id, '/tool policy_management_list {}', clientTurnId);
    expect(res.status).toBe(200);
    expect(res.body.turn).toMatchObject({ status: 'completed', seq: 1, toolCalls: 1 });
    expect(res.body.message).toMatchObject({
      role: 'assistant',
      content: 'Found 2 records. More are available.',
    });
    expect(res.body.executions[0]).toMatchObject({
      tool: 'policy_management_list',
      decision: 'allowed',
      hasMore: true,
      card: { kind: 'table', nextCursor: true },
    });
    // The loopback carried the caller's own bearer token, never a model-chosen header.
    expect(loopback.toolCalls[0]!.authorization).toMatch(/^Bearer /);
    const replay = await ask(id, 'ignored on replay', clientTurnId);
    expect(replay.body).toEqual(res.body);
    expect(world.turns).toHaveLength(1);
    const messages = await send('get', `${BASE}/conversations/${id}/messages`);
    expect(messages.status).toBe(200);
    expect(messages.body.data.map((m: { role: string }) => m.role)).toEqual(['user', 'assistant']);
    expect(messages.body.data[1].executions).toHaveLength(1);
    const tooLong = await ask(id, 'x'.repeat(4001));
    expect(tooLong.status).toBe(413);
    expect(tooLong.body.code).toBe('payload_too_large');
    const badZone = await send('post', `${BASE}/conversations/${id}/turns`, {
      clientTurnId: randomUUID(),
      message: 'x',
      timeZone: 'Mars/Olympus',
    });
    expect(badZone.status).toBe(400);
  });

  it('POST /turns with accept: text/event-stream streams assistant-stream/1 in order', async () => {
    const id = await newConversation();
    const res = await api
      .http()
      .post(`${BASE}/conversations/${id}/turns`)
      .set(await as())
      .set('accept', 'text/event-stream')
      .send({ clientTurnId: randomUUID(), message: '/tool policy_management_list {}' })
      .buffer(true)
      .parse((response, callback) => {
        let text = '';
        response.on('data', (chunk: Buffer) => (text += chunk.toString('utf8')));
        response.on('end', () => callback(null, text));
      });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('text/event-stream');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-accel-buffering']).toBe('no');
    const events = parseStream(res.body as string);
    expect(events.map(([e]) => e)).toEqual([
      'turn.started',
      'tool.started',
      'tool.completed',
      'text.delta',
      'turn.completed',
    ]);
    expect(events[0]![1]).toMatchObject({ conversationId: id, seq: 1 });
    expect(events[2]![1]).toMatchObject({
      status: 'succeeded',
      decision: 'allowed',
      card: { kind: 'table' },
    });
    expect(events[4]![1]).toMatchObject({ status: 'completed' });
  });

  it('refuses before streaming with ordinary coded JSON errors (gates, lock)', async () => {
    const id = await newConversation();
    const conversation = world.conversations.find((c) => c.publicId === id)!;
    await api.kv.set(`as:turn:${conversation.publicId}`, 'other-turn', 60);
    const locked = await api
      .http()
      .post(`${BASE}/conversations/${id}/turns`)
      .set(await as())
      .set('accept', 'text/event-stream')
      .send({ clientTurnId: randomUUID(), message: 'x' });
    expect(locked.status).toBe(409);
    expect(locked.headers['content-type']).toMatch(/application\/json/);
    expect(locked.body.code).toBe('assistant_turn_in_progress');
    await api.kv.del(`as:turn:${conversation.publicId}`);
    world.features.set(ORG, false);
    expect((await ask(id, 'x')).body.code).toBe('assistant_not_enabled');
    world.features.set(ORG, true);
    world.settings.get(ORG)!.enabled = false;
    expect((await ask(id, 'x')).body.code).toBe('assistant_tenant_disabled');
    expect((await send('post', `${BASE}/conversations`, {})).body.code).toBe(
      'assistant_tenant_disabled',
    );
  });

  it('POST /turns/{id}/cancel: own turns only, idempotent; GET and POST more on executions', async () => {
    const id = await newConversation();
    const turn = await ask(id, '/tool policy_management_list {}');
    const cancel = await send('post', `${BASE}/turns/${turn.body.turn.id}/cancel`);
    expect(cancel.status).toBe(202);
    expect(cancel.body).toEqual({ turnId: turn.body.turn.id, status: 'completed' });
    expect((await send('post', `${BASE}/turns/${randomUUID()}/cancel`)).body.code).toBe(
      'assistant_turn_not_found',
    );
    const executionId = turn.body.executions[0].id as string;
    const got = await send('get', `${BASE}/executions/${executionId}`);
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({ id: executionId, hasMore: true });
    loopback.on('GET /api/v1/policies', () => policyPage(1, null));
    const more = await send('post', `${BASE}/executions/${executionId}/more`);
    expect(more.status).toBe(200);
    expect(more.body).toMatchObject({
      parentExecutionId: executionId,
      turnId: null,
      hasMore: false,
    });
    expect(loopback.toolCalls.at(-1)!.path).toContain('cursor=next-page-1');
    const none = await send('post', `${BASE}/executions/${more.body.id}/more`);
    expect(none.status).toBe(409);
    expect(none.body.code).toBe('assistant_no_more_results');
    expect((await send('get', `${BASE}/executions/${randomUUID()}`)).body.code).toBe(
      'assistant_execution_not_found',
    );
  });
});
