/**
 * The step AI-1 assistant routes (docs/plan/steps/28-ai-chat-management.md §4.1, §4.2, §9 item 3)
 * over HTTP with MySQL, Redis and S3 stubbed: the assistant tables through `AssistantWorld`, the
 * deterministic fake LLM provider, and a fake loopback dispatcher in place of the api's own
 * pipeline (the real loopback runs in integration/assistant.test.ts). For every operation:
 * success, 403 without its permission, 403 `user_required` for API keys, coded errors; then a
 * turn as JSON and as `assistant-stream/1`, replay of a `clientTurnId`, cancellation, "more"
 * pages and the availability gates; step AI-2 (docs/plan/steps/29-ai-chat-confirmations-mail-
 * writes.md §4.1, §9 item 3): a write proposal in a turn, then get, confirm and cancel of its
 * confirmation over HTTP; step AI-R (docs/plan/steps/31-ai-chat-reports.md §4.1, §9 item 3): a
 * report generated in a turn, its view with the HTML, and an emailed report confirmed over HTTP;
 * step AI-4 (docs/plan/steps/32-ai-chat-security-operations.md §9 item 2): an ATO response approved
 * by another user (high confirmation, re-authentication, executed through the loopback), the
 * requester's own approval refused before any card (four-eyes guard), and the DLP pattern test
 * whose sample and pattern never reach a stored or audited row; step AI-5 (docs/plan/steps/
 * 33-ai-chat-compliance-integrations.md §9 item 2): a retention shortening through the fake
 * provider's retention plan (high, re-authentication) and a mail-flow apply whose impact token
 * the server takes from a fresh preview (the model's value ignored). Synthetic data only.
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
// @covers get /api/v1/assistant/reports/:reportId
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ASSISTANT_EXAMPLES } from '../src/modules/assistant/dto/assistant.schemas';
import {
  AI5_ESCALATION_WARNINGS,
  findTool,
  GUARD_MESSAGES,
  REDACTED_PARAM,
  REPORT_SOURCE_DEFS,
  type ReportSourceKey,
} from '@email-gateway/assistant';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import { reportSourceBodies } from './support/assistant-report-fixtures';
import {
  AssistantWorld,
  FakeLoopback,
  overrideAssistant,
  policyPage,
  REAUTH_PASSWORD,
  REAUTH_TOTP,
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
      ['get', `${BASE}/confirmations/${randomUUID()}`, USE],
      [
        'post',
        `${BASE}/confirmations/${randomUUID()}/confirm`,
        USE,
        { token: 'A'.repeat(43), actionDigest: 'a'.repeat(64) },
      ],
      ['post', `${BASE}/confirmations/${randomUUID()}/cancel`, USE],
      ['get', `${BASE}/reports/${randomUUID()}`, USE],
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
    // Writes need their permissions; the only write without one is the caller's own
    // notification preferences (step AI-3, `authenticated`).
    expect(
      tools.body.tools
        .filter((t: { access: string }) => t.access === 'write')
        .map((t: { name: string }) => t.name),
    ).toEqual(['notifications_put_preferences']);
  });

  it('a write on the caller’s own account is denied_guard (step AI-3 D3): no request, no confirmation', async () => {
    const id = await newConversation();
    const self = api.principals.ids.user;
    const res = await send(
      'post',
      `${BASE}/conversations/${id}/turns`,
      { clientTurnId: randomUUID(), message: `/tool users_reset_mfa {"id":"${self}"}` },
      [USE, 'user:manage', 'user:read'],
    );
    expect(res.status).toBe(200);
    expect(res.body.executions[0]).toMatchObject({
      tool: 'users_reset_mfa',
      decision: 'denied_guard',
      status: 'refused',
      card: null,
      confirmation: null,
    });
    expect(res.body.confirmations).toEqual([]);
    expect(loopback.calls.some((c) => c.path.startsWith('/api/v1/users'))).toBe(false);
    expect(world.confirmations).toHaveLength(0);
    expect(audit.entries.find((e) => e.action === 'assistant.tool_denied')?.metadata).toMatchObject(
      { decision: 'denied_guard', guard: 'not_self_user' },
    );
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

  describe('confirmations (step AI-2 §4.1)', () => {
    const POLICY = '0193c000-0000-7000-8000-000000000001';
    const WRITERS = [...ALL, 'policy:publish'];
    let policyRowVersion = 3;
    const writes: string[] = [];

    beforeEach(() => {
      policyRowVersion = 3;
      writes.length = 0;
      loopback.on(`GET /api/v1/policies/${POLICY}`, () => ({
        kind: 'response',
        status: 200,
        body: {
          id: POLICY,
          name: 'Block executables',
          status: 'active',
          rowVersion: policyRowVersion,
        },
      }));
      loopback.on(`POST /api/v1/policies/${POLICY}/disable`, (call) => {
        writes.push(`${call.method} ${call.path}`);
        policyRowVersion += 1;
        return {
          kind: 'response',
          status: 200,
          body: {
            id: POLICY,
            name: 'Block executables',
            status: 'disabled',
            rowVersion: policyRowVersion,
          },
        };
      });
    });

    const propose = async (conversationId: string) => {
      const res = await send(
        'post',
        `${BASE}/conversations/${conversationId}/turns`,
        {
          clientTurnId: randomUUID(),
          message: `/tool policy_management_disable {"policyId":"${POLICY}"}`,
        },
        WRITERS,
      );
      expect(res.status).toBe(200);
      return res;
    };

    it('a turn proposes (pending_confirmation, token in the JSON answer only); GET shows it without the token', async () => {
      const id = await newConversation();
      const res = await propose(id);
      expect(res.body.executions[0]).toMatchObject({
        tool: 'policy_management_disable',
        status: 'pending_confirmation',
        confirmation: { status: 'pending', risk: 'medium' },
      });
      expect(res.body.confirmations).toHaveLength(1);
      const { confirmation, token } = res.body.confirmations[0] as {
        confirmation: { id: string; actionDigest: string };
        token: string;
      };
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(writes).toEqual([]);
      const got = await send('get', `${BASE}/confirmations/${confirmation.id}`, undefined, WRITERS);
      expect(got.status).toBe(200);
      expect(got.body).toMatchObject({ id: confirmation.id, status: 'pending' });
      expect(JSON.stringify(got.body)).not.toContain(token);
      const unknown = await send(
        'get',
        `${BASE}/confirmations/${randomUUID()}`,
        undefined,
        WRITERS,
      );
      expect(unknown.status).toBe(404);
      expect(unknown.body.code).toBe('assistant_confirmation_not_found');
    });

    it('POST confirm: body validation, digest refusal, then 200 executed; a replay is 409', async () => {
      const id = await newConversation();
      const res = await propose(id);
      const { confirmation, token } = res.body.confirmations[0] as {
        confirmation: { id: string; actionDigest: string };
        token: string;
      };
      const url = `${BASE}/confirmations/${confirmation.id}/confirm`;
      const invalid = await send('post', url, { token: 'short', actionDigest: 'x' }, WRITERS);
      expect(invalid.status).toBe(400);
      const extra = await send(
        'post',
        url,
        { token, actionDigest: confirmation.actionDigest, unexpected: 1 },
        WRITERS,
      );
      expect(extra.status).toBe(400);
      const digest = await send('post', url, { token, actionDigest: 'f'.repeat(64) }, WRITERS);
      expect(digest.status).toBe(409);
      expect(digest.body.code).toBe('assistant_confirmation_digest_mismatch');
      const ok = await send(
        'post',
        url,
        { token, actionDigest: confirmation.actionDigest },
        WRITERS,
      );
      expect(ok.status).toBe(200);
      expect(ok.body.confirmation).toMatchObject({
        status: 'executed',
        result: { httpStatus: 200 },
      });
      expect(ok.body.execution).toMatchObject({ status: 'succeeded', turnId: null });
      expect(writes).toEqual([`POST /api/v1/policies/${POLICY}/disable`]);
      const again = await send(
        'post',
        url,
        { token, actionDigest: confirmation.actionDigest },
        WRITERS,
      );
      expect(again.status).toBe(409);
      expect(again.body).toMatchObject({
        code: 'assistant_confirmation_not_pending',
        status: 'executed',
      });
      expect(audit.entries.map((e) => e.action)).toContain('assistant.confirmation_executed');
      // The next turn hears about it (and the stored user message stays the user's text).
      await send(
        'post',
        `${BASE}/conversations/${id}/turns`,
        { clientTurnId: randomUUID(), message: 'thanks' },
        WRITERS,
      );
      expect(world.confirmations[0]!.reportedAt).not.toBeNull();
      expect(world.messages.filter((m) => m.role === 'user').map((m) => m.content)).toEqual([
        `/tool policy_management_disable {"policyId":"${POLICY}"}`,
        'thanks',
      ]);
    });

    it('POST cancel: 200 cancelled, idempotent; then confirm answers 409', async () => {
      const id = await newConversation();
      const res = await propose(id);
      const { confirmation, token } = res.body.confirmations[0] as {
        confirmation: { id: string; actionDigest: string };
        token: string;
      };
      const cancel = await send(
        'post',
        `${BASE}/confirmations/${confirmation.id}/cancel`,
        undefined,
        WRITERS,
      );
      expect(cancel.status).toBe(200);
      expect(cancel.body.confirmation.status).toBe('cancelled');
      const again = await send(
        'post',
        `${BASE}/confirmations/${confirmation.id}/cancel`,
        undefined,
        WRITERS,
      );
      expect(again.status).toBe(200);
      const confirm = await send(
        'post',
        `${BASE}/confirmations/${confirmation.id}/confirm`,
        { token, actionDigest: confirmation.actionDigest },
        WRITERS,
      );
      expect(confirm.status).toBe(409);
      expect(writes).toEqual([]);
    });
  });
  describe('reports (step AI-R §4.1)', () => {
    const REPORTERS = [USE, 'report:read', 'quarantine:read', 'ato:read'];
    const SELF = 'it-e2e-analyst@example.test';

    beforeEach(() => {
      const window = { from: '2026-11-16T09:00:00.000Z', to: '2026-11-23T09:00:00.000Z' };
      const bodies = reportSourceBodies(window);
      for (const key of Object.keys(REPORT_SOURCE_DEFS) as ReportSourceKey[]) {
        const path = findTool(REPORT_SOURCE_DEFS[key].tool)!.pathTemplate;
        loopback.on(`GET ${path}`, () => ({ kind: 'response', status: 200, body: bodies[key] }));
      }
      world.reportWorld.users.push({
        id: 10n,
        organizationId: ORG,
        email: SELF,
        status: 'active',
        verified: true,
        deleted: false,
      });
    });

    const turnOf = async (conversationId: string, message: string) => {
      const res = await send(
        'post',
        `${BASE}/conversations/${conversationId}/turns`,
        { clientTurnId: randomUUID(), message },
        REPORTERS,
      );
      expect(res.status).toBe(200);
      return res;
    };

    it('a turn generates a report card; GET returns the view and the inert HTML (no-store)', async () => {
      const id = await newConversation();
      const res = await turnOf(id, 'generate a security report');
      const execution = res.body.executions[0];
      expect(execution).toMatchObject({
        tool: 'report_generate',
        operationId: 'AssistantNative_reportGenerate',
        decision: 'allowed',
        status: 'succeeded',
        httpStatus: 201,
        card: { kind: 'report', status: 'ok' },
      });
      const reportId = execution.card.report.reportId as string;
      expect(res.body.message.content).toMatch(/security report/i);
      expect(loopback.toolCalls.every((c) => c.path.startsWith('/api/v1/'))).toBe(true);

      const view = await send('get', `${BASE}/reports/${reportId}`, undefined, REPORTERS);
      expect(view.status).toBe(200);
      expect(view.headers['cache-control']).toBe('no-store');
      expect(view.headers['content-type']).toMatch(/^application\/json/);
      expect(view.body.report).toMatchObject({
        id: reportId,
        conversationId: id,
        executionId: execution.id,
        status: 'available',
        deliveries: [],
      });
      expect(view.body.html).toMatch(/^<!doctype html>/);
      expect(view.body.html).not.toMatch(/<script|<a |<img|<iframe|href=|src=/i);

      // Another user of the organization (same id space, other user id) answers 404.
      const report = world.reportWorld.reports[0]!;
      report.userId = 999n;
      const foreign = await send('get', `${BASE}/reports/${reportId}`, undefined, REPORTERS);
      expect(foreign.status).toBe(404);
      expect(foreign.body.code).toBe('assistant_report_not_found');
      const bad = await send('get', `${BASE}/reports/not-a-uuid`, undefined, REPORTERS);
      expect(bad.status).toBe(400);
    });

    it('send this report to my email: medium confirmation, confirm → delivery queued with its outbox event', async () => {
      const id = await newConversation();
      await turnOf(id, 'generate a security report');
      const proposal = await turnOf(id, 'send this report to my email');
      expect(proposal.body.confirmations).toHaveLength(1);
      const { confirmation, token } = proposal.body.confirmations[0];
      expect(confirmation).toMatchObject({
        tool: 'report_send_email',
        risk: 'medium',
        requiresReauth: false,
        summary: { title: 'Email security report', request: { path: 'native:report_send_email' } },
      });
      const confirmed = await send(
        'post',
        `${BASE}/confirmations/${confirmation.id}/confirm`,
        { token, actionDigest: confirmation.actionDigest },
        REPORTERS,
      );
      expect(confirmed.status).toBe(200);
      expect(confirmed.body.confirmation.status).toBe('executed');
      expect(confirmed.body.execution).toMatchObject({
        httpStatus: 202,
        card: { kind: 'message', message: `Report email queued to ${SELF}` },
      });
      const delivery = world.reportWorld.deliveries[0]!;
      expect(delivery).toMatchObject({ status: 'queued', recipientAddress: SELF });
      expect(world.reportWorld.outbox[0]).toMatchObject({
        eventType: 'assistant.report.email_requested.v1',
        eventId: delivery.publicId,
      });
      const reportId = world.reportWorld.reports[0]!.publicId;
      const view = await send('get', `${BASE}/reports/${reportId}`, undefined, REPORTERS);
      expect(view.body.report.deliveries).toEqual([
        expect.objectContaining({ id: delivery.publicId, to: SELF, status: 'queued' }),
      ]);

      // An address outside the organization is refused: no confirmation card.
      const refused = await turnOf(id, 'send the report to someone@outside.test');
      expect(refused.body.confirmations).toEqual([]);
      expect(refused.body.executions[0]).toMatchObject({
        tool: 'report_send_email',
        decision: 'denied_guard',
      });
    });
  });

  describe('security operations (step AI-4 §9 item 2)', () => {
    const RESPONSE = '0193c400-0000-7000-8000-0000000e2e01';
    const ACCOUNT = '0193c400-0000-7000-8000-0000000e2e02';
    const OTHER_ANALYST = '0193b000-0000-7000-8000-0000000e2e03';
    const RESPONDERS = [USE, 'ato:read', 'ato:respond'];
    const DLP_MANAGERS = [USE, 'dlp:read', 'dlp:manage'];
    const SAMPLE = 'Synthetic e2e sample: ticket QJV-90817263 for the it-dlp check';
    const PATTERN = 'QJV-[0-9]{8}';
    const writes: string[] = [];
    let requestedBy = { type: 'user', id: OTHER_ANALYST };

    const responseBody = () => ({
      id: RESPONSE,
      actionType: 'restrict_smtp_sending',
      provider: 'gateway',
      impact: 'high',
      status: 'pending_approval',
      account: { id: ACCOUNT, kind: 'mailbox' },
      target: { scope: 'mailbox', connectorId: null, cidr: null },
      params: { durationMinutes: 60, mode: 'reject', description: null },
      requestedBy,
      requestReason: 'Outbound spam from the mailbox',
      approvalExpiresAt: '2026-11-26T18:00:00.000Z',
      executedAt: null,
      effectiveUntil: null,
      // The api's view: never the requester (nor the creator of a requesting key).
      canDecide: requestedBy.id !== api.principals.ids.user,
      createdAt: '2026-11-25T09:00:00.000Z',
    });

    beforeEach(() => {
      writes.length = 0;
      requestedBy = { type: 'user', id: OTHER_ANALYST };
      loopback.on('GET /api/v1/ato/responses', () => ({
        kind: 'response',
        status: 200,
        body: { data: [responseBody()], nextCursor: null },
      }));
      loopback.on(`GET /api/v1/ato/responses/${RESPONSE}`, () => ({
        kind: 'response',
        status: 200,
        body: responseBody(),
      }));
      loopback.on(`POST /api/v1/ato/responses/${RESPONSE}/approve`, (call) => {
        writes.push(`${call.method} ${call.path} ${call.idempotencyKey ?? '-'}`);
        return {
          kind: 'response',
          status: 200,
          body: { ...responseBody(), status: 'succeeded', canDecide: false },
        };
      });
      loopback.on('POST /api/v1/dlp/patterns/test', () => ({
        kind: 'response',
        status: 200,
        body: {
          valid: true,
          matches: [{ start: 30, end: 42, masked: '********7263', validator: null }],
          truncated: false,
        },
      }));
    });

    const turn = async (conversationId: string, message: string, permissions: string[]) => {
      const res = await send(
        'post',
        `${BASE}/conversations/${conversationId}/turns`,
        { clientTurnId: randomUUID(), message },
        permissions,
      );
      expect(res.status).toBe(200);
      return res;
    };

    it('another responder approves the pending response: high card, re-auth, executed through the loopback', async () => {
      const id = await newConversation();
      const res = await turn(id, 'approve the pending ato response', RESPONDERS);
      const tools = res.body.executions.map((e: { tool: string }) => e.tool);
      expect(tools).toEqual(['ato_responses_list', 'ato_responses_approve']);
      expect(res.body.executions[1]).toMatchObject({
        status: 'pending_confirmation',
        confirmation: { status: 'pending', risk: 'high', requiresReauth: true },
      });
      const { confirmation, token } = res.body.confirmations[0] as {
        confirmation: { id: string; actionDigest: string; summary: { request: unknown } };
        token: string;
      };
      expect(confirmation.summary.request).toMatchObject({
        method: 'POST',
        path: `/api/v1/ato/responses/${RESPONSE}/approve`,
      });
      expect(writes).toEqual([]);
      const url = `${BASE}/confirmations/${confirmation.id}/confirm`;
      const body = { token, actionDigest: confirmation.actionDigest };
      const noReauth = await send('post', url, body, RESPONDERS);
      expect(noReauth.status).toBe(401);
      expect(noReauth.body.code).toBe('assistant_reauth_required');
      const ok = await send(
        'post',
        url,
        { ...body, reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP } },
        RESPONDERS,
      );
      expect(ok.status).toBe(200);
      expect(ok.body.confirmation).toMatchObject({
        status: 'executed',
        result: { httpStatus: 200 },
      });
      expect(writes).toEqual([`POST /api/v1/ato/responses/${RESPONSE}/approve ${confirmation.id}`]);
      expect(audit.entries.map((e) => e.action)).toContain('assistant.confirmation_executed');
    });

    it('the requester approving their own response is denied_guard: no confirmation, no request to approve', async () => {
      requestedBy = { type: 'user', id: api.principals.ids.user };
      const id = await newConversation();
      const res = await turn(
        id,
        `/tool ato_responses_approve {"responseId":"${RESPONSE}","body":{"reason":"Looks right to me"}}`,
        RESPONDERS,
      );
      expect(res.body.executions[0]).toMatchObject({
        tool: 'ato_responses_approve',
        decision: 'denied_guard',
        status: 'refused',
        message: GUARD_MESSAGES.ato_four_eyes,
        confirmation: null,
      });
      expect(res.body.confirmations).toEqual([]);
      expect(world.confirmations).toHaveLength(0);
      expect(writes).toEqual([]);
      // Only the precondition read (an internal read: no execution id), never the approval.
      expect(
        loopback.calls
          .filter((c) => c.path.startsWith('/api/v1/ato/'))
          .map((c) => `${c.method} ${c.path}`),
      ).toEqual([`GET /api/v1/ato/responses/${RESPONSE}`]);
      const view = await send(
        'get',
        `${BASE}/executions/${res.body.executions[0].id}`,
        undefined,
        RESPONDERS,
      );
      expect(view.status).toBe(200);
      expect(view.body.message).toBe(GUARD_MESSAGES.ato_four_eyes);
      expect(
        audit.entries.find((e) => e.action === 'assistant.tool_denied')?.metadata,
      ).toMatchObject({ decision: 'denied_guard', guard: 'not_self_field' });
    });

    it('dlp_patterns_test: the loopback gets the sample; execution rows, audit and the view never hold it', async () => {
      const id = await newConversation();
      const args = { body: { pattern: PATTERN, sample: SAMPLE, maskStyle: 'last4' } };
      const res = await turn(id, `/tool dlp_patterns_test ${JSON.stringify(args)}`, DLP_MANAGERS);
      const execution = res.body.executions[0];
      expect(execution).toMatchObject({
        tool: 'dlp_patterns_test',
        decision: 'allowed',
        status: 'succeeded',
        httpStatus: 200,
      });
      expect(loopback.toolCalls.find((c) => c.path === '/api/v1/dlp/patterns/test')!.body).toEqual(
        args.body,
      );
      const stored = world.executions.find((e) => e.publicId === execution.id)!;
      expect(stored.paramsRedacted).toEqual({
        body: { pattern: REDACTED_PARAM, sample: REDACTED_PARAM, maskStyle: 'last4' },
      });
      const view = await send('get', `${BASE}/executions/${execution.id}`, undefined, DLP_MANAGERS);
      expect(view.status).toBe(200);
      expect(view.body).toMatchObject({ id: execution.id, status: 'succeeded' });
      const serialized = (value: unknown) =>
        JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));
      for (const value of [SAMPLE, PATTERN]) {
        expect(serialized(view.body)).not.toContain(value);
        expect(serialized(execution)).not.toContain(value);
        expect(serialized(world.executions)).not.toContain(value);
        expect(serialized(audit.entries)).not.toContain(value);
      }
    });
  });

  describe('compliance and integrations (step AI-5 §9 item 2)', () => {
    const POLICY = '0193c500-0000-7000-8000-0000000e2e01';
    const CONNECTION = '0193c500-0000-7000-8000-0000000e2e02';
    const DOMAIN = '0193c500-0000-7000-8000-0000000e2e03';
    const ARCHIVE_ADMINS = [USE, 'archive:read', 'archive:manage'];
    const INTEGRATION_ADMINS = [USE, 'integration:read', 'integration:manage'];
    const SERVER_TOKEN = 'e2e-impact-token-server-1';
    const MODEL_TOKEN = 'e2e-impact-token-from-model';
    const CHANGE = { kind: 'inbound', domainIds: [DOMAIN] };
    const writes: Array<{ route: string; body: unknown; key: string | undefined }> = [];
    const previews: unknown[] = [];

    const policyBody = () => ({
      id: POLICY,
      name: 'E2E retention finance',
      retentionDays: 365,
      onExpiry: 'review',
      priority: 50,
      criteria: { directions: ['inbound'] },
      isDefault: false,
      rowVersion: 4,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    });

    beforeEach(() => {
      writes.length = 0;
      previews.length = 0;
      loopback.on('GET /api/v1/archive/retention-policies', () => ({
        kind: 'response',
        status: 200,
        body: { data: [policyBody()], nextCursor: null },
      }));
      loopback.on(`GET /api/v1/archive/retention-policies/${POLICY}`, () => ({
        kind: 'response',
        status: 200,
        body: policyBody(),
      }));
      loopback.on(`PUT /api/v1/archive/retention-policies/${POLICY}`, (call) => {
        writes.push({
          route: `${call.method} ${call.path}`,
          body: call.body,
          key: call.idempotencyKey,
        });
        return {
          kind: 'response',
          status: 200,
          body: { ...policyBody(), retentionDays: 30, rowVersion: 5 },
        };
      });
      loopback.on(`GET /api/v1/provider-connections/${CONNECTION}`, () => ({
        kind: 'response',
        status: 200,
        body: {
          id: CONNECTION,
          provider: 'microsoft_365',
          displayName: 'E2E Contoso',
          status: 'active',
          outboundMode: 'off',
          internalRouting: false,
          grants: [],
          domains: [{ id: DOMAIN, name: 'contoso.example', providerVerification: 'verified' }],
          rowVersion: 3,
        },
      }));
      loopback.on(`POST /api/v1/provider-connections/${CONNECTION}/mail-flow/preview`, (call) => {
        previews.push(call.body);
        return {
          kind: 'response',
          status: 200,
          body: {
            change: (call.body as { change: unknown }).change,
            changeSet: {
              kind: 'inbound',
              domains: [
                {
                  domainId: DOMAIN,
                  name: 'contoso.example',
                  current: { provider: null, servers: [] },
                  proposed: {
                    provider: 'microsoft_365',
                    servers: [
                      {
                        host: 'contoso-example.mail.protection.example',
                        port: 25,
                        priority: 0,
                        tlsMode: 'required',
                      },
                    ],
                  },
                  changed: true,
                },
              ],
              connector: null,
              connection: [],
              grantsRevoked: 0,
            },
            impactToken: SERVER_TOKEN,
            expiresAt: '2026-11-25T12:15:00.000Z',
            warnings: [],
          },
        };
      });
      loopback.on(`POST /api/v1/provider-connections/${CONNECTION}/mail-flow/apply`, (call) => {
        writes.push({
          route: `${call.method} ${call.path}`,
          body: call.body,
          key: call.idempotencyKey,
        });
        return { kind: 'response', status: 200, body: { id: CONNECTION, rowVersion: 4 } };
      });
    });

    const turn = async (conversationId: string, message: string, permissions: string[]) => {
      const res = await send(
        'post',
        `${BASE}/conversations/${conversationId}/turns`,
        { clientTurnId: randomUUID(), message },
        permissions,
      );
      expect(res.status).toBe(200);
      return res;
    };
    const confirmOf = (res: { body: { confirmations: unknown[] } }) =>
      res.body.confirmations[0] as {
        confirmation: {
          id: string;
          actionDigest: string;
          risk: string;
          requiresReauth: boolean;
          summary: { warnings?: string[]; request: unknown };
        };
        token: string;
      };

    it('set retention policy "…" to 30 days on a 365-day policy: high card with the shortening warning, re-auth, PUT', async () => {
      const id = await newConversation();
      const res = await turn(
        id,
        'set retention policy "E2E retention finance" to 30 days',
        ARCHIVE_ADMINS,
      );
      expect(res.body.executions.map((e: { tool: string }) => e.tool)).toEqual([
        'archive_retention_list',
        'archive_retention_get',
        'archive_retention_update',
      ]);
      expect(res.body.executions[2]).toMatchObject({
        status: 'pending_confirmation',
        confirmation: { status: 'pending', risk: 'high', requiresReauth: true },
      });
      const { confirmation, token } = confirmOf(res);
      expect(confirmation.summary.warnings).toContain(AI5_ESCALATION_WARNINGS.retentionShortened);
      expect(writes).toEqual([]);
      const url = `${BASE}/confirmations/${confirmation.id}/confirm`;
      const body = { token, actionDigest: confirmation.actionDigest };
      const noReauth = await send('post', url, body, ARCHIVE_ADMINS);
      expect(noReauth.status).toBe(401);
      expect(noReauth.body.code).toBe('assistant_reauth_required');
      const ok = await send(
        'post',
        url,
        { ...body, reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP } },
        ARCHIVE_ADMINS,
      );
      expect(ok.status).toBe(200);
      expect(ok.body.confirmation).toMatchObject({
        status: 'executed',
        result: { httpStatus: 200 },
      });
      expect(writes).toHaveLength(1);
      expect(writes[0]!.route).toBe(`PUT /api/v1/archive/retention-policies/${POLICY}`);
      // The fields the plan copied from the read, the new days and the injected CAS.
      expect(writes[0]!.body).toEqual({
        name: 'E2E retention finance',
        retentionDays: 30,
        onExpiry: 'review',
        priority: 50,
        criteria: { directions: ['inbound'] },
        expectedRowVersion: 4,
      });
      const requested = audit.entries.find((e) => e.action === 'assistant.confirmation_requested');
      expect(requested?.metadata).toMatchObject({ risk: 'high', baseRisk: 'medium' });
    });

    it('provider_mail_flow_apply: preview called with the change, the server token injected (the model’s ignored), apply sent with it', async () => {
      const id = await newConversation();
      const args = {
        id: CONNECTION,
        body: { change: CHANGE, impactToken: MODEL_TOKEN, confirm: true },
      };
      const res = await turn(
        id,
        `/tool provider_mail_flow_apply ${JSON.stringify(args)}`,
        INTEGRATION_ADMINS,
      );
      expect(res.body.executions[0]).toMatchObject({
        tool: 'provider_mail_flow_apply',
        status: 'pending_confirmation',
        confirmation: { status: 'pending', risk: 'high', requiresReauth: true },
      });
      expect(previews).toEqual([{ change: CHANGE }]);
      const stored = world.confirmations[0]!;
      expect((stored.request as { body: unknown }).body).toEqual({
        change: CHANGE,
        impactToken: SERVER_TOKEN,
        confirm: true,
      });
      const { confirmation, token } = confirmOf(res);
      const view = await send(
        'get',
        `${BASE}/confirmations/${confirmation.id}`,
        undefined,
        INTEGRATION_ADMINS,
      );
      expect(view.status).toBe(200);
      const serialized = (value: unknown) =>
        JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));
      for (const value of [SERVER_TOKEN, MODEL_TOKEN]) {
        expect(serialized(res.body), value).not.toContain(value);
        expect(serialized(view.body), value).not.toContain(value);
        expect(serialized(world.executions), value).not.toContain(value);
        expect(serialized(audit.entries), value).not.toContain(value);
      }
      const ok = await send(
        'post',
        `${BASE}/confirmations/${confirmation.id}/confirm`,
        {
          token,
          actionDigest: confirmation.actionDigest,
          reauth: { password: REAUTH_PASSWORD, totpCode: REAUTH_TOTP },
        },
        INTEGRATION_ADMINS,
      );
      expect(ok.status).toBe(200);
      expect(ok.body.confirmation).toMatchObject({
        status: 'executed',
        result: { httpStatus: 200 },
      });
      // The confirm-time re-read ran the preview again; the apply carries the stored token.
      expect(previews).toEqual([{ change: CHANGE }, { change: CHANGE }]);
      expect(writes).toEqual([
        {
          route: `POST /api/v1/provider-connections/${CONNECTION}/mail-flow/apply`,
          body: { change: CHANGE, impactToken: SERVER_TOKEN, confirm: true },
          key: confirmation.id,
        },
      ]);
      expect(serialized(ok.body)).not.toContain(SERVER_TOKEN);
      expect(serialized(world.executions)).not.toContain(SERVER_TOKEN);
      expect(serialized(audit.entries)).not.toContain(SERVER_TOKEN);
    });
  });
});
