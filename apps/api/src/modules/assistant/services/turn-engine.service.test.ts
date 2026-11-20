import { LlmError } from '@email-gateway/assistant';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { testUser, policyPage } from '../../../../test/support/assistant-fixtures';
import {
  callTool,
  createAssistantHarness,
  reply,
  ScriptedProvider,
} from '../../../../test/support/assistant-harness';
import { assistantKeys } from '../assistant.constants';
import { ownerOf } from './conversation.service';
import { deriveTitle, executionSummary, mapWithConcurrency } from './turn-engine.service';

const ORG = 7001n;

function setup(env: Record<string, string> = {}, provider?: ScriptedProvider) {
  const h = createAssistantHarness(env, provider);
  h.world.enable(ORG);
  const conversation = h.world.addConversation(ownerOf(h.user, h.scope));
  h.loopback.on('GET /api/v1/policies', () => policyPage(2));
  return { h, conversation };
}

const coded = async (promise: Promise<unknown>): Promise<{ status: number; code: string }> => {
  try {
    await promise;
  } catch (error) {
    const e = error as { getStatus(): number; code: string };
    return { status: e.getStatus(), code: e.code };
  }
  throw new Error('expected a coded error');
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('TurnEngineService: a turn with the deterministic fake provider (D7, §4.2)', () => {
  it('runs a /tool directive end to end: events in order, persistence order, stored answer', async () => {
    const { h, conversation } = setup();
    const { sink, prepared } = await h.ask(
      conversation.publicId,
      '/tool policy_management_list {}',
    );
    expect(prepared.kind).toBe('run');
    expect(sink.types).toEqual([
      'turn.started',
      'tool.started',
      'tool.completed',
      'text.delta',
      'turn.completed',
    ]);
    const completed = sink.events.at(-1) as { status: string; usage: { inputTokens: number } };
    expect(completed.status).toBe('completed');
    expect(completed.usage.inputTokens).toBeGreaterThan(0);
    // start transaction → execution row (with its audit row) → closing transaction → usage
    expect(h.world.log).toEqual(['startTurn', 'execution:allowed', 'finishTurn', 'usage']);
    const turn = h.world.turns[0]!;
    expect(turn).toMatchObject({ status: 'completed', rounds: 2, toolCalls: 1, errorCode: null });
    expect(JSON.parse(turn.providerTranscript!)).toHaveLength(4);
    const answer = h.world.messages.find((m) => m.role === 'assistant')!;
    expect(answer.content).toBe('Found 2 records.');
    expect(answer.seq).toBe(2);
    expect(h.world.conversations[0]!.title).toBe('/tool policy_management_list {}');
    expect(h.world.executions[0]).toMatchObject({
      toolName: 'policy_management_list',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 200,
      seq: 1,
    });
    expect(h.audit.entries.map((e) => e.action)).toEqual(['assistant.tool_executed']);
    expect(h.world.usage[0]).toMatchObject({ turns: 1, provider: 'fake', model: 'fake' });
    // The context read (/auth/me) and the tool call carry the turn request's own credential.
    expect(h.loopback.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'GET /api/v1/auth/me',
      'GET /api/v1/policies',
    ]);
    expect(h.loopback.calls.every((c) => c.authorization === 'Bearer it-access-token')).toBe(true);
    expect(h.loopback.toolCalls[0]!.clientIp).toBe('198.51.100.7');
    // Lock and slot are released.
    expect(await h.kv.get(assistantKeys.turnLock(conversation.publicId))).toBeNull();
    expect(h.limits.activeTurns).toBe(0);
  });

  it('builds the JSON answer and replays a finished clientTurnId without running again', async () => {
    const { h, conversation } = setup();
    const id = '0193d000-0000-7000-8000-00000000abcd';
    const first = await h.ask(conversation.publicId, 'show active policies', { clientTurnId: id });
    expect(first.prepared.kind).toBe('run');
    const stored = first.prepared.kind === 'run' ? await h.engine.stored(first.prepared) : null;
    expect(stored?.message?.content).toBe('Found 2 records.');
    expect(stored?.executions).toHaveLength(1);
    const again = await h.ask(conversation.publicId, 'show active policies', { clientTurnId: id });
    expect(again.prepared.kind).toBe('replay');
    if (again.prepared.kind === 'replay') expect(again.prepared.result).toEqual(stored);
    expect(again.sink.types).toEqual([
      'turn.started',
      'tool.started',
      'tool.completed',
      'text.delta',
      'turn.completed',
    ]);
    expect(h.world.turns).toHaveLength(1);
    expect(h.loopback.toolCalls).toHaveLength(1);
  });

  it('answers 409 assistant_turn_in_progress for a running clientTurnId and a held lock', async () => {
    const { h, conversation } = setup();
    const id = '0193d000-0000-7000-8000-00000000beef';
    const prepared = await h.engine.prepare(
      h.user,
      h.scope,
      conversation.publicId,
      { clientTurnId: id, message: 'hello' },
      { authorization: 'Bearer it', clientIp: null },
    );
    expect(prepared.kind).toBe('run');
    expect(
      await coded(
        h.engine.prepare(
          h.user,
          h.scope,
          conversation.publicId,
          { clientTurnId: id, message: 'x' },
          {
            authorization: 'Bearer it',
            clientIp: null,
          },
        ),
      ),
    ).toEqual({ status: 409, code: 'assistant_turn_in_progress' });
    expect(
      await coded(
        h.engine.prepare(
          h.user,
          h.scope,
          conversation.publicId,
          { clientTurnId: '0193d000-0000-7000-8000-00000000cafe', message: 'x' },
          { authorization: 'Bearer it', clientIp: null },
        ),
      ),
    ).toEqual({ status: 409, code: 'assistant_turn_in_progress' });
    if (prepared.kind === 'run') await prepared.release();
    expect(h.limits.activeTurns).toBe(0);
  });

  it('derives the title from the first user message only', async () => {
    const { h, conversation } = setup();
    await h.ask(conversation.publicId, '  list   my\npolicies  ');
    await h.ask(conversation.publicId, 'something else');
    expect(h.world.conversations[0]!.title).toBe('list my policies');
    expect(deriveTitle('x'.repeat(200))).toHaveLength(80);
  });
});

describe('TurnEngineService: limits and budgets (D11)', () => {
  it('refuses at turn start when the tenant budget is used up (429, scope tenant)', async () => {
    const { h, conversation } = setup();
    h.world.settings.get(ORG)!.dailyTokenBudget = 100;
    await h.ask(conversation.publicId, 'hello'); // uses > 100 tokens
    expect(await coded(h.ask(conversation.publicId, 'again'))).toEqual({
      status: 429,
      code: 'assistant_budget_exhausted',
    });
  });

  it('refuses when the platform daily budget is used up (scope platform)', async () => {
    const { h, conversation } = setup({ ASSISTANT_PLATFORM_DAILY_TOKENS: '50' });
    await h.ask(conversation.publicId, 'hello');
    await expect(h.ask(conversation.publicId, 'again')).rejects.toMatchObject({
      code: 'assistant_budget_exhausted',
      details: { scope: 'platform' },
    });
  });

  it('counts turns per user per minute (429 rate_limited, Retry-After)', async () => {
    const { h, conversation } = setup({ ASSISTANT_TURNS_PER_USER_PER_MINUTE: '1' });
    await h.ask(conversation.publicId, 'hello');
    await expect(h.ask(conversation.publicId, 'again')).rejects.toMatchObject({
      code: 'rate_limited',
      details: { scope: 'route' },
    });
  });

  it('caps concurrent turns per process (503 assistant_busy)', async () => {
    const { h, conversation } = setup({ ASSISTANT_MAX_CONCURRENT_TURNS: '1' });
    const hold = h.limits.acquireSlot();
    expect(await coded(h.ask(conversation.publicId, 'hello'))).toEqual({
      status: 503,
      code: 'assistant_busy',
    });
    hold();
    await h.ask(conversation.publicId, 'hello');
  });

  it('answers 413 for a message over ASSISTANT_USER_MESSAGE_MAX_CHARS', async () => {
    const { h, conversation } = setup({ ASSISTANT_USER_MESSAGE_MAX_CHARS: '100' });
    expect(await coded(h.ask(conversation.publicId, 'x'.repeat(101)))).toEqual({
      status: 413,
      code: 'payload_too_large',
    });
  });

  it('ends the turn with assistant_turn_limit after ASSISTANT_MAX_TOOL_ROUNDS', async () => {
    const provider = new ScriptedProvider([], () =>
      reply({ toolCalls: [callTool(`c${Math.random()}`, 'policy_management_list')] }),
    );
    const { h, conversation } = setup({ ASSISTANT_MAX_TOOL_ROUNDS: '2' }, provider);
    const { sink } = await h.ask(conversation.publicId, 'loop');
    expect(sink.events.at(-1)).toMatchObject({ type: 'turn.failed', code: 'assistant_turn_limit' });
    expect(provider.requests).toHaveLength(2);
    expect(h.world.turns[0]).toMatchObject({ status: 'failed', errorCode: 'assistant_turn_limit' });
    expect(h.world.messages.filter((m) => m.role === 'assistant')).toHaveLength(0);
  });

  it('refuses calls beyond ASSISTANT_MAX_TOOL_CALLS_PER_TURN as denied_budget (recorded, audited)', async () => {
    const provider = new ScriptedProvider([
      () =>
        reply({
          toolCalls: [
            callTool('a', 'policy_management_list'),
            callTool('b', 'policy_management_list'),
            callTool('c', 'policy_management_list'),
          ],
        }),
      (_r, _s, d) => reply({ text: 'done' }, d),
    ]);
    const { h, conversation } = setup({ ASSISTANT_MAX_TOOL_CALLS_PER_TURN: '2' }, provider);
    const { sink } = await h.ask(conversation.publicId, 'three');
    expect([...h.world.executions].sort((a, b) => a.seq - b.seq).map((e) => e.decision)).toEqual([
      'allowed',
      'allowed',
      'denied_budget',
    ]);
    expect(h.loopback.toolCalls).toHaveLength(2);
    expect(sink.types.filter((t) => t === 'tool.denied')).toHaveLength(1);
    expect(h.audit.entries.map((e) => e.action).sort()).toEqual([
      'assistant.tool_denied',
      'assistant.tool_executed',
      'assistant.tool_executed',
    ]);
    // Results go back to the model in call order.
    const last = provider.requests[1]!.transcript.slice(-3) as Array<{ toolCallId: string }>;
    expect(last.map((e) => e.toolCallId)).toEqual(['a', 'b', 'c']);
  });

  it('stops at the output token cap (assistant_turn_limit)', async () => {
    const provider = new ScriptedProvider([], () =>
      reply({
        toolCalls: [callTool('x', 'policy_management_list')],
        usage: { inputTokens: 1, outputTokens: 300, cacheReadTokens: 0, cacheWriteTokens: 0 },
      }),
    );
    const { h, conversation } = setup({ ASSISTANT_MAX_OUTPUT_TOKENS: '512' }, provider);
    const { sink } = await h.ask(conversation.publicId, 'tokens');
    expect(sink.events.at(-1)).toMatchObject({ type: 'turn.failed', code: 'assistant_turn_limit' });
    expect(provider.requests.map((r) => r.maxOutputTokens)).toEqual([512, 212]);
  });

  it('ends the turn at the deadline (assistant_turn_limit) and aborts the provider call', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
    let aborted = false;
    const provider = new ScriptedProvider([
      (_r, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            aborted = true;
            reject(new LlmError('aborted'));
          });
        }),
    ]);
    const { h, conversation } = setup(
      {
        ASSISTANT_TURN_DEADLINE_MS: '10000',
        ASSISTANT_TIMEOUT_MS: '5000',
        ASSISTANT_TOOL_TIMEOUT_MS: '1000',
      },
      provider,
    );
    const done = h.ask(conversation.publicId, 'slow');
    await vi.advanceTimersByTimeAsync(10_001);
    const { sink } = await done;
    expect(aborted).toBe(true);
    expect(sink.events.at(-1)).toMatchObject({ type: 'turn.failed', code: 'assistant_turn_limit' });
  });
});

describe('TurnEngineService: cancellation, session expiry, refusals (D7, D2)', () => {
  it('cancels a running turn through the cancel route: partial text kept, status cancelled', async () => {
    let started!: () => void;
    const begun = new Promise<void>((r) => (started = r));
    const provider = new ScriptedProvider([
      (_r, signal, onDelta) =>
        new Promise((_resolve, reject) => {
          onDelta('Partial answer');
          started();
          signal.addEventListener('abort', () => reject(new LlmError('aborted')));
        }),
    ]);
    const { h, conversation } = setup({}, provider);
    const run = h.ask(conversation.publicId, 'cancel me');
    await begun;
    const turn = h.world.turns[0]!;
    await expect(h.engine.cancel(h.user, h.scope, turn.publicId)).resolves.toEqual({
      turnId: turn.publicId,
      status: 'running',
    });
    const { sink } = await run;
    expect(sink.events.at(-1)).toMatchObject({ type: 'turn.completed', status: 'cancelled' });
    expect(h.world.turns[0]!.status).toBe('cancelled');
    expect(h.world.messages.find((m) => m.role === 'assistant')!.content).toBe('Partial answer');
    // Idempotent afterwards; another user's turn is 404.
    await expect(h.engine.cancel(h.user, h.scope, turn.publicId)).resolves.toMatchObject({
      status: 'cancelled',
    });
    const other = testUser({ userId: 999n, userPublicId: '0193b000-0000-7000-8000-000000000999' });
    await expect(h.engine.cancel(other, h.scope, turn.publicId)).rejects.toMatchObject({
      code: 'assistant_turn_not_found',
    });
  });

  it('aborts on a client disconnect (abort) and on a cross-pod cancel flag', async () => {
    const provider = new ScriptedProvider([
      () => reply({ toolCalls: [callTool('a', 'policy_management_list')] }),
      (_r, _s, d) => reply({ text: 'never' }, d),
    ]);
    const { h, conversation } = setup({}, provider);
    h.loopback.on('GET /api/v1/policies', async (call) => {
      // Another pod's cancel route set the flag while the tool ran.
      await h.limits.requestCancel(h.world.turns[0]!.publicId);
      expect(call.signal.aborted).toBe(false);
      return policyPage(1);
    });
    const { sink } = await h.ask(conversation.publicId, 'flag');
    expect(sink.events.at(-1)).toMatchObject({ type: 'turn.completed', status: 'cancelled' });
    expect(provider.requests).toHaveLength(1);
  });

  it('ends with assistant_session_expired when the loopback answers 401', async () => {
    const { h, conversation } = setup();
    h.loopback.on('GET /api/v1/policies', () => ({
      kind: 'response',
      status: 401,
      body: { statusCode: 401, error: 'Unauthorized', message: 'Unauthorized' },
    }));
    const { sink } = await h.ask(conversation.publicId, '/tool policy_management_list {}');
    expect(sink.events.at(-1)).toMatchObject({
      type: 'turn.failed',
      code: 'assistant_session_expired',
    });
    expect(h.world.executions[0]).toMatchObject({ status: 'failed', httpStatus: 401 });
  });

  it('ends with assistant_session_expired before the model call when /auth/me answers 401', async () => {
    const provider = new ScriptedProvider([]);
    const { h, conversation } = setup({}, provider);
    h.loopback.on('GET /api/v1/auth/me', () => ({ kind: 'response', status: 401, body: null }));
    const { sink } = await h.ask(conversation.publicId, 'hi');
    expect(sink.types).toEqual(['turn.started', 'turn.failed']);
    expect(provider.requests).toHaveLength(0);
  });

  it('maps a provider refusal (assistant_refused with the category) and provider errors', async () => {
    const refusing = new ScriptedProvider([
      () => reply({ stop: 'refusal', refusalCategory: 'cyber' }),
    ]);
    const a = setup({}, refusing);
    const refused = await a.h.ask(a.conversation.publicId, 'x');
    expect(refused.sink.events.at(-1)).toMatchObject({
      type: 'turn.failed',
      code: 'assistant_refused',
    });
    const failing = new ScriptedProvider([
      () => Promise.reject(new LlmError('client_error', { httpStatus: 400 })),
    ]);
    const b = setup({}, failing);
    const failed = await b.h.ask(b.conversation.publicId, 'x');
    expect(failed.sink.events.at(-1)).toMatchObject({
      type: 'turn.failed',
      code: 'assistant_provider_error',
    });
  });

  it('opens the breaker after ASSISTANT_BREAKER_THRESHOLD provider outages (503 at turn start)', async () => {
    const outage = new ScriptedProvider([], () => {
      throw new LlmError('server_error', { httpStatus: 503 });
    });
    const { h, conversation } = setup({ ASSISTANT_BREAKER_THRESHOLD: '1' }, outage);
    await h.ask(conversation.publicId, 'x');
    expect(await coded(h.ask(conversation.publicId, 'y'))).toEqual({
      status: 503,
      code: 'assistant_provider_unavailable',
    });
  });
});

describe('TurnEngineService: context, segments and recap (D7)', () => {
  it('replays the native transcript of the segment verbatim and appends the new message', async () => {
    const { h, conversation } = setup();
    await h.ask(conversation.publicId, '/text first answer');
    const provider = h.provider.provider();
    const spy = vi.spyOn(provider, 'complete');
    await h.ask(conversation.publicId, '/text second answer');
    const transcript = spy.mock.calls[0]![0].transcript as Array<{ role: string; text?: string }>;
    expect(transcript.map((e) => e.role)).toEqual(['user', 'assistant', 'user']);
    expect(transcript[0]!.text).toBe('/text first answer');
    // The system prompt carries the catalogue of the caller's tools and the context block.
    const system = spy.mock.calls[0]![0].system;
    expect(system).toContain('\npolicy_management_list(');
    expect(system).toContain('IT User');
    expect(system).not.toContain('\nusers_list('); // no user:read
  });

  it('opens a new segment with a deterministic recap when the window overflows', async () => {
    const { h, conversation } = setup({
      ASSISTANT_CONTEXT_MAX_TOKENS: '8000',
      ASSISTANT_USER_MESSAGE_MAX_CHARS: '16000',
    });
    await h.ask(conversation.publicId, `/text ${'long '.repeat(3000)}`);
    await h.ask(conversation.publicId, `/text ${'more '.repeat(3000)}`);
    const provider = h.provider.provider();
    const spy = vi.spyOn(provider, 'complete');
    await h.ask(conversation.publicId, '/text after');
    const transcript = spy.mock.calls[0]![0].transcript as Array<{ role: string; text: string }>;
    expect(transcript).toHaveLength(1);
    expect(transcript[0]!.text).toContain('Conversation recap');
    expect(transcript[0]!.text).toContain('Current user message:\n/text after');
    // Each oversized turn opened a segment: 1, 2, 3; the conversation continues the last one.
    expect(h.world.turns.map((t) => t.segment)).toEqual([1, 2, 3]);
    expect(h.world.conversations[0]!.segment).toBe(3);
    expect(transcript[0]!.text).toContain('/text more');
  });

  it('summarizes stored executions for the recap without record content', () => {
    expect(
      executionSummary({
        decision: 'allowed',
        status: 'succeeded',
        httpStatus: 200,
        errorCode: null,
        resultCard: { kind: 'table', rows: [{}, {}], nextCursor: true },
      }),
    ).toBe('ok, 2 rows, more available');
    expect(
      executionSummary({
        decision: 'denied_permission',
        status: 'refused',
        httpStatus: null,
        errorCode: 'denied_permission',
        resultCard: null,
      }),
    ).toBe('denied denied_permission');
  });

  it('runs parallel calls at most 4 at a time, results in input order', async () => {
    let active = 0;
    let peak = 0;
    const results = await mapWithConcurrency([5, 1, 4, 2, 3, 0, 6], 4, async (ms, i) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, ms));
      active -= 1;
      return i;
    });
    expect(peak).toBe(4);
    expect(results).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });
});

describe('TurnEngineService: availability gates at turn start (D11)', () => {
  it('answers the coded refusals of each gate before writing anything', async () => {
    const off = createAssistantHarness({ ASSISTANT_ENABLED: 'false' });
    const c0 = off.world.addConversation(ownerOf(off.user, off.scope));
    expect(await coded(off.ask(c0.publicId, 'x'))).toEqual({
      status: 503,
      code: 'assistant_disabled',
    });

    const { h, conversation } = setup();
    h.world.features.set(ORG, false);
    expect(await coded(h.ask(conversation.publicId, 'x'))).toEqual({
      status: 403,
      code: 'assistant_not_enabled',
    });
    h.world.features.set(ORG, true);
    h.world.settings.get(ORG)!.enabled = false;
    expect(await coded(h.ask(conversation.publicId, 'x'))).toEqual({
      status: 403,
      code: 'assistant_tenant_disabled',
    });
    expect(h.world.turns).toHaveLength(0);
    expect(h.world.log).toEqual([]);
  });

  it('answers 404 for another user’s conversation', async () => {
    const { h, conversation } = setup();
    const other = testUser({ userId: 777n, userPublicId: '0193b000-0000-7000-8000-000000000777' });
    expect(await coded(h.ask(conversation.publicId, 'x', { principal: other }))).toEqual({
      status: 404,
      code: 'assistant_conversation_not_found',
    });
  });
});
