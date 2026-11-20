import { HttpResponse } from 'msw';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/lib/api/errors';
import { apiErrorJson, expectRequestMatchesContract, mockApi, okJson } from '@/test';
import {
  MAX_EVENT_CHARS,
  SseParser,
  StreamProtocolError,
  eventsFromTurnResult,
  parseStreamEvent,
  runTurn,
  type RawSseEvent,
} from './stream';
import {
  CONVERSATION_ID,
  EXECUTION_ID,
  MESSAGE_ID,
  TABLE_CARD,
  TURN_ID,
  completedTurnFrames,
  execution,
  sseFrame,
  streamOf,
} from './test-data';
import { newPendingTurn, reduceTurn } from './turn-state';
import type { AssistantStreamEvent, TurnResult } from './types';

function collect(chunks: readonly string[], max?: number): RawSseEvent[] {
  const events: RawSseEvent[] = [];
  const parser = new SseParser((event) => events.push(event), max);
  for (const chunk of chunks) parser.push(chunk);
  parser.end();
  return events;
}

const SAMPLE =
  ': heartbeat\n\n' +
  'event: turn.started\ndata: {"turnId":"t1","conversationId":"c1","seq":1}\n\n' +
  'event: text.delta\r\ndata: {"text":"Hel"}\r\n\r\n' +
  'event: text.delta\rdata: {"text":"lo"}\r\r' +
  'id: 7\nretry: 100\nunknown: x\nnovalue\nevent: turn.completed\ndata: {"turnId":"t1",\ndata: "status":"completed","usage":{"inputTokens":1,"outputTokens":2},"messageId":"m1"}\n\n';

describe('SseParser (assistant-stream/1)', () => {
  it('parses events, CR/LF/CRLF line ends, comments, unknown fields and multi-line data', () => {
    const events = collect([SAMPLE]);
    expect(events.map((e) => e.event)).toEqual([
      'turn.started',
      'text.delta',
      'text.delta',
      'turn.completed',
    ]);
    expect(events[3]?.data).toBe(
      '{"turnId":"t1",\n"status":"completed","usage":{"inputTokens":1,"outputTokens":2},"messageId":"m1"}',
    );
    expect(JSON.parse(events[3]?.data ?? '')).toMatchObject({ messageId: 'm1' });
  });

  it('gives the same events however the stream is split (every boundary, one char at a time)', () => {
    const whole = collect([SAMPLE]);
    expect(collect([...SAMPLE])).toEqual(whole);
    for (let cut = 1; cut < SAMPLE.length; cut += 7) {
      expect(collect([SAMPLE.slice(0, cut), SAMPLE.slice(cut)]), `cut at ${cut}`).toEqual(whole);
    }
    // A CRLF split exactly between CR and LF is one line end, not two (no empty event).
    expect(collect(['data: {"text":"a"}\r', '\n\r', '\n'])).toEqual([
      { event: 'message', data: '{"text":"a"}' },
    ]);
  });

  it('ignores heartbeats and data-less blocks, drops an unterminated event at the end', () => {
    expect(collect([': heartbeat\n\n: heartbeat\n\nevent: text.delta\n\n'])).toEqual([]);
    expect(collect(['event: text.delta\ndata: {"text":"cut"}'])).toEqual([]);
  });

  it('refuses an event larger than the limit, even when it never ends a line', () => {
    expect(() => collect([`data: ${'x'.repeat(200)}\n\n`], 100)).toThrow(StreamProtocolError);
    expect(() => collect(['data: ', 'y'.repeat(150)], 100)).toThrow(/size limit/);
    expect(() => collect([`data: ${'z'.repeat(60)}\ndata: ${'z'.repeat(60)}\n`], 100)).toThrow(
      StreamProtocolError,
    );
    expect(MAX_EVENT_CHARS).toBeGreaterThanOrEqual(64 * 1024);
  });
});

describe('parseStreamEvent', () => {
  it('validates the known events and skips malformed or unknown ones', () => {
    expect(parseStreamEvent({ event: 'text.delta', data: '{"text":"hi"}' })).toEqual({
      type: 'text.delta',
      text: 'hi',
    });
    expect(parseStreamEvent({ event: 'text.delta', data: '{"text":' })).toBeNull();
    expect(parseStreamEvent({ event: 'text.delta', data: '{"text":3}' })).toBeNull();
    expect(parseStreamEvent({ event: 'confirmation.required', data: '{}' })).toBeNull();
    expect(parseStreamEvent({ event: 'message', data: '{"text":"x"}' })).toBeNull();
    expect(parseStreamEvent({ event: '__proto__', data: '{}' })).toBeNull();
    const completed = parseStreamEvent({
      event: 'tool.completed',
      data: JSON.stringify({
        executionId: EXECUTION_ID,
        status: 'succeeded',
        decision: 'allowed',
        card: TABLE_CARD,
      }),
    });
    expect(completed).toMatchObject({ type: 'tool.completed', card: { kind: 'table' } });
    expect(
      parseStreamEvent({
        event: 'tool.completed',
        data: JSON.stringify({
          executionId: EXECUTION_ID,
          status: 'succeeded',
          decision: 'allowed',
          card: { ...TABLE_CARD, version: 'assistant-card/9' },
        }),
      }),
    ).toBeNull();
  });
});

describe('turn reducer', () => {
  it('builds text, tool chips and the outcome from the event order', () => {
    let turn = newPendingTurn({ clientTurnId: 'x', conversationId: CONVERSATION_ID, message: 'q' });
    const events: AssistantStreamEvent[] = [
      { type: 'turn.started', turnId: TURN_ID, conversationId: CONVERSATION_ID, seq: 1 },
      {
        type: 'tool.started',
        executionId: 'e1',
        tool: 'policy_management_list',
        title: 'Policies',
      },
      { type: 'tool.started', executionId: 'e2', tool: 'platform_x', title: 'Platform' },
      {
        type: 'tool.denied',
        executionId: 'e2',
        tool: 'platform_x',
        decision: 'denied_permission',
        message: 'no',
      },
      { type: 'text.delta', text: 'Hello ' },
      { type: 'tool.started', executionId: 'e3', tool: 'slow', title: 'Slow' },
      { type: 'text.delta', text: 'world' },
      {
        type: 'turn.failed',
        turnId: TURN_ID,
        code: 'assistant_turn_limit',
        message: 'limit',
      },
      { type: 'text.delta', text: 'ignored after the end' },
    ];
    for (const event of events) turn = reduceTurn(turn, event);
    expect(turn.text).toBe('Hello world');
    expect(turn.tools.map((t) => [t.executionId, t.state])).toEqual([
      ['e1', 'failed'],
      ['e2', 'denied'],
      ['e3', 'failed'],
    ]);
    expect(turn.status).toBe('failed');
    expect(turn.error?.code).toBe('assistant_turn_limit');
  });
});

const TURN_RESULT: TurnResult = {
  turn: {
    id: TURN_ID,
    conversationId: CONVERSATION_ID,
    seq: 1,
    status: 'completed',
    errorCode: null,
    provider: 'fake',
    model: 'fake-model',
    responseModel: null,
    rounds: 2,
    toolCalls: 2,
    usage: { inputTokens: 10, outputTokens: 5, cacheReadTokens: 0, cacheWriteTokens: 0 },
    latencyMs: 300,
    startedAt: '2026-11-20T09:00:00.000Z',
    finishedAt: '2026-11-20T09:00:01.000Z',
  },
  message: {
    id: MESSAGE_ID,
    turnId: TURN_ID,
    seq: 2,
    role: 'assistant',
    content: 'Done.',
    createdAt: '2026-11-20T09:00:01.000Z',
  },
  executions: [
    execution(TABLE_CARD),
    execution(null, {
      id: '01930000-0000-7000-8000-00000000e399',
      decision: 'denied_permission',
      status: 'refused',
      errorCode: 'forbidden',
    }),
  ],
};

describe('runTurn', () => {
  it('POSTs with accept text/event-stream and CSRF, and streams events in order', async () => {
    document.cookie = 'eg_csrf=csrf-token-1; path=/';
    let seen: { accept: string | null; csrf: string | null; body: unknown } | null = null;
    mockApi({
      AssistantTurnsController_create_v1: ({ request, body, params }) => {
        expect(params.conversationId).toBe(CONVERSATION_ID);
        seen = {
          accept: request.headers.get('accept'),
          csrf: request.headers.get('x-csrf-token'),
          body,
        };
        const text = completedTurnFrames().join('');
        // Arbitrary chunk boundaries, including inside a JSON string and a multi-byte character.
        return new HttpResponse(
          streamOf([text.slice(0, 33), text.slice(33, 140), text.slice(140)]),
          {
            headers: { 'content-type': 'text/event-stream; charset=utf-8' },
          },
        );
      },
    });
    const events: AssistantStreamEvent[] = [];
    const outcome = await runTurn(
      {
        conversationId: CONVERSATION_ID,
        clientTurnId: '5f0c2c1e-8b8a-4f7e-9a0e-2d3c4b5a6f70',
        message: 'Which policies are active?',
        timeZone: 'Asia/Kolkata',
      },
      { onEvent: (event) => events.push(event) },
    );
    expect(outcome).toEqual({ kind: 'completed', turnId: TURN_ID, messageId: MESSAGE_ID });
    expect(events.map((e) => e.type)).toEqual([
      'turn.started',
      'tool.started',
      'tool.completed',
      'text.delta',
      'text.delta',
      'turn.completed',
    ]);
    expect(seen!.accept).toContain('text/event-stream');
    expect(seen!.csrf).toBe('csrf-token-1');
    expectRequestMatchesContract('AssistantTurnsController_create_v1', seen!.body);
  });

  it('falls back to the JSON answer when the response is not an event stream', async () => {
    mockApi({ AssistantTurnsController_create_v1: () => okJson(TURN_RESULT) });
    const events: AssistantStreamEvent[] = [];
    const outcome = await runTurn(
      { conversationId: CONVERSATION_ID, clientTurnId: crypto.randomUUID(), message: 'q' },
      { onEvent: (event) => events.push(event) },
    );
    expect(outcome.kind).toBe('completed');
    expect(events.map((e) => e.type)).toEqual([
      'turn.started',
      'tool.completed',
      'tool.denied',
      'text.delta',
      'turn.completed',
    ]);
    expect(
      eventsFromTurnResult({
        ...TURN_RESULT,
        turn: { ...TURN_RESULT.turn, status: 'failed', errorCode: 'assistant_refused' },
      }).at(-1),
    ).toMatchObject({
      type: 'turn.failed',
      code: 'assistant_refused',
    });
  });

  it('recovers a broken stream from the stored turn (same clientTurnId, JSON), waiting while it runs', async () => {
    const clientTurnId = crypto.randomUUID();
    const calls: { accept: string | null; clientTurnId: unknown }[] = [];
    mockApi({
      AssistantTurnsController_create_v1: ({ request, body }) => {
        calls.push({
          accept: request.headers.get('accept'),
          clientTurnId: (body as { clientTurnId: string }).clientTurnId,
        });
        if (calls.length === 1) {
          return new HttpResponse(
            streamOf(
              [
                sseFrame('turn.started', {
                  turnId: TURN_ID,
                  conversationId: CONVERSATION_ID,
                  seq: 1,
                }),
                sseFrame('text.delta', { text: 'partial' }),
              ],
              { failAfter: true },
            ),
            { headers: { 'content-type': 'text/event-stream' } },
          );
        }
        if (calls.length === 2) return apiErrorJson(409, 'assistant_turn_in_progress');
        return okJson(TURN_RESULT);
      },
    });
    const sleep = vi.fn(() => Promise.resolve());
    const events: AssistantStreamEvent[] = [];
    const outcome = await runTurn(
      { conversationId: CONVERSATION_ID, clientTurnId, message: 'q' },
      { onEvent: (event) => events.push(event), sleep },
    );
    expect(outcome.kind).toBe('completed');
    expect(calls.map((c) => c.clientTurnId)).toEqual([clientTurnId, clientTurnId, clientTurnId]);
    expect(calls[1]?.accept).toBe('application/json');
    expect(sleep).toHaveBeenCalledTimes(1);
    // The replay starts again with turn.started, so the consumer rebuilds the turn.
    const replayed = newPendingTurn({
      clientTurnId,
      conversationId: CONVERSATION_ID,
      message: 'q',
    });
    const final = events.reduce(reduceTurn, replayed);
    expect(final.text).toBe('Done.');
    expect(final.status).toBe('completed');
  });

  it('rejects with the coded ApiError when the api refuses the turn', async () => {
    mockApi({
      AssistantTurnsController_create_v1: () =>
        apiErrorJson(429, 'assistant_budget_exhausted', 'Budget used', {
          extra: { scope: 'tenant' },
        }),
    });
    const error = await runTurn(
      { conversationId: CONVERSATION_ID, clientTurnId: crypto.randomUUID(), message: 'q' },
      { onEvent: () => undefined },
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 429, code: 'assistant_budget_exhausted' });
  });

  it('fails a stream that ends before turn.started without a retry', async () => {
    let calls = 0;
    mockApi({
      AssistantTurnsController_create_v1: () => {
        calls += 1;
        return new HttpResponse(streamOf([': heartbeat\n\n']), {
          headers: { 'content-type': 'text/event-stream' },
        });
      },
    });
    await expect(
      runTurn(
        { conversationId: CONVERSATION_ID, clientTurnId: crypto.randomUUID(), message: 'q' },
        { onEvent: () => undefined },
      ),
    ).rejects.toMatchObject({ code: 'stream_ended' });
    expect(calls).toBe(1);
  });

  it('stops with an AbortError when the caller aborts', async () => {
    mockApi({
      AssistantTurnsController_create_v1: () =>
        new HttpResponse(
          new ReadableStream({
            start(controller) {
              controller.enqueue(
                new TextEncoder().encode(
                  sseFrame('turn.started', {
                    turnId: TURN_ID,
                    conversationId: CONVERSATION_ID,
                    seq: 1,
                  }),
                ),
              );
            },
          }),
          { headers: { 'content-type': 'text/event-stream' } },
        ),
    });
    const controller = new AbortController();
    const promise = runTurn(
      { conversationId: CONVERSATION_ID, clientTurnId: crypto.randomUUID(), message: 'q' },
      {
        signal: controller.signal,
        onEvent: (event) => {
          if (event.type === 'turn.started') controller.abort();
        },
      },
    );
    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });
});
