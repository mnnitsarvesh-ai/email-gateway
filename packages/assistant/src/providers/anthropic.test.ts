import { describe, expect, it } from 'vitest';
import { AnthropicProvider, SERVER_SIDE_FALLBACK_BETA, type RefusalFallback } from './anthropic';
import { completeWithRetry } from './retry';
import { META_TOOLS } from './meta-tools';
import { LlmError, type LlmRequest } from './types';

/**
 * The provider never reaches the network: the SDK client gets an injected `fetch` that records
 * the request and answers with recorded synthetic SSE fixtures (no API key anywhere).
 */

interface Captured {
  url: string;
  headers: Headers;
  body: Record<string, unknown>;
}

const TEST_KEY = 'test-key-not-real';

function sse(events: Array<Record<string, unknown>>): string {
  return events
    .map((event) => `event: ${String(event.type)}\ndata: ${JSON.stringify(event)}\n\n`)
    .join('');
}

function messageStart(over: Record<string, unknown> = {}) {
  return {
    type: 'message_start',
    message: {
      id: 'msg_fixture',
      type: 'message',
      role: 'assistant',
      model: 'claude-opus-5-5',
      content: [],
      stop_reason: null,
      stop_sequence: null,
      stop_details: null,
      usage: {
        input_tokens: 1200,
        output_tokens: 1,
        cache_read_input_tokens: 800,
        cache_creation_input_tokens: 64,
      },
      ...over,
    },
  };
}

const textBlock = (index: number, parts: string[]) => [
  { type: 'content_block_start', index, content_block: { type: 'text', text: '' } },
  ...parts.map((text) => ({
    type: 'content_block_delta',
    index,
    delta: { type: 'text_delta', text },
  })),
  { type: 'content_block_stop', index },
];

const thinkingBlock = (index: number) => [
  {
    type: 'content_block_start',
    index,
    content_block: { type: 'thinking', thinking: '', signature: '' },
  },
  {
    type: 'content_block_delta',
    index,
    delta: { type: 'signature_delta', signature: 'sig-fixture-1' },
  },
  { type: 'content_block_stop', index },
];

const toolBlock = (index: number, id: string, name: string, json: string[]) => [
  {
    type: 'content_block_start',
    index,
    content_block: { type: 'tool_use', id, name, input: {} },
  },
  ...json.map((partial_json) => ({
    type: 'content_block_delta',
    index,
    delta: { type: 'input_json_delta', partial_json },
  })),
  { type: 'content_block_stop', index },
];

const end = (stopReason: string, stopDetails: unknown = null) => [
  {
    type: 'message_delta',
    delta: { stop_reason: stopReason, stop_sequence: null, stop_details: stopDetails },
    usage: { output_tokens: 57 },
  },
  { type: 'message_stop' },
];

const streamResponse = (events: Array<Record<string, unknown>>) =>
  new Response(sse(events), {
    status: 200,
    headers: { 'content-type': 'text/event-stream', 'request-id': 'req_fixture' },
  });

const errorResponse = (status: number, type: string, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ type: 'error', error: { type, message: 'fixture' } }), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

function setup(
  respond: (captured: Captured, call: number) => Response | Promise<Response>,
  options: { fallback?: RefusalFallback; timeoutMs?: number } = {},
) {
  const calls: Captured[] = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const captured: Captured = {
      url: String(input instanceof Request ? input.url : input),
      headers: new Headers(init?.headers),
      body: JSON.parse(typeof init?.body === 'string' ? init.body : '{}') as Record<
        string,
        unknown
      >,
    };
    calls.push(captured);
    const abortSignal = init?.signal;
    if (abortSignal?.aborted) throw new DOMException('aborted', 'AbortError');
    const aborted = new Promise<never>((_resolve, reject) =>
      abortSignal?.addEventListener('abort', () =>
        reject(new DOMException('aborted', 'AbortError')),
      ),
    );
    return Promise.race([Promise.resolve(respond(captured, calls.length)), aborted]);
  };
  const provider = new AnthropicProvider({
    apiKey: TEST_KEY,
    model: 'claude-opus-5-5',
    effort: 'low',
    refusalFallback: options.fallback ?? 'default',
    timeoutMs: options.timeoutMs ?? 20_000,
    fetch,
    now: () => Date.parse('2026-11-20T10:00:00Z'),
  });
  return { provider, calls };
}

const request: LlmRequest = {
  system: 'SYSTEM PROMPT FIXTURE',
  transcript: [{ role: 'user', content: [{ type: 'text', text: 'show active policies' }] }],
  tools: META_TOOLS,
  maxOutputTokens: 4096,
};
const signal = () => new AbortController().signal;

describe('AnthropicProvider request shape', () => {
  it('streams through the beta endpoint with cache_control, strict meta tools, auto tool choice, effort and the server-side fallback', async () => {
    const { provider, calls } = setup(() =>
      streamResponse([messageStart(), ...textBlock(0, ['Hi']), ...end('end_turn')]),
    );
    await provider.complete(request, signal(), () => undefined);
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toMatch(/\/v1\/messages\?beta=true$/);
    expect(call.headers.get('anthropic-beta')).toBe(SERVER_SIDE_FALLBACK_BETA);
    // SDK 1.1.0 sends the key as a bearer credential.
    expect(call.headers.get('authorization')).toBe(`Bearer ${TEST_KEY}`);
    expect(call.body).toMatchObject({
      model: 'claude-opus-5-5',
      max_tokens: 4096,
      stream: true,
      fallbacks: 'default',
      tool_choice: { type: 'auto' },
      output_config: { effort: 'low' },
      system: [
        { type: 'text', text: 'SYSTEM PROMPT FIXTURE', cache_control: { type: 'ephemeral' } },
      ],
      messages: request.transcript,
    });
    const tools = call.body.tools as Array<Record<string, unknown>>;
    expect(tools.map((tool) => tool.name)).toEqual(['describe_tool', 'call_tool']);
    for (const tool of tools) {
      expect(tool.strict).toBe(true);
      expect((tool.input_schema as Record<string, unknown>).additionalProperties).toBe(false);
    }
    for (const forbidden of ['thinking', 'temperature', 'top_p', 'top_k', 'betas', 'metadata'])
      expect(call.body, forbidden).not.toHaveProperty(forbidden);
  });

  it('refusal fallback off: plain messages endpoint without betas or fallbacks', async () => {
    const { provider, calls } = setup(
      () => streamResponse([messageStart(), ...textBlock(0, ['Hi']), ...end('end_turn')]),
      { fallback: 'off' },
    );
    await provider.complete(request, signal(), () => undefined);
    expect(calls[0]!.url).toMatch(/\/v1\/messages$/);
    expect(calls[0]!.headers.get('anthropic-beta')).toBeNull();
    expect(calls[0]!.body).not.toHaveProperty('fallbacks');
    expect(calls[0]!.body.tool_choice).toEqual({ type: 'auto' });
    expect(calls[0]!.body).not.toHaveProperty('thinking');
  });

  it('refuses to construct without an API key', () => {
    expect(
      () =>
        new AnthropicProvider({
          apiKey: '',
          model: 'claude-opus-5-5',
          effort: 'low',
          refusalFallback: 'off',
          timeoutMs: 1000,
        }),
    ).toThrow(/ASSISTANT_ANTHROPIC_API_KEY/);
  });

  it('builds native user and tool-result entries', () => {
    const { provider } = setup(() => errorResponse(500, 'api_error'));
    expect(provider.userEntry('hello')).toEqual([
      { role: 'user', content: [{ type: 'text', text: 'hello' }] },
    ]);
    expect(
      provider.toolResultEntries([
        { toolCallId: 'toolu_1', content: '{"a":1}', isError: false },
        { toolCallId: 'toolu_2', content: '{"b":2}', isError: true },
      ]),
    ).toEqual([
      {
        role: 'user',
        content: [
          { type: 'tool_result', tool_use_id: 'toolu_1', content: '{"a":1}' },
          { type: 'tool_result', tool_use_id: 'toolu_2', content: '{"b":2}', is_error: true },
        ],
      },
    ]);
  });
});

describe('AnthropicProvider responses', () => {
  it('streams text deltas, collects tool calls, preserves thinking blocks verbatim and maps usage', async () => {
    const { provider } = setup(() =>
      streamResponse([
        messageStart(),
        ...thinkingBlock(0),
        ...textBlock(1, ['Let me ', 'check.']),
        ...toolBlock(2, 'toolu_fixture_1', 'call_tool', [
          '{"name":"policy_management_list",',
          '"arguments":"{\\"status\\":\\"active\\"}"}',
        ]),
        ...end('tool_use'),
      ]),
    );
    const deltas: string[] = [];
    const response = await provider.complete(request, signal(), (text) => deltas.push(text));
    expect(deltas).toEqual(['Let me ', 'check.']);
    expect(response.stop).toBe('tool_use');
    expect(response.text).toBe('Let me check.');
    expect(response.toolCalls).toEqual([
      {
        id: 'toolu_fixture_1',
        name: 'call_tool',
        input: { name: 'policy_management_list', arguments: '{"status":"active"}' },
      },
    ]);
    expect(response.appendToTranscript).toEqual([
      {
        role: 'assistant',
        content: [
          { type: 'thinking', thinking: '', signature: 'sig-fixture-1' },
          { type: 'text', text: 'Let me check.' },
          {
            type: 'tool_use',
            id: 'toolu_fixture_1',
            name: 'call_tool',
            input: { name: 'policy_management_list', arguments: '{"status":"active"}' },
          },
        ],
      },
    ]);
    expect(response.usage).toEqual({
      inputTokens: 1200,
      outputTokens: 57,
      cacheReadTokens: 800,
      cacheWriteTokens: 64,
    });
    expect(response.responseModel).toBe('claude-opus-5-5');
  });

  it('reports the model that answered after a server-side fallback', async () => {
    const { provider } = setup(() =>
      streamResponse([
        messageStart(),
        {
          type: 'content_block_start',
          index: 0,
          content_block: {
            type: 'fallback',
            from: { model: 'claude-opus-5-5' },
            to: { model: 'claude-opus-4-8' },
          },
        },
        { type: 'content_block_stop', index: 0 },
        ...textBlock(1, ['Answer']),
        ...end('end_turn'),
      ]),
    );
    const response = await provider.complete(request, signal(), () => undefined);
    expect(response.responseModel).toBe('claude-opus-4-8');
    expect((response.appendToTranscript[0] as { content: unknown[] }).content).toHaveLength(2);
  });

  it('stop_reason refusal → LlmError(refusal) with the stop_details category, no content used', async () => {
    const { provider } = setup(() =>
      streamResponse([
        messageStart(),
        ...end('refusal', { type: 'refusal', category: 'cyber', explanation: null }),
      ]),
    );
    const error = await provider
      .complete(request, signal(), () => undefined)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(LlmError);
    expect(error).toMatchObject({ reason: 'refusal', category: 'cyber', httpStatus: null });
  });

  it('max_tokens → truncated text, an incomplete tool_use is never executed', async () => {
    const { provider } = setup(() =>
      streamResponse([
        messageStart(),
        ...textBlock(0, ['Partial']),
        ...toolBlock(1, 'toolu_cut', 'call_tool', ['{"name":"users_list"']),
        ...end('max_tokens'),
      ]),
    );
    const response = await provider.complete(request, signal(), () => undefined);
    expect(response.stop).toBe('max_tokens');
    expect(response.text).toBe('Partial');
    expect(response.toolCalls).toEqual([]);
  });

  it('pause_turn → stop pause_turn with the content to append', async () => {
    const { provider } = setup(() =>
      streamResponse([messageStart(), ...textBlock(0, ['Working']), ...end('pause_turn')]),
    );
    const response = await provider.complete(request, signal(), () => undefined);
    expect(response.stop).toBe('pause_turn');
    expect(response.appendToTranscript).toHaveLength(1);
  });
});

describe('AnthropicProvider errors (typed SDK classes, never message text)', () => {
  const failure = async (respond: () => Response | Promise<Response>, timeoutMs?: number) => {
    const { provider, calls } = setup(respond, { timeoutMs });
    const error = await provider
      .complete(request, signal(), () => undefined)
      .catch((e: unknown) => e as LlmError);
    return { error: error as LlmError, calls };
  };

  it('429 → rate_limited with retry-after, one call only (maxRetries 0)', async () => {
    const { error, calls } = await failure(() =>
      errorResponse(429, 'rate_limit_error', { 'retry-after': '1' }),
    );
    expect(calls).toHaveLength(1);
    expect(error).toMatchObject({ reason: 'rate_limited', httpStatus: 429, retryAfterMs: 1000 });
    expect(error.retryable).toBe(true);
    expect(error.message).not.toContain('fixture');
  });

  it('5xx → server_error; 400 → client_error (not retryable)', async () => {
    expect((await failure(() => errorResponse(529, 'overloaded_error'))).error).toMatchObject({
      reason: 'server_error',
      httpStatus: 529,
    });
    const bad = (await failure(() => errorResponse(400, 'invalid_request_error'))).error;
    expect(bad).toMatchObject({ reason: 'client_error', httpStatus: 400 });
    expect(bad.retryable).toBe(false);
  });

  it('401/403 → auth (step AI-6: a rejected key; not retryable)', async () => {
    for (const status of [401, 403]) {
      const { error, calls } = await failure(() =>
        errorResponse(status, status === 401 ? 'authentication_error' : 'permission_error'),
      );
      expect(calls).toHaveLength(1);
      expect(error).toMatchObject({ reason: 'auth', httpStatus: status });
      expect(error.retryable).toBe(false);
      expect(error.message).not.toContain('fixture');
    }
  });

  it('connection failure → connection; timeout → timeout; caller abort → aborted', async () => {
    expect(
      (
        await failure(() => {
          throw new TypeError('fetch failed');
        })
      ).error.reason,
    ).toBe('connection');
    const slow = await failure(
      () =>
        new Promise<Response>(() => {
          /* never answers */
        }),
      50,
    );
    expect(slow.error.reason).toBe('timeout');
    const controller = new AbortController();
    const { provider } = setup(
      () =>
        new Promise<Response>(() => {
          /* never answers */
        }),
    );
    const pending = provider.complete(request, controller.signal, () => undefined);
    controller.abort();
    expect(await pending.catch((e: unknown) => (e as LlmError).reason)).toBe('aborted');
  });

  it('a stream that breaks after a delta is not retryable', async () => {
    const encoder = new TextEncoder();
    const { provider } = setup(() => {
      let pulls = 0;
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          pulls += 1;
          if (pulls === 1)
            controller.enqueue(encoder.encode(sse([messageStart(), ...textBlock(0, ['Half'])])));
          else controller.error(new TypeError('socket closed'));
        },
      });
      return new Response(body, { headers: { 'content-type': 'text/event-stream' } });
    });
    const deltas: string[] = [];
    const error = (await provider
      .complete(request, signal(), (text) => deltas.push(text))
      .catch((e: unknown) => e)) as LlmError;
    expect(deltas).toEqual(['Half']);
    expect(error).toBeInstanceOf(LlmError);
    expect(error.afterDelta).toBe(true);
    expect(error.retryable).toBe(false);
  });
});

describe('completeWithRetry', () => {
  it('retries once after a 429 before any delta, waiting retry-after capped at 2 s', async () => {
    const waits: number[] = [];
    const { provider, calls } = setup((_captured, call) =>
      call === 1
        ? errorResponse(429, 'rate_limit_error', { 'retry-after': '30' })
        : streamResponse([messageStart(), ...textBlock(0, ['ok']), ...end('end_turn')]),
    );
    const response = await completeWithRetry(provider, request, signal(), () => undefined, {
      sleep: (ms) => {
        waits.push(ms);
        return Promise.resolve();
      },
    });
    expect(response.text).toBe('ok');
    expect(calls).toHaveLength(2);
    expect(waits).toEqual([2000]);
  });

  it('does not retry client errors or a second failure', async () => {
    const bad = setup(() => errorResponse(400, 'invalid_request_error'));
    await expect(
      completeWithRetry(bad.provider, request, signal(), () => undefined, {
        sleep: () => Promise.resolve(),
      }),
    ).rejects.toMatchObject({ reason: 'client_error' });
    expect(bad.calls).toHaveLength(1);
    const down = setup(() => errorResponse(503, 'api_error'));
    await expect(
      completeWithRetry(down.provider, request, signal(), () => undefined, {
        sleep: () => Promise.resolve(),
      }),
    ).rejects.toMatchObject({ reason: 'server_error' });
    expect(down.calls).toHaveLength(2);
  });
});
