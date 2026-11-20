import { describe, expect, it } from 'vitest';
import { META_TOOLS } from './meta-tools';
import {
  AzureOpenAiProvider,
  OpenAiProvider,
  SSE_MAX_LINE_BYTES,
  readSseData,
} from './openai-compatible';
import { LlmError, type LlmRequest } from './types';

/** Synthetic recorded Chat Completions SSE fixtures through an injected fetch; no network. */

const TEST_KEY = 'test-key-not-real';

interface Captured {
  url: string;
  headers: Headers;
  body: Record<string, unknown>;
}

const chunk = (choice: Record<string, unknown> | null, extra: Record<string, unknown> = {}) => ({
  id: 'chatcmpl-fixture',
  object: 'chat.completion.chunk',
  model: 'gpt-fixture-1',
  choices: choice ? [{ index: 0, ...choice }] : [],
  ...extra,
});

const sseBody = (chunks: unknown[], done = true) =>
  chunks.map((c) => `data: ${JSON.stringify(c)}\n\n`).join('') + (done ? 'data: [DONE]\n\n' : '');

const streamResponse = (text: string) =>
  new Response(text, { status: 200, headers: { 'content-type': 'text/event-stream' } });

function setup(
  respond: (captured: Captured, call: number) => Response | Promise<Response>,
  kind: 'openai' | 'azure' = 'openai',
  timeoutMs = 20_000,
) {
  const calls: Captured[] = [];
  const fetch = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({
      url: String(input instanceof Request ? input.url : input),
      headers: new Headers(init?.headers),
      body: JSON.parse(typeof init?.body === 'string' ? init.body : '{}') as Record<
        string,
        unknown
      >,
    });
    const signal = init?.signal;
    if (signal?.aborted) return Promise.reject(new DOMException('aborted', 'AbortError'));
    const aborted = new Promise<never>((_resolve, reject) =>
      signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))),
    );
    return Promise.race([Promise.resolve(respond(calls.at(-1)!, calls.length)), aborted]);
  };
  const provider =
    kind === 'openai'
      ? new OpenAiProvider({
          apiKey: TEST_KEY,
          model: 'gpt-fixture-1',
          baseURL: 'https://llm.example.test/v1/',
          timeoutMs,
          fetch,
        })
      : new AzureOpenAiProvider({
          apiKey: TEST_KEY,
          endpoint: 'https://resource.example.test/',
          deployment: 'assistant-deploy',
          apiVersion: '2026-01-01',
          timeoutMs,
          fetch,
        });
  return { provider, calls };
}

const request: LlmRequest = {
  system: 'SYSTEM PROMPT FIXTURE',
  transcript: [{ role: 'user', content: 'list domains' }],
  tools: META_TOOLS,
  maxOutputTokens: 2048,
};
const signal = () => new AbortController().signal;

const toolCallStream = sseBody([
  chunk({ delta: { role: 'assistant', content: 'Checking' }, finish_reason: null }),
  chunk({
    delta: {
      tool_calls: [
        {
          index: 0,
          id: 'call_a',
          type: 'function',
          function: { name: 'call_tool', arguments: '' },
        },
      ],
    },
    finish_reason: null,
  }),
  chunk({
    delta: { tool_calls: [{ index: 0, function: { arguments: '{"name":"domains_list",' } }] },
    finish_reason: null,
  }),
  chunk({
    delta: {
      tool_calls: [
        {
          index: 1,
          id: 'call_b',
          type: 'function',
          function: { name: 'describe_tool', arguments: '{"na' },
        },
      ],
    },
    finish_reason: null,
  }),
  chunk({
    delta: { tool_calls: [{ index: 0, function: { arguments: '"arguments":"{}"}' } }] },
    finish_reason: null,
  }),
  chunk({
    delta: { tool_calls: [{ index: 1, function: { arguments: 'me":"users_list"}' } }] },
    finish_reason: null,
  }),
  chunk({ delta: {}, finish_reason: 'tool_calls' }),
  chunk(null, {
    usage: {
      prompt_tokens: 900,
      completion_tokens: 40,
      prompt_tokens_details: { cached_tokens: 600 },
    },
  }),
]);

describe('OpenAiProvider', () => {
  it('posts the Chat Completions request with bearer auth, system first, strict functions, auto tool choice and streaming usage', async () => {
    const { provider, calls } = setup(() => streamResponse(toolCallStream));
    await provider.complete(request, signal(), () => undefined);
    const call = calls[0]!;
    expect(call.url).toBe('https://llm.example.test/v1/chat/completions');
    expect(call.headers.get('authorization')).toBe(`Bearer ${TEST_KEY}`);
    expect(call.headers.get('api-key')).toBeNull();
    expect(call.body).toMatchObject({
      model: 'gpt-fixture-1',
      messages: [{ role: 'system', content: 'SYSTEM PROMPT FIXTURE' }, ...request.transcript],
      tool_choice: 'auto',
      stream: true,
      stream_options: { include_usage: true },
      max_completion_tokens: 2048,
    });
    const tools = call.body.tools as Array<{ type: string; function: Record<string, unknown> }>;
    expect(tools.map((t) => [t.type, t.function.name, t.function.strict])).toEqual([
      ['function', 'describe_tool', true],
      ['function', 'call_tool', true],
    ]);
    for (const forbidden of ['temperature', 'top_p', 'max_tokens', 'functions'])
      expect(call.body).not.toHaveProperty(forbidden);
  });

  it('concatenates split tool-call argument chunks by index, maps usage and builds the transcript', async () => {
    const { provider } = setup(() => streamResponse(toolCallStream));
    const deltas: string[] = [];
    const response = await provider.complete(request, signal(), (text) => deltas.push(text));
    expect(deltas).toEqual(['Checking']);
    expect(response.stop).toBe('tool_use');
    expect(response.toolCalls).toEqual([
      { id: 'call_a', name: 'call_tool', input: { name: 'domains_list', arguments: '{}' } },
      { id: 'call_b', name: 'describe_tool', input: { name: 'users_list' } },
    ]);
    expect(response.usage).toEqual({
      inputTokens: 300,
      outputTokens: 40,
      cacheReadTokens: 600,
      cacheWriteTokens: 0,
    });
    expect(response.responseModel).toBe('gpt-fixture-1');
    expect(response.appendToTranscript).toEqual([
      {
        role: 'assistant',
        content: 'Checking',
        tool_calls: [
          {
            id: 'call_a',
            type: 'function',
            function: { name: 'call_tool', arguments: '{"name":"domains_list","arguments":"{}"}' },
          },
          {
            id: 'call_b',
            type: 'function',
            function: { name: 'describe_tool', arguments: '{"name":"users_list"}' },
          },
        ],
      },
    ]);
    expect(
      provider.toolResultEntries([{ toolCallId: 'call_a', content: '{"x":1}', isError: false }]),
    ).toEqual([{ role: 'tool', tool_call_id: 'call_a', content: '{"x":1}' }]);
    expect(provider.userEntry('hi')).toEqual([{ role: 'user', content: 'hi' }]);
  });

  it('maps finish reasons: stop → end_turn, length → max_tokens, content_filter → refusal', async () => {
    const run = (finish: string) =>
      setup(() =>
        streamResponse(
          sseBody([
            chunk({ delta: { content: 'Text' }, finish_reason: null }),
            chunk({ delta: {}, finish_reason: finish }),
          ]),
        ),
      ).provider.complete(request, signal(), () => undefined);
    expect((await run('stop')).stop).toBe('end_turn');
    expect((await run('length')).stop).toBe('max_tokens');
    await expect(run('content_filter')).rejects.toMatchObject({
      reason: 'refusal',
      category: 'content_filter',
    });
    await expect(run('mystery')).rejects.toMatchObject({ reason: 'schema' });
  });

  it('rejects malformed chunks and missing finish reasons (zod)', async () => {
    const bad = setup(() => streamResponse('data: {"choices":"nope"}\n\n'));
    await expect(bad.provider.complete(request, signal(), () => undefined)).rejects.toMatchObject({
      reason: 'schema',
    });
    const notJson = setup(() => streamResponse('data: {not json\n\n'));
    await expect(
      notJson.provider.complete(request, signal(), () => undefined),
    ).rejects.toMatchObject({ reason: 'schema' });
    const truncated = setup(() =>
      streamResponse(sseBody([chunk({ delta: { content: 'x' }, finish_reason: null })], false)),
    );
    const error = (await truncated.provider
      .complete(request, signal(), () => undefined)
      .catch((e: unknown) => e)) as LlmError;
    expect(error).toMatchObject({ reason: 'schema', afterDelta: true });
  });

  it('classifies error statuses without reading the body into the error', async () => {
    const status = (code: number, headers: Record<string, string> = {}) =>
      setup(
        () =>
          new Response(JSON.stringify({ error: { message: 'secret-looking provider text' } }), {
            status: code,
            headers,
          }),
      )
        .provider.complete(request, signal(), () => undefined)
        .then(
          () => new LlmError('unexpected'),
          (e: unknown) => e as LlmError,
        );
    expect(await status(429, { 'retry-after': '2' })).toMatchObject({
      reason: 'rate_limited',
      httpStatus: 429,
      retryAfterMs: 2000,
    });
    expect(await status(503)).toMatchObject({ reason: 'server_error', httpStatus: 503 });
    const client = await status(401);
    expect(client).toMatchObject({ reason: 'client_error', httpStatus: 401 });
    expect(client.message).not.toContain('provider text');
  });

  it('connection, timeout and abort', async () => {
    const connection = setup(() => Promise.reject(new TypeError('fetch failed')));
    await expect(
      connection.provider.complete(request, signal(), () => undefined),
    ).rejects.toMatchObject({ reason: 'connection' });
    const slow = setup(() => new Promise<Response>(() => undefined), 'openai', 30);
    await expect(slow.provider.complete(request, signal(), () => undefined)).rejects.toMatchObject({
      reason: 'timeout',
    });
    const controller = new AbortController();
    const pending = setup(() => new Promise<Response>(() => undefined)).provider.complete(
      request,
      controller.signal,
      () => undefined,
    );
    controller.abort();
    await expect(pending).rejects.toMatchObject({ reason: 'aborted' });
  });

  it('refuses to construct without a key', () => {
    expect(
      () => new OpenAiProvider({ apiKey: '', model: 'm', baseURL: 'https://x.test', timeoutMs: 1 }),
    ).toThrow(/ASSISTANT_OPENAI_API_KEY/);
  });
});

describe('AzureOpenAiProvider', () => {
  it('uses the deployment URL with api-version, the api-key header and no model in the body', async () => {
    const { provider, calls } = setup(() => streamResponse(toolCallStream), 'azure');
    const response = await provider.complete(request, signal(), () => undefined);
    const call = calls[0]!;
    expect(call.url).toBe(
      'https://resource.example.test/openai/deployments/assistant-deploy/chat/completions?api-version=2026-01-01',
    );
    expect(call.headers.get('api-key')).toBe(TEST_KEY);
    expect(call.headers.get('authorization')).toBeNull();
    expect(call.body).not.toHaveProperty('model');
    expect(call.body.tool_choice).toBe('auto');
    expect(provider.model).toBe('assistant-deploy');
    expect(response.toolCalls).toHaveLength(2);
  });

  it('requires endpoint, deployment and API version', () => {
    expect(
      () =>
        new AzureOpenAiProvider({
          apiKey: TEST_KEY,
          endpoint: 'https://x.test',
          deployment: '',
          apiVersion: 'v',
          timeoutMs: 1,
        }),
    ).toThrow(/deployment/);
  });
});

describe('readSseData (bounded)', () => {
  const stream = (parts: string[]) =>
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const part of parts) controller.enqueue(new TextEncoder().encode(part));
        controller.close();
      },
    });
  const collect = async (parts: string[], max = 1024 * 1024) => {
    const out: string[] = [];
    for await (const data of readSseData(stream(parts), max)) out.push(data);
    return out;
  };

  it('handles events split across chunks, CRLF, comments and multi-line data', async () => {
    expect(
      await collect([
        'data: {"a"',
        ':1}\r\n\r\n: comment\n',
        'event: x\ndata: l1\ndata: l2\n\n',
        'data: last',
      ]),
    ).toEqual(['{"a":1}', 'l1\nl2', 'last']);
  });

  it('rejects an oversized line and an oversized body', async () => {
    await expect(collect(['data: ' + 'x'.repeat(SSE_MAX_LINE_BYTES + 1)])).rejects.toBeInstanceOf(
      LlmError,
    );
    await expect(collect(['data: 1\n\n', 'data: 2\n\n'], 12)).rejects.toMatchObject({
      reason: 'schema',
    });
  });
});
