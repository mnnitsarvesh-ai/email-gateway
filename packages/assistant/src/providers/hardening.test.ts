import { describe, expect, it } from 'vitest';
import { AnthropicProvider } from './anthropic';
import { countsTowardBreaker, ProviderBreaker, type CounterStore } from './breaker';
import { createLlmProvider } from './factory';
import { FAKE_STREAM_CHUNKS, FakeProvider, fakeChunks } from './fake';
import { META_TOOLS } from './meta-tools';
import { AzureOpenAiProvider, OpenAiProvider } from './openai-compatible';
import {
  PROVIDER_ROLES,
  breakerKeyFor,
  createProviderFromSpec,
  isSwitchableFailure,
  type ProviderCommonOptions,
} from './routing';
import { LLM_ERROR_REASONS, LlmError, reasonOfStatus, type LlmRequest } from './types';

/**
 * Step AI-6 (design 34 D6, D7, D11): the `auth` reason, provider probes (injected fetch only:
 * no network, synthetic keys that match no secret pattern), routing helpers and the fake's
 * latency and failure options.
 */

const TENANT_KEY = 'test-tenant-key-0001-not-a-secret';
const ORG = '0193aaaa-0000-7000-8000-00000000000a';

interface Captured {
  url: string;
  method: string;
  headers: Headers;
}

function recordingFetch(respond: (call: Captured) => Response | Promise<Response>) {
  const calls: Captured[] = [];
  const fetch = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const call: Captured = {
      url: String(input instanceof Request ? input.url : input),
      method: init?.method ?? (input instanceof Request ? input.method : 'GET'),
      headers: new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)),
    };
    calls.push(call);
    const signal = init?.signal;
    if (signal?.aborted) return Promise.reject(new DOMException('aborted', 'AbortError'));
    const aborted = new Promise<never>((_resolve, reject) =>
      signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))),
    );
    return Promise.race([Promise.resolve(respond(call)), aborted]);
  };
  return { fetch, calls };
}

const json = (status: number, body: unknown = {}, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

const signal = () => new AbortController().signal;

const probeError = (promise: Promise<void>) =>
  promise.then(
    () => null,
    (e: unknown) => e as LlmError,
  );

describe('LlmError reason auth (D6/D7)', () => {
  it('is appended to the reasons; 401/403 map to it; it is neither retryable nor a breaker failure', () => {
    expect(LLM_ERROR_REASONS.at(-1)).toBe('auth');
    expect(LLM_ERROR_REASONS.slice(0, -1)).toEqual([
      'timeout',
      'aborted',
      'rate_limited',
      'server_error',
      'client_error',
      'connection',
      'refusal',
      'schema',
      'unexpected',
    ]);
    expect(reasonOfStatus(401)).toBe('auth');
    expect(reasonOfStatus(403)).toBe('auth');
    expect(reasonOfStatus(404)).toBe('client_error');
    expect(reasonOfStatus(429)).toBe('rate_limited');
    expect(reasonOfStatus(502)).toBe('server_error');
    const error = new LlmError('auth', { httpStatus: 401 });
    expect(error.retryable).toBe(false);
    expect(countsTowardBreaker(error)).toBe(false);
  });
});

describe('AnthropicProvider.probe (models.retrieve through the SDK)', () => {
  const provider = (
    respond: (call: Captured) => Response | Promise<Response>,
    timeoutMs = 5_000,
  ) => {
    const recorded = recordingFetch(respond);
    return {
      calls: recorded.calls,
      provider: new AnthropicProvider({
        apiKey: TENANT_KEY,
        model: 'claude-opus-5-5',
        effort: 'low',
        refusalFallback: 'default',
        timeoutMs,
        baseURL: 'https://llm.example.test',
        fetch: recorded.fetch,
      }),
    };
  };

  it('GET /v1/models/{model} with the key; resolves on 200', async () => {
    const { provider: p, calls } = provider(() =>
      json(200, {
        type: 'model',
        id: 'claude-opus-5-5',
        display_name: 'fixture',
        created_at: '2026-01-01T00:00:00Z',
      }),
    );
    await expect(p.probe(signal())).resolves.toBeUndefined();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.method).toBe('GET');
    expect(new URL(calls[0]!.url).pathname).toBe('/v1/models/claude-opus-5-5');
    expect(calls[0]!.headers.get('authorization')).toBe(`Bearer ${TENANT_KEY}`);
  });

  it('classifies 401/403 → auth, 429, 5xx, connection and timeout (one call, no retries)', async () => {
    for (const [status, reason] of [
      [401, 'auth'],
      [403, 'auth'],
      [404, 'client_error'],
      [429, 'rate_limited'],
      [503, 'server_error'],
    ] as const) {
      const { provider: p, calls } = provider(() =>
        json(status, { type: 'error', error: { type: 'x', message: 'fixture provider text' } }),
      );
      const error = await probeError(p.probe(signal()));
      expect(error, String(status)).toMatchObject({ reason, httpStatus: status });
      expect(error!.message).not.toContain('fixture');
      expect(calls).toHaveLength(1);
    }
    const down = provider(() => Promise.reject(new TypeError('fetch failed')));
    expect((await probeError(down.provider.probe(signal())))!.reason).toBe('connection');
    const slow = provider(() => new Promise<Response>(() => undefined), 30);
    expect((await probeError(slow.provider.probe(signal())))!.reason).toBe('timeout');
  });
});

describe('OpenAiProvider.probe (GET {base}/models/{model})', () => {
  const provider = (
    respond: (call: Captured) => Response | Promise<Response>,
    timeoutMs = 5_000,
  ) => {
    const recorded = recordingFetch(respond);
    return {
      calls: recorded.calls,
      provider: new OpenAiProvider({
        apiKey: TENANT_KEY,
        model: 'gpt-fixture/1',
        baseURL: 'https://llm.example.test/v1/',
        timeoutMs,
        fetch: recorded.fetch,
      }),
    };
  };

  it('sends a bearer GET to the encoded model path and discards the body', async () => {
    const { provider: p, calls } = provider(() => json(200, { id: 'gpt-fixture/1' }));
    await expect(p.probe(signal())).resolves.toBeUndefined();
    expect(calls).toEqual([
      expect.objectContaining({
        url: 'https://llm.example.test/v1/models/gpt-fixture%2F1',
        method: 'GET',
      }),
    ]);
    expect(calls[0]!.headers.get('authorization')).toBe(`Bearer ${TENANT_KEY}`);
  });

  it('classifies statuses, transport failures, timeouts and caller aborts', async () => {
    for (const [status, reason] of [
      [401, 'auth'],
      [403, 'auth'],
      [404, 'client_error'],
      [500, 'server_error'],
    ] as const) {
      const error = await probeError(
        provider(() =>
          json(status, { error: { message: 'fixture provider text' } }),
        ).provider.probe(signal()),
      );
      expect(error, String(status)).toMatchObject({ reason, httpStatus: status });
      expect(error!.message).not.toContain('fixture');
    }
    const limited = await probeError(
      provider(() => json(429, {}, { 'retry-after': '3' })).provider.probe(signal()),
    );
    expect(limited).toMatchObject({ reason: 'rate_limited', retryAfterMs: 3000 });
    expect(
      (await probeError(
        provider(() => Promise.reject(new TypeError('x'))).provider.probe(signal()),
      ))!.reason,
    ).toBe('connection');
    expect(
      (await probeError(
        provider(() => new Promise<Response>(() => undefined), 30).provider.probe(signal()),
      ))!.reason,
    ).toBe('timeout');
    const controller = new AbortController();
    const pending = probeError(
      provider(() => new Promise<Response>(() => undefined)).provider.probe(controller.signal),
    );
    controller.abort();
    expect((await pending)!.reason).toBe('aborted');
  });

  it('Azure OpenAI has no probe; the fake resolves', async () => {
    const azure = new AzureOpenAiProvider({
      apiKey: TENANT_KEY,
      endpoint: 'https://resource.example.test',
      deployment: 'dep',
      apiVersion: '2026-01-01',
      timeoutMs: 1000,
    });
    expect((azure as { probe?: unknown }).probe).toBeUndefined();
    await expect(new FakeProvider({ nodeEnv: 'test' }).probe(signal())).resolves.toBeUndefined();
  });
});

describe('routing helpers (D6)', () => {
  it('breakerKeyFor: provider id, :fb for the secondary, t:<org> for a tenant key', async () => {
    expect(PROVIDER_ROLES).toEqual(['primary', 'fallback', 'tenant']);
    expect(breakerKeyFor('primary', 'anthropic')).toBe('anthropic');
    expect(breakerKeyFor('fallback', 'anthropic')).toBe('anthropic:fb');
    expect(breakerKeyFor('tenant', 'openai', ORG)).toBe(`t:${ORG}`);
    expect(() => breakerKeyFor('tenant', 'openai')).toThrow();
    expect(() => breakerKeyFor('primary', 'bad key')).toThrow();
    // the ProviderBreaker adds its prefix: as:brk:anthropic:fb, as:brk:t:<org>
    const keys: string[] = [];
    const store: CounterStore = {
      incrWithTtl: (key) => {
        keys.push(key);
        return Promise.resolve(1);
      },
      get: () => Promise.resolve(null),
    };
    const breaker = new ProviderBreaker(store, { threshold: 3, resetMs: 30_000 });
    await breaker.recordFailure(breakerKeyFor('fallback', 'anthropic'));
    await breaker.recordFailure(breakerKeyFor('tenant', 'anthropic', ORG));
    expect(keys).toEqual(['as:brk:anthropic:fb', `as:brk:t:${ORG}`]);
  });

  it('isSwitchableFailure: breaker-qualifying failures before any delta only', () => {
    for (const reason of ['connection', 'timeout', 'rate_limited', 'server_error'] as const) {
      expect(isSwitchableFailure(new LlmError(reason)), reason).toBe(true);
      expect(isSwitchableFailure(new LlmError(reason, { afterDelta: true })), reason).toBe(false);
    }
    for (const reason of [
      'auth',
      'client_error',
      'refusal',
      'schema',
      'aborted',
      'unexpected',
    ] as const)
      expect(isSwitchableFailure(new LlmError(reason)), reason).toBe(false);
    expect(isSwitchableFailure(new Error('x'))).toBe(false);
    expect(isSwitchableFailure(null)).toBe(false);
  });

  const common: ProviderCommonOptions = {
    effort: 'low',
    refusalFallback: 'off',
    timeoutMs: 5_000,
    nodeEnv: 'test',
  };

  it('createProviderFromSpec builds each provider with the spec key and the shared options', async () => {
    const recorded = recordingFetch(() => json(200, { id: 'x' }));
    const anthropic = createProviderFromSpec(
      {
        role: 'tenant',
        provider: 'anthropic',
        model: 'claude-sonnet-5-5',
        apiKey: TENANT_KEY,
        baseURL: 'https://llm.example.test',
        organizationPublicId: ORG,
      },
      { ...common, fetch: recorded.fetch },
    );
    expect(anthropic).toBeInstanceOf(AnthropicProvider);
    expect(anthropic.model).toBe('claude-sonnet-5-5');
    await anthropic.probe!(signal());
    expect(recorded.calls[0]!.headers.get('authorization')).toBe(`Bearer ${TENANT_KEY}`);

    const openai = createProviderFromSpec(
      { role: 'fallback', provider: 'openai', model: 'gpt-fixture-1', apiKey: TENANT_KEY },
      { ...common, fetch: recorded.fetch },
    );
    expect(openai).toBeInstanceOf(OpenAiProvider);
    await openai.probe!(signal());
    expect(recorded.calls[1]!.url).toBe('https://api.openai.com/v1/models/gpt-fixture-1');

    const azure = createProviderFromSpec(
      {
        role: 'primary',
        provider: 'azure_openai',
        model: 'ignored',
        apiKey: TENANT_KEY,
        azureEndpoint: 'https://resource.example.test',
        azureDeployment: 'dep-1',
        azureApiVersion: '2026-01-01',
      },
      common,
    );
    expect(azure).toBeInstanceOf(AzureOpenAiProvider);
    expect(azure.model).toBe('dep-1');

    const fake = createProviderFromSpec(
      { role: 'fallback', provider: 'fake', model: 'fake-secondary' },
      { ...common, fakeFailure: 'server_error' },
    );
    expect(fake).toBeInstanceOf(FakeProvider);
    expect(fake.model).toBe('fake-secondary');
    await expect(fake.probe!(signal())).rejects.toMatchObject({ reason: 'server_error' });
  });

  it('refuses a tenant spec for Azure/fake or without an organization, missing keys and fake in production', () => {
    expect(() =>
      createProviderFromSpec(
        {
          role: 'tenant',
          provider: 'azure_openai',
          model: 'm',
          apiKey: TENANT_KEY,
          organizationPublicId: ORG,
        },
        common,
      ),
    ).toThrow(/not offered/);
    expect(() =>
      createProviderFromSpec(
        { role: 'tenant', provider: 'anthropic', model: 'm', apiKey: TENANT_KEY },
        common,
      ),
    ).toThrow(/organization/);
    expect(() =>
      createProviderFromSpec({ role: 'primary', provider: 'anthropic', model: 'm' }, common),
    ).toThrow(/API_KEY/);
    expect(() =>
      createProviderFromSpec(
        { role: 'primary', provider: 'fake', model: 'fake' },
        { ...common, nodeEnv: 'production' },
      ),
    ).toThrow(/refused/);
  });
});

describe('fake provider latency and failure (D6, D11)', () => {
  const request = (text: string): LlmRequest => ({
    system: 'PROMPT',
    transcript: [{ role: 'user', text }],
    tools: META_TOOLS,
    maxOutputTokens: 256,
  });

  it('latencyMs delays the first delta deterministically and streams the text in chunks', async () => {
    const provider = createLlmProvider({
      provider: 'fake',
      model: 'fake',
      effort: 'low',
      refusalFallback: 'off',
      timeoutMs: 1_000,
      nodeEnv: 'test',
      fakeLatencyMs: 40,
    });
    const deltas: Array<{ text: string; at: number }> = [];
    const started = Date.now();
    const response = await provider.complete(request('/text hello there, general'), signal(), (t) =>
      deltas.push({ text: t, at: Date.now() - started }),
    );
    expect(response.text).toBe('hello there, general');
    expect(deltas.map((d) => d.text).join('')).toBe(response.text);
    expect(deltas.length).toBeGreaterThan(1);
    expect(deltas.length).toBeLessThanOrEqual(FAKE_STREAM_CHUNKS);
    expect(deltas[0]!.at).toBeGreaterThanOrEqual(35);
    expect(fakeChunks('abcdefgh')).toEqual(['ab', 'cd', 'ef', 'gh']);
    expect(fakeChunks('abc')).toEqual(['a', 'b', 'c']);
    expect(fakeChunks('')).toEqual([]);
  });

  it('the delay is abortable; without latency the answer is one synchronous delta as before', async () => {
    const slow = new FakeProvider({ nodeEnv: 'test', latencyMs: 10_000 });
    const controller = new AbortController();
    const pending = slow.complete(request('/text x'), controller.signal, () => undefined);
    controller.abort();
    await expect(pending).rejects.toMatchObject({ reason: 'aborted' });
    const deltas: string[] = [];
    await new FakeProvider({ nodeEnv: 'test' }).complete(request('/text one two'), signal(), (t) =>
      deltas.push(t),
    );
    expect(deltas).toEqual(['one two']);
  });

  it('failure throws the reason before any delta, on complete and probe', async () => {
    for (const reason of ['server_error', 'auth', 'connection'] as const) {
      const provider = new FakeProvider({ nodeEnv: 'test', failure: reason });
      const deltas: string[] = [];
      const error = await provider
        .complete(request('/text hi'), signal(), (t) => deltas.push(t))
        .catch((e: unknown) => e as LlmError);
      expect(error).toBeInstanceOf(LlmError);
      expect(error).toMatchObject({ reason, afterDelta: false });
      expect(deltas).toEqual([]);
      await expect(provider.probe(signal())).rejects.toMatchObject({ reason });
    }
  });

  it('validates the options and stays refused in production', () => {
    expect(() => new FakeProvider({ nodeEnv: 'test', latencyMs: -1 })).toThrow();
    expect(() => new FakeProvider({ nodeEnv: 'test', latencyMs: 1.5 })).toThrow();
    expect(() => new FakeProvider({ nodeEnv: 'test', latencyMs: 60_001 })).toThrow();
    expect(
      () => new FakeProvider({ nodeEnv: 'test', failure: 'nope' as unknown as 'auth' }),
    ).toThrow();
    expect(() => new FakeProvider({ nodeEnv: 'production', latencyMs: 10 })).toThrow(/refused/);
  });
});
