import { describe, expect, it } from 'vitest';
import { AnthropicProvider } from './anthropic';
import { ProviderBreaker, countsTowardBreaker, type CounterStore } from './breaker';
import { FakeProvider } from './fake';
import { createLlmProvider, type ProviderFactoryOptions } from './factory';
import { CALL_TOOL, DESCRIBE_TOOL, META_TOOLS, parseMetaToolInput } from './meta-tools';
import { AzureOpenAiProvider, OpenAiProvider } from './openai-compatible';
import { DEFAULT_MODEL_PRICES, costMicros, parseModelPrices } from './prices';
import { LlmError, parseRetryAfter } from './types';

describe('meta tools', () => {
  it('are strict-mode schemas: every property required, no additional properties', () => {
    expect(META_TOOLS.map((tool) => tool.name)).toEqual(['describe_tool', 'call_tool']);
    for (const tool of [DESCRIBE_TOOL, CALL_TOOL]) {
      const schema = tool.inputSchema as {
        properties: Record<string, unknown>;
        required: string[];
        additionalProperties: boolean;
      };
      expect(schema.additionalProperties).toBe(false);
      expect([...schema.required].sort()).toEqual(Object.keys(schema.properties).sort());
    }
  });

  it('parses and rejects model input', () => {
    expect(parseMetaToolInput('describe_tool', { name: 'users_list' })).toEqual({
      ok: true,
      meta: 'describe_tool',
      name: 'users_list',
    });
    expect(parseMetaToolInput('call_tool', { name: 'users_list', arguments: '' })).toMatchObject({
      ok: true,
      arguments: {},
    });
    expect(
      parseMetaToolInput('call_tool', { name: 'users_list', arguments: { status: 'active' } }),
    ).toMatchObject({ ok: true, arguments: { status: 'active' } });
    expect(parseMetaToolInput('call_tool', { name: 'users_list', arguments: '[1]' })).toMatchObject(
      { ok: false, error: 'invalid_arguments' },
    );
    expect(
      parseMetaToolInput('call_tool', { name: 'users_list', arguments: '{bad' }),
    ).toMatchObject({ ok: false, error: 'invalid_arguments' });
    expect(parseMetaToolInput('call_tool', { name: 'Users-List', arguments: '{}' })).toMatchObject({
      ok: false,
      error: 'invalid_meta_tool',
    });
    expect(
      parseMetaToolInput('call_tool', { name: 'users_list', arguments: '{}', extra: 1 }),
    ).toMatchObject({ ok: false });
    expect(parseMetaToolInput('run_shell', { name: 'x' })).toEqual({
      ok: false,
      meta: null,
      error: 'invalid_meta_tool',
    });
  });
});

describe('createLlmProvider', () => {
  const base: ProviderFactoryOptions = {
    provider: 'fake',
    model: 'claude-opus-5-5',
    effort: 'low',
    refusalFallback: 'default',
    timeoutMs: 1000,
    nodeEnv: 'test',
  };
  it('builds each provider from plain options', () => {
    expect(createLlmProvider(base)).toBeInstanceOf(FakeProvider);
    expect(
      createLlmProvider({ ...base, provider: 'anthropic', anthropicApiKey: 'test-key-not-real' }),
    ).toBeInstanceOf(AnthropicProvider);
    const openai = createLlmProvider({
      ...base,
      provider: 'openai',
      model: 'gpt-fixture-1',
      openaiApiKey: 'test-key-not-real',
    });
    expect(openai).toBeInstanceOf(OpenAiProvider);
    expect(openai.model).toBe('gpt-fixture-1');
    const azure = createLlmProvider({
      ...base,
      provider: 'azure_openai',
      azureApiKey: 'test-key-not-real',
      azureEndpoint: 'https://resource.example.test',
      azureDeployment: 'deploy-1',
      azureApiVersion: '2026-01-01',
    });
    expect(azure).toBeInstanceOf(AzureOpenAiProvider);
    expect(azure.id).toBe('azure_openai');
  });
  it('fails closed: fake in production, missing keys', () => {
    expect(() => createLlmProvider({ ...base, nodeEnv: 'production' })).toThrow(/production/);
    expect(() => createLlmProvider({ ...base, provider: 'anthropic' })).toThrow(/API_KEY/);
    expect(() => createLlmProvider({ ...base, provider: 'openai' })).toThrow(/API_KEY/);
  });
});

class MemoryCounters implements CounterStore {
  readonly values = new Map<string, number>();
  readonly ttls = new Map<string, number>();
  incrWithTtl(key: string, ttlSeconds: number): Promise<number> {
    const next = (this.values.get(key) ?? 0) + 1;
    this.values.set(key, next);
    if (!this.ttls.has(key)) this.ttls.set(key, ttlSeconds);
    return Promise.resolve(next);
  }
  get(key: string): Promise<string | null> {
    const value = this.values.get(key);
    return Promise.resolve(value === undefined ? null : String(value));
  }
  del(...keys: string[]): Promise<number> {
    let removed = 0;
    for (const key of keys) if (this.values.delete(key)) removed += 1;
    return Promise.resolve(removed);
  }
  expire(key: string): void {
    this.values.delete(key);
    this.ttls.delete(key);
  }
}

describe('ProviderBreaker', () => {
  it('opens after the threshold within the window and closes when the counter expires', async () => {
    const store = new MemoryCounters();
    const breaker = new ProviderBreaker(store, { threshold: 3, resetMs: 30_000 });
    expect(await breaker.isOpen('anthropic')).toBe(false);
    await breaker.recordFailure('anthropic');
    await breaker.recordFailure('anthropic');
    expect(await breaker.isOpen('anthropic')).toBe(false);
    expect(await breaker.recordFailure('anthropic')).toBe(3);
    expect(await breaker.isOpen('anthropic')).toBe(true);
    expect(await breaker.isOpen('openai')).toBe(false);
    expect(store.ttls.get('as:brk:anthropic')).toBe(30);
    store.expire('as:brk:anthropic');
    expect(await breaker.isOpen('anthropic')).toBe(false);
    await breaker.recordFailure('anthropic');
    await breaker.recordSuccess('anthropic');
    expect(await store.get('as:brk:anthropic')).toBeNull();
  });

  it('counts only availability failures', () => {
    expect(countsTowardBreaker(new LlmError('server_error', { httpStatus: 500 }))).toBe(true);
    expect(countsTowardBreaker(new LlmError('rate_limited', { httpStatus: 429 }))).toBe(true);
    expect(countsTowardBreaker(new LlmError('connection'))).toBe(true);
    expect(countsTowardBreaker(new LlmError('timeout'))).toBe(true);
    expect(countsTowardBreaker(new LlmError('client_error', { httpStatus: 400 }))).toBe(false);
    expect(countsTowardBreaker(new LlmError('refusal'))).toBe(false);
    expect(countsTowardBreaker(new LlmError('aborted'))).toBe(false);
    expect(countsTowardBreaker(new LlmError('auth', { httpStatus: 401 }))).toBe(false);
    expect(countsTowardBreaker(new Error('x'))).toBe(false);
  });

  it('rejects a bad threshold and propagates store errors (fail closed)', async () => {
    expect(() => new ProviderBreaker(new MemoryCounters(), { threshold: 0, resetMs: 1 })).toThrow();
    const failing: CounterStore = {
      incrWithTtl: () => Promise.reject(new Error('redis down')),
      get: () => Promise.reject(new Error('redis down')),
    };
    await expect(
      new ProviderBreaker(failing, { threshold: 1, resetMs: 1000 }).isOpen('fake'),
    ).rejects.toThrow('redis down');
  });
});

describe('prices', () => {
  const usage = {
    inputTokens: 1_000_000,
    outputTokens: 100_000,
    cacheReadTokens: 2_000_000,
    cacheWriteTokens: 400_000,
  };
  it('claude-opus-5-5: $4 / $20 / $0.20 cache read / 1.25× input cache write', () => {
    expect(DEFAULT_MODEL_PRICES['claude-opus-5-5']!.cacheWriteMicrosPerMTok).toBe(5_000_000);
    // 4 + 2 + 0.4 + 2 = 8.4 USD
    expect(costMicros('claude-opus-5-5', usage)).toBe(8_400_000);
  });
  it('claude-sonnet-5-5: $2 / $10 / $0.10 / 1.25×', () => {
    // 2 + 1 + 0.2 + 1 = 4.2 USD
    expect(costMicros('claude-sonnet-5-5', usage)).toBe(4_200_000);
  });
  it('unknown models cost null unless priced by ASSISTANT_MODEL_PRICES', () => {
    expect(costMicros('gpt-fixture-1', usage)).toBeNull();
    const overrides = parseModelPrices(
      JSON.stringify({
        'gpt-fixture-1': { inputMicrosPerMTok: 1_000_000, outputMicrosPerMTok: 4_000_000 },
      }),
    );
    expect(overrides['gpt-fixture-1']).toEqual({
      inputMicrosPerMTok: 1_000_000,
      outputMicrosPerMTok: 4_000_000,
      cacheReadMicrosPerMTok: 1_000_000,
      cacheWriteMicrosPerMTok: 1_250_000,
    });
    expect(costMicros('gpt-fixture-1', usage, overrides)).toBe(
      1_000_000 + 400_000 + 2_000_000 + 500_000,
    );
    expect(parseModelPrices(undefined)).toEqual({});
    expect(() =>
      parseModelPrices('{"m":{"inputMicrosPerMTok":-1,"outputMicrosPerMTok":1}}'),
    ).toThrow();
    expect(() => parseModelPrices('not json')).toThrow();
  });
});

describe('parseRetryAfter', () => {
  it('reads seconds and HTTP dates', () => {
    const now = Date.parse('2026-11-20T10:00:00Z');
    expect(parseRetryAfter('3', now)).toBe(3000);
    expect(parseRetryAfter('Fri, 20 Nov 2026 10:00:05 GMT', now)).toBe(5000);
    expect(parseRetryAfter('soon', now)).toBeNull();
    expect(parseRetryAfter(null, now)).toBeNull();
  });
});
