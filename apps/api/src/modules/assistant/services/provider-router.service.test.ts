import { FakeProvider, LlmError, type LlmProvider } from '@email-gateway/assistant';
import { MetricsService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import { testUser } from '../../../../test/support/assistant-fixtures';
import { stubbedApiEnv } from '../../../../test/support/api-test-app';
import { reply, ScriptedProvider } from '../../../../test/support/assistant-harness';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { loadApiConfig } from '../../../config';
import type { AssistantConfig } from '../assistant.constants';
import { AssistantMetrics } from './assistant-metrics';
import { AssistantProviderService, type TurnRoute } from './assistant-provider.service';
import type { ProviderFactorySpec } from './llm-provider-factory';
import type { TenantClient, TenantKeyService } from './tenant-key.service';

const ORG_PUBLIC = '0193b000-0000-7000-8000-000000007001';
const principal = testUser();
const scope = scopeFromPrincipal(principal);
const who = { organizationPublicId: ORG_PUBLIC };

function config(env: Record<string, string> = {}): AssistantConfig {
  return loadApiConfig(
    stubbedApiEnv({
      ASSISTANT_ENABLED: 'true',
      ASSISTANT_PROVIDER: 'fake',
      ASSISTANT_BREAKER_THRESHOLD: '2',
      ...env,
    }),
  );
}

/** A tenant-key double: a valid client of key version 3 unless `client` is null. */
function tenantKeys(client: Partial<TenantClient> | null = {}) {
  const invalidated: number[] = [];
  const service = {
    enabled: true,
    client: vi.fn(() =>
      Promise.resolve(
        client === null
          ? null
          : {
              provider: new FakeProvider({ nodeEnv: 'test', model: 'tenant-model' }),
              providerId: 'anthropic' as const,
              model: 'claude-sonnet-5-5',
              keyVersion: 3,
              ...client,
            },
      ),
    ),
    invalidate: vi.fn((_p: unknown, _s: unknown, version: number) => {
      invalidated.push(version);
      return Promise.resolve();
    }),
  } as unknown as TenantKeyService;
  return { service, invalidated };
}

function router(
  env: Record<string, string> = {},
  keys?: TenantKeyService,
  build: (spec: ProviderFactorySpec) => LlmProvider = (spec) =>
    new FakeProvider({ nodeEnv: 'test', model: spec.model }),
) {
  const kv = new InMemoryKeyValueStore();
  const registry = new MetricsService({ service: 'api-test' });
  const metrics = new AssistantMetrics(registry);
  const specs: ProviderFactorySpec[] = [];
  const service = new AssistantProviderService(
    config(env),
    (spec) => {
      specs.push(spec);
      return build(spec);
    },
    kv,
    metrics,
    keys,
  );
  const series = async (name: string) =>
    (await registry.metrics()).split('\n').filter((l) => l.startsWith(name));
  return { service, kv, specs, series };
}

const FALLBACK = {
  ASSISTANT_FALLBACK_PROVIDER: 'fake',
  ASSISTANT_FALLBACK_MODEL: 'fake-secondary',
};

const routeOf = async (
  r: ReturnType<typeof router>,
  settings: { useTenantKey?: boolean; tenantKeyFallbackToPlatform?: boolean } | null = null,
): Promise<TurnRoute> => {
  const selection = await r.service.select(scope, settings, who);
  if (selection.kind !== 'route') throw new Error(`no route: ${selection.kind}`);
  return selection.route;
};

describe('ProviderRouterService: candidates and breakers (step AI-6 D6, D7)', () => {
  it('orders tenant key → primary → secondary with one breaker key per role', async () => {
    const keys = tenantKeys();
    const r = router(FALLBACK, keys.service);
    const route = await routeOf(r, { useTenantKey: true, tenantKeyFallbackToPlatform: true });
    expect(
      route.candidates.map((c) => [c.role, c.providerId, c.model, c.breakerKey, c.keySource]),
    ).toEqual([
      ['tenant', 'anthropic', 'claude-sonnet-5-5', `t:${ORG_PUBLIC}`, 'tenant'],
      ['primary', 'fake', 'fake', 'fake', 'platform'],
      ['fallback', 'fake', 'fake-secondary', 'fake:fb', 'platform'],
    ]);
    expect(route.current.role).toBe('tenant');
    expect(route.fallbackFrom).toBeNull();
    // The platform factory is called once per role (cached); the tenant client comes from the
    // key service (its own cache).
    await routeOf(r, { useTenantKey: true, tenantKeyFallbackToPlatform: true });
    expect(r.specs.map((s) => [s.role, s.provider, s.model])).toEqual([
      ['primary', 'fake', 'fake'],
      ['fallback', 'fake', 'fake-secondary'],
    ]);
  });

  it('keeps a tenant key alone unless the tenant allows the platform fallback', async () => {
    const r = router(FALLBACK, tenantKeys().service);
    const route = await routeOf(r, { useTenantKey: true });
    expect(route.candidates.map((c) => c.role)).toEqual(['tenant']);
    // Without a usable key and without the fallback: tenant_key_invalid.
    const none = router(FALLBACK, tenantKeys(null).service);
    await expect(none.service.select(scope, { useTenantKey: true }, who)).resolves.toEqual({
      kind: 'tenant_key_invalid',
    });
    // With the fallback the platform answers.
    const fb = await routeOf(none, { useTenantKey: true, tenantKeyFallbackToPlatform: true });
    expect(fb.current.role).toBe('primary');
    // Without the setting (or the platform gate off) the platform is used.
    expect((await routeOf(r, { useTenantKey: false })).current.role).toBe('primary');
    const off = tenantKeys();
    (off.service as { enabled: boolean }).enabled = false;
    expect(
      (await routeOf(router(FALLBACK, off.service), { useTenantKey: true })).current.role,
    ).toBe('primary');
  });

  it('selects the first closed breaker: an open primary moves the turn to the secondary', async () => {
    const r = router(FALLBACK);
    await r.kv.set('as:brk:fake', '2', 60);
    const route = await routeOf(r);
    expect(route.current).toMatchObject({ role: 'fallback', model: 'fake-secondary' });
    expect(route.fallbackFrom).toBe('fake');
    expect(await r.series('assistant_provider_fallback_active')).toContain(
      'assistant_provider_fallback_active{service="api-test"} 1',
    );
    expect(await r.series('assistant_provider_breaker_open{')).toEqual(
      expect.arrayContaining([
        expect.stringContaining('provider="fake",role="primary",service="api-test"} 1'),
        expect.stringContaining('provider="fake",role="fallback",service="api-test"} 0'),
      ]),
    );
    expect(await r.series('assistant_provider_switches_total{')).toEqual([
      expect.stringContaining('from="primary",to="fallback",reason="breaker_open"'),
    ]);
    // Both open: unavailable.
    await r.kv.set('as:brk:fake:fb', '2', 60);
    await expect(r.service.select(scope, null, who)).resolves.toEqual({ kind: 'unavailable' });
    // A tenant key's breaker never opens the platform's, nor the other way round.
    const t = router(FALLBACK, tenantKeys().service);
    await t.kv.set('as:brk:fake', '5', 60);
    expect((await routeOf(t, { useTenantKey: true })).current.role).toBe('tenant');
  });

  it('records breaker failures and request metrics per role on the route’s candidate', async () => {
    const failing = new ScriptedProvider([
      () => {
        throw new LlmError('server_error', { httpStatus: 503 });
      },
      () => {
        throw new LlmError('server_error', { httpStatus: 503 });
      },
    ]);
    const r = router(FALLBACK, undefined, (spec) =>
      spec.role === 'primary' ? failing : new FakeProvider({ nodeEnv: 'test', model: spec.model }),
    );
    const route = await routeOf(r);
    const request = { system: 's', transcript: [], tools: [], maxOutputTokens: 10 };
    await expect(
      r.service.complete(route, request, new AbortController().signal, () => undefined),
    ).rejects.toThrow(LlmError);
    expect(await r.kv.get('as:brk:fake')).toBe('1');
    expect(await r.kv.get('as:brk:fake:fb')).toBeNull();
    expect(await r.series('assistant_llm_requests_total{')).toEqual([
      expect.stringContaining('provider="fake",role="primary",outcome="server_error"'),
    ]);
    expect(await r.series('assistant_llm_seconds_count{')).toEqual([
      expect.stringContaining('provider="fake",role="primary"'),
    ]);
  });
});

describe('ProviderRouterService.onFailure: the same-turn switch (D6)', () => {
  it('switches once on a switchable failure when allowed, to the next closed candidate', async () => {
    const r = router(FALLBACK);
    const route = await routeOf(r);
    const error = new LlmError('server_error', { httpStatus: 502 });
    const who2 = { principal, scope };
    expect(await r.service.onFailure(route, error, who2, false)).toEqual({ kind: 'fail' });
    const switched = await r.service.onFailure(route, error, who2, true);
    expect(switched.kind).toBe('switch');
    const next = (switched as { route: TurnRoute }).route;
    expect(next).toMatchObject({ switched: true, fallbackFrom: 'fake' });
    expect(next.current.role).toBe('fallback');
    // At most one switch per turn.
    expect(await r.service.onFailure(next, error, who2, true)).toEqual({ kind: 'fail' });
    // Not switchable: a refusal, a client error, a delta already streamed.
    for (const e of [
      new LlmError('refusal'),
      new LlmError('client_error', { httpStatus: 400 }),
      new LlmError('server_error', { afterDelta: true }),
    ]) {
      expect(await r.service.onFailure(route, e, who2, true)).toEqual({ kind: 'fail' });
    }
    // The next candidate's breaker is open: no switch.
    await r.kv.set('as:brk:fake:fb', '2', 60);
    expect(await r.service.onFailure(route, error, who2, true)).toEqual({ kind: 'fail' });
  });

  it('invalidates a tenant key answered `auth` and falls back only when allowed', async () => {
    const keys = tenantKeys();
    const r = router(FALLBACK, keys.service);
    const who2 = { principal, scope };
    const auth = new LlmError('auth', { httpStatus: 401 });
    const alone = await routeOf(r, { useTenantKey: true });
    expect(await r.service.onFailure(alone, auth, who2, true)).toEqual({
      kind: 'tenant_key_invalid',
    });
    expect(keys.invalidated).toEqual([3]);
    const withFallback = await routeOf(r, {
      useTenantKey: true,
      tenantKeyFallbackToPlatform: true,
    });
    const decision = await r.service.onFailure(withFallback, auth, who2, true);
    expect(decision).toMatchObject({
      kind: 'switch',
      route: { current: { role: 'primary', keySource: 'platform' }, fallbackFrom: 'anthropic' },
    });
    // Later in the turn (no switch allowed) the key is still invalidated; the turn fails.
    expect(await r.service.onFailure(withFallback, auth, who2, false)).toEqual({
      kind: 'tenant_key_invalid',
    });
    expect(keys.invalidated).toEqual([3, 3, 3]);
    expect(await r.series('assistant_provider_switches_total{')).toEqual([
      expect.stringContaining('from="tenant",to="primary",reason="tenant_key_invalid"'),
    ]);
    // A platform key answered `auth` is an ordinary provider error (no invalidation, no switch).
    const platform = await routeOf(router(FALLBACK, keys.service));
    expect(await r.service.onFailure(platform, auth, who2, true)).toEqual({ kind: 'fail' });
    expect(keys.invalidated).toHaveLength(3);
  });
});

describe('ProviderRouterService: the AI-1 surface', () => {
  it('keeps providerId, model, provider() and isOpen() of the primary', async () => {
    const r = router();
    expect(r.service.providerId).toBe('fake');
    expect(r.service.model).toBe('fake');
    expect(r.service.provider()).toBe(r.service.provider());
    expect(await r.service.isOpen()).toBe(false);
    await r.kv.set('as:brk:fake', '2', 60);
    expect(await r.service.isOpen()).toBe(true);
    const answer = await r.service.complete(
      await routeOf(router()),
      {
        system: 's',
        transcript: [{ role: 'user', text: '/text hi' }],
        tools: [],
        maxOutputTokens: 50,
      },
      new AbortController().signal,
      () => undefined,
    );
    expect(answer.stop).toBeDefined();
    expect(reply({ text: 'x' }).text).toBe('x');
  });
});
