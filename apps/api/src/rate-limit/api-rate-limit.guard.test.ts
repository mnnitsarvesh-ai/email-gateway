import { type ExecutionContext, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { PrismaReadService } from '@email-gateway/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../test/support/in-memory-key-value-store';
import { Public } from '../auth-contracts/decorators';
import type { ApiKeyPrincipal, Principal, UserPrincipal } from '../auth-contracts/principal';
import { CodedHttpException } from '../http/coded-exception';
import { ApiRateLimitGuard, RATE_LIMIT_HEADERS } from './api-rate-limit.guard';
import { RATE_CLASS_KEY, RateClass, ReturnsSecret } from './rate-class.decorator';
import { TenantRateLimitResolver } from './tenant-rate-limit.resolver';

class Routes {
  @Public()
  open(): void {}

  plain(): void {}

  @RateClass('sensitive')
  sensitive(): void {}

  @RateClass('expensive')
  expensive(): void {}

  @ReturnsSecret()
  secret(): void {}
}

const config = {
  API_RATE_PRINCIPAL_PER_MINUTE: 5,
  API_RATE_SENSITIVE_PER_MINUTE: 2,
  API_RATE_EXPENSIVE_PER_MINUTE: 3,
  API_RATE_TENANT_DEFAULT_PER_MINUTE: 300,
  API_RATE_TENANT_MIN_PER_MINUTE: 4,
  API_RATE_TENANT_MAX_PER_MINUTE: 1000,
  API_RATE_LIMIT_CACHE_SECONDS: 60,
};

const user = (overrides: Partial<UserPrincipal> = {}): UserPrincipal => ({
  kind: 'user',
  userId: 10n,
  userPublicId: 'u-1',
  organizationId: 7n,
  organizationPublicId: 'o-7',
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: false,
  mfaEnrollmentRequired: false,
  permissions: new Set(),
  ...overrides,
});
const apiKey: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: 'k-1',
  organizationId: 7n,
  organizationPublicId: 'o-7',
  permissions: new Set(),
};

function readStub(limits: Map<bigint, bigint>, failing = { on: false }) {
  const findUnique = vi.fn(
    ({
      where,
    }: {
      where: { organizationId_limitKey: { organizationId: bigint; limitKey: string } };
    }) => {
      if (failing.on) return Promise.reject(new Error('replica down'));
      const { organizationId, limitKey } = where.organizationId_limitKey;
      const value = limits.get(organizationId);
      return Promise.resolve(
        value === undefined ? null : { organizationId, limitKey, limitValue: value },
      );
    },
  );
  return {
    read: { client: { organizationLimit: { findUnique } } } as unknown as PrismaReadService,
    findUnique,
  };
}

function setup(limits = new Map<bigint, bigint>([[7n, 1000n]])) {
  const kv = new InMemoryKeyValueStore();
  const failing = { on: false };
  const { read, findUnique } = readStub(limits, failing);
  const resolver = new TenantRateLimitResolver(config, read);
  const limited: string[] = [];
  const metrics = {
    rateLimited: { inc: vi.fn((l: { scope: string }) => limited.push(l.scope)) },
    rateLimitStoreErrors: { inc: vi.fn() },
  };
  const guard = new ApiRateLimitGuard(new Reflector(), kv, resolver, metrics as never, config);
  const call = async (handler: () => void, principal?: Principal, req: object = {}) => {
    const headers: Record<string, string> = {};
    const request = { principal, ...req };
    const ctx = {
      getType: () => 'http',
      getHandler: () => handler,
      getClass: () => Routes,
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: (n: string, v: string) => (headers[n] = v) }),
      }),
    } as unknown as ExecutionContext;
    const outcome = await guard.canActivate(ctx).catch((e: unknown) => e);
    return { outcome, headers, request };
  };
  return { kv, guard, call, metrics, limited, resolver, findUnique, failing };
}

function scopeOf(outcome: unknown): string | undefined {
  if (!(outcome instanceof CodedHttpException)) return undefined;
  expect(outcome.getStatus()).toBe(429);
  expect(outcome.code).toBe('rate_limited');
  expect(outcome.message).toBe('Too many requests');
  return outcome.details.scope as string;
}

describe('ApiRateLimitGuard (step 6.1 D8)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-12T10:00:00Z'));
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('skips public routes and requests without a principal', async () => {
    const { call, kv } = setup();
    expect((await call(Routes.prototype.open, user())).outcome).toBe(true);
    expect((await call(Routes.prototype.plain)).outcome).toBe(true);
    expect(kv.entries.size).toBe(0);
  });

  it('limits per principal, with RateLimit-* headers and a coded 429 + Retry-After', async () => {
    const { call, kv, limited } = setup();
    for (let i = 1; i <= 5; i += 1) {
      const { outcome, headers } = await call(Routes.prototype.plain, user());
      expect(outcome).toBe(true);
      expect(headers).toMatchObject({
        [RATE_LIMIT_HEADERS.limit]: '5',
        [RATE_LIMIT_HEADERS.remaining]: String(5 - i),
        [RATE_LIMIT_HEADERS.reset]: '60',
      });
    }
    vi.advanceTimersByTime(20_000);
    const { outcome, headers } = await call(Routes.prototype.plain, user());
    expect(scopeOf(outcome)).toBe('principal');
    expect(headers['Retry-After']).toBe('40');
    expect(headers[RATE_LIMIT_HEADERS.remaining]).toBe('0');
    expect(headers[RATE_LIMIT_HEADERS.reset]).toBe('40');
    expect(limited).toEqual(['principal']);
    expect([...kv.entries.keys()].sort()).toEqual(['rl:api:p:user:u-1', 'rl:api:t:7']);
    // Another principal of the same tenant is not affected; the window resets.
    expect((await call(Routes.prototype.plain, apiKey)).outcome).toBe(true);
    vi.advanceTimersByTime(41_000);
    expect((await call(Routes.prototype.plain, user())).outcome).toBe(true);
  });

  it('limits per tenant from organization_limits, shared by every principal', async () => {
    const { call } = setup(new Map([[7n, 6n]]));
    for (let i = 0; i < 3; i += 1)
      expect((await call(Routes.prototype.plain, user())).outcome).toBe(true);
    for (let i = 0; i < 3; i += 1)
      expect((await call(Routes.prototype.plain, apiKey)).outcome).toBe(true);
    const { outcome, headers } = await call(Routes.prototype.plain, user({ userPublicId: 'u-3' }));
    expect(scopeOf(outcome)).toBe('tenant');
    expect(headers[RATE_LIMIT_HEADERS.limit]).toBe('6');
  });

  it('clamps tenant values to the configured minimum and maximum', async () => {
    const low = setup(new Map([[7n, 1n]]));
    expect(await low.resolver.limitFor(7n)).toBe(4);
    const high = setup(new Map([[7n, 50_000n]]));
    expect(await high.resolver.limitFor(7n)).toBe(1000);
    const missing = setup(new Map());
    expect(await missing.resolver.limitFor(7n)).toBe(300);
  });

  it('uses the default (never unlimited) when the lookup fails, caches and retries', async () => {
    const { resolver, failing, findUnique } = setup(new Map([[7n, 50n]]));
    failing.on = true;
    expect(await resolver.limitFor(7n)).toBe(300);
    expect(await resolver.limitFor(7n)).toBe(300);
    expect(findUnique).toHaveBeenCalledTimes(1);
    failing.on = false;
    vi.advanceTimersByTime(5_001);
    expect(await resolver.limitFor(7n)).toBe(50);
  });

  it('caches tenant values for API_RATE_LIMIT_CACHE_SECONDS and shares concurrent lookups', async () => {
    const limits = new Map([[7n, 50n]]);
    const { resolver, findUnique } = setup(limits);
    const [a, b] = await Promise.all([resolver.limitFor(7n), resolver.limitFor(7n)]);
    expect([a, b]).toEqual([50, 50]);
    expect(findUnique).toHaveBeenCalledTimes(1);
    limits.set(7n, 70n);
    vi.advanceTimersByTime(59_000);
    expect(await resolver.limitFor(7n)).toBe(50);
    vi.advanceTimersByTime(2_000);
    expect(await resolver.limitFor(7n)).toBe(70);
  });

  it('refuses a row that does not echo the organization (uses the default)', async () => {
    const { resolver, findUnique } = setup();
    findUnique.mockResolvedValueOnce({
      organizationId: 8n,
      limitKey: 'api_requests_per_minute',
      limitValue: 900n,
    });
    expect(await resolver.limitFor(7n)).toBe(300);
  });

  it('applies the sensitive and expensive class buckets per principal', async () => {
    const { call, limited, kv } = setup();
    expect((await call(Routes.prototype.sensitive, user())).outcome).toBe(true);
    const second = await call(Routes.prototype.sensitive, user());
    expect(second.outcome).toBe(true);
    expect(second.headers[RATE_LIMIT_HEADERS.limit]).toBe('2');
    expect(second.headers[RATE_LIMIT_HEADERS.remaining]).toBe('0');
    expect(scopeOf((await call(Routes.prototype.sensitive, user())).outcome)).toBe('sensitive');
    // @ReturnsSecret() routes share the sensitive bucket.
    expect(scopeOf((await call(Routes.prototype.secret, user())).outcome)).toBe('sensitive');
    for (let i = 0; i < 3; i += 1) {
      expect((await call(Routes.prototype.expensive, apiKey)).outcome).toBe(true);
    }
    expect(scopeOf((await call(Routes.prototype.expensive, apiKey)).outcome)).toBe('expensive');
    expect(limited).toEqual(['sensitive', 'sensitive', 'expensive']);
    expect(kv.entries.has('rl:api:s:user:u-1')).toBe(true);
    expect(kv.entries.has('rl:api:x:api_key:k-1')).toBe(true);
  });

  it('counts a request once even if the guard runs twice', async () => {
    const { guard, kv } = setup();
    const request = { principal: user() };
    const ctx = {
      getType: () => 'http',
      getHandler: () => Routes.prototype.plain,
      getClass: () => Routes,
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: vi.fn() }),
      }),
    } as unknown as ExecutionContext;
    await guard.canActivate(ctx);
    await guard.canActivate(ctx);
    expect(await kv.get('rl:api:p:user:u-1')).toBe('1');
  });

  it('fails closed with 503 when the store is down', async () => {
    const { call, kv, metrics } = setup();
    kv.failing = true;
    const { outcome } = await call(Routes.prototype.plain, user());
    expect(outcome).toBeInstanceOf(CodedHttpException);
    expect((outcome as CodedHttpException).getStatus()).toBe(503);
    expect((outcome as CodedHttpException).code).toBe('service_unavailable');
    expect(metrics.rateLimitStoreErrors.inc).toHaveBeenCalledTimes(1);
  });

  it('counts an override session as the user and against the target tenant', async () => {
    const { call, kv } = setup(new Map([[42n, 500n]]));
    const override = user({
      organizationId: 1n,
      organizationKind: 'platform',
      override: {
        id: 'ovr-1',
        reason: 'support',
        targetOrganizationId: 42n,
        targetOrganizationPublicId: 'o-42',
        expiresAt: new Date('2026-11-12T11:00:00Z'),
      },
    });
    expect((await call(Routes.prototype.plain, override)).outcome).toBe(true);
    expect([...kv.entries.keys()].sort()).toEqual(['rl:api:p:user:u-1', 'rl:api:t:42']);
  });
});

describe('@RateClass / @ReturnsSecret metadata', () => {
  it('records the class and documents it', () => {
    expect(Reflect.getMetadata(RATE_CLASS_KEY, Routes.prototype.expensive)).toBe('expensive');
    expect(Reflect.getMetadata(RATE_CLASS_KEY, Routes.prototype.secret)).toBe('sensitive');
    expect(Reflect.getMetadata('swagger/apiExtension', Routes.prototype.secret)).toEqual({
      'x-eg-returns-secret': true,
      'x-eg-rate-class': 'sensitive',
    });
  });

  it('refuses two different classes on one route and unknown classes', () => {
    expect(() => {
      class X {
        @RateClass('expensive')
        @RateClass('sensitive')
        m(): void {}
      }
      return X;
    }).toThrow(/one rate class/);
    expect(() => RateClass('cheap' as 'sensitive')).toThrow();
  });
});
