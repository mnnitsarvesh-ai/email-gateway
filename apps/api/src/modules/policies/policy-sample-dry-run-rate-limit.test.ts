import { type ExecutionContext, Logger } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../test/support/in-memory-key-value-store';
import type { ApiConventionMetrics } from '../../http/api-metrics';
import { CodedHttpException } from '../../http/coded-exception';
import {
  POLICY_SAMPLE_DRY_RUN_BUCKET,
  POLICY_SAMPLE_DRY_RUN_RATE_LIMIT_KEY,
  PolicySampleDryRunRateLimit,
  PolicySampleDryRunRateLimitGuard,
  policySampleDryRunRate,
} from './policy-sample-dry-run-rate-limit';

class Controller {
  @PolicySampleDryRunRateLimit()
  sampleDryRun(): void {}
}

const user = { kind: 'user', userPublicId: 'u-1' };
const apiKey = { kind: 'api_key', apiKeyPublicId: 'k-1' };

function context(principal: unknown, preset: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...preset };
  const req = { ip: '198.51.100.1', principal };
  const res = {
    setHeader: (name: string, value: string) => (headers[name] = value),
    getHeader: (name: string) => headers[name],
  };
  const ctx = {
    getHandler: () => Controller.prototype.sampleDryRun,
    getClass: () => Controller,
    switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
  } as unknown as ExecutionContext;
  return { ctx, headers };
}

describe('PolicySampleDryRunRateLimitGuard (step 7.3 §4.3)', () => {
  let kv: InMemoryKeyValueStore;
  let metrics: {
    rateLimited: { inc: ReturnType<typeof vi.fn> };
    rateLimitStoreErrors: { inc: ReturnType<typeof vi.fn> };
  };
  let guard: PolicySampleDryRunRateLimitGuard;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-16T12:00:00Z'));
    kv = new InMemoryKeyValueStore();
    metrics = { rateLimited: { inc: vi.fn() }, rateLimitStoreErrors: { inc: vi.fn() } };
    guard = new PolicySampleDryRunRateLimitGuard(
      { POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: 2 },
      kv,
      metrics as unknown as ApiConventionMetrics,
    );
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('is applied by the decorator with discoverable metadata', () => {
    expect(
      Reflect.getMetadata(POLICY_SAMPLE_DRY_RUN_RATE_LIMIT_KEY, Controller.prototype.sampleDryRun),
    ).toBe(POLICY_SAMPLE_DRY_RUN_BUCKET);
    expect(Reflect.getMetadata(GUARDS_METADATA, Controller.prototype.sampleDryRun)).toEqual([
      PolicySampleDryRunRateLimitGuard,
    ]);
    expect(policySampleDryRunRate({ POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: 6 })).toEqual({
      bucket: 'policy-sample-dry-run',
      limit: 6,
      windowSeconds: 60,
    });
  });

  it('counts per principal in a 60 s window, then 429 rate_limited (route) with Retry-After', async () => {
    const first = context(user);
    await expect(guard.canActivate(first.ctx)).resolves.toBe(true);
    expect(first.headers).toMatchObject({
      'RateLimit-Limit': '2',
      'RateLimit-Remaining': '1',
      'RateLimit-Reset': '60',
    });
    vi.advanceTimersByTime(20_000);
    await expect(guard.canActivate(context(user).ctx)).resolves.toBe(true);
    const third = context(user);
    const err = await guard.canActivate(third.ctx).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CodedHttpException);
    expect(err).toMatchObject({ code: 'rate_limited', status: 429, details: { scope: 'route' } });
    expect(third.headers).toMatchObject({
      'Retry-After': '40',
      'RateLimit-Limit': '2',
      'RateLimit-Remaining': '0',
      'RateLimit-Reset': '40',
    });
    expect(metrics.rateLimited.inc).toHaveBeenCalledWith({ scope: 'route' });
    expect(kv.entries.has('rl:policy-sample-dry-run:user:u-1')).toBe(true);
    // Another principal (an API key) has its own counter.
    await expect(guard.canActivate(context(apiKey).ctx)).resolves.toBe(true);
    expect(kv.entries.has('rl:policy-sample-dry-run:api_key:k-1')).toBe(true);
    // The window ends.
    vi.advanceTimersByTime(41_000);
    await expect(guard.canActivate(context(user).ctx)).resolves.toBe(true);
  });

  it('keeps the class headers when they are more restrictive', async () => {
    const tight = context(user, {
      'RateLimit-Limit': '30',
      'RateLimit-Remaining': '0',
      'RateLimit-Reset': '10',
    });
    await guard.canActivate(tight.ctx);
    expect(tight.headers).toMatchObject({ 'RateLimit-Limit': '30', 'RateLimit-Remaining': '0' });
    const loose = context(apiKey, {
      'RateLimit-Limit': '30',
      'RateLimit-Remaining': '25',
      'RateLimit-Reset': '10',
    });
    await guard.canActivate(loose.ctx);
    expect(loose.headers).toMatchObject({ 'RateLimit-Limit': '2', 'RateLimit-Remaining': '1' });
  });

  it('fails closed with 503 service_unavailable when the store is down', async () => {
    kv.failing = true;
    await expect(guard.canActivate(context(user).ctx)).rejects.toMatchObject({
      code: 'service_unavailable',
      status: 503,
    });
    expect(metrics.rateLimitStoreErrors.inc).toHaveBeenCalled();
  });
});
