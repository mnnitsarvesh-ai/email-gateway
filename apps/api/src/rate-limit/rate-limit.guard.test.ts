import {
  type ExecutionContext,
  HttpException,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { Reflector } from '@nestjs/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../test/support/in-memory-key-value-store';
import { sha256Hex } from '../crypto/tokens';
import { RateLimit } from './rate-limit.decorator';
import { RateLimitGuard } from './rate-limit.guard';

class Controller {
  @RateLimit({ bucket: 'login', limit: 2, windowSeconds: 60, by: 'ip' })
  login(): void {}

  @RateLimit({ bucket: 'forgot-ip', limit: 5, windowSeconds: 900, by: 'ip' })
  @RateLimit({
    bucket: 'forgot-email',
    limit: 1,
    windowSeconds: 3600,
    by: 'body',
    bodyField: 'email',
  })
  forgot(): void {}

  @RateLimit({ bucket: 'pair', limit: 1, windowSeconds: 60, by: 'ip+body', bodyField: 'email' })
  pair(): void {}
}

interface Call {
  ip?: string;
  body?: unknown;
}

function context(
  handler: () => void,
  call: Call,
): { ctx: ExecutionContext; headers: Record<string, string> } {
  const headers: Record<string, string> = {};
  const req = { ip: call.ip ?? '198.51.100.1', body: call.body };
  const res = { setHeader: (name: string, value: string) => (headers[name] = value) };
  const ctx = {
    getHandler: () => handler,
    getClass: () => Controller,
    switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
  } as unknown as ExecutionContext;
  return { ctx, headers };
}

describe('RateLimitGuard', () => {
  let kv: InMemoryKeyValueStore;
  let guard: RateLimitGuard;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-02T00:00:00Z'));
    kv = new InMemoryKeyValueStore();
    guard = new RateLimitGuard(new Reflector(), kv);
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const call = (handler: () => void, c: Call = {}) => guard.canActivate(context(handler, c).ctx);

  it('allows requests up to the limit, then answers 429 with Retry-After', async () => {
    const handler = Controller.prototype.login;
    await expect(call(handler)).resolves.toBe(true);
    await expect(call(handler)).resolves.toBe(true);
    vi.advanceTimersByTime(15_000);
    const { ctx, headers } = context(handler, {});
    const error = await guard.canActivate(ctx).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpException);
    expect((error as HttpException).getStatus()).toBe(429);
    expect(headers['Retry-After']).toBe('45');
  });

  it('counts per identifier', async () => {
    const handler = Controller.prototype.login;
    await call(handler, { ip: '198.51.100.1' });
    await call(handler, { ip: '198.51.100.1' });
    await expect(call(handler, { ip: '198.51.100.2' })).resolves.toBe(true);
  });

  it('resets after the window', async () => {
    const handler = Controller.prototype.login;
    await call(handler);
    await call(handler);
    await expect(call(handler)).rejects.toThrow(HttpException);
    vi.advanceTimersByTime(60_000);
    await expect(call(handler)).resolves.toBe(true);
  });

  it('applies every stacked limit; body identifiers are hashed, lower-cased and trimmed', async () => {
    const handler = Controller.prototype.forgot;
    await expect(call(handler, { body: { email: 'Alice@Example.com ' } })).resolves.toBe(true);
    expect(await kv.get(`rl:forgot-email:${sha256Hex('alice@example.com')}`)).toBe('1');
    expect(await kv.get('rl:forgot-ip:198.51.100.1')).toBe('1');
    expect([...kv.entries.keys()].join(' ')).not.toContain('alice');
    // Same email from another IP: the per-email limit (1/hour) applies.
    await expect(
      call(handler, { ip: '203.0.113.9', body: { email: 'alice@example.com' } }),
    ).rejects.toThrow(HttpException);
  });

  it('skips a body limit when the field is absent (validation rejects the request later)', async () => {
    const handler = Controller.prototype.forgot;
    await expect(call(handler, { body: {} })).resolves.toBe(true);
    await expect(call(handler, { body: { email: 42 } })).resolves.toBe(true);
    expect(await kv.get('rl:forgot-ip:198.51.100.1')).toBe('2');
  });

  it('combines IP and body for ip+body', async () => {
    const handler = Controller.prototype.pair;
    await call(handler, { body: { email: 'a@example.com' } });
    expect(await kv.get(`rl:pair:198.51.100.1:${sha256Hex('a@example.com')}`)).toBe('1');
    await expect(call(handler, { body: { email: 'b@example.com' } })).resolves.toBe(true);
  });

  it('fails closed with 503 when the store is unavailable', async () => {
    kv.failing = true;
    await expect(call(Controller.prototype.login)).rejects.toThrow(ServiceUnavailableException);
  });

  it('counts a request once even if the guard runs twice', async () => {
    const { ctx } = context(Controller.prototype.login, {});
    await guard.canActivate(ctx);
    await guard.canActivate(ctx);
    expect(await kv.get('rl:login:198.51.100.1')).toBe('1');
  });
});

describe('@RateLimit()', () => {
  it('attaches the guard once per route, however many limits are stacked', () => {
    const guards = Reflect.getMetadata(GUARDS_METADATA, Controller.prototype.forgot) as unknown[];
    expect(guards).toEqual([RateLimitGuard]);
  });

  it('validates its options at decoration time', () => {
    expect(() =>
      RateLimit({ bucket: 'Bad Bucket', limit: 1, windowSeconds: 1, by: 'ip' }),
    ).toThrow();
    expect(() => RateLimit({ bucket: 'b', limit: 0, windowSeconds: 1, by: 'ip' })).toThrow();
    expect(() => RateLimit({ bucket: 'b', limit: 1, windowSeconds: 0, by: 'ip' })).toThrow();
    expect(() => RateLimit({ bucket: 'b', limit: 1, windowSeconds: 1, by: 'body' })).toThrow();
  });
});
