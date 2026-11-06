import { describe, expect, it } from 'vitest';
import { MemoryRedis } from './click.test-support';
import { RateLimiter, RATE_WINDOW_MS, tokenKeyHash } from './rate-limiter';

const limits = { ipPerMinute: 3, tokenPerMinute: 2, invalidPerMinute: 2 };

describe('RateLimiter (fixed window, Lua INCR+PEXPIRE)', () => {
  it('limits per network, per token and invalid tokens per network', async () => {
    const redis = new MemoryRedis();
    const limiter = new RateLimiter(redis, limits, 100, () => 0);
    expect(await limiter.check('192.0.2.0/24', 't1')).toEqual({
      limited: false,
      failedOpen: false,
    });
    expect(await limiter.check('192.0.2.0/24', 't1')).toEqual({
      limited: false,
      failedOpen: false,
    });
    expect(await limiter.check('198.51.100.0/24', 't1')).toEqual({ limited: true, scope: 'token' });
    expect(await limiter.check('192.0.2.0/24', 't2')).toEqual({
      limited: false,
      failedOpen: false,
    });
    expect(await limiter.check('192.0.2.0/24', 't3')).toEqual({ limited: true, scope: 'ip' });
    await limiter.recordInvalid('203.0.113.0/24');
    await limiter.recordInvalid('203.0.113.0/24');
    expect(await limiter.check('203.0.113.0/24', 't4')).toEqual({
      limited: true,
      scope: 'invalid',
    });
  });

  it('a new window starts over', async () => {
    let now = 0;
    const limiter = new RateLimiter(new MemoryRedis(), limits, 100, () => now);
    for (let i = 0; i < 3; i += 1) await limiter.check('n', `t${i}`);
    expect((await limiter.check('n', 'tx')).limited).toBe(true);
    now += RATE_WINDOW_MS;
    expect((await limiter.check('n', 'tx')).limited).toBe(false);
  });

  it('fails open on Redis errors and timeouts', async () => {
    const redis = new MemoryRedis();
    redis.down = true;
    const limiter = new RateLimiter(redis, limits, 50);
    expect(await limiter.check('n', 't')).toEqual({ limited: false, failedOpen: true });
    expect(await limiter.recordInvalid('n')).toBe(false);
    redis.down = false;
    redis.delayMs = 200;
    expect(await limiter.check('n', 't')).toEqual({ limited: false, failedOpen: true });
  });

  it('keys hold a token hash, never the token', async () => {
    const redis = new MemoryRedis();
    const token = 'A'.repeat(62);
    await new RateLimiter(redis, limits, 100).check('n', token);
    const keys = [...redis.store.keys()];
    expect(keys.some((k) => k.includes(token))).toBe(false);
    expect(keys.some((k) => k.includes(tokenKeyHash(token)))).toBe(true);
  });
});
