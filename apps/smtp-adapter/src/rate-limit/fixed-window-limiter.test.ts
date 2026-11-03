import { describe, expect, it } from 'vitest';
import {
  FakeRedis,
  metricValue,
  newMetrics,
  redisService,
} from '../../integration/in-session-support/fakes';
import { dayWindow, FixedWindowLimiter, minuteWindow, rateLimitKey } from './fixed-window-limiter';

const now = new Date('2026-11-02T10:15:30.500Z');

describe('rate limit windows and keys (D6)', () => {
  it('uses the UTC minute number and the UTC day', () => {
    expect(minuteWindow(now)).toBe(Math.floor(now.getTime() / 60_000));
    expect(minuteWindow(new Date('2026-11-02T10:15:59.999Z'))).toBe(minuteWindow(now));
    expect(minuteWindow(new Date('2026-11-02T10:16:00.000Z'))).toBe(minuteWindow(now) + 1);
    expect(dayWindow(now)).toBe('20261102');
    expect(dayWindow(new Date('2026-11-02T23:59:59.999Z'))).toBe('20261102');
  });

  it('builds the documented keys', () => {
    const minute = minuteWindow(now);
    expect(rateLimitKey('ip', '203.0.113.9', now)).toBe(`sa:rl:ip:203.0.113.9:${minute}`);
    expect(rateLimitKey('tenant_in', '7', now)).toBe(`sa:rl:in:7:${minute}`);
    expect(rateLimitKey('tenant_out', '7', now)).toBe(`sa:rl:out:7:${minute}`);
    expect(rateLimitKey('tenant_out_day', '7', now)).toBe('sa:rl:outd:7:20261102');
  });
});

describe('FixedWindowLimiter', () => {
  it('counts every attempt, sets the TTL on the first hit only, and limits above the limit', async () => {
    const redis = new FakeRedis();
    const metrics = newMetrics();
    const limiter = new FixedWindowLimiter(redisService(redis), metrics);
    const results: boolean[] = [];
    for (let i = 0; i < 4; i += 1) results.push(await limiter.exceeded('tenant_in', '7', 2, now));
    expect(results).toEqual([false, false, true, true]);
    const key = rateLimitKey('tenant_in', '7', now);
    expect(redis.store.get(key)?.value).toBe('4');
    expect(redis.ttlMs.get(key)).toBe(70_000);
    expect(await metricValue(metrics, 'smtp_rate_limited_total', { scope: 'tenant_in' })).toBe(2);
  });

  it('keeps day windows for a day plus the grace period', async () => {
    const redis = new FakeRedis();
    const limiter = new FixedWindowLimiter(redisService(redis), newMetrics());
    await limiter.exceeded('tenant_out_day', '7', 10, now);
    expect(redis.ttlMs.get('sa:rl:outd:7:20261102')).toBe(86_410_000);
  });

  it('treats a limit of 0 as "no mail of that kind"', async () => {
    const limiter = new FixedWindowLimiter(redisService(new FakeRedis()), newMetrics());
    expect(await limiter.exceeded('tenant_out', '7', 0, now)).toBe(true);
  });

  it('starts a new window each minute', async () => {
    const limiter = new FixedWindowLimiter(redisService(new FakeRedis()), newMetrics());
    expect(await limiter.exceeded('ip', '1.2.3.4', 1, now)).toBe(false);
    expect(await limiter.exceeded('ip', '1.2.3.4', 1, now)).toBe(true);
    expect(await limiter.exceeded('ip', '1.2.3.4', 1, new Date(now.getTime() + 60_000))).toBe(
      false,
    );
  });

  it('propagates Redis errors (fail closed)', async () => {
    const redis = new FakeRedis();
    redis.failing = true;
    const limiter = new FixedWindowLimiter(redisService(redis), newMetrics());
    await expect(limiter.exceeded('ip', '1.2.3.4', 10, now)).rejects.toThrow('redis unavailable');
  });
});
