import { Injectable } from '@nestjs/common';
import { type Counter, MetricsService, RedisService } from '@email-gateway/common';
import { LuaScript } from './lua-script';

/**
 * Atomic counter with an expiry set on the first increment (step 2.2 D6):
 * KEYS[1] counter, ARGV[1] increment, ARGV[2] TTL in milliseconds. Returns the new value.
 */
export const INCREMENT_SCRIPT = `
local count = redis.call('INCRBY', KEYS[1], ARGV[1])
if count == tonumber(ARGV[1]) then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return count
`;
const increment = new LuaScript(INCREMENT_SCRIPT);

/** D6: windows are kept 10 s longer than their length. */
export const WINDOW_GRACE_MS = 10_000;
export const MINUTE_MS = 60_000;
export const DAY_MS = 86_400_000;

export type RateScope = 'ip' | 'tenant_in' | 'tenant_out' | 'tenant_out_day';

/** UTC minute number (`floor(epochMs / 60000)`). */
export const minuteWindow = (now: Date): number => Math.floor(now.getTime() / MINUTE_MS);
/** UTC day as `yyyymmdd`. */
export const dayWindow = (now: Date): string => now.toISOString().slice(0, 10).replaceAll('-', '');

/** Redis keys of D6. */
export function rateLimitKey(scope: RateScope, subject: string, now: Date): string {
  switch (scope) {
    case 'ip':
      return `sa:rl:ip:${subject}:${minuteWindow(now)}`;
    case 'tenant_in':
      return `sa:rl:in:${subject}:${minuteWindow(now)}`;
    case 'tenant_out':
      return `sa:rl:out:${subject}:${minuteWindow(now)}`;
    case 'tenant_out_day':
      return `sa:rl:outd:${subject}:${dayWindow(now)}`;
  }
}

const windowMs = (scope: RateScope): number => (scope === 'tenant_out_day' ? DAY_MS : MINUTE_MS);

/**
 * Fixed-window rate limiting in Redis (step 2.2 D6). One atomic script per hit (INCRBY, and
 * PEXPIRE on the first increment). Every attempt counts, including those over the limit.
 *
 * **Errors propagate**: rate limiting is fail-closed, so a Redis failure makes the policy
 * tempfail (never DUNNO).
 */
@Injectable()
export class FixedWindowLimiter {
  private readonly limited: Counter<'scope'>;

  constructor(
    private readonly redis: RedisService,
    metrics: MetricsService,
  ) {
    this.limited = metrics.counter(
      'smtp_rate_limited_total',
      'Recipients deferred by an in-session rate limit',
      ['scope'],
    );
  }

  /** Increments `key` (expiring after `ttlMs` from the first hit) and returns the new count. */
  async increment(key: string, ttlMs: number, by = 1): Promise<number> {
    const result = await increment.run(this.redis.client, [key], [by, ttlMs]);
    if (typeof result !== 'number') throw new Error('unexpected rate limit script result');
    return result;
  }

  /**
   * Counts one hit of `subject` in the current window of `scope` and returns true when the
   * count is above `limit` (a limit of 0 always exceeds). Counted in
   * `smtp_rate_limited_total{scope}`.
   */
  async exceeded(scope: RateScope, subject: string, limit: number, now: Date): Promise<boolean> {
    const count = await this.increment(
      rateLimitKey(scope, subject, now),
      windowMs(scope) + WINDOW_GRACE_MS,
    );
    if (count <= limit) return false;
    this.limited.inc({ scope });
    return true;
  }
}
