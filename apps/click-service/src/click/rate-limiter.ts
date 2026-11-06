import { createHash } from 'node:crypto';

/**
 * Fixed-window rate limits of the click endpoint (U14 step 1) in the shared Redis: one Lua
 * `INCR` + `PEXPIRE` per key and window (atomic, the first hit sets the expiry). Counters:
 * requests per client network, requests per token, invalid tokens per client network. A Redis
 * error or timeout fails OPEN for rate limiting only (counted by the caller), never for a
 * decision. Keys hold a network prefix and a token hash, never a full token.
 */

/** The subset of ioredis used here. */
export interface RedisEval {
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown>;
}

/** INCR every key; set the window expiry on the first hit; return the counts in key order. */
export const INCR_SCRIPT = `
local out = {}
for i, key in ipairs(KEYS) do
  local n = redis.call('INCR', key)
  if n == 1 then redis.call('PEXPIRE', key, ARGV[1]) end
  out[i] = n
end
return out
`;

/** Read the counters without incrementing (missing → 0). */
export const PEEK_SCRIPT = `
local out = {}
for i, key in ipairs(KEYS) do
  out[i] = tonumber(redis.call('GET', key) or '0')
end
return out
`;

export const RATE_WINDOW_MS = 60_000;
const KEY_PREFIX = 'eg:click:rl:v1';

export interface RateLimits {
  ipPerMinute: number;
  tokenPerMinute: number;
  invalidPerMinute: number;
}

export type RateDecision =
  { limited: false; failedOpen: boolean } | { limited: true; scope: 'ip' | 'token' | 'invalid' };

export const tokenKeyHash = (token: string): string =>
  createHash('sha256').update(token, 'utf8').digest('hex').slice(0, 32);

export class RateLimiter {
  constructor(
    private readonly redis: RedisEval,
    private readonly limits: RateLimits,
    private readonly timeoutMs = 250,
    private readonly now: () => number = Date.now,
  ) {}

  private window(): number {
    return Math.floor(this.now() / RATE_WINDOW_MS);
  }

  private keys(network: string, token: string): { ip: string; token: string; invalid: string } {
    const w = this.window();
    return {
      ip: `${KEY_PREFIX}:ip:${network}:${w}`,
      token: `${KEY_PREFIX}:tok:${tokenKeyHash(token)}:${w}`,
      invalid: `${KEY_PREFIX}:inv:${network}:${w}`,
    };
  }

  private async run(script: string, keys: string[], ...args: number[]): Promise<number[]> {
    let timer: NodeJS.Timeout | undefined;
    try {
      const result = await Promise.race([
        this.redis.eval(script, keys.length, ...keys, ...args),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('rate limiter timeout')), this.timeoutMs);
        }),
      ]);
      if (!Array.isArray(result) || result.length !== keys.length)
        throw new Error('unexpected rate limiter reply');
      return result.map((value) => {
        const n = Number(value);
        if (!Number.isFinite(n)) throw new Error('unexpected rate limiter reply');
        return n;
      });
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Counts this request (network and token windows) and checks the invalid-token window.
   * Throws nothing: a Redis failure returns `{ limited: false, failedOpen: true }`.
   */
  async check(network: string, token: string): Promise<RateDecision> {
    const keys = this.keys(network, token);
    try {
      const [ip = 0, tok = 0] = await this.run(INCR_SCRIPT, [keys.ip, keys.token], RATE_WINDOW_MS);
      const [invalid = 0] = await this.run(PEEK_SCRIPT, [keys.invalid]);
      if (ip > this.limits.ipPerMinute) return { limited: true, scope: 'ip' };
      if (invalid >= this.limits.invalidPerMinute) return { limited: true, scope: 'invalid' };
      if (tok > this.limits.tokenPerMinute) return { limited: true, scope: 'token' };
      return { limited: false, failedOpen: false };
    } catch {
      return { limited: false, failedOpen: true };
    }
  }

  /** Counts one invalid token of `network`; returns false when Redis failed (fail open). */
  async recordInvalid(network: string): Promise<boolean> {
    const keys = this.keys(network, '');
    try {
      await this.run(INCR_SCRIPT, [keys.invalid], RATE_WINDOW_MS);
      return true;
    } catch {
      return false;
    }
  }
}
