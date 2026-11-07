import type { BudgetResult } from './bec-metrics';

/**
 * LLM call budgets of the bec engine (step 4.4 B10) in the shared Redis: a per-tenant daily
 * fixed window `eg:bec:llm:t:<org>:<yyyymmdd>` (UTC; limit = the tenant's effective
 * `ai.llmDailyCallLimit` ≤ BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY) and a platform per-minute fixed
 * window `eg:bec:llm:m:<epochMinute>` (BEC_LLM_MAX_CALLS_PER_MINUTE). One Lua script checks both
 * windows and increments both only when both have room (`INCR` + `EXPIRE` on the first hit), so a
 * refused call never consumes the other window and the check is atomic across workers.
 *
 * **Never call without a passed budget check:** a Redis error, timeout or unexpected reply is
 * `unavailable` and the caller records the assessment as `skipped`. Keys hold the organization
 * id and a time bucket only.
 */

/** The subset of ioredis used here. */
export interface RedisEval {
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown>;
}

/**
 * KEYS[1] tenant day window, KEYS[2] platform minute window; ARGV: tenant limit, minute limit,
 * tenant TTL seconds, minute TTL seconds. Returns 0 allowed, 1 tenant exhausted, 2 platform
 * exhausted.
 */
export const BUDGET_SCRIPT = `
local tenant = tonumber(redis.call('GET', KEYS[1]) or '0')
if tenant >= tonumber(ARGV[1]) then return 1 end
local minute = tonumber(redis.call('GET', KEYS[2]) or '0')
if minute >= tonumber(ARGV[2]) then return 2 end
if redis.call('INCR', KEYS[1]) == 1 then redis.call('EXPIRE', KEYS[1], ARGV[3]) end
if redis.call('INCR', KEYS[2]) == 1 then redis.call('EXPIRE', KEYS[2], ARGV[4]) end
return 0
`;

const KEY_PREFIX = 'eg:bec:llm';
/** The day window lives two days (a window that started just before midnight UTC). */
export const TENANT_WINDOW_TTL_SECONDS = 2 * 86_400;
export const MINUTE_WINDOW_TTL_SECONDS = 120;

/** `yyyymmdd` of a time (UTC). */
export function utcDay(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getUTCFullYear())}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(
    d.getUTCDate(),
  ).padStart(2, '0')}`;
}

export function budgetKeys(
  organizationId: bigint,
  nowMs: number,
): { tenant: string; minute: string } {
  return {
    tenant: `${KEY_PREFIX}:t:${organizationId.toString()}:${utcDay(nowMs)}`,
    minute: `${KEY_PREFIX}:m:${String(Math.floor(nowMs / 60_000))}`,
  };
}

export interface LlmBudgetCheck {
  check(organizationId: bigint, tenantDailyLimit: number): Promise<BudgetResult>;
}

export class RedisLlmBudget implements LlmBudgetCheck {
  constructor(
    /** Null: no Redis configured → every check is `unavailable` (no call). */
    private readonly redis: RedisEval | null,
    private readonly perMinute: number,
    private readonly timeoutMs = 500,
    private readonly now: () => number = Date.now,
  ) {}

  async check(organizationId: bigint, tenantDailyLimit: number): Promise<BudgetResult> {
    if (!this.redis) return 'unavailable';
    const keys = budgetKeys(organizationId, this.now());
    let timer: NodeJS.Timeout | undefined;
    try {
      const reply = await Promise.race([
        this.redis.eval(
          BUDGET_SCRIPT,
          2,
          keys.tenant,
          keys.minute,
          Math.max(0, Math.floor(tenantDailyLimit)),
          this.perMinute,
          TENANT_WINDOW_TTL_SECONDS,
          MINUTE_WINDOW_TTL_SECONDS,
        ),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('llm budget timeout')), this.timeoutMs);
        }),
      ]);
      const code = Number(reply);
      if (code === 0) return 'allowed';
      if (code === 1) return 'tenant_exhausted';
      if (code === 2) return 'platform_exhausted';
      return 'unavailable';
    } catch {
      return 'unavailable';
    } finally {
      clearTimeout(timer);
    }
  }
}
