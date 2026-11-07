import { describe, expect, it } from 'vitest';
import { llmGatePasses, Semaphore } from './ai-layer';
import {
  BUDGET_SCRIPT,
  budgetKeys,
  MINUTE_WINDOW_TTL_SECONDS,
  RedisLlmBudget,
  type RedisEval,
  TENANT_WINDOW_TTL_SECONDS,
  utcDay,
} from './llm-budget';

/** Executes BUDGET_SCRIPT's semantics over an in-memory map (the script is asserted too). */
class FakeRedis implements RedisEval {
  readonly counters = new Map<string, number>();
  readonly ttls = new Map<string, number>();
  calls = 0;
  failWith: Error | null = null;
  hang = false;

  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown> {
    this.calls += 1;
    if (this.failWith) return Promise.reject(this.failWith);
    if (this.hang) return new Promise(() => undefined);
    expect(script).toBe(BUDGET_SCRIPT);
    expect(numKeys).toBe(2);
    const [tenantKey, minuteKey, tenantLimit, minuteLimit, tenantTtl, minuteTtl] = args as [
      string,
      string,
      number,
      number,
      number,
      number,
    ];
    if ((this.counters.get(tenantKey) ?? 0) >= tenantLimit) return Promise.resolve(1);
    if ((this.counters.get(minuteKey) ?? 0) >= minuteLimit) return Promise.resolve(2);
    for (const [key, ttl] of [
      [tenantKey, tenantTtl],
      [minuteKey, minuteTtl],
    ] as const) {
      const n = (this.counters.get(key) ?? 0) + 1;
      this.counters.set(key, n);
      if (n === 1) this.ttls.set(key, ttl);
    }
    return Promise.resolve(0);
  }
}

const NOW = Date.parse('2026-11-06T23:59:30.000Z');

describe('LLM budgets (step 4.4 B10)', () => {
  it('uses the documented fixed-window keys (UTC day, epoch minute) and TTLs', () => {
    expect(utcDay(NOW)).toBe('20261106');
    expect(budgetKeys(42n, NOW)).toEqual({
      tenant: 'eg:bec:llm:t:42:20261106',
      minute: `eg:bec:llm:m:${String(Math.floor(NOW / 60_000))}`,
    });
    expect(BUDGET_SCRIPT).toMatch(/INCR/);
    expect(BUDGET_SCRIPT).toMatch(/EXPIRE/);
  });

  it('allows until the tenant day limit, then tenant_exhausted (the minute window is untouched)', async () => {
    const redis = new FakeRedis();
    const budget = new RedisLlmBudget(redis, 100, 500, () => NOW);
    expect(await budget.check(42n, 2)).toBe('allowed');
    expect(await budget.check(42n, 2)).toBe('allowed');
    expect(await budget.check(42n, 2)).toBe('tenant_exhausted');
    const keys = budgetKeys(42n, NOW);
    expect(redis.counters.get(keys.tenant)).toBe(2);
    expect(redis.counters.get(keys.minute)).toBe(2);
    expect(redis.ttls.get(keys.tenant)).toBe(TENANT_WINDOW_TTL_SECONDS);
    expect(redis.ttls.get(keys.minute)).toBe(MINUTE_WINDOW_TTL_SECONDS);
    // Another tenant has its own day window.
    expect(await budget.check(43n, 2)).toBe('allowed');
  });

  it('the platform minute window is shared: platform_exhausted, and a new minute allows again', async () => {
    const redis = new FakeRedis();
    let now = NOW;
    const budget = new RedisLlmBudget(redis, 2, 500, () => now);
    expect(await budget.check(1n, 100)).toBe('allowed');
    expect(await budget.check(2n, 100)).toBe('allowed');
    expect(await budget.check(3n, 100)).toBe('platform_exhausted');
    now += 60_000;
    expect(await budget.check(3n, 100)).toBe('allowed');
  });

  it('a Redis error, timeout, unexpected reply or no Redis is unavailable (no call is made)', async () => {
    const failing = new FakeRedis();
    failing.failWith = new Error('ECONNREFUSED');
    expect(await new RedisLlmBudget(failing, 10, 500, () => NOW).check(1n, 10)).toBe('unavailable');
    const hanging = new FakeRedis();
    hanging.hang = true;
    expect(await new RedisLlmBudget(hanging, 10, 20, () => NOW).check(1n, 10)).toBe('unavailable');
    const odd: RedisEval = { eval: () => Promise.resolve('OK') };
    expect(await new RedisLlmBudget(odd, 10, 500, () => NOW).check(1n, 10)).toBe('unavailable');
    expect(await new RedisLlmBudget(null, 10).check(1n, 10)).toBe('unavailable');
  });
});

describe('LLM gating (B10) and the concurrency semaphore', () => {
  const rules = (over: Partial<Parameters<typeof llmGatePasses>[0]> = {}) => ({
    verdict: 'clean' as const,
    score: 0,
    inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' } as const,
    firedRules: [] as Parameters<typeof llmGatePasses>[0]['firedRules'],
    ...over,
  });
  const intent: Parameters<typeof llmGatePasses>[0]['firedRules'][number] = {
    id: 'C1',
    code: 'bec.content.payment_request',
    category: 'intent',
    severity: 'medium',
    weight: 15,
    suppressed: null,
    evidence: [],
  };

  it('asks the LLM for borderline scores or intent, never for skipped/malicious/empty messages', () => {
    expect(llmGatePasses(rules(), 15, 80)).toBe(false);
    expect(llmGatePasses(rules({ score: 15 }), 15, 80)).toBe(true);
    expect(llmGatePasses(rules({ score: 79, verdict: 'suspicious' }), 15, 80)).toBe(true);
    expect(llmGatePasses(rules({ score: 80, verdict: 'suspicious' }), 15, 80)).toBe(false);
    expect(llmGatePasses(rules({ score: 5, firedRules: [intent] }), 15, 80)).toBe(true);
    expect(
      llmGatePasses(
        rules({ score: 5, firedRules: [{ ...intent, suppressed: 'feedback' }] }),
        15,
        80,
      ),
    ).toBe(false);
    expect(
      llmGatePasses(rules({ score: 90, verdict: 'malicious', firedRules: [intent] }), 15, 80),
    ).toBe(false);
    expect(llmGatePasses(rules({ verdict: 'skipped', score: 20 }), 15, 80)).toBe(false);
    expect(
      llmGatePasses(
        rules({
          score: 20,
          inputs: { auth: 'failed', url: 'not_in_round', text: 'absent', history: 'disabled' },
        }),
        15,
        80,
      ),
    ).toBe(false);
  });

  it('bounds concurrent calls; a waiter gives up when its signal aborts', async () => {
    const semaphore = new Semaphore(1);
    const first = await semaphore.acquire(new AbortController().signal);
    expect(first).not.toBeNull();
    const controller = new AbortController();
    const waiting = semaphore.acquire(controller.signal);
    controller.abort();
    expect(await waiting).toBeNull();
    const next = semaphore.acquire(new AbortController().signal);
    first!();
    const release = await next;
    expect(semaphore.inUse).toBe(1);
    release!();
    release!();
    expect(semaphore.inUse).toBe(0);
  });
});
