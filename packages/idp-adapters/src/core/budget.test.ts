import { describe, expect, it, vi } from 'vitest';
import { InMemoryRateBudget } from '../testing/in-memory-stores';
import { RATE_BUDGET_RETRY_AFTER_MS, takeBudget } from './budget';
import { ProviderCallError } from './errors';

const limits = { graph: 2, o365: 1, google_reports: 1, google_directory: 1, gmail: 1 };

describe('rate budgets (D7.5)', () => {
  it('allows the per-second limit per integration and family', async () => {
    let now = 1_000_000;
    const budget = new InMemoryRateBudget(limits, () => now);
    const signal = new AbortController().signal;
    expect(await budget.take('1', 'graph', signal)).toBe('ok');
    expect(await budget.take('1', 'graph', signal)).toBe('ok');
    expect(await budget.take('1', 'graph', signal)).toBe('exhausted');
    expect(await budget.take('2', 'graph', signal)).toBe('ok');
    expect(await budget.take('1', 'o365', signal)).toBe('ok');
    now += 1000;
    expect(await budget.take('1', 'graph', signal)).toBe('ok');
  });

  it('waits up to 1 s, then fails rate_budget (retryable, retryAfterMs 1000)', async () => {
    const budget = new InMemoryRateBudget(limits);
    budget.exhaust('graph');
    const sleep = vi.fn(() => Promise.resolve());
    const metrics = { rateBudgetWait: vi.fn() };
    const error = await takeBudget({
      budget,
      integrationId: '1',
      family: 'graph',
      signal: new AbortController().signal,
      sleep,
      metrics,
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ProviderCallError);
    expect(error).toMatchObject({
      code: 'rate_budget',
      retryable: true,
      retryAfterMs: RATE_BUDGET_RETRY_AFTER_MS,
    });
    expect(sleep).toHaveBeenCalledTimes(10);
    expect(metrics.rateBudgetWait).toHaveBeenCalledTimes(1);
  });

  it('continues once the budget frees within the wait', async () => {
    const budget = new InMemoryRateBudget(limits);
    budget.exhaust('gmail');
    const sleep = vi.fn(() => {
      budget.restore('gmail');
      return Promise.resolve();
    });
    await takeBudget({
      budget,
      integrationId: '1',
      family: 'gmail',
      signal: new AbortController().signal,
      sleep,
    });
    expect(sleep).toHaveBeenCalledTimes(1);
  });
});
