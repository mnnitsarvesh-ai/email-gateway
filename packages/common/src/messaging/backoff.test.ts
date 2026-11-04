import { describe, expect, it } from 'vitest';
import { backoffDelay, sleep } from './backoff';

const policy = { baseMs: 1000, maxMs: 60_000 };

describe('backoffDelay (equal jitter)', () => {
  it('doubles per attempt: d = base * 2^(n-1), delay in [d/2, d]', () => {
    expect(backoffDelay(1, policy, () => 0)).toBe(500);
    expect(backoffDelay(1, policy, () => 0.999999)).toBe(999);
    expect(backoffDelay(2, policy, () => 0)).toBe(1000);
    expect(backoffDelay(3, policy, () => 0.5)).toBe(3000);
    expect(backoffDelay(4, policy, () => 0)).toBe(4000);
  });

  it('never goes below half of d and never above d', () => {
    for (let n = 1; n <= 20; n += 1) {
      const d = Math.min(policy.maxMs, policy.baseMs * 2 ** (n - 1));
      for (const r of [0, 0.1, 0.5, 0.9, 0.999]) {
        const delay = backoffDelay(n, policy, () => r);
        expect(delay).toBeGreaterThanOrEqual(Math.floor(d / 2));
        expect(delay).toBeLessThanOrEqual(d);
      }
    }
  });

  it('caps at maxMs', () => {
    expect(backoffDelay(7, policy, () => 0)).toBe(30_000);
    expect(backoffDelay(30, policy, () => 0.999999)).toBe(59_999);
  });

  it('is overflow-safe for huge or odd attempt numbers', () => {
    for (const n of [1_000, 1e9, Number.MAX_SAFE_INTEGER, Number.POSITIVE_INFINITY]) {
      const delay = backoffDelay(n, policy, () => 0.5);
      expect(Number.isFinite(delay)).toBe(true);
      expect(delay).toBe(45_000);
    }
    expect(backoffDelay(0, policy, () => 0)).toBe(500);
    expect(backoffDelay(-3, policy, () => 0)).toBe(500);
    expect(backoffDelay(Number.NaN, policy, () => 0)).toBe(30_000);
  });

  it('clamps an out-of-range random source', () => {
    expect(backoffDelay(1, policy, () => 5)).toBe(1000);
    expect(backoffDelay(1, policy, () => -1)).toBe(500);
    expect(backoffDelay(1, policy, () => Number.NaN)).toBe(500);
  });

  it('uses Math.random by default within the bounds', () => {
    const delay = backoffDelay(2, policy);
    expect(delay).toBeGreaterThanOrEqual(1000);
    expect(delay).toBeLessThanOrEqual(2000);
  });
});

describe('sleep', () => {
  it('resolves true after the delay and false when aborted', async () => {
    expect(await sleep(1)).toBe(true);
    const controller = new AbortController();
    const pending = sleep(10_000, controller.signal);
    controller.abort();
    expect(await pending).toBe(false);
    expect(await sleep(10, controller.signal)).toBe(false);
  });
});
