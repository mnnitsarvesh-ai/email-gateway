import { describe, expect, it } from 'vitest';
import { nextWindowStart, retryDelayMs, sleep } from './backoff';

describe('retryDelayMs (R8 step 4)', () => {
  const options = { baseSeconds: 30, maxSeconds: 900 };

  it('doubles from the base up to the maximum', () => {
    const mid = () => 0.5; // no jitter
    expect(retryDelayMs(1, options, mid)).toBe(30_000);
    expect(retryDelayMs(2, options, mid)).toBe(60_000);
    expect(retryDelayMs(3, options, mid)).toBe(120_000);
    expect(retryDelayMs(6, options, mid)).toBe(900_000);
    expect(retryDelayMs(60, options, mid)).toBe(900_000);
    expect(retryDelayMs(0, options, mid)).toBe(30_000);
  });

  it('adds at most ±10 % jitter', () => {
    expect(retryDelayMs(1, options, () => 0)).toBe(27_000);
    expect(retryDelayMs(1, options, () => 0.999999)).toBeLessThanOrEqual(33_000);
    for (let i = 0; i < 100; i += 1) {
      const delay = retryDelayMs(2, options);
      expect(delay).toBeGreaterThanOrEqual(54_000);
      expect(delay).toBeLessThanOrEqual(66_000);
    }
  });
});

describe('nextWindowStart (R11)', () => {
  it('is the next UTC minute plus up to 2 s of jitter', () => {
    const now = new Date('2026-11-03T10:15:42.500Z');
    expect(nextWindowStart(now, () => 0).toISOString()).toBe('2026-11-03T10:16:00.000Z');
    expect(nextWindowStart(now, () => 0.9999).getTime()).toBeLessThan(
      Date.parse('2026-11-03T10:16:02.000Z'),
    );
  });
});

describe('sleep', () => {
  it('resolves early when aborted', async () => {
    const controller = new AbortController();
    const started = Date.now();
    const done = sleep(10_000, controller.signal);
    controller.abort();
    await done;
    expect(Date.now() - started).toBeLessThan(1000);
  });
});
