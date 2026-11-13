import { describe, expect, it } from 'vitest';
import {
  DEFAULT_WEBHOOK_RETRY_CONFIG,
  isRetryableOutcome,
  nextAttempt,
  parseRetryAfter,
  retryDelayMs,
} from './retry';

const cfg = DEFAULT_WEBHOOK_RETRY_CONFIG;
const mid = () => 0.5; // jitter factor exactly 1.0
const NOW = new Date('2026-11-13T09:00:00.000Z');

describe('retryDelayMs (W10)', () => {
  it('doubles from the base and matches the documented schedule with a neutral jitter', () => {
    const delays = [1, 2, 3, 4, 5, 6, 7].map((n) => retryDelayMs(n, cfg, mid) / 1000);
    expect(delays).toEqual([30, 60, 120, 240, 480, 960, 1920]);
    // Cumulative attempt times ≈ 0, 30 s, 1.5, 3.5, 7.5, 15.5, 31.5, 63.5 min.
    const at = delays.reduce<number[]>((acc, d) => [...acc, acc.at(-1)! + d], [0]);
    expect(at.map((s) => s / 60)).toEqual([0, 0.5, 1.5, 3.5, 7.5, 15.5, 31.5, 63.5]);
  });

  it('applies full jitter in [0.8, 1.2] × delay', () => {
    expect(retryDelayMs(1, cfg, () => 0)).toBe(24_000);
    expect(retryDelayMs(1, cfg, () => 0.999_999_999)).toBe(36_000);
    for (let i = 0; i < 200; i += 1) {
      const d = retryDelayMs(3, cfg);
      expect(d).toBeGreaterThanOrEqual(96_000);
      expect(d).toBeLessThanOrEqual(144_000);
    }
  });

  it('caps the base delay at WEBHOOK_RETRY_MAX_DELAY_SECONDS', () => {
    expect(retryDelayMs(30, cfg, mid)).toBe(21_600_000);
    expect(retryDelayMs(1000, { baseSeconds: 600, maxDelaySeconds: 3600 }, mid)).toBe(3_600_000);
    expect(() => retryDelayMs(0, cfg)).toThrow();
  });
});

describe('parseRetryAfter (W10)', () => {
  it('reads delta-seconds and HTTP-dates', () => {
    expect(parseRetryAfter('2', NOW)).toBe(2000);
    expect(parseRetryAfter(' 120 ', NOW)).toBe(120_000);
    expect(parseRetryAfter('0', NOW)).toBe(0);
    expect(parseRetryAfter('Fri, 13 Nov 2026 09:01:00 GMT', NOW)).toBe(60_000);
    expect(parseRetryAfter('Friday, 13-Nov-26 09:00:30 GMT', NOW)).toBe(30_000);
    expect(parseRetryAfter('Fri Nov 13 09:00:10 2026', NOW.getTime())).toBe(10_000);
  });

  it('returns null for invalid, negative and past values', () => {
    for (const value of [
      undefined,
      null,
      '',
      'soon',
      '-5',
      '1.5',
      '2026-11-13T09:01:00Z',
      'Fri, 31 Foo 2026',
    ]) {
      expect(parseRetryAfter(value, NOW), String(value)).toBeNull();
    }
    expect(parseRetryAfter('Fri, 13 Nov 2026 08:59:00 GMT', NOW)).toBeNull();
  });
});

describe('nextAttempt (W10)', () => {
  const first = new Date(NOW.getTime() - 60_000);

  it('schedules the next attempt from the backoff', () => {
    expect(
      nextAttempt({ attemptNo: 1, firstAttemptAt: first, now: NOW, cfg, random: mid }),
    ).toEqual({
      kind: 'retry',
      at: new Date(NOW.getTime() + 30_000),
      delayMs: 30_000,
    });
  });

  it('honors Retry-After as max(computed, retryAfter), clamped to the cap, never ignored', () => {
    const at = (retryAfterMs: number | null) =>
      nextAttempt({
        attemptNo: 1,
        firstAttemptAt: first,
        now: NOW,
        cfg,
        random: mid,
        retryAfterMs,
      });
    expect(at(2_000)).toMatchObject({ delayMs: 30_000 });
    expect(at(600_000)).toMatchObject({ delayMs: 600_000 });
    expect(at(10 * 3_600_000)).toMatchObject({ delayMs: 3_600_000 });
    expect(at(null)).toMatchObject({ delayMs: 30_000 });
    const small = { ...cfg, retryAfterMaxSeconds: 10 };
    expect(
      nextAttempt({
        attemptNo: 1,
        firstAttemptAt: first,
        now: NOW,
        cfg: small,
        random: mid,
        retryAfterMs: 999_999,
      }),
    ).toMatchObject({ delayMs: 30_000 });
  });

  it('dead-letters after max attempts or max age', () => {
    expect(nextAttempt({ attemptNo: 8, firstAttemptAt: first, now: NOW, cfg })).toEqual({
      kind: 'dead',
      reason: 'max_attempts',
    });
    expect(
      nextAttempt({ attemptNo: 7, firstAttemptAt: first, now: NOW, cfg, random: mid }),
    ).toMatchObject({
      kind: 'retry',
    });
    const old = new Date(NOW.getTime() - 24 * 3_600_000 - 1);
    expect(nextAttempt({ attemptNo: 2, firstAttemptAt: old, now: NOW, cfg })).toEqual({
      kind: 'dead',
      reason: 'max_age',
    });
    const exactly = new Date(NOW.getTime() - 24 * 3_600_000);
    expect(
      nextAttempt({ attemptNo: 2, firstAttemptAt: exactly, now: NOW, cfg, random: mid }),
    ).toMatchObject({
      kind: 'retry',
    });
  });

  it('classifies outcomes: blocked is final, the rest retry', () => {
    for (const outcome of [
      'http_error',
      'redirect',
      'timeout',
      'dns_error',
      'connection_error',
      'tls_error',
      'too_large',
      'secret_unavailable',
    ]) {
      expect(isRetryableOutcome(outcome), outcome).toBe(true);
    }
    expect(isRetryableOutcome('blocked')).toBe(false);
    expect(isRetryableOutcome('succeeded')).toBe(false);
  });
});
