import { describe, expect, it } from 'vitest';
import {
  addLatency,
  averageMs,
  DELIVERY_LATENCY_BOUNDS_MS,
  emptyLatency,
  histogramOf,
  isConsistentLatency,
  type LatencySamples,
  percentileUpperBound,
  PROCESSING_LATENCY_BOUNDS_MS,
  successRate,
} from './latency-histogram';

const BOUNDS = [250, 500, 1000] as const;
const sample = (samples: number, sumUs: number, cumulative: number[]): LatencySamples => ({
  samples,
  sumUs,
  cumulative,
});

describe('latency histogram bounds (§3.3.1)', () => {
  it('are the design constants, strictly increasing', () => {
    expect(PROCESSING_LATENCY_BOUNDS_MS).toEqual([
      250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 300000, 900000,
    ]);
    expect(DELIVERY_LATENCY_BOUNDS_MS).toEqual([
      1000, 5000, 10000, 30000, 60000, 300000, 900000, 3600000, 14400000, 86400000,
    ]);
    for (const bounds of [PROCESSING_LATENCY_BOUNDS_MS, DELIVERY_LATENCY_BOUNDS_MS]) {
      for (let i = 1; i < bounds.length; i += 1) expect(bounds[i]!).toBeGreaterThan(bounds[i - 1]!);
    }
  });
});

describe('histogramOf', () => {
  it('turns cumulative counts into per-bucket counts with an overflow bucket', () => {
    expect(histogramOf(BOUNDS, sample(10, 0, [2, 5, 9]))).toEqual([
      { leMs: 250, count: 2 },
      { leMs: 500, count: 3 },
      { leMs: 1000, count: 4 },
      { leMs: null, count: 1 },
    ]);
    expect(histogramOf(BOUNDS, emptyLatency(BOUNDS)).map((b) => b.count)).toEqual([0, 0, 0, 0]);
  });
});

describe('percentileUpperBound', () => {
  it('is the smallest bound whose cumulative count reaches the percentile', () => {
    const v = sample(100, 0, [50, 94, 95]);
    expect(percentileUpperBound(BOUNDS, v, 50)).toBe(250);
    expect(percentileUpperBound(BOUNDS, v, 95)).toBe(1000);
    // 94 of 100 is below 95 %: the next bound.
    expect(percentileUpperBound(BOUNDS, sample(100, 0, [10, 95, 100]), 95)).toBe(500);
  });

  it('uses exact integer comparison (no rounding up of a fraction)', () => {
    // 19 samples: p95 needs cumulative × 100 ≥ 95 × 19 = 1805 → 19 (18 × 100 = 1800 < 1805).
    expect(percentileUpperBound(BOUNDS, sample(19, 0, [18, 18, 19]), 95)).toBe(1000);
    expect(percentileUpperBound(BOUNDS, sample(20, 0, [19, 19, 20]), 95)).toBe(250);
  });

  it('is null without samples or when the percentile is in the overflow bucket', () => {
    expect(percentileUpperBound(BOUNDS, emptyLatency(BOUNDS), 50)).toBeNull();
    expect(percentileUpperBound(BOUNDS, sample(10, 0, [1, 2, 9]), 95)).toBeNull();
    expect(percentileUpperBound(BOUNDS, sample(10, 0, [1, 2, 9]), 50)).toBe(1000);
  });
});

describe('averageMs', () => {
  it('rounds the mean of the microsecond sum to whole milliseconds', () => {
    expect(averageMs(sample(3, 1_000_000 + 2_000_000 + 2_500_000, [0, 0, 0]))).toBe(1833);
    expect(averageMs(sample(2, 1499, [2, 2, 2]))).toBe(1);
    expect(averageMs(emptyLatency(BOUNDS))).toBeNull();
  });
});

describe('addLatency / isConsistentLatency', () => {
  it('adds samples, sums and cumulative counts', () => {
    const total = emptyLatency(BOUNDS);
    addLatency(total, sample(2, 300, [1, 2, 2]));
    addLatency(total, sample(3, 700, [0, 1, 3]));
    expect(total).toEqual(sample(5, 1000, [1, 3, 5]));
    expect(() => addLatency(total, sample(1, 0, [1]))).toThrow();
  });

  it('refuses decreasing, oversized or negative values', () => {
    expect(isConsistentLatency(sample(5, 10, [1, 3, 5]))).toBe(true);
    expect(isConsistentLatency(sample(5, 10, [3, 1, 5]))).toBe(false);
    expect(isConsistentLatency(sample(5, 10, [1, 3, 6]))).toBe(false);
    expect(isConsistentLatency(sample(5, -1, [1, 3, 5]))).toBe(false);
    expect(isConsistentLatency(sample(-1, 0, [0, 0, 0]))).toBe(false);
  });
});

describe('successRate', () => {
  it('is delivered / (delivered + bounced + failed + expired), 4 decimals', () => {
    expect(successRate({ delivered: 2, bounced: 1, failed: 0, expired: 0 })).toBe(0.6667);
    expect(successRate({ delivered: 1, bounced: 0, failed: 0, expired: 0 })).toBe(1);
    expect(successRate({ delivered: 0, bounced: 1, failed: 1, expired: 1 })).toBe(0);
    expect(successRate({ delivered: 1, bounced: 1, failed: 1, expired: 4 })).toBe(0.1429);
  });

  it('is null when no delivery reached a final state', () => {
    expect(successRate({ delivered: 0, bounced: 0, failed: 0, expired: 0 })).toBeNull();
  });
});
