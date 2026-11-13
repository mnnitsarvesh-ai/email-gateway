/**
 * Latency histograms of the delivery and processing reports (step 7.1,
 * docs/plan/steps/20-admin-portal.md §3.3.1). MySQL has no percentile function, so the SQL counts
 * the samples at or below each bound (code constants, never input) and the percentiles are
 * reported as histogram UPPER BOUNDS ("p95 ≤ 5 s"): exact for the histogram, never estimated.
 */

/** Time to verdict (`email_scans.received_at` → `completed_at`), milliseconds. */
export const PROCESSING_LATENCY_BOUNDS_MS = Object.freeze([
  250, 500, 1000, 2000, 5000, 10_000, 30_000, 60_000, 120_000, 300_000, 900_000,
] as const);

/** Delivery latency (`email_deliveries.received_at` → `delivered_at`), milliseconds. */
export const DELIVERY_LATENCY_BOUNDS_MS = Object.freeze([
  1000, 5000, 10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000, 14_400_000, 86_400_000,
] as const);

/**
 * Samples of one group: how many, the sum of their latencies in microseconds and, per bound,
 * how many were at or below it (cumulative, as the SQL counts them).
 */
export interface LatencySamples {
  samples: number;
  sumUs: number;
  cumulative: number[];
}

/** One histogram bucket: samples in `(previous bound, leMs]`; `leMs: null` = above the last. */
export interface HistogramBucket {
  leMs: number | null;
  count: number;
}

export const emptyLatency = (bounds: readonly number[]): LatencySamples => ({
  samples: 0,
  sumUs: 0,
  cumulative: bounds.map(() => 0),
});

/** Adds `source` into `target` (same bounds). */
export function addLatency(target: LatencySamples, source: LatencySamples): void {
  if (target.cumulative.length !== source.cumulative.length) {
    throw new Error('addLatency: histograms with different bounds');
  }
  target.samples += source.samples;
  target.sumUs += source.sumUs;
  source.cumulative.forEach((n, i) => {
    target.cumulative[i]! += n;
  });
}

/**
 * True when cumulative counts never decrease and never exceed the sample count (the SQL
 * invariant; a violation is an inconsistent read).
 */
export function isConsistentLatency(value: LatencySamples): boolean {
  let previous = 0;
  for (const n of value.cumulative) {
    if (!Number.isSafeInteger(n) || n < previous || n > value.samples) return false;
    previous = n;
  }
  return Number.isSafeInteger(value.samples) && value.samples >= 0 && value.sumUs >= 0;
}

/** Per-bucket (non-cumulative) counts, the last bucket being the overflow (`leMs: null`). */
export function histogramOf(bounds: readonly number[], value: LatencySamples): HistogramBucket[] {
  const buckets: HistogramBucket[] = [];
  let previous = 0;
  bounds.forEach((leMs, i) => {
    const cumulative = value.cumulative[i] ?? 0;
    buckets.push({ leMs, count: cumulative - previous });
    previous = cumulative;
  });
  buckets.push({ leMs: null, count: value.samples - previous });
  return buckets;
}

/**
 * The smallest bound whose cumulative count reaches `percent` % of the samples (integer
 * arithmetic: `cumulative × 100 ≥ percent × samples`); `null` without samples or when the
 * percentile lies above the last bound (the overflow bucket).
 */
export function percentileUpperBound(
  bounds: readonly number[],
  value: LatencySamples,
  percent: number,
): number | null {
  if (value.samples === 0) return null;
  for (let i = 0; i < bounds.length; i += 1) {
    if ((value.cumulative[i] ?? 0) * 100 >= percent * value.samples) return bounds[i]!;
  }
  return null;
}

/** Mean latency in whole milliseconds; `null` without samples. */
export function averageMs(value: LatencySamples): number | null {
  if (value.samples === 0) return null;
  return Math.round(value.sumUs / value.samples / 1000);
}

/**
 * `delivered / (delivered + bounced + failed + expired)` rounded to 4 decimals; `null` when no
 * delivery reached one of those final states.
 */
export function successRate(statuses: {
  delivered: number;
  bounced: number;
  failed: number;
  expired: number;
}): number | null {
  const completed = statuses.delivered + statuses.bounced + statuses.failed + statuses.expired;
  if (completed === 0) return null;
  return Math.round((statuses.delivered / completed) * 10_000) / 10_000;
}
