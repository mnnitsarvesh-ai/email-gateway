import { BadRequestException } from '@nestjs/common';

/**
 * Report windows (step 6.1 D12, docs/plan/steps/18-rest-api.md §3.3): bounded UTC ranges aligned
 * to bucket boundaries. `from` is floored and `to` ceiled to the bucket size, so a report always
 * covers whole buckets and two requests in the same bucket resolve to the same window (the report
 * cache key, D12). The span limit applies to the requested range; alignment adds less than one
 * bucket at each end.
 */

export const REPORT_GRANULARITIES = ['hour', 'day'] as const;
export type ReportGranularity = (typeof REPORT_GRANULARITIES)[number];

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

export const BUCKET_MS: Readonly<Record<ReportGranularity, number>> = Object.freeze({
  hour: HOUR_MS,
  day: DAY_MS,
});

/** `granularity=hour` covers at most 7 days (D12). */
export const HOUR_GRANULARITY_MAX_DAYS = 7;

/** Default window when `from` is omitted: the last 24 hours (hour) or 7 days (day, threats). */
export const DEFAULT_REPORT_RANGE_MS: Readonly<Record<ReportGranularity, number>> = Object.freeze({
  hour: DAY_MS,
  day: 7 * DAY_MS,
});

export interface ReportWindow {
  /** Inclusive, aligned to the bucket size (UTC). */
  from: Date;
  /** Exclusive, aligned to the bucket size (UTC). */
  to: Date;
  granularity: ReportGranularity;
}

/** Start of the UTC bucket containing `instant` (epoch-aligned: hours and days are UTC). */
export function floorTo(instant: Date, granularity: ReportGranularity): Date {
  const size = BUCKET_MS[granularity];
  return new Date(Math.floor(instant.getTime() / size) * size);
}

/** The first bucket boundary at or after `instant`. */
export function ceilTo(instant: Date, granularity: ReportGranularity): Date {
  const size = BUCKET_MS[granularity];
  return new Date(Math.ceil(instant.getTime() / size) * size);
}

/** Longest requested range of a granularity: hour ≤ 7 days, day ≤ `REPORTS_MAX_RANGE_DAYS`. */
export function maxRangeDays(granularity: ReportGranularity, reportsMaxDays: number): number {
  return granularity === 'hour'
    ? Math.min(HOUR_GRANULARITY_MAX_DAYS, reportsMaxDays)
    : reportsMaxDays;
}

/**
 * Resolves `[from, to)`: `to` defaults to now, `from` to `to − defaultMs`; `from < to` and at most
 * `maxDays` days (else `400 validation_failed`), then aligned to the granularity.
 */
export function resolveReportWindow(
  query: { from?: Date | undefined; to?: Date | undefined },
  options: { granularity: ReportGranularity; maxDays: number; defaultMs?: number; now: Date },
): ReportWindow {
  const { granularity, maxDays, now } = options;
  const to = query.to ?? now;
  const from =
    query.from ??
    new Date(to.getTime() - (options.defaultMs ?? DEFAULT_REPORT_RANGE_MS[granularity]));
  if (from.getTime() >= to.getTime()) {
    throw new BadRequestException(['from: must be before to']);
  }
  if (to.getTime() - from.getTime() > maxDays * DAY_MS) {
    throw new BadRequestException([
      `to: a ${granularity} report may cover at most ${maxDays} day${maxDays === 1 ? '' : 's'}`,
    ]);
  }
  return { from: floorTo(from, granularity), to: ceilTo(to, granularity), granularity };
}

/** Every bucket start of the window, oldest first. */
export function bucketStarts(window: ReportWindow): Date[] {
  const size = BUCKET_MS[window.granularity];
  const starts: Date[] = [];
  for (let t = window.from.getTime(); t < window.to.getTime(); t += size) starts.push(new Date(t));
  return starts;
}
