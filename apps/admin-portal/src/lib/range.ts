/**
 * Report ranges (design P13): presets `24h` (hour buckets), `7d` and `30d` (day buckets) and a
 * custom from/to of whole UTC days, at most REPORTS_MAX_RANGE_DAYS days.
 */
export const REPORTS_MAX_RANGE_DAYS = 31;
export const RANGE_PRESETS = ['24h', '7d', '30d'] as const;
export type RangePreset = (typeof RANGE_PRESETS)[number];

export interface ResolvedRange {
  /** ISO 8601, inclusive. */
  readonly from: string;
  /** ISO 8601, exclusive. */
  readonly to: string;
  readonly granularity: 'hour' | 'day';
  readonly preset: RangePreset | 'custom';
  readonly label: string;
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const PRESET_LABEL: Record<RangePreset, string> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

/** `to` is the next whole UTC hour (stable within the hour, so query keys do not churn). */
export function resolvePreset(preset: RangePreset, now = Date.now()): ResolvedRange {
  const to = Math.ceil(now / HOUR) * HOUR;
  const duration = preset === '24h' ? DAY : preset === '7d' ? 7 * DAY : 30 * DAY;
  return {
    from: new Date(to - duration).toISOString(),
    to: new Date(to).toISOString(),
    granularity: preset === '24h' ? 'hour' : 'day',
    preset,
    label: PRESET_LABEL[preset],
  };
}

const DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

export type CustomRangeError = 'invalid' | 'order' | 'too_long' | 'future';

/** Validates a custom range of UTC days (`to` inclusive in the UI, exclusive on the wire). */
export function validateCustomRange(
  fromDay: string,
  toDay: string,
  now = Date.now(),
): { ok: true; range: ResolvedRange } | { ok: false; error: CustomRangeError; message: string } {
  if (!DAY_PATTERN.test(fromDay) || !DAY_PATTERN.test(toDay)) {
    return { ok: false, error: 'invalid', message: 'Enter both dates.' };
  }
  const from = Date.parse(`${fromDay}T00:00:00.000Z`);
  const toInclusive = Date.parse(`${toDay}T00:00:00.000Z`);
  if (!Number.isFinite(from) || !Number.isFinite(toInclusive)) {
    return { ok: false, error: 'invalid', message: 'Enter valid dates.' };
  }
  if (toInclusive < from) {
    return {
      ok: false,
      error: 'order',
      message: 'The end date must not be before the start date.',
    };
  }
  const days = (toInclusive - from) / DAY + 1;
  if (days > REPORTS_MAX_RANGE_DAYS) {
    return {
      ok: false,
      error: 'too_long',
      message: `Choose at most ${REPORTS_MAX_RANGE_DAYS} days (longer ranges arrive with the analytics store).`,
    };
  }
  if (from > now)
    return { ok: false, error: 'future', message: 'The start date is in the future.' };
  return {
    ok: true,
    range: {
      from: new Date(from).toISOString(),
      to: new Date(toInclusive + DAY).toISOString(),
      granularity: 'day',
      preset: 'custom',
      label: `${fromDay} – ${toDay} (UTC)`,
    },
  };
}
