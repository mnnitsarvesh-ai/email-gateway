/**
 * Minute-precision time ranges (step 7.2 §2 E10): presets `1h`, `24h`, `7d`, `30d` and a custom
 * from/to typed in the browser's time zone and sent as UTC ISO 8601. At most
 * `MESSAGES_MAX_RANGE_DAYS` days (the api's `API_MESSAGES_MAX_RANGE_DAYS` default). Pure
 * functions: `now` is always passed in, so the bounds are unit-tested.
 */
export const DATE_TIME_PRESETS = ['1h', '24h', '7d', '30d'] as const;
export type DateTimePreset = (typeof DATE_TIME_PRESETS)[number];
export const DATE_TIME_RANGE_KINDS = [...DATE_TIME_PRESETS, 'custom'] as const;
export type DateTimeRangeKind = (typeof DATE_TIME_RANGE_KINDS)[number];

/** The api default of `API_MESSAGES_MAX_RANGE_DAYS` (and of saved views' absolute ranges). */
export const MESSAGES_MAX_RANGE_DAYS = 31;

export const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

export const PRESET_DURATION_MS: Readonly<Record<DateTimePreset, number>> = {
  '1h': HOUR_MS,
  '24h': DAY_MS,
  '7d': 7 * DAY_MS,
  '30d': 30 * DAY_MS,
};

export const DATE_TIME_PRESET_LABEL: Readonly<Record<DateTimePreset, string>> = {
  '1h': 'Last hour',
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

export type DateTimeRangeValue =
  | { readonly kind: DateTimePreset }
  | { readonly kind: 'custom'; readonly from: string; readonly to: string };

export interface ResolvedDateTimeRange {
  /** UTC ISO 8601, inclusive. */
  readonly from: string;
  /** UTC ISO 8601, exclusive. */
  readonly to: string;
  readonly kind: DateTimeRangeKind;
}

/**
 * A preset ends at the next whole minute after `now` (so the current minute is included and the
 * query key changes at most once a minute); a custom range is used as given.
 */
export function resolveDateTimeRange(
  value: DateTimeRangeValue,
  now: number,
): ResolvedDateTimeRange {
  if (value.kind === 'custom') return { from: value.from, to: value.to, kind: 'custom' };
  const to = Math.ceil(now / MINUTE_MS) * MINUTE_MS;
  return {
    from: new Date(to - PRESET_DURATION_MS[value.kind]).toISOString(),
    to: new Date(to).toISOString(),
    kind: value.kind,
  };
}

/** `2026-11-13T08:00:00.000Z` (UTC, whole minute): the URL form of a custom bound. */
const MINUTE_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::00(?:\.000)?)?Z$/;

export function isMinuteIso(value: string): boolean {
  return MINUTE_ISO.test(value) && Number.isFinite(Date.parse(value));
}

const pad = (n: number) => String(n).padStart(2, '0');

/** A UTC instant as the `datetime-local` value of the browser's time zone (`YYYY-MM-DDTHH:mm`). */
export function toLocalInput(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

const LOCAL_INPUT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::\d{2}(?:\.\d+)?)?$/;

/**
 * A `datetime-local` value (browser time zone) as UTC ISO at minute precision, or null when it is
 * not a real local date-time (e.g. `2026-02-30T10:00`).
 */
export function fromLocalInput(local: string): string | null {
  const match = LOCAL_INPUT.exec(local.trim());
  if (!match) return null;
  const [, y, mo, d, h, mi] = match.map(Number) as [number, number, number, number, number, number];
  const date = new Date(y, mo - 1, d, h, mi, 0, 0);
  if (
    date.getFullYear() !== y ||
    date.getMonth() !== mo - 1 ||
    date.getDate() !== d ||
    date.getHours() !== h ||
    date.getMinutes() !== mi
  ) {
    // Not a calendar date, or a local time skipped by a daylight-saving change.
    return null;
  }
  return date.toISOString();
}

export type DateTimeRangeError =
  | { readonly field: 'from' | 'to'; readonly message: string }
  | { readonly field: 'range'; readonly message: string };

/**
 * Validates a custom range typed in the browser's time zone: both bounds required, real
 * date-times, `from` before `to`, `from` not in the future, at most `maxDays` days.
 */
export function validateCustomDateTimeRange(
  fromLocal: string,
  toLocal: string,
  now: number,
  maxDays = MESSAGES_MAX_RANGE_DAYS,
): { ok: true; from: string; to: string } | { ok: false; errors: DateTimeRangeError[] } {
  const errors: DateTimeRangeError[] = [];
  const from = fromLocal ? fromLocalInput(fromLocal) : null;
  const to = toLocal ? fromLocalInput(toLocal) : null;
  if (!fromLocal) errors.push({ field: 'from', message: 'Enter the start date and time.' });
  else if (!from) errors.push({ field: 'from', message: 'Enter a valid start date and time.' });
  if (!toLocal) errors.push({ field: 'to', message: 'Enter the end date and time.' });
  else if (!to) errors.push({ field: 'to', message: 'Enter a valid end date and time.' });
  if (from && to) {
    const start = Date.parse(from);
    const end = Date.parse(to);
    if (end <= start) {
      errors.push({ field: 'to', message: 'The end must be after the start.' });
    } else if (end - start > maxDays * DAY_MS) {
      errors.push({ field: 'range', message: `Choose a range of at most ${maxDays} days.` });
    }
    if (start > now) errors.push({ field: 'from', message: 'The start is in the future.' });
  }
  return errors.length > 0 ? { ok: false, errors } : { ok: true, from: from ?? '', to: to ?? '' };
}

/** Whether URL bounds form an acceptable custom range (silently ignored otherwise). */
export function isValidCustomRange(
  from: string | undefined,
  to: string | undefined,
  maxDays = MESSAGES_MAX_RANGE_DAYS,
): boolean {
  if (!from || !to || !isMinuteIso(from) || !isMinuteIso(to)) return false;
  const start = Date.parse(from);
  const end = Date.parse(to);
  return end > start && end - start <= maxDays * DAY_MS;
}

/** The browser's IANA time zone (`Europe/Berlin`), or `local time` when unknown. */
export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time';
  } catch {
    return 'local time';
  }
}

/** `13 Nov 2026, 08:00 – 14 Nov 2026, 08:00` in the browser's locale and time zone. */
export function formatLocalRange(from: string, to: string): string {
  const format = new Intl.DateTimeFormat(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
  return `${format.format(new Date(from))} – ${format.format(new Date(to))}`;
}
