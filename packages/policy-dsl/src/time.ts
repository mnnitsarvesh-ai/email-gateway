import { WEEKDAYS, type Weekday } from './vocabulary';

/**
 * Time conditions (step 5.2 P2, P3): the evaluation time is a fact of the input (never the
 * clock); local wall time comes from `Intl.DateTimeFormat` with the IANA zone of the condition.
 * DST gaps and overlaps follow from that: an instant always has exactly one local time.
 */

const ZONE_PATTERN = /^[A-Za-z][A-Za-z0-9_+-]{0,31}(\/[A-Za-z0-9_+-]{1,32}){0,2}$/;
const formatters = new Map<string, Intl.DateTimeFormat>();
let supported: Set<string> | null = null;

function supportedZones(): Set<string> {
  supported ??= new Set(Intl.supportedValuesOf('timeZone'));
  return supported;
}

function formatter(timeZone: string): Intl.DateTimeFormat {
  let f = formatters.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
      weekday: 'short',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
    formatters.set(timeZone, f);
  }
  return f;
}

/**
 * True for an IANA zone this runtime knows: listed by `Intl.supportedValuesOf('timeZone')`, or an
 * alias `Intl.DateTimeFormat` resolves to a listed zone, to `UTC` or to an `Etc/*` zone (Node 22's
 * ICU lists `Asia/Calcutta` but not `Asia/Kolkata`, and neither `UTC` nor `Etc/*`).
 */
export function isValidTimeZone(zone: unknown): zone is string {
  if (typeof zone !== 'string' || !ZONE_PATTERN.test(zone)) return false;
  if (supportedZones().has(zone)) return true;
  try {
    const resolved = new Intl.DateTimeFormat('en-US', { timeZone: zone }).resolvedOptions()
      .timeZone;
    return resolved === 'UTC' || resolved.startsWith('Etc/') || supportedZones().has(resolved);
  } catch {
    return false;
  }
}

export interface LocalTime {
  /** ISO weekday index, Monday = 0. */
  weekday: number;
  /** Minutes since local midnight. */
  minutes: number;
  /** `YYYY-MM-DD`. */
  date: string;
}

const WEEKDAY_SHORT: Readonly<Record<string, number>> = {
  Mon: 0,
  Tue: 1,
  Wed: 2,
  Thu: 3,
  Fri: 4,
  Sat: 5,
  Sun: 6,
};

/** Local wall time of an instant (epoch milliseconds) in a zone. */
export function localTime(epochMs: number, timeZone: string): LocalTime {
  const parts = formatter(timeZone).formatToParts(new Date(epochMs));
  const get = (type: Intl.DateTimeFormatPartTypes): string =>
    parts.find((p) => p.type === type)?.value ?? '';
  const hour = Number(get('hour')) % 24;
  return {
    weekday: WEEKDAY_SHORT[get('weekday')] ?? 0,
    minutes: hour * 60 + Number(get('minute')),
    date: `${get('year')}-${get('month')}-${get('day')}`,
  };
}

const HHMM = /^([01][0-9]|2[0-3]):([0-5][0-9])$/;

/** `HH:MM` → minutes; `24:00` only where `allowEnd` (end of day). */
export function parseHhMm(text: unknown, allowEnd = false): number | null {
  if (typeof text !== 'string') return null;
  if (allowEnd && text === '24:00') return 1440;
  const m = HHMM.exec(text);
  return m ? Number(m[1]) * 60 + Number(m[2]) : null;
}

const DATE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;

/** True for a real calendar date `YYYY-MM-DD` (proleptic Gregorian, years 1970–9999). */
export function isCalendarDate(text: unknown): text is string {
  if (typeof text !== 'string') return false;
  const m = DATE.exec(text);
  if (!m) return false;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (y < 1970 || mo < 1 || mo > 12 || d < 1) return false;
  const days = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  return d <= days;
}

export interface TimeWindow {
  timeZone: string;
  days: readonly Weekday[];
  from: number;
  to: number;
}

/**
 * Weekly window: `from < to` → same local day, `from ≤ t < to`; `from > to` → wraps midnight
 * and belongs to the day it starts on (`t ≥ from` on a listed day, or `t < to` on the day after
 * a listed day).
 */
export function withinWindow(epochMs: number, w: TimeWindow): boolean {
  const local = localTime(epochMs, w.timeZone);
  const listed = (index: number) => w.days.includes(WEEKDAYS[((index % 7) + 7) % 7]!);
  if (w.from < w.to)
    return listed(local.weekday) && local.minutes >= w.from && local.minutes < w.to;
  return (
    (listed(local.weekday) && local.minutes >= w.from) ||
    (listed(local.weekday - 1) && local.minutes < w.to)
  );
}

/** Inclusive local date range. */
export function withinDateRange(
  epochMs: number,
  range: { timeZone: string; from: string; to: string },
): boolean {
  const { date } = localTime(epochMs, range.timeZone);
  return date >= range.from && date <= range.to;
}

/** The ICU time-zone data version (recorded in every result). */
export function tzdataVersion(): string {
  const tz = process.versions.tz;
  return typeof tz === 'string' && tz.length > 0 ? tz.slice(0, 16) : 'unknown';
}
