/**
 * A 5-field cron evaluator with IANA time zones (step 5.3 Q20). It accepts **exactly** the grammar
 * of the api's organization settings validator (`isValidCron` in
 * apps/api/src/modules/organizations/domain/settings-validation.ts; the unit test runs both on a
 * shared corpus): `minute hour day-of-month month day-of-week`, `*`, numbers (1–2 digits), names
 * (`JAN`…`DEC`, `SUN`…`SAT`, case-insensitive), ranges `a-b` (a ≤ b), steps on `*` or a range
 * (`*\/15`, `0-30/5`; step 1–max), lists; day-of-week 0 and 7 are Sunday; at most 64 characters.
 * No seconds, macros or Quartz extensions.
 *
 * Semantics (Vixie cron): when both day-of-month and day-of-week are restricted (neither field
 * starts with `*`), a day matches if **either** matches; otherwise both must match. Wall-clock
 * times are resolved in the time zone like `Temporal`'s `compatible` disambiguation: a time that
 * does not exist (spring-forward gap) fires at the same wall-clock offset after the gap (02:30 in
 * a 02:00→03:00 gap fires at 03:30); a repeated time (fall-back) fires once, at its first
 * occurrence.
 */

interface CronField {
  min: number;
  max: number;
  names?: readonly string[];
}

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const DAYS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
const FIELDS: readonly CronField[] = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12, names: MONTHS },
  { min: 0, max: 7, names: DAYS },
];

function value(token: string, field: CronField): number | null {
  if (/^\d{1,2}$/.test(token)) {
    const n = Number(token);
    return n >= field.min && n <= field.max ? n : null;
  }
  const index = field.names?.indexOf(token.toUpperCase()) ?? -1;
  return index < 0 ? null : field.min + index;
}

/** One list element → its values, or null when refused. */
function part(text: string, field: CronField): number[] | null {
  const [range, step, ...rest] = text.split('/');
  if (rest.length > 0 || range === undefined || range === '') return null;
  let by = 1;
  if (step !== undefined) {
    if (!/^\d{1,2}$/.test(step)) return null;
    by = Number(step);
    if (by < 1 || by > field.max) return null;
  }
  let lo: number;
  let hi: number;
  if (range === '*') {
    lo = field.min;
    hi = field.max;
  } else {
    const bounds = range.split('-');
    if (bounds.length === 1) {
      if (step !== undefined) return null;
      const v = value(bounds[0]!, field);
      return v === null ? null : [v];
    }
    if (bounds.length !== 2) return null;
    const a = value(bounds[0]!, field);
    const b = value(bounds[1]!, field);
    if (a === null || b === null || a > b) return null;
    lo = a;
    hi = b;
  }
  const out: number[] = [];
  for (let v = lo; v <= hi; v += by) out.push(v);
  return out;
}

export interface CronSchedule {
  minutes: ReadonlySet<number>;
  hours: ReadonlySet<number>;
  daysOfMonth: ReadonlySet<number>;
  months: ReadonlySet<number>;
  /** 0 = Sunday (7 is folded to 0). */
  daysOfWeek: ReadonlySet<number>;
  domStar: boolean;
  dowStar: boolean;
}

/** Parses an expression of the api grammar; null when refused. */
export function parseCron(expression: string): CronSchedule | null {
  if (typeof expression !== 'string' || expression.length > 64) return null;
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== FIELDS.length) return null;
  const sets: Array<Set<number>> = [];
  for (let i = 0; i < FIELDS.length; i += 1) {
    const set = new Set<number>();
    for (const p of fields[i]!.split(',')) {
      const values = part(p, FIELDS[i]!);
      if (values === null) return null;
      for (const v of values) set.add(i === 4 && v === 7 ? 0 : v);
    }
    sets.push(set);
  }
  return {
    minutes: sets[0]!,
    hours: sets[1]!,
    daysOfMonth: sets[2]!,
    months: sets[3]!,
    daysOfWeek: sets[4]!,
    domStar: fields[2]!.startsWith('*'),
    dowStar: fields[4]!.startsWith('*'),
  };
}

export const isValidCronExpression = (expression: string): boolean =>
  parseCron(expression) !== null;

// ---------------------------------------------------------------------------------------------
// Time zones
// ---------------------------------------------------------------------------------------------

const formatters = new Map<string, Intl.DateTimeFormat>();

function formatter(timeZone: string): Intl.DateTimeFormat {
  let f = formatters.get(timeZone);
  if (f === undefined) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
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

/** Shape of an IANA zone name (`Area/Location[/Sub]`, or `UTC`), as the api validator. */
const IANA_ZONE_SHAPE = /^(?:UTC|[A-Za-z]+(?:\/[A-Za-z0-9_+-]+){1,2})$/;

/**
 * True for an IANA time zone the runtime knows, with the shape the api's organization settings
 * validator accepts (`UTC` or `Area/Location[/Sub]`; offsets like `+05:30` and abbreviations are
 * refused).
 */
export function isValidTimeZoneName(timeZone: string): boolean {
  if (typeof timeZone !== 'string' || timeZone.length === 0 || timeZone.length > 64) return false;
  if (!IANA_ZONE_SHAPE.test(timeZone)) return false;
  try {
    formatter(timeZone);
    return true;
  } catch {
    return false;
  }
}

/** Local wall-clock minute of an instant, as UTC milliseconds of the same fields. */
function localWall(ms: number, timeZone: string): number {
  const parts = formatter(timeZone).formatToParts(new Date(ms));
  const get = (type: string) => Number(parts.find((p) => p.type === type)!.value);
  return Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'));
}

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** Offset (local − UTC) in ms at an instant, minute resolution. */
const offsetAt = (ms: number, timeZone: string): number => {
  const minute = Math.floor(ms / MINUTE_MS) * MINUTE_MS;
  return localWall(minute, timeZone) - minute;
};

/**
 * The instant of a local wall time (UTC-ms encoded fields) with `compatible` disambiguation.
 * `before`/`after` are the offsets one day before/after (precomputed per day by the caller).
 */
function instantOf(wall: number, timeZone: string, before: number, after: number): number {
  if (before === after) return wall - before;
  const candidates = [...new Set([wall - before, wall - after])].sort((a, b) => a - b);
  const valid = candidates.filter((c) => localWall(c, timeZone) === wall);
  if (valid.length > 0) return valid[0]!;
  return wall - before; // in a gap: shift forward by the gap length
}

/** Every instant of the schedule in `(from, to]`, ascending (milliseconds). */
export function cronInstants(
  schedule: CronSchedule,
  timeZone: string,
  from: Date,
  to: Date,
): Date[] {
  const start = from.getTime();
  const end = to.getTime();
  if (!(end > start)) return [];
  const hours = [...schedule.hours].sort((a, b) => a - b);
  const minutes = [...schedule.minutes].sort((a, b) => a - b);
  const firstWall = localWall(start, timeZone);
  const lastWall = localWall(end, timeZone);
  const out = new Set<number>();
  for (
    let day = Math.floor(firstWall / DAY_MS) * DAY_MS - DAY_MS;
    day <= lastWall + DAY_MS;
    day += DAY_MS
  ) {
    const d = new Date(day);
    const month = d.getUTCMonth() + 1;
    if (!schedule.months.has(month)) continue;
    const dom = schedule.daysOfMonth.has(d.getUTCDate());
    const dow = schedule.daysOfWeek.has(d.getUTCDay());
    const dayMatches = schedule.domStar || schedule.dowStar ? dom && dow : dom || dow;
    if (!dayMatches) continue;
    // Offsets around this local day (one transition at most within ±1 day).
    const approx = day - offsetAt(day, timeZone);
    const before = offsetAt(approx - DAY_MS, timeZone);
    const after = offsetAt(approx + 2 * DAY_MS, timeZone);
    for (const h of hours) {
      for (const m of minutes) {
        const t = instantOf(day + h * HOUR_MS + m * MINUTE_MS, timeZone, before, after);
        if (t > start && t <= end) out.add(t);
      }
    }
  }
  return [...out].sort((a, b) => a - b).map((t) => new Date(t));
}

// ---------------------------------------------------------------------------------------------
// Digest windows (Q20)
// ---------------------------------------------------------------------------------------------

/** At most one digest run per this interval (coalescing). */
export const DIGEST_MIN_INTERVAL_MS = HOUR_MS;
/** How far back missed schedule instants are looked for (older ones merge into the first window). */
export const DIGEST_MAX_LOOKBACK_MS = 2 * DAY_MS;
/** The window start of the very first run (no previous run). */
export const DIGEST_FIRST_WINDOW_MS = DAY_MS;

export class InvalidDigestScheduleError extends Error {
  constructor(readonly reason: 'schedule' | 'time_zone' | 'max_per_day') {
    super(`invalid digest ${reason}`);
    this.name = 'InvalidDigestScheduleError';
  }
}

export interface DigestWindow {
  /** The schedule instant (unique key of `quarantine_digest_runs` with organization and kind). */
  scheduledFor: Date;
  /** Exclusive start of the entry window (the previous run's `scheduledFor`). */
  windowFrom: Date;
}

/**
 * Q20: the due digest runs in `(lastScheduledFor, now]` of `schedule` in `timeZone`, coalesced
 * to at most one per hour (an instant less than an hour after the previous kept one — or the last
 * run — is skipped; its entries fall into the next window) and at most `maxPerDay` (the latest
 * kept; the first returned window then starts at the last run so no entry is lost). Instants
 * older than 48 hours are not run separately (their entries fall into the first window). Without
 * a previous run the first window starts 24 hours before `now`. Throws
 * `InvalidDigestScheduleError` for an invalid schedule, time zone or `maxPerDay`.
 */
export function nextDigestWindows(
  schedule: string,
  timeZone: string,
  lastScheduledFor: Date | null,
  now: Date,
  maxPerDay: number,
): DigestWindow[] {
  const parsed = parseCron(schedule);
  if (parsed === null) throw new InvalidDigestScheduleError('schedule');
  if (!isValidTimeZoneName(timeZone)) throw new InvalidDigestScheduleError('time_zone');
  if (!Number.isInteger(maxPerDay) || maxPerDay < 1) {
    throw new InvalidDigestScheduleError('max_per_day');
  }
  const nowMs = now.getTime();
  const lastMs = lastScheduledFor === null ? null : lastScheduledFor.getTime();
  const firstFrom = lastMs ?? nowMs - DIGEST_FIRST_WINDOW_MS;
  const searchFrom = Math.max(firstFrom, nowMs - DIGEST_MAX_LOOKBACK_MS);
  const kept: number[] = [];
  let previous = lastMs;
  for (const instant of cronInstants(parsed, timeZone, new Date(searchFrom), now)) {
    const t = instant.getTime();
    if (previous !== null && t - previous < DIGEST_MIN_INTERVAL_MS) continue;
    kept.push(t);
    previous = t;
  }
  const latest = kept.slice(-maxPerDay);
  return latest.map((t, i) => ({
    scheduledFor: new Date(t),
    windowFrom: new Date(i === 0 ? firstFrom : latest[i - 1]!),
  }));
}
