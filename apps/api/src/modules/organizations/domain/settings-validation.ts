/**
 * Validation rules of `organization_settings` (D12) that zod cannot express on its own: IANA
 * time zones, BCP 47 locales, 5-field cron expressions and the serialized size of preferences.
 */

let supportedTimeZones: ReadonlySet<string> | undefined;

/** Shape of an IANA zone name (`Area/Location[/Sub]`), plus `UTC`. Rejects offsets like `+05:30`. */
const IANA_ZONE_SHAPE = /^(?:UTC|[A-Za-z]+(?:\/[A-Za-z0-9_+-]+){1,2})$/;

/**
 * True for an IANA time zone: one listed by `Intl.supportedValuesOf('timeZone')`, or an IANA
 * alias the runtime resolves (the ICU list holds canonical names only, so `UTC` and
 * `Asia/Kolkata` are absent from it on some Node builds although every runtime accepts them).
 */
export function isValidTimeZone(value: string): boolean {
  if (value.length === 0 || value.length > 64 || !IANA_ZONE_SHAPE.test(value)) return false;
  supportedTimeZones ??= new Set(Intl.supportedValuesOf('timeZone'));
  if (supportedTimeZones.has(value)) return true;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

/** A well-formed BCP 47 language tag of 2–16 characters (`en`, `en-IN`, `pt-BR`). */
export function isValidLocale(value: string): boolean {
  if (value.length < 2 || value.length > 16) return false;
  try {
    return Intl.getCanonicalLocales(value).length === 1;
  } catch {
    return false;
  }
}

interface CronField {
  min: number;
  max: number;
  names?: readonly string[];
}

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const DAYS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];

/** minute, hour, day of month, month, day of week (0 and 7 are Sunday). */
const CRON_FIELDS: readonly CronField[] = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12, names: MONTHS },
  { min: 0, max: 7, names: DAYS },
];

function cronValue(token: string, field: CronField): number | null {
  if (/^\d{1,2}$/.test(token)) {
    const n = Number(token);
    return n >= field.min && n <= field.max ? n : null;
  }
  const index = field.names?.indexOf(token.toUpperCase()) ?? -1;
  if (index < 0) return null;
  // Month names are 1-based, day names 0-based.
  return field.min + index;
}

function isValidCronPart(part: string, field: CronField): boolean {
  const [range, step, ...rest] = part.split('/');
  if (rest.length > 0 || range === undefined || range === '') return false;
  if (step !== undefined) {
    if (!/^\d{1,2}$/.test(step)) return false;
    const n = Number(step);
    if (n < 1 || n > field.max) return false;
  }
  if (range === '*') return true;
  const bounds = range.split('-');
  if (bounds.length === 1) {
    // A step needs a range or `*` (`5/10` is ambiguous across cron dialects).
    return step === undefined && cronValue(bounds[0]!, field) !== null;
  }
  if (bounds.length !== 2) return false;
  const low = cronValue(bounds[0]!, field);
  const high = cronValue(bounds[1]!, field);
  return low !== null && high !== null && low <= high;
}

/**
 * A standard 5-field cron expression (`minute hour day-of-month month day-of-week`) with `*`,
 * numbers, names (`JAN`, `MON`), ranges (`1-5`), steps (`*\/15`, `0-30/5`) and lists (`1,15`).
 * No seconds field, no `@daily` macros, no Quartz extensions (`?`, `L`, `W`, `#`).
 */
export function isValidCron(expression: string): boolean {
  if (expression.length > 64) return false;
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== CRON_FIELDS.length) return false;
  return fields.every((value, i) =>
    value.split(',').every((part) => isValidCronPart(part, CRON_FIELDS[i]!)),
  );
}

/** `preferences` limit (D12): 16 KiB of serialized JSON. */
export const MAX_PREFERENCES_BYTES = 16 * 1024;

export function serializedSize(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value) ?? '', 'utf8');
}

/**
 * Upper bound of `quarantineRetentionDays`: the organization's `quarantine_retention_days` limit
 * and the platform's `quarantine.max_retention_days`, whichever is lower (a missing value does
 * not constrain). Never below 1.
 */
export function maxQuarantineRetentionDays(
  organizationLimit: bigint | null,
  systemMax: number | null,
): number | null {
  const candidates = [
    organizationLimit === null ? null : Number(organizationLimit),
    systemMax,
  ].filter((v): v is number => v !== null && Number.isFinite(v));
  if (candidates.length === 0) return null;
  return Math.max(1, Math.min(...candidates));
}
