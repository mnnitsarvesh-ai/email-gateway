import { sanitizeText } from '../results/sanitize';

/**
 * Escaping and formatting of the report renderer (design D4). One escaping path: every string
 * that reaches the HTML (fixed labels and data alike) passes `escapeHtml`; data strings pass
 * `dataText` (sanitized and capped) first. Numbers pass `finite` before formatting. Formatting is
 * locale-fixed (`en-US`) and time-zone-fixed (UTC) and never reads the clock, so the same model
 * renders to the same bytes.
 */

/** Caps of data strings (design D4). */
export const DATA_CAPS = {
  domain: 253,
  address: 120,
  displayName: 80,
  organization: 120,
  code: 64,
  /** Country codes, map keys and other short tokens. */
  token: 64,
} as const;

const HTML_ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Escapes `& < > " '` for text nodes and double-quoted attribute values. */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]!);
}

/** A data string: sanitized (controls, bidi, zero-width removed), line breaks folded, capped. */
export function dataText(value: unknown, cap: number): string {
  if (typeof value !== 'string') return '';
  return sanitizeText(value.replace(/[\r\n\t]+/g, ' '), cap);
}

/** A finite number, else 0 (design D4). */
export function finite(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

const INTEGER = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const ONE_DECIMAL = new Intl.NumberFormat('en-US', {
  minimumFractionDigits: 1,
  maximumFractionDigits: 1,
});

/** `1,248` (rounded to an integer). */
export function fmtNumber(value: unknown): string {
  return INTEGER.format(Math.round(finite(value)));
}

/** A ratio 0–1 as `98.6%`; null/non-finite → `n/a`. */
export function fmtPercent(ratio: unknown): string {
  if (typeof ratio !== 'number' || !Number.isFinite(ratio)) return 'n/a';
  return `${ONE_DECIMAL.format(ratio * 100)}%`;
}

/** A share of a total as `3.3%` (0 when the total is 0). */
export function fmtShare(part: number, total: number): string {
  return fmtPercent(total > 0 ? finite(part) / total : 0);
}

const trimDecimal = (value: number): string => {
  const rounded = Math.round(value * 10) / 10;
  return Number.isInteger(rounded) ? String(rounded) : ONE_DECIMAL.format(rounded);
};

/** Milliseconds as `250 ms`, `1.5 s`, `15 min`, `4 h`, `1 d`; null → `n/a`. */
export function fmtDuration(ms: unknown): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return 'n/a';
  const value = Math.max(0, ms);
  if (value < 1000) return `${Math.round(value)} ms`;
  if (value < 60_000) return `${trimDecimal(value / 1000)} s`;
  if (value < 3_600_000) return `${trimDecimal(value / 60_000)} min`;
  if (value < 86_400_000) return `${trimDecimal(value / 3_600_000)} h`;
  return `${trimDecimal(value / 86_400_000)} d`;
}

/** Bytes as `812 B`, `12.3 KiB`, `1.2 MiB`. */
export function fmtBytes(bytes: unknown): string {
  const value = Math.max(0, finite(bytes));
  if (value < 1024) return `${Math.round(value)} B`;
  if (value < 1024 * 1024) return `${ONE_DECIMAL.format(value / 1024)} KiB`;
  return `${ONE_DECIMAL.format(value / (1024 * 1024))} MiB`;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number): string => String(n).padStart(2, '0');

export type UtcFormat = 'datetime' | 'date' | 'time' | 'day';

/**
 * An ISO instant in UTC: `datetime` `Nov 16, 2026 09:00 UTC`, `date` `Nov 16, 2026`, `day`
 * `Nov 16` (axis labels of daily buckets), `time` `09:00` (hourly buckets). Invalid → `n/a`.
 */
export function fmtUtc(iso: unknown, format: UtcFormat = 'datetime'): string {
  const date = typeof iso === 'string' ? new Date(iso) : null;
  if (!date || Number.isNaN(date.getTime())) return 'n/a';
  const day = `${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()}`;
  const time = `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
  switch (format) {
    case 'date':
      return `${day}, ${date.getUTCFullYear()}`;
    case 'day':
      return day;
    case 'time':
      return time;
    default:
      return `${day}, ${date.getUTCFullYear()} ${time} UTC`;
  }
}

/** A coordinate rounded to 2 decimals without trailing zeros (`12.5`, `3`). */
export function coord(value: number): string {
  const rounded = Math.round(finite(value) * 100) / 100;
  return String(Object.is(rounded, -0) ? 0 : rounded);
}
