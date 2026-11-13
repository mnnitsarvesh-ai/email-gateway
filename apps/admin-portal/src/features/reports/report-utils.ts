import { shouldRetry } from '@/lib/api/hooks';
import { ApiError } from '@/lib/api/errors';
import type { SuccessBody } from '@/lib/api/types';
import { formatDuration } from '@/lib/format';
import type { ResolvedRange } from '@/lib/range';

/** Report bodies (typed from the OpenAPI snapshot). */
export type TrafficReport = SuccessBody<'ReportsController_traffic_v1'>;
export type ThreatsReport = SuccessBody<'ReportsController_threats_v1'>;
export type DeliveryReport = SuccessBody<'ReportsController_delivery_v1'>;
export type ProcessingReport = SuccessBody<'ReportsController_processing_v1'>;
export type TopDomainsReport = SuccessBody<'ReportsController_topDomains_v1'>;
export type UrlClicksReport = SuccessBody<'ReportsController_urlClicks_v1'>;
export type HistogramBin = DeliveryReport['latency']['histogram'][number];

/** Threat verdict series in the fixed order of design P13 (position also distinguishes them). */
export const THREAT_VERDICTS = [
  'spam',
  'phishing',
  'malware',
  'bec',
  'suspicious',
  'dlp_violation',
] as const;

export const VERDICT_LABELS: Readonly<Record<string, string>> = {
  clean: 'Clean',
  spam: 'Spam',
  bulk: 'Bulk',
  phishing: 'Phishing',
  malware: 'Malware',
  bec: 'BEC',
  dlp_violation: 'DLP violation',
  suspicious: 'Suspicious',
  unknown: 'Unknown',
  none: 'No verdict yet',
};

export const ACTION_LABELS: Readonly<Record<string, string>> = {
  deliver: 'Deliver',
  tag: 'Tag',
  quarantine: 'Quarantine',
  discard: 'Discard',
  reject: 'Reject',
  require_approval: 'Require approval',
  partial: 'Partial',
  none: 'No action yet',
};

/** The `from`/`to` (and bucket size) of a resolved range, as the report operations take them. */
export function reportWindow(range: ResolvedRange): {
  from: string;
  to: string;
  granularity: 'hour' | 'day';
} {
  return { from: range.from, to: range.to, granularity: range.granularity };
}

/** Range length in days (custom ranges are whole days; presets 1, 7, 30). */
export function rangeDays(range: ResolvedRange): number {
  return (Date.parse(range.to) - Date.parse(range.from)) / 86_400_000;
}

/** `hour` buckets are allowed by the api for ranges of at most 7 days. */
export function hourAllowed(range: ResolvedRange): boolean {
  return rangeDays(range) <= 7;
}

/**
 * Report queries retry like every query (network errors, 503) except `503 report_timeout`:
 * the same window would time out again; the user narrows the range instead.
 */
export function reportRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError && error.code === 'report_timeout') return false;
  return shouldRetry(failureCount, error);
}

const UTC_HOUR = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'UTC',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
});
const UTC_DAY = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'UTC',
  month: 'short',
  day: 'numeric',
});

/** Bucket label in UTC (`13 Nov 09:00` for hours, `13 Nov` for days). */
export function bucketLabel(start: string, granularity: 'hour' | 'day'): string {
  const date = new Date(start);
  if (Number.isNaN(date.getTime())) return start;
  return granularity === 'hour' ? `${UTC_HOUR.format(date)} UTC` : UTC_DAY.format(date);
}

/** Spam blocked (dashboard widget 5): Σ outcomes with verdict spam|bulk and a blocking action. */
export const SPAM_VERDICTS: readonly string[] = ['spam', 'bulk'];
export const BLOCKING_ACTIONS: readonly string[] = ['quarantine', 'discard', 'reject'];

export function spamBlocked(outcomes: ThreatsReport['outcomes']): number {
  return outcomes
    .filter((o) => SPAM_VERDICTS.includes(o.verdict) && BLOCKING_ACTIONS.includes(o.action))
    .reduce((sum, o) => sum + o.count, 0);
}

/** Number of samples a histogram covers (the api counts per bin, not cumulatively). */
export function histogramSamples(histogram: readonly HistogramBin[]): number {
  return histogram.reduce((sum, bin) => sum + bin.count, 0);
}

/** The largest finite bound of a histogram (`null` when it has none). */
export function lastFiniteBound(histogram: readonly HistogramBin[]): number | null {
  let last: number | null = null;
  for (const bin of histogram)
    if (bin.leMs !== null && (last === null || bin.leMs > last)) last = bin.leMs;
  return last;
}

/**
 * How a `pXXUpperBoundMs` reads (design §3.3.1): `≤ X` for a bound; `> last bound` when there are
 * samples but the percentile falls into the overflow bin (the api returns `null` then); `null`
 * when there are no samples at all.
 */
export type PercentileReading =
  | { readonly kind: 'bound'; readonly ms: number; readonly text: string }
  | { readonly kind: 'overflow'; readonly ms: number; readonly text: string }
  | { readonly kind: 'none' };

export function percentileReading(
  upperBoundMs: number | null,
  histogram: readonly HistogramBin[],
): PercentileReading {
  if (upperBoundMs !== null) {
    return { kind: 'bound', ms: upperBoundMs, text: `≤ ${formatDuration(upperBoundMs)}` };
  }
  const last = lastFiniteBound(histogram);
  if (histogramSamples(histogram) > 0 && last !== null) {
    return { kind: 'overflow', ms: last, text: `> ${formatDuration(last)}` };
  }
  return { kind: 'none' };
}

/** Histogram bin label: `≤ 250 ms`, overflow `> 15 min`. */
export function binLabel(bin: HistogramBin, histogram: readonly HistogramBin[]): string {
  if (bin.leMs !== null) return `≤ ${formatDuration(bin.leMs)}`;
  const last = lastFiniteBound(histogram);
  return last === null ? 'Overflow' : `> ${formatDuration(last)}`;
}

/** Search params of the current range, to link detailed pages "with the same range". */
export function rangeSearch(searchParams: URLSearchParams): URLSearchParams {
  const out = new URLSearchParams();
  for (const key of ['range', 'from', 'to']) {
    const value = searchParams.get(key);
    if (value) out.set(key, value);
  }
  return out;
}

export function hrefWithRange(
  pathname: string,
  searchParams: URLSearchParams,
  extra: Record<string, string> = {},
): string {
  const params = new URLSearchParams(extra);
  for (const [key, value] of rangeSearch(searchParams)) params.set(key, value);
  const query = params.toString();
  return query ? `${pathname}?${query}` : pathname;
}
