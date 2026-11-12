import { createHash } from 'node:crypto';
import { canonicalJson } from '../../../http/idempotency/idempotency-key';

/** Reports with a cache entry and metrics (`report` label of the D16 series). */
export const REPORT_NAMES = ['traffic', 'threats', 'url_clicks', 'billing_usage'] as const;
export type ReportName = (typeof REPORT_NAMES)[number];

export const REPORT_CACHE_PREFIX = 'rpt:v1';

/** Normalized report parameters: ISO instants, enum codes and month strings only. */
export type ReportParams = Readonly<Record<string, string | number | null>>;

/**
 * `rpt:v1:<organizationId>:<report>:<sha256(normalized params)>` (D12). The organization is the
 * tenant scope's (never client input), so an entry of one organization is never read for another;
 * the parameter hash is over the canonical JSON (keys sorted), so equal queries share an entry.
 */
export function reportCacheKey(
  organizationId: bigint,
  report: ReportName,
  params: ReportParams,
): string {
  if (typeof organizationId !== 'bigint' || organizationId < 1n) {
    throw new Error('reportCacheKey: a positive organization id is required');
  }
  const digest = createHash('sha256').update(canonicalJson(params), 'utf8').digest('hex');
  return `${REPORT_CACHE_PREFIX}:${organizationId.toString(10)}:${report}:${digest}`;
}
