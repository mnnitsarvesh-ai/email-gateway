/**
 * Recipient direction and lag buckets of copies (design D7.4, D7.8, D11.3). Pure.
 */

export type CopyDirection = 'inbound' | 'internal';

/** The lower-case domain of an address, or null. */
export function addressDomain(address: string | null | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  return address
    .slice(at + 1)
    .trim()
    .replace(/>$/, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

/**
 * D7.4: `internal` when the sender and the recipient are both on a domain of the organization
 * (exact domain match, case-insensitive), otherwise `inbound`. A missing sender is `inbound`.
 */
export function classifyRecipientDirection(
  sender: string | null | undefined,
  recipient: string,
  orgDomains: Iterable<string>,
): CopyDirection {
  const domains = new Set<string>();
  for (const domain of orgDomains) domains.add(domain.trim().replace(/\.$/, '').toLowerCase());
  const senderDomain = addressDomain(sender);
  const recipientDomain = addressDomain(recipient);
  return senderDomain !== null &&
    recipientDomain !== null &&
    domains.has(senderDomain) &&
    domains.has(recipientDomain)
    ? 'internal'
    : 'inbound';
}

/** `api_mode_counters` lag columns (D3.2). */
export const LAG_BUCKETS = ['le_60s', 'le_300s', 'le_900s', 'le_3600s', 'gt_3600s'] as const;
export type LagBucket = (typeof LAG_BUCKETS)[number];

/** Upper bound (seconds) of each bucket; `gt_3600s` has none. */
export const LAG_BUCKET_UPPER_SECONDS: Readonly<Record<LagBucket, number | null>> = {
  le_60s: 60,
  le_300s: 300,
  le_900s: 900,
  le_3600s: 3600,
  gt_3600s: null,
};

/** The counter bucket of a lag (negative lags count as 0). */
export function lagBucket(lagMs: number): LagBucket {
  const seconds = Math.max(0, lagMs) / 1000;
  if (seconds <= 60) return 'le_60s';
  if (seconds <= 300) return 'le_300s';
  if (seconds <= 900) return 'le_900s';
  if (seconds <= 3600) return 'le_3600s';
  return 'gt_3600s';
}

/** `lag_ms = max(0, verdictAt − providerDeliveredAt)` (D7.8), capped to INT UNSIGNED. */
export function copyLagMs(providerDeliveredAt: Date, verdictAt: Date): number {
  return Math.min(Math.max(0, verdictAt.getTime() - providerDeliveredAt.getTime()), 4_294_967_295);
}

/**
 * A bucket percentile (D11.3 "bucket p95"): the upper bound in seconds of the bucket holding the
 * `quantile` of the counted lags; for `gt_3600s` the observed maximum (`maxMs`) when larger than
 * 3600 s, else 3601. Null without observations.
 */
export function lagPercentileSeconds(
  counts: Readonly<Record<LagBucket, number>>,
  quantile: number,
  maxMs?: number,
): number | null {
  const total = LAG_BUCKETS.reduce((sum, bucket) => sum + Math.max(0, counts[bucket]), 0);
  if (total === 0) return null;
  const rank = Math.ceil(Math.min(Math.max(quantile, 0), 1) * total);
  let seen = 0;
  for (const bucket of LAG_BUCKETS) {
    seen += Math.max(0, counts[bucket]);
    if (seen >= Math.max(rank, 1)) {
      const upper = LAG_BUCKET_UPPER_SECONDS[bucket];
      if (upper !== null) return upper;
      return Math.max(3601, Math.ceil((maxMs ?? 0) / 1000));
    }
  }
  return Math.max(3601, Math.ceil((maxMs ?? 0) / 1000));
}
