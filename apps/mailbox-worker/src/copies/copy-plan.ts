import type { ApiCopyDeliveredBasis, ApiCopyStatus, MessageVerdict } from '@email-gateway/database';
import type { COPY_SCAN_OUTCOME_VALUES } from '@email-gateway/event-contracts';
import { copyLagMs, lagBucket } from '@email-gateway/mailbox-api';
import type { CounterDelta } from '../runtime/redis-stores';

export type CopyScanOutcome = (typeof COPY_SCAN_OUTCOME_VALUES)[number];

/** `api_message_copies.status` of a `copy_scanned.v1` outcome (D7 steps 6–7). */
export const STATUS_OF_OUTCOME: Readonly<Record<CopyScanOutcome, ApiCopyStatus>> = {
  scanned: 'scanned',
  scan_failed: 'scan_failed',
  parse_failed: 'parse_failed',
};

/** The delivery time of a journal copy (D7.8): the topmost `Received:`, else the ingest time. */
export function journalDelivery(
  topReceivedAt: Date | null,
  receivedAt: Date,
): { at: Date; basis: ApiCopyDeliveredBasis } {
  if (topReceivedAt !== null && !Number.isNaN(topReceivedAt.getTime())) {
    return { at: topReceivedAt, basis: 'received_header' };
  }
  return { at: receivedAt, basis: 'ingest' };
}

/**
 * Lag of a finalized copy (D7.8): `max(0, verdict_at − provider_delivered_at)` for a scanned copy;
 * null when the copy has no verdict (scan or parse failure) or no delivery time.
 */
export function lagOf(
  outcome: CopyScanOutcome,
  deliveredAt: Date | null,
  verdictAt: Date,
): number | null {
  if (outcome !== 'scanned' || deliveredAt === null) return null;
  return copyLagMs(deliveredAt, verdictAt);
}

/** Counter delta of one lag observation (bucket, count, sum, max). */
export function lagDelta(lagMs: number): CounterDelta {
  const bucket = lagBucket(lagMs);
  return {
    lag_count: 1,
    [`lag_${bucket}`]: 1,
    lag_sum_ms: lagMs,
    lag_max_ms: lagMs,
  };
}

/** Sums counter deltas (max for `lag_max_ms` and `remediation_latency_max_ms`). */
export function mergeDelta(into: CounterDelta, add: CounterDelta): CounterDelta {
  for (const [key, value] of Object.entries(add) as [keyof CounterDelta, number][]) {
    if (value === undefined) continue;
    if (key === 'lag_max_ms' || key === 'remediation_latency_max_ms') {
      into[key] = Math.max(into[key] ?? 0, value);
    } else into[key] = (into[key] ?? 0) + value;
  }
  return into;
}

/**
 * The verdict stored on a copy (D7 step 5): a hybrid copy linked to an inline gateway message
 * carries the inline message's policy outcome (`final_verdict`), falling back to the copy's own
 * verdict while the inline message has none; otherwise the copy's verdict.
 */
export function storedVerdict(
  copyVerdict: MessageVerdict | null,
  inline: { finalVerdict: MessageVerdict | null } | null,
): { verdict: MessageVerdict | null; authority: 'copy' | 'inline' } {
  if (inline) return { verdict: inline.finalVerdict ?? copyVerdict, authority: 'inline' };
  return { verdict: copyVerdict, authority: 'copy' };
}
