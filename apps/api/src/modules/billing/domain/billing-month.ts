import { HttpStatus } from '@nestjs/common';
import { PARTITION_REGISTRY, type PartitionSpec, retentionCutoff } from '@email-gateway/database';
import { CodedHttpException } from '../../../http/coded-exception';

/** `400 usage_period_unavailable` (step 6.1 §3.2, D12). */
export const USAGE_PERIOD_UNAVAILABLE = 'usage_period_unavailable';

/** `YYYY-MM` with a month 01–12. */
export const BILLING_MONTH_PATTERN = /^(\d{4})-(0[1-9]|1[0-2])$/;

/** The partitioned table the metered message counts come from. */
const MESSAGES_TABLE = 'email_messages';

/**
 * The `email_messages` retention spec of the partitioning registry (6 monthly partitions plus the
 * current month, docs/plan/steps/01-database.md D3): months whose partitions were dropped have no
 * rows left to count.
 */
export const EMAIL_MESSAGES_RETENTION: PartitionSpec = (() => {
  const spec = PARTITION_REGISTRY.find((s) => s.table === MESSAGES_TABLE);
  if (!spec || spec.granularity !== 'month' || spec.retention === null) {
    throw new Error('The partitioning registry has no monthly retention for email_messages');
  }
  return spec;
})();

export interface BillingMonth {
  /** `YYYY-MM`. */
  month: string;
  /** First instant of the month (UTC). */
  from: Date;
  /** First instant of the next month (UTC). */
  end: Date;
  /** Exclusive end of what is counted: the month end, or now for the current month. */
  to: Date;
}

const usagePeriodUnavailable = (message: string): CodedHttpException =>
  new CodedHttpException(HttpStatus.BAD_REQUEST, USAGE_PERIOD_UNAVAILABLE, message);

const formatMonth = (date: Date): string =>
  `${date.getUTCFullYear().toString().padStart(4, '0')}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;

/**
 * `?month=YYYY-MM` (default the current UTC month) → the calendar month in UTC. A month in the
 * future or whose start is before the `email_messages` retention cutoff (its partitions are
 * dropped: `retentionCutoff`, the same rule the partition maintenance job applies) is
 * `400 usage_period_unavailable`; the current month is counted up to `now`.
 */
export function resolveBillingMonth(
  month: string | undefined,
  now: Date,
  spec: PartitionSpec = EMAIL_MESSAGES_RETENTION,
): BillingMonth {
  let year: number;
  let index: number;
  if (month === undefined) {
    year = now.getUTCFullYear();
    index = now.getUTCMonth();
  } else {
    const match = BILLING_MONTH_PATTERN.exec(month);
    if (!match) throw usagePeriodUnavailable('month: must be YYYY-MM');
    year = Number(match[1]);
    index = Number(match[2]) - 1;
  }
  const from = new Date(Date.UTC(year, index, 1));
  const end = new Date(Date.UTC(year, index + 1, 1));
  if (from.getTime() > now.getTime()) {
    throw usagePeriodUnavailable('month: the month has not started yet');
  }
  const cutoff = retentionCutoff(spec, now);
  if (cutoff !== null && from.getTime() < cutoff.getTime()) {
    throw usagePeriodUnavailable(
      `month: message records are kept for ${String(spec.retention)} months; the earliest ` +
        `available month is ${formatMonth(cutoff)}`,
    );
  }
  return { month: formatMonth(from), from, end, to: end.getTime() < now.getTime() ? end : now };
}
