import { BadRequestException } from '@nestjs/common';

const DAY_MS = 24 * 60 * 60 * 1000;

/** Default usage window (D12). */
export const DEFAULT_USAGE_DAYS = 30;
/**
 * Longest usage window served from MySQL (D12): message counts scan `email_messages` by
 * `(organization_id, received_at)`; longer windows belong to the ClickHouse rollups (steps 9–10).
 */
export const MAX_USAGE_DAYS = 31;

export interface UsagePeriod {
  from: Date;
  to: Date;
}

/**
 * Resolves `?from&to` (D12): `to` defaults to now, `from` to 30 days before `to`; `from < to`
 * and at most 31 days, else `400`.
 */
export function resolveUsagePeriod(
  query: { from?: Date | undefined; to?: Date | undefined },
  now: Date = new Date(),
): UsagePeriod {
  const to = query.to ?? now;
  const from = query.from ?? new Date(to.getTime() - DEFAULT_USAGE_DAYS * DAY_MS);
  if (from.getTime() >= to.getTime()) {
    throw new BadRequestException(['from: must be before to']);
  }
  if (to.getTime() - from.getTime() > MAX_USAGE_DAYS * DAY_MS) {
    throw new BadRequestException([`(root): the period must not exceed ${MAX_USAGE_DAYS} days`]);
  }
  return { from, to };
}

/** Midnight UTC of the given instant (`messages.today`, `messages_per_day`). */
export function startOfUtcDay(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}
