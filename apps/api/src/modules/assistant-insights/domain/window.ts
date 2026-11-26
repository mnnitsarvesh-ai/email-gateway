import { BadRequestException } from '@nestjs/common';
import { resolveRange, type ResolvedRange } from '../../../http/listing/range';
import {
  DAY_MS,
  INSIGHTS_DEFAULT_RANGE_DAYS,
  INSIGHTS_MAX_RANGE_DAYS,
} from '../insights.constants';

/** Windows of the admin and audit reads (step AI-6 D1, D2, D4): at most 92 days. */

export interface DayWindow {
  /** First UTC day (00:00). */
  from: Date;
  /** Last UTC day (00:00), inclusive. */
  to: Date;
}

export const dayString = (date: Date): string => date.toISOString().slice(0, 10);
const dayStart = (now: Date): Date =>
  new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

/**
 * `from`/`to` as UTC days (YYYY-MM-DD, inclusive), as `GET /assistant/usage`: `to` defaults to
 * today, `from` to 29 days before `to`; `from` after `to` or more than 92 days is `400`.
 */
export function resolveDayWindow(query: { from?: string; to?: string }, now: Date): DayWindow {
  const to = query.to ? new Date(`${query.to}T00:00:00.000Z`) : dayStart(now);
  const from = query.from
    ? new Date(`${query.from}T00:00:00.000Z`)
    : new Date(to.getTime() - (INSIGHTS_DEFAULT_RANGE_DAYS - 1) * DAY_MS);
  if (from.getTime() > to.getTime()) {
    throw new BadRequestException(['from: must not be after to']);
  }
  if ((to.getTime() - from.getTime()) / DAY_MS + 1 > INSIGHTS_MAX_RANGE_DAYS) {
    throw new BadRequestException([`to: the range is at most ${INSIGHTS_MAX_RANGE_DAYS} days`]);
  }
  return { from, to };
}

/**
 * `[from, to)` instants of a v1 list with a required window (feedback, executions): `to`
 * defaults to now, `from` to 30 days before; at most 92 days. A cursor's window is reused (later
 * pages stay stable when `to` defaulted to now).
 */
export function resolveInstantWindow(
  query: { from?: Date; to?: Date },
  now: Date,
  cursorWindow: readonly [number, number] | undefined,
): ResolvedRange {
  return resolveRange(query, {
    defaultMs: INSIGHTS_DEFAULT_RANGE_DAYS * DAY_MS,
    maxDays: INSIGHTS_MAX_RANGE_DAYS,
    now,
    cursorWindow,
  });
}

/**
 * The optional window of the audit conversation list: none when neither bound is given (and the
 * cursor carries none), else as `resolveInstantWindow`.
 */
export function resolveOptionalWindow(
  query: { from?: Date; to?: Date },
  now: Date,
  cursorWindow: readonly [number, number] | undefined,
): ResolvedRange | null {
  if (query.from === undefined && query.to === undefined && cursorWindow === undefined) {
    return null;
  }
  return resolveInstantWindow(query, now, cursorWindow);
}
