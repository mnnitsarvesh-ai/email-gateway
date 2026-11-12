import { BadRequestException } from '@nestjs/common';
import { cursorInvalid } from '../cursor/cursor-codec';

const DAY_MS = 86_400_000;

export interface ResolvedRange {
  from: Date;
  to: Date;
}

/**
 * `[from, to)` of a list over a partitioned table (step 6.1 D4): `to` defaults to `now`, `from`
 * to `to − defaultMs`; `from` must be before `to` and the range at most `maxDays` days, else
 * `400 validation_failed` (messages like the deliveries range).
 *
 * With `cursorWindow` (the `w` of a decoded v1 cursor) the first page's window is reused, so
 * later pages stay stable when `to` defaulted to "now": the request may omit `from`/`to` or repeat
 * exactly the same values; anything else is `400 cursor_invalid`.
 */
export function resolveRange(
  query: { from?: Date | undefined; to?: Date | undefined },
  options: {
    defaultMs: number;
    maxDays: number;
    now: Date;
    cursorWindow?: readonly [number, number] | undefined;
  },
): ResolvedRange {
  if (options.cursorWindow) {
    const [fromMs, toMs] = options.cursorWindow;
    if (
      (query.from !== undefined && query.from.getTime() !== fromMs) ||
      (query.to !== undefined && query.to.getTime() !== toMs)
    ) {
      throw cursorInvalid();
    }
    return { from: new Date(fromMs), to: new Date(toMs) };
  }
  const to = query.to ?? options.now;
  const from = query.from ?? new Date(to.getTime() - options.defaultMs);
  if (from.getTime() >= to.getTime()) {
    throw new BadRequestException(['from: must be before to']);
  }
  if (to.getTime() - from.getTime() > options.maxDays * DAY_MS) {
    throw new BadRequestException([
      `to: the range may cover at most ${options.maxDays} day${options.maxDays === 1 ? '' : 's'}`,
    ]);
  }
  return { from, to };
}

/** `[fromMs, toMs]` of a resolved range, for `CursorPosition.window`. */
export const rangeWindow = (range: ResolvedRange): [number, number] => [
  range.from.getTime(),
  range.to.getTime(),
];
