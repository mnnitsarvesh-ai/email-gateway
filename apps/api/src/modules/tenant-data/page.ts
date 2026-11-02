/**
 * One page of a tenant-scoped list, as produced by `pageWindow` (http/pagination): `take` rows
 * (limit + 1) with ids below `beforeId`, newest first.
 */
export interface IdPageWindow {
  take: number;
  beforeId?: bigint;
}

/** Hard cap on rows per repository call, whatever the caller asks for. */
export const MAX_TAKE = 101;

export const clampTake = (take: number): number => Math.max(1, Math.min(take, MAX_TAKE));
