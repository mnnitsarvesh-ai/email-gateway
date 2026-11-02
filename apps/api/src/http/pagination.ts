import { BadRequestException } from '@nestjs/common';
import { formatId, isIdString } from '@email-gateway/database';
import { z } from 'zod';

export const DEFAULT_PAGE_LIMIT = 25;
export const MAX_PAGE_LIMIT = 100;

/**
 * `?limit=` (1–100, default 25) and `?cursor=` (opaque). Lists are ordered by id descending
 * (newest first); the cursor encodes the id of the last row of the previous page.
 */
export const PageQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(MAX_PAGE_LIMIT).default(DEFAULT_PAGE_LIMIT),
  cursor: z.string().min(1).max(64).optional(),
});

export type PageQuery = z.infer<typeof PageQuerySchema>;

export interface Page<T> {
  data: T[];
  /** Pass as `?cursor=` to fetch the next page; null on the last page. */
  nextCursor: string | null;
}

/** Encodes a row id as an opaque cursor (base64url of its decimal string). */
export function encodeCursor(id: bigint): string {
  return Buffer.from(formatId(id), 'utf8').toString('base64url');
}

/** Decodes a cursor produced by `encodeCursor`; anything else is a `400`. */
export function decodeCursor(cursor: string): bigint {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  if (!isIdString(decoded) || encodeCursor(BigInt(decoded)) !== cursor) {
    throw new BadRequestException(['cursor: Invalid cursor']);
  }
  return BigInt(decoded);
}

/**
 * What a repository fetches for one page: `take` is limit + 1 (the extra row only tells whether
 * another page exists) and `beforeId` is the exclusive upper bound from the cursor.
 */
export function pageWindow(query: PageQuery): { take: number; beforeId?: bigint } {
  return {
    take: query.limit + 1,
    ...(query.cursor !== undefined && { beforeId: decodeCursor(query.cursor) }),
  };
}

/**
 * Builds a page from rows fetched with `pageWindow` (ordered by id descending, at most
 * limit + 1 rows). `map` turns each row into its response shape.
 */
export function toPage<R extends { id: bigint }, T>(
  rows: readonly R[],
  limit: number,
  map: (row: R) => T,
): Page<T> {
  const pageRows = rows.slice(0, limit);
  const last = pageRows[pageRows.length - 1];
  return {
    data: pageRows.map(map),
    nextCursor: rows.length > limit && last ? encodeCursor(last.id) : null,
  };
}
