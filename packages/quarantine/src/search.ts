import { createHash } from 'node:crypto';
import { canonicalJson } from '@email-gateway/policy-dsl';

/**
 * Keyset cursors of the quarantine search (step 5.3 Q9): order `(quarantined_at DESC, id DESC)`,
 * cursor `base64url(JSON{ t, id, f })` where `f` binds the cursor to the canonical filter (a
 * cursor used with other filters is `400 quarantine_cursor_invalid`).
 */

export const QUARANTINE_SEARCH_MAX_RANGE_DAYS = 62;
export const QUARANTINE_SEARCH_MAX_PAGE_SIZE = 100;
export const QUARANTINE_SEARCH_DEFAULT_PAGE_SIZE = 50;
const CURSOR_MAX_LENGTH = 512;

/** First 16 hex characters of SHA-256 over the canonical filter (pagination fields excluded). */
export function searchFilterHash(filter: Record<string, unknown>): string {
  const { cursor: _cursor, limit: _limit, ...rest } = filter;
  const defined = Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== undefined));
  return createHash('sha256').update(canonicalJson(defined)).digest('hex').slice(0, 16);
}

export interface SearchCursor {
  /** `quarantined_at` of the last item (ISO). */
  t: string;
  /** Internal id of the last item (decimal). */
  id: string;
  /** `searchFilterHash` of the filter it belongs to. */
  f: string;
}

export function encodeSearchCursor(cursor: SearchCursor): string {
  return Buffer.from(JSON.stringify({ t: cursor.t, id: cursor.id, f: cursor.f }), 'utf8').toString(
    'base64url',
  );
}

/** Decodes and checks a cursor against the current filter hash; null = `quarantine_cursor_invalid`. */
export function decodeSearchCursor(text: string, filterHash: string): SearchCursor | null {
  if (typeof text !== 'string' || text.length === 0 || text.length > CURSOR_MAX_LENGTH) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(text)) return null;
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(text, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (value === null || typeof value !== 'object') return null;
  const { t, id, f, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (typeof t !== 'string' || Number.isNaN(Date.parse(t)) || !/^\d{4}-\d{2}-\d{2}T/.test(t)) {
    return null;
  }
  if (typeof id !== 'string' || !/^[0-9]{1,20}$/.test(id)) return null;
  if (typeof f !== 'string' || f !== filterHash) return null;
  return { t, id, f };
}

/** `to - from` within `(0, maxRangeDays]` days (`400 quarantine_search_range_invalid` otherwise). */
export function checkSearchRange(
  from: Date,
  to: Date,
  maxRangeDays = QUARANTINE_SEARCH_MAX_RANGE_DAYS,
): boolean {
  const span = to.getTime() - from.getTime();
  return Number.isFinite(span) && span > 0 && span <= maxRangeDays * 86_400_000;
}
