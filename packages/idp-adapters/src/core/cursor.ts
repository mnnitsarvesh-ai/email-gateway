/**
 * Cursor codec v1 (design note D7.3): base64url of strict JSON, ≤ 4 096 characters.
 *
 * `{ v: 1, a, seq, wm?, ws?, we?, page?, sw? }`:
 * - `a` the adapter version that wrote it (another version ⇒ `cursor_invalid`),
 * - `seq` a page counter that only grows (contract kit: cursors are monotonic),
 * - `wm` the watermark, `ws`/`we` the window being paged,
 * - `page` the provider continuation (Graph `$skiptoken` value, Google `pageToken`, Office 365
 *   `{ next?, blob? }`),
 * - `sw` snapshot sweep state, `pq` priority refreshes awaiting the commit (deviations WP1-2, WP1-4).
 *
 * Companion streams return `companion:v1:<primary>` (D3).
 */
import { z } from 'zod';

export const CURSOR_MAX_LENGTH = 4096;

const iso = z.iso.datetime();
const token = z.string().min(1).max(2048);

export const o365PageSchema = z.strictObject({
  /** Path and query (relative to the family base) of the content listing page being processed. */
  next: z.string().min(1).max(2048).optional(),
  /** Blob being sliced: content id and record offset. */
  blob: z
    .strictObject({
      id: z.string().min(1).max(256),
      offset: z.number().int().min(0).max(1_000_000),
    })
    .optional(),
});
export type O365Page = z.infer<typeof o365PageSchema>;

export const sweepStateSchema = z.strictObject({
  /** Start of the last (or current) full sweep. */
  at: iso.optional(),
  /** Continuation of the user listing of the sweep in progress. */
  next: token.optional(),
  /** Alternation flag so sweeps and audit windows share polls fairly. */
  alt: z.boolean().optional(),
});
export type SweepState = z.infer<typeof sweepStateSchema>;

export const cursorSchema = z.strictObject({
  v: z.literal(1),
  a: z.string().min(1).max(32),
  seq: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  wm: iso.optional(),
  ws: iso.optional(),
  we: iso.optional(),
  page: z.union([token, o365PageSchema]).optional(),
  sw: sweepStateSchema.optional(),
  /**
   * Identity hashes of a priority refresh done by the page that wrote this cursor; cleared when
   * `ingest` runs with this cursor, i.e. after the runner committed that page (deviation WP1-4).
   */
  pq: z
    .array(z.string().regex(/^[0-9a-f]{64}$/))
    .max(20)
    .optional(),
});
export type CursorV1 = z.infer<typeof cursorSchema>;

export class CursorTooLargeError extends Error {
  constructor() {
    super('cursor_too_large');
    this.name = 'CursorTooLargeError';
  }
}

export function encodeCursor(cursor: CursorV1): string {
  const parsed = cursorSchema.parse(cursor);
  const encoded = Buffer.from(JSON.stringify(parsed), 'utf8').toString('base64url');
  if (encoded.length > CURSOR_MAX_LENGTH) throw new CursorTooLargeError();
  return encoded;
}

export type DecodedCursor =
  { ok: true; cursor: CursorV1 } | { ok: false; reason: 'cursor_invalid' };

/** Decodes a cursor of `adapterVersion`; anything else (or malformed) is `cursor_invalid`. */
export function decodeCursor(raw: string, adapterVersion: string): DecodedCursor {
  if (raw.length === 0 || raw.length > CURSOR_MAX_LENGTH || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    return { ok: false, reason: 'cursor_invalid' };
  }
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'cursor_invalid' };
  }
  const result = cursorSchema.safeParse(json);
  if (!result.success || result.data.a !== adapterVersion) {
    return { ok: false, reason: 'cursor_invalid' };
  }
  return { ok: true, cursor: result.data };
}

/** The page counter of a cursor (0 for `null` or an invalid cursor). */
export function cursorSeq(raw: string | null, adapterVersion: string): number {
  if (raw === null) return 0;
  const decoded = decodeCursor(raw, adapterVersion);
  return decoded.ok ? decoded.cursor.seq : 0;
}

/**
 * A cursor that starts a stream (or a backfill, D8.1) at `from`: the runner (WP4) stores it on the
 * stream row. `seq` continues from the previous cursor so cursors stay monotonic.
 */
export function initialCursor(adapterVersion: string, from: Date, previousSeq = 0): string {
  return encodeCursor({ v: 1, a: adapterVersion, seq: previousSeq, wm: from.toISOString() });
}

export const COMPANION_CURSOR_PREFIX = 'companion:v1:';

export function companionCursor(primary: string): string {
  return `${COMPANION_CURSOR_PREFIX}${primary}`;
}

/**
 * The cursor an `ingest` call starts from. `null` starts fresh (seq 0, no watermark: the window
 * begins at `now − overlap`). An invalid cursor (malformed or of another adapter version) also
 * starts at `now − overlap`, never at the epoch, with `seq` = epoch seconds so it stays above any
 * previous page counter (`reset: true`, counted `ato_idp_cursor_resets_total`).
 */
export function resolveCursor(
  raw: string | null,
  adapterVersion: string,
  now: Date,
): { cursor: CursorV1; reset: boolean } {
  if (raw === null) return { cursor: { v: 1, a: adapterVersion, seq: 0 }, reset: false };
  const decoded = decodeCursor(raw, adapterVersion);
  if (decoded.ok) return { cursor: decoded.cursor, reset: false };
  return {
    cursor: { v: 1, a: adapterVersion, seq: Math.floor(now.getTime() / 1000) },
    reset: true,
  };
}
