import type { DisplayHints } from '../registry/types';

/** Generic response shape detection shared by the minimizer and the card builder (D8). */

export const LIST_KEYS = ['data', 'items'] as const;

export interface ListShape {
  kind: 'list';
  listKey: string | null;
  rows: unknown[];
  hasMore: boolean;
  /** Other top-level fields of the response. */
  rest: Record<string, unknown>;
}

export interface RecordShape {
  kind: 'record';
  record: Record<string, unknown>;
}

export interface EmptyShape {
  kind: 'empty';
  value: unknown;
}

export type ResponseShape = ListShape | RecordShape | EmptyShape;

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** `{ data: [...], nextCursor }` / `{ items: [...] }` / `[...]` → list; object → record. */
export function detectShape(body: unknown): ResponseShape {
  if (Array.isArray(body))
    return { kind: 'list', listKey: null, rows: body, hasMore: false, rest: {} };
  if (!isPlainObject(body)) return { kind: 'empty', value: body ?? null };
  for (const key of LIST_KEYS) {
    const value = body[key];
    if (Array.isArray(value)) {
      const rest: Record<string, unknown> = {};
      for (const [name, item] of Object.entries(body))
        if (name !== key && name !== 'nextCursor') rest[name] = item;
      const cursor = body.nextCursor;
      return {
        kind: 'list',
        listKey: key,
        rows: value,
        hasMore: typeof cursor === 'string' && cursor.length > 0,
        rest,
      };
    }
  }
  return { kind: 'record', record: body };
}

/** The opaque next-page cursor of a list response (stored server-side, never sent to the model). */
export function extractNextCursor(body: unknown): string | null {
  if (!isPlainObject(body)) return null;
  const cursor = body.nextCursor;
  return typeof cursor === 'string' && cursor.length > 0 ? cursor : null;
}

/** Public ids and keys only: no spaces, no markup, bounded. */
export const PUBLIC_ID = /^[A-Za-z0-9._:@-]{1,128}$/;

/** The value at a dotted field path (`policy.id`), or undefined. */
function fieldAt(row: Record<string, unknown>, path: string): unknown {
  let node: unknown = row;
  for (const segment of path.split('.')) {
    if (!isPlainObject(node)) return undefined;
    node = node[segment];
  }
  return node;
}

/**
 * The public id of a row: the manifest's `refField` (a field or a dotted path such as
 * `policy.id`), else `id`, `publicId`, else the first `<x>Id` field holding an id-shaped string.
 */
export function detectRowId(row: unknown, hints: DisplayHints | undefined): string | null {
  if (!isPlainObject(row)) return null;
  const candidates: unknown[] = [];
  if (hints?.refField) candidates.push(fieldAt(row, hints.refField));
  else {
    candidates.push(row.id, row.publicId);
    for (const [key, value] of Object.entries(row))
      if (/[a-z]Id$/.test(key)) candidates.push(value);
  }
  for (const value of candidates)
    if (typeof value === 'string' && PUBLIC_ID.test(value)) return value;
  return null;
}
