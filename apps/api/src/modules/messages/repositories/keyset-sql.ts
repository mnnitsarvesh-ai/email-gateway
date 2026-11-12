import { Prisma } from '@email-gateway/database';
import type { CursorDirection } from '../../../http/cursor/cursor-codec';
import type { TimeIdKey } from '../domain/v1-list';

/**
 * `Prisma.sql` fragments of the `(time, id)` keyset of the step 6.1 v1 lists (D3, D5). Column
 * names come only from the code constants of the calling repository (`Prisma.raw` of a literal),
 * values are always bound parameters. Row-constructor comparisons are avoided: MySQL turns the
 * `t < ? OR (t = ? AND id < ?)` form into index ranges.
 */

/** A column identifier from a code constant (never input). */
export const column = (name: `${string}`): Prisma.Sql => {
  if (!/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$/.test(name)) {
    throw new Error(`keyset-sql: invalid column constant ${name}`);
  }
  return Prisma.raw(name);
};

/** Rows strictly after the cursor position in keyset order (`TRUE` without a cursor). */
export function afterKey(
  time: Prisma.Sql,
  id: Prisma.Sql,
  key: TimeIdKey | undefined,
  direction: CursorDirection,
): Prisma.Sql {
  if (!key) return Prisma.sql`TRUE`;
  return direction === 'desc'
    ? Prisma.sql`(${time} < ${key.at} OR (${time} = ${key.at} AND ${id} < ${key.id}))`
    : Prisma.sql`(${time} > ${key.at} OR (${time} = ${key.at} AND ${id} > ${key.id}))`;
}

/** Rows up to and including the scan boundary in keyset order (`TRUE` without one). */
export function upToKey(
  time: Prisma.Sql,
  id: Prisma.Sql,
  boundary: TimeIdKey | null,
  direction: CursorDirection,
): Prisma.Sql {
  if (!boundary) return Prisma.sql`TRUE`;
  return direction === 'desc'
    ? Prisma.sql`(${time} > ${boundary.at} OR (${time} = ${boundary.at} AND ${id} >= ${boundary.id}))`
    : Prisma.sql`(${time} < ${boundary.at} OR (${time} = ${boundary.at} AND ${id} <= ${boundary.id}))`;
}

/** `ORDER BY time <dir>, id <dir>`. */
export function keysetOrder(time: Prisma.Sql, id: Prisma.Sql, direction: CursorDirection) {
  return direction === 'desc'
    ? Prisma.sql`ORDER BY ${time} DESC, ${id} DESC`
    : Prisma.sql`ORDER BY ${time} ASC, ${id} ASC`;
}

/** `AND`-joins fragments (`TRUE` for none). */
export function allOf(parts: readonly Prisma.Sql[]): Prisma.Sql {
  return parts.length === 0 ? Prisma.sql`TRUE` : Prisma.join(parts, ' AND ');
}
