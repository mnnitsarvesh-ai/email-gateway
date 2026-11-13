import { Prisma } from '@email-gateway/database';
import { idOf } from '../shared/errors';

/**
 * `((id = ? AND event_occurred_at = ?) OR …)` for a set of `webhook_deliveries` primary keys. A
 * row constructor `(id, event_occurred_at) IN ((?, ?), …)` is not used: MySQL rejects the
 * DATETIME parameters of a prepared row constructor with more than one tuple (error 1292 through
 * Prisma's binary protocol; the event-relay documents the same).
 */
export function deliveryKeyMatch(
  rows: ReadonlyArray<{ id: bigint | number; event_occurred_at: Date }>,
): Prisma.Sql {
  if (rows.length === 0) return Prisma.sql`FALSE`;
  return Prisma.sql`(${Prisma.join(
    rows.map(
      (r) => Prisma.sql`(id = ${idOf(r.id)} AND event_occurred_at = ${r.event_occurred_at})`,
    ),
    ' OR ',
  )})`;
}
