import { BadRequestException } from '@nestjs/common';

/** Keyset position `(received_at, id)` of the last row of a `/deliveries` page. */
export interface DeliveryCursor {
  receivedAt: Date;
  id: bigint;
}

const DECODED = /^(\d{1,15})\.([1-9]\d{0,19})$/;

/** Opaque cursor: base64url of `<received_at epoch ms>.<id>`. */
export function encodeDeliveryCursor(cursor: DeliveryCursor): string {
  return Buffer.from(`${cursor.receivedAt.getTime()}.${cursor.id.toString(10)}`, 'utf8').toString(
    'base64url',
  );
}

/** Decodes a cursor produced by encodeDeliveryCursor; anything else is a `400`. */
export function decodeDeliveryCursor(value: string): DeliveryCursor {
  const decoded = Buffer.from(value, 'base64url').toString('utf8');
  const match = DECODED.exec(decoded);
  if (match) {
    const cursor = { receivedAt: new Date(Number(match[1])), id: BigInt(match[2]!) };
    if (encodeDeliveryCursor(cursor) === value) return cursor;
  }
  throw new BadRequestException(['cursor: Invalid cursor']);
}

/** Longest `[from, to)` range of `GET /deliveries` (partition pruning, R13). */
export const MAX_RANGE_MS = 31 * 86_400_000;
/** Default range: the last 24 hours. */
export const DEFAULT_RANGE_MS = 86_400_000;

/**
 * `[from, to)` of a list request: `to` defaults to now, `from` to `to` − 24 h. `from` must be
 * before `to` and the range at most 31 days (`400` otherwise).
 */
export function deliveryRange(
  query: { from?: string | undefined; to?: string | undefined },
  now: Date = new Date(),
): { from: Date; to: Date } {
  const to = query.to === undefined ? now : new Date(query.to);
  const from =
    query.from === undefined ? new Date(to.getTime() - DEFAULT_RANGE_MS) : new Date(query.from);
  if (from.getTime() >= to.getTime()) {
    throw new BadRequestException(['from: must be before to']);
  }
  if (to.getTime() - from.getTime() > MAX_RANGE_MS) {
    throw new BadRequestException(['to: the range may cover at most 31 days']);
  }
  return { from, to };
}
