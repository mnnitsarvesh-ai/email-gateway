/** Identifier shapes shared by the AADs, object keys, index names and tokens of the archive. */

/** A lower-case RFC 9562 style UUID (public ids, capture ids). */
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** An internal decimal id (`BIGINT UNSIGNED`), no leading zero. */
export const DECIMAL_ID_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/;

export type NumericId = bigint | number | string;

/** The decimal form of an internal id; null when it is not a non-negative integer id. */
export function decimalIdOrNull(value: NumericId): string | null {
  if (typeof value === 'bigint') return value >= 0n ? value.toString() : null;
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? String(value) : null;
  }
  return typeof value === 'string' && DECIMAL_ID_PATTERN.test(value) ? value : null;
}

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

/** True for a positive 32-bit integer (key versions, rounds). */
export function isPositiveInt(value: unknown, max = 0xffff_ffff): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= max;
}
