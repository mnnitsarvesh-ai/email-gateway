/**
 * Helpers for BIGINT UNSIGNED ids (ADR-0014 §1).
 *
 * Prisma returns ids as `bigint`. JSON numbers cannot hold 64-bit integers and `JSON.stringify`
 * throws on `bigint`, so internal contracts (events, S3 keys, logs) carry ids as canonical
 * decimal strings: no sign, no leading zeros, no whitespace. External APIs expose `public_id`
 * (UUIDv7) instead of numeric ids.
 */

const ID_PATTERN = /^[1-9][0-9]{0,19}$/;

/** Largest value of a MySQL BIGINT UNSIGNED column (2^64 − 1). */
export const MAX_ID = 18446744073709551615n;

/** True when `value` is a canonical decimal id string within the BIGINT UNSIGNED range. */
export function isIdString(value: string): boolean {
  return ID_PATTERN.test(value) && BigInt(value) <= MAX_ID;
}

/** Parses a canonical decimal id string. Throws a descriptive Error for anything else. */
export function parseId(value: string): bigint {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new Error(
      `Invalid id ${JSON.stringify(value)}: expected a decimal string of 1-20 digits without leading zeros`,
    );
  }
  const id = BigInt(value);
  if (id > MAX_ID) {
    throw new Error(`Invalid id ${JSON.stringify(value)}: exceeds the BIGINT UNSIGNED maximum`);
  }
  return id;
}

/** Formats an id as its canonical decimal string. Throws if it is out of range. */
export function formatId(id: bigint): string {
  if (typeof id !== 'bigint' || id < 1n || id > MAX_ID) {
    throw new Error(`Invalid id ${String(id)}: expected a bigint between 1 and ${MAX_ID}`);
  }
  return id.toString(10);
}
