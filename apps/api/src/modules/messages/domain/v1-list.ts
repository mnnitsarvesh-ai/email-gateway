import { createHash } from 'node:crypto';
import type { Principal } from '../../../auth-contracts/principal';
import {
  type CursorCodec,
  type CursorDirection,
  cursorInvalid,
  type DecodedCursor,
} from '../../../http/cursor/cursor-codec';
import { filterHash, type ParsedFilter } from '../../../http/listing';

/**
 * Building blocks of the step 6.1 v1 lists of the messages data routes (WP2; D3, D4, ADR-0051):
 * the organization public id the cursor MAC binds, the filter hash, cursor decoding with the
 * sort direction check, and the typed keyset values of a cursor. Every failure is the same
 * `400 cursor_invalid`.
 */

/** Public id of the scope's organization: the override target under a platform override. */
export function scopeOrganizationPublicId(principal: Principal): string {
  if (principal.kind === 'user' && principal.override) {
    return principal.override.targetOrganizationPublicId;
  }
  return principal.organizationPublicId;
}

/** `-receivedAt` → `desc`, `receivedAt` → `asc` (sorts are leading keyset keys only, D4). */
export const directionOf = (sort: string): CursorDirection =>
  sort.startsWith('-') ? 'desc' : 'asc';

/** One v1 list request: what its cursor is bound to. */
export interface ListBinding {
  resource: string;
  organizationPublicId: string;
  filterHash: string;
  direction: CursorDirection;
}

export function listBinding(input: {
  resource: string;
  principal: Principal;
  filters: Record<string, ParsedFilter<unknown> | undefined>;
  sort: string;
}): ListBinding {
  return {
    resource: input.resource,
    organizationPublicId: scopeOrganizationPublicId(input.principal),
    filterHash: filterHash({ resource: input.resource, filters: input.filters, sort: input.sort }),
    direction: directionOf(input.sort),
  };
}

/** Verifies the cursor (MAC, resource, filter hash, age) and its direction; `undefined` without. */
export function decodeListCursor(
  codec: CursorCodec,
  binding: ListBinding,
  cursor: string | undefined,
  keyCount: number,
): DecodedCursor | undefined {
  if (cursor === undefined) return undefined;
  const decoded = codec.decode(cursor, binding);
  if (decoded.direction !== binding.direction || decoded.keys.length !== keyCount) {
    throw cursorInvalid();
  }
  return decoded;
}

export function encodeListCursor(
  codec: CursorCodec,
  binding: ListBinding,
  keys: readonly string[],
  window?: readonly [number, number],
): string {
  return codec.encode({
    resource: binding.resource,
    organizationPublicId: binding.organizationPublicId,
    filterHash: binding.filterHash,
    direction: binding.direction,
    keys,
    ...(window && { window }),
  });
}

const DECIMAL = /^(0|[1-9]\d{0,19})$/;
const MAX_UNSIGNED_BIGINT = 18_446_744_073_709_551_615n;

/** A decimal keyset value (an internal row id) of a verified cursor. */
export function decimalKey(value: string | undefined): bigint {
  if (value === undefined || !DECIMAL.test(value)) throw cursorInvalid();
  const parsed = BigInt(value);
  if (parsed > MAX_UNSIGNED_BIGINT) throw cursorInvalid();
  return parsed;
}

/** An ISO instant keyset value of a verified cursor (canonical `toISOString` form only). */
export function instantKey(value: string | undefined): Date {
  if (value === undefined) throw cursorInvalid();
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) throw cursorInvalid();
  return date;
}

/** A small non-negative integer keyset value (a sequence) of a verified cursor. */
export function intKey(value: string | undefined, max: number): number {
  if (value === undefined || !/^(0|[1-9]\d{0,9})$/.test(value)) throw cursorInvalid();
  const parsed = Number(value);
  if (parsed > max) throw cursorInvalid();
  return parsed;
}

/** `(time, id)` keyset position of a row. */
export interface TimeIdKey {
  at: Date;
  id: bigint;
}

export const timeIdKeys = (key: TimeIdKey): string[] => [key.at.toISOString(), key.id.toString()];

export function timeIdKeyOf(decoded: DecodedCursor | undefined): TimeIdKey | undefined {
  if (!decoded) return undefined;
  return { at: instantKey(decoded.keys[0]), id: decimalKey(decoded.keys[1]) };
}

/** Hex SHA-256 of an identifying search value (audit metadata never holds the value, D11). */
export const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');
