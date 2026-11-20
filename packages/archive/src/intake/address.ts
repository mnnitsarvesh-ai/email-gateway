import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { isUuid } from '../ids';

/**
 * Journal intake addresses and header tokens (step 8.6 D1, ADR-0087).
 *
 * - address `journal-<token>@<JOURNAL_INTAKE_DOMAIN>`, token = the first 26 characters of the
 *   lower-case RFC 4648 base32 (no padding) of
 *   `HMAC-SHA256(secret, "eg-journal-intake-address/v1\0<sourcePublicId>\0<addressVersion>")`
 *   (130 bits);
 * - Google Workspace header token (`X-EG-Journal-Token`): the same over
 *   `"eg-journal-intake-header/v1\0<sourcePublicId>\0<addressVersion>"`;
 * - the database stores only `address_hash = sha256(lower(local part))` and
 *   `header_token_hash = sha256(lower(token))`; only the api holds the secret.
 */

export const INTAKE_ADDRESS_LABEL = 'eg-journal-intake-address/v1';
export const INTAKE_HEADER_LABEL = 'eg-journal-intake-header/v1';
export const INTAKE_TOKEN_LENGTH = 26;
export const INTAKE_LOCAL_PART_PREFIX = 'journal-';
export const JOURNAL_TOKEN_HEADER_NAME = 'X-EG-Journal-Token';

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
const TOKEN_PATTERN = /^[a-z2-7]{26}$/;
const LOCAL_PART_PATTERN = /^journal-([a-z2-7]{26})$/;

/** Lower-case RFC 4648 base32 without padding. */
export function base32Lower(data: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(buffer << (5 - bits)) & 31];
  return out;
}

export class IntakeAddressError extends Error {
  constructor(readonly what: string) {
    super(`Invalid journal intake ${what}`);
    this.name = 'IntakeAddressError';
  }
}

/**
 * Parses `JOURNAL_INTAKE_ADDRESS_SECRET` (hex, at least 32 bytes) into the HMAC key. The error
 * names the key, never the value.
 */
export function parseIntakeAddressSecret(hex: string): Buffer {
  if (typeof hex !== 'string' || !/^(?:[0-9a-fA-F]{2}){32,}$/.test(hex.trim())) {
    throw new IntakeAddressError('JOURNAL_INTAKE_ADDRESS_SECRET');
  }
  return Buffer.from(hex.trim(), 'hex');
}

function checkInputs(secret: Uint8Array, sourcePublicId: string, version: number): void {
  if (!(secret instanceof Uint8Array) || secret.length < 32) throw new IntakeAddressError('secret');
  if (!isUuid(sourcePublicId)) throw new IntakeAddressError('source id');
  if (!Number.isInteger(version) || version < 1 || version > 65_535) {
    throw new IntakeAddressError('address version');
  }
}

function derive(label: string, secret: Uint8Array, sourcePublicId: string, version: number) {
  checkInputs(secret, sourcePublicId, version);
  const mac = createHmac('sha256', secret)
    .update(`${label}\0${sourcePublicId}\0${version}`, 'utf8')
    .digest();
  return base32Lower(mac).slice(0, INTAKE_TOKEN_LENGTH);
}

/** The address token of a source and address version (26 lower-case base32 characters). */
export function deriveIntakeAddressToken(
  secret: Uint8Array,
  sourcePublicId: string,
  version: number,
): string {
  return derive(INTAKE_ADDRESS_LABEL, secret, sourcePublicId, version);
}

/** The `X-EG-Journal-Token` value of a Google Workspace source and address version. */
export function deriveIntakeHeaderToken(
  secret: Uint8Array,
  sourcePublicId: string,
  version: number,
): string {
  return derive(INTAKE_HEADER_LABEL, secret, sourcePublicId, version);
}

/** `journal-<token>` (the local part). */
export function intakeLocalPart(token: string): string {
  if (!TOKEN_PATTERN.test(token)) throw new IntakeAddressError('token');
  return `${INTAKE_LOCAL_PART_PREFIX}${token}`;
}

/** `journal-<token>@<domain>`. */
export function intakeAddress(token: string, domain: string): string {
  const d = domain.trim().toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(d)) throw new IntakeAddressError('domain');
  return `${intakeLocalPart(token)}@${d}`;
}

/** The token of an intake local part (case-insensitive), or null when it has another shape. */
export function parseIntakeLocalPart(localPart: string): string | null {
  if (typeof localPart !== 'string' || localPart.length > 64) return null;
  const m = LOCAL_PART_PATTERN.exec(localPart.trim().toLowerCase());
  return m ? m[1]! : null;
}

/** `address_hash`: SHA-256 (hex) of the lower-cased local part. */
export function intakeAddressHash(localPart: string): string {
  return createHash('sha256').update(localPart.trim().toLowerCase(), 'utf8').digest('hex');
}

/** `header_token_hash`: SHA-256 (hex) of the lower-cased, trimmed header token. */
export function intakeHeaderTokenHash(token: string): string {
  return createHash('sha256').update(token.trim().toLowerCase(), 'utf8').digest('hex');
}

/** Constant-time comparison of two SHA-256 hex digests (false for any malformed input). */
export function sha256HexEqual(a: string, b: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(a) || !/^[0-9a-f]{64}$/.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

const MASK = '••••';

/** `journal-••••<last 4>@domain` (D1, like the 8.2 route token); other shapes → `••••`. */
export function maskIntakeAddress(address: string): string {
  const at = address.lastIndexOf('@');
  if (at < 0) return MASK;
  const token = parseIntakeLocalPart(address.slice(0, at));
  if (token === null) return MASK;
  return `${INTAKE_LOCAL_PART_PREFIX}${MASK}${token.slice(-4)}@${address.slice(at + 1).toLowerCase()}`;
}

/** `••••<last 4>` of a header token. */
export function maskIntakeHeaderToken(token: string): string {
  return TOKEN_PATTERN.test(token) ? `${MASK}${token.slice(-4)}` : MASK;
}
