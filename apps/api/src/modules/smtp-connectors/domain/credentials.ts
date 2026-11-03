import { randomBytes, randomInt } from 'node:crypto';

/**
 * Generated SASL credentials and certificate fingerprints of connectors (step 2.2 D10). Pure
 * apart from the CSPRNG.
 */

/** RFC 4648 base32 alphabet, lower case. */
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
export const SASL_USERNAME_PREFIX = 'egc-';
export const SASL_USERNAME_RANDOM_LENGTH = 20;
export const SASL_USERNAME_PATTERN = /^egc-[a-z2-7]{20}$/;
/** Bytes of entropy in a generated secret (base64url-encoded: 43 characters). */
export const SASL_SECRET_BYTES = 32;

/** `egc-` + 20 random lower-case base32 characters (100 bits). */
export function generateSaslUsername(): string {
  let out = SASL_USERNAME_PREFIX;
  for (let i = 0; i < SASL_USERNAME_RANDOM_LENGTH; i++) out += BASE32[randomInt(32)];
  return out;
}

/** 32 random bytes, base64url without padding. Returned once; only its Argon2id hash is kept. */
export function generateSaslSecret(): string {
  return randomBytes(SASL_SECRET_BYTES).toString('base64url');
}

const HEX64 = /^[0-9a-f]{64}$/;
const COLON_HEX = /^[0-9a-f]{2}(:[0-9a-f]{2}){31}$/;

/**
 * Normalizes a SHA-256 certificate fingerprint: 64 hex characters, or 32 colon-separated hex
 * pairs (as `openssl x509 -fingerprint -sha256` prints it), any case, surrounding whitespace
 * ignored. Returns lower-case hex without colons, or null when the input is not one of those.
 */
export function normalizeFingerprint(input: string): string | null {
  const value = input.trim().toLowerCase();
  if (HEX64.test(value)) return value;
  if (COLON_HEX.test(value)) return value.replaceAll(':', '');
  return null;
}
