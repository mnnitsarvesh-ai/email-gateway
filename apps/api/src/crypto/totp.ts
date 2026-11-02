import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** RFC 6238 parameters used everywhere (D4): SHA-1, 6 digits, 30-second steps. */
export const TOTP_DIGITS = 6;
export const TOTP_PERIOD_SECONDS = 30;
const SECRET_BYTES = 20;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32, upper-case, without padding. */
export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Decodes base32 (case-insensitive, spaces and `=` padding ignored). Throws on other input. */
export function base32Decode(input: string): Buffer {
  const clean = input.replace(/[\s=]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error('Invalid base32 input');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A new random 160-bit secret, base32-encoded (32 characters). */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(SECRET_BYTES));
}

/** RFC 4226 HOTP (HMAC-SHA-1, dynamic truncation) for a counter, zero-padded to `digits`. */
export function hotp(key: Buffer, counter: number, digits = TOTP_DIGITS): string {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('Invalid HOTP counter');
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', key).update(message).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

/** The 30-second step that contains `nowMs`. */
export function totpStep(nowMs: number): number {
  return Math.floor(nowMs / 1000 / TOTP_PERIOD_SECONDS);
}

/** The 6-digit code of a base32 secret for one step. */
export function totpCode(secret: string, step: number): string {
  return hotp(base32Decode(secret), step);
}

export interface VerifyTotpOptions {
  /** Defaults to `Date.now()`. */
  now?: number;
  /** Accepted clock drift in steps on each side (default 1). */
  window?: number;
  /** Replay protection: only steps strictly greater than this are accepted. */
  afterStep?: number | bigint | null;
}

export type TotpVerification = { ok: true; step: number } | { ok: false };

/**
 * Checks a code against the current step ± `window`. Returns the matched step, which the caller
 * stores (`users.mfa_last_used_step`, conditional update) so the same code cannot be replayed.
 */
export function verifyTotp(
  secret: string,
  code: string,
  options: VerifyTotpOptions = {},
): TotpVerification {
  if (!/^\d{6}$/.test(code)) return { ok: false };
  const current = totpStep(options.now ?? Date.now());
  const window = options.window ?? 1;
  const after = options.afterStep == null ? -1 : Number(options.afterStep);
  const key = base32Decode(secret);
  const given = Buffer.from(code, 'utf8');
  let matched: number | undefined;
  // Compare every candidate step so timing does not reveal which one matched.
  for (let step = current - window; step <= current + window; step += 1) {
    if (step < 0 || step <= after) continue;
    const expected = Buffer.from(hotp(key, step), 'utf8');
    if (timingSafeEqual(expected, given) && matched === undefined) matched = step;
  }
  return matched === undefined ? { ok: false } : { ok: true, step: matched };
}

/** `otpauth://` URI for authenticator apps (Key Uri Format). */
export function otpauthUri(params: { issuer: string; account: string; secret: string }): string {
  const issuer = encodeURIComponent(params.issuer);
  const label = `${issuer}:${encodeURIComponent(params.account)}`;
  // encodeURIComponent (not URLSearchParams): authenticator apps expect %20, not '+'.
  const query = [
    `secret=${encodeURIComponent(params.secret)}`,
    `issuer=${issuer}`,
    'algorithm=SHA1',
    `digits=${TOTP_DIGITS}`,
    `period=${TOTP_PERIOD_SECONDS}`,
  ].join('&');
  return `otpauth://totp/${label}?${query}`;
}
