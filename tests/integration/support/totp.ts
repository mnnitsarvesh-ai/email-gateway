import { createHmac } from 'node:crypto';

/**
 * RFC 6238 TOTP for the stack suites' MFA logins (the api's TOTP: HMAC-SHA-1, 6 digits, 30 s
 * steps; the secret is stored base32 in `users.mfa_secret_ciphertext`). Secrets are generated per
 * test user and never printed.
 */
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

/** RFC 6238 TOTP of a raw key for one 30-second step (HMAC-SHA-1, dynamic truncation). */
export function totp(key: Buffer, step: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', key).update(message).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

/** The code of the current 30-second step. */
export function totpNow(key: Buffer): string {
  return totp(key, Math.floor(Date.now() / 30_000));
}
