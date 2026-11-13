/**
 * RFC 6238 TOTP (HMAC-SHA-1, 6 digits, 30-second steps) with node:crypto only, the parameters
 * the api uses (docs/security/authentication.md). Independent of the api's implementation.
 */
import { createHmac } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const STEP_SECONDS = 30;

export function base32Decode(input: string): Buffer {
  const clean = input.replace(/[\s=-]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error('Invalid base32 key');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function stepAt(ms: number): number {
  return Math.floor(ms / 1000 / STEP_SECONDS);
}

/** RFC 4226 HOTP for `counter`, RFC 6238 when the counter is the time step. */
export function totpAtStep(secret: string, step: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', base32Decode(secret)).update(message).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return (binary % 1_000_000).toString().padStart(6, '0');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * A code the api has not seen yet for this secret. The api accepts each step once (replay
 * protection) and the current step ± 1, so a second login within the same 30 s waits for the
 * next step. `lastUsedStep` is persisted by the caller (support/state.ts).
 */
export async function freshTotp(
  secret: string,
  lastUsedStep: number | undefined,
): Promise<{ code: string; step: number }> {
  for (;;) {
    const current = stepAt(Date.now());
    if (lastUsedStep === undefined || current > lastUsedStep) {
      return { code: totpAtStep(secret, current), step: current };
    }
    // Wait for the next step (plus a small margin against clock skew).
    const nextStepMs = (current + 1) * STEP_SECONDS * 1000;
    await sleep(Math.max(250, nextStepMs - Date.now() + 500));
  }
}
