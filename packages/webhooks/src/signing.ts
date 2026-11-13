import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** The signature header of every webhook request (§4.2). */
export const WEBHOOK_SIGNATURE_HEADER = 'EG-Signature';
/** Prefix of every signing secret. */
export const WEBHOOK_SECRET_PREFIX = 'whsec_';
/** Random bytes of a secret (256 bits). */
export const WEBHOOK_SECRET_BYTES = 32;
/** `whsec_` + base64url(32 bytes) without padding = 6 + 43 characters. */
export const WEBHOOK_SECRET_LENGTH = WEBHOOK_SECRET_PREFIX.length + 43;
/** Default accepted clock difference between the signed timestamp and the receiver (seconds). */
export const WEBHOOK_SIGNATURE_TOLERANCE_SECONDS = 300;
/** Longest header accepted by the parser (a rotation overlap carries two signatures). */
const MAX_HEADER_LENGTH = 1024;
const MAX_SIGNATURES = 8;

const SECRET_PATTERN = /^whsec_[A-Za-z0-9_-]{43}$/;
const HEX_SIGNATURE = /^[0-9a-f]{64}$/;
const TIMESTAMP = /^[0-9]{1,12}$/;

/** A fresh signing secret: `whsec_` + base64url of 32 CSPRNG bytes (W7). */
export function generateWebhookSecret(random: (size: number) => Buffer = randomBytes): string {
  const bytes = random(WEBHOOK_SECRET_BYTES);
  if (bytes.length !== WEBHOOK_SECRET_BYTES) throw new Error('Secret entropy source failed');
  return `${WEBHOOK_SECRET_PREFIX}${bytes.toString('base64url')}`;
}

/** True for a well-formed secret (shape only). */
export function isWebhookSecret(value: string): boolean {
  return SECRET_PATTERN.test(value);
}

/**
 * Lower-case hex HMAC-SHA256 over `` `${timestamp}.${rawBody}` ``. The key is the UTF-8 bytes of
 * the **whole** secret string, prefix included (receivers use the secret as shown, no decoding).
 */
export function signPayload(
  secret: string,
  timestamp: number,
  rawBody: string | Buffer | Uint8Array,
): string {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error('Invalid timestamp');
  return createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(`${timestamp}.`, 'utf8')
    .update(typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody)
    .digest('hex');
}

/**
 * `t=<unix seconds>,v1=<hex>[,v1=<hex>]`: one `v1` per secret, in the given order (the current
 * secret first, then the previous one during a rotation overlap).
 */
export function signatureHeader(
  secrets: readonly string[],
  timestamp: number,
  rawBody: string | Buffer | Uint8Array,
): string {
  if (secrets.length === 0) throw new Error('At least one secret is required');
  return [
    `t=${timestamp}`,
    ...secrets.map((secret) => `v1=${signPayload(secret, timestamp, rawBody)}`),
  ].join(',');
}

export interface ParsedSignatureHeader {
  timestamp: number;
  /** Every `v1` signature (lower-case hex). Unknown schemes are ignored. */
  signatures: string[];
}

/**
 * Parses `t=<digits>,v1=<64 hex>[,…]`; `null` when malformed: missing, repeated or non-numeric
 * `t`, no `v1`, a `v1` that is not 64 lower-case hex characters, an element without `=`, or an
 * over-long header. Other schemes (`v0=`, `v2=`) are ignored for forward compatibility.
 */
export function parseSignatureHeader(
  header: string | null | undefined,
): ParsedSignatureHeader | null {
  if (typeof header !== 'string' || header.length === 0 || header.length > MAX_HEADER_LENGTH) {
    return null;
  }
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const element of header.split(',')) {
    const part = element.trim();
    const eq = part.indexOf('=');
    if (eq <= 0) return null;
    const scheme = part.slice(0, eq);
    const value = part.slice(eq + 1);
    if (scheme === 't') {
      if (timestamp !== null || !TIMESTAMP.test(value)) return null;
      timestamp = Number(value);
    } else if (scheme === 'v1') {
      if (!HEX_SIGNATURE.test(value)) return null;
      signatures.push(value);
    }
  }
  if (timestamp === null || signatures.length === 0 || signatures.length > MAX_SIGNATURES) {
    return null;
  }
  return { timestamp, signatures };
}

export type WebhookVerificationResult =
  { ok: true } | { ok: false; reason: 'malformed' | 'stale' | 'mismatch' };

export interface VerifyWebhookSignatureInput {
  header: string | null | undefined;
  /** The exact received body bytes (verify before parsing). */
  rawBody: string | Buffer | Uint8Array;
  /** Accepted secrets (e.g. current and previous during a rotation). */
  secrets: readonly string[];
  toleranceSeconds?: number;
  /** Receiver clock (epoch milliseconds or a Date); defaults to `Date.now()`. */
  now?: number | Date;
}

/**
 * Receiver-side verification (§4.2): parse, reject `|now − t| > tolerance` (`stale`, both
 * directions), then compare every `v1` against every secret in constant time without stopping
 * at the first match (`mismatch` when none matches).
 */
export function verifyWebhookSignature(
  input: VerifyWebhookSignatureInput,
): WebhookVerificationResult {
  const parsed = parseSignatureHeader(input.header);
  if (!parsed) return { ok: false, reason: 'malformed' };
  const tolerance = input.toleranceSeconds ?? WEBHOOK_SIGNATURE_TOLERANCE_SECONDS;
  const nowMs = input.now instanceof Date ? input.now.getTime() : (input.now ?? Date.now());
  if (Math.abs(Math.floor(nowMs / 1000) - parsed.timestamp) > tolerance) {
    return { ok: false, reason: 'stale' };
  }
  let matched = false;
  for (const secret of input.secrets) {
    const expected = Buffer.from(signPayload(secret, parsed.timestamp, input.rawBody), 'hex');
    for (const signature of parsed.signatures) {
      const candidate = Buffer.from(signature, 'hex');
      // Both are 32 bytes (the parser accepts only 64-hex signatures).
      if (timingSafeEqual(expected, candidate)) matched = true;
    }
  }
  return matched ? { ok: true } : { ok: false, reason: 'mismatch' };
}
