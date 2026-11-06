import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

/**
 * Click tokens (docs/plan/steps/11-url-protection.md U12), TOKEN_VERSION 1: 46 bytes, base64url
 * without padding = 62 characters.
 *
 *   0       version 0x01
 *   1       key id 1..255
 *   2–9     organization_id uint64 BE
 *   10–17   message_id uint64 BE
 *   18–23   received_at epoch ms uint48 BE
 *   24–25   url_seq uint16 BE
 *   26–29   expiry epoch seconds uint32 BE
 *   30–45   HMAC-SHA256(key, "eg-url-token/v1\0" ‖ bytes 0–29), first 16 bytes
 *
 * The URL, tenant name and recipient are never in the token; the original URL is stored server
 * side and never taken from the token.
 */

export const TOKEN_VERSION = 1;
export const TOKEN_BYTES = 46;
export const TOKEN_LENGTH = 62;
const CLAIM_BYTES = 30;
const MAC_BYTES = 16;
const DOMAIN = Buffer.from('eg-url-token/v1\0', 'latin1');
const CONTINUE_INFO = 'eg-url-continue/v1';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{62}$/;
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_UINT48 = 2 ** 48 - 1;

export interface TokenKey {
  /** Key id 1..255 (URL_TOKEN_KEY_CURRENT_ID / _PREVIOUS_ID). */
  id: number;
  /** 32 bytes. */
  key: Buffer;
}

export interface TokenKeys {
  current: TokenKey;
  previous?: TokenKey | null;
}

export interface TokenClaims {
  keyId: number;
  organizationId: bigint;
  messageId: bigint;
  /** Epoch milliseconds (the partition key of the lookup). */
  receivedAtMs: number;
  urlSeq: number;
  /** Epoch seconds. */
  expiresAt: number;
}

/** Parses a 64-hex-character key (URL_TOKEN_KEY_CURRENT/PREVIOUS) into 32 bytes. */
export function parseTokenKey(hex: string, id: number): TokenKey {
  if (!/^[0-9a-fA-F]{64}$/.test(hex))
    throw new Error('a token key must be 64 hexadecimal characters');
  if (!Number.isInteger(id) || id < 1 || id > 255) throw new Error('a token key id must be 1..255');
  return { id, key: Buffer.from(hex, 'hex') };
}

/** Validates a key pair (distinct ids, distinct keys). */
export function validateTokenKeys(keys: TokenKeys): TokenKeys {
  if (keys.current.key.length !== 32) throw new Error('the current token key must be 32 bytes');
  if (keys.previous) {
    if (keys.previous.key.length !== 32) throw new Error('the previous token key must be 32 bytes');
    if (keys.previous.id === keys.current.id)
      throw new Error('current and previous token key ids must differ');
    if (keys.previous.key.equals(keys.current.key))
      throw new Error('current and previous token keys must differ');
  }
  return keys;
}

function mac(key: Buffer, claims: Buffer): Buffer {
  return createHmac('sha256', key).update(DOMAIN).update(claims).digest().subarray(0, MAC_BYTES);
}

export function signToken(claims: Omit<TokenClaims, 'keyId'>, key: TokenKey): string {
  const { organizationId, messageId, receivedAtMs, urlSeq, expiresAt } = claims;
  if (organizationId <= 0n || organizationId > MAX_UINT64)
    throw new Error('organizationId out of range');
  if (messageId <= 0n || messageId > MAX_UINT64) throw new Error('messageId out of range');
  if (!Number.isSafeInteger(receivedAtMs) || receivedAtMs < 0 || receivedAtMs > MAX_UINT48) {
    throw new Error('receivedAtMs out of range');
  }
  if (!Number.isInteger(urlSeq) || urlSeq < 0 || urlSeq > 0xffff)
    throw new Error('urlSeq out of range');
  if (!Number.isInteger(expiresAt) || expiresAt < 1 || expiresAt > 0xffffffff)
    throw new Error('expiresAt out of range');
  if (!Number.isInteger(key.id) || key.id < 1 || key.id > 255)
    throw new Error('key id out of range');
  const buffer = Buffer.alloc(TOKEN_BYTES);
  buffer.writeUInt8(TOKEN_VERSION, 0);
  buffer.writeUInt8(key.id, 1);
  buffer.writeBigUInt64BE(organizationId, 2);
  buffer.writeBigUInt64BE(messageId, 10);
  buffer.writeUIntBE(receivedAtMs, 18, 6);
  buffer.writeUInt16BE(urlSeq, 24);
  buffer.writeUInt32BE(expiresAt, 26);
  mac(key.key, buffer.subarray(0, CLAIM_BYTES)).copy(buffer, CLAIM_BYTES);
  return buffer.toString('base64url');
}

export type TokenOutcome =
  'malformed' | 'bad_version' | 'unknown_kid' | 'bad_mac' | 'expired' | 'ok';

export type TokenVerification =
  | { outcome: 'malformed' | 'bad_version' | 'unknown_kid' | 'bad_mac' }
  | { outcome: 'expired' | 'ok'; claims: TokenClaims };

/**
 * Verification order (U12): length 62 and alphabet → decode → version → known key id →
 * constant-time MAC → expiry (`expired` carries the claims: the MAC was valid) → id ranges.
 */
export function verifyToken(
  token: string,
  keys: TokenKeys,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): TokenVerification {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) return { outcome: 'malformed' };
  const buffer = Buffer.from(token, 'base64url');
  // Canonical encoding only (the last character's unused bits must be zero).
  if (buffer.length !== TOKEN_BYTES || buffer.toString('base64url') !== token)
    return { outcome: 'malformed' };
  if (buffer.readUInt8(0) !== TOKEN_VERSION) return { outcome: 'bad_version' };
  const keyId = buffer.readUInt8(1);
  const key =
    keys.current.id === keyId
      ? keys.current
      : keys.previous && keys.previous.id === keyId
        ? keys.previous
        : null;
  if (key === null) return { outcome: 'unknown_kid' };
  const expected = mac(key.key, buffer.subarray(0, CLAIM_BYTES));
  if (!timingSafeEqual(expected, buffer.subarray(CLAIM_BYTES))) return { outcome: 'bad_mac' };
  const claims: TokenClaims = {
    keyId,
    organizationId: buffer.readBigUInt64BE(2),
    messageId: buffer.readBigUInt64BE(10),
    receivedAtMs: buffer.readUIntBE(18, 6),
    urlSeq: buffer.readUInt16BE(24),
    expiresAt: buffer.readUInt32BE(26),
  };
  if (nowSeconds >= claims.expiresAt) return { outcome: 'expired', claims };
  if (claims.organizationId === 0n || claims.messageId === 0n) return { outcome: 'malformed' };
  return { outcome: 'ok', claims };
}

/** Expiry (epoch seconds) of a token signed at `scanTime` for `expiryDays` (1..max). */
export function tokenExpiry(scanTime: Date, expiryDays: number, maxExpiryDays: number): number {
  if (!Number.isInteger(expiryDays) || expiryDays < 1 || expiryDays > maxExpiryDays) {
    throw new Error(`expiryDays must be 1..${maxExpiryDays}`);
  }
  return Math.floor(scanTime.getTime() / 1000) + expiryDays * 86_400;
}

// --- continue nonce (warn page) --------------------------------------------------------------

function continueKey(key: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), CONTINUE_INFO, 32));
}

export const windowStart = (nowSeconds: number, ttlSeconds: number): number =>
  Math.floor(nowSeconds / ttlSeconds) * ttlSeconds;

function nonceFor(key: Buffer, token: string, start: number): string {
  const window = Buffer.alloc(8);
  window.writeBigUInt64BE(BigInt(start));
  return createHmac('sha256', continueKey(key))
    .update(Buffer.from(token, 'latin1'))
    .update(window)
    .digest()
    .subarray(0, 16)
    .toString('base64url');
}

/**
 * `HMAC-SHA256(HKDF(currentKey, "eg-url-continue/v1"), token ‖ windowStart)`, first 16 bytes,
 * base64url; windows of CLICK_CONTINUE_TTL_SECONDS.
 */
export function continueNonce(
  token: string,
  currentKey: TokenKey,
  nowSeconds: number,
  ttlSeconds: number,
): string {
  return nonceFor(currentKey.key, token, windowStart(nowSeconds, ttlSeconds));
}

/** Valid for the current and the previous window (constant-time compare). */
export function verifyContinueNonce(
  token: string,
  nonce: string,
  currentKey: TokenKey,
  nowSeconds: number,
  ttlSeconds: number,
): boolean {
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(nonce)) return false;
  const given = Buffer.from(nonce, 'utf8');
  const start = windowStart(nowSeconds, ttlSeconds);
  let ok = false;
  for (const window of [start, start - ttlSeconds]) {
    const expected = Buffer.from(nonceFor(currentKey.key, token, window), 'utf8');
    if (expected.length === given.length && timingSafeEqual(expected, given)) ok = true;
  }
  return ok;
}
