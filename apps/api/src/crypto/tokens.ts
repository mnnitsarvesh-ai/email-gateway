import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';

/** `egr_`: refresh tokens. `egt_`: single-use tokens (invitation, reset, verification, MFA). */
export type OpaqueTokenPrefix = 'egr' | 'egt';

const TOKEN_BYTES = 32;
/** 32 bytes in unpadded base64url. */
const TOKEN_BODY = '[A-Za-z0-9_-]{43}';
const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const API_KEY_PATTERN = new RegExp(`^(egk_[0-9A-Za-z]{12})_${TOKEN_BODY}$`);
/** RFC 4648 base32 alphabet, lower-case, for recovery codes. */
const RECOVERY_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const RECOVERY_CODE_PATTERN = /^[a-z2-7]{10}$/;

/** `<prefix>_` + 32 random bytes (base64url). */
export function generateOpaqueToken(prefix: OpaqueTokenPrefix): string {
  return `${prefix}_${randomBytes(TOKEN_BYTES).toString('base64url')}`;
}

/** Strict format check before any lookup, so junk never reaches the database. */
export function isOpaqueToken(value: unknown, prefix: OpaqueTokenPrefix): value is string {
  return typeof value === 'string' && new RegExp(`^${prefix}_${TOKEN_BODY}$`).test(value);
}

/** Lookup hash of high-entropy tokens (refresh, single-use). */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Constant-time comparison of two hex digests; false for different lengths or non-hex input. */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(a + b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export type TokenHasherConfig = Pick<ApiConfig, 'AUTH_TOKEN_PEPPER'>;

/**
 * HMAC-SHA256 with the server-side pepper (AUTH_TOKEN_PEPPER) for API keys and recovery codes:
 * a database dump alone is not enough to test guesses offline.
 */
@Injectable()
export class TokenHasher {
  private readonly pepper: Buffer;

  constructor(@Inject(API_CONFIG) config: TokenHasherConfig) {
    this.pepper = Buffer.from(config.AUTH_TOKEN_PEPPER, 'utf8');
  }

  hmacHex(value: string): string {
    return createHmac('sha256', this.pepper).update(value, 'utf8').digest('hex');
  }
}

export interface GeneratedApiKey {
  /** The full key, shown to the creator once: `egk_<12 base62>_<secret>`. */
  key: string;
  /** `egk_` + 12 base62 characters (16 characters): unique lookup handle, safe to display. */
  prefix: string;
}

export function generateApiKey(): GeneratedApiKey {
  let handle = '';
  for (let i = 0; i < 12; i += 1) handle += BASE62[randomInt(BASE62.length)];
  const prefix = `egk_${handle}`;
  return { key: `${prefix}_${randomBytes(TOKEN_BYTES).toString('base64url')}`, prefix };
}

/** Returns the lookup prefix of a well-formed API key, or null. */
export function parseApiKey(key: unknown): { prefix: string } | null {
  if (typeof key !== 'string') return null;
  const match = API_KEY_PATTERN.exec(key);
  return match?.[1] ? { prefix: match[1] } : null;
}

function recoveryCode(): string {
  let raw = '';
  for (let i = 0; i < 10; i += 1) raw += RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)];
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

/** `n` distinct codes `xxxxx-xxxxx` (base32, 50 bits each), shown to the user once. */
export function generateRecoveryCodes(n = 10): string[] {
  const codes = new Set<string>();
  while (codes.size < n) codes.add(recoveryCode());
  return [...codes];
}

/**
 * Canonical form of user input (`ABCDE FGHIJ`, `abcdefghij`, `abcde-fghij`) → `abcde-fghij`, or
 * null when it cannot be a recovery code. Hash the canonical form.
 */
export function normalizeRecoveryCode(input: unknown): string | null {
  if (typeof input !== 'string' || input.length > 32) return null;
  const compact = input.toLowerCase().replace(/[\s-]/g, '');
  if (!RECOVERY_CODE_PATTERN.test(compact)) return null;
  return `${compact.slice(0, 5)}-${compact.slice(5)}`;
}
