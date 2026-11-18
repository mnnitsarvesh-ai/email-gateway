import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { ArchiveKeyConfigError } from '../crypto/errors';
import { UUID_PATTERN } from '../ids';
import { ARCHIVE_DOWNLOAD_KINDS } from '../vocabulary';

/**
 * Archive download tokens (§4.2, A18, A19): `v1.<base64url payload>.<base64url HMAC-SHA256>`,
 * payload `{ jti, org, usr, kind, tgt, exp }` (public ids; `exp` in seconds since the epoch),
 * serialized as JSON in this exact key order. The MAC is HMAC-SHA256 under
 * `ARCHIVE_DOWNLOAD_TOKEN_KEY` (32 bytes, 64 hex) over the domain separator
 * `eg-archive-download/v1\0` followed by the payload bytes. Verification checks the shape, the
 * canonical encoding and the MAC in constant time **before** parsing the payload, then the
 * schema, the expiry against an injected clock and the expected binding. Single use is the
 * api's atomic consume of the `archive_download_grants` row.
 */

export const ARCHIVE_DOWNLOAD_TOKEN_PREFIX = 'v1';
export const ARCHIVE_DOWNLOAD_TOKEN_DOMAIN = 'eg-archive-download/v1\0';
export const ARCHIVE_DOWNLOAD_TOKEN_MAX_LENGTH = 1024;
/** Default and bounds of `ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS`. */
export const ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS = 60;
export const ARCHIVE_DOWNLOAD_TOKEN_TTL_BOUNDS = Object.freeze({ min: 10, max: 300 });

const ID = z.string().regex(UUID_PATTERN);

export const archiveDownloadTokenPayloadSchema = z.strictObject({
  jti: ID,
  org: ID,
  usr: ID,
  kind: z.enum(ARCHIVE_DOWNLOAD_KINDS),
  tgt: ID,
  exp: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
});
export type ArchiveDownloadTokenPayload = z.infer<typeof archiveDownloadTokenPayloadSchema>;

const B64URL = /^[A-Za-z0-9_-]+$/;

/** Parses `ARCHIVE_DOWNLOAD_TOKEN_KEY` (64 hex); the error names the key, never the value. */
export function parseDownloadTokenKey(
  value: string | Buffer | undefined,
  keyName = 'ARCHIVE_DOWNLOAD_TOKEN_KEY',
): Buffer {
  if (Buffer.isBuffer(value)) {
    if (value.length !== 32)
      throw new ArchiveKeyConfigError(keyName, '32 bytes (64 hex characters)');
    return Buffer.from(value);
  }
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new ArchiveKeyConfigError(keyName, '32 bytes (64 hex characters)');
  }
  return Buffer.from(value, 'hex');
}

function mac(key: Buffer, payload: Buffer): Buffer {
  return createHmac('sha256', key)
    .update(ARCHIVE_DOWNLOAD_TOKEN_DOMAIN, 'utf8')
    .update(payload)
    .digest();
}

function payloadBytes(p: ArchiveDownloadTokenPayload): Buffer {
  return Buffer.from(
    JSON.stringify({ jti: p.jti, org: p.org, usr: p.usr, kind: p.kind, tgt: p.tgt, exp: p.exp }),
    'utf8',
  );
}

/** Signs a grant token (payload validated first). */
export function signArchiveDownloadToken(
  payload: ArchiveDownloadTokenPayload,
  key: string | Buffer,
): string {
  const k = parseDownloadTokenKey(key);
  const p = archiveDownloadTokenPayloadSchema.parse(payload);
  const bytes = payloadBytes(p);
  return `${ARCHIVE_DOWNLOAD_TOKEN_PREFIX}.${bytes.toString('base64url')}.${mac(k, bytes).toString(
    'base64url',
  )}`;
}

export type ArchiveDownloadTokenVerification =
  | { ok: true; payload: ArchiveDownloadTokenPayload }
  | { ok: false; reason: 'malformed' | 'bad_mac' | 'payload_invalid' | 'expired' | 'binding' };

/** Verifies a token (see the module comment); `expected` binds organization, user, kind, target. */
export function verifyArchiveDownloadToken(
  token: string,
  key: string | Buffer,
  options: {
    now: Date;
    expected?: {
      org?: string;
      usr?: string;
      kind?: ArchiveDownloadTokenPayload['kind'];
      tgt?: string;
    };
  },
): ArchiveDownloadTokenVerification {
  const k = parseDownloadTokenKey(key);
  if (typeof token !== 'string' || token.length > ARCHIVE_DOWNLOAD_TOKEN_MAX_LENGTH) {
    return { ok: false, reason: 'malformed' };
  }
  const parts = token.split('.');
  if (
    parts.length !== 3 ||
    parts[0] !== ARCHIVE_DOWNLOAD_TOKEN_PREFIX ||
    !B64URL.test(parts[1]!) ||
    !B64URL.test(parts[2]!)
  ) {
    return { ok: false, reason: 'malformed' };
  }
  const bytes = Buffer.from(parts[1]!, 'base64url');
  const given = Buffer.from(parts[2]!, 'base64url');
  if (bytes.toString('base64url') !== parts[1] || given.toString('base64url') !== parts[2]) {
    return { ok: false, reason: 'malformed' };
  }
  const expected = mac(k, bytes);
  let same = false;
  if (given.length === expected.length) same = timingSafeEqual(given, expected);
  else timingSafeEqual(expected, expected);
  if (!same) return { ok: false, reason: 'bad_mac' };
  let json: unknown;
  try {
    json = JSON.parse(bytes.toString('utf8'));
  } catch {
    return { ok: false, reason: 'payload_invalid' };
  }
  const parsed = archiveDownloadTokenPayloadSchema.safeParse(json);
  if (!parsed.success) return { ok: false, reason: 'payload_invalid' };
  const p = parsed.data;
  if (p.exp * 1000 <= options.now.getTime()) return { ok: false, reason: 'expired' };
  const e = options.expected;
  if (
    e !== undefined &&
    ((e.org !== undefined && e.org !== p.org) ||
      (e.usr !== undefined && e.usr !== p.usr) ||
      (e.kind !== undefined && e.kind !== p.kind) ||
      (e.tgt !== undefined && e.tgt !== p.tgt))
  ) {
    return { ok: false, reason: 'binding' };
  }
  return { ok: true, payload: p };
}
