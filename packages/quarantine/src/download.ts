import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { QUARANTINE_DOWNLOAD_OBJECTS } from './vocabulary';

/**
 * The download door (step 5.3 Q12, ADR-0048): the single-use grant token and the malware gating.
 *
 * Token `qdl1.<b64url(payload)>.<b64url(mac)>`; payload `{ v: 1, jti, org, usr, ent, obj, part,
 * exp }` serialized as JSON with this exact key order; `mac = HMAC-SHA256(key,
 * "eg-quarantine-download/v1\0" ‖ payload bytes)`. Verification decodes strictly, compares the
 * MAC in constant time **before** parsing the payload, then checks the payload schema and the
 * expiry against an injected `now`. Single use is enforced by the api (atomic consume of the
 * `quarantine_download_grants` row); the token only proves what was granted.
 */

export const DOWNLOAD_TOKEN_PREFIX = 'qdl1';
export const DOWNLOAD_TOKEN_DOMAIN = 'eg-quarantine-download/v1\0';
/** Platform default and bounds of `QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS`. */
export const QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS = 60;
export const DOWNLOAD_TOKEN_TTL_BOUNDS = Object.freeze({ min: 10, max: 300 });
/** Tokens are short; anything longer is refused before any work. */
export const DOWNLOAD_TOKEN_MAX_LENGTH = 1024;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Ids: public UUIDs or decimal internal ids. */
const ID = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9]{1,20})$/;

export const downloadTokenPayloadSchema = z
  .strictObject({
    v: z.literal(1),
    jti: z.string().regex(UUID),
    org: z.string().regex(ID),
    usr: z.string().regex(ID),
    ent: z.string().regex(ID),
    obj: z.enum(QUARANTINE_DOWNLOAD_OBJECTS),
    part: z.number().int().min(0).max(65_535).nullable(),
    /** Expiry, seconds since the epoch. */
    exp: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  })
  .refine((p) => (p.obj === 'attachment') === (p.part !== null), {
    message: 'part is required for an attachment and null for the eml',
  });
export type DownloadTokenPayload = z.infer<typeof downloadTokenPayloadSchema>;

const b64url = (b: Buffer): string => b.toString('base64url');
const B64URL = /^[A-Za-z0-9_-]+$/;

function keyBytes(key: Buffer | string): Buffer {
  const k =
    typeof key === 'string' ? Buffer.from(key, /^[0-9a-fA-F]+$/.test(key) ? 'hex' : 'utf8') : key;
  if (k.length < 32) throw new RangeError('download token key must be at least 32 bytes');
  return k;
}

function mac(key: Buffer, payload: Buffer): Buffer {
  return createHmac('sha256', key).update(DOWNLOAD_TOKEN_DOMAIN, 'utf8').update(payload).digest();
}

/** Canonical payload bytes (fixed key order). */
function payloadBytes(p: DownloadTokenPayload): Buffer {
  return Buffer.from(
    JSON.stringify({
      v: p.v,
      jti: p.jti,
      org: p.org,
      usr: p.usr,
      ent: p.ent,
      obj: p.obj,
      part: p.part,
      exp: p.exp,
    }),
    'utf8',
  );
}

/** Signs a grant (the payload is validated first). `key`: Buffer or hex (≥ 32 bytes). */
export function signDownloadToken(payload: DownloadTokenPayload, key: Buffer | string): string {
  const p = downloadTokenPayloadSchema.parse(payload);
  const bytes = payloadBytes(p);
  return `${DOWNLOAD_TOKEN_PREFIX}.${b64url(bytes)}.${b64url(mac(keyBytes(key), bytes))}`;
}

export type DownloadTokenVerification =
  | { ok: true; payload: DownloadTokenPayload }
  | { ok: false; reason: 'malformed' | 'bad_mac' | 'payload_invalid' | 'expired' | 'binding' };

/**
 * Verifies a token: shape, MAC (constant time), payload schema, expiry (`exp > now`), and the
 * binding to the caller's organization and user when `expected` is given.
 */
export function verifyDownloadToken(
  token: string,
  key: Buffer | string,
  options: { now: Date; expected?: { org?: string; usr?: string; ent?: string } },
): DownloadTokenVerification {
  const k = keyBytes(key);
  if (typeof token !== 'string' || token.length > DOWNLOAD_TOKEN_MAX_LENGTH) {
    return { ok: false, reason: 'malformed' };
  }
  const parts = token.split('.');
  if (
    parts.length !== 3 ||
    parts[0] !== DOWNLOAD_TOKEN_PREFIX ||
    !B64URL.test(parts[1]!) ||
    !B64URL.test(parts[2]!)
  ) {
    return { ok: false, reason: 'malformed' };
  }
  const bytes = Buffer.from(parts[1]!, 'base64url');
  const given = Buffer.from(parts[2]!, 'base64url');
  // Canonical base64url only (no alternative encodings of the same bytes).
  if (b64url(bytes) !== parts[1] || b64url(given) !== parts[2]) {
    return { ok: false, reason: 'malformed' };
  }
  const expected = mac(k, bytes);
  let same = false;
  if (given.length === expected.length) {
    same = timingSafeEqual(given, expected);
  } else {
    // Same work for a wrong-length MAC (no early exit on length).
    timingSafeEqual(expected, expected);
  }
  if (!same) return { ok: false, reason: 'bad_mac' };
  let json: unknown;
  try {
    json = JSON.parse(bytes.toString('utf8'));
  } catch {
    return { ok: false, reason: 'payload_invalid' };
  }
  const parsed = downloadTokenPayloadSchema.safeParse(json);
  if (!parsed.success) return { ok: false, reason: 'payload_invalid' };
  const p = parsed.data;
  if (p.exp * 1000 <= options.now.getTime()) return { ok: false, reason: 'expired' };
  const e = options.expected;
  if (
    e !== undefined &&
    ((e.org !== undefined && e.org !== p.org) ||
      (e.usr !== undefined && e.usr !== p.usr) ||
      (e.ent !== undefined && e.ent !== p.ent))
  ) {
    return { ok: false, reason: 'binding' };
  }
  return { ok: true, payload: p };
}

// ---------------------------------------------------------------------------------------------
// Malware gating (Q12.4)
// ---------------------------------------------------------------------------------------------

export interface DownloadableFacts {
  object: 'eml' | 'attachment';
  /** Required for `attachment`. */
  partIndex?: number | null;
  /** Hard blocks of the entry and of the message (any round's evaluation of the message). */
  entryHardBlocks: readonly string[];
  messageHardBlocks: readonly string[];
  /** The latest round's risk verdict (`MessageVerdict`), null when unknown. */
  latestVerdict: string | null;
  /** Latest-round attachment facts (verdict `clean`, `suspicious`, `malicious`, `error`, `skipped` …). */
  attachments: ReadonlyArray<{
    partIndex: number;
    verdict: string | null;
    objectKey: string | null;
  }>;
  /** Latest-round URL verdicts. */
  urls: ReadonlyArray<{ verdict: string | null }>;
}

export type DownloadBlockReason =
  | 'hard_block'
  | 'malware_verdict'
  | 'phishing_verdict'
  | 'attachment_missing'
  | 'attachment_not_clean'
  | 'attachment_object_missing'
  | 'url_malicious';

export type DownloadableCheck =
  { ok: true } | { ok: false; code: 'quarantine_download_blocked'; reason: DownloadBlockReason };

/**
 * Q12.4: refused when the entry or the message has a hard block, the latest verdict is malware
 * or phishing; for an attachment, its latest verdict is not `clean` (anything else, including a
 * missing row, refuses) or its object is gone; for the EML, any attachment not `clean` or any
 * URL `malicious`. No defanged archive in 5.3.
 */
export function checkDownloadable(facts: DownloadableFacts): DownloadableCheck {
  const block = (reason: DownloadBlockReason) =>
    ({ ok: false, code: 'quarantine_download_blocked', reason }) as const;
  if (facts.entryHardBlocks.length > 0 || facts.messageHardBlocks.length > 0) {
    return block('hard_block');
  }
  if (facts.latestVerdict === 'malware') return block('malware_verdict');
  if (facts.latestVerdict === 'phishing') return block('phishing_verdict');
  if (facts.object === 'attachment') {
    const a = facts.attachments.find((x) => x.partIndex === facts.partIndex);
    if (a === undefined || facts.partIndex === null || facts.partIndex === undefined) {
      return block('attachment_missing');
    }
    if (a.verdict !== 'clean') return block('attachment_not_clean');
    if (a.objectKey === null || a.objectKey === '') return block('attachment_object_missing');
    return { ok: true };
  }
  if (facts.attachments.some((a) => a.verdict !== 'clean')) return block('attachment_not_clean');
  if (facts.urls.some((u) => u.verdict === 'malicious')) return block('url_malicious');
  return { ok: true };
}
