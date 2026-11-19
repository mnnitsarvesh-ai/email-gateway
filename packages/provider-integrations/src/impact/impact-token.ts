import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Impact tokens (D13, ADR-0080): base64url(HMAC-SHA256(`PROVIDER_IMPACT_TOKEN_KEY`, canonical
 * JSON of `{ orgId, connectionId, rowVersion, changeSet, userId, expiresAt }`)). The api returns
 * the token with a preview; the apply recomputes the change set and the body, and the token
 * verifies only when nothing changed, for the same user and organization, before expiry.
 */
export interface ImpactTokenBody {
  /** Organization id (decimal string or bigint). */
  orgId: string | bigint;
  /** Connection public id. */
  connectionId: string;
  /** The connection's `row_version` at preview time. */
  rowVersion: number;
  /** The concrete change set (any JSON value; canonicalized). */
  changeSet: unknown;
  /** The previewing user's public id. */
  userId: string;
  /** ISO 8601 instant (or Date). */
  expiresAt: string | Date;
}

const MIN_KEY_BYTES = 32;

export class ImpactTokenKeyError extends Error {
  override readonly name = 'ImpactTokenKeyError';
  constructor() {
    super('PROVIDER_IMPACT_TOKEN_KEY must be at least 32 bytes (64 hex characters)');
  }
}

/** The key from its configuration value (64 hex characters). */
export function impactTokenKey(hex: string): Buffer {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64,}$/.test(hex) || hex.length % 2 !== 0) {
    throw new ImpactTokenKeyError();
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Canonical JSON: object keys sorted (code-point order) at every depth, `undefined` members
 * dropped, `bigint` as decimal strings, `Date` as ISO strings, non-finite numbers refused.
 */
export function canonicalJson(value: unknown): string {
  const walk = (v: unknown): unknown => {
    if (v === null) return null;
    if (typeof v === 'bigint') return v.toString();
    if (v instanceof Date) return v.toISOString();
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new TypeError('canonicalJson: non-finite number');
      return v;
    }
    if (typeof v === 'string' || typeof v === 'boolean') return v;
    if (Array.isArray(v)) return v.map((item) => (item === undefined ? null : walk(item)));
    if (typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(v).sort()) {
        const member = (v as Record<string, unknown>)[key];
        if (member !== undefined && typeof member !== 'function') out[key] = walk(member);
      }
      return out;
    }
    throw new TypeError(`canonicalJson: unsupported ${typeof v}`);
  };
  return JSON.stringify(walk(value));
}

function bodyOf(body: ImpactTokenBody): string {
  return canonicalJson({
    orgId: String(body.orgId),
    connectionId: body.connectionId,
    rowVersion: body.rowVersion,
    changeSet: body.changeSet,
    userId: body.userId,
    expiresAt: body.expiresAt instanceof Date ? body.expiresAt.toISOString() : body.expiresAt,
  });
}

export function signImpactToken(key: Buffer, body: ImpactTokenBody): string {
  if (key.length < MIN_KEY_BYTES) throw new ImpactTokenKeyError();
  return createHmac('sha256', key).update(bodyOf(body), 'utf8').digest('base64url');
}

/**
 * True only when `token` is the HMAC of `body` (constant-time comparison) and `now` is before
 * `body.expiresAt`. Malformed tokens are false, never an exception.
 */
export function verifyImpactToken(
  key: Buffer,
  token: string,
  body: ImpactTokenBody,
  now: Date,
): boolean {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return false;
  const expires =
    body.expiresAt instanceof Date ? body.expiresAt.getTime() : Date.parse(body.expiresAt);
  if (!Number.isFinite(expires) || now.getTime() >= expires) return false;
  let expected: Buffer;
  try {
    expected = Buffer.from(signImpactToken(key, body), 'base64url');
  } catch {
    return false;
  }
  const given = Buffer.from(token, 'base64url');
  return given.length === expected.length && timingSafeEqual(given, expected);
}
