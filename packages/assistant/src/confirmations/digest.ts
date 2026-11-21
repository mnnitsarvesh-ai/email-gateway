import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { HttpMethod } from '../registry/types';
import { canonicalJson, sha256Hex } from './canonical';
import { ACTION_DIGEST_VERSION, type ConfirmationRisk } from './types';

/**
 * The binding of a confirmation (step AI-2 D3, ADR-0093): the action digest over the stored
 * request, preconditions and identity, the state digest of the precondition read, and the
 * single-use token (32 random bytes, base64url; only its SHA-256 is stored).
 */

/** Per-item preconditions of an `each` spec (quarantine bulk). */
export interface DigestPreconditionItem {
  id: string;
  /** `stateDigest(readBody, stateFields)` of the item's read. */
  stateDigest: string;
}

export interface DigestPreconditions {
  stateDigest: string | null;
  rowVersion: number | null;
  definitionSha256: string | null;
  items?: DigestPreconditionItem[];
}

export interface DigestRequest {
  method: HttpMethod;
  /** Concrete, encoded path including the query string. */
  path: string;
  body: unknown;
}

/** Every member is stored on the confirmation row so the digest is recomputable (D3). */
export interface DigestInput {
  v: typeof ACTION_DIGEST_VERSION;
  confirmationId: string;
  organizationPublicId: string;
  userPublicId: string;
  sessionFamilyId: string;
  overrideId: string | null;
  conversationId: string;
  /** The proposal execution's public id. */
  executionId: string;
  tool: string;
  operationId: string;
  risk: ConfirmationRisk;
  requiresReauth: boolean;
  request: DigestRequest;
  preconditions: DigestPreconditions;
  /** ISO 8601 instant. */
  expiresAt: string;
}

/** SHA-256 hex of the canonical JSON of the digest input. */
export function actionDigest(input: DigestInput): string {
  if (input.v !== ACTION_DIGEST_VERSION) throw new TypeError('actionDigest: unsupported version');
  return sha256Hex(canonicalJson(input));
}

const HEX64 = /^[0-9a-f]{64}$/;

/** A lower-case SHA-256 hex digest (the confirm body's `actionDigest`). */
export function isDigestHex(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

/** The value at a dotted path (`sender.envelope`); `undefined` when any segment is missing. */
export function valueAtPath(value: unknown, path: string): unknown {
  let node: unknown = value;
  for (const segment of path.split('.')) {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) return undefined;
    if (!Object.prototype.hasOwnProperty.call(node, segment)) return undefined;
    node = (node as Record<string, unknown>)[segment];
  }
  return node;
}

/** The picked state fields of a read body: `{ <path>: value }`, a missing path is `null`. */
export function pickState(body: unknown, stateFields: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const path of stateFields) {
    const value = valueAtPath(body, path);
    out[path] = value === undefined ? null : value;
  }
  return out;
}

/** `sha256(canonicalJson(pick(readBody, stateFields)))` (D3). */
export function stateDigest(body: unknown, stateFields: readonly string[]): string {
  return sha256Hex(canonicalJson(pickState(body, stateFields)));
}

// ---------------------------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------------------------

export const CONFIRMATION_TOKEN_BYTES = 32;
const TOKEN_FORMAT = /^[A-Za-z0-9_-]{43}$/;

/** A new single-use token: 32 random bytes, base64url without padding (43 characters). */
export function newConfirmationToken(): string {
  return randomBytes(CONFIRMATION_TOKEN_BYTES).toString('base64url');
}

/** SHA-256 hex of the token (the only form that is stored). */
export function hashConfirmationToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * True when `token` has the token format and its SHA-256 equals `hash` (constant-time compare of
 * the digests). Never throws: any malformed input is simply false.
 */
export function tokenMatches(token: unknown, hash: unknown): boolean {
  try {
    if (typeof token !== 'string' || !TOKEN_FORMAT.test(token)) return false;
    if (typeof hash !== 'string' || !HEX64.test(hash)) return false;
    const actual = Buffer.from(hashConfirmationToken(token), 'hex');
    const expected = Buffer.from(hash, 'hex');
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}
