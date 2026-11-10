import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { base64UrlPart, gcmDecrypt, gcmEncrypt, IV_BYTES, TAG_BYTES } from './envelope/aes-gcm';
import { SandboxEnvelopeError } from './envelope/errors';
import { parseSymmetricKey } from './keys';

/**
 * Result authentication of `mail.sandbox.task_completed.v1` (step 4.6 X11, ADR-0040 decision
 * 3–4): a **one-time result token per task** plus a MAC over the **whole result**.
 *
 * - The dispatcher draws a fresh 32-byte token `T` per task, stores only `SHA-256(T)` on the
 *   analysis (`sandbox_analyses.result_token_sha256`) and puts `T` into the task **sealed**
 *   (`resultToken = "t1.<iv>.<tag>.<ct>"`, AES-256-GCM under the token-seal subkey, AAD
 *   `eg-sandbox-result-token/v1\0<taskId>`). The task reaches the analytics firehose; the sealed
 *   token is useless there without `SANDBOX_RESULT_KEY`.
 * - The controller opens the token of each task it receives and answers with
 *
 *       resultMac = hex(HMAC-SHA256(macSubkey,
 *                     "eg-sandbox-result/v2\0" ‖ SHA-256(T) ‖ "\0" ‖ organizationId ‖ "\0"
 *                     ‖ canonicalJson(payload without resultMac)))
 *
 *   so every field of the result (status, codes, backend, isolation, executed, observations,
 *   findings, artifacts and their wrapped keys, timings, cleanup) and the envelope organization
 *   are authenticated. A copied MAC does not fit a modified body.
 * - The results consumer recomputes it with the stored hash of the analysis named by the
 *   result, timing-safe; a mismatch (or an analysis without a token) is `bad_mac`.
 *
 * Subkeys are derived from `SANDBOX_RESULT_KEY` with HKDF-SHA256 (distinct `info` per use), so
 * the seal and the MAC never share a key. Forging a result needs `SANDBOX_RESULT_KEY` **and** the
 * sealed task (delivered only to the controller through `scan.sandbox`) or the stored token hash
 * (MySQL): a compromised key alone does not let anyone answer for tasks they never received.
 */

const TOKEN_BYTES = 32;
const TOKEN_VERSION = 't1';
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAC_HEX = SHA256_HEX;
const TASK_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ORGANIZATION_ID = /^[1-9][0-9]{0,19}$/;
/** `t1.<iv 16>.<tag 22>.<ct 43>` (base64url). */
export const SEALED_RESULT_TOKEN_PATTERN =
  /^t1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;

type Subkey = 'seal' | 'mac';
function subkey(key: Buffer | string, use: Subkey): Buffer {
  const k = parseSymmetricKey('SANDBOX_RESULT_KEY', key);
  try {
    return Buffer.from(
      hkdfSync('sha256', k, Buffer.alloc(0), `eg-sandbox-result/v2 ${use}`, TOKEN_BYTES),
    );
  } finally {
    k.fill(0);
  }
}

const tokenAad = (taskId: string): string => {
  if (!TASK_ID.test(taskId)) throw new SandboxEnvelopeError('malformed');
  return `eg-sandbox-result-token/v1\0${taskId}`;
};

const sha256Hex = (value: Buffer): string => createHash('sha256').update(value).digest('hex');

export interface SealedResultToken {
  /** The `resultToken` of the task (`t1.<iv>.<tag>.<ct>`). */
  sealed: string;
  /** Lower-case hex SHA-256 of the token: the only form the email-worker stores. */
  tokenSha256: string;
}

/** Draws a fresh one-time result token for `taskId` and seals it (dispatcher). */
export function sealResultToken(resultKey: Buffer | string, taskId: string): SealedResultToken {
  const aad = tokenAad(taskId);
  const key = subkey(resultKey, 'seal');
  const token = randomBytes(TOKEN_BYTES);
  try {
    const box = gcmEncrypt(key, token, aad);
    return {
      sealed: [
        TOKEN_VERSION,
        box.iv.toString('base64url'),
        box.tag.toString('base64url'),
        box.ciphertext.toString('base64url'),
      ].join('.'),
      tokenSha256: sha256Hex(token),
    };
  } finally {
    token.fill(0);
    key.fill(0);
  }
}

/**
 * Opens the sealed token of a task (controller) and returns its SHA-256 (hex). Throws
 * `SandboxEnvelopeError` (`malformed`, `unauthentic`) for another task id, key or tampering.
 */
export function openResultToken(
  resultKey: Buffer | string,
  taskId: string,
  sealed: string,
): string {
  const aad = tokenAad(taskId);
  if (typeof sealed !== 'string' || !SEALED_RESULT_TOKEN_PATTERN.test(sealed)) {
    throw new SandboxEnvelopeError('malformed');
  }
  const [, ivPart, tagPart, ctPart] = sealed.split('.');
  const iv = base64UrlPart(ivPart);
  const tag = base64UrlPart(tagPart);
  const ct = base64UrlPart(ctPart);
  if (!iv || !tag || !ct || iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new SandboxEnvelopeError('malformed');
  }
  if (ct.length !== TOKEN_BYTES) throw new SandboxEnvelopeError('malformed');
  const key = subkey(resultKey, 'seal');
  const token = gcmDecrypt(key, iv, tag, ct, aad);
  key.fill(0);
  if (!token) throw new SandboxEnvelopeError('unauthentic');
  try {
    return sha256Hex(token);
  } finally {
    token.fill(0);
  }
}

/**
 * Deterministic JSON (keys sorted by code unit at every level, no whitespace; `undefined`
 * members omitted as JSON.stringify does). Refuses non-finite numbers, bigints, functions and
 * other non-JSON values.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new Error('Invalid result MAC input');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',')}]`;
      }
      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null) throw new Error('Invalid result MAC input');
      const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
    }
    default:
      throw new Error('Invalid result MAC input');
  }
}

export interface ResultMacInput {
  /** The envelope organization of the task (and so of the result). */
  organizationId: string;
  /** SHA-256 (hex) of the task's one-time result token. */
  tokenSha256: string;
  /** The `task_completed.v1` payload; a `resultMac` member is ignored. */
  payload: Readonly<Record<string, unknown>>;
}

const message = (input: ResultMacInput): string => {
  if (
    typeof input.organizationId !== 'string' ||
    !ORGANIZATION_ID.test(input.organizationId) ||
    typeof input.tokenSha256 !== 'string' ||
    !SHA256_HEX.test(input.tokenSha256) ||
    input.payload === null ||
    typeof input.payload !== 'object' ||
    Array.isArray(input.payload)
  ) {
    throw new Error('Invalid result MAC input');
  }
  const { resultMac: _ignored, ...body } = input.payload as Record<string, unknown>;
  return `eg-sandbox-result/v2\0${input.tokenSha256}\0${input.organizationId}\0${canonicalJson(body)}`;
};

/** The hex result MAC of a task result. `key`: `SANDBOX_RESULT_KEY` (64 hex or 32 bytes). */
export function resultMac(key: Buffer | string, input: ResultMacInput): string {
  const text = message(input);
  const k = subkey(key, 'mac');
  try {
    return createHmac('sha256', k).update(text, 'utf8').digest('hex');
  } finally {
    k.fill(0);
  }
}

/**
 * Timing-safe verification; false for a malformed MAC or input (never throws for those). A
 * malformed `SANDBOX_RESULT_KEY` throws `SandboxKeyError` (a configuration defect).
 */
export function verifyResultMac(key: Buffer | string, input: ResultMacInput, mac: string): boolean {
  if (typeof mac !== 'string' || !MAC_HEX.test(mac)) return false;
  let expected: string;
  try {
    expected = resultMac(key, input);
  } catch (error) {
    if (error instanceof Error && error.message === 'Invalid result MAC input') return false;
    throw error;
  }
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(mac, 'hex'));
}
