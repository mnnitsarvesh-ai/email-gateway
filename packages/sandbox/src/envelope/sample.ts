import { createHash, randomBytes } from 'node:crypto';
import { SANDBOX_SAMPLE_ALGORITHM } from '@email-gateway/security-contracts';
import { parseOptionalSymmetricKey, parseSymmetricKey } from '../keys';
import {
  base64UrlPart,
  DATA_KEY_BYTES,
  gcmDecrypt,
  gcmEncrypt,
  IV_BYTES,
  TAG_BYTES,
} from './aes-gcm';
import { SandboxEnvelopeError } from './errors';

/**
 * `sandbox-sample/1` (step 4.6 X12): the sealed sample the email-worker stages in the sandbox
 * bucket and the controller opens.
 *
 *     object = "EGSBXS1" ‖ u16be header length ‖ header JSON { v: 1, kid, wrappedKey }
 *              ‖ IV (12) ‖ tag (16) ‖ ciphertext
 *
 * - payload: AES-256-GCM under a fresh 32-byte data key, AAD
 *   `eg-sandbox-sample/v1\0<taskId>\0<sha256>` (the plaintext SHA-256, lower-case hex);
 * - `wrappedKey`: the data key wrapped AES-256-GCM under `SANDBOX_SAMPLE_KEY` (kid `k1`) with
 *   AAD + `\0dek`, in the SecretBox format `v1.<kid>.<iv>.<tag>.<ct>` (base64url);
 *   `SANDBOX_SAMPLE_KEY_PREVIOUS` opens during a rotation.
 *
 * The wrapped key travels in the object header (the controller has no database); confidentiality
 * rests on `SANDBOX_SAMPLE_KEY`, held only by the email-worker and the controller. Opening checks
 * the plaintext SHA-256 against the expected hash. Errors carry no detail.
 */

export const SANDBOX_SAMPLE_MAGIC = Buffer.from('EGSBXS1', 'ascii');
export const SANDBOX_SAMPLE_KEY_ID = 'k1';
const VERSION = 'v1';
/** Upper bound of the header JSON (it holds `v`, `kid` and a ~100-character wrapped key). */
const MAX_HEADER_BYTES = 1024;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const TASK_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface SampleKek {
  /** `SANDBOX_SAMPLE_KEY`: 32 bytes or 64 hex characters. */
  current: Buffer | string;
  /** `SANDBOX_SAMPLE_KEY_PREVIOUS` (rotation), optional. */
  previous?: Buffer | string | null;
}

export interface SampleIds {
  /** The task id (`sandbox_analyses.public_id`, UUIDv7). */
  taskId: string;
  /** Lower-case hex SHA-256 of the plaintext sample. */
  sha256: string;
}

export interface SealedSample {
  /** The S3 object body. */
  object: Buffer;
  /** Hex SHA-256 and size of the object body. */
  objectSha256: string;
  size: number;
  keyId: string;
  algorithm: typeof SANDBOX_SAMPLE_ALGORITHM;
}

export interface OpenedSample {
  plaintext: Buffer;
  /** Only `SANDBOX_SAMPLE_KEY_PREVIOUS` could unwrap the data key. */
  usedPreviousKey: boolean;
}

/** The payload AAD (X12). */
export function sampleAad(ids: SampleIds): string {
  if (!TASK_ID.test(ids.taskId) || !SHA256_HEX.test(ids.sha256)) {
    throw new SandboxEnvelopeError('malformed');
  }
  return `eg-sandbox-sample/v1\0${ids.taskId}\0${ids.sha256}`;
}

const sha256Hex = (value: Buffer): string => createHash('sha256').update(value).digest('hex');

/**
 * Seals a sample for one task. Refuses a plaintext whose SHA-256 differs from `ids.sha256` (the
 * staging integrity check, `sample_integrity`).
 */
export function sealSample(kek: SampleKek, plaintext: Buffer, ids: SampleIds): SealedSample {
  const wrapKey = parseSymmetricKey('SANDBOX_SAMPLE_KEY', kek.current);
  const aad = sampleAad(ids);
  if (sha256Hex(plaintext) !== ids.sha256) throw new SandboxEnvelopeError('integrity');
  const dataKey = randomBytes(DATA_KEY_BYTES);
  try {
    const body = gcmEncrypt(dataKey, plaintext, aad);
    const wrapped = gcmEncrypt(wrapKey, dataKey, `${aad}\0dek`);
    const wrappedKey = [
      VERSION,
      SANDBOX_SAMPLE_KEY_ID,
      wrapped.iv.toString('base64url'),
      wrapped.tag.toString('base64url'),
      wrapped.ciphertext.toString('base64url'),
    ].join('.');
    const header = Buffer.from(
      JSON.stringify({ v: 1, kid: SANDBOX_SAMPLE_KEY_ID, wrappedKey }),
      'utf8',
    );
    const length = Buffer.alloc(2);
    length.writeUInt16BE(header.length);
    const object = Buffer.concat([
      SANDBOX_SAMPLE_MAGIC,
      length,
      header,
      body.iv,
      body.tag,
      body.ciphertext,
    ]);
    return {
      object,
      objectSha256: sha256Hex(object),
      size: object.length,
      keyId: SANDBOX_SAMPLE_KEY_ID,
      algorithm: SANDBOX_SAMPLE_ALGORITHM,
    };
  } finally {
    dataKey.fill(0);
    wrapKey.fill(0);
  }
}

interface ParsedSample {
  wrapIv: Buffer;
  wrapTag: Buffer;
  wrapCt: Buffer;
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

function parseSampleObject(object: Buffer): ParsedSample {
  const magic = SANDBOX_SAMPLE_MAGIC.length;
  if (!Buffer.isBuffer(object) || object.length < magic + 2) {
    throw new SandboxEnvelopeError('malformed');
  }
  if (!object.subarray(0, magic).equals(SANDBOX_SAMPLE_MAGIC)) {
    throw new SandboxEnvelopeError('malformed');
  }
  const headerLength = object.readUInt16BE(magic);
  const headerStart = magic + 2;
  const bodyStart = headerStart + headerLength;
  if (headerLength === 0 || headerLength > MAX_HEADER_BYTES) {
    throw new SandboxEnvelopeError('malformed');
  }
  if (object.length < bodyStart + IV_BYTES + TAG_BYTES) throw new SandboxEnvelopeError('malformed');
  let header: unknown;
  try {
    header = JSON.parse(object.subarray(headerStart, bodyStart).toString('utf8'));
  } catch {
    throw new SandboxEnvelopeError('malformed');
  }
  if (
    header === null ||
    typeof header !== 'object' ||
    Array.isArray(header) ||
    Object.keys(header).sort().join(',') !== 'kid,v,wrappedKey'
  ) {
    throw new SandboxEnvelopeError('malformed');
  }
  const { v, kid, wrappedKey } = header as Record<string, unknown>;
  if (v !== 1 || typeof kid !== 'string' || typeof wrappedKey !== 'string') {
    throw new SandboxEnvelopeError('malformed');
  }
  const parts = wrappedKey.split('.');
  if (parts.length !== 5 || parts[0] !== VERSION || parts[1] !== kid || !/^k[0-9]+$/.test(kid)) {
    throw new SandboxEnvelopeError('malformed');
  }
  const wrapIv = base64UrlPart(parts[2]);
  const wrapTag = base64UrlPart(parts[3]);
  const wrapCt = base64UrlPart(parts[4]);
  if (
    !wrapIv ||
    !wrapTag ||
    !wrapCt ||
    wrapIv.length !== IV_BYTES ||
    wrapTag.length !== TAG_BYTES ||
    wrapCt.length !== DATA_KEY_BYTES
  ) {
    throw new SandboxEnvelopeError('malformed');
  }
  return {
    wrapIv,
    wrapTag,
    wrapCt,
    iv: object.subarray(bodyStart, bodyStart + IV_BYTES),
    tag: object.subarray(bodyStart + IV_BYTES, bodyStart + IV_BYTES + TAG_BYTES),
    ciphertext: object.subarray(bodyStart + IV_BYTES + TAG_BYTES),
  };
}

/**
 * Opens a sealed sample for the task `ids.taskId` with the expected plaintext hash `ids.sha256`.
 * Throws `SandboxEnvelopeError` (`malformed`, `unauthentic`, `integrity`).
 */
export function openSample(kek: SampleKek, object: Buffer, ids: SampleIds): OpenedSample {
  const current = parseSymmetricKey('SANDBOX_SAMPLE_KEY', kek.current);
  const previous = parseOptionalSymmetricKey('SANDBOX_SAMPLE_KEY_PREVIOUS', kek.previous, current);
  const aad = sampleAad(ids);
  const parsed = parseSampleObject(object);
  const dekAad = `${aad}\0dek`;
  let usedPreviousKey = false;
  let dataKey = gcmDecrypt(current, parsed.wrapIv, parsed.wrapTag, parsed.wrapCt, dekAad);
  if (!dataKey && previous) {
    dataKey = gcmDecrypt(previous, parsed.wrapIv, parsed.wrapTag, parsed.wrapCt, dekAad);
    usedPreviousKey = dataKey !== null;
  }
  current.fill(0);
  previous?.fill(0);
  if (!dataKey) throw new SandboxEnvelopeError('unauthentic');
  try {
    const plaintext = gcmDecrypt(dataKey, parsed.iv, parsed.tag, parsed.ciphertext, aad);
    if (!plaintext) throw new SandboxEnvelopeError('unauthentic');
    if (sha256Hex(plaintext) !== ids.sha256) throw new SandboxEnvelopeError('integrity');
    return { plaintext, usedPreviousKey };
  } finally {
    dataKey.fill(0);
  }
}
