import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { DLP_EVIDENCE_ALGORITHM } from '@email-gateway/security-contracts';

/**
 * `dlp-evidence/1` envelope encryption (step 4.5 D16, ADR-0038), used by the worker to seal and
 * by the api to open:
 *
 * - a fresh 32-byte data key per evidence; payload AES-256-GCM with a 12-byte random IV and
 *   AAD `eg-dlp-evidence/v1\0<organizationId>\0<messageId>\0<scanId>`;
 * - object body = `EGDLP1` ‖ IV (12) ‖ tag (16) ‖ ciphertext;
 * - the data key wrapped with AES-256-GCM under the key-encryption key `DLP_EVIDENCE_KEY` with
 *   AAD = the same string + `\0dek`, serialized in the SecretBox format
 *   `v1.<kid>.<iv>.<tag>.<ct>` (base64url), kid `k1`; `DLP_EVIDENCE_KEY_PREVIOUS` opens during
 *   a rotation.
 *
 * The wrapped key exists only in the `dlp_evidence` row, so an object without a committed row
 * is undecryptable (crypto-shredding). Errors carry no detail.
 */

export const DLP_EVIDENCE_MAGIC = Buffer.from('EGDLP1', 'ascii');
export const DLP_EVIDENCE_KEY_ID = 'k1';
const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;
const PART = /^[A-Za-z0-9_-]+$/;

export interface EvidenceKek {
  /** 32 bytes, or 64 hex characters (`DLP_EVIDENCE_KEY`). */
  current: Buffer | string;
  /** `DLP_EVIDENCE_KEY_PREVIOUS` (rotation), optional. */
  previous?: Buffer | string | null;
}

export interface EvidenceIds {
  organizationId: string;
  messageId: string;
  scanId: string;
}

export interface SealedEvidence {
  /** The S3 object body. */
  object: Buffer;
  /** `dlp_evidence.wrapped_key`. */
  wrappedKey: string;
  keyId: string;
  algorithm: typeof DLP_EVIDENCE_ALGORITHM;
  /** SHA-256 (hex) and size of the object body. */
  sha256: string;
  size: number;
}

/** Raised for a malformed, tampered or undecryptable evidence. Carries no detail. */
export class DlpEvidenceCryptoError extends Error {
  constructor() {
    super('Unable to open the DLP evidence');
    this.name = 'DlpEvidenceCryptoError';
  }
}

/** Raised for an invalid key-encryption key (configuration error; names no value). */
export class DlpEvidenceKeyError extends Error {
  constructor() {
    super('DLP_EVIDENCE_KEY must be 32 bytes (64 hex characters)');
    this.name = 'DlpEvidenceKeyError';
  }
}

const keyOf = (value: Buffer | string): Buffer => {
  if (Buffer.isBuffer(value)) {
    if (value.length !== KEY_BYTES) throw new DlpEvidenceKeyError();
    return value;
  }
  if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new DlpEvidenceKeyError();
  return Buffer.from(value, 'hex');
};

/** The payload AAD (D16). Ids are decimal strings; a NUL inside an id is refused. */
export function evidenceAad(ids: EvidenceIds): string {
  for (const id of [ids.organizationId, ids.messageId, ids.scanId]) {
    if (typeof id !== 'string' || id.length === 0 || id.includes('\0')) {
      throw new DlpEvidenceCryptoError();
    }
  }
  return `eg-dlp-evidence/v1\0${ids.organizationId}\0${ids.messageId}\0${ids.scanId}`;
}

const gcmEncrypt = (key: Buffer, plaintext: Buffer, aad: string) => {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), ciphertext };
};

const gcmDecrypt = (
  key: Buffer,
  iv: Buffer,
  tag: Buffer,
  ciphertext: Buffer,
  aad: string,
): Buffer | null => {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
};

/** Seals an evidence plaintext (the evidence JSON) for one (organization, message, scan). */
export function sealEvidence(
  kek: EvidenceKek,
  plaintext: Buffer | string,
  ids: EvidenceIds,
): SealedEvidence {
  const wrapKey = keyOf(kek.current);
  const aad = evidenceAad(ids);
  const dataKey = randomBytes(KEY_BYTES);
  try {
    const body = gcmEncrypt(
      dataKey,
      Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8'),
      aad,
    );
    const object = Buffer.concat([DLP_EVIDENCE_MAGIC, body.iv, body.tag, body.ciphertext]);
    const wrapped = gcmEncrypt(wrapKey, dataKey, `${aad}\0dek`);
    const wrappedKey = [
      VERSION,
      DLP_EVIDENCE_KEY_ID,
      wrapped.iv.toString('base64url'),
      wrapped.tag.toString('base64url'),
      wrapped.ciphertext.toString('base64url'),
    ].join('.');
    return {
      object,
      wrappedKey,
      keyId: DLP_EVIDENCE_KEY_ID,
      algorithm: DLP_EVIDENCE_ALGORITHM,
      sha256: createHash('sha256').update(object).digest('hex'),
      size: object.length,
    };
  } finally {
    dataKey.fill(0);
  }
}

export interface OpenedEvidence {
  plaintext: Buffer;
  /** Only `DLP_EVIDENCE_KEY_PREVIOUS` could unwrap the data key. */
  usedPreviousKey: boolean;
}

/** Opens a sealed evidence object with its wrapped key; throws `DlpEvidenceCryptoError`. */
export function openEvidence(
  kek: EvidenceKek,
  object: Buffer,
  wrappedKey: string,
  ids: EvidenceIds,
): OpenedEvidence {
  const current = keyOf(kek.current);
  const previous = kek.previous ? keyOf(kek.previous) : null;
  const aad = evidenceAad(ids);
  const parts = typeof wrappedKey === 'string' ? wrappedKey.split('.') : [];
  if (parts.length !== 5) throw new DlpEvidenceCryptoError();
  const [version, kid, ivPart, tagPart, ctPart] = parts as [string, string, string, string, string];
  if (version !== VERSION || !/^k[0-9]+$/.test(kid)) throw new DlpEvidenceCryptoError();
  if (![ivPart, tagPart, ctPart].every((p) => PART.test(p))) throw new DlpEvidenceCryptoError();
  const wrapIv = Buffer.from(ivPart, 'base64url');
  const wrapTag = Buffer.from(tagPart, 'base64url');
  const wrapCt = Buffer.from(ctPart, 'base64url');
  if (wrapIv.length !== IV_BYTES || wrapTag.length !== TAG_BYTES || wrapCt.length !== KEY_BYTES) {
    throw new DlpEvidenceCryptoError();
  }
  let usedPreviousKey = false;
  let dataKey = gcmDecrypt(current, wrapIv, wrapTag, wrapCt, `${aad}\0dek`);
  if (!dataKey && previous) {
    dataKey = gcmDecrypt(previous, wrapIv, wrapTag, wrapCt, `${aad}\0dek`);
    usedPreviousKey = dataKey !== null;
  }
  if (!dataKey) throw new DlpEvidenceCryptoError();
  try {
    const header = DLP_EVIDENCE_MAGIC.length;
    if (
      object.length < header + IV_BYTES + TAG_BYTES ||
      !object.subarray(0, header).equals(DLP_EVIDENCE_MAGIC)
    ) {
      throw new DlpEvidenceCryptoError();
    }
    const iv = object.subarray(header, header + IV_BYTES);
    const tag = object.subarray(header + IV_BYTES, header + IV_BYTES + TAG_BYTES);
    const ciphertext = object.subarray(header + IV_BYTES + TAG_BYTES);
    const plaintext = gcmDecrypt(dataKey, iv, tag, ciphertext, aad);
    if (!plaintext) throw new DlpEvidenceCryptoError();
    return { plaintext, usedPreviousKey };
  } finally {
    dataKey.fill(0);
  }
}
