import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { ArchiveCryptoError } from './errors';

/**
 * The SecretBox wrapped-key format shared with the api (`v1.<kid>.<iv>.<tag>.<ct>`, base64url
 * parts, AES-256-GCM, 12-byte IV, 16-byte tag), used for every wrapped key of the archive
 * hierarchy (A8). Errors carry no detail.
 */

export const DATA_KEY_BYTES = 32;
export const GCM_IV_BYTES = 12;
export const GCM_TAG_BYTES = 16;
const VERSION = 'v1';
const PART = /^[A-Za-z0-9_-]+$/;
const KID = /^[a-z0-9]{1,32}$/;
/** Upper bound of a wrapped string (the widest column holding one is 512 characters). */
export const WRAPPED_MAX_LENGTH = 512;

export interface ParsedSecretBox {
  kid: string;
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

/** Seals `plaintext` under `key` with `aad`; `kid` names the key in the output. */
export function sealSecretBox(key: Buffer, kid: string, plaintext: Buffer, aad: string): string {
  if (key.length !== DATA_KEY_BYTES || !KID.test(kid)) throw new ArchiveCryptoError('malformed');
  const iv = randomBytes(GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [
    VERSION,
    kid,
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

/** Strictly parses the format (canonical base64url, exact IV/tag sizes); throws `malformed`. */
export function parseSecretBox(wrapped: unknown): ParsedSecretBox {
  if (typeof wrapped !== 'string' || wrapped.length > WRAPPED_MAX_LENGTH) {
    throw new ArchiveCryptoError('malformed');
  }
  const parts = wrapped.split('.');
  if (parts.length !== 5) throw new ArchiveCryptoError('malformed');
  const [version, kid, ivPart, tagPart, ctPart] = parts as [string, string, string, string, string];
  if (version !== VERSION || !KID.test(kid)) throw new ArchiveCryptoError('malformed');
  if (![ivPart, tagPart, ctPart].every((p) => PART.test(p))) {
    throw new ArchiveCryptoError('malformed');
  }
  const iv = Buffer.from(ivPart, 'base64url');
  const tag = Buffer.from(tagPart, 'base64url');
  const ciphertext = Buffer.from(ctPart, 'base64url');
  if (
    iv.length !== GCM_IV_BYTES ||
    tag.length !== GCM_TAG_BYTES ||
    iv.toString('base64url') !== ivPart ||
    tag.toString('base64url') !== tagPart ||
    ciphertext.toString('base64url') !== ctPart
  ) {
    throw new ArchiveCryptoError('malformed');
  }
  return { kid, iv, tag, ciphertext };
}

/** Opens a parsed box; null on any failure (wrong key, AAD or tampering). */
export function openSecretBox(key: Buffer, box: ParsedSecretBox, aad: string): Buffer | null {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, box.iv, {
      authTagLength: GCM_TAG_BYTES,
    });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(box.tag);
    return Buffer.concat([decipher.update(box.ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}
