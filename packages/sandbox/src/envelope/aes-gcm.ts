import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/** AES-256-GCM helpers shared by the sandbox envelopes (12-byte IV, 16-byte tag). */
export const IV_BYTES = 12;
export const TAG_BYTES = 16;
export const DATA_KEY_BYTES = 32;
export const BASE64URL_PART = /^[A-Za-z0-9_-]+$/;

export interface GcmBox {
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

export function gcmEncrypt(key: Buffer, plaintext: Buffer, aad: string): GcmBox {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), ciphertext };
}

/** Decrypts; null on any failure (wrong key, AAD or tampering). */
export function gcmDecrypt(
  key: Buffer,
  iv: Buffer,
  tag: Buffer,
  ciphertext: Buffer,
  aad: string,
): Buffer | null {
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) return null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}

/** Decodes a base64url part; null when it is not strictly base64url. */
export function base64UrlPart(value: string | undefined): Buffer | null {
  if (value === undefined || !BASE64URL_PART.test(value)) return null;
  return Buffer.from(value, 'base64url');
}
