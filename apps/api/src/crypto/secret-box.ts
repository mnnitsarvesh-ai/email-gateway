import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';

const VERSION = 'v1';
/** Label of the key that encrypts. Decryption accepts the previous key too (rotation). */
const CURRENT_KID = 'k1';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const PART = /^[A-Za-z0-9_-]+$/;

export type SecretBoxConfig = Pick<
  ApiConfig,
  'DATA_ENCRYPTION_KEY' | 'DATA_ENCRYPTION_KEY_PREVIOUS'
>;

export interface Decrypted {
  plaintext: string;
  /** True when only DATA_ENCRYPTION_KEY_PREVIOUS could decrypt it: re-encrypt and store. */
  usedPreviousKey: boolean;
}

/** Raised for malformed, tampered or undecryptable ciphertexts. Carries no detail. */
export class SecretBoxError extends Error {
  constructor() {
    super('Unable to decrypt the protected value');
    this.name = 'SecretBoxError';
  }
}

/**
 * Application-level encryption of short secrets (MFA secrets, D4): AES-256-GCM, 12-byte random
 * IV, caller-supplied additional authenticated data that binds the ciphertext to its row (e.g.
 * `mfa:user:<id>`). Output: `v1.<kid>.<iv>.<tag>.<ciphertext>` (base64url parts).
 */
@Injectable()
export class SecretBox {
  private readonly current: Buffer;
  private readonly previous: Buffer | undefined;

  constructor(@Inject(API_CONFIG) config: SecretBoxConfig) {
    this.current = Buffer.from(config.DATA_ENCRYPTION_KEY, 'hex');
    this.previous = config.DATA_ENCRYPTION_KEY_PREVIOUS
      ? Buffer.from(config.DATA_ENCRYPTION_KEY_PREVIOUS, 'hex')
      : undefined;
    if (this.current.length !== 32 || (this.previous && this.previous.length !== 32)) {
      throw new Error('DATA_ENCRYPTION_KEY must be 32 bytes (64 hex characters)');
    }
  }

  encrypt(plaintext: string, aad: string): string {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.current, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return [
      VERSION,
      CURRENT_KID,
      iv.toString('base64url'),
      cipher.getAuthTag().toString('base64url'),
      ciphertext.toString('base64url'),
    ].join('.');
  }

  /** Throws `SecretBoxError` when the value is malformed, tampered or bound to another AAD. */
  decrypt(payload: string, aad: string): Decrypted {
    const parts = payload.split('.');
    if (parts.length !== 5) throw new SecretBoxError();
    const [version, kid, ivPart, tagPart, ctPart] = parts as [
      string,
      string,
      string,
      string,
      string,
    ];
    if (version !== VERSION || !/^k\d+$/.test(kid)) throw new SecretBoxError();
    if (![ivPart, tagPart].every((p) => PART.test(p)) || !(ctPart === '' || PART.test(ctPart))) {
      throw new SecretBoxError();
    }
    const iv = Buffer.from(ivPart, 'base64url');
    const tag = Buffer.from(tagPart, 'base64url');
    const ciphertext = Buffer.from(ctPart, 'base64url');
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new SecretBoxError();

    const plaintext = this.open(this.current, iv, tag, ciphertext, aad);
    if (plaintext !== undefined) return { plaintext, usedPreviousKey: false };
    if (this.previous) {
      const old = this.open(this.previous, iv, tag, ciphertext, aad);
      if (old !== undefined) return { plaintext: old, usedPreviousKey: true };
    }
    throw new SecretBoxError();
  }

  private open(
    key: Buffer,
    iv: Buffer,
    tag: Buffer,
    ciphertext: Buffer,
    aad: string,
  ): string | undefined {
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
      decipher.setAAD(Buffer.from(aad, 'utf8'));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch {
      return undefined;
    }
  }
}
