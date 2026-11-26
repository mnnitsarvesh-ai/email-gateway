import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';

const VERSION = 'v1';
/** Label of the key that encrypts. Decryption accepts the previous key too (rotation). */
const CURRENT_KID = 'k1';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const PART = /^[A-Za-z0-9_-]+$/;
/** `k1` (the DI box) or `k` + 7 hex of the key's SHA-256 (boxes built by `withKeys`). */
const KID = /^k(?:\d+|[0-9a-f]{7})$/;

/** `k` + the first 7 hex characters of SHA-256 of the raw key (ADR-0077 `kid` format). */
export function keyKidOf(hexKey: string): string {
  return `k${createHash('sha256').update(Buffer.from(hexKey, 'hex')).digest('hex').slice(0, 7)}`;
}

/** An explicit key pair (`SecretBox.withKeys`): 64 hex characters each. */
export interface SecretBoxKeys {
  current: string;
  previous?: string | undefined;
  /** The configuration key named in the length error (never the value). */
  name: string;
}

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
 *
 * The injectable box uses DATA_ENCRYPTION_KEY (`kid` `k1`). `SecretBox.withKeys` builds the same
 * construction over a dedicated key pair (step AI-6 D7: tenant provider keys under
 * ASSISTANT_TENANT_KEY_ENCRYPTION_KEY), labelled `k` + 7 hex of the key's SHA-256. Decryption
 * always tries the current key, then the previous one (rotation).
 */
@Injectable()
export class SecretBox {
  private current!: Buffer;
  private previous: Buffer | undefined;
  private currentKid!: string;

  constructor(@Inject(API_CONFIG) config: SecretBoxConfig) {
    this.useKeys(
      {
        current: config.DATA_ENCRYPTION_KEY,
        previous: config.DATA_ENCRYPTION_KEY_PREVIOUS,
        name: 'DATA_ENCRYPTION_KEY',
      },
      CURRENT_KID,
    );
  }

  /** A box over an explicit key pair (not DI); `kid` = `keyKidOf(current)`. */
  static withKeys(keys: SecretBoxKeys): SecretBox {
    const box = Object.create(SecretBox.prototype) as SecretBox;
    box.useKeys(keys, null);
    return box;
  }

  /** The label of the encrypting key (stored next to the ciphertext, e.g. `key_kid`). */
  get kid(): string {
    return this.currentKid;
  }

  private useKeys(keys: SecretBoxKeys, fixedKid: string | null): void {
    const hex = /^[0-9a-fA-F]{64}$/;
    const previous = keys.previous ? keys.previous : undefined;
    if (!hex.test(keys.current) || (previous !== undefined && !hex.test(previous))) {
      throw new Error(`${keys.name} must be 32 bytes (64 hex characters)`);
    }
    this.current = Buffer.from(keys.current, 'hex');
    this.previous = previous ? Buffer.from(previous, 'hex') : undefined;
    this.currentKid = fixedKid ?? keyKidOf(keys.current);
  }

  encrypt(plaintext: string, aad: string): string {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.current, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return [
      VERSION,
      this.currentKid,
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
    if (version !== VERSION || !KID.test(kid)) throw new SecretBoxError();
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
