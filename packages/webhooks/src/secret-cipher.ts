import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 'v1';
/** Label of the key that encrypts. Decryption accepts the previous key too (rotation). */
const CURRENT_KID = 'k1';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_HEX = /^[0-9a-fA-F]{64}$/;
const PART = /^[A-Za-z0-9_-]+$/;

/** Malformed key material at construction; names the key, never its value. */
export class WebhookSecretKeyError extends Error {
  override readonly name = 'WebhookSecretKeyError';
  constructor(key: 'WEBHOOK_SECRET_ENCRYPTION_KEY' | 'WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS') {
    super(`${key} must be 32 bytes (64 hex characters)`);
  }
}

/** A malformed, tampered or undecryptable ciphertext, or one bound to another AAD. No detail. */
export class WebhookSecretCipherError extends Error {
  override readonly name = 'WebhookSecretCipherError';
  constructor() {
    super('Unable to decrypt the webhook secret');
  }
}

export interface WebhookSecretCipherKeys {
  /** `WEBHOOK_SECRET_ENCRYPTION_KEY`: 64 hex characters (encrypts and decrypts). */
  key: string;
  /** `WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS`: decrypts only (key rotation). */
  previousKey?: string | null;
}

export interface DecryptedWebhookSecret {
  plaintext: string;
  /** Only the previous key could decrypt it: re-encrypt with the current key and store. */
  usedPreviousKey: boolean;
}

/**
 * The additional authenticated data binding a ciphertext to its subscription row and secret
 * version (W7): `webhook-secret:v1:<organizationId>:<subscriptionPublicId>:<secretVersion>`.
 * A ciphertext copied to another row or version never decrypts.
 */
export function secretAad(
  organizationId: string | number | bigint,
  subscriptionPublicId: string,
  secretVersion: number,
): string {
  return `webhook-secret:v1:${String(organizationId)}:${subscriptionPublicId}:${secretVersion}`;
}

/**
 * Encryption of webhook signing secrets (W7, §2.0 invariant 5): AES-256-GCM, 12-byte random IV,
 * 16-byte tag, the AAD of `secretAad`; output `v1.<kid>.<iv>.<tag>.<ciphertext>` (base64url
 * parts), the format of the api's `SecretBox`. Key custody: the api encrypts, the
 * webhook-worker decrypts; nobody else holds `WEBHOOK_SECRET_ENCRYPTION_KEY`. Errors carry no
 * detail and never a value.
 */
export class WebhookSecretCipher {
  private readonly current: Buffer;
  private readonly previous: Buffer | undefined;

  constructor(keys: WebhookSecretCipherKeys) {
    if (!KEY_HEX.test(keys.key)) throw new WebhookSecretKeyError('WEBHOOK_SECRET_ENCRYPTION_KEY');
    if (keys.previousKey && !KEY_HEX.test(keys.previousKey)) {
      throw new WebhookSecretKeyError('WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS');
    }
    this.current = Buffer.from(keys.key, 'hex');
    this.previous = keys.previousKey ? Buffer.from(keys.previousKey, 'hex') : undefined;
  }

  /** From the two configuration keys (empty previous = none). */
  static fromConfig(config: {
    WEBHOOK_SECRET_ENCRYPTION_KEY: string;
    WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS?: string | null | undefined;
  }): WebhookSecretCipher {
    return new WebhookSecretCipher({
      key: config.WEBHOOK_SECRET_ENCRYPTION_KEY,
      previousKey: config.WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS || null,
    });
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

  /** Throws `WebhookSecretCipherError` for anything but an intact ciphertext of this AAD. */
  decrypt(payload: string, aad: string): DecryptedWebhookSecret {
    const parts = typeof payload === 'string' ? payload.split('.') : [];
    if (parts.length !== 5) throw new WebhookSecretCipherError();
    const [version, kid, ivPart, tagPart, ctPart] = parts as [
      string,
      string,
      string,
      string,
      string,
    ];
    if (version !== VERSION || !/^k\d+$/.test(kid)) throw new WebhookSecretCipherError();
    if (![ivPart, tagPart].every((p) => PART.test(p)) || !(ctPart === '' || PART.test(ctPart))) {
      throw new WebhookSecretCipherError();
    }
    const iv = Buffer.from(ivPart, 'base64url');
    const tag = Buffer.from(tagPart, 'base64url');
    const ciphertext = Buffer.from(ctPart, 'base64url');
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new WebhookSecretCipherError();

    const plaintext = this.open(this.current, iv, tag, ciphertext, aad);
    if (plaintext !== undefined) return { plaintext, usedPreviousKey: false };
    if (this.previous) {
      const old = this.open(this.previous, iv, tag, ciphertext, aad);
      if (old !== undefined) return { plaintext: old, usedPreviousKey: true };
    }
    throw new WebhookSecretCipherError();
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
