import { secretAad, type WebhookSecretCipher } from '@email-gateway/webhooks';

/** The subscription columns the signer needs (never logged). */
export interface SecretColumns {
  id: bigint;
  organizationId: bigint;
  publicId: string;
  secretVersion: number;
  secretCiphertext: string;
  previousSecretCiphertext: string | null;
  previousSecretExpiresAt: Date | null;
}

/** No usable secret (undecryptable, wrong AAD, key missing). Carries no detail. */
export class SecretUnavailableError extends Error {
  override readonly name = 'SecretUnavailableError';
  constructor() {
    super('webhook signing secret unavailable');
  }
}

interface Cached {
  at: number;
  current: string;
  previous: string | null;
  previousExpiresAt: number | null;
}

/** Decrypted secrets are kept at most this long (W7). */
export const SECRET_CACHE_TTL_MS = 60_000;
const MAX_ENTRIES = 10_000;

/**
 * The signing secrets of a subscription (step 6.2 W7): the current secret (AAD version
 * `secret_version`) and, while `previous_secret_expires_at` is in the future, the previous one
 * (AAD version `secret_version − 1`: a rotation moves the current ciphertext unchanged to
 * `previous_secret_ciphertext`). Cached in memory ≤ 60 s keyed by `(subscription id, secret
 * version)`; a rotation bumps the version, so a new secret is used at once. Any decryption
 * failure is `SecretUnavailableError` (attempt outcome `secret_unavailable`, retried). Values
 * never leave this class except as the returned array, are never logged and never stored.
 */
export class SecretProvider {
  private readonly cache = new Map<string, Cached>();

  constructor(
    private readonly cipher: WebhookSecretCipher,
    private readonly now: () => number = Date.now,
    private readonly ttlMs: number = SECRET_CACHE_TTL_MS,
  ) {}

  /** Current first, then the unexpired previous secret. */
  secrets(sub: SecretColumns): string[] {
    const key = `${sub.id}:${sub.secretVersion}`;
    const now = this.now();
    let entry = this.cache.get(key);
    if (entry === undefined || now - entry.at >= this.ttlMs) {
      entry = this.decrypt(sub, now);
      this.cache.delete(key);
      this.cache.set(key, entry);
      while (this.cache.size > MAX_ENTRIES) {
        const oldest = this.cache.keys().next().value;
        if (oldest === undefined) break;
        this.cache.delete(oldest);
      }
    }
    const out = [entry.current];
    if (
      entry.previous !== null &&
      entry.previousExpiresAt !== null &&
      entry.previousExpiresAt > now
    ) {
      out.push(entry.previous);
    }
    return out;
  }

  clear(): void {
    this.cache.clear();
  }

  private decrypt(sub: SecretColumns, now: number): Cached {
    try {
      const current = this.cipher.decrypt(
        sub.secretCiphertext,
        secretAad(sub.organizationId, sub.publicId, sub.secretVersion),
      ).plaintext;
      let previous: string | null = null;
      const expiresAt = sub.previousSecretExpiresAt?.getTime() ?? null;
      if (
        sub.previousSecretCiphertext !== null &&
        expiresAt !== null &&
        expiresAt > now &&
        sub.secretVersion > 1
      ) {
        previous = this.cipher.decrypt(
          sub.previousSecretCiphertext,
          secretAad(sub.organizationId, sub.publicId, sub.secretVersion - 1),
        ).plaintext;
      }
      return { at: now, current, previous, previousExpiresAt: expiresAt };
    } catch {
      throw new SecretUnavailableError();
    }
  }
}
