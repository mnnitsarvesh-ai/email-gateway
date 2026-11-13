import { describe, expect, it } from 'vitest';
import {
  secretAad,
  WebhookSecretCipher,
  WebhookSecretCipherError,
  WebhookSecretKeyError,
} from './secret-cipher';
import { generateWebhookSecret } from './signing';

const KEY = '0123456789abcdef'.repeat(4);
const OLD = 'fedcba9876543210'.repeat(4);
const SUB = '0192f0c4-c355-7062-9b73-5e6f708192a3';
const AAD = secretAad('42', SUB, 1);

describe('secretAad (W7)', () => {
  it('binds organization, subscription and secret version', () => {
    expect(AAD).toBe(`webhook-secret:v1:42:${SUB}:1`);
    expect(secretAad(42n, SUB, 2)).toBe(`webhook-secret:v1:42:${SUB}:2`);
    expect(secretAad(42, SUB, 1)).toBe(AAD);
  });
});

describe('WebhookSecretCipher (W7)', () => {
  const cipher = new WebhookSecretCipher({ key: KEY });

  it('round-trips in the v1.<kid>.<iv>.<tag>.<ct> base64url format', () => {
    const secret = generateWebhookSecret();
    const sealed = cipher.encrypt(secret, AAD);
    expect(sealed).toMatch(/^v1\.k1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]+$/);
    expect(sealed).not.toContain(secret);
    expect(sealed.length).toBeLessThanOrEqual(512);
    expect(cipher.decrypt(sealed, AAD)).toEqual({ plaintext: secret, usedPreviousKey: false });
    // A fresh IV per encryption.
    expect(cipher.encrypt(secret, AAD)).not.toBe(sealed);
  });

  it('refuses another AAD (other organization, subscription or version)', () => {
    const sealed = cipher.encrypt('whsec_x', AAD);
    for (const aad of [
      secretAad('43', SUB, 1),
      secretAad('42', '0192f0c4-c355-7062-9b73-5e6f708192a4', 1),
      secretAad('42', SUB, 2),
    ]) {
      expect(() => cipher.decrypt(sealed, aad), aad).toThrow(WebhookSecretCipherError);
    }
  });

  it('refuses tampering with any part', () => {
    const sealed = cipher.encrypt('whsec_x', AAD);
    const parts = sealed.split('.');
    for (const index of [2, 3, 4]) {
      const changed = [...parts];
      const buf = Buffer.from(changed[index]!, 'base64url');
      buf[0] = buf[0]! ^ 0x01;
      changed[index] = buf.toString('base64url');
      expect(() => cipher.decrypt(changed.join('.'), AAD), String(index)).toThrow(
        WebhookSecretCipherError,
      );
    }
  });

  it('decrypts with the previous key during a key rotation and says so', () => {
    const before = new WebhookSecretCipher({ key: OLD });
    const sealed = before.encrypt('whsec_old', AAD);
    const rotated = new WebhookSecretCipher({ key: KEY, previousKey: OLD });
    expect(rotated.decrypt(sealed, AAD)).toEqual({ plaintext: 'whsec_old', usedPreviousKey: true });
    expect(() => cipher.decrypt(sealed, AAD)).toThrow(WebhookSecretCipherError);
    const fromConfig = WebhookSecretCipher.fromConfig({
      WEBHOOK_SECRET_ENCRYPTION_KEY: KEY,
      WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: '',
    });
    expect(() => fromConfig.decrypt(sealed, AAD)).toThrow(WebhookSecretCipherError);
  });

  it.each([
    [''],
    ['v1.k1.a.b'],
    ['v2.k1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AA'],
    ['v1.kx.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AA'],
    ['v1.k1.AAAA.AAAAAAAAAAAAAAAAAAAAAA.AA'],
    ['v1.k1.AAAAAAAAAAAAAAAA.AAAA.AA'],
    ['v1.k1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.A+/='],
  ])('refuses the malformed value %j without detail', (value) => {
    try {
      cipher.decrypt(value, AAD);
      throw new Error('expected a refusal');
    } catch (error) {
      expect(error).toBeInstanceOf(WebhookSecretCipherError);
      expect((error as Error).message).toBe('Unable to decrypt the webhook secret');
    }
  });

  it('refuses malformed keys, naming the key only', () => {
    expect(() => new WebhookSecretCipher({ key: 'abc' })).toThrow(WebhookSecretKeyError);
    expect(() => new WebhookSecretCipher({ key: KEY, previousKey: 'zz' })).toThrow(
      /WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS/,
    );
    try {
      new WebhookSecretCipher({ key: 'not-a-key-value' });
    } catch (error) {
      expect((error as Error).message).not.toContain('not-a-key-value');
    }
  });
});
