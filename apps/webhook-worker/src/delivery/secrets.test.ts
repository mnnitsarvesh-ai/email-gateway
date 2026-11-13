import { secretAad, WebhookSecretCipher } from '@email-gateway/webhooks';
import { describe, expect, it } from 'vitest';
import { type SecretColumns, SecretProvider, SecretUnavailableError } from './secrets';

const cipher = new WebhookSecretCipher({ key: '1'.repeat(64) });
const SUB = '01890a5d-ac96-774b-bcce-b3020990b501';

function columns(overrides: Partial<SecretColumns> = {}): SecretColumns {
  return {
    id: 5n,
    organizationId: 42n,
    publicId: SUB,
    secretVersion: 2,
    secretCiphertext: cipher.encrypt('whsec_current', secretAad(42n, SUB, 2)),
    previousSecretCiphertext: cipher.encrypt('whsec_previous', secretAad(42n, SUB, 1)),
    previousSecretExpiresAt: new Date(10_000),
    ...overrides,
  };
}

describe('SecretProvider (W7)', () => {
  it('returns the current secret first and the previous one while unexpired', () => {
    let now = 1_000;
    const provider = new SecretProvider(cipher, () => now);
    expect(provider.secrets(columns())).toEqual(['whsec_current', 'whsec_previous']);
    now = 10_000; // the overlap ended (even within the cache TTL)
    expect(provider.secrets(columns())).toEqual(['whsec_current']);
  });

  it('ignores a previous secret without expiry or already expired at decryption', () => {
    const provider = new SecretProvider(cipher, () => 20_000);
    expect(provider.secrets(columns())).toEqual(['whsec_current']);
    expect(provider.secrets(columns({ id: 6n, previousSecretExpiresAt: null }))).toEqual([
      'whsec_current',
    ]);
  });

  it('caches by (subscription, version) for 60 s; a rotation (new version) is used at once', () => {
    let now = 0;
    let decrypts = 0;
    const counting = {
      decrypt: (payload: string, aad: string) => {
        decrypts += 1;
        return cipher.decrypt(payload, aad);
      },
    } as unknown as WebhookSecretCipher;
    const provider = new SecretProvider(counting, () => now);
    const c = columns({ previousSecretCiphertext: null, previousSecretExpiresAt: null });
    provider.secrets(c);
    provider.secrets(c);
    expect(decrypts).toBe(1);
    now = 59_999;
    provider.secrets(c);
    expect(decrypts).toBe(1);
    now = 60_000;
    provider.secrets(c);
    expect(decrypts).toBe(2);
    const rotated = columns({
      secretVersion: 3,
      secretCiphertext: cipher.encrypt('whsec_new', secretAad(42n, SUB, 3)),
      previousSecretCiphertext: null,
      previousSecretExpiresAt: null,
    });
    expect(provider.secrets(rotated)).toEqual(['whsec_new']);
  });

  it('fails closed (secret_unavailable) on a wrong key, AAD or tampered ciphertext', () => {
    const provider = new SecretProvider(cipher, () => 0);
    const other = new WebhookSecretCipher({ key: '2'.repeat(64) });
    expect(() =>
      provider.secrets(
        columns({ id: 7n, secretCiphertext: other.encrypt('x', secretAad(42n, SUB, 2)) }),
      ),
    ).toThrow(SecretUnavailableError);
    expect(() =>
      provider.secrets(
        columns({ id: 8n, secretCiphertext: cipher.encrypt('x', secretAad(43n, SUB, 2)) }),
      ),
    ).toThrow(SecretUnavailableError);
    expect(() =>
      provider.secrets(columns({ id: 9n, previousSecretCiphertext: 'v1.k1.x.y.z' })),
    ).toThrow(SecretUnavailableError);
    try {
      provider.secrets(columns({ id: 10n, secretCiphertext: 'garbage' }));
    } catch (error) {
      expect(String(error)).not.toContain('whsec_');
    }
  });

  it('decrypts with the previous encryption key during a key rotation', () => {
    const rotated = new WebhookSecretCipher({ key: '3'.repeat(64), previousKey: '1'.repeat(64) });
    const provider = new SecretProvider(rotated, () => 0);
    expect(provider.secrets(columns())).toEqual(['whsec_current', 'whsec_previous']);
  });
});
