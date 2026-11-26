import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { keyKidOf, SecretBox, SecretBoxError } from './secret-box';

const key = () => randomBytes(32).toString('hex');

describe('SecretBox', () => {
  const current = key();
  const box = new SecretBox({ DATA_ENCRYPTION_KEY: current });
  const aad = 'mfa:user:42';

  it('round-trips with the documented format', () => {
    const sealed = box.encrypt('JBSWY3DPEHPK3PXP', aad);
    expect(sealed).toMatch(/^v1\.k1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]+$/);
    expect(box.decrypt(sealed, aad)).toEqual({
      plaintext: 'JBSWY3DPEHPK3PXP',
      usedPreviousKey: false,
    });
  });

  it('uses a fresh IV every time', () => {
    expect(box.encrypt('same', aad)).not.toBe(box.encrypt('same', aad));
  });

  it('fits VARCHAR(512) for a 32-character TOTP secret', () => {
    expect(box.encrypt('A'.repeat(32), aad).length).toBeLessThan(512);
  });

  it('rejects a ciphertext bound to another row (AAD)', () => {
    expect(() => box.decrypt(box.encrypt('secret', aad), 'mfa:user:43')).toThrow(SecretBoxError);
  });

  it.each([
    ['ciphertext', 4],
    ['tag', 3],
    ['iv', 2],
  ])('detects tampering with the %s', (_name, index) => {
    const parts = box.encrypt('secret value', aad).split('.');
    const bytes = Buffer.from(parts[index]!, 'base64url');
    bytes[0] = bytes[0]! ^ 0x01;
    parts[index] = bytes.toString('base64url');
    expect(() => box.decrypt(parts.join('.'), aad)).toThrow(SecretBoxError);
  });

  it.each(['', 'v1.k1.abc', 'v2.k1.a.b.c', 'v1.kx.a.b.c', 'v1.k1.!!.b.c', 'v1.k1.AAAA.AAAA.AAAA'])(
    'rejects malformed input %j without detail',
    (payload) => {
      expect(() => box.decrypt(payload, aad)).toThrow('Unable to decrypt the protected value');
    },
  );

  it('decrypts with the previous key during rotation and reports it', () => {
    const old = new SecretBox({ DATA_ENCRYPTION_KEY: current });
    const rotated = new SecretBox({
      DATA_ENCRYPTION_KEY: key(),
      DATA_ENCRYPTION_KEY_PREVIOUS: current,
    });
    const sealed = old.encrypt('legacy', aad);
    expect(rotated.decrypt(sealed, aad)).toEqual({ plaintext: 'legacy', usedPreviousKey: true });
    const resealed = rotated.encrypt('legacy', aad);
    expect(rotated.decrypt(resealed, aad).usedPreviousKey).toBe(false);
  });

  it('fails without the right key', () => {
    const other = new SecretBox({ DATA_ENCRYPTION_KEY: key() });
    expect(() => other.decrypt(box.encrypt('secret', aad), aad)).toThrow(SecretBoxError);
  });

  it('refuses keys that are not 32 bytes', () => {
    expect(() => new SecretBox({ DATA_ENCRYPTION_KEY: 'ab'.repeat(16) })).toThrow();
  });
});

describe('SecretBox.withKeys (step AI-6 D7: an explicit key pair)', () => {
  const aad = 'assistant-provider-key:v1:7:1';

  it('labels ciphertexts with k + 7 hex of the key SHA-256 and round-trips', () => {
    const current = key();
    const box = SecretBox.withKeys({ current, name: 'TEST_KEY' });
    expect(box.kid).toBe(keyKidOf(current));
    expect(box.kid).toMatch(/^k[0-9a-f]{7}$/);
    const sealed = box.encrypt('test-tenant-key-0001-not-a-secret', aad);
    expect(sealed.split('.').slice(0, 2)).toEqual(['v1', box.kid]);
    expect(box.decrypt(sealed, aad)).toEqual({
      plaintext: 'test-tenant-key-0001-not-a-secret',
      usedPreviousKey: false,
    });
    expect(() => box.decrypt(sealed, 'assistant-provider-key:v1:7:2')).toThrow(SecretBoxError);
  });

  it('decrypts with the previous key during rotation and stays separate from the DI box', () => {
    const old = key();
    const sealed = SecretBox.withKeys({ current: old, name: 'TEST_KEY' }).encrypt('value', aad);
    const rotated = SecretBox.withKeys({ current: key(), previous: old, name: 'TEST_KEY' });
    expect(rotated.decrypt(sealed, aad)).toEqual({ plaintext: 'value', usedPreviousKey: true });
    const di = new SecretBox({ DATA_ENCRYPTION_KEY: key() });
    expect(di.kid).toBe('k1');
    expect(() => di.decrypt(sealed, aad)).toThrow(SecretBoxError);
  });

  it('names the key, never the value, when it is not 32 bytes', () => {
    expect(() => SecretBox.withKeys({ current: 'ab'.repeat(16), name: 'TEST_KEY' })).toThrow(
      /^TEST_KEY must be 32 bytes/,
    );
    expect(() =>
      SecretBox.withKeys({ current: key(), previous: 'zz'.repeat(32), name: 'TEST_KEY' }),
    ).toThrow(/TEST_KEY/);
  });
});
