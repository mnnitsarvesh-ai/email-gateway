import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateTestRsaKey } from '../testing/helpers';
import {
  credentialAad,
  credentialFingerprint,
  credentialKeyId,
  parseClientSecret,
  parseServiceAccountKey,
  ProviderCredentialCipher,
  ProviderCredentialCipherError,
  ProviderCredentialInvalidError,
  ProviderCredentialKeyError,
  shortFingerprint,
  type ProviderCredential,
} from './credential-cipher';

const key = () => randomBytes(32).toString('hex');
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const parts = {
  organizationId: 42n,
  connectionPublicId: '01930000-0000-7000-8000-000000000001',
  grantPublicId: '01930000-0000-7000-8000-000000000002',
  credentialVersion: 1,
};

describe('ProviderCredentialCipher', () => {
  it('round-trips with the row-bound AAD and the v1.<kid>.<iv>.<tag>.<ct> format', () => {
    const k = key();
    const cipher = new ProviderCredentialCipher({ key: k });
    const sealed = cipher.encrypt('plain text', credentialAad(parts));
    expect(sealed.ciphertext).toMatch(
      /^v1\.k[0-9a-f]{7}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );
    expect(sealed.keyId).toBe(credentialKeyId(k));
    expect(sealed.keyId).toHaveLength(8);
    expect(sealed.ciphertext).not.toContain('plain');
    expect(cipher.decrypt(sealed.ciphertext, credentialAad(parts))).toEqual({
      plaintext: 'plain text',
      keyId: sealed.keyId,
      usedPreviousKey: false,
    });
    expect(credentialAad(parts)).toBe(
      'provider-credential:v1:42:01930000-0000-7000-8000-000000000001:01930000-0000-7000-8000-000000000002:1',
    );
  });

  it('a ciphertext copied to another row, grant or version never decrypts', () => {
    const cipher = new ProviderCredentialCipher({ key: key() });
    const sealed = cipher.encrypt('x', credentialAad(parts));
    for (const other of [
      { ...parts, organizationId: 43n },
      { ...parts, connectionPublicId: '01930000-0000-7000-8000-000000000009' },
      { ...parts, grantPublicId: '01930000-0000-7000-8000-000000000009' },
      { ...parts, credentialVersion: 2 },
    ]) {
      expect(() => cipher.decrypt(sealed.ciphertext, credentialAad(other))).toThrow(
        ProviderCredentialCipherError,
      );
    }
  });

  it('decrypts with the previous key during rotation and reports it', () => {
    const oldKey = key();
    const newKey = key();
    const old = new ProviderCredentialCipher({ key: oldKey });
    const sealed = old.encrypt('rotating', credentialAad(parts));
    const rotated = new ProviderCredentialCipher({ key: newKey, previousKey: oldKey });
    expect(rotated.previousKeyId).toBe(credentialKeyId(oldKey));
    const opened = rotated.decrypt(sealed.ciphertext, credentialAad(parts));
    expect(opened).toEqual({
      plaintext: 'rotating',
      keyId: credentialKeyId(oldKey),
      usedPreviousKey: true,
    });
    const resealed = rotated.encrypt(opened.plaintext, credentialAad(parts));
    expect(resealed.keyId).toBe(credentialKeyId(newKey));
    expect(
      new ProviderCredentialCipher({ key: newKey }).decrypt(
        resealed.ciphertext,
        credentialAad(parts),
      ).plaintext,
    ).toBe('rotating');
    expect(() =>
      new ProviderCredentialCipher({ key: newKey }).decrypt(
        sealed.ciphertext,
        credentialAad(parts),
      ),
    ).toThrow(ProviderCredentialCipherError);
  });

  it('refuses tampering and malformed payloads without detail', () => {
    const cipher = new ProviderCredentialCipher({ key: key() });
    const sealed = cipher.encrypt('secret-ish', credentialAad(parts)).ciphertext;
    const [v, kid, iv, tag, ct] = sealed.split('.') as [string, string, string, string, string];
    const flip = (s: string) => (s[0] === 'A' ? `B${s.slice(1)}` : `A${s.slice(1)}`);
    const bad = [
      '',
      'v1.k1234567.x.y',
      [v, kid, iv, tag, flip(ct)].join('.'),
      [v, kid, iv, flip(tag), ct].join('.'),
      [v, kid, flip(iv), tag, ct].join('.'),
      ['v2', kid, iv, tag, ct].join('.'),
      [v, 'kXYZ', iv, tag, ct].join('.'),
      [v, kid, 'short', tag, ct].join('.'),
      [v, kid, iv, tag, `${ct}=`].join('.'),
    ];
    for (const payload of bad) {
      expect(() => cipher.decrypt(payload, credentialAad(parts)), payload).toThrow(
        ProviderCredentialCipherError,
      );
    }
    try {
      cipher.decrypt([v, kid, iv, tag, flip(ct)].join('.'), credentialAad(parts));
    } catch (error) {
      expect((error as Error).message).toBe('Unable to decrypt the provider credential');
    }
  });

  it('validates key material and never echoes it', () => {
    const short = 'ab'.repeat(16);
    expect(() => new ProviderCredentialCipher({ key: short })).toThrow(ProviderCredentialKeyError);
    expect(() => new ProviderCredentialCipher({ key: 'zz'.repeat(32) })).toThrow(
      /PROVIDER_CREDENTIAL_ENCRYPTION_KEY must be/,
    );
    const k = key();
    expect(() => new ProviderCredentialCipher({ key: k, previousKey: k })).toThrow(/must differ/);
    expect(() => new ProviderCredentialCipher({ key: key(), previousKey: 'nothex' })).toThrow(
      /_PREVIOUS/,
    );
    try {
      new ProviderCredentialCipher({ key: short });
    } catch (error) {
      expect((error as Error).message).not.toContain(short);
    }
    expect(
      ProviderCredentialCipher.fromConfig({
        PROVIDER_CREDENTIAL_ENCRYPTION_KEY: k,
        PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: '',
      }).previousKeyId,
    ).toBeNull();
  });
});

describe('credential documents', () => {
  it('encrypts and decrypts strict per-method documents', () => {
    const cipher = new ProviderCredentialCipher({ key: key() });
    const secret: ProviderCredential = {
      method: 'customer_app_secret',
      clientSecret: 'fakeSecretValue123',
    };
    const sealed = cipher.encryptCredential(secret, parts);
    expect(cipher.decryptCredential(sealed.ciphertext, parts).credential).toEqual(secret);

    const rsa = generateTestRsaKey();
    const sa = parseServiceAccountKey(
      {
        type: 'service_account',
        project_id: 'dropped',
        private_key_id: rsa.keyId,
        private_key: rsa.privateKeyPem,
        client_email: 'Gateway@Project.iam.gserviceaccount.test',
        client_id: '123456789012345678901',
        auth_uri: 'https://accounts.example.test/o/oauth2/auth',
        token_uri: TOKEN_URL,
        universe_domain: 'googleapis.com',
      },
      { tokenUrl: `${TOKEN_URL}/` },
    );
    expect(Object.keys(sa).sort()).toEqual([
      'client_email',
      'client_id',
      'private_key',
      'private_key_id',
      'token_uri',
      'type',
    ]);
    expect(sa.client_email).toBe('gateway@project.iam.gserviceaccount.test');
    const doc: ProviderCredential = { method: 'customer_service_account', key: sa };
    const sealedSa = cipher.encryptCredential(doc, parts);
    expect(cipher.decryptCredential(sealedSa.ciphertext, parts).credential).toEqual(doc);
    // A ciphertext of another grant never decrypts as this one.
    expect(() =>
      cipher.decryptCredential(sealedSa.ciphertext, { ...parts, credentialVersion: 2 }),
    ).toThrow(ProviderCredentialCipherError);
  });

  it('refuses a wrong token_uri, missing fields and weak or unparsable keys (field named, value never)', () => {
    const rsa = generateTestRsaKey();
    const good = {
      type: 'service_account',
      private_key_id: rsa.keyId,
      private_key: rsa.privateKeyPem,
      client_email: 'gw@project.iam.gserviceaccount.test',
      token_uri: TOKEN_URL,
    };
    const field = (input: unknown) => {
      try {
        parseServiceAccountKey(input, { tokenUrl: TOKEN_URL });
        return 'accepted';
      } catch (error) {
        expect(error).toBeInstanceOf(ProviderCredentialInvalidError);
        expect((error as Error).message).not.toContain(rsa.privateKeyPem.slice(40, 80));
        return (error as ProviderCredentialInvalidError).field;
      }
    };
    expect(field(good)).toBe('accepted');
    expect(field(JSON.stringify(good))).toBe('accepted');
    expect(field({ ...good, token_uri: 'https://evil.example.test/token' })).toBe('token_uri');
    expect(field({ ...good, type: 'authorized_user' })).toBe('type');
    expect(field({ ...good, private_key: undefined })).toBe('private_key');
    expect(field({ ...good, private_key: 'x'.repeat(200) })).toBe('private_key');
    expect(field({ ...good, private_key: generateTestRsaKey(1024).privateKeyPem })).toBe(
      'private_key',
    );
    expect(field({ ...good, client_email: 'not-an-email' })).toBe('client_email');
    expect(field('{not json')).toBe('serviceAccountKey');
    expect(field([good])).toBe('serviceAccountKey');
  });

  it('validates client secrets', () => {
    expect(parseClientSecret('fakeSecretValue123')).toEqual({
      method: 'customer_app_secret',
      clientSecret: 'fakeSecretValue123',
    });
    for (const bad of ['short', 'has space inside', `tab\tinside12`, 42, 'x'.repeat(1025)]) {
      expect(() => parseClientSecret(bad)).toThrow(ProviderCredentialInvalidError);
    }
  });

  it('fingerprints identify a credential version without revealing it', () => {
    const a = credentialFingerprint({ clientId: 'client', credentialVersion: 1 });
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(
      credentialFingerprint({ clientId: 'client', privateKeyId: null, credentialVersion: 1 }),
    );
    expect(a).not.toBe(credentialFingerprint({ clientId: 'client', credentialVersion: 2 }));
    expect(a).not.toBe(
      credentialFingerprint({ clientId: 'client', privateKeyId: 'abc', credentialVersion: 1 }),
    );
    expect(shortFingerprint(a)).toBe(a.slice(0, 12));
  });
});
