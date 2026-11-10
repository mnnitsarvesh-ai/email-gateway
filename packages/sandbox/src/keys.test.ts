import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  artifactKeyId,
  generateArtifactKeyPair,
  parseArtifactPrivateKey,
  parseArtifactPublicKey,
  parseOptionalSymmetricKey,
  parseSymmetricKey,
  rawX25519PublicKey,
  SandboxKeyError,
  spkiDer,
  x25519PublicKeyFromRaw,
} from './keys';

const messageOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(SandboxKeyError);
    return (error as Error).message;
  }
  return 'no error';
};

describe('symmetric keys', () => {
  it('parses 64 hex characters or 32 bytes and refuses anything else without echoing it', () => {
    expect(parseSymmetricKey('K', 'ab'.repeat(32))).toEqual(Buffer.from('ab'.repeat(32), 'hex'));
    expect(parseSymmetricKey('K', 'AB'.repeat(32))).toHaveLength(32);
    const raw = Buffer.alloc(32, 7);
    const parsed = parseSymmetricKey('K', raw);
    expect(parsed).toEqual(raw);
    parsed.fill(0);
    expect(raw[0]).toBe(7); // a copy
    for (const bad of [
      '',
      'ab'.repeat(31),
      'ab'.repeat(33),
      'zz'.repeat(32),
      undefined,
      Buffer.alloc(31),
    ]) {
      const message = messageOf(() => parseSymmetricKey('SANDBOX_RESULT_KEY', bad));
      expect(message).toBe('SANDBOX_RESULT_KEY must be 32 bytes (64 hex characters)');
    }
  });

  it('parses an optional previous key, refusing one equal to the current key', () => {
    const current = parseSymmetricKey('K', 'ab'.repeat(32));
    expect(parseOptionalSymmetricKey('P', '', current)).toBeNull();
    expect(parseOptionalSymmetricKey('P', undefined, current)).toBeNull();
    expect(parseOptionalSymmetricKey('P', null, current)).toBeNull();
    expect(parseOptionalSymmetricKey('P', 'cd'.repeat(32), current)).toHaveLength(32);
    expect(messageOf(() => parseOptionalSymmetricKey('P', 'ab'.repeat(32), current))).toBe(
      'P must be empty or different from the current key',
    );
  });
});

describe('X25519 artifact keys', () => {
  it('generates a pair in the .env encodings and parses both halves', () => {
    const pair = generateArtifactKeyPair();
    expect(pair.privateKey).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pair.publicKey).toMatch(/^[A-Za-z0-9_-]+$/);
    const publicKey = parseArtifactPublicKey(pair.publicKey);
    const privateKey = parseArtifactPrivateKey(pair.privateKey);
    expect(publicKey.asymmetricKeyType).toBe('x25519');
    expect(privateKey.type).toBe('private');
    // The public half of the private key is the published public key.
    expect(spkiDer(createPublicKey(privateKey)).toString('base64url')).toBe(pair.publicKey);
    expect(Buffer.from(pair.publicKey, 'base64url')).toHaveLength(44);
    expect(rawX25519PublicKey(publicKey)).toHaveLength(32);
    expect(
      spkiDer(x25519PublicKeyFromRaw(rawX25519PublicKey(publicKey))).toString('base64url'),
    ).toBe(pair.publicKey);
    expect(artifactKeyId(publicKey)).toMatch(/^[0-9a-f]{8}$/);
    expect(artifactKeyId(parseArtifactPublicKey(generateArtifactKeyPair().publicKey))).not.toBe(
      artifactKeyId(publicKey),
    );
  });

  it('refuses malformed, swapped and non-X25519 keys, naming the key only', () => {
    const pair = generateArtifactKeyPair();
    const ed = generateKeyPairSync('ed25519');
    const edSpki = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const edPkcs8 = ed.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url');
    for (const bad of [undefined, '', 'not base64url!', 'AAAA', pair.privateKey, edSpki]) {
      expect(messageOf(() => parseArtifactPublicKey(bad))).toBe(
        'SANDBOX_ARTIFACT_PUBLIC_KEY must be an X25519 public key (SPKI DER, base64url)',
      );
    }
    for (const bad of [undefined, '', 'AAAA', pair.publicKey, edPkcs8]) {
      const message = messageOf(() => parseArtifactPrivateKey(bad));
      expect(message).toBe(
        'SANDBOX_ARTIFACT_PRIVATE_KEY must be an X25519 private key (PKCS#8 DER, base64url)',
      );
      if (bad) expect(message).not.toContain(bad);
    }
    expect(messageOf(() => x25519PublicKeyFromRaw(Buffer.alloc(31)))).toContain('32 raw bytes');
  });
});
