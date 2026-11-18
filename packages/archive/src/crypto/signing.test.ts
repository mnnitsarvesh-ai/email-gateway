import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ArchiveKeyConfigError } from './errors';
import {
  exportSigningPublicKeyOf,
  generateExportSigningKeyPair,
  parseExportSigningPrivateKey,
  parseExportSigningPublicKey,
  parsePreviousSigningPublicKeys,
  parseSigningKeyId,
  signManifest,
  verifyManifestSignature,
} from './signing';

const pair = generateExportSigningKeyPair();
const privateKey = parseExportSigningPrivateKey(pair.privateKey);
const publicKey = parseExportSigningPublicKey(pair.publicKey);
const manifest = Buffer.from('{"version":"archive-export-manifest/1"}');

function keyName(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof ArchiveKeyConfigError) return error.keyName;
    throw error;
  }
  return 'parsed';
}

describe('Ed25519 manifest signatures', () => {
  it('signs and verifies the exact bytes', () => {
    const sig = signManifest(manifest, privateKey);
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(verifyManifestSignature(manifest, sig, publicKey)).toBe(true);
    expect(exportSigningPublicKeyOf(privateKey)).toBe(pair.publicKey);
    expect(exportSigningPublicKeyOf(publicKey)).toBe(pair.publicKey);
  });

  it('fails for other bytes, another key and a tampered or non-canonical signature', () => {
    const sig = signManifest(manifest, privateKey);
    expect(
      verifyManifestSignature(Buffer.concat([manifest, Buffer.from(' ')]), sig, publicKey),
    ).toBe(false);
    const other = parseExportSigningPublicKey(generateExportSigningKeyPair().publicKey);
    expect(verifyManifestSignature(manifest, sig, other)).toBe(false);
    const bytes = Buffer.from(sig, 'base64url');
    bytes[0] = bytes[0]! ^ 1;
    expect(verifyManifestSignature(manifest, bytes.toString('base64url'), publicKey)).toBe(false);
    expect(verifyManifestSignature(manifest, `${sig}A`, publicKey)).toBe(false);
    expect(verifyManifestSignature(manifest, sig.slice(0, 40), publicKey)).toBe(false);
    expect(verifyManifestSignature(manifest, '', publicKey)).toBe(false);
  });

  it('parses keys and names the configuration key on errors, never the value', () => {
    expect(keyName(() => parseExportSigningPrivateKey(undefined))).toBe(
      'ARCHIVE_EXPORT_SIGNING_KEY',
    );
    expect(keyName(() => parseExportSigningPrivateKey(pair.publicKey))).toBe(
      'ARCHIVE_EXPORT_SIGNING_KEY',
    );
    expect(keyName(() => parseExportSigningPublicKey('not+base64'))).toBe(
      'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY',
    );
    const x = generateKeyPairSync('x25519');
    const xPub = x.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    expect(keyName(() => parseExportSigningPublicKey(xPub))).toBe(
      'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY',
    );
    try {
      parseExportSigningPrivateKey(pair.publicKey);
    } catch (error) {
      expect((error as Error).message).not.toContain(pair.publicKey);
    }
    expect(parseSigningKeyId('es1', 'ARCHIVE_EXPORT_SIGNING_KEY_ID')).toBe('es1');
    expect(keyName(() => parseSigningKeyId('ES1', 'ARCHIVE_EXPORT_SIGNING_KEY_ID'))).toBe(
      'ARCHIVE_EXPORT_SIGNING_KEY_ID',
    );
  });

  it('parses the previous public keys list', () => {
    const prev = generateExportSigningKeyPair();
    expect(parsePreviousSigningPublicKeys(undefined)).toEqual([]);
    expect(parsePreviousSigningPublicKeys(' ')).toEqual([]);
    const list = parsePreviousSigningPublicKeys(`es0:${prev.publicKey}, es1:${pair.publicKey}`);
    expect(list.map((k) => k.id)).toEqual(['es0', 'es1']);
    expect(list[0]!.publicKey).toBe(prev.publicKey);
    expect(
      keyName(() => parsePreviousSigningPublicKeys(`es0:${prev.publicKey},es0:${pair.publicKey}`)),
    ).toBe('ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS entry 2');
    expect(keyName(() => parsePreviousSigningPublicKeys('nokey'))).toBe(
      'ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS entry 1',
    );
  });
});
