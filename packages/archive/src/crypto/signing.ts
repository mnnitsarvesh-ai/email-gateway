import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
  verify,
} from 'node:crypto';
import { ArchiveKeyConfigError } from './errors';

/**
 * Ed25519 signatures of export manifests (A18, §4.2): `manifest.sig` = base64url Ed25519 over the
 * exact `manifest.json` bytes. Keys: `ARCHIVE_EXPORT_SIGNING_KEY` (PKCS#8 DER, base64url, worker
 * only), `ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY` (SPKI DER, base64url, api), ids
 * `^[a-z][a-z0-9]{0,15}$`. Parse errors name the configuration key, never the value.
 */

const BASE64URL = /^[A-Za-z0-9_-]+$/;
export const SIGNING_KEY_ID_PATTERN = /^[a-z][a-z0-9]{0,15}$/;
const PRIVATE_EXPECTED = 'an Ed25519 private key (PKCS#8 DER, base64url)';
const PUBLIC_EXPECTED = 'an Ed25519 public key (SPKI DER, base64url)';

function der(keyName: string, value: unknown, expected: string): Buffer {
  if (typeof value !== 'string' || value.length === 0 || !BASE64URL.test(value)) {
    throw new ArchiveKeyConfigError(keyName, expected);
  }
  return Buffer.from(value, 'base64url');
}

export function parseExportSigningPrivateKey(
  value: string | undefined,
  keyName = 'ARCHIVE_EXPORT_SIGNING_KEY',
): KeyObject {
  const bytes = der(keyName, value, PRIVATE_EXPECTED);
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' });
  } catch {
    throw new ArchiveKeyConfigError(keyName, PRIVATE_EXPECTED);
  }
  if (key.asymmetricKeyType !== 'ed25519')
    throw new ArchiveKeyConfigError(keyName, PRIVATE_EXPECTED);
  return key;
}

export function parseExportSigningPublicKey(
  value: string | undefined,
  keyName = 'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY',
): KeyObject {
  const bytes = der(keyName, value, PUBLIC_EXPECTED);
  let key: KeyObject;
  try {
    key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
  } catch {
    throw new ArchiveKeyConfigError(keyName, PUBLIC_EXPECTED);
  }
  if (key.asymmetricKeyType !== 'ed25519')
    throw new ArchiveKeyConfigError(keyName, PUBLIC_EXPECTED);
  return key;
}

export function parseSigningKeyId(value: string | undefined, keyName: string): string {
  if (typeof value !== 'string' || !SIGNING_KEY_ID_PATTERN.test(value)) {
    throw new ArchiveKeyConfigError(keyName, 'a lower-case id (^[a-z][a-z0-9]{0,15}$)');
  }
  return value;
}

export interface ExportVerificationKey {
  id: string;
  /** SPKI DER, base64url (as published by `GET /archive/export-signing-keys`). */
  publicKey: string;
  key: KeyObject;
}

/**
 * Parses `ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS` (`id:key,id:key`, empty = none). Ids must
 * be unique; errors name the entry position, never a value.
 */
export function parsePreviousSigningPublicKeys(
  value: string | undefined,
  keyName = 'ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS',
): ExportVerificationKey[] {
  if (value === undefined || value.trim() === '') return [];
  const seen = new Set<string>();
  return value.split(',').map((raw, index) => {
    const entry = raw.trim();
    const at = entry.indexOf(':');
    const name = `${keyName} entry ${index + 1}`;
    if (at <= 0) throw new ArchiveKeyConfigError(name, 'id:key');
    const id = parseSigningKeyId(entry.slice(0, at), name);
    if (seen.has(id)) throw new ArchiveKeyConfigError(name, 'a unique id');
    seen.add(id);
    const publicKey = entry.slice(at + 1);
    return { id, publicKey, key: parseExportSigningPublicKey(publicKey, name) };
  });
}

export interface ExportSigningKeyPair {
  /** PKCS#8 DER, base64url (`ARCHIVE_EXPORT_SIGNING_KEY`). */
  privateKey: string;
  /** SPKI DER, base64url (`ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY`). */
  publicKey: string;
}

/** A fresh Ed25519 pair in the `.env` encodings (tests and tooling). */
export function generateExportSigningKeyPair(): ExportSigningKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url'),
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  };
}

/** The SPKI DER (base64url) of a key object's public half. */
export function exportSigningPublicKeyOf(key: KeyObject): string {
  const pub = key.type === 'private' ? createPublicKey(key) : key;
  return pub.export({ format: 'der', type: 'spki' }).toString('base64url');
}

/** Ed25519 signature (base64url) over the exact manifest bytes. */
export function signManifest(manifestBytes: Buffer, privateKey: KeyObject): string {
  return sign(null, manifestBytes, privateKey).toString('base64url');
}

/** True only for a canonical base64url Ed25519 signature of these exact bytes. */
export function verifyManifestSignature(
  manifestBytes: Buffer,
  signature: string,
  publicKey: KeyObject,
): boolean {
  if (typeof signature !== 'string' || !BASE64URL.test(signature.trim())) return false;
  const sig = Buffer.from(signature.trim(), 'base64url');
  if (sig.length !== 64 || sig.toString('base64url') !== signature.trim()) return false;
  try {
    return verify(null, manifestBytes, publicKey, sig);
  } catch {
    return false;
  }
}
