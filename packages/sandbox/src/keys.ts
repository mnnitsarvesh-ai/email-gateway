import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';

/**
 * Key material of the sandbox (step 4.6 X11, X12; docs/plan/steps/14-sandbox.md §5):
 *
 * - `SANDBOX_SAMPLE_KEY` / `SANDBOX_SAMPLE_KEY_PREVIOUS`: 32-byte key-encryption keys (64 hex) of
 *   the `sandbox-sample/1` envelope (email-worker seals, controller opens);
 * - `SANDBOX_RESULT_KEY`: the 32-byte (64 hex) HMAC key of the result MAC (email-worker and
 *   controller only);
 * - `SANDBOX_ARTIFACT_PUBLIC_KEY`: the X25519 public key (SPKI DER, base64url) the controller
 *   wraps artifact data keys to; `SANDBOX_ARTIFACT_PRIVATE_KEY`: its PKCS#8 DER private key
 *   (base64url), held by no service in 4.6 (tests and the `artifact:open` ops script only).
 *
 * Errors name the configuration key and the expected shape, never a value.
 */

export const SANDBOX_KEY_BYTES = 32;
/** DER prefix of an X25519 SubjectPublicKeyInfo (RFC 8410): the raw key follows (32 bytes). */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** A sandbox key is missing or malformed. Names the key, never the value. */
export class SandboxKeyError extends Error {
  constructor(
    readonly keyName: string,
    expected: string,
  ) {
    super(`${keyName} must be ${expected}`);
    this.name = 'SandboxKeyError';
  }
}

/** Parses a 32-byte symmetric key given as 64 hex characters (or a 32-byte Buffer). */
export function parseSymmetricKey(keyName: string, value: Buffer | string | undefined): Buffer {
  if (Buffer.isBuffer(value)) {
    if (value.length !== SANDBOX_KEY_BYTES) {
      throw new SandboxKeyError(keyName, '32 bytes (64 hex characters)');
    }
    return Buffer.from(value);
  }
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new SandboxKeyError(keyName, '32 bytes (64 hex characters)');
  }
  return Buffer.from(value, 'hex');
}

/**
 * Parses an optional previous symmetric key (rotation): empty/undefined → null. It must differ
 * from the current key.
 */
export function parseOptionalSymmetricKey(
  keyName: string,
  value: Buffer | string | null | undefined,
  current?: Buffer,
): Buffer | null {
  if (value === null || value === undefined || value === '') return null;
  const key = parseSymmetricKey(keyName, value);
  if (current && key.equals(current)) {
    throw new SandboxKeyError(keyName, 'empty or different from the current key');
  }
  return key;
}

const decodeBase64Url = (keyName: string, value: unknown, expected: string): Buffer => {
  if (typeof value !== 'string' || value.length === 0 || !BASE64URL.test(value)) {
    throw new SandboxKeyError(keyName, expected);
  }
  return Buffer.from(value, 'base64url');
};

const PUBLIC_EXPECTED = 'an X25519 public key (SPKI DER, base64url)';
const PRIVATE_EXPECTED = 'an X25519 private key (PKCS#8 DER, base64url)';

/** Parses `SANDBOX_ARTIFACT_PUBLIC_KEY` (X25519 SPKI DER, base64url). */
export function parseArtifactPublicKey(
  value: string | undefined,
  keyName = 'SANDBOX_ARTIFACT_PUBLIC_KEY',
): KeyObject {
  const der = decodeBase64Url(keyName, value, PUBLIC_EXPECTED);
  let key: KeyObject;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new SandboxKeyError(keyName, PUBLIC_EXPECTED);
  }
  if (key.asymmetricKeyType !== 'x25519') throw new SandboxKeyError(keyName, PUBLIC_EXPECTED);
  return key;
}

/** Parses `SANDBOX_ARTIFACT_PRIVATE_KEY` (X25519 PKCS#8 DER, base64url). */
export function parseArtifactPrivateKey(
  value: string | undefined,
  keyName = 'SANDBOX_ARTIFACT_PRIVATE_KEY',
): KeyObject {
  const der = decodeBase64Url(keyName, value, PRIVATE_EXPECTED);
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch {
    throw new SandboxKeyError(keyName, PRIVATE_EXPECTED);
  }
  if (key.asymmetricKeyType !== 'x25519') throw new SandboxKeyError(keyName, PRIVATE_EXPECTED);
  return key;
}

/** The SPKI DER of an X25519 public key. */
export function spkiDer(publicKey: KeyObject): Buffer {
  return publicKey.export({ format: 'der', type: 'spki' });
}

/** The raw 32-byte X25519 public key (the last 32 bytes of its SPKI DER, RFC 8410). */
export function rawX25519PublicKey(publicKey: KeyObject): Buffer {
  const der = spkiDer(publicKey);
  if (
    der.length !== X25519_SPKI_PREFIX.length + 32 ||
    !der.subarray(0, 12).equals(X25519_SPKI_PREFIX)
  ) {
    throw new SandboxKeyError('X25519 public key', 'an RFC 8410 X25519 key');
  }
  return der.subarray(X25519_SPKI_PREFIX.length);
}

/** The X25519 public key object of 32 raw bytes. */
export function x25519PublicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new SandboxKeyError('X25519 public key', '32 raw bytes');
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

/**
 * The key id of an artifact key pair: the first 8 hex characters of SHA-256 of its public SPKI
 * DER. It is carried in `wrappedKey` (`x1.<kid>.…`) and `sandbox_artifacts.key_id`, so tooling
 * picks the right private key after a rotation.
 */
export function artifactKeyId(publicKey: KeyObject): string {
  return createHash('sha256').update(spkiDer(publicKey)).digest('hex').slice(0, 8);
}

export interface ArtifactKeyPair {
  /** PKCS#8 DER, base64url (`SANDBOX_ARTIFACT_PRIVATE_KEY`). */
  privateKey: string;
  /** SPKI DER, base64url (`SANDBOX_ARTIFACT_PUBLIC_KEY`). */
  publicKey: string;
}

/** Generates an X25519 artifact key pair in the `.env` encodings (tests, `scripts/init-env.mjs`). */
export function generateArtifactKeyPair(): ArtifactKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return {
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url'),
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  };
}
