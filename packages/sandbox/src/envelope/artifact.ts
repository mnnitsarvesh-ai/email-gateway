import {
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
  randomBytes,
} from 'node:crypto';
import {
  ARTIFACT_KINDS,
  type ArtifactKind,
  SANDBOX_ARTIFACT_ALGORITHM,
} from '@email-gateway/security-contracts';
import { artifactKeyId, rawX25519PublicKey, x25519PublicKeyFromRaw } from '../keys';
import {
  base64UrlPart,
  DATA_KEY_BYTES,
  gcmDecrypt,
  gcmEncrypt,
  IV_BYTES,
  TAG_BYTES,
} from './aes-gcm';
import { SandboxEnvelopeError } from './errors';

/**
 * `sandbox-artifact/1` (step 4.6 X12, ADR-0040 decision 6): artifacts sealed by the controller
 * so that the controller itself can never open them again (a compromised controller cannot read
 * earlier artifacts).
 *
 *     object = "EGSBXA1" ‖ IV (12) ‖ tag (16) ‖ ciphertext
 *
 * - payload: AES-256-GCM under a fresh 32-byte data key, AAD
 *   `eg-sandbox-artifact/v1\0<taskId>\0<seq>\0<kind>`;
 * - key wrap: an ephemeral X25519 key pair per artifact; shared secret = X25519(ephemeral private,
 *   recipient public `SANDBOX_ARTIFACT_PUBLIC_KEY`); KEK = HKDF-SHA256(shared, salt = raw
 *   ephemeral public ‖ raw recipient public (32 + 32 bytes), info `eg-sandbox-artifact-kek/v1`,
 *   32 bytes); the data key AES-256-GCM-wrapped under the KEK with AAD = payload AAD + `\0dek`;
 * - `wrappedKey = x1.<kid>.<ephemeralPub>.<iv>.<tag>.<ct>` (base64url parts; `kid` = the first 8
 *   hex of SHA-256 of the recipient SPKI DER, `artifactKeyId`), ≤ 256 characters, stored only in
 *   the `sandbox_artifacts` row (crypto-shredding: null it, then delete the object).
 *
 * `openArtifact` needs the PKCS#8 private key, which no service holds in 4.6 (tests and the
 * `artifact:open` ops script only). Errors carry no detail.
 */

export const SANDBOX_ARTIFACT_MAGIC = Buffer.from('EGSBXA1', 'ascii');
const WRAP_VERSION = 'x1';
const HKDF_INFO = 'eg-sandbox-artifact-kek/v1';
const TASK_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const ARTIFACT_WRAPPED_KEY_PATTERN = /^x1\.[a-z0-9]{1,8}(\.[A-Za-z0-9_-]+){4}$/;
export const ARTIFACT_WRAPPED_KEY_MAX_LENGTH = 256;

export interface ArtifactIds {
  taskId: string;
  /** 0..15. */
  seq: number;
  kind: ArtifactKind;
}

export interface SealedArtifact {
  /** The S3 object body. */
  object: Buffer;
  /** `sandbox_artifacts.wrapped_key` / task_completed.v1 `artifacts[].wrappedKey`. */
  wrappedKey: string;
  keyId: string;
  algorithm: typeof SANDBOX_ARTIFACT_ALGORITHM;
  /** Hex SHA-256 of the sealed object and of the plaintext. */
  objectSha256: string;
  plainSha256: string;
  /** Plaintext size in bytes. */
  sizeBytes: number;
}

/** The payload AAD (X12). */
export function artifactAad(ids: ArtifactIds): string {
  if (
    !TASK_ID.test(ids.taskId) ||
    !Number.isInteger(ids.seq) ||
    ids.seq < 0 ||
    ids.seq > 15 ||
    !(ARTIFACT_KINDS as readonly string[]).includes(ids.kind)
  ) {
    throw new SandboxEnvelopeError('malformed');
  }
  return `eg-sandbox-artifact/v1\0${ids.taskId}\0${ids.seq}\0${ids.kind}`;
}

const sha256Hex = (value: Buffer): string => createHash('sha256').update(value).digest('hex');

function deriveKek(shared: Buffer, ephemeralRaw: Buffer, recipientRaw: Buffer): Buffer {
  return Buffer.from(
    hkdfSync(
      'sha256',
      shared,
      Buffer.concat([ephemeralRaw, recipientRaw]),
      Buffer.from(HKDF_INFO, 'utf8'),
      DATA_KEY_BYTES,
    ),
  );
}

/**
 * Seals one artifact to the recipient public key (`parseArtifactPublicKey`). The caller enforces
 * the artifact caps and kinds before sealing (X12).
 */
export function sealArtifact(
  recipientPublicKey: KeyObject,
  plaintext: Buffer,
  ids: ArtifactIds,
): SealedArtifact {
  if (recipientPublicKey.type !== 'public' || recipientPublicKey.asymmetricKeyType !== 'x25519') {
    throw new SandboxEnvelopeError('malformed');
  }
  const aad = artifactAad(ids);
  const recipientRaw = rawX25519PublicKey(recipientPublicKey);
  const kid = artifactKeyId(recipientPublicKey);
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralRaw = rawX25519PublicKey(ephemeral.publicKey);
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientPublicKey });
  const kek = deriveKek(shared, ephemeralRaw, recipientRaw);
  const dataKey = randomBytes(DATA_KEY_BYTES);
  try {
    const body = gcmEncrypt(dataKey, plaintext, aad);
    const object = Buffer.concat([SANDBOX_ARTIFACT_MAGIC, body.iv, body.tag, body.ciphertext]);
    const wrapped = gcmEncrypt(kek, dataKey, `${aad}\0dek`);
    const wrappedKey = [
      WRAP_VERSION,
      kid,
      ephemeralRaw.toString('base64url'),
      wrapped.iv.toString('base64url'),
      wrapped.tag.toString('base64url'),
      wrapped.ciphertext.toString('base64url'),
    ].join('.');
    return {
      object,
      wrappedKey,
      keyId: kid,
      algorithm: SANDBOX_ARTIFACT_ALGORITHM,
      objectSha256: sha256Hex(object),
      plainSha256: sha256Hex(plaintext),
      sizeBytes: plaintext.length,
    };
  } finally {
    dataKey.fill(0);
    kek.fill(0);
    shared.fill(0);
  }
}

/**
 * Opens a sealed artifact with the recipient private key (`parseArtifactPrivateKey`), its wrapped
 * key and ids. Throws `SandboxEnvelopeError` (`malformed`, `unauthentic`); a wrapped key for
 * another key pair (kid mismatch) is `unauthentic`.
 */
export function openArtifact(
  recipientPrivateKey: KeyObject,
  object: Buffer,
  wrappedKey: string,
  ids: ArtifactIds,
): Buffer {
  if (
    recipientPrivateKey.type !== 'private' ||
    recipientPrivateKey.asymmetricKeyType !== 'x25519'
  ) {
    throw new SandboxEnvelopeError('malformed');
  }
  const aad = artifactAad(ids);
  if (
    typeof wrappedKey !== 'string' ||
    wrappedKey.length > ARTIFACT_WRAPPED_KEY_MAX_LENGTH ||
    !ARTIFACT_WRAPPED_KEY_PATTERN.test(wrappedKey)
  ) {
    throw new SandboxEnvelopeError('malformed');
  }
  const [, kid, ephPart, ivPart, tagPart, ctPart] = wrappedKey.split('.') as [
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  const ephemeralRaw = base64UrlPart(ephPart);
  const wrapIv = base64UrlPart(ivPart);
  const wrapTag = base64UrlPart(tagPart);
  const wrapCt = base64UrlPart(ctPart);
  if (
    !ephemeralRaw ||
    !wrapIv ||
    !wrapTag ||
    !wrapCt ||
    ephemeralRaw.length !== 32 ||
    wrapIv.length !== IV_BYTES ||
    wrapTag.length !== TAG_BYTES ||
    wrapCt.length !== DATA_KEY_BYTES
  ) {
    throw new SandboxEnvelopeError('malformed');
  }
  const recipientPublic = createPublicKey(recipientPrivateKey);
  if (artifactKeyId(recipientPublic) !== kid) throw new SandboxEnvelopeError('unauthentic');
  let shared: Buffer;
  try {
    shared = diffieHellman({
      privateKey: recipientPrivateKey,
      publicKey: x25519PublicKeyFromRaw(ephemeralRaw),
    });
  } catch {
    throw new SandboxEnvelopeError('unauthentic');
  }
  const kek = deriveKek(shared, ephemeralRaw, rawX25519PublicKey(recipientPublic));
  shared.fill(0);
  const dataKey = gcmDecrypt(kek, wrapIv, wrapTag, wrapCt, `${aad}\0dek`);
  kek.fill(0);
  if (!dataKey) throw new SandboxEnvelopeError('unauthentic');
  try {
    const magic = SANDBOX_ARTIFACT_MAGIC.length;
    if (
      !Buffer.isBuffer(object) ||
      object.length < magic + IV_BYTES + TAG_BYTES ||
      !object.subarray(0, magic).equals(SANDBOX_ARTIFACT_MAGIC)
    ) {
      throw new SandboxEnvelopeError('malformed');
    }
    const plaintext = gcmDecrypt(
      dataKey,
      object.subarray(magic, magic + IV_BYTES),
      object.subarray(magic + IV_BYTES, magic + IV_BYTES + TAG_BYTES),
      object.subarray(magic + IV_BYTES + TAG_BYTES),
      aad,
    );
    if (!plaintext) throw new SandboxEnvelopeError('unauthentic');
    return plaintext;
  } finally {
    dataKey.fill(0);
  }
}
