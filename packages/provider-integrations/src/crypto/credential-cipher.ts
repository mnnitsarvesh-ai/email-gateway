import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
import { z } from 'zod';
import { isEmailAddress } from '../types';

/**
 * Provider credential custody (D5, ADR-0077): the webhook secret cipher's construction with the
 * dedicated key `PROVIDER_CREDENTIAL_ENCRYPTION_KEY` (and `_PREVIOUS`, decrypt only), output
 * `v1.<kid>.<iv>.<tag>.<ciphertext>` (base64url parts), AAD
 * `provider-credential:v1:<organizationId>:<connectionPublicId>:<grantPublicId>:<credentialVersion>`.
 * The api encrypts and never decrypts; the integration-worker (and any worker a later ADR adds)
 * decrypts. Errors carry no detail and never a value.
 *
 * Key ids: `k` + the first 7 hex characters of SHA-256(key), so the id stored in
 * `provider_connection_grants.credential_key_id` (VARCHAR(8)) tells the maintenance role which
 * rows are still under the previous key after a rotation, without revealing the key.
 */

const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_HEX = /^[0-9a-fA-F]{64}$/;
const PART = /^[A-Za-z0-9_-]+$/;
const KID = /^k[0-9a-f]{7}$/;

export type ProviderCredentialKeyName =
  'PROVIDER_CREDENTIAL_ENCRYPTION_KEY' | 'PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS';

/** Malformed key material at construction; names the key, never its value. */
export class ProviderCredentialKeyError extends Error {
  override readonly name = 'ProviderCredentialKeyError';
  constructor(key: ProviderCredentialKeyName, reason = 'must be 32 bytes (64 hex characters)') {
    super(`${key} ${reason}`);
  }
}

/** A malformed, tampered or undecryptable ciphertext, or one bound to another AAD. No detail. */
export class ProviderCredentialCipherError extends Error {
  override readonly name = 'ProviderCredentialCipherError';
  constructor() {
    super('Unable to decrypt the provider credential');
  }
}

/**
 * A credential document that does not match its method's strict schema. `field` names the
 * offending field (never its value), for the api's `credential_invalid` error.
 */
export class ProviderCredentialInvalidError extends Error {
  override readonly name = 'ProviderCredentialInvalidError';
  constructor(readonly field: string) {
    super(`Invalid provider credential: ${field}`);
  }
}

export interface CredentialAadParts {
  organizationId: string | number | bigint;
  connectionPublicId: string;
  grantPublicId: string;
  credentialVersion: number;
}

/** The row-bound AAD (ADR-0077 decision 1): a ciphertext copied to another row never decrypts. */
export function credentialAad(parts: CredentialAadParts): string {
  return (
    `provider-credential:v1:${String(parts.organizationId)}:${parts.connectionPublicId}:` +
    `${parts.grantPublicId}:${parts.credentialVersion}`
  );
}

/** `k` + 7 hex characters of SHA-256 of the raw key. */
export function credentialKeyId(keyHex: string): string {
  return `k${createHash('sha256').update(Buffer.from(keyHex, 'hex')).digest('hex').slice(0, 7)}`;
}

export interface ProviderCredentialCipherKeys {
  /** `PROVIDER_CREDENTIAL_ENCRYPTION_KEY`: 64 hex characters (encrypts and decrypts). */
  key: string;
  /** `PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS`: decrypts only (rotation). */
  previousKey?: string | null;
}

export interface EncryptedCredential {
  ciphertext: string;
  /** The `credential_key_id` to store with the ciphertext. */
  keyId: string;
}

export interface DecryptedCredentialText {
  plaintext: string;
  keyId: string;
  /** Only the previous key could decrypt it: re-encrypt with the current key and store. */
  usedPreviousKey: boolean;
}

export class ProviderCredentialCipher {
  private readonly current: Buffer;
  private readonly previous: Buffer | undefined;
  readonly currentKeyId: string;
  readonly previousKeyId: string | null;

  constructor(keys: ProviderCredentialCipherKeys) {
    if (typeof keys.key !== 'string' || !KEY_HEX.test(keys.key)) {
      throw new ProviderCredentialKeyError('PROVIDER_CREDENTIAL_ENCRYPTION_KEY');
    }
    if (keys.previousKey && !KEY_HEX.test(keys.previousKey)) {
      throw new ProviderCredentialKeyError('PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS');
    }
    if (keys.previousKey && keys.previousKey.toLowerCase() === keys.key.toLowerCase()) {
      throw new ProviderCredentialKeyError(
        'PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS',
        'must differ from PROVIDER_CREDENTIAL_ENCRYPTION_KEY',
      );
    }
    this.current = Buffer.from(keys.key, 'hex');
    this.currentKeyId = credentialKeyId(keys.key);
    this.previous = keys.previousKey ? Buffer.from(keys.previousKey, 'hex') : undefined;
    this.previousKeyId = keys.previousKey ? credentialKeyId(keys.previousKey) : null;
  }

  /** From the two configuration keys (empty previous = none). */
  static fromConfig(config: {
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY: string;
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS?: string | null | undefined;
  }): ProviderCredentialCipher {
    return new ProviderCredentialCipher({
      key: config.PROVIDER_CREDENTIAL_ENCRYPTION_KEY,
      previousKey: config.PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS || null,
    });
  }

  encrypt(plaintext: string, aad: string): EncryptedCredential {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.current, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return {
      ciphertext: [
        VERSION,
        this.currentKeyId,
        iv.toString('base64url'),
        cipher.getAuthTag().toString('base64url'),
        ciphertext.toString('base64url'),
      ].join('.'),
      keyId: this.currentKeyId,
    };
  }

  /** Throws `ProviderCredentialCipherError` for anything but an intact ciphertext of this AAD. */
  decrypt(payload: string, aad: string): DecryptedCredentialText {
    const parts = typeof payload === 'string' ? payload.split('.') : [];
    if (parts.length !== 5) throw new ProviderCredentialCipherError();
    const [version, kid, ivPart, tagPart, ctPart] = parts as [
      string,
      string,
      string,
      string,
      string,
    ];
    if (version !== VERSION || !KID.test(kid)) throw new ProviderCredentialCipherError();
    if (![ivPart, tagPart, ctPart].every((p) => PART.test(p))) {
      throw new ProviderCredentialCipherError();
    }
    const iv = Buffer.from(ivPart, 'base64url');
    const tag = Buffer.from(tagPart, 'base64url');
    const ciphertext = Buffer.from(ctPart, 'base64url');
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES)
      throw new ProviderCredentialCipherError();

    // The kid selects the key; an unknown kid still tries both (a key may have been renamed).
    const order: { key: Buffer; id: string; previous: boolean }[] = [
      { key: this.current, id: this.currentKeyId, previous: false },
    ];
    if (this.previous && this.previousKeyId) {
      const prev = { key: this.previous, id: this.previousKeyId, previous: true };
      if (kid === this.previousKeyId) order.unshift(prev);
      else order.push(prev);
    }
    for (const candidate of order) {
      const plaintext = open(candidate.key, iv, tag, ciphertext, aad);
      if (plaintext !== undefined) {
        return { plaintext, keyId: candidate.id, usedPreviousKey: candidate.previous };
      }
    }
    throw new ProviderCredentialCipherError();
  }

  /** Encrypts a credential document after validating it against its method's strict schema. */
  encryptCredential(
    credential: ProviderCredential,
    parts: CredentialAadParts,
  ): EncryptedCredential {
    const normalized = normalizeCredential(credential);
    return this.encrypt(JSON.stringify(normalized), credentialAad(parts));
  }

  /** Decrypts and validates a stored credential document. */
  decryptCredential(
    payload: string,
    parts: CredentialAadParts,
  ): { credential: ProviderCredential; keyId: string; usedPreviousKey: boolean } {
    const opened = this.decrypt(payload, credentialAad(parts));
    let json: unknown;
    try {
      json = JSON.parse(opened.plaintext);
    } catch {
      throw new ProviderCredentialCipherError();
    }
    const parsed = storedCredentialSchema.safeParse(json);
    if (!parsed.success) throw new ProviderCredentialCipherError();
    return {
      credential: parsed.data,
      keyId: opened.keyId,
      usedPreviousKey: opened.usedPreviousKey,
    };
  }
}

function open(
  key: Buffer,
  iv: Buffer,
  tag: Buffer,
  ciphertext: Buffer,
  aad: string,
): string | undefined {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------------------------
// Strict plaintext documents per method (D5).
// ---------------------------------------------------------------------------------------------

/** `customer_app_secret`: `{ clientSecret }`. */
export interface CustomerAppSecretCredential {
  method: 'customer_app_secret';
  clientSecret: string;
}

/**
 * `customer_service_account` (and the platform service-account key file): exactly the fields
 * the JWT bearer flow needs; every other field of an uploaded key file is dropped.
 */
export interface ServiceAccountKey {
  type: 'service_account';
  client_email: string;
  private_key: string;
  private_key_id: string;
  token_uri: string;
  /** Numeric OAuth client id (shown for domain-wide delegation); optional in uploads. */
  client_id?: string;
}

export interface CustomerServiceAccountCredential {
  method: 'customer_service_account';
  key: ServiceAccountKey;
}

export type ProviderCredential = CustomerAppSecretCredential | CustomerServiceAccountCredential;

const clientSecretSchema = z
  .string()
  .min(8)
  .max(1024)
  .refine(
    (v) => ![...v].some((c) => c.charCodeAt(0) < 0x21 || c.charCodeAt(0) === 0x7f),
    'no whitespace or control characters',
  );

const serviceAccountKeyShape = z.object({
  type: z.literal('service_account'),
  client_email: z
    .string()
    .max(320)
    .refine(isEmailAddress, 'client_email must be an e-mail address'),
  private_key: z.string().min(100).max(8192),
  private_key_id: z.string().regex(/^[0-9a-f]{8,64}$/i),
  token_uri: z.string().url().max(512),
  client_id: z
    .string()
    .regex(/^[0-9]{6,32}$/)
    .optional(),
});

const storedCredentialSchema = z.discriminatedUnion('method', [
  z.object({ method: z.literal('customer_app_secret'), clientSecret: clientSecretSchema }),
  z.object({ method: z.literal('customer_service_account'), key: serviceAccountKeyShape }),
]);

/** The minimum RSA modulus accepted for service-account keys. */
const MIN_RSA_BITS = 2048;

function privateKeyObject(pem: string): KeyObject {
  try {
    return createPrivateKey({ key: pem, format: 'pem' });
  } catch {
    throw new ProviderCredentialInvalidError('private_key');
  }
}

/**
 * Parses an uploaded (or operator-provided) Google service-account key file (D5): strict on the
 * fields it keeps (`type`, `client_email`, `private_key`, `private_key_id`, `token_uri`,
 * optional `client_id`), drops every other field, requires `token_uri` to equal the configured
 * `PROVIDER_GOOGLE_TOKEN_URL` and the key to be an RSA private key of ≥ 2048 bits.
 */
export function parseServiceAccountKey(
  input: unknown,
  options: { tokenUrl: string },
): ServiceAccountKey {
  if (typeof input === 'string') {
    try {
      input = JSON.parse(input);
    } catch {
      throw new ProviderCredentialInvalidError('serviceAccountKey');
    }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new ProviderCredentialInvalidError('serviceAccountKey');
  }
  const parsed = serviceAccountKeyShape.safeParse(input);
  if (!parsed.success) {
    const field = parsed.error.issues[0]?.path[0];
    throw new ProviderCredentialInvalidError(
      typeof field === 'string' ? field : 'serviceAccountKey',
    );
  }
  const key = parsed.data;
  if (normalizeUrl(key.token_uri) !== normalizeUrl(options.tokenUrl)) {
    throw new ProviderCredentialInvalidError('token_uri');
  }
  const object = privateKeyObject(key.private_key);
  if (
    object.asymmetricKeyType !== 'rsa' ||
    (object.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS
  ) {
    throw new ProviderCredentialInvalidError('private_key');
  }
  return {
    type: 'service_account',
    client_email: key.client_email.toLowerCase(),
    private_key: key.private_key,
    private_key_id: key.private_key_id.toLowerCase(),
    token_uri: key.token_uri,
    ...(key.client_id ? { client_id: key.client_id } : {}),
  };
}

const normalizeUrl = (value: string): string => value.trim().replace(/\/+$/, '');

/** Validates a client secret for `customer_app_secret` (no echo of the value in errors). */
export function parseClientSecret(input: unknown): CustomerAppSecretCredential {
  const parsed = clientSecretSchema.safeParse(input);
  if (!parsed.success) throw new ProviderCredentialInvalidError('clientSecret');
  return { method: 'customer_app_secret', clientSecret: parsed.data };
}

function normalizeCredential(credential: ProviderCredential): ProviderCredential {
  const parsed = storedCredentialSchema.safeParse(credential);
  if (!parsed.success) {
    const path = parsed.error.issues[0]?.path;
    throw new ProviderCredentialInvalidError(
      path && path.length > 0 ? String(path.at(-1)) : 'credential',
    );
  }
  if (parsed.data.method === 'customer_service_account') {
    privateKeyObject(parsed.data.key.private_key);
  }
  return parsed.data;
}

/**
 * `credential_fingerprint` (D5): lower-case hex SHA-256 of
 * `clientId|<private_key_id or "secret">|credentialVersion`. It identifies a credential version
 * without revealing anything about the secret.
 */
export function credentialFingerprint(input: {
  clientId: string;
  privateKeyId?: string | null;
  credentialVersion: number;
}): string {
  return createHash('sha256')
    .update(
      `${input.clientId}|${input.privateKeyId || 'secret'}|${input.credentialVersion}`,
      'utf8',
    )
    .digest('hex');
}

/** The 12-character form shown in api responses (`credentialFingerprint`). */
export const shortFingerprint = (fingerprint: string): string => fingerprint.slice(0, 12);
