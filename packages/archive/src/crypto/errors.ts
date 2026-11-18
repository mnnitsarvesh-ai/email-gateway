/**
 * Why archive crypto failed: `malformed` (not the format, or invalid ids), `unauthentic` (no key
 * opens it, wrong ids/AAD, wrong kind or tampered, truncated, reordered or extended bytes),
 * `integrity` (decrypted, but the plaintext SHA-256 differs from the expected one). The error
 * carries no value, no key material, no id and no plaintext.
 */
export type ArchiveCryptoFailure = 'malformed' | 'unauthentic' | 'integrity';

export class ArchiveCryptoError extends Error {
  constructor(readonly reason: ArchiveCryptoFailure) {
    super(`Archive crypto operation failed (${reason})`);
    this.name = 'ArchiveCryptoError';
  }
}

/** A configured key is missing or malformed. Names the configuration key, never the value. */
export class ArchiveKeyConfigError extends Error {
  constructor(
    readonly keyName: string,
    expected: string,
  ) {
    super(`${keyName} must be ${expected}`);
    this.name = 'ArchiveKeyConfigError';
  }
}
