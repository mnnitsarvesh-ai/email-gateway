import { parseSecretBox, openSecretBox, sealSecretBox, DATA_KEY_BYTES } from './secret-box';
import { ArchiveCryptoError, ArchiveKeyConfigError } from './errors';

/**
 * The root of the archive key hierarchy (A8, ADR-0065): `ARCHIVE_ROOT_KEY` (32 bytes, 64 hex,
 * id `ARCHIVE_ROOT_KEY_ID`) wraps tenant key versions; `ARCHIVE_ROOT_KEY_PREVIOUS` /
 * `_PREVIOUS_ID` only unwrap during a root rotation. Held by the archive-worker and the api only.
 *
 * `ArchiveRootKeyProvider` is the seam for an AWS KMS implementation (step 10.1); its methods are
 * asynchronous for that reason.
 */

export const ROOT_KEY_ID_PATTERN = /^[a-z][a-z0-9]{0,15}$/;
const HEX_64 = /^[0-9a-fA-F]{64}$/;

export interface RootUnwrapResult {
  key: Buffer;
  /** The root key id named in the wrapped value. */
  rootKeyId: string;
  /** Only the previous root key opened it: re-wrap under the current key (A9). */
  usedPreviousKey: boolean;
}

export interface ArchiveRootKeyProvider {
  /** Id written into new wrapped values and `archive_encryption_keys.root_key_id`. */
  readonly currentKeyId: string;
  /** The previous id during a rotation (null otherwise). */
  readonly previousKeyId: string | null;
  /** Wraps a 32-byte key under the current root key: `v1.<rootKid>.<iv>.<tag>.<ct>`. */
  wrap(plaintextKey: Buffer, aad: string): Promise<string>;
  /** Unwraps with the key its kid names (current or previous); throws `ArchiveCryptoError`. */
  unwrap(wrapped: string, aad: string): Promise<RootUnwrapResult>;
}

export interface ArchiveRootKeyConfig {
  ARCHIVE_ROOT_KEY: string;
  ARCHIVE_ROOT_KEY_ID?: string | undefined;
  ARCHIVE_ROOT_KEY_PREVIOUS?: string | null | undefined;
  ARCHIVE_ROOT_KEY_PREVIOUS_ID?: string | null | undefined;
}

export interface ParsedRootKeys {
  current: { id: string; key: Buffer };
  previous: { id: string; key: Buffer } | null;
}

/** Parses and cross-checks the root key configuration; errors name keys, never values. */
export function parseArchiveRootKeys(config: ArchiveRootKeyConfig): ParsedRootKeys {
  const currentId = config.ARCHIVE_ROOT_KEY_ID ?? 'r1';
  if (typeof config.ARCHIVE_ROOT_KEY !== 'string' || !HEX_64.test(config.ARCHIVE_ROOT_KEY)) {
    throw new ArchiveKeyConfigError('ARCHIVE_ROOT_KEY', '32 bytes (64 hex characters)');
  }
  if (!ROOT_KEY_ID_PATTERN.test(currentId)) {
    throw new ArchiveKeyConfigError(
      'ARCHIVE_ROOT_KEY_ID',
      'a lower-case id (^[a-z][a-z0-9]{0,15}$)',
    );
  }
  const current = { id: currentId, key: Buffer.from(config.ARCHIVE_ROOT_KEY, 'hex') };
  const prevKey = config.ARCHIVE_ROOT_KEY_PREVIOUS || null;
  const prevId = config.ARCHIVE_ROOT_KEY_PREVIOUS_ID || null;
  if (prevKey === null && prevId === null) return { current, previous: null };
  if (prevKey === null || prevId === null) {
    throw new ArchiveKeyConfigError(
      prevKey === null ? 'ARCHIVE_ROOT_KEY_PREVIOUS' : 'ARCHIVE_ROOT_KEY_PREVIOUS_ID',
      'set together with its pair (ARCHIVE_ROOT_KEY_PREVIOUS and ARCHIVE_ROOT_KEY_PREVIOUS_ID)',
    );
  }
  if (!HEX_64.test(prevKey)) {
    throw new ArchiveKeyConfigError('ARCHIVE_ROOT_KEY_PREVIOUS', '32 bytes (64 hex characters)');
  }
  if (!ROOT_KEY_ID_PATTERN.test(prevId)) {
    throw new ArchiveKeyConfigError(
      'ARCHIVE_ROOT_KEY_PREVIOUS_ID',
      'a lower-case id (^[a-z][a-z0-9]{0,15}$)',
    );
  }
  const previous = { id: prevId, key: Buffer.from(prevKey, 'hex') };
  if (previous.key.equals(current.key)) {
    throw new ArchiveKeyConfigError('ARCHIVE_ROOT_KEY_PREVIOUS', 'different from ARCHIVE_ROOT_KEY');
  }
  if (previous.id === current.id) {
    throw new ArchiveKeyConfigError(
      'ARCHIVE_ROOT_KEY_PREVIOUS_ID',
      'different from ARCHIVE_ROOT_KEY_ID',
    );
  }
  return { current, previous };
}

/** The configuration-key implementation of `ArchiveRootKeyProvider` (A8, A30). */
export class LocalRootKeyProvider implements ArchiveRootKeyProvider {
  readonly currentKeyId: string;
  readonly previousKeyId: string | null;
  private readonly current: Buffer;
  private readonly previous: Buffer | null;

  constructor(keys: ParsedRootKeys) {
    this.currentKeyId = keys.current.id;
    this.current = Buffer.from(keys.current.key);
    this.previousKeyId = keys.previous?.id ?? null;
    this.previous = keys.previous ? Buffer.from(keys.previous.key) : null;
  }

  static fromConfig(config: ArchiveRootKeyConfig): LocalRootKeyProvider {
    return new LocalRootKeyProvider(parseArchiveRootKeys(config));
  }

  wrap(plaintextKey: Buffer, aad: string): Promise<string> {
    if (!Buffer.isBuffer(plaintextKey) || plaintextKey.length !== DATA_KEY_BYTES) {
      return Promise.reject(new ArchiveCryptoError('malformed'));
    }
    try {
      return Promise.resolve(sealSecretBox(this.current, this.currentKeyId, plaintextKey, aad));
    } catch (error) {
      return Promise.reject(error instanceof Error ? error : new ArchiveCryptoError('malformed'));
    }
  }

  unwrap(wrapped: string, aad: string): Promise<RootUnwrapResult> {
    try {
      const box = parseSecretBox(wrapped);
      let key: Buffer | null = null;
      let usedPreviousKey = false;
      if (box.kid === this.currentKeyId) key = this.current;
      else if (this.previous && box.kid === this.previousKeyId) {
        key = this.previous;
        usedPreviousKey = true;
      }
      if (key === null) throw new ArchiveCryptoError('unauthentic');
      const plain = openSecretBox(key, box, aad);
      if (plain === null || plain.length !== DATA_KEY_BYTES) {
        throw new ArchiveCryptoError('unauthentic');
      }
      return Promise.resolve({ key: plain, rootKeyId: box.kid, usedPreviousKey });
    } catch (error) {
      return Promise.reject(
        error instanceof ArchiveCryptoError ? error : new ArchiveCryptoError('malformed'),
      );
    }
  }
}
