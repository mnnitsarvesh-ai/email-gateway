import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  type Hash,
  timingSafeEqual,
} from 'node:crypto';
import { Transform, type TransformCallback } from 'node:stream';
import { ArchiveCryptoError } from './errors';
import {
  ARCHIVE_OBJECT_KINDS,
  type ArchiveObjectKind,
  deriveObjectKey,
  type ObjectKeyContext,
  OBJECT_SALT_BYTES,
} from './keys';
import { GCM_TAG_BYTES } from './secret-box';

/**
 * `archive-object/1` (A8, ADR-0065): a chunked AES-256-GCM stream.
 *
 *     header = "EGARC1" ‖ 0x01 ‖ kind (1 eml, 2 journal, 3 scan, 4 export) ‖ chunk size (u32 BE)
 *              ‖ salt (32) ‖ nonce prefix (7)                                     = 51 bytes
 *     chunk  = AES-256-GCM(objectKey, nonce = prefix ‖ counter (u32 BE) ‖ final (1 byte),
 *              AAD = header) → ciphertext ‖ tag (16)
 *
 * The object key is HKDF-SHA256(DEK, salt, `eg-archive-object/v1\0<kind>\0<org>\0<subject>`).
 * Every chunk but the last carries exactly `chunk size` plaintext bytes; the last carries 0 …
 * `chunk size` bytes and the final flag 1 (an empty plaintext is one empty final chunk). So
 * truncation (at or inside a chunk), reordering, extension, a changed header or a wrong
 * key/kind/organization/subject all fail authentication. Both directions stream with memory
 * bounded by one chunk.
 */

export const ARCHIVE_OBJECT_MAGIC = Buffer.from('EGARC1', 'ascii');
export const ARCHIVE_OBJECT_FORMAT_VERSION = 0x01;
export const ARCHIVE_OBJECT_HEADER_BYTES = 51;
export const ARCHIVE_NONCE_PREFIX_BYTES = 7;
export const ARCHIVE_DEFAULT_CHUNK_BYTES = 65_536;
/** Bounds of `ARCHIVE_CHUNK_BYTES` (16 KiB – 1 MiB); a header outside them is refused. */
export const ARCHIVE_CHUNK_MIN_BYTES = 16_384;
export const ARCHIVE_CHUNK_MAX_BYTES = 1_048_576;
/** Content type of every archive object (§4.1). */
export const ARCHIVE_OBJECT_CONTENT_TYPE = 'application/octet-stream';

const KIND_CODES: Record<ArchiveObjectKind, number> = { eml: 1, journal: 2, scan: 3, export: 4 };
const MAX_CHUNKS = 0xffff_ffff;

export function archiveObjectKindCode(kind: ArchiveObjectKind): number {
  return KIND_CODES[kind];
}

export interface ArchiveObjectHeader {
  kind: ArchiveObjectKind;
  chunkBytes: number;
  salt: Buffer;
  noncePrefix: Buffer;
  bytes: Buffer;
}

function buildHeader(kind: ArchiveObjectKind, chunkBytes: number): ArchiveObjectHeader {
  const salt = randomBytes(OBJECT_SALT_BYTES);
  const noncePrefix = randomBytes(ARCHIVE_NONCE_PREFIX_BYTES);
  const bytes = Buffer.alloc(ARCHIVE_OBJECT_HEADER_BYTES);
  ARCHIVE_OBJECT_MAGIC.copy(bytes, 0);
  bytes.writeUInt8(ARCHIVE_OBJECT_FORMAT_VERSION, 6);
  bytes.writeUInt8(KIND_CODES[kind], 7);
  bytes.writeUInt32BE(chunkBytes, 8);
  salt.copy(bytes, 12);
  noncePrefix.copy(bytes, 44);
  return { kind, chunkBytes, salt, noncePrefix, bytes };
}

/** Parses and bounds-checks a header; throws `malformed` (a kind mismatch is `unauthentic`). */
export function parseArchiveObjectHeader(
  bytes: Buffer,
  expectedKind?: ArchiveObjectKind,
): ArchiveObjectHeader {
  if (bytes.length < ARCHIVE_OBJECT_HEADER_BYTES) throw new ArchiveCryptoError('malformed');
  const header = Buffer.from(bytes.subarray(0, ARCHIVE_OBJECT_HEADER_BYTES));
  if (!header.subarray(0, 6).equals(ARCHIVE_OBJECT_MAGIC))
    throw new ArchiveCryptoError('malformed');
  if (header.readUInt8(6) !== ARCHIVE_OBJECT_FORMAT_VERSION) {
    throw new ArchiveCryptoError('malformed');
  }
  const code = header.readUInt8(7);
  const kind = ARCHIVE_OBJECT_KINDS.find((k) => KIND_CODES[k] === code);
  if (kind === undefined) throw new ArchiveCryptoError('malformed');
  if (expectedKind !== undefined && kind !== expectedKind) {
    throw new ArchiveCryptoError('unauthentic');
  }
  const chunkBytes = header.readUInt32BE(8);
  if (chunkBytes < ARCHIVE_CHUNK_MIN_BYTES || chunkBytes > ARCHIVE_CHUNK_MAX_BYTES) {
    throw new ArchiveCryptoError('malformed');
  }
  return {
    kind,
    chunkBytes,
    salt: Buffer.from(header.subarray(12, 44)),
    noncePrefix: Buffer.from(header.subarray(44, 51)),
    bytes: header,
  };
}

function nonce(prefix: Buffer, counter: number, final: boolean): Buffer {
  const n = Buffer.alloc(12);
  prefix.copy(n, 0);
  n.writeUInt32BE(counter, 7);
  n.writeUInt8(final ? 1 : 0, 11);
  return n;
}

function sealChunk(
  key: Buffer,
  header: ArchiveObjectHeader,
  counter: number,
  final: boolean,
  plain: Buffer,
): Buffer {
  const cipher = createCipheriv('aes-256-gcm', key, nonce(header.noncePrefix, counter, final), {
    authTagLength: GCM_TAG_BYTES,
  });
  cipher.setAAD(header.bytes);
  return Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}

function openChunk(
  key: Buffer,
  header: ArchiveObjectHeader,
  counter: number,
  final: boolean,
  sealed: Buffer,
): Buffer {
  if (sealed.length < GCM_TAG_BYTES) throw new ArchiveCryptoError('unauthentic');
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      nonce(header.noncePrefix, counter, final),
      { authTagLength: GCM_TAG_BYTES },
    );
    decipher.setAAD(header.bytes);
    decipher.setAuthTag(sealed.subarray(sealed.length - GCM_TAG_BYTES));
    return Buffer.concat([
      decipher.update(sealed.subarray(0, sealed.length - GCM_TAG_BYTES)),
      decipher.final(),
    ]);
  } catch {
    throw new ArchiveCryptoError('unauthentic');
  }
}

export interface ArchiveObjectContext extends ObjectKeyContext {
  /** The record or export DEK (32 bytes). */
  dek: Buffer;
}

export interface ArchiveEncryptOptions extends ArchiveObjectContext {
  /** Plaintext bytes per chunk (`ARCHIVE_CHUNK_BYTES`, default 65 536). */
  chunkBytes?: number;
}

export interface ArchiveEncryptSummary {
  plaintextBytes: number;
  /** SHA-256 (hex) of the plaintext (the EML hash check of A5 and the integrity column). */
  plaintextSha256: string;
  ciphertextBytes: number;
  ciphertextSha256: string;
}

export interface ArchiveDecryptSummary {
  plaintextBytes: number;
  plaintextSha256: string;
}

/** Encrypting transform: plaintext in, `archive-object/1` bytes out. */
export class ArchiveEncryptStream extends Transform {
  private readonly key: Buffer;
  private readonly header: ArchiveObjectHeader;
  private pending: Buffer = Buffer.alloc(0);
  private counter = 0;
  private headerSent = false;
  private readonly plainHash: Hash = createHash('sha256');
  private readonly cipherHash: Hash = createHash('sha256');
  private plainBytes = 0;
  private cipherBytes = 0;
  private done: ArchiveEncryptSummary | null = null;

  constructor(options: ArchiveEncryptOptions) {
    super();
    const chunkBytes = options.chunkBytes ?? ARCHIVE_DEFAULT_CHUNK_BYTES;
    if (
      !Number.isInteger(chunkBytes) ||
      chunkBytes < ARCHIVE_CHUNK_MIN_BYTES ||
      chunkBytes > ARCHIVE_CHUNK_MAX_BYTES
    ) {
      throw new ArchiveCryptoError('malformed');
    }
    this.header = buildHeader(options.kind, chunkBytes);
    this.key = deriveObjectKey(options.dek, this.header.salt, options);
  }

  /** Available once the stream has flushed (after `end`); null before. */
  get summary(): ArchiveEncryptSummary | null {
    return this.done;
  }

  private out(bytes: Buffer): void {
    this.cipherHash.update(bytes);
    this.cipherBytes += bytes.length;
    this.push(bytes);
  }

  private sendHeader(): void {
    if (this.headerSent) return;
    this.headerSent = true;
    this.out(this.header.bytes);
  }

  private nextCounter(): number {
    if (this.counter >= MAX_CHUNKS) throw new ArchiveCryptoError('malformed');
    return this.counter++;
  }

  override _transform(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      this.plainHash.update(data);
      this.plainBytes += data.length;
      this.sendHeader();
      this.pending = this.pending.length === 0 ? data : Buffer.concat([this.pending, data]);
      const size = this.header.chunkBytes;
      // Keep at least one full chunk back: only flush knows which chunk is final.
      let offset = 0;
      while (this.pending.length - offset > size) {
        const plain = this.pending.subarray(offset, offset + size);
        this.out(sealChunk(this.key, this.header, this.nextCounter(), false, plain));
        offset += size;
      }
      if (offset > 0) this.pending = Buffer.from(this.pending.subarray(offset));
      callback();
    } catch (error) {
      callback(error instanceof ArchiveCryptoError ? error : new ArchiveCryptoError('malformed'));
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      this.sendHeader();
      this.out(sealChunk(this.key, this.header, this.nextCounter(), true, this.pending));
      this.pending = Buffer.alloc(0);
      this.done = {
        plaintextBytes: this.plainBytes,
        plaintextSha256: this.plainHash.digest('hex'),
        ciphertextBytes: this.cipherBytes,
        ciphertextSha256: this.cipherHash.digest('hex'),
      };
      this.emit('summary', this.done);
      callback();
    } catch (error) {
      callback(error instanceof ArchiveCryptoError ? error : new ArchiveCryptoError('malformed'));
    }
  }
}

export interface ArchiveDecryptOptions extends ArchiveObjectContext {
  /** When set, a different plaintext SHA-256 fails the stream at its end (`integrity`). */
  expectedSha256?: string;
}

/** Decrypting transform: `archive-object/1` bytes in, plaintext out (constant memory). */
export class ArchiveDecryptStream extends Transform {
  private readonly context: ArchiveDecryptOptions;
  private header: ArchiveObjectHeader | null = null;
  private key: Buffer | null = null;
  private pending: Buffer = Buffer.alloc(0);
  private counter = 0;
  private readonly plainHash: Hash = createHash('sha256');
  private plainBytes = 0;
  private done: ArchiveDecryptSummary | null = null;

  constructor(options: ArchiveDecryptOptions) {
    super();
    if (options.expectedSha256 !== undefined && !/^[0-9a-f]{64}$/.test(options.expectedSha256)) {
      throw new ArchiveCryptoError('malformed');
    }
    this.context = options;
  }

  get summary(): ArchiveDecryptSummary | null {
    return this.done;
  }

  private open(final: boolean, sealed: Buffer): void {
    if (this.counter >= MAX_CHUNKS) throw new ArchiveCryptoError('unauthentic');
    const plain = openChunk(this.key!, this.header!, this.counter++, final, sealed);
    this.plainHash.update(plain);
    this.plainBytes += plain.length;
    if (plain.length > 0) this.push(plain);
  }

  override _transform(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      this.pending = this.pending.length === 0 ? data : Buffer.concat([this.pending, data]);
      if (this.header === null) {
        if (this.pending.length < ARCHIVE_OBJECT_HEADER_BYTES) return callback();
        this.header = parseArchiveObjectHeader(this.pending, this.context.kind);
        this.key = deriveObjectKey(this.context.dek, this.header.salt, this.context);
        this.pending = Buffer.from(this.pending.subarray(ARCHIVE_OBJECT_HEADER_BYTES));
      }
      const record = this.header.chunkBytes + GCM_TAG_BYTES;
      let offset = 0;
      // A full record followed by more bytes is not the final chunk.
      while (this.pending.length - offset > record) {
        this.open(false, this.pending.subarray(offset, offset + record));
        offset += record;
      }
      if (offset > 0) this.pending = Buffer.from(this.pending.subarray(offset));
      callback();
    } catch (error) {
      callback(error instanceof ArchiveCryptoError ? error : new ArchiveCryptoError('malformed'));
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      if (this.header === null) throw new ArchiveCryptoError('malformed');
      this.open(true, this.pending);
      this.pending = Buffer.alloc(0);
      const sha = this.plainHash.digest('hex');
      if (
        this.context.expectedSha256 !== undefined &&
        !timingSafeEqual(Buffer.from(sha, 'hex'), Buffer.from(this.context.expectedSha256, 'hex'))
      ) {
        throw new ArchiveCryptoError('integrity');
      }
      this.done = { plaintextBytes: this.plainBytes, plaintextSha256: sha };
      this.emit('summary', this.done);
      callback();
    } catch (error) {
      callback(error instanceof ArchiveCryptoError ? error : new ArchiveCryptoError('malformed'));
    }
  }
}

export function createArchiveEncryptStream(options: ArchiveEncryptOptions): ArchiveEncryptStream {
  return new ArchiveEncryptStream(options);
}

export function createArchiveDecryptStream(options: ArchiveDecryptOptions): ArchiveDecryptStream {
  return new ArchiveDecryptStream(options);
}

/** Encrypts a whole buffer (journal and scan objects, tests); same bytes as the stream. */
export function encryptArchiveObject(
  plaintext: Buffer,
  options: ArchiveEncryptOptions,
): { object: Buffer; summary: ArchiveEncryptSummary } {
  const chunkBytes = options.chunkBytes ?? ARCHIVE_DEFAULT_CHUNK_BYTES;
  if (
    !Number.isInteger(chunkBytes) ||
    chunkBytes < ARCHIVE_CHUNK_MIN_BYTES ||
    chunkBytes > ARCHIVE_CHUNK_MAX_BYTES
  ) {
    throw new ArchiveCryptoError('malformed');
  }
  const header = buildHeader(options.kind, chunkBytes);
  const key = deriveObjectKey(options.dek, header.salt, options);
  const parts: Buffer[] = [header.bytes];
  const chunks = Math.max(1, Math.ceil(plaintext.length / chunkBytes));
  if (chunks > MAX_CHUNKS) throw new ArchiveCryptoError('malformed');
  for (let i = 0; i < chunks; i += 1) {
    const plain = plaintext.subarray(i * chunkBytes, (i + 1) * chunkBytes);
    parts.push(sealChunk(key, header, i, i === chunks - 1, plain));
  }
  const object = Buffer.concat(parts);
  return {
    object,
    summary: {
      plaintextBytes: plaintext.length,
      plaintextSha256: createHash('sha256').update(plaintext).digest('hex'),
      ciphertextBytes: object.length,
      ciphertextSha256: createHash('sha256').update(object).digest('hex'),
    },
  };
}

/** Decrypts a whole object; throws `ArchiveCryptoError` (no partial output). */
export function decryptArchiveObject(object: Buffer, options: ArchiveDecryptOptions): Buffer {
  const header = parseArchiveObjectHeader(object, options.kind);
  const key = deriveObjectKey(options.dek, header.salt, options);
  const record = header.chunkBytes + GCM_TAG_BYTES;
  const body = object.subarray(ARCHIVE_OBJECT_HEADER_BYTES);
  if (body.length < GCM_TAG_BYTES) throw new ArchiveCryptoError('unauthentic');
  const chunks = Math.max(1, Math.ceil(body.length / record));
  const parts: Buffer[] = [];
  for (let i = 0; i < chunks; i += 1) {
    parts.push(
      openChunk(key, header, i, i === chunks - 1, body.subarray(i * record, (i + 1) * record)),
    );
  }
  const plain = Buffer.concat(parts);
  if (options.expectedSha256 !== undefined) {
    const sha = createHash('sha256').update(plain).digest('hex');
    if (sha !== options.expectedSha256) throw new ArchiveCryptoError('integrity');
  }
  return plain;
}
