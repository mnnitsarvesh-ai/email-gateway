import { createHash, randomBytes } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { ArchiveCryptoError } from './errors';
import { generateDataKey } from './keys';
import {
  ARCHIVE_DEFAULT_CHUNK_BYTES,
  ARCHIVE_OBJECT_HEADER_BYTES,
  createArchiveDecryptStream,
  createArchiveEncryptStream,
  decryptArchiveObject,
  encryptArchiveObject,
  parseArchiveObjectHeader,
} from './object-format';

const ORG = '42';
const MSG = '0190a5d0-0000-7000-8000-0000000000aa';
const CHUNK = 16_384;
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

function context(dek = generateDataKey()) {
  return { dek, kind: 'eml' as const, organizationId: ORG, subjectId: MSG };
}

/** Feeds `data` in pieces of random sizes (exercises chunk boundaries inside writes). */
function pieces(data: Buffer, maxPiece = 50_000): Readable {
  let offset = 0;
  return new Readable({
    read() {
      if (offset >= data.length) {
        this.push(null);
        return;
      }
      const n = 1 + Math.floor(Math.random() * maxPiece);
      this.push(data.subarray(offset, offset + n));
      offset += n;
    },
  });
}

async function collect(source: Readable, transform: NodeJS.ReadWriteStream): Promise<Buffer> {
  const out: Buffer[] = [];
  await pipeline(
    source,
    transform,
    new Writable({
      write(chunk: Buffer, _enc, cb) {
        out.push(chunk);
        cb();
      },
    }),
  );
  return Buffer.concat(out);
}

async function streamEncrypt(plain: Buffer, ctx: ReturnType<typeof context>, chunkBytes = CHUNK) {
  const enc = createArchiveEncryptStream({ ...ctx, chunkBytes });
  const object = await collect(pieces(plain), enc);
  return { object, summary: enc.summary! };
}

async function streamDecrypt(
  object: Buffer,
  ctx: ReturnType<typeof context>,
  expectedSha256?: string,
): Promise<Buffer> {
  const dec = createArchiveDecryptStream({ ...ctx, expectedSha256 });
  return collect(pieces(object), dec);
}

async function failure(fn: () => unknown): Promise<string> {
  try {
    await fn();
  } catch (error) {
    if (error instanceof ArchiveCryptoError) return error.reason;
    throw error;
  }
  return 'opened';
}

describe('archive-object/1 layout', () => {
  it('writes the 51-byte header: magic, version, kind, chunk size, salt, nonce prefix', () => {
    const ctx = context();
    const { object } = encryptArchiveObject(Buffer.from('hello'), { ...ctx, chunkBytes: CHUNK });
    expect(object.subarray(0, 6).toString('ascii')).toBe('EGARC1');
    expect(object[6]).toBe(1);
    expect(object[7]).toBe(1); // eml
    expect(object.readUInt32BE(8)).toBe(CHUNK);
    expect(ARCHIVE_OBJECT_HEADER_BYTES).toBe(51);
    // One final chunk: 5 bytes of ciphertext + 16-byte tag.
    expect(object.length).toBe(51 + 5 + 16);
    const header = parseArchiveObjectHeader(object);
    expect(header).toMatchObject({ kind: 'eml', chunkBytes: CHUNK });
    expect(header.salt).toHaveLength(32);
    expect(header.noncePrefix).toHaveLength(7);
    const kinds = ['eml', 'journal', 'scan', 'export'] as const;
    kinds.forEach((kind, i) => {
      const o = encryptArchiveObject(Buffer.alloc(0), { ...ctx, kind }).object;
      expect(o[7]).toBe(i + 1);
      expect(o.readUInt32BE(8)).toBe(ARCHIVE_DEFAULT_CHUNK_BYTES);
    });
  });

  it('uses a fresh salt and nonce prefix per object', () => {
    const ctx = context();
    const a = encryptArchiveObject(Buffer.from('x'), ctx).object;
    const b = encryptArchiveObject(Buffer.from('x'), ctx).object;
    expect(a.subarray(12, 51).equals(b.subarray(12, 51))).toBe(false);
  });

  it('refuses chunk sizes outside 16 KiB … 1 MiB', async () => {
    expect(
      await failure(() => createArchiveEncryptStream({ ...context(), chunkBytes: 1024 })),
    ).toBe('malformed');
    expect(
      await failure(() =>
        encryptArchiveObject(Buffer.alloc(1), { ...context(), chunkBytes: 2_000_000 }),
      ),
    ).toBe('malformed');
  });
});

describe('archive-object/1 round trips', () => {
  const sizes = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7];

  it.each(sizes)('streams %i bytes and matches the buffer helpers', async (size) => {
    const ctx = context();
    const plain = randomBytes(size);
    const { object, summary } = await streamEncrypt(plain, ctx);
    const chunks = Math.max(1, Math.ceil(size / CHUNK));
    expect(object.length).toBe(51 + size + 16 * chunks);
    expect(summary).toEqual({
      plaintextBytes: size,
      plaintextSha256: sha(plain),
      ciphertextBytes: object.length,
      ciphertextSha256: sha(object),
    });
    expect((await streamDecrypt(object, ctx, sha(plain))).equals(plain)).toBe(true);
    expect(decryptArchiveObject(object, ctx).equals(plain)).toBe(true);
    const buffered = encryptArchiveObject(plain, { ...ctx, chunkBytes: CHUNK });
    expect(buffered.object.length).toBe(object.length);
    expect((await streamDecrypt(buffered.object, ctx)).equals(plain)).toBe(true);
    expect(buffered.summary.plaintextSha256).toBe(sha(plain));
  });

  it('round-trips arbitrary sizes and write patterns (property)', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 5 * CHUNK + 3 }), async (size) => {
        const ctx = context();
        const plain = randomBytes(size);
        const { object } = await streamEncrypt(plain, ctx);
        expect((await streamDecrypt(object, ctx)).equals(plain)).toBe(true);
      }),
      { numRuns: 25 },
    );
  });

  it('streams 50 MiB with the default chunk size and bounded buffering', async () => {
    const ctx = context();
    const total = 50 * 1024 * 1024;
    const block = randomBytes(1024 * 1024);
    const plainHash = createHash('sha256');
    let produced = 0;
    const source = new Readable({
      read() {
        if (produced >= total) return void this.push(null);
        plainHash.update(block);
        produced += block.length;
        this.push(block);
      },
    });
    const enc = createArchiveEncryptStream(ctx);
    const encrypted: Buffer[] = [];
    await pipeline(
      source,
      enc,
      new Writable({
        write(chunk: Buffer, _e, cb) {
          encrypted.push(chunk);
          cb();
        },
      }),
    );
    const expected = plainHash.digest('hex');
    expect(enc.summary).toMatchObject({ plaintextBytes: total, plaintextSha256: expected });
    const dec = createArchiveDecryptStream({ ...ctx, expectedSha256: expected });
    let maxOut = 0;
    let outBytes = 0;
    await pipeline(
      Readable.from(encrypted),
      dec,
      new Writable({
        write(chunk: Buffer, _e, cb) {
          maxOut = Math.max(maxOut, chunk.length);
          outBytes += chunk.length;
          cb();
        },
      }),
    );
    expect(outBytes).toBe(total);
    // Output is emitted chunk by chunk: never more than one plaintext chunk at a time.
    expect(maxOut).toBeLessThanOrEqual(ARCHIVE_DEFAULT_CHUNK_BYTES);
    expect(dec.summary).toEqual({ plaintextBytes: total, plaintextSha256: expected });
  });
});

describe('archive-object/1 refuses every manipulation', () => {
  const ctx = context();
  const plain = randomBytes(3 * CHUNK + 100);
  const { object } = encryptArchiveObject(plain, { ...ctx, chunkBytes: CHUNK });
  const record = CHUNK + 16;
  const body = (i: number) => object.subarray(51 + i * record, 51 + (i + 1) * record);

  const both = async (bytes: Buffer, c = ctx) => {
    const a = await failure(() => decryptArchiveObject(bytes, c));
    const b = await failure(() => streamDecrypt(bytes, c));
    return [a, b];
  };

  it('a flipped byte anywhere (header, ciphertext, tag)', async () => {
    for (const offset of [8, 12, 44, 50, 51, 51 + CHUNK + 3, 51 + record - 1, object.length - 1]) {
      const copy = Buffer.from(object);
      copy[offset] = copy[offset]! ^ 0x01;
      const [a, b] = await both(copy);
      expect(a, `offset ${offset}`).not.toBe('opened');
      expect(b, `offset ${offset}`).not.toBe('opened');
    }
  });

  it('a changed magic, version or chunk size is malformed', async () => {
    for (const [offset, value] of [
      [0, 0x58],
      [6, 2],
      [7, 9],
    ] as const) {
      const copy = Buffer.from(object);
      copy[offset] = value;
      expect(await both(copy)).toEqual(['malformed', 'malformed']);
    }
    const huge = Buffer.from(object);
    huge.writeUInt32BE(64 * 1024 * 1024, 8);
    expect(await both(huge)).toEqual(['malformed', 'malformed']);
  });

  it('truncation at a chunk boundary, inside a chunk and inside the header', async () => {
    expect(await both(object.subarray(0, 51 + 3 * record))).toEqual(['unauthentic', 'unauthentic']);
    expect(await both(object.subarray(0, 51 + record))).toEqual(['unauthentic', 'unauthentic']);
    expect(await both(object.subarray(0, object.length - 5))).toEqual([
      'unauthentic',
      'unauthentic',
    ]);
    expect(await both(object.subarray(0, 51 + 10))).toEqual(['unauthentic', 'unauthentic']);
    expect(await both(object.subarray(0, 51))).toEqual(['unauthentic', 'unauthentic']);
    expect(await both(object.subarray(0, 30))).toEqual(['malformed', 'malformed']);
  });

  it('reordered, duplicated and extended chunks', async () => {
    const header = object.subarray(0, 51);
    const tail = object.subarray(51 + 3 * record);
    const swapped = Buffer.concat([header, body(1), body(0), body(2), tail]);
    expect(await both(swapped)).toEqual(['unauthentic', 'unauthentic']);
    const duplicated = Buffer.concat([header, body(0), body(0), body(1), body(2), tail]);
    expect(await both(duplicated)).toEqual(['unauthentic', 'unauthentic']);
    const extended = Buffer.concat([object, randomBytes(40)]);
    expect(await both(extended)).toEqual(['unauthentic', 'unauthentic']);
    const twice = Buffer.concat([object, object.subarray(51)]);
    expect(await both(twice)).toEqual(['unauthentic', 'unauthentic']);
  });

  it('a different header (spliced from another object) fails', async () => {
    const other = encryptArchiveObject(plain, { ...ctx, chunkBytes: CHUNK }).object;
    const spliced = Buffer.concat([other.subarray(0, 51), object.subarray(51)]);
    expect(await both(spliced)).toEqual(['unauthentic', 'unauthentic']);
  });

  it('a wrong key, kind, organization or subject fails', async () => {
    expect(await both(object, { ...ctx, dek: generateDataKey() })).toEqual([
      'unauthentic',
      'unauthentic',
    ]);
    expect(await both(object, { ...ctx, kind: 'journal' as never })).toEqual([
      'unauthentic',
      'unauthentic',
    ]);
    expect(await both(object, { ...ctx, organizationId: '43' })).toEqual([
      'unauthentic',
      'unauthentic',
    ]);
    expect(
      await both(object, { ...ctx, subjectId: '0190a5d0-0000-7000-8000-0000000000ab' }),
    ).toEqual(['unauthentic', 'unauthentic']);
  });

  it('an unexpected plaintext hash is an integrity failure', async () => {
    const wrong = 'f'.repeat(64);
    expect(
      await failure(() => decryptArchiveObject(object, { ...ctx, expectedSha256: wrong })),
    ).toBe('integrity');
    expect(await failure(() => streamDecrypt(object, ctx, wrong))).toBe('integrity');
    expect(await failure(() => createArchiveDecryptStream({ ...ctx, expectedSha256: 'xyz' }))).toBe(
      'malformed',
    );
  });

  it('an empty input is malformed', async () => {
    expect(await both(Buffer.alloc(0))).toEqual(['malformed', 'malformed']);
  });
});
