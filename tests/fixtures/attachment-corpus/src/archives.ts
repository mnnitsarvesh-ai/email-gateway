import { gzipSync } from 'node:zlib';
import { pack } from 'tar-stream';
import { buildRawZip, rawEntry, zip, zipLayout, zipOfZeros, type ZipEntry } from './zip';

const MiB = 1024 * 1024;

/** A file inside a tar archive. */
export interface TarEntry {
  name: string;
  data: Buffer;
}

/** `depth` zips nested in each other around `inner` (depth 1 = a zip that contains `inner`). */
export async function nestedZip(depth: number, inner: ZipEntry): Promise<Buffer> {
  if (!Number.isInteger(depth) || depth < 1) throw new RangeError('depth must be >= 1');
  let current = await zip([inner]);
  for (let level = depth - 1; level >= 1; level -= 1) {
    current = await zip([{ name: `level-${level}.zip`, data: current, compress: false }]);
  }
  return current;
}

/** A single-member gzip of `data`. */
export function gzip(data: Buffer): Buffer {
  return gzipSync(data, { level: 9 });
}

/** Two gzip members back to back (valid: `gunzip` yields both concatenated). */
export function multiMemberGzip(first: Buffer, second: Buffer): Buffer {
  return Buffer.concat([gzip(first), gzip(second)]);
}

/** A ustar archive (tar-stream) of regular files with fixed metadata. */
export async function tar(entries: readonly TarEntry[]): Promise<Buffer> {
  const archive = pack();
  const parts: Buffer[] = [];
  archive.on('data', (chunk: unknown) => parts.push(chunk as Buffer));
  const finished = new Promise<void>((resolve, reject) => {
    archive.on('end', resolve);
    archive.on('error', reject);
  });
  for (const entry of entries) {
    await new Promise<void>((resolve, reject) => {
      archive.entry(
        {
          name: entry.name,
          size: entry.data.length,
          mode: 0o644,
          mtime: new Date('2026-01-01T00:00:00Z'),
          type: 'file',
          uid: 1000,
          gid: 1000,
          uname: 'eg',
          gname: 'eg',
        },
        entry.data,
        (error) => (error ? reject(error) : resolve()),
      );
    });
  }
  archive.finalize();
  await finished;
  return Buffer.concat(parts);
}

/** gzip(tar(entries)): two archive levels for the inspector (A4). */
export async function tgz(entries: readonly TarEntry[]): Promise<Buffer> {
  return gzip(await tar(entries));
}

/**
 * Zip bomb: one entry of `uncompressedBytes` zeros (default 64 MiB, at least 50 MiB) deflated
 * to roughly 1/1000 of its size. Above ATTACHMENT_MAX_DECOMPRESSED_BYTES' default only when
 * `uncompressedBytes` > 100 MiB; the ratio limit (100) is crossed within the first megabyte.
 */
export async function zipBomb(uncompressedBytes = 64 * MiB): Promise<Buffer> {
  if (uncompressedBytes < 50 * MiB) throw new RangeError('a zip bomb is at least 50 MiB');
  return zipOfZeros('zeros.bin', uncompressedBytes);
}

/**
 * A small zip whose single entry has a compression ratio far above 100 while its decompressed
 * size (default 4 MiB) stays below every size limit: only `limit.compression_ratio` applies.
 */
export async function highRatioFile(uncompressedBytes = 4 * MiB): Promise<Buffer> {
  return zipOfZeros('report.txt', uncompressedBytes);
}

/**
 * A structurally valid zip whose entry claims traditional PKWARE encryption (general purpose
 * bit 0; the 12-byte encryption header and data are random-looking bytes, not real ZipCrypto).
 */
export function encryptedZip(): Buffer {
  const data = Buffer.alloc(64);
  for (let i = 0; i < data.length; i += 1) data[i] = (i * 73 + 41) & 0xff;
  return buildRawZip([
    { name: 'secret.pdf', data, method: 8, uncompressedSize: 500, crc: 0x1234abcd, flags: 0x0001 },
  ]);
}

/**
 * WinZip AES variant: compression method 99 with the 0x9901 extra field (vendor `AE`, AE-2,
 * AES-256, actual method deflate); general purpose bit 0 set as WinZip does.
 */
export function aesEncryptedZip(): Buffer {
  const extra = Buffer.alloc(11);
  extra.writeUInt16LE(0x9901, 0);
  extra.writeUInt16LE(7, 2);
  extra.writeUInt16LE(2, 4); // AE-2
  extra.write('AE', 6, 'latin1');
  extra.writeUInt8(3, 8); // AES-256
  extra.writeUInt16LE(8, 9); // actual compression method
  const data = Buffer.alloc(16 + 2 + 48 + 10, 0x5a); // salt + verifier + data + MAC
  return buildRawZip([
    { name: 'secret.docx', data, method: 99, uncompressedSize: 300, crc: 0, flags: 0x0001, extra },
  ]);
}

/** A zip whose central directory is cut in half while the end record still claims all of it. */
export async function malformedZip(): Promise<Buffer> {
  const valid = await zip([
    { name: 'a.txt', data: Buffer.from('first entry\n') },
    { name: 'b.txt', data: Buffer.from('second entry\n') },
    { name: 'c.txt', data: Buffer.from('third entry\n') },
  ]);
  const { endOffset, directoryOffset, directorySize } = zipLayout(valid);
  return Buffer.concat([
    valid.subarray(0, directoryOffset + Math.floor(directorySize / 2)),
    valid.subarray(endOffset),
  ]);
}

/** A zip that ends inside its first local file header (no central directory at all). */
export async function truncatedZip(): Promise<Buffer> {
  const valid = await zip([{ name: 'a.txt', data: Buffer.from('content '.repeat(64)) }]);
  return valid.subarray(0, 20);
}

/** A gzip cut before its CRC/ISIZE trailer and inside the deflate stream. */
export function truncatedGzip(
  data: Buffer = Buffer.from('truncated gzip payload\n'.repeat(400)),
): Buffer {
  const full = gzip(data);
  return full.subarray(0, Math.max(11, full.length - 16));
}

/** A tar whose first header checksum field (offset 148) is wrong. */
export async function badTarChecksum(): Promise<Buffer> {
  const archive = await tar([{ name: 'notes.txt', data: Buffer.from('tar entry\n') }]);
  archive.write('0000000\0', 148, 'latin1');
  return archive;
}

/** A zip with one entry named `../../etc/evil.txt` (yazl refuses such names; written raw). */
export function pathTraversalZip(): Buffer {
  return buildRawZip([
    rawEntry('readme.txt', Buffer.from('fine\n')),
    rawEntry('../../etc/evil.txt', Buffer.from('escaped\n')),
  ]);
}

/** A zip with an absolute entry name. */
export function absolutePathZip(): Buffer {
  return buildRawZip([rawEntry('/tmp/evil.txt', Buffer.from('absolute\n'))]);
}

/**
 * A zip with two central-directory entries that point at the same local header (overlapping
 * entries: the classic non-recursive zip bomb construction).
 */
export function overlappingZip(): Buffer {
  const shared = rawEntry('one.txt', Buffer.from('shared bytes\n'.repeat(32)));
  return buildRawZip([shared, { ...shared, name: 'two.txt', localHeaderOffset: 0 }]);
}

/** A zip of `count` tiny stored entries (entry-count limit tests, e.g. 1 001 > 1 000). */
export async function manyEntriesZip(count: number): Promise<Buffer> {
  const entries: ZipEntry[] = [];
  for (let i = 0; i < count; i += 1) {
    entries.push({ name: `f/${i}.txt`, data: Buffer.from(`${i}\n`), compress: false });
  }
  return zip(entries);
}
