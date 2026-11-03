import { Readable } from 'node:stream';
import { crc32, deflateRawSync } from 'node:zlib';
import yazl from 'yazl';

export interface ZipEntry {
  name: string;
  data?: Buffer;
  /** Streams this many zero bytes instead of `data` (bombs without allocating them). */
  zeros?: number;
  compress?: boolean;
}

/** Builds a zip with yazl at test time (never committed). */
export async function buildZip(
  entries: ZipEntry[],
  options: { zip64?: boolean; comment?: string } = {},
): Promise<Buffer> {
  const zip = new yazl.ZipFile();
  for (const entry of entries) {
    const compress = entry.compress ?? true;
    if (entry.zeros !== undefined) {
      zip.addReadStream(zeroStream(entry.zeros), entry.name, { compress, size: entry.zeros });
    } else {
      zip.addBuffer(entry.data ?? Buffer.alloc(0), entry.name, { compress });
    }
  }
  zip.end({ forceZip64Format: options.zip64 ?? false, comment: options.comment ?? '' });
  const chunks: Buffer[] = [];
  for await (const chunk of zip.outputStream as AsyncIterable<Buffer>) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function zeroStream(total: number): Readable {
  const block = Buffer.alloc(1024 * 1024);
  return Readable.from(
    (function* () {
      for (let sent = 0; sent < total; sent += block.length)
        yield block.subarray(0, Math.min(block.length, total - sent));
    })(),
  );
}

/** Offsets of every central directory header (signature PK\x01\x02) of a zip built above. */
export function centralHeaders(zip: Buffer): number[] {
  const offsets: number[] = [];
  for (
    let index = zip.indexOf('PK\x01\x02', 0, 'latin1');
    index >= 0;
    index = zip.indexOf('PK\x01\x02', index + 4, 'latin1')
  ) {
    offsets.push(index);
  }
  return offsets;
}

/** Sets general-purpose bit 0 (traditional encryption) in every central directory header. */
export function markEncrypted(zip: Buffer): Buffer {
  const copy = Buffer.from(zip);
  for (const offset of centralHeaders(copy))
    copy.writeUInt16LE(copy.readUInt16LE(offset + 8) | 0x1, offset + 8);
  return copy;
}

/** Points the second entry's local header offset at the first one's (Fifield-style overlap). */
export function overlapEntries(zip: Buffer): Buffer {
  const copy = Buffer.from(zip);
  const [first, second] = centralHeaders(copy);
  if (first === undefined || second === undefined) throw new Error('need two entries');
  copy.writeUInt32LE(copy.readUInt32LE(first + 42), second + 42);
  return copy;
}

/** Rewrites an entry name in the central directory only (same length), e.g. to `../x.txt`. */
export function renameEntry(zip: Buffer, from: string, to: string): Buffer {
  if (from.length !== to.length) throw new Error('same length only');
  const copy = Buffer.from(zip);
  for (const offset of centralHeaders(copy)) {
    const nameLength = copy.readUInt16LE(offset + 28);
    if (copy.toString('latin1', offset + 46, offset + 46 + nameLength) === from)
      copy.write(to, offset + 46, 'latin1');
  }
  return copy;
}

/** A gzip member with optional FNAME, and an ISIZE that can be forced (a lying trailer). */
export function buildGzip(
  data: Buffer,
  options: { name?: string; extra?: Buffer; isize?: number } = {},
): Buffer {
  let flags = 0;
  const header: Buffer[] = [];
  if (options.extra) {
    flags |= 0x04;
    const length = Buffer.alloc(2);
    length.writeUInt16LE(options.extra.length);
    header.push(length, options.extra);
  }
  if (options.name !== undefined) {
    flags |= 0x08;
    header.push(Buffer.from(`${options.name}\0`, 'latin1'));
  }
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(data), 0);
  trailer.writeUInt32LE(options.isize ?? data.length % 2 ** 32, 4);
  return Buffer.concat([
    Buffer.from([0x1f, 0x8b, 0x08, flags, 0, 0, 0, 0, 0, 0x03]),
    ...header,
    deflateRawSync(data),
    trailer,
  ]);
}
