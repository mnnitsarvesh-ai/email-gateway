import { Readable } from 'node:stream';
import { crc32, deflateRawSync } from 'node:zlib';
import { ZipFile } from 'yazl';

/** One file of a generated zip. */
export interface ZipEntry {
  name: string;
  data: Buffer;
  /** Deflate (default true) or store. */
  compress?: boolean;
}

/** Fixed timestamp so generated archives are byte-identical between runs (stable hashes). */
export const FIXED_MTIME = new Date('2026-01-01T00:00:00Z');

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) parts.push(chunk);
  return Buffer.concat(parts);
}

/** A valid zip (yazl) of `entries`, in order. */
export async function zip(entries: readonly ZipEntry[]): Promise<Buffer> {
  const file = new ZipFile();
  for (const entry of entries) {
    file.addBuffer(entry.data, entry.name, {
      compress: entry.compress ?? true,
      mtime: FIXED_MTIME,
      mode: 0o100644,
    });
  }
  file.end();
  return collect(file.outputStream);
}

/**
 * A zip with one deflated entry of `uncompressedBytes` zeros, streamed into yazl in 1 MiB
 * chunks (the uncompressed data never exists as one buffer).
 */
export async function zipOfZeros(name: string, uncompressedBytes: number): Promise<Buffer> {
  const chunk = Buffer.alloc(Math.min(1024 * 1024, Math.max(uncompressedBytes, 1)));
  let left = uncompressedBytes;
  const zeros = new Readable({
    read() {
      if (left <= 0) {
        this.push(null);
        return;
      }
      const size = Math.min(left, chunk.length);
      left -= size;
      this.push(chunk.subarray(0, size));
    },
  });
  const file = new ZipFile();
  file.addReadStream(zeros, name, {
    compress: true,
    compressionLevel: 9,
    mtime: FIXED_MTIME,
    size: uncompressedBytes,
  });
  file.end();
  return collect(file.outputStream);
}

/**
 * An entry of the low-level zip writer: every header field can be set, including values a
 * well-behaved writer (yazl) refuses (`../` names, encryption flags, AES extra fields, overlapping
 * local header offsets). `data` is written as is (already compressed when `method` is 8).
 */
export interface RawZipEntry {
  name: string;
  data: Buffer;
  /** 0 stored, 8 deflate, 99 AES (WinZip AE-x). */
  method: number;
  uncompressedSize: number;
  crc: number;
  /** General purpose bit flag (bit 0 = encrypted, bit 6 = strong encryption, bit 11 = UTF-8). */
  flags?: number;
  /** Extra field bytes of the local and central headers. */
  extra?: Buffer;
  /** Central directory local-header offset override (overlapping entries). */
  localHeaderOffset?: number;
}

/** A stored or deflated raw entry with correct sizes and CRC. */
export function rawEntry(name: string, data: Buffer, deflate = true): RawZipEntry {
  return {
    name,
    data: deflate ? deflateRawSync(data) : data,
    method: deflate ? 8 : 0,
    uncompressedSize: data.length,
    crc: crc32(data),
  };
}

const DOS_TIME = 0; // 00:00:00
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1; // 2026-01-01

/** Writes local headers + data, the central directory and the end record (no zip64). */
export function buildRawZip(entries: readonly RawZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const extra = entry.extra ?? Buffer.alloc(0);
    const flags = entry.flags ?? 0x0800;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(entry.method, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(entry.crc >>> 0, 14);
    local.writeUInt32LE(entry.data.length, 18);
    local.writeUInt32LE(entry.uncompressedSize, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(extra.length, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x031e, 4); // made by: Unix, 3.0
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(entry.method, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(entry.crc >>> 0, 16);
    central.writeUInt32LE(entry.data.length, 20);
    central.writeUInt32LE(entry.uncompressedSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt16LE(0, 32); // comment length
    central.writeUInt16LE(0, 34); // disk number
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    central.writeUInt32LE(entry.localHeaderOffset ?? offset, 42);
    locals.push(local, name, extra, entry.data);
    centrals.push(central, name, extra);
    offset += local.length + name.length + extra.length + entry.data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/** Offsets of the end-of-central-directory record and the central directory of a zip. */
export function zipLayout(buffer: Buffer): {
  endOffset: number;
  directoryOffset: number;
  directorySize: number;
} {
  const endOffset = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (endOffset < 0) throw new Error('not a zip: no end of central directory record');
  return {
    endOffset,
    directorySize: buffer.readUInt32LE(endOffset + 12),
    directoryOffset: buffer.readUInt32LE(endOffset + 16),
  };
}
