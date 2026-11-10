import { inflateRawSync } from 'node:zlib';

/**
 * A bounded ZIP central-directory reader (OOXML packages; step 4.6 X4 `ooxml`): end of central
 * directory (with ZIP64 locator), at most `maxEntries` entries, stored or deflated entries only,
 * inflate capped per entry (`maxOutputLength`) and by a caller budget. Pure; throws `ZipError`.
 */

export class ZipError extends Error {
  override readonly name = 'ZipError';
  constructor(readonly code: string) {
    super(`zip: ${code}`);
  }
}

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
}

const EOCD = 0x06054b50;
const ZIP64_LOCATOR = 0x07064b50;
const ZIP64_EOCD = 0x06064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

export function isZip(bytes: Buffer): boolean {
  return bytes.length >= 22 && bytes.readUInt32LE(0) === LOCAL;
}

export function readCentralDirectory(bytes: Buffer, maxEntries = 10_000): ZipEntry[] {
  const searchFrom = Math.max(0, bytes.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= searchFrom; i -= 1) {
    if (bytes.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipError('no_eocd');
  let count = bytes.readUInt16LE(eocd + 10);
  let cdSize = bytes.readUInt32LE(eocd + 12);
  let cdOffset = bytes.readUInt32LE(eocd + 16);
  if (
    (count === 0xffff || cdOffset === 0xffffffff) &&
    eocd >= 20 &&
    bytes.readUInt32LE(eocd - 20) === ZIP64_LOCATOR
  ) {
    const z64 = Number(bytes.readBigUInt64LE(eocd - 20 + 8));
    if (z64 + 56 > bytes.length || bytes.readUInt32LE(z64) !== ZIP64_EOCD)
      throw new ZipError('zip64');
    count = Number(bytes.readBigUInt64LE(z64 + 32));
    cdSize = Number(bytes.readBigUInt64LE(z64 + 40));
    cdOffset = Number(bytes.readBigUInt64LE(z64 + 48));
  }
  if (cdOffset + cdSize > bytes.length) throw new ZipError('cd_range');
  const entries: ZipEntry[] = [];
  let pos = cdOffset;
  for (let i = 0; i < Math.min(count, maxEntries); i += 1) {
    if (pos + 46 > bytes.length || bytes.readUInt32LE(pos) !== CENTRAL)
      throw new ZipError('cd_entry');
    const method = bytes.readUInt16LE(pos + 10);
    let compressedSize = bytes.readUInt32LE(pos + 20);
    let uncompressedSize = bytes.readUInt32LE(pos + 24);
    const nameLength = bytes.readUInt16LE(pos + 28);
    const extraLength = bytes.readUInt16LE(pos + 30);
    const commentLength = bytes.readUInt16LE(pos + 32);
    let localOffset = bytes.readUInt32LE(pos + 42);
    const nameEnd = pos + 46 + nameLength;
    if (nameEnd + extraLength + commentLength > bytes.length) throw new ZipError('cd_entry');
    const name = bytes.subarray(pos + 46, nameEnd).toString('utf8');
    // ZIP64 extended information extra field (0x0001).
    let extra = nameEnd;
    const extraEnd = nameEnd + extraLength;
    while (extra + 4 <= extraEnd) {
      const id = bytes.readUInt16LE(extra);
      const size = bytes.readUInt16LE(extra + 2);
      if (id === 0x0001) {
        let field = extra + 4;
        const take = (): number => {
          const v = field + 8 <= extra + 4 + size ? Number(bytes.readBigUInt64LE(field)) : 0;
          field += 8;
          return v;
        };
        if (uncompressedSize === 0xffffffff) uncompressedSize = take();
        if (compressedSize === 0xffffffff) compressedSize = take();
        if (localOffset === 0xffffffff) localOffset = take();
      }
      extra += 4 + size;
    }
    entries.push({ name, method, compressedSize, uncompressedSize, localOffset });
    pos = extraEnd + commentLength;
  }
  return entries;
}

/**
 * The bytes of one entry, inflated to at most `maxBytes`; null when the method is unsupported
 * or the entry is larger than allowed (the caller records the limit).
 */
export function readEntry(bytes: Buffer, entry: ZipEntry, maxBytes: number): Buffer | null {
  const at = entry.localOffset;
  if (at + 30 > bytes.length || bytes.readUInt32LE(at) !== LOCAL)
    throw new ZipError('local_header');
  const nameLength = bytes.readUInt16LE(at + 26);
  const extraLength = bytes.readUInt16LE(at + 28);
  const start = at + 30 + nameLength + extraLength;
  const end = start + entry.compressedSize;
  if (end > bytes.length) throw new ZipError('entry_range');
  const data = bytes.subarray(start, end);
  if (entry.method === 0) return data.length <= maxBytes ? data : null;
  if (entry.method !== 8) return null;
  if (entry.uncompressedSize > maxBytes) return null;
  try {
    return inflateRawSync(data, { maxOutputLength: maxBytes });
  } catch (error) {
    if ((error as { code?: unknown }).code === 'ERR_BUFFER_TOO_LARGE') return null;
    throw new ZipError('inflate');
  }
}
