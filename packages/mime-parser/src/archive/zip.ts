import { PassThrough, Readable } from 'node:stream';
import yauzl from 'yauzl';
import type { AttachmentFlag } from '../constants';
import { ARCHIVE_EXTENSIONS, finalExtension } from '../filename';
import type { MimeLimits } from '../limits';
import type { ArchiveInfo, StoredPart } from '../types';
import { roundRatio } from './gzip';

const EOCD_SIGNATURE = 0x06054b50;
const EOCD_MIN_BYTES = 22;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;
const ZIP64_LOCATOR_BYTES = 20;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const ZIP64_EOCD_BYTES = 56;
/** EOCD plus the longest comment: what yauzl reads first (min(size, 65 557) bytes). */
export const ZIP_TAIL_BYTES = ZIP64_LOCATOR_BYTES + EOCD_MIN_BYTES + 0xffff;
/** The smallest local file header; the next entry cannot start before its end plus its data. */
const LOCAL_HEADER_MIN_BYTES = 30;

/** A read of the archive that the prefetched ranges do not cover: the zip is malformed. */
class ReadOutsidePrefetch extends Error {
  override readonly name = 'ReadOutsidePrefetch';
}

/** The archive could not be read as a zip (yauzl or our own EOCD check). */
class ZipRejected extends Error {
  override readonly name = 'ZipRejected';
}

interface Segment {
  start: number;
  data: Buffer;
}

/**
 * Serves yauzl from the ranges fetched up front. No read ever reaches storage from here, so an
 * entry's data (or anything else outside the central directory) is never fetched.
 */
class PrefetchedReader extends yauzl.RandomAccessReader {
  constructor(private readonly segments: readonly Segment[]) {
    super();
  }

  override _readStreamForRange(start: number, end: number): Readable {
    const segment = this.segments.find(
      (candidate) => start >= candidate.start && end <= candidate.start + candidate.data.length,
    );
    if (segment === undefined) {
      const failing = new PassThrough();
      process.nextTick(() => failing.destroy(new ReadOutsidePrefetch()));
      return failing;
    }
    return Readable.from([segment.data.subarray(start - segment.start, end - segment.start)]);
  }

  override close(callback: (err: Error | null) => void): void {
    setImmediate(() => callback(null));
  }
}

interface CentralDirectory {
  offset: number;
  size: number;
}

function readUInt64(buffer: Buffer, offset: number): number | null {
  const value = buffer.readBigUInt64LE(offset);
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(value);
}

/**
 * Locates the central directory the way yauzl does (last EOCD signature, zip64 locator in front
 * of it), so it can be bounded and fetched in one range before yauzl reads it.
 */
async function locateCentralDirectory(
  part: StoredPart,
  sizeBytes: number,
  tail: Segment,
  segments: Segment[],
  signal: AbortSignal,
): Promise<CentralDirectory | null> {
  const buffer = tail.data;
  for (let index = buffer.length - EOCD_MIN_BYTES; index >= 0; index--) {
    if (buffer.readUInt32LE(index) !== EOCD_SIGNATURE) continue;
    const locator = index - ZIP64_LOCATOR_BYTES;
    if (locator >= 0 && buffer.readUInt32LE(locator) === ZIP64_LOCATOR_SIGNATURE) {
      const recordOffset = readUInt64(buffer, locator + 8);
      if (recordOffset === null || recordOffset + ZIP64_EOCD_BYTES > sizeBytes) return null;
      let record: Buffer;
      if (recordOffset >= tail.start) {
        record = buffer.subarray(
          recordOffset - tail.start,
          recordOffset - tail.start + ZIP64_EOCD_BYTES,
        );
      } else {
        record = await part.readRange(recordOffset, recordOffset + ZIP64_EOCD_BYTES - 1, signal);
        if (record.length !== ZIP64_EOCD_BYTES) return null;
        segments.push({ start: recordOffset, data: record });
      }
      if (record.readUInt32LE(0) !== ZIP64_EOCD_SIGNATURE) return null;
      const size = readUInt64(record, 40);
      const offset = readUInt64(record, 48);
      return size === null || offset === null ? null : { offset, size };
    }
    return { size: buffer.readUInt32LE(index + 12), offset: buffer.readUInt32LE(index + 16) };
  }
  return null;
}

function emptyInfo(flag: AttachmentFlag): ArchiveInfo {
  return {
    type: 'zip',
    inspected: false,
    entries: null,
    declaredUncompressedBytes: null,
    maxRatio: null,
    encryptedEntries: null,
    nestedArchives: null,
    flags: [flag],
  };
}

function isTraversal(name: string): boolean {
  return name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.split('/').includes('..');
}

/**
 * Zip central-directory inspection (design M10). Two bounded fetches through `readRange` (the
 * tail, then the central directory, plus the 56-byte zip64 record if it lies before the tail);
 * yauzl then reads only from them. Errors thrown by `readRange` are rethrown unchanged
 * (infrastructure); anything yauzl rejects is `archive_malformed`. No entry data is read.
 */
export async function inspectZip(
  part: StoredPart,
  sizeBytes: number,
  limits: MimeLimits,
  signal: AbortSignal,
): Promise<ArchiveInfo> {
  if (sizeBytes < EOCD_MIN_BYTES) return emptyInfo('archive_malformed');
  const tailLength = Math.min(sizeBytes, ZIP_TAIL_BYTES);
  const tailStart = sizeBytes - tailLength;
  const tailData = await part.readRange(tailStart, sizeBytes - 1, signal);
  if (tailData.length !== tailLength) return emptyInfo('archive_malformed');
  const tail: Segment = { start: tailStart, data: tailData };
  const segments: Segment[] = [tail];

  const directory = await locateCentralDirectory(part, sizeBytes, tail, segments, signal);
  if (directory === null) return emptyInfo('archive_malformed');
  if (directory.size > limits.archiveMaxCentralDirectoryBytes)
    return emptyInfo('archive_not_inspected');
  if (directory.offset + directory.size > sizeBytes) return emptyInfo('archive_malformed');
  if (directory.size > 0 && directory.offset < tailStart) {
    const data = await part.readRange(
      directory.offset,
      directory.offset + directory.size - 1,
      signal,
    );
    if (data.length !== directory.size) return emptyInfo('archive_malformed');
    segments.push({ start: directory.offset, data });
  }
  signal.throwIfAborted();

  const flags = new Set<AttachmentFlag>();
  const offsets: { offset: number; compressedSize: number }[] = [];
  let declaredEntries = 0;
  let seen = 0;
  let total = 0;
  let maxRatio = 0;
  let encrypted = 0;
  let nested = 0;
  let complete = false;
  try {
    await new Promise<void>((resolve, reject) => {
      const options: yauzl.Options = {
        lazyEntries: true,
        autoClose: true,
        // Names are judged from the raw bytes: with decodeStrings yauzl rejects the whole
        // archive on the first `..` or absolute name, which would hide archive_path_traversal.
        decodeStrings: false,
        validateEntrySizes: false,
        strictFileNames: false,
      };
      yauzl.fromRandomAccessReader(
        new PrefetchedReader(segments),
        sizeBytes,
        options,
        (error, zip) => {
          if (error) return reject(new ZipRejected());
          declaredEntries = zip.entryCount;
          if (declaredEntries > limits.archiveMaxEntries) flags.add('archive_entry_count');
          const onAbort = (): void => {
            zip.close();
            reject(signal.reason instanceof Error ? signal.reason : new Error('aborted'));
          };
          signal.addEventListener('abort', onAbort, { once: true });
          const done = (): void => {
            signal.removeEventListener('abort', onAbort);
            resolve();
          };
          zip.on('error', () => {
            signal.removeEventListener('abort', onAbort);
            reject(new ZipRejected());
          });
          zip.on('end', () => {
            complete = true;
            done();
          });
          zip.on('entry', (entry: yauzl.Entry) => {
            seen++;
            if (seen > limits.archiveMaxEntries) {
              flags.add('archive_entry_count');
              complete = true;
              zip.close();
              done();
              return;
            }
            const name = entry.fileNameRaw.toString('latin1').replace(/\\/g, '/');
            if (isTraversal(name)) flags.add('archive_path_traversal');
            const extension = finalExtension(name.slice(name.lastIndexOf('/') + 1));
            if (extension !== null && ARCHIVE_EXTENSIONS.has(extension)) nested++;
            if (entry.generalPurposeBitFlag & 0x1) encrypted++;
            const ratio = entry.uncompressedSize / Math.max(entry.compressedSize, 1);
            if (ratio > maxRatio) maxRatio = ratio;
            total += entry.uncompressedSize;
            offsets.push({
              offset: entry.relativeOffsetOfLocalHeader,
              compressedSize: entry.compressedSize,
            });
            zip.readEntry();
          });
          zip.readEntry();
        },
      );
    });
  } catch (error) {
    if (!(error instanceof ZipRejected)) throw error;
    flags.add('archive_malformed');
  }

  if (maxRatio > limits.archiveMaxRatio) flags.add('archive_compression_ratio');
  if (total > limits.archiveMaxTotalUncompressedBytes) flags.add('archive_total_size');
  if (encrypted > 0) flags.add('archive_encrypted');
  if (nested > 0) flags.add('archive_nested');
  if (hasOverlap(offsets)) flags.add('archive_overlapping_entries');
  return {
    type: 'zip',
    inspected: complete,
    entries: declaredEntries,
    declaredUncompressedBytes: total,
    maxRatio: roundRatio(maxRatio),
    encryptedEntries: encrypted,
    nestedArchives: nested,
    flags: [...flags],
  };
}

/**
 * Entries whose local header plus compressed data reach into the next entry's local header
 * (sorted by offset): the Fifield non-recursive zip bomb, or entries sharing one header.
 */
function hasOverlap(offsets: { offset: number; compressedSize: number }[]): boolean {
  const sorted = [...offsets].sort((a, b) => a.offset - b.offset);
  for (let index = 1; index < sorted.length; index++) {
    const previous = sorted[index - 1];
    const current = sorted[index];
    if (previous === undefined || current === undefined) continue;
    if (current.offset < previous.offset + LOCAL_HEADER_MIN_BYTES + previous.compressedSize)
      return true;
  }
  return false;
}
