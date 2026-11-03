import type { AttachmentFlag } from '../constants';
import { ARCHIVE_EXTENSIONS, finalExtension } from '../filename';
import type { MimeLimits } from '../limits';
import type { ArchiveInfo } from '../types';

const FEXTRA = 0x04;
const FNAME = 0x08;
/** Header (10) plus trailer (8): the smallest valid gzip member. */
const MIN_GZIP_BYTES = 18;

/**
 * gzip metadata from the bytes the parser kept while streaming (design M10): the header in the
 * first 4 KiB (FLG, FNAME) and ISIZE in the last 4 of the trailer. ISIZE is the uncompressed size
 * of the last member modulo 2^32, so every number here is a hint; nothing is decompressed.
 */
export function inspectGzip(
  head: Buffer,
  tail: Buffer,
  sizeBytes: number,
  limits: MimeLimits,
): ArchiveInfo {
  const flags = new Set<AttachmentFlag>();
  if (
    sizeBytes < MIN_GZIP_BYTES ||
    head.length < 10 ||
    head[0] !== 0x1f ||
    head[1] !== 0x8b ||
    tail.length < 4
  ) {
    return {
      type: 'gzip',
      inspected: false,
      entries: null,
      declaredUncompressedBytes: null,
      maxRatio: null,
      encryptedEntries: null,
      nestedArchives: null,
      flags: ['archive_malformed'],
    };
  }
  const flg = head[3] ?? 0;
  let position = 10;
  if (flg & FEXTRA && head.length >= position + 2) position += 2 + head.readUInt16LE(position);
  let nested = 0;
  if (flg & FNAME && position < head.length) {
    const end = head.indexOf(0, position);
    // A name that runs past the kept 4 KiB is not judged.
    if (end >= 0) {
      const extension = finalExtension(head.toString('latin1', position, end));
      if (extension !== null && ARCHIVE_EXTENSIONS.has(extension)) nested = 1;
    }
  }
  const isize = tail.readUInt32LE(tail.length - 4);
  const ratio = isize / Math.max(sizeBytes, 1);
  if (ratio > limits.archiveMaxRatio) flags.add('archive_compression_ratio');
  if (isize > limits.archiveMaxTotalUncompressedBytes) flags.add('archive_total_size');
  if (nested) flags.add('archive_nested');
  return {
    type: 'gzip',
    inspected: true,
    entries: 1,
    declaredUncompressedBytes: isize,
    maxRatio: roundRatio(ratio),
    encryptedEntries: 0,
    nestedArchives: nested,
    flags: [...flags],
  };
}

/** Ratios are stored with two decimals (JSON numbers, stable across runs). */
export function roundRatio(ratio: number): number {
  return Math.round(ratio * 100) / 100;
}
