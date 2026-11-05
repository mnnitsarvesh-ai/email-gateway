import { createHash } from 'node:crypto';
import type { Readable } from 'node:stream';
import { crc32, createGunzip } from 'node:zlib';
import type { FileTypeId, YaraMatch } from '@email-gateway/security-contracts';
import { extract as tarExtract } from 'tar-stream';
import { type Entry, fromBuffer, type ZipFile } from 'yauzl';
import {
  type ArchiveContent,
  type EntryFinding,
  type EntryHash,
  INSPECTOR_VERSION,
  type InspectionResult,
  type InspectLimits,
  type InspectorCode,
} from '../content';
import { executableDisguised } from '../type-rules';
import {
  contentType,
  detectMagic,
  emptyZipNames,
  extensionTypeOfName,
  noteZipName,
  oleHasVba,
  refineTextType,
  subtypeZip,
  TEXT_LIKE_TYPES,
  type ZipNames,
} from './file-type';
import { addMatches, type YaraEngine } from './yara-scanner';

/**
 * The inspection of one attachment (step 4.2 A4), inside the inspector child, over an in-memory
 * buffer: true type (A5), the archive walk (zip, gzip, tar and their compositions; 7z, rar, cab,
 * bzip2, xz recorded as unsupported) with every limit checked while inflating, YARA on the
 * attachment and on every inspected entry, the office macro marker. Depth-first, one entry
 * buffer per level; nothing is written anywhere, nothing is executed. Entries are addressed by
 * index path (`"2/0/5"`); their names are read only to sub-type containers, to imply an entry's
 * extension type and to detect path traversal, and are dropped at once.
 */

/** At most this many YARA matches per attachment (A4). */
const MAX_YARA_MATCHES = 32;
/** Formats the walker records as unsupported (rule U1; ClamAV unpacks them, A7). */
const UNSUPPORTED: ReadonlySet<FileTypeId> = new Set<FileTypeId>([
  '7z',
  'rar',
  'cab',
  'bzip2',
  'xz',
]);
/** Zip-based containers walked like a zip (OOXML/ODF parts, Java/Android packages). */
const ZIP_BASED: ReadonlySet<FileTypeId> = new Set<FileTypeId>([
  'zip',
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'odf',
  'jar',
  'apk',
]);

class Walk {
  entries = 0;
  decompressed = 0;
  maxRatio = 0;
  depthReached = 0;
  encrypted = false;
  malformed = false;
  stopped = false;
  readonly limits = new Set<InspectorCode>();
  readonly codes = new Set<InspectorCode>();
  readonly findings: EntryFinding[] = [];
  findingCount = 0;
  readonly entryHashes: EntryHash[] = [];
  readonly yara: YaraMatch[] = [];
  yaraTimedOut = false;

  constructor(
    readonly limits_: InspectLimits,
    readonly yaraEngine: YaraEngine,
    readonly attachmentBytes: number,
  ) {}

  limit(code: InspectorCode): void {
    this.limits.add(code);
  }

  finding(path: string, type: FileTypeId, codes: readonly InspectorCode[]): void {
    if (codes.length === 0) return;
    this.findingCount += 1;
    if (this.findings.length < this.limits_.maxEntryFindings) {
      this.findings.push({ path, type, codes: [...new Set(codes)].slice(0, 16) });
    }
  }
}

const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

/** Entry name from its raw bytes (bit 11 = UTF-8, else CP437 approximated as latin1). */
const entryName = (raw: Buffer, flags: number): string =>
  raw.toString((flags & 0x800) !== 0 ? 'utf8' : 'latin1');

/** Absolute, drive-letter, backslash-escaping or `..` names (A4 `archive.path_traversal`). */
export function isTraversalName(name: string): boolean {
  if (name.startsWith('/') || name.startsWith('\\') || /^[A-Za-z]:/.test(name)) return true;
  return name.split(/[\\/]/).includes('..');
}

const isEncryptedEntry = (entry: Entry): boolean =>
  (entry.generalPurposeBitFlag & 0x0001) !== 0 ||
  (entry.generalPurposeBitFlag & 0x0040) !== 0 ||
  entry.compressionMethod === 99 ||
  entry.extraFields.some((field) => field.id === 0x9901);

function openZip(bytes: Buffer): Promise<ZipFile> {
  return new Promise((resolve, reject) => {
    fromBuffer(
      bytes,
      {
        lazyEntries: true,
        autoClose: false,
        // Names are decoded and checked here (yauzl's own check rejects the whole archive).
        decodeStrings: false,
        validateEntrySizes: true,
        strictFileNames: false,
      },
      (error, zip) => (error ? reject(error) : resolve(zip)),
    );
  });
}

function nextEntry(zip: ZipFile): Promise<Entry | null> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      zip.removeListener('entry', onEntry);
      zip.removeListener('end', onEnd);
      zip.removeListener('error', onError);
    };
    const onEntry = (entry: Entry) => {
      cleanup();
      resolve(entry);
    };
    const onEnd = () => {
      cleanup();
      resolve(null);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    zip.once('entry', onEntry);
    zip.once('end', onEnd);
    zip.once('error', onError);
    zip.readEntry();
  });
}

function openEntry(zip: ZipFile, entry: Entry): Promise<Readable> {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => (error ? reject(error) : resolve(stream)));
  });
}

type ReadOutcome =
  { kind: 'data'; data: Buffer; malformed: boolean } | { kind: 'limit'; code: InspectorCode };

/**
 * Reads an entry stream into one buffer, checking every limit on each chunk (A4: a bomb stops at
 * the first breach): entry size, the entry's ratio to its compressed size, the decompressed
 * total and the overall ratio to the attachment size (the last two stop the whole walk).
 */
async function readCounted(
  walk: Walk,
  stream: AsyncIterable<Buffer>,
  compressedSize: number,
): Promise<ReadOutcome> {
  const { limits_: limits } = walk;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of stream) {
      size += chunk.length;
      walk.decompressed += chunk.length;
      const ratio = size / Math.max(compressedSize, 1);
      walk.maxRatio = Math.max(walk.maxRatio, ratio);
      if (walk.decompressed > limits.maxDecompressedBytes) {
        walk.stopped = true;
        return { kind: 'limit', code: 'limit.decompressed_size' };
      }
      if (walk.decompressed / Math.max(walk.attachmentBytes, 1) > limits.maxCompressionRatio) {
        walk.stopped = true;
        return { kind: 'limit', code: 'limit.compression_ratio' };
      }
      if (size > limits.maxEntryBytes) return { kind: 'limit', code: 'limit.entry_size' };
      if (ratio > limits.maxCompressionRatio) {
        return { kind: 'limit', code: 'limit.compression_ratio' };
      }
      chunks.push(chunk);
    }
  } catch {
    // CRC, size or inflate error, truncated stream: what was read is still inspected.
    return { kind: 'data', data: Buffer.concat(chunks), malformed: true };
  }
  return { kind: 'data', data: Buffer.concat(chunks), malformed: false };
}

/** Type, hash, YARA and nested walk of one entry at `depth` (≥ 1). */
async function processEntry(
  walk: Walk,
  data: Buffer,
  path: string,
  depth: number,
  ext: FileTypeId | null,
  extraCodes: InspectorCode[],
): Promise<void> {
  walk.depthReached = Math.max(walk.depthReached, depth);
  const codes = [...extraCodes];
  let type = detectMagic(data);
  type = await walkNested(walk, type, data, depth, path, codes);
  type = refineTextType(type, ext);
  if (executableDisguised(type, ext)) codes.push('type.executable_disguised');
  const yara = walk.yaraEngine.scan(data);
  if (yara.timedOut) {
    walk.yaraTimedOut = true;
    codes.push('limit.yara_timeout');
  }
  addMatches(walk.yara, path, yara, MAX_YARA_MATCHES);
  if (walk.entryHashes.length < walk.limits_.archiveMaxEntries) {
    walk.entryHashes.push({ path, sha256: sha256(data), type, ext });
  }
  for (const code of codes) {
    if (code.startsWith('limit.')) walk.limit(code);
    else if (code !== 'type.executable_disguised') walk.codes.add(code);
  }
  if (yara.matches.length > 0 && codes.length === 0) {
    // A YARA hit alone is a finding too (the mapper adds `yara.*` from the matches).
    walk.findingCount += 1;
    if (walk.findings.length < walk.limits_.maxEntryFindings) {
      walk.findings.push({ path, type, codes: [] });
    }
  } else {
    walk.finding(path, type, codes);
  }
}

/**
 * Walks `data` (detected as `type`, at `depth`) when it is a container; returns the refined
 * type (zip sub-types). Adds codes for the entry that holds it.
 */
async function walkNested(
  walk: Walk,
  type: FileTypeId,
  data: Buffer,
  depth: number,
  path: string | null,
  codes: InspectorCode[],
): Promise<FileTypeId> {
  if (UNSUPPORTED.has(type)) {
    codes.push('archive.unsupported_format');
    return type;
  }
  if (type === 'ole_office' && oleHasVba(data)) codes.push('office.macros');
  const walkable = type === 'zip' || type === 'gzip' || type === 'tar';
  if (!walkable) return type;
  if (walk.stopped) return type;
  if (depth + 1 > walk.limits_.archiveMaxDepth) {
    codes.push('limit.archive_depth');
    return type;
  }
  if (type === 'zip') {
    const names = await walkZip(walk, data, depth, path, codes);
    const subtype = subtypeZip(names);
    if (names.hasVbaProject || names.hasOdfBasic) codes.push('office.macros');
    return subtype;
  }
  if (type === 'gzip') await walkGzip(walk, data, depth, path, codes);
  else await walkTar(walk, data, depth, path, codes);
  return type;
}

const childPath = (prefix: string | null, index: number): string =>
  prefix === null ? String(index) : `${prefix}/${String(index)}`;

/** Counts one more entry; false (and the limit) when the total entry limit is reached. */
function countEntry(walk: Walk): boolean {
  if (walk.entries >= walk.limits_.archiveMaxEntries) {
    walk.limit('limit.archive_entries');
    walk.stopped = true;
    return false;
  }
  walk.entries += 1;
  return true;
}

async function walkZip(
  walk: Walk,
  bytes: Buffer,
  depth: number,
  prefix: string | null,
  codes: InspectorCode[],
): Promise<ZipNames> {
  const names = emptyZipNames();
  let zip: ZipFile;
  try {
    zip = await openZip(bytes);
  } catch {
    walk.malformed = true;
    codes.push('archive.malformed');
    return names;
  }
  const ranges: Array<{ start: number; end: number }> = [];
  try {
    for (let index = 0; !walk.stopped; index += 1) {
      let entry: Entry | null;
      try {
        entry = await nextEntry(zip);
      } catch (error) {
        // yauzl 3.x refuses the whole archive at an entry with the strong-encryption bit (6)
        // ("strong encryption is not supported"): an encrypted archive, not a malformed one.
        if ((error as Error | null)?.message === 'strong encryption is not supported') {
          walk.encrypted = true;
          walk.codes.add('archive.encrypted');
          codes.push('archive.encrypted');
        } else {
          walk.malformed = true;
          codes.push('archive.malformed');
        }
        break;
      }
      if (entry === null) break;
      if (!countEntry(walk)) break;
      const name = entryName(entry.fileNameRaw, entry.generalPurposeBitFlag);
      noteZipName(names, name);
      const path = childPath(prefix, index);
      const entryCodes: InspectorCode[] = [];
      ranges.push({
        start: entry.relativeOffsetOfLocalHeader,
        end: entry.relativeOffsetOfLocalHeader + 30 + entry.fileNameLength + entry.compressedSize,
      });
      if (isTraversalName(name)) {
        entryCodes.push('archive.path_traversal');
        walk.codes.add('archive.path_traversal');
      }
      const ext = extensionTypeOfName(name);
      if (name.endsWith('/')) {
        walk.finding(path, 'unknown', entryCodes);
        continue;
      }
      if (isEncryptedEntry(entry)) {
        walk.encrypted = true;
        walk.codes.add('archive.encrypted');
        walk.finding(path, ext ?? 'unknown', [...entryCodes, 'archive.encrypted']);
        continue;
      }
      if (entry.compressionMethod !== 0 && entry.compressionMethod !== 8) {
        walk.codes.add('archive.unsupported_format');
        walk.finding(path, ext ?? 'unknown', [...entryCodes, 'archive.unsupported_format']);
        continue;
      }
      const declaredRatio = entry.uncompressedSize / Math.max(entry.compressedSize, 1);
      walk.maxRatio = Math.max(walk.maxRatio, declaredRatio);
      if (declaredRatio > walk.limits_.maxCompressionRatio) {
        walk.limit('limit.compression_ratio');
        walk.finding(path, ext ?? 'unknown', [...entryCodes, 'limit.compression_ratio']);
        continue;
      }
      if (entry.uncompressedSize > walk.limits_.maxEntryBytes) {
        walk.limit('limit.entry_size');
        walk.finding(path, ext ?? 'unknown', [...entryCodes, 'limit.entry_size']);
        continue;
      }
      let stream: Readable;
      try {
        stream = await openEntry(zip, entry);
      } catch {
        walk.malformed = true;
        walk.codes.add('archive.malformed');
        walk.finding(path, ext ?? 'unknown', [...entryCodes, 'archive.malformed']);
        continue;
      }
      const read = await readCounted(walk, stream as AsyncIterable<Buffer>, entry.compressedSize);
      if (!stream.destroyed) stream.destroy();
      if (read.kind === 'limit') {
        walk.limit(read.code);
        walk.finding(path, ext ?? 'unknown', [...entryCodes, read.code]);
        continue;
      }
      let malformed = read.malformed;
      if (!malformed && crc32(read.data) !== entry.crc32) malformed = true;
      if (malformed) {
        walk.malformed = true;
        walk.codes.add('archive.malformed');
        entryCodes.push('archive.malformed');
      }
      if (name === 'mimetype' && read.data.length < 256) {
        names.odfMimetype = read.data
          .toString('latin1')
          .startsWith('application/vnd.oasis.opendocument');
      }
      await processEntry(walk, read.data, path, depth + 1, ext, entryCodes);
    }
  } finally {
    zip.close();
  }
  ranges.sort((a, b) => a.start - b.start);
  for (let i = 1; i < ranges.length; i += 1) {
    if (ranges[i]!.start < ranges[i - 1]!.end) {
      walk.codes.add('archive.overlapping_entries');
      codes.push('archive.overlapping_entries');
      break;
    }
  }
  return names;
}

async function walkGzip(
  walk: Walk,
  bytes: Buffer,
  depth: number,
  prefix: string | null,
  codes: InspectorCode[],
): Promise<void> {
  if (!countEntry(walk)) return;
  const path = childPath(prefix, 0);
  // Multi-member streams are decoded as one (zlib continues after each member's trailer);
  // the ISIZE trailer is a hint only and is not read.
  const gunzip = createGunzip();
  gunzip.end(bytes);
  const read = await readCounted(walk, gunzip, bytes.length);
  gunzip.destroy();
  if (read.kind === 'limit') {
    walk.limit(read.code);
    walk.finding(path, 'unknown', [read.code]);
    return;
  }
  const entryCodes: InspectorCode[] = [];
  if (read.malformed) {
    walk.malformed = true;
    walk.codes.add('archive.malformed');
    codes.push('archive.malformed');
    entryCodes.push('archive.malformed');
  }
  if (read.data.length === 0) {
    walk.finding(path, 'unknown', entryCodes);
    return;
  }
  await processEntry(walk, read.data, path, depth + 1, null, entryCodes);
}

async function walkTar(
  walk: Walk,
  bytes: Buffer,
  depth: number,
  prefix: string | null,
  codes: InspectorCode[],
): Promise<void> {
  const extractor = tarExtract();
  extractor.end(bytes);
  let index = 0;
  try {
    for await (const entry of extractor) {
      if (walk.stopped || !countEntry(walk)) {
        entry.resume();
        break;
      }
      const path = childPath(prefix, index);
      index += 1;
      const { header } = entry;
      const entryCodes: InspectorCode[] = [];
      if (isTraversalName(header.name)) {
        entryCodes.push('archive.path_traversal');
        walk.codes.add('archive.path_traversal');
      }
      const ext = extensionTypeOfName(header.name);
      if (header.type !== 'file' && header.type !== 'contiguous-file') {
        entry.resume();
        walk.finding(path, 'unknown', entryCodes);
        continue;
      }
      if ((header.size ?? 0) > walk.limits_.maxEntryBytes) {
        entry.resume();
        walk.limit('limit.entry_size');
        walk.finding(path, ext ?? 'unknown', [...entryCodes, 'limit.entry_size']);
        continue;
      }
      const read = await readCounted(walk, entry as AsyncIterable<Buffer>, header.size ?? 0);
      if (read.kind === 'limit') {
        entry.resume();
        walk.limit(read.code);
        walk.finding(path, ext ?? 'unknown', [...entryCodes, read.code]);
        if (walk.stopped) break;
        continue;
      }
      await processEntry(walk, read.data, path, depth + 1, ext, entryCodes);
    }
  } catch {
    walk.malformed = true;
    walk.codes.add('archive.malformed');
    codes.push('archive.malformed');
  } finally {
    extractor.destroy();
  }
}

/** Inspects one attachment's bytes (A4). */
export async function inspectBytes(
  bytes: Buffer,
  limits: InspectLimits,
  yara: YaraEngine,
): Promise<InspectionResult> {
  const walk = new Walk(limits, yara, bytes.length);
  const topCodes: InspectorCode[] = [];
  let detected = detectMagic(bytes);
  const textLike = TEXT_LIKE_TYPES.has(detected);

  // YARA on the attachment (A4); never on more than ATTACHMENT_MAX_ENTRY_BYTES (binding 0.10.0
  // has no setMaxScanSize, §12 WP2): a larger attachment is scanned in its first part only.
  if (bytes.length > limits.maxEntryBytes) walk.limit('limit.entry_size');
  const top = yara.scan(
    bytes.length > limits.maxEntryBytes ? bytes.subarray(0, limits.maxEntryBytes) : bytes,
  );
  if (top.timedOut) {
    walk.yaraTimedOut = true;
    walk.limit('limit.yara_timeout');
  }
  addMatches(walk.yara, 'attachment', top, MAX_YARA_MATCHES);

  let archive: ArchiveContent | null = null;
  const container = detected === 'zip' || detected === 'gzip' || detected === 'tar';
  if (container || UNSUPPORTED.has(detected) || detected === 'ole_office') {
    detected = await walkNested(walk, detected, bytes, 0, null, topCodes);
  }
  for (const code of topCodes) {
    if (code.startsWith('limit.')) walk.limit(code);
    else walk.codes.add(code);
  }
  if (container || UNSUPPORTED.has(detected)) {
    const supported = !UNSUPPORTED.has(detected);
    archive = {
      format: ZIP_BASED.has(detected) ? 'zip' : detected,
      supported,
      depthReached: walk.depthReached,
      entries: walk.entries,
      decompressedBytes: walk.decompressed,
      maxRatio: Math.round(walk.maxRatio * 100) / 100,
      encrypted: walk.encrypted,
      malformed: walk.malformed,
      findings: walk.findings,
      findingCount: walk.findingCount,
      entryHashes: walk.entryHashes,
    };
  }
  return {
    inspectorVersion: INSPECTOR_VERSION,
    type: contentType(detected, textLike),
    yara: { bundleId: yara.bundleId, matches: walk.yara },
    archive,
    limits: [...walk.limits].sort(),
    codes: [...walk.codes].sort(),
  };
}
