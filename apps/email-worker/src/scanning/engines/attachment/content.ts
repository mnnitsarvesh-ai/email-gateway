import type {
  AttachmentReasonCode,
  FileTypeFamily,
  FileTypeId,
  YaraMatch,
} from '@email-gateway/security-contracts';

/**
 * The tenant-independent content result of one attachment (step 4.2 A4, A10): what the bytes
 * alone say (true type, ClamAV, YARA, archive walk, limits). Cached in Redis under
 * `eg:scan:att:v1:<sha256>:<contentVersion>`, so it never depends on the tenant, the message or
 * the filename: the filename extension, the declared content type, the known-hash catalog and
 * the tenant rules are applied afterwards by the verdict mapper (A6). Bounded and JSON-only:
 * hashes, type ids, rule and signature names, counts and codes; never content, never an archive
 * entry name (entries are addressed by index path).
 */

/** `inspectorVersion` of the content result (A9: part of the content version). */
export const INSPECTOR_VERSION = 'att-inspect/1';

/** Codes the inspector itself reports (a subset of ATTACHMENT_REASON_CODES). */
export type InspectorCode = Extract<
  AttachmentReasonCode,
  | 'limit.archive_depth'
  | 'limit.archive_entries'
  | 'limit.entry_size'
  | 'limit.decompressed_size'
  | 'limit.compression_ratio'
  | 'limit.cpu_time'
  | 'limit.memory'
  | 'limit.yara_timeout'
  | 'archive.encrypted'
  | 'archive.malformed'
  | 'archive.path_traversal'
  | 'archive.overlapping_entries'
  | 'archive.unsupported_format'
  | 'office.macros'
  | 'type.mismatch'
  | 'type.executable_disguised'
>;

export interface ContentType {
  /** True type from magic bytes and structure (scripts are `text`, see `textLike`). */
  detected: FileTypeId;
  family: FileTypeFamily;
  executable: boolean;
  /**
   * Bounded UTF-8/ASCII check passed: the mapper may refine `text` by the filename extension
   * into a script or markup type (A5: scripts have no magic), outside the cache.
   */
  textLike: boolean;
}

export interface ClamavContent {
  /** `size_limit`: clamd refused the stream (`limit.clamav`, A7). */
  status: 'clean' | 'found' | 'size_limit';
  signature: string | null;
  engineVersion: string;
  dbVersion: number;
}

export interface YaraContent {
  bundleId: string;
  /** ≤ 32, rule names only (never matched strings or offsets). */
  matches: YaraMatch[];
}

/** One archive entry with a non-clean content signal (≤ ATTACHMENT_MAX_ENTRY_FINDINGS). */
export interface EntryFinding {
  path: string;
  type: FileTypeId;
  codes: InspectorCode[];
}

/** One inspected entry (≤ ATTACHMENT_ARCHIVE_MAX_ENTRIES): the known-hash and type-rule input. */
export interface EntryHash {
  path: string;
  sha256: string;
  type: FileTypeId;
  /** Type implied by the entry name's extension (the name itself is discarded), or null. */
  ext: FileTypeId | null;
}

export interface ArchiveContent {
  /** Container format (an `archive` family id; OOXML/ODF documents walk as `zip`). */
  format: FileTypeId;
  supported: boolean;
  depthReached: number;
  entries: number;
  decompressedBytes: number;
  maxRatio: number;
  encrypted: boolean;
  malformed: boolean;
  findings: EntryFinding[];
  /** Total findings with a signal, including those past the kept ≤ 20. */
  findingCount: number;
  entryHashes: EntryHash[];
}

export interface ContentResult {
  inspectorVersion: string;
  type: ContentType;
  clamav: ClamavContent;
  /** Null when the inspector was killed (CPU/memory) before YARA ran. */
  yara: YaraContent | null;
  archive: ArchiveContent | null;
  /** `limit.*` codes of the walk, YARA and inspector kills. */
  limits: InspectorCode[];
  /** Other inspector codes (`archive.*`, `office.macros`). */
  codes: InspectorCode[];
}

/** The part of a content result the inspector child produces (the worker adds ClamAV). */
export type InspectionResult = Omit<ContentResult, 'clamav'>;

/** The platform limits the inspector applies (A4, A8): part of the content version (A9). */
export interface InspectLimits {
  archiveMaxDepth: number;
  archiveMaxEntries: number;
  maxEntryBytes: number;
  maxDecompressedBytes: number;
  maxCompressionRatio: number;
  maxEntryFindings: number;
  yaraTimeoutMs: number;
  cpuSeconds: number;
  maxRssMb: number;
}
