import type { AttachmentFlag, MimeDefectCode, MimeLimitName, MimeParseStatus } from './constants';
import type { MimeLimits } from './limits';

/** What the sink is told about a part before its bytes arrive (design M4, M11). */
export interface PartInfo {
  /** Index of the node in `structure` (document order, 0 = root). Part keys use it. */
  partIndex: number;
  /** Structural path, see `StructureNode.path`. */
  partPath: string;
  depth: number;
  kind: 'text' | 'html' | 'attachment';
}

/** A finished, durable part object. `readRange` serves the archive inspector (M10). */
export interface StoredPart {
  key: string;
  readRange(start: number, endInclusive: number, signal: AbortSignal): Promise<Buffer>;
}

/** Streams one part to storage. Every call is awaited by the parser (backpressure). */
export interface PartWriter {
  write(chunk: Buffer): Promise<void>;
  /** Completes the object; it is durable when the promise resolves. */
  finish(): Promise<StoredPart>;
  /** Discards the object; no object remains afterwards. */
  abort(): Promise<void>;
}

/** Opens one writer per body or attachment leaf. Errors it throws are rethrown by the parser. */
export interface PartSink {
  open(part: PartInfo): Promise<PartWriter>;
}

export interface ParseOptions {
  limits: MimeLimits;
  sink: PartSink;
  /** Wall clock of the whole stage (download to parse end); firing records `parse_timeout`. */
  signal: AbortSignal;
}

export type StructureKind = 'container' | 'text' | 'html' | 'attachment' | 'message';

/**
 * One MIME node in document order (design M13). Never holds filenames or header values; the
 * string fields are normalized MIME tokens.
 */
export interface StructureNode {
  index: number;
  /**
   * `0` for the root, `<parent>.<n>` (n from 1) for the n-th child of a multipart and
   * `<container>.0` for the root of an embedded `message/rfc822`.
   */
  path: string;
  parent: number | null;
  depth: number;
  contentType: string;
  multipart?: string;
  charset?: string;
  encoding?: string;
  disposition?: string;
  encodedBytes?: number;
  decodedBytes?: number;
  kind: StructureKind;
  truncated?: true;
}

/** One stored `email_headers` row (design M7). */
export interface ExtractedHeader {
  seq: number;
  /** Canonical spelling of the allow-list (`From`, `Message-ID`, ...). */
  name: string;
  value: string;
}

export interface BodyResult {
  /** Part key, or null when the body was not stored (`not_stored_size_limit`). */
  key: string | null;
  /** SHA-256 (hex) of the transfer-decoded, UTF-8 converted bytes. */
  sha256: string;
  sizeBytes: number;
  /** Declared charset, normalized (lower-case token), or null when none was declared. */
  charset: string | null;
  partIndex: number;
  flags: AttachmentFlag[];
}

/** Archive metadata stored as `email_attachments.archive_info` (numbers only, no names). */
export interface ArchiveSummary {
  type: 'zip' | 'gzip' | 'bzip2' | 'xz' | '7z' | 'rar' | 'tar' | 'cab';
  inspected: boolean;
  entries: number | null;
  declaredUncompressedBytes: number | null;
  maxRatio: number | null;
  encryptedEntries: number | null;
  nestedArchives: number | null;
}

/** Result of an archive inspector: the stored summary plus the M10 flags it raised. */
export interface ArchiveInfo extends ArchiveSummary {
  flags: AttachmentFlag[];
}

export interface AttachmentResult {
  partIndex: number;
  partPath: string;
  depth: number;
  disposition: 'attachment' | 'inline';
  /** Lower-case `type/subtype` as declared (≤ 255 characters). */
  declaredContentType: string;
  /** From the magic-byte sniffer (M9). */
  detectedContentType: string;
  /** Decoded bytes. */
  sizeBytes: number;
  /** Transfer-encoded bytes as they were in the message. */
  encodedSizeBytes: number;
  /** SHA-256 (hex) of the decoded bytes. */
  sha256: string;
  key: string | null;
  filename: string | null;
  originalFilename: string | null;
  flags: AttachmentFlag[];
  archiveInfo: ArchiveSummary | null;
}

export interface MimeParseStats {
  /** Bytes read from the input. Equal to the input size unless `inputComplete` is false. */
  bytesRead: number;
  /** SHA-256 (hex) of the bytes read. */
  sha256: string;
  /** False when reading stopped before the end of the input (message_size, parse_timeout). */
  inputComplete: boolean;
  /** Nodes in `structure`. */
  partCount: number;
  maxDepth: number;
  /** Header fields of the top-level block (every field, stored or not). */
  headerCount: number;
  attachmentCount: number;
  /** Transfer-decoded bytes over all leaves. */
  decodedBytes: number;
  durationMs: number;
}

export interface MimeParseResult {
  status: MimeParseStatus;
  failureReason?: 'parser_error';
  limitsExceeded: MimeLimitName[];
  defects: MimeDefectCode[];
  stats: MimeParseStats;
  /** Decoded subject (≤ 998 code points), null when the message has none. */
  subject: string | null;
  headers: ExtractedHeader[];
  textBody: BodyResult | null;
  htmlBody: BodyResult | null;
  attachments: AttachmentResult[];
  structure: StructureNode[];
}
