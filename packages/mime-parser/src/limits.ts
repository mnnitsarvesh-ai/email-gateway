/**
 * Parser limits (design M5) plus the storage caps of M7/M9 and the archive thresholds of M10.
 * email-worker validates them in its zod config (cross-field rules); the library only refuses
 * values that would make it misbehave (`assertMimeLimits`).
 */
export interface MimeLimits {
  /** `message_size`: bytes of the whole input (MIME_MAX_MESSAGE_BYTES). */
  maxMessageBytes: number;
  /** `nesting_depth`: root 0, every multipart child and every embedded message root +1 (MIME_MAX_DEPTH). */
  maxDepth: number;
  /** `part_count`: nodes of the tree, containers and leaves (MIME_MAX_PARTS). */
  maxParts: number;
  /** `header_count`: header fields of any one node's header block (MIME_MAX_HEADERS). */
  maxHeaders: number;
  /** `header_line_length`: bytes of one unfolded header field (MIME_MAX_HEADER_LINE_BYTES). */
  maxHeaderLineBytes: number;
  /** `header_block_size`: mailsplit `maxHeadSize` per node (MIME_MAX_HEADER_BLOCK_BYTES). */
  maxHeaderBlockBytes: number;
  /** `attachment_count`: leaves classified as attachments (MIME_MAX_ATTACHMENTS). */
  maxAttachments: number;
  /** `attachment_size`: decoded bytes of one attachment (MIME_MAX_ATTACHMENT_BYTES). */
  maxAttachmentBytes: number;
  /** `body_size`: decoded and UTF-8 converted bytes of the text or HTML body (MIME_MAX_BODY_BYTES). */
  maxBodyBytes: number;
  /** `decoded_ratio`: decoded ÷ max(encoded, 1) per leaf, checked from 64 KiB decoded (MIME_MAX_DECODED_RATIO). */
  maxDecodedRatio: number;
  /** `total_decoded_size`: decoded bytes over all leaves (MIME_MAX_TOTAL_DECODED_BYTES). */
  maxTotalDecodedBytes: number;
  /** `parse_timeout`: wall clock of `parseMessage` itself, on top of the caller's signal (MIME_PARSE_TIMEOUT_MS). */
  parseTimeoutMs: number;
  /** Rows of `email_headers` kept (MIME_MAX_STORED_HEADERS). */
  maxStoredHeaders: number;
  /** Code points of a sanitized filename (MIME_FILENAME_MAX_CHARS). */
  filenameMaxChars: number;
  /** M10: entries read from a zip central directory before `archive_entry_count`. */
  archiveMaxEntries: number;
  /** M10: uncompressed ÷ compressed above which `archive_compression_ratio` is set. */
  archiveMaxRatio: number;
  /** M10: declared uncompressed total above which `archive_total_size` is set. */
  archiveMaxTotalUncompressedBytes: number;
  /** M10: central directory bytes above which the zip is `archive_not_inspected`. */
  archiveMaxCentralDirectoryBytes: number;
}

/** The defaults of design §5. */
export const DEFAULT_MIME_LIMITS: Readonly<MimeLimits> = Object.freeze({
  maxMessageBytes: 53_477_376,
  maxDepth: 10,
  maxParts: 250,
  maxHeaders: 1_000,
  maxHeaderLineBytes: 32_768,
  maxHeaderBlockBytes: 262_144,
  maxAttachments: 100,
  maxAttachmentBytes: 26_214_400,
  maxBodyBytes: 10_485_760,
  maxDecodedRatio: 1.1,
  maxTotalDecodedBytes: 104_857_600,
  parseTimeoutMs: 120_000,
  maxStoredHeaders: 200,
  filenameMaxChars: 200,
  archiveMaxEntries: 1_000,
  archiveMaxRatio: 100,
  archiveMaxTotalUncompressedBytes: 1_073_741_824,
  archiveMaxCentralDirectoryBytes: 8_388_608,
});

const INTEGER_FIELDS = [
  'maxMessageBytes',
  'maxDepth',
  'maxParts',
  'maxHeaders',
  'maxHeaderLineBytes',
  'maxHeaderBlockBytes',
  'maxAttachments',
  'maxAttachmentBytes',
  'maxBodyBytes',
  'maxTotalDecodedBytes',
  'parseTimeoutMs',
  'maxStoredHeaders',
  'filenameMaxChars',
  'archiveMaxEntries',
  'archiveMaxTotalUncompressedBytes',
  'archiveMaxCentralDirectoryBytes',
] as const satisfies readonly (keyof MimeLimits)[];

/**
 * Refuses limits the parser cannot work with (a programming error, not a content outcome).
 * Product rules (for example attachment ≤ message size) are the caller's config validation.
 */
export function assertMimeLimits(limits: MimeLimits): void {
  for (const field of INTEGER_FIELDS) {
    const value = limits[field];
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`MimeLimits.${field} must be a positive safe integer`);
    }
  }
  for (const field of ['maxDecodedRatio', 'archiveMaxRatio'] as const) {
    const value = limits[field];
    if (!Number.isFinite(value) || value <= 0) {
      throw new RangeError(`MimeLimits.${field} must be a positive finite number`);
    }
  }
  if (limits.filenameMaxChars < 16) {
    throw new RangeError('MimeLimits.filenameMaxChars must be at least 16');
  }
}
