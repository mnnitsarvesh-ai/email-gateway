import { assertMimeLimits, type MimeLimits } from '@email-gateway/mime-parser';
import type { WorkerConfig } from '../config';

/** The parser limits of design M5/M7/M9/M10 from the validated config. */
export function mimeLimitsFromConfig(config: Readonly<WorkerConfig>): MimeLimits {
  const limits: MimeLimits = {
    maxMessageBytes: config.MIME_MAX_MESSAGE_BYTES,
    maxDepth: config.MIME_MAX_DEPTH,
    maxParts: config.MIME_MAX_PARTS,
    maxHeaders: config.MIME_MAX_HEADERS,
    maxHeaderLineBytes: config.MIME_MAX_HEADER_LINE_BYTES,
    maxHeaderBlockBytes: config.MIME_MAX_HEADER_BLOCK_BYTES,
    maxAttachments: config.MIME_MAX_ATTACHMENTS,
    maxAttachmentBytes: config.MIME_MAX_ATTACHMENT_BYTES,
    maxBodyBytes: config.MIME_MAX_BODY_BYTES,
    maxDecodedRatio: config.MIME_MAX_DECODED_RATIO,
    maxTotalDecodedBytes: config.MIME_MAX_TOTAL_DECODED_BYTES,
    parseTimeoutMs: config.MIME_PARSE_TIMEOUT_MS,
    maxStoredHeaders: config.MIME_MAX_STORED_HEADERS,
    filenameMaxChars: config.MIME_FILENAME_MAX_CHARS,
    archiveMaxEntries: config.MIME_ARCHIVE_MAX_ENTRIES,
    archiveMaxRatio: config.MIME_ARCHIVE_MAX_RATIO,
    archiveMaxTotalUncompressedBytes: config.MIME_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES,
    archiveMaxCentralDirectoryBytes: config.MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES,
  };
  assertMimeLimits(limits);
  return Object.freeze(limits);
}
