/**
 * Version of the parse output. Bump it on every change that alters the output for the same input
 * (part indices, keys, defects, flags, header values), because part keys and rows are derived
 * from it (design M4, M12).
 */
export const PARSER_VERSION = 'mime-1';

/**
 * Longest `partPath` the parser records (`email_attachments.part_path` is VARCHAR(128)). A node
 * whose path would be longer stops the parse as `nesting_depth`, like a node below `maxDepth`:
 * paths grow with depth, so only very deep trees with wide levels reach it.
 */
export const MAX_PART_PATH_CHARS = 128;

/**
 * Limit names recorded in `limitsExceeded` (design M5), in the order of the design table.
 * `@email-gateway/event-contracts` keeps its own copy; email-worker asserts that both are equal.
 */
export const MIME_LIMIT_NAMES = [
  'message_size',
  'nesting_depth',
  'part_count',
  'header_count',
  'header_line_length',
  'header_block_size',
  'attachment_count',
  'attachment_size',
  'body_size',
  'decoded_ratio',
  'total_decoded_size',
  'parse_timeout',
] as const;
export type MimeLimitName = (typeof MIME_LIMIT_NAMES)[number];

/** Malformed-MIME and storage-cap codes (design M6). snake_case, at most 48 characters. */
export const MIME_DEFECT_CODES = [
  'no_headers',
  'invalid_header_line',
  'missing_boundary_parameter',
  'boundary_not_found',
  'missing_closing_boundary',
  'invalid_base64',
  'invalid_quoted_printable',
  'unknown_transfer_encoding',
  'unknown_charset',
  'invalid_encoded_word',
  'duplicate_singleton_header',
  'header_control_chars',
  'header_bidi_control',
  'header_value_truncated',
  'stored_headers_truncated',
  'subject_truncated',
  'nul_bytes',
  'empty_message',
] as const;
export type MimeDefectCode = (typeof MIME_DEFECT_CODES)[number];

/** Per-attachment flags (design M9 filename and sniff flags, M10 archive flags). */
export const ATTACHMENT_FLAGS = [
  // M9 filename rules
  'filename_path_stripped',
  'filename_control_chars',
  'filename_bidi_control',
  'filename_zero_width',
  'filename_whitespace_padding',
  'filename_reserved_name',
  'filename_truncated',
  'filename_missing',
  'filename_executable_extension',
  'filename_double_extension',
  'filename_extension_mismatch',
  'original_filename_truncated',
  // M9 sniffing and storage
  'content_type_mismatch',
  'executable',
  'archive',
  'nested_message_part',
  'not_stored_size_limit',
  // M10 archives
  'archive_entry_count',
  'archive_compression_ratio',
  'archive_total_size',
  'archive_encrypted',
  'archive_nested',
  'archive_overlapping_entries',
  'archive_path_traversal',
  'archive_malformed',
  'archive_not_inspected',
] as const;
export type AttachmentFlag = (typeof ATTACHMENT_FLAGS)[number];

export const MESSAGE_PARSE_STATUSES = [
  'parsed',
  'parsed_with_defects',
  'parse_limit_exceeded',
  'parse_failed',
] as const;
export type MimeParseStatus = (typeof MESSAGE_PARSE_STATUSES)[number];
