import libmime from 'libmime';
import type { MimeDefectCode, MimeLimitName } from './constants';
import { isKnownWordCharset, normalizeCharset } from './decode';
import type { MimeLimits } from './limits';
import {
  BIDI_CONTROLS,
  decodeUtf8Strict,
  global,
  HEADER_CONTROL_CHARS,
  normalizeText,
  truncateCodePoints,
} from './text';
import type { ExtractedHeader } from './types';

/** A header line as mailsplit reports it: the raw bytes as a latin1 ("binary") string. */
export interface RawHeaderLine {
  key: string;
  line: string;
}

/** Allow-list of stored headers, canonical spelling (design M7). */
export const STORED_HEADER_NAMES = [
  'From',
  'Sender',
  'Reply-To',
  'To',
  'Cc',
  'Subject',
  'Message-ID',
  'Date',
  'In-Reply-To',
  'References',
  'Return-Path',
  'Authentication-Results',
] as const;

const CANONICAL = new Map<string, string>(
  STORED_HEADER_NAMES.map((name) => [name.toLowerCase(), name]),
);

/** RFC 5322 §3.6: fields that may occur at most once. */
const SINGLETONS = new Set([
  'from',
  'sender',
  'subject',
  'date',
  'message-id',
  'to',
  'cc',
  'reply-to',
  'in-reply-to',
  'references',
]);

export const HEADER_VALUE_MAX_CODE_POINTS = 2048;
export const SUBJECT_MAX_CODE_POINTS = 998;

/** RFC 5322 field name: printable US-ASCII except colon. */
const FIELD_NAME = /^[\x21-\x39\x3B-\x7E]+$/;

export interface HeaderBlockCheck {
  fieldCount: number;
  defects: MimeDefectCode[];
  /** The first structural limit the block breaches, if any. */
  limit: Extract<MimeLimitName, 'header_count' | 'header_line_length'> | null;
  /** The first line is not a header field. */
  firstLineInvalid: boolean;
}

/** Limits and defects of one node's header block (design M5 header_count/line, M6). */
export function checkHeaderBlock(
  lines: readonly RawHeaderLine[],
  limits: MimeLimits,
): HeaderBlockCheck {
  const defects = new Set<MimeDefectCode>();
  let limit: HeaderBlockCheck['limit'] = null;
  if (lines.length > limits.maxHeaders) limit = 'header_count';
  let firstLineInvalid = false;
  lines.forEach((entry, index) => {
    const raw = entry.line;
    if (raw.includes('\u0000')) defects.add('nul_bytes');
    if (limit === null && unfold(raw).length > limits.maxHeaderLineBytes)
      limit = 'header_line_length';
    const colon = raw.indexOf(':');
    const name = colon < 0 ? '' : raw.slice(0, colon).trim();
    if (colon < 0 || !FIELD_NAME.test(name)) {
      defects.add('invalid_header_line');
      if (index === 0) firstLineInvalid = true;
    }
  });
  return { fieldCount: lines.length, defects: [...defects], limit, firstLineInvalid };
}

/** RFC 5322 §2.2.3 unfolding: a line break followed by whitespace is removed. */
function unfold(value: string): string {
  return value.replace(/\r?\n(?=[ \t])/g, '');
}

const ENCODED_WORD = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;
const B_TEXT = /^[A-Za-z0-9+/]*={0,2}$/;
const Q_BAD_ESCAPE = /=(?![0-9A-Fa-f]{2})/;
const Q_TEXT = /^[\x21-\x3E\x40-\x7E]*$/;

/** Validates the encoded words of a value, then decodes them with `libmime.decodeWords`. */
function decodeEncodedWords(value: string, defects: Set<MimeDefectCode>): string {
  if (!value.includes('=?')) return value;
  let remainder = value;
  for (const match of value.matchAll(ENCODED_WORD)) {
    const [word, rawCharset = '', encoding = '', text = ''] = match;
    if (!isKnownWordCharset(normalizeCharset(rawCharset))) defects.add('unknown_charset');
    const valid =
      encoding.toUpperCase() === 'B'
        ? B_TEXT.test(text) && text.length % 4 === 0
        : Q_TEXT.test(text) && !Q_BAD_ESCAPE.test(text);
    if (!valid) defects.add('invalid_encoded_word');
    remainder = remainder.replace(word, '');
  }
  // An `=?` that did not form a complete word is a broken word; it stays as it is.
  if (remainder.includes('=?')) defects.add('invalid_encoded_word');
  try {
    return libmime.decodeWords(value);
  } catch {
    defects.add('invalid_encoded_word');
    return value;
  }
}

/**
 * The stored form of one header value (design M7): unfold, raw UTF-8 or latin1, RFC 2047, NFC
 * and well-formed, controls replaced, bidi controls flagged, truncated at a code-point boundary.
 */
export function decodeHeaderValue(
  rawLine: string,
  maxCodePoints: number,
  defects: Set<MimeDefectCode>,
): { value: string; truncated: boolean } {
  const colon = rawLine.indexOf(':');
  const raw = unfold(colon < 0 ? rawLine : rawLine.slice(colon + 1)).replace(
    /^[ \t]+|[ \t]+$/g,
    '',
  );
  let text = raw;
  if (/[\x80-\xFF]/.test(raw)) {
    const utf8 = decodeUtf8Strict(Buffer.from(raw, 'latin1'));
    if (utf8 === null) defects.add('unknown_charset');
    else text = utf8;
  }
  text = normalizeText(decodeEncodedWords(text, defects));
  if (HEADER_CONTROL_CHARS.test(text)) {
    defects.add('header_control_chars');
    text = text.replace(global(HEADER_CONTROL_CHARS), '\uFFFD');
  }
  if (BIDI_CONTROLS.test(text)) defects.add('header_bidi_control');
  return truncateCodePoints(text, maxCodePoints);
}

export interface TopLevelHeaders {
  headers: ExtractedHeader[];
  subject: string | null;
}

/** Stored headers and the decoded subject of the top-level block (design M7). */
export function extractTopLevelHeaders(
  lines: readonly RawHeaderLine[],
  limits: MimeLimits,
  defects: Set<MimeDefectCode>,
): TopLevelHeaders {
  const headers: ExtractedHeader[] = [];
  const seen = new Map<string, number>();
  let subject: string | null = null;
  for (const entry of lines) {
    const name = CANONICAL.get(entry.key);
    if (name === undefined) continue;
    if (SINGLETONS.has(entry.key)) {
      const count = (seen.get(entry.key) ?? 0) + 1;
      seen.set(entry.key, count);
      if (count === 2) defects.add('duplicate_singleton_header');
    }
    if (entry.key === 'subject' && subject === null) {
      const decoded = decodeHeaderValue(entry.line, SUBJECT_MAX_CODE_POINTS, defects);
      if (decoded.truncated) defects.add('subject_truncated');
      subject = decoded.value;
    }
    if (headers.length >= limits.maxStoredHeaders) {
      defects.add('stored_headers_truncated');
      continue;
    }
    const decoded = decodeHeaderValue(entry.line, HEADER_VALUE_MAX_CODE_POINTS, defects);
    if (decoded.truncated) defects.add('header_value_truncated');
    headers.push({ seq: headers.length, name, value: decoded.value });
  }
  return { headers, subject };
}
