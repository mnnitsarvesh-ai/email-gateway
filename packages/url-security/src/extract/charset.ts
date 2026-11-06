import iconv from 'iconv-lite';

/**
 * Charset handling shared by extraction (attachment parts, U4) and the rewriter (U11).
 * Only ASCII-compatible charsets are used for rewriting; UTF-16/32, UTF-7, ISO-2022-* and EBCDIC
 * code pages are refused there (`unsupported_charset`).
 */

const UNSUPPORTED_FOR_REWRITE =
  /^(?:utf-?16|utf-?32|ucs-?2|ucs-?4|utf-?7|unicode(?:-1-1)?(?:-utf-?7)?|iso-?2022|csiso2022|cp0?37$|cp273|cp500|cp875|cp1026|cp1140|ibm0?37|ibm273|ibm500|ibm1047|ebcdic|cp1047)/i;

export function normalizeCharset(charset: string | null | undefined): string | null {
  if (!charset) return null;
  const value = charset
    .trim()
    .replace(/^["']|["']$/g, '')
    .toLowerCase();
  return value || null;
}

/** iconv-lite knows the charset and it is ASCII compatible (safe to rewrite in place). */
export function isRewritableCharset(charset: string): boolean {
  const name = normalizeCharset(charset) ?? 'us-ascii';
  if (UNSUPPORTED_FOR_REWRITE.test(name)) return false;
  return iconv.encodingExists(name);
}

/** `<meta charset>` / `http-equiv content-type` within the first 1 024 bytes, else null. */
export function sniffHtmlCharset(bytes: Buffer): string | null {
  const head = bytes.subarray(0, 1024).toString('latin1');
  const direct = /<meta[^>]+charset\s*=\s*["']?\s*([a-z0-9_.:-]+)/i.exec(head);
  return direct ? normalizeCharset(direct[1]) : null;
}

export interface DecodedText {
  text: string;
  charset: string;
  /** No usable declared charset: decoded as UTF-8 (`url.charset_guess`). */
  guessed: boolean;
}

/**
 * Decodes an attachment part for extraction: the declared charset (from `structure`), else the
 * HTML meta charset, else UTF-8 with `guessed`. Unknown charsets fall back the same way.
 */
export function decodeText(
  bytes: Buffer,
  declared: string | null,
  kind: 'text' | 'html',
): DecodedText {
  const candidates = [normalizeCharset(declared), kind === 'html' ? sniffHtmlCharset(bytes) : null];
  for (const charset of candidates) {
    if (charset && iconv.encodingExists(charset)) {
      return { text: iconv.decode(bytes, charset), charset, guessed: false };
    }
  }
  return { text: iconv.decode(bytes, 'utf-8'), charset: 'utf-8', guessed: true };
}

/** Decodes and requires a lossless round trip (`encode(decode(b)) == b`), else null. */
export function decodeLossless(bytes: Buffer, charset: string): string | null {
  const name = normalizeCharset(charset) ?? 'us-ascii';
  if (!iconv.encodingExists(name)) return null;
  const text = iconv.decode(bytes, name, { stripBOM: false });
  const back = iconv.encode(text, name, { addBOM: false });
  return back.equals(bytes) ? text : null;
}

export function encodeText(text: string, charset: string): Buffer {
  return iconv.encode(text, normalizeCharset(charset) ?? 'us-ascii', { addBOM: false });
}
