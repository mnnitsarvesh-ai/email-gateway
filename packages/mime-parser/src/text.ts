/** Unicode helpers shared by header and filename handling (design M7, M9). */

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** `String.prototype.toWellFormed` (ES2024): lone surrogates become U+FFFD. */
export function toWellFormed(value: string): string {
  return value.replace(LONE_SURROGATE, '\uFFFD');
}

/** NFC plus well-formed, the first step of every untrusted string. */
export function normalizeText(value: string): string {
  return toWellFormed(value).normalize('NFC');
}

/** C0 controls, DEL and C1 controls. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
export const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/u;
/** C0 except HT, DEL and C1: the characters replaced in a stored header value. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
export const HEADER_CONTROL_CHARS = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F]/u;
/** Bidirectional controls (ALM, LRM, RLM, LRE..RLO, LRI..PDI). */
export const BIDI_CONTROLS = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;
/** Zero-width space, non-joiner, joiner and BOM / zero-width no-break space. */
export const ZERO_WIDTH = /[\u200B-\u200D\uFEFF]/u;

export function global(pattern: RegExp): RegExp {
  return new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
  );
}

export function codePointLength(value: string): number {
  let length = 0;
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) index++;
    }
    length++;
  }
  return length;
}

/** First `max` code points of `value` (never splits a surrogate pair). */
export function truncateCodePoints(
  value: string,
  max: number,
): { value: string; truncated: boolean } {
  if (value.length <= max) return { value, truncated: false };
  let count = 0;
  let end = 0;
  for (const char of value) {
    if (count === max) return { value: value.slice(0, end), truncated: true };
    count++;
    end += char.length;
  }
  return { value, truncated: false };
}

/** Decodes bytes as UTF-8 when they are valid UTF-8, otherwise returns null. */
const fatalUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
export function decodeUtf8Strict(bytes: Buffer): string | null {
  try {
    return fatalUtf8.decode(bytes);
  } catch {
    return null;
  }
}
