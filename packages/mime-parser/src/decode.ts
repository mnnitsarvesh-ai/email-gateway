import iconv from 'iconv-lite';
import * as libbase64 from 'libbase64';
import * as libqp from 'libqp';

/**
 * Streaming transfer and charset decoding (design M4 "Leaf decoding"). All decoders are
 * synchronous and incremental: each `write` returns what can be decoded so far, `end` the rest,
 * so the parser controls the pace (and awaits the sink) without stream plumbing in between.
 */
export interface ChunkDecoder {
  write(chunk: Buffer): Buffer;
  end(): Buffer;
  /** True once malformed input was seen (`invalid_base64` / `invalid_quoted_printable`). */
  readonly invalid: boolean;
}

const EMPTY = Buffer.alloc(0);

/** 7bit, 8bit, binary and unknown encodings: the bytes as they are. */
export class PassThroughDecoder implements ChunkDecoder {
  readonly invalid = false;
  write(chunk: Buffer): Buffer {
    return chunk;
  }
  end(): Buffer {
    return EMPTY;
  }
}

const BASE64_ALPHABET_OR_WSP = /[^A-Za-z0-9+/=\r\n\t ]/;
const NOT_BASE64_ALPHABET = /[^A-Za-z0-9+/=]/g;

/**
 * Base64 with `libbase64.decode` over quartet-aligned input, the same segmentation as
 * `libbase64.Decoder` (everything up to the last padding character, then whole quartets), so at
 * most three characters are held back. Characters outside the alphabet are skipped as libbase64
 * skips them and mark the input invalid, as does a length that is not a multiple of four.
 */
export class Base64Decoder implements ChunkDecoder {
  private rest = '';
  private characters = 0;
  private sawInvalid = false;

  get invalid(): boolean {
    return this.sawInvalid || this.characters % 4 !== 0;
  }

  write(chunk: Buffer): Buffer {
    if (chunk.length === 0) return EMPTY;
    let text = chunk.toString('latin1');
    if (BASE64_ALPHABET_OR_WSP.test(text)) this.sawInvalid = true;
    text = text.replace(NOT_BASE64_ALPHABET, '');
    this.characters += text.length;
    let input = this.rest + text;
    this.rest = '';
    let padded = '';
    const lastPad = input.lastIndexOf('=');
    if (lastPad >= 0) {
      padded = input.slice(0, lastPad + 1);
      input = input.slice(lastPad + 1);
    }
    const keep = input.length % 4;
    if (keep) {
      this.rest = input.slice(input.length - keep);
      input = input.slice(0, input.length - keep);
    }
    const whole = padded + input;
    return whole ? libbase64.decode(whole) : EMPTY;
  }

  end(): Buffer {
    if (!this.rest) return EMPTY;
    const rest = this.rest;
    this.rest = '';
    return libbase64.decode(rest);
  }
}

/** Longest run without a line break kept back before it is decoded in a safe place anyway. */
const QP_MAX_PENDING = 64 * 1024;
/** `=` not followed by two hex digits or by a (soft) line break. */
const INVALID_QP_ESCAPE = /=(?![0-9A-Fa-f]{2})(?![ \t]*(?:\r?\n|$))/;

/**
 * Quoted-printable with `libqp.decode` over line-aligned batches. `libqp.Decoder` concatenates
 * the whole part and decodes it on flush, which would hold up to a full attachment in memory, so
 * it is not used (deviation from design M4, documented in the README). Decoding whole lines
 * gives exactly libqp's output: escapes, soft line breaks and the trailing whitespace rule never
 * span a line break. A line longer than 64 KiB is cut before any trailing whitespace and before
 * a `=` in its last two characters, so no escape or soft break is split.
 */
export class QuotedPrintableDecoder implements ChunkDecoder {
  private pending = '';
  private sawInvalid = false;

  get invalid(): boolean {
    return this.sawInvalid;
  }

  write(chunk: Buffer): Buffer {
    if (chunk.length === 0) return EMPTY;
    const text = this.pending + chunk.toString('latin1');
    let cut = text.lastIndexOf('\n') + 1;
    if (cut === 0) {
      if (text.length <= QP_MAX_PENDING) {
        this.pending = text;
        return EMPTY;
      }
      cut = safeCut(text);
    }
    this.pending = text.slice(cut);
    return this.decode(text.slice(0, cut));
  }

  end(): Buffer {
    const rest = this.pending;
    this.pending = '';
    return rest ? this.decode(rest) : EMPTY;
  }

  private decode(text: string): Buffer {
    if (!this.sawInvalid && INVALID_QP_ESCAPE.test(text)) this.sawInvalid = true;
    return libqp.decode(Buffer.from(text, 'latin1'));
  }
}

function safeCut(text: string): number {
  let cut = text.length;
  while (cut > 0 && (text[cut - 1] === ' ' || text[cut - 1] === '\t')) cut--;
  if (cut > 0 && text[cut - 1] === '=') cut--;
  else if (cut > 1 && text[cut - 2] === '=') cut -= 2;
  // A pathological run of whitespace: cut inside it (libqp drops whitespace at a cut, which
  // only ever removes padding) rather than buffering it without bound.
  return cut > 0 ? cut : text.length - 2;
}

export const KNOWN_TRANSFER_ENCODINGS = new Set([
  '',
  '7bit',
  '8bit',
  'binary',
  'base64',
  'quoted-printable',
]);

export function transferDecoder(encoding: string): ChunkDecoder {
  switch (encoding) {
    case 'base64':
      return new Base64Decoder();
    case 'quoted-printable':
      return new QuotedPrintableDecoder();
    default:
      return new PassThroughDecoder();
  }
}

/**
 * A declared charset as a normalized token (lower case, quotes and RFC 2231 language removed,
 * at most 64 characters of `[a-z0-9._:+-]`), or null when none was declared.
 */
export function normalizeCharset(raw: string | false | null | undefined): string | null {
  if (!raw) return null;
  let value = raw.trim().replace(/^["']+|["']+$/g, '');
  const star = value.indexOf('*');
  if (star >= 0) value = value.slice(0, star);
  value = value
    .toLowerCase()
    .replace(/[^a-z0-9._:+-]/g, '')
    .slice(0, 64);
  return value || null;
}

/** Charsets read as UTF-8 (ASCII is a subset; "none declared" is us-ascii). */
const UTF8_COMPATIBLE = new Set([
  'us-ascii',
  'ascii',
  'ansi_x3.4-1968',
  'utf-8',
  'utf8',
  'iso-646-us',
]);

/** Charsets libmime decodes through encoding-japanese for encoded words (header use only). */
const JAPANESE = /^(?:iso-?2022-?jp(?:-\w+)?|shift[-_]?jis|sjis|x-sjis|euc-?jp|cp932|windows-31j)$/;

/** iconv-lite name for a body charset, or null when iconv-lite cannot decode it. */
export function iconvCharset(charset: string | null): string | null {
  if (charset === null || UTF8_COMPATIBLE.has(charset)) return 'utf-8';
  return iconv.encodingExists(charset) ? charset : null;
}

/** Whether an encoded-word charset can be decoded by libmime (iconv-lite or encoding-japanese). */
export function isKnownWordCharset(charset: string | null): boolean {
  if (charset === null) return false;
  return iconvCharset(charset) !== null || JAPANESE.test(charset);
}

/** Converts a text body to UTF-8 incrementally (iconv-lite's streaming decoder). */
export class CharsetConverter {
  private readonly decoder: ReturnType<typeof iconv.getDecoder>;

  constructor(iconvName: string) {
    this.decoder = iconv.getDecoder(iconvName, { stripBOM: false });
  }

  write(chunk: Buffer): Buffer {
    if (chunk.length === 0) return EMPTY;
    const text = this.decoder.write(chunk);
    return text ? Buffer.from(text, 'utf8') : EMPTY;
  }

  end(): Buffer {
    const text = this.decoder.end();
    return text ? Buffer.from(text, 'utf8') : EMPTY;
  }
}
