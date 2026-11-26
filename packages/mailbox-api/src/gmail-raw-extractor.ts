/**
 * Incremental extractor of Gmail's `format=raw` answers (design D9, risk R10): a JSON object whose
 * top-level string field `raw` holds the RFC 5322 message as base64url (up to ~67 MiB for a
 * 50 MiB message). The extractor scans the JSON byte by byte, independent of field order,
 * skips every other field (strings with escapes, nested objects and arrays, numbers, literals),
 * finds the top-level `"raw"` key (also when the key itself is written with escapes) and decodes
 * its value chunk by chunk, so memory stays bounded by one input chunk.
 *
 * Bounds: `maxDecodedBytes` (the message cap: `response_too_large`) and `maxOtherBytes` (bytes of
 * everything except the raw value). Malformed JSON, a missing, non-string or duplicate top-level
 * `raw`, or invalid base64 fail `unexpected_response`. Accepts the base64url and the standard
 * alphabet, with or without `=` padding; escaped characters and whitespace escapes inside the
 * value are decoded first.
 */
import { MailboxApiError } from './errors';

export interface GmailRawExtractorOptions {
  /** Maximum decoded message size (bytes). */
  maxDecodedBytes: number;
  /** Maximum bytes of the JSON outside the raw value (default 1 MiB). */
  maxOtherBytes?: number;
}

const DEFAULT_MAX_OTHER_BYTES = 1024 * 1024;
const MAX_KEY_CHARS = 16;

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const LBRACE = 0x7b;
const RBRACE = 0x7d;
const LBRACKET = 0x5b;
const RBRACKET = 0x5d;
const COLON = 0x3a;
const COMMA = 0x2c;

/** 6-bit value per byte; -1 invalid, -2 padding, -3 whitespace. */
const B64 = new Int16Array(256).fill(-1);
for (let i = 0; i < 26; i += 1) {
  B64[0x41 + i] = i;
  B64[0x61 + i] = 26 + i;
}
for (let i = 0; i < 10; i += 1) B64[0x30 + i] = 52 + i;
B64[0x2d] = 62; // '-'
B64[0x2b] = 62; // '+'
B64[0x5f] = 63; // '_'
B64[0x2f] = 63; // '/'
B64[0x3d] = -2; // '='
for (const ws of [0x20, 0x09, 0x0a, 0x0d]) B64[ws] = -3;

const isWhitespace = (b: number): boolean => b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d;

const SIMPLE_ESCAPES: Readonly<Record<number, number>> = {
  0x22: 0x22,
  0x5c: 0x5c,
  0x2f: 0x2f,
  0x62: 0x08,
  0x66: 0x0c,
  0x6e: 0x0a,
  0x72: 0x0d,
  0x74: 0x09,
};

type Phase = 'key' | 'colon' | 'value' | 'comma';

const malformed = (): MailboxApiError =>
  new MailboxApiError('unexpected_response', { retryable: false });

export class GmailRawExtractor {
  private readonly maxDecoded: number;
  private readonly maxOther: number;

  /** Container stack (`{` or `[`). */
  private readonly stack: number[] = [];
  private started = false;
  private done = false;
  /** Top-level object phase. */
  private phase: Phase = 'key';
  private inString = false;
  /** 0 none, 1 after a backslash, 2..5 reading `\uXXXX` hex digits. */
  private escape = 0;
  private hex = 0;
  private stringIsKey = false;
  private stringIsRaw = false;
  private key = '';
  private keyOverflow = false;
  private keyIsRaw = false;
  private sawRaw = false;
  /** A top-level scalar value (number, literal) is being skipped. */
  private inScalar = false;

  private otherBytes = 0;
  private decodedBytes = 0;
  private bits = 0;
  private bitCount = 0;
  private padding = 0;
  private out: Uint8Array = new Uint8Array(0);
  private outLength = 0;

  constructor(options: GmailRawExtractorOptions) {
    this.maxDecoded = options.maxDecodedBytes;
    this.maxOther = options.maxOtherBytes ?? DEFAULT_MAX_OTHER_BYTES;
  }

  /** Decoded message bytes so far. */
  get decodedLength(): number {
    return this.decodedBytes;
  }

  /** Feeds one chunk; returns the message bytes decoded from it (possibly empty). */
  push(chunk: Uint8Array): Uint8Array {
    this.out = new Uint8Array(Math.ceil((chunk.length * 3) / 4) + 3);
    this.outLength = 0;
    for (let i = 0; i < chunk.length; i += 1) this.byte(chunk[i] as number);
    return this.out.subarray(0, this.outLength);
  }

  /** Ends the input: the JSON must be complete and contain the raw string. */
  end(): void {
    if (!this.done || !this.sawRaw) throw malformed();
  }

  /** Extracts the decoded message from a streamed answer. */
  static async *extract(
    source: AsyncIterable<Uint8Array>,
    options: GmailRawExtractorOptions,
  ): AsyncGenerator<Uint8Array, void, undefined> {
    const extractor = new GmailRawExtractor(options);
    for await (const chunk of source) {
      const decoded = extractor.push(chunk);
      if (decoded.length > 0) yield decoded;
    }
    extractor.end();
  }

  private countOther(): void {
    this.otherBytes += 1;
    if (this.otherBytes > this.maxOther) {
      throw new MailboxApiError('response_too_large', { retryable: false });
    }
  }

  private byte(b: number): void {
    if (this.inString && this.stringIsRaw) {
      this.rawByte(b);
      return;
    }
    this.countOther();
    if (this.inString) {
      this.stringByte(b);
      return;
    }
    if (this.done) {
      if (!isWhitespace(b)) throw malformed();
      return;
    }
    if (!this.started) {
      if (isWhitespace(b)) return;
      if (b !== LBRACE) throw malformed();
      this.started = true;
      this.stack.push(LBRACE);
      this.phase = 'key';
      return;
    }
    const depth = this.stack.length;
    if (this.inScalar) {
      if (b === COMMA || b === RBRACE || isWhitespace(b)) {
        this.inScalar = false;
        this.phase = 'comma';
        // fall through to handle the delimiter
      } else {
        return;
      }
    }
    if (isWhitespace(b)) return;
    switch (b) {
      case QUOTE:
        this.inString = true;
        this.escape = 0;
        this.stringIsKey = depth === 1 && this.phase === 'key';
        this.stringIsRaw = depth === 1 && this.phase === 'value' && this.keyIsRaw;
        if (this.stringIsKey) {
          this.key = '';
          this.keyOverflow = false;
        }
        if (this.stringIsRaw) {
          if (this.sawRaw) throw malformed();
          this.bits = 0;
          this.bitCount = 0;
          this.padding = 0;
        } else if (depth === 1 && this.phase !== 'key' && this.phase !== 'value') {
          throw malformed();
        }
        return;
      case LBRACE:
      case LBRACKET:
        if (depth === 1) {
          if (this.phase !== 'value' || this.keyIsRaw) throw malformed();
        }
        this.stack.push(b);
        return;
      case RBRACE:
      case RBRACKET: {
        const open = this.stack.pop();
        if (open !== (b === RBRACE ? LBRACE : LBRACKET)) throw malformed();
        if (this.stack.length === 0) {
          if (this.phase === 'colon' || this.phase === 'value') throw malformed();
          this.done = true;
        } else if (this.stack.length === 1) {
          this.phase = 'comma';
        }
        return;
      }
      case COLON:
        if (depth === 1) {
          if (this.phase !== 'colon') throw malformed();
          this.phase = 'value';
        }
        return;
      case COMMA:
        if (depth === 1) {
          if (this.phase !== 'comma') throw malformed();
          this.phase = 'key';
        }
        return;
      default:
        if (depth === 1) {
          // A scalar (number, true, false, null) as a top-level value.
          if (this.phase !== 'value' || this.keyIsRaw) throw malformed();
          this.inScalar = true;
        }
    }
  }

  /** A byte inside a string that is not the raw value. */
  private stringByte(b: number): void {
    if (this.escape === 1) {
      if (b === 0x75) {
        this.escape = 2;
        this.hex = 0;
        return;
      }
      const mapped = SIMPLE_ESCAPES[b];
      if (mapped === undefined) throw malformed();
      this.escape = 0;
      this.keyChar(mapped);
      return;
    }
    if (this.escape >= 2) {
      const digit = hexDigit(b);
      if (digit < 0) throw malformed();
      this.hex = (this.hex << 4) | digit;
      this.escape += 1;
      if (this.escape === 6) {
        this.escape = 0;
        this.keyChar(this.hex);
      }
      return;
    }
    if (b === BACKSLASH) {
      this.escape = 1;
      return;
    }
    if (b === QUOTE) {
      this.inString = false;
      if (this.stringIsKey) {
        this.keyIsRaw = !this.keyOverflow && this.key === 'raw';
        this.phase = 'colon';
      } else if (this.stack.length === 1) {
        this.phase = 'comma';
      }
      return;
    }
    if (b < 0x20) throw malformed();
    this.keyChar(b);
  }

  private keyChar(code: number): void {
    if (!this.stringIsKey || this.keyOverflow) return;
    if (this.key.length >= MAX_KEY_CHARS) {
      this.keyOverflow = true;
      return;
    }
    this.key += String.fromCharCode(code);
  }

  /** A byte of the raw value: unescape, then base64-decode. */
  private rawByte(b: number): void {
    if (this.escape === 1) {
      if (b === 0x75) {
        this.escape = 2;
        this.hex = 0;
        return;
      }
      const mapped = SIMPLE_ESCAPES[b];
      if (mapped === undefined) throw malformed();
      this.escape = 0;
      this.b64(mapped);
      return;
    }
    if (this.escape >= 2) {
      const digit = hexDigit(b);
      if (digit < 0) throw malformed();
      this.hex = (this.hex << 4) | digit;
      this.escape += 1;
      if (this.escape === 6) {
        this.escape = 0;
        if (this.hex > 0xff) throw malformed();
        this.b64(this.hex);
      }
      return;
    }
    if (b === BACKSLASH) {
      this.escape = 1;
      return;
    }
    if (b === QUOTE) {
      this.finishRaw();
      return;
    }
    this.b64(b);
  }

  private b64(b: number): void {
    const value = B64[b] as number;
    if (value === -3) return; // whitespace (line-wrapped base64)
    if (value === -2) {
      this.padding += 1;
      if (this.padding > 2) throw malformed();
      return;
    }
    if (value < 0 || this.padding > 0) throw malformed();
    this.bits = ((this.bits << 6) | value) & 0xffffff;
    this.bitCount += 6;
    if (this.bitCount >= 8) {
      this.bitCount -= 8;
      this.emit((this.bits >> this.bitCount) & 0xff);
    }
  }

  private emit(value: number): void {
    this.decodedBytes += 1;
    if (this.decodedBytes > this.maxDecoded) {
      throw new MailboxApiError('response_too_large', { retryable: false });
    }
    if (this.outLength >= this.out.length) {
      const grown = new Uint8Array(this.out.length * 2 + 16);
      grown.set(this.out);
      this.out = grown;
    }
    this.out[this.outLength] = value;
    this.outLength += 1;
  }

  private finishRaw(): void {
    // Leftover bits: 0 (aligned), 2 (one extra char pair → one byte already emitted) or 4. A
    // single dangling character (6 bits, nothing emitted) is invalid.
    const leftoverChars = this.charsMod4();
    if (leftoverChars === 1) throw malformed();
    if (this.padding > 0 && (leftoverChars + this.padding) % 4 !== 0) throw malformed();
    this.inString = false;
    this.stringIsRaw = false;
    this.sawRaw = true;
    this.keyIsRaw = false;
    this.phase = 'comma';
  }

  /** Number of base64 characters after the last full quartet (from the bit counter). */
  private charsMod4(): number {
    // After n chars: bitCount cycles 6, 4, 2, 0 for n mod 4 = 1, 2, 3, 0.
    switch (this.bitCount) {
      case 6:
        return 1;
      case 4:
        return 2;
      case 2:
        return 3;
      default:
        return 0;
    }
  }
}

function hexDigit(b: number): number {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  if (b >= 0x61 && b <= 0x66) return b - 0x61 + 10;
  return -1;
}
