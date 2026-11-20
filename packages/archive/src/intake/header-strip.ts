import { Transform, type TransformCallback } from 'node:stream';

/**
 * Removal of header fields from the header block of a stored message (step 8.6 D2.6): the intake
 * LMTP drops every `X-EG-Journal-Token` field before upload so the archive never holds the
 * credential. Streaming and line-based: every occurrence of a named field (case-insensitive),
 * with its folded continuation lines, is removed from the header block only; the empty line and
 * the body pass through untouched (byte-exact). Memory is one header line, bounded by
 * `maxLineBytes`: a longer line is passed through unparsed and counted in `overlongLines` (no
 * legitimate token line comes near it; the intake proof refuses such a message anyway).
 */

export interface HeaderFieldStripOptions {
  /** Longest header line held while looking for its end (default 64 KiB). */
  maxLineBytes?: number;
}

const FIELD_NAME = /^[!-9;-~]+$/;

export class HeaderFieldStripper {
  private readonly names: Set<string>;
  private readonly maxLineBytes: number;
  private inBody = false;
  private line: Buffer[] = [];
  private lineBytes = 0;
  /** The current field (the last non-continuation line) is being dropped. */
  private dropping = false;
  /** The current line is overlong and passed through as it arrives. */
  private passingLine = false;
  /** Fields removed so far. */
  removed = 0;
  /** Header lines that exceeded `maxLineBytes` (passed through). */
  overlongLines = 0;

  constructor(names: readonly string[], options: HeaderFieldStripOptions = {}) {
    if (names.length === 0) throw new RangeError('names must not be empty');
    for (const n of names) {
      if (!FIELD_NAME.test(n)) throw new RangeError('invalid header field name');
    }
    this.names = new Set(names.map((n) => n.toLowerCase()));
    const max = options.maxLineBytes ?? 65_536;
    if (!Number.isInteger(max) || max < 80) throw new RangeError('maxLineBytes must be ≥ 80');
    this.maxLineBytes = max;
  }

  push(chunk: Buffer): Buffer[] {
    if (this.inBody) return chunk.length > 0 ? [chunk] : [];
    const out: Buffer[] = [];
    let i = 0;
    while (i < chunk.length) {
      if (this.inBody) {
        out.push(chunk.subarray(i));
        break;
      }
      const nl = chunk.indexOf(0x0a, i);
      const end = nl < 0 ? chunk.length : nl + 1;
      const piece = chunk.subarray(i, end);
      i = end;
      if (this.passingLine) {
        if (!this.dropping) out.push(piece);
        if (nl >= 0) this.passingLine = false;
        continue;
      }
      this.line.push(piece);
      this.lineBytes += piece.length;
      if (nl < 0) {
        if (this.lineBytes > this.maxLineBytes) {
          // Too long to hold: decide on what we have (the field name is at the start).
          this.overlongLines++;
          const held = Buffer.concat(this.line);
          this.line = [];
          this.lineBytes = 0;
          this.passingLine = true;
          this.classify(held, false);
          if (!this.dropping) out.push(held);
        }
        continue;
      }
      const full = this.line.length === 1 ? this.line[0]! : Buffer.concat(this.line);
      this.line = [];
      this.lineBytes = 0;
      if (this.classify(full, true)) {
        out.push(full);
        continue;
      }
      if (!this.dropping) out.push(full);
    }
    return out;
  }

  /**
   * Classifies a header line: returns true when it is the empty line (end of the header block,
   * always emitted); otherwise updates `dropping` for a new field or keeps it for a continuation.
   */
  private classify(line: Buffer, complete: boolean): boolean {
    if (complete && (line.length === 1 || (line.length === 2 && line[0] === 0x0d))) {
      this.inBody = true;
      this.dropping = false;
      return true;
    }
    if (line[0] === 0x20 || line[0] === 0x09) return false; // continuation: same decision
    const colon = line.indexOf(0x3a);
    const name =
      colon > 0
        ? line
            .subarray(0, colon)
            .toString('latin1')
            .replace(/[ \t]+$/, '')
        : null;
    const drop = name !== null && this.names.has(name.toLowerCase());
    if (drop) this.removed++;
    this.dropping = drop;
    return false;
  }

  end(): Buffer[] {
    if (this.line.length === 0) return [];
    // A header block without a final line break: classify what is left.
    const rest = Buffer.concat(this.line);
    this.line = [];
    this.lineBytes = 0;
    if (this.passingLine) return this.dropping ? [] : [rest];
    this.classify(rest, false);
    return this.dropping ? [] : [rest];
  }
}

/** A Transform that removes the named header fields; `removed` counts the fields dropped. */
export class HeaderFieldStripStream extends Transform {
  private readonly stripper: HeaderFieldStripper;

  constructor(names: readonly string[], options: HeaderFieldStripOptions = {}) {
    super();
    this.stripper = new HeaderFieldStripper(names, options);
  }

  get removed(): number {
    return this.stripper.removed;
  }

  get overlongLines(): number {
    return this.stripper.overlongLines;
  }

  override _transform(chunk: unknown, _enc: BufferEncoding, callback: TransformCallback): void {
    try {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
      for (const c of this.stripper.push(buf)) this.push(c);
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    for (const c of this.stripper.end()) this.push(c);
    callback();
  }
}

/** `stripHeaderFields(['X-EG-Journal-Token'])`: the Transform of the intake LMTP. */
export function stripHeaderFields(
  names: readonly string[],
  options: HeaderFieldStripOptions = {},
): HeaderFieldStripStream {
  return new HeaderFieldStripStream(names, options);
}

/** Whole-buffer form (tests, small messages). */
export function stripHeaderFieldsFromBuffer(
  message: Buffer,
  names: readonly string[],
  options: HeaderFieldStripOptions = {},
): { output: Buffer; removed: number } {
  const s = new HeaderFieldStripper(names, options);
  const output = Buffer.concat([...s.push(message), ...s.end()]);
  return { output, removed: s.removed };
}
