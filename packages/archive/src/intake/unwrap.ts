import { Transform, type TransformCallback } from 'node:stream';
import { headerValues, parseHeaderFields } from './rfc5322';
import {
  createTransferDecoder,
  decodeTransfer,
  type StreamDecoder,
  type TransferEncoding,
  transferEncodingOf,
} from './transfer-decoding';

/**
 * The Exchange journal report unwrapper (step 8.6 D2.6, ADR-0087), streaming and bounded.
 *
 * Input: the raw message as received at the intake LMTP (outer header block + body), in chunks
 * of any size. Output: the bytes to **store**:
 *
 * - `journal_report`: the report was recognized (outer header `X-MS-Journal-Report` present,
 *   top-level `multipart/mixed` with a boundary, first part `text/plain` = the envelope, second
 *   part `message/rfc822` = the original message). The output is the embedded message, decoded
 *   (`7bit` / `8bit` / `binary` pass through byte-exact; `base64` and `quoted-printable` are
 *   decoded). The envelope part is captured (≤ `envelopeMaxBytes`) and decoded to text.
 * - `journal_report_unparsed`: anything else, at any point before the decision. The output is the
 *   original message byte for byte (compliance over tidiness).
 *
 * **Decision before output.** Nothing is emitted until the decision is made, and the decision is
 * made on a bounded prefix: the outer header block, the preamble, the envelope part and the
 * second part's header block. Once made it is final: later anomalies (a missing closing
 * delimiter, extra parts) only add `anomalies`, the output stays the embedded message. So a
 * caller (the intake LMTP) can stream the output straight to S3 in both cases without re-reading
 * the input, and learns the format (event `decision`) before the first output byte.
 *
 * **Memory bound.** Before the decision the unwrapper retains the received chunks, at most
 * `prefixLimitOf(options)` bytes (= 3 × `headerMaxBytes` + `preambleMaxBytes` +
 * `envelopeMaxBytes` + 4 KiB; 1 MiB + 832 KiB with the defaults) plus the chunk that crossed it:
 * a prefix that reaches the limit without a decision is unparsed. After the decision it holds
 * only a delimiter-sized tail (boundary length + 3 bytes) and the decoder state (≤ 3 bytes).
 */

export interface JournalUnwrapOptions {
  /** `JOURNAL_INTAKE_ENVELOPE_MAX_BYTES` (default 1 MiB): the envelope part's encoded size. */
  envelopeMaxBytes?: number;
  /** Bound of the outer header block and of each part header block (default 256 KiB). */
  headerMaxBytes?: number;
  /** Bound of the preamble before the first delimiter (default 64 KiB). */
  preambleMaxBytes?: number;
}

export const JOURNAL_UNWRAP_DEFAULTS = Object.freeze({
  envelopeMaxBytes: 1_048_576,
  headerMaxBytes: 262_144,
  preambleMaxBytes: 65_536,
});

/** Why a report was stored as received. */
export type JournalUnwrapUnparsedReason =
  | 'not_journal_report'
  | 'not_multipart_mixed'
  | 'boundary_missing'
  | 'header_too_large'
  | 'preamble_too_large'
  | 'envelope_part_missing'
  | 'envelope_too_large'
  | 'embedded_part_missing'
  | 'unsupported_encoding'
  | 'truncated'
  | 'prefix_too_large';

export type JournalUnwrapAnomaly = 'closing_delimiter_missing' | 'extra_parts';

export type JournalUnwrapDecision =
  | {
      format: 'journal_report';
      reason: null;
      /** The decoded envelope part (charset `utf-8` / `us-ascii` / `iso-8859-1`; else UTF-8). */
      envelopeText: string;
      /** Transfer encoding of the embedded message part. */
      embeddedEncoding: TransferEncoding;
      /** The outer header block (proof evaluation), ≤ `headerMaxBytes`. */
      outerHeaderBlock: Buffer;
    }
  | {
      format: 'journal_report_unparsed';
      reason: JournalUnwrapUnparsedReason;
      envelopeText: null;
      embeddedEncoding: null;
      /** The outer header block when it was complete, else null. */
      outerHeaderBlock: Buffer | null;
    };

export type JournalUnwrapResult = JournalUnwrapDecision & {
  /** Bytes received. */
  inputBytes: number;
  /** Bytes emitted (the stored message). */
  outputBytes: number;
  anomalies: JournalUnwrapAnomaly[];
};

/** The most input bytes retained before the decision (excluding the chunk that crossed it). */
export function prefixLimitOf(options: JournalUnwrapOptions = {}): number {
  const o = resolveOptions(options);
  return 3 * o.headerMaxBytes + o.preambleMaxBytes + o.envelopeMaxBytes + 4096;
}

function resolveOptions(options: JournalUnwrapOptions) {
  const pick = (v: number | undefined, d: number, name: string) => {
    if (v === undefined) return d;
    if (!Number.isInteger(v) || v < 1 || v > 64 * 1_048_576) {
      throw new RangeError(`${name} must be 1 … 64 MiB`);
    }
    return v;
  };
  return {
    envelopeMaxBytes: pick(
      options.envelopeMaxBytes,
      JOURNAL_UNWRAP_DEFAULTS.envelopeMaxBytes,
      'envelopeMaxBytes',
    ),
    headerMaxBytes: pick(
      options.headerMaxBytes,
      JOURNAL_UNWRAP_DEFAULTS.headerMaxBytes,
      'headerMaxBytes',
    ),
    preambleMaxBytes: pick(
      options.preambleMaxBytes,
      JOURNAL_UNWRAP_DEFAULTS.preambleMaxBytes,
      'preambleMaxBytes',
    ),
  };
}

// ---------------------------------------------------------------------------------------------
// MIME helpers
// ---------------------------------------------------------------------------------------------

export interface ParsedContentType {
  /** `type/subtype`, lower-case. */
  mediaType: string;
  /** Parameter names lower-case; values unquoted. */
  params: Record<string, string>;
}

/** Parses a `Content-Type` value (RFC 2045 §5.1; RFC 2231 continuations are not joined). */
export function parseContentType(value: string | null | undefined): ParsedContentType | null {
  if (typeof value !== 'string') return null;
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (c === '\\' && quoted && i + 1 < value.length) {
      current += value[++i];
      continue;
    }
    if (c === '"') {
      quoted = !quoted;
      current += c;
      continue;
    }
    if (c === ';' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += c;
  }
  parts.push(current);
  const mediaType = parts[0]!
    .replace(/\(.*?\)/g, '')
    .trim()
    .toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType)) return null;
  const params: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const eq = p.indexOf('=');
    if (eq <= 0) continue;
    const name = p.slice(0, eq).trim().toLowerCase();
    let v = p.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) v = v.slice(1, -1);
    if (name !== '' && !(name in params)) params[name] = v;
  }
  return { mediaType, params };
}

/** End of the header block that starts at `start` (index after its empty line), or -1. */
function headerBlockEnd(buf: Buffer, start: number, limit: number): number {
  let i = start;
  while (i < limit) {
    const nl = buf.indexOf(0x0a, i);
    if (nl < 0 || nl >= limit) return -1;
    if (nl === i || (nl === i + 1 && buf[i] === 0x0d)) return nl + 1;
    i = nl + 1;
  }
  return -1;
}

type DelimiterSearch =
  | { found: true; bodyEnd: number; next: number; closing: boolean }
  | { found: false; safeEnd: number };

/**
 * Finds the next delimiter line (`--boundary` + optional `--` + transport padding) at a line
 * start in `buf[from, limit)`. The line break before the delimiter belongs to it (RFC 2046
 * §5.1.1), so `bodyEnd` excludes it. Without a match, `safeEnd` is the end of the bytes that are
 * body for certain (a partial delimiter may follow). `final`: `limit` is the end of the input.
 */
function searchDelimiter(
  buf: Buffer,
  from: number,
  limit: number,
  bodyAtLineStart: boolean,
  dash: Buffer,
  final: boolean,
): DelimiterSearch {
  let i = from;
  for (;;) {
    const k = buf.indexOf(dash, i);
    if (k < 0 || k + dash.length > limit) {
      return { found: false, safeEnd: final ? limit : Math.max(from, limit - dash.length - 1) };
    }
    let bodyEnd = -1;
    if (k === from && bodyAtLineStart) bodyEnd = from;
    else if (k - 1 >= from && buf[k - 1] === 0x0a) {
      bodyEnd = k - 2 >= from && buf[k - 2] === 0x0d ? k - 2 : k - 1;
    }
    if (bodyEnd < 0) {
      i = k + 1;
      continue;
    }
    const after = k + dash.length;
    const nl = buf.indexOf(0x0a, after);
    const lineEnd = nl >= 0 && nl < limit ? nl : -1;
    const rest = buf
      .subarray(after, lineEnd < 0 ? limit : lineEnd)
      .toString('latin1')
      .replace(/\r$/, '');
    if (rest.startsWith('--')) {
      // A closing delimiter (tolerant: anything may follow the `--` up to the line end).
      return { found: true, bodyEnd, next: lineEnd < 0 ? limit : lineEnd + 1, closing: true };
    }
    if (lineEnd < 0 && !final) {
      // The line is incomplete: wait while it can still become a delimiter.
      if (rest === '-' || /^[ \t]*\r?$/.test(rest)) return { found: false, safeEnd: bodyEnd };
      i = k + 1;
      continue;
    }
    if (/^[ \t]*$/.test(rest)) {
      return { found: true, bodyEnd, next: lineEnd < 0 ? limit : lineEnd + 1, closing: false };
    }
    i = k + 1;
  }
}

function charsetDecode(data: Buffer, charset: string | undefined): string {
  const c = (charset ?? '').toLowerCase();
  if (c === 'iso-8859-1' || c === 'latin1' || c === 'windows-1252') return data.toString('latin1');
  return data.toString('utf8');
}

// ---------------------------------------------------------------------------------------------
// The splitter (push API) and its Transform
// ---------------------------------------------------------------------------------------------

type Phase =
  | 'outer_headers'
  | 'preamble'
  | 'envelope_headers'
  | 'envelope_body'
  | 'embedded_headers'
  | 'embedded'
  | 'epilogue'
  | 'passthrough';

/** A growable byte buffer (capacity doubling) for the bounded prefix. */
class Prefix {
  buf = Buffer.alloc(0);
  length = 0;
  append(data: Buffer): void {
    if (this.length + data.length > this.buf.length) {
      const next = Buffer.alloc(Math.max(this.length + data.length, this.buf.length * 2, 4096));
      this.buf.copy(next, 0, 0, this.length);
      this.buf = next;
    }
    data.copy(this.buf, this.length);
    this.length += data.length;
  }
  view(): Buffer {
    return this.buf.subarray(0, this.length);
  }
}

/**
 * The push-based core of the unwrapper: `push(chunk)` and `end()` return the output chunks to
 * store (empty until the decision). `decision` is set once, before the first output byte.
 */
export class JournalReportSplitter {
  private readonly options: ReturnType<typeof resolveOptions>;
  private readonly prefixLimit: number;
  private phase: Phase = 'outer_headers';
  private readonly prefix = new Prefix();
  /** Received chunks retained until the decision (references, not copies). */
  private raw: Buffer[] = [];
  private rawBytes = 0;
  /** Parse cursor inside the prefix. */
  private cursor = 0;
  private dash: Buffer | null = null;
  private outerHeaderBlock: Buffer | null = null;
  private envelopeText: string | null = null;
  private envelopeCharset: string | undefined;
  private envelopeEncoding: TransferEncoding = 'identity';
  private embeddedEncoding: TransferEncoding = 'identity';
  private decoder: StreamDecoder | null = null;
  /** Unconsumed embedded bytes (≤ boundary-sized tail between pushes). */
  private work: Buffer = Buffer.alloc(0);
  private workAtLineStart = true;
  private inputBytes = 0;
  private outputBytes = 0;
  private readonly anomalies: JournalUnwrapAnomaly[] = [];
  private ended = false;
  private decided: JournalUnwrapDecision | null = null;

  constructor(options: JournalUnwrapOptions = {}) {
    this.options = resolveOptions(options);
    this.prefixLimit = prefixLimitOf(options);
  }

  get decision(): JournalUnwrapDecision | null {
    return this.decided;
  }

  push(chunk: Buffer): Buffer[] {
    if (this.ended) throw new Error('JournalReportSplitter: push after end');
    if (chunk.length === 0) return [];
    this.inputBytes += chunk.length;
    switch (this.phase) {
      case 'passthrough':
        return this.emit([chunk]);
      case 'embedded':
        return this.embedded(chunk, false);
      case 'epilogue':
        return [];
      default:
        return this.beforeDecision(chunk, false);
    }
  }

  end(): Buffer[] {
    if (this.ended) return [];
    this.ended = true;
    switch (this.phase) {
      case 'passthrough':
      case 'epilogue':
        return [];
      case 'embedded':
        return this.embedded(Buffer.alloc(0), true);
      default:
        return this.beforeDecision(Buffer.alloc(0), true);
    }
  }

  result(): JournalUnwrapResult {
    if (!this.ended || this.decided === null) {
      throw new Error('JournalReportSplitter: result before end');
    }
    return {
      ...this.decided,
      inputBytes: this.inputBytes,
      outputBytes: this.outputBytes,
      anomalies: [...this.anomalies],
    };
  }

  private emit(chunks: Buffer[]): Buffer[] {
    const out = chunks.filter((c) => c.length > 0);
    for (const c of out) this.outputBytes += c.length;
    return out;
  }

  private beforeDecision(chunk: Buffer, final: boolean): Buffer[] {
    if (chunk.length > 0) {
      this.raw.push(chunk);
      this.rawBytes += chunk.length;
      const room = this.prefixLimit - this.prefix.length;
      if (room > 0) this.prefix.append(room >= chunk.length ? chunk : chunk.subarray(0, room));
    }
    const prefixComplete = final && this.rawBytes <= this.prefixLimit;
    const outcome = this.advance(prefixComplete);
    if (outcome === 'need_more') {
      if (this.rawBytes >= this.prefixLimit) return this.unparsed('prefix_too_large');
      if (final) return this.unparsed('truncated');
      return [];
    }
    if (outcome !== 'decided') return this.unparsed(outcome);
    // Decided `journal_report`: the rest of the prefix and the retained bytes beyond it are the
    // start of the embedded part.
    const view = this.prefix.view();
    const beyond: Buffer[] = [];
    let skipped = 0;
    for (const c of this.raw) {
      const end = skipped + c.length;
      if (end > view.length)
        beyond.push(skipped >= view.length ? c : c.subarray(view.length - skipped));
      skipped = end;
    }
    const start = Buffer.concat([view.subarray(this.cursor), ...beyond]);
    this.raw = [];
    this.prefix.buf = Buffer.alloc(0);
    this.prefix.length = 0;
    this.phase = 'embedded';
    this.decoder = createTransferDecoder(this.embeddedEncoding);
    this.work = Buffer.alloc(0);
    this.workAtLineStart = true;
    return this.embedded(start, final);
  }

  private unparsed(reason: JournalUnwrapUnparsedReason): Buffer[] {
    this.decided = {
      format: 'journal_report_unparsed',
      reason,
      envelopeText: null,
      embeddedEncoding: null,
      outerHeaderBlock: this.outerHeaderBlock,
    };
    this.phase = 'passthrough';
    const out = this.raw;
    this.raw = [];
    this.prefix.buf = Buffer.alloc(0);
    this.prefix.length = 0;
    return this.emit(out);
  }

  /** Runs the pre-decision stages on the prefix. */
  private advance(final: boolean): 'need_more' | 'decided' | JournalUnwrapUnparsedReason {
    const buf = this.prefix.view();
    const o = this.options;
    for (;;) {
      switch (this.phase) {
        case 'outer_headers': {
          const end = headerBlockEnd(buf, 0, Math.min(buf.length, o.headerMaxBytes));
          if (end < 0) {
            if (buf.length >= o.headerMaxBytes) return 'header_too_large';
            return final ? 'truncated' : 'need_more';
          }
          this.outerHeaderBlock = Buffer.from(buf.subarray(0, end));
          const fields = parseHeaderFields(this.outerHeaderBlock);
          if (headerValues(fields, 'X-MS-Journal-Report').length === 0) {
            return 'not_journal_report';
          }
          const ct = parseContentType(headerValues(fields, 'Content-Type')[0]);
          if (ct === null || ct.mediaType !== 'multipart/mixed') return 'not_multipart_mixed';
          const boundary = ct.params.boundary;
          if (boundary === undefined || boundary.length < 1 || boundary.length > 200) {
            return 'boundary_missing';
          }
          this.dash = Buffer.from(`--${boundary}`, 'latin1');
          this.cursor = end;
          this.phase = 'preamble';
          break;
        }
        case 'preamble': {
          const limit = Math.min(
            buf.length,
            this.cursor + o.preambleMaxBytes + this.dash!.length + 4,
          );
          const r = searchDelimiter(buf, this.cursor, limit, true, this.dash!, final);
          if (!r.found) {
            if (buf.length - this.cursor > o.preambleMaxBytes) return 'preamble_too_large';
            return final ? 'envelope_part_missing' : 'need_more';
          }
          if (r.closing) return 'envelope_part_missing';
          this.cursor = r.next;
          this.phase = 'envelope_headers';
          break;
        }
        case 'envelope_headers':
        case 'embedded_headers': {
          const limit = Math.min(buf.length, this.cursor + o.headerMaxBytes);
          const end = headerBlockEnd(buf, this.cursor, limit);
          if (end < 0) {
            if (buf.length - this.cursor >= o.headerMaxBytes) return 'header_too_large';
            return final
              ? this.phase === 'envelope_headers'
                ? 'envelope_part_missing'
                : 'embedded_part_missing'
              : 'need_more';
          }
          const fields = parseHeaderFields(buf.subarray(this.cursor, end));
          const ct = parseContentType(headerValues(fields, 'Content-Type')[0] ?? 'text/plain');
          const cte = transferEncodingOf(headerValues(fields, 'Content-Transfer-Encoding')[0]);
          this.cursor = end;
          if (this.phase === 'envelope_headers') {
            if (ct === null || ct.mediaType !== 'text/plain') return 'envelope_part_missing';
            if (cte === null) return 'unsupported_encoding';
            this.envelopeEncoding = cte;
            this.envelopeCharset = ct.params.charset;
            this.phase = 'envelope_body';
            break;
          }
          if (ct === null || ct.mediaType !== 'message/rfc822') return 'embedded_part_missing';
          if (cte === null) return 'unsupported_encoding';
          this.embeddedEncoding = cte;
          this.decided = {
            format: 'journal_report',
            reason: null,
            envelopeText: this.envelopeText ?? '',
            embeddedEncoding: cte,
            outerHeaderBlock: this.outerHeaderBlock!,
          };
          return 'decided';
        }
        case 'envelope_body': {
          const limit = Math.min(
            buf.length,
            this.cursor + o.envelopeMaxBytes + this.dash!.length + 4,
          );
          const r = searchDelimiter(buf, this.cursor, limit, true, this.dash!, final);
          if (!r.found) {
            if (buf.length - this.cursor > o.envelopeMaxBytes) return 'envelope_too_large';
            return final ? 'embedded_part_missing' : 'need_more';
          }
          if (r.bodyEnd - this.cursor > o.envelopeMaxBytes) return 'envelope_too_large';
          if (r.closing) return 'embedded_part_missing';
          this.envelopeText = charsetDecode(
            decodeTransfer(this.envelopeEncoding, buf.subarray(this.cursor, r.bodyEnd)),
            this.envelopeCharset,
          );
          this.cursor = r.next;
          this.phase = 'embedded_headers';
          break;
        }
        default:
          return 'need_more';
      }
    }
  }

  /** Streams the embedded part's body through the decoder up to the next delimiter. */
  private embedded(chunk: Buffer, final: boolean): Buffer[] {
    const data = this.work.length > 0 ? Buffer.concat([this.work, chunk]) : chunk;
    const decoder = this.decoder!;
    const r = searchDelimiter(data, 0, data.length, this.workAtLineStart, this.dash!, final);
    if (r.found) {
      const out = [decoder.push(data.subarray(0, r.bodyEnd)), decoder.end()];
      if (!r.closing) this.anomalies.push('extra_parts');
      this.work = Buffer.alloc(0);
      this.phase = 'epilogue';
      return this.emit(out);
    }
    const body = data.subarray(0, r.safeEnd);
    // Copy the tail so a large chunk is not kept alive by a small view.
    this.work = Buffer.from(data.subarray(r.safeEnd));
    if (body.length > 0) this.workAtLineStart = false;
    const out = [decoder.push(body)];
    if (final) {
      this.anomalies.push('closing_delimiter_missing');
      out.push(decoder.push(this.work), decoder.end());
      this.work = Buffer.alloc(0);
      this.phase = 'epilogue';
    }
    return this.emit(out);
  }
}

/**
 * The Transform form of `JournalReportSplitter`: write the raw message, read the bytes to store.
 * Emits `decision` (with the `JournalUnwrapDecision`) before the first output byte; `result` is
 * available after `finish`/`end`.
 */
export class JournalReportUnwrapper extends Transform {
  private readonly splitter: JournalReportSplitter;
  private announced = false;

  constructor(options: JournalUnwrapOptions = {}) {
    super();
    this.splitter = new JournalReportSplitter(options);
  }

  get decision(): JournalUnwrapDecision | null {
    return this.splitter.decision;
  }

  get result(): JournalUnwrapResult | null {
    try {
      return this.splitter.result();
    } catch {
      return null;
    }
  }

  private forward(chunks: Buffer[]): void {
    const decision = this.splitter.decision;
    if (!this.announced && decision !== null) {
      this.announced = true;
      this.emit('decision', decision);
    }
    for (const c of chunks) this.push(c);
  }

  override _transform(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
      this.forward(this.splitter.push(buf));
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      this.forward(this.splitter.end());
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }
}

/** Unwraps a whole buffer (tests and small messages). */
export function unwrapJournalReport(
  message: Buffer,
  options: JournalUnwrapOptions = {},
): { output: Buffer; result: JournalUnwrapResult } {
  const s = new JournalReportSplitter(options);
  const output = Buffer.concat([...s.push(message), ...s.end()]);
  return { output, result: s.result() };
}
