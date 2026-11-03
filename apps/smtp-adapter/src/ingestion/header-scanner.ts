/**
 * Bounded header-block scanner of LMTP ingestion (step 2.2 D7 step 3). No MIME parsing (step
 * 3.1 owns that): it keeps at most `maxBytes` of the message until the first empty line and
 * extracts raw, unfolded header values.
 */

/** RFC 5322 line-length limit; also the `email_messages` column limits. */
export const MAX_MESSAGE_ID_CHARS = 998;
export const MAX_SUBJECT_CHARS = 998;
export const MAX_HEADER_FROM_CHARS = 320;

export interface HeaderMetadata {
  /** First `Message-ID`, unfolded raw value, ≤ 998 characters. */
  messageId: string | null;
  /** First `Subject`, unfolded raw value (encoded-words as-is), ≤ 998 characters. */
  subject: string | null;
  /** First `From`: the address inside `<…>` if present, else the raw value; ≤ 320. */
  from: string | null;
  /** Every `From` header value, unfolded (for the outbound From check). */
  fromValues: string[];
  /** Number of `Received:` headers (metric only). */
  receivedCount: number;
  /** Every `X-Gateway-Trace` value (D14). */
  traces: string[];
  /** The empty line ending the header block was seen within the limit. */
  complete: boolean;
  /** The header block exceeded the limit; only complete lines within it were parsed. */
  truncated: boolean;
}

/** Cuts a string to at most `max` code points (never splits a surrogate pair). */
export function truncateCodePoints(value: string, max: number): string {
  if (value.length <= max) return value;
  let count = 0;
  let end = 0;
  for (const char of value) {
    if (count === max) break;
    count += 1;
    end += char.length;
  }
  return value.slice(0, end);
}

/** The address inside the first `<…>` of a header value, else the trimmed value. */
export function headerAddress(value: string): string {
  const match = /<([^<>]*)>/.exec(value);
  return (match ? match[1]! : value).trim();
}

const LF = 0x0a;

/**
 * Finds the end of the header block: the index just after the empty line (CRLF CRLF, LF LF, or
 * a message that starts with an empty line). Returns -1 when not found.
 */
function findHeaderEnd(buffer: Buffer, from: number): number {
  if (from === 0) {
    if (buffer[0] === LF) return 1;
    if (buffer[0] === 0x0d && buffer[1] === LF) return 2;
  }
  let index = buffer.indexOf(LF, Math.max(0, from));
  while (index !== -1) {
    // LF followed by LF, or LF followed by CR LF: an empty line.
    const next = buffer[index + 1];
    if (next === LF) return index + 2;
    if (next === 0x0d && buffer[index + 2] === LF) return index + 3;
    index = buffer.indexOf(LF, index + 1);
  }
  return -1;
}

/**
 * Feed message chunks with `push` until `done`; then call `result()`. Memory is bounded by
 * `maxBytes` plus one chunk (the excess is discarded immediately).
 */
export class HeaderScanner {
  private buffer: Buffer = Buffer.alloc(0);
  private ended = false;
  private complete = false;
  private truncated = false;

  constructor(private readonly maxBytes: number) {}

  /** True once the header block ended or the limit was reached. */
  get done(): boolean {
    return this.ended;
  }

  push(chunk: Buffer): void {
    if (this.ended || chunk.length === 0) return;
    const searchFrom = Math.max(0, this.buffer.length - 2);
    const combined = Buffer.concat([this.buffer, chunk]);
    const end = findHeaderEnd(combined, this.buffer.length === 0 ? 0 : searchFrom);
    if (end !== -1 && end <= this.maxBytes) {
      this.buffer = combined.subarray(0, end);
      this.complete = true;
      this.ended = true;
      return;
    }
    if (combined.length >= this.maxBytes) {
      this.buffer = Buffer.from(combined.subarray(0, this.maxBytes));
      this.truncated = true;
      this.ended = true;
      return;
    }
    this.buffer = combined;
  }

  /** Marks the end of the message (a message may have no body and no empty line). */
  finish(): void {
    this.ended = true;
  }

  result(): HeaderMetadata {
    let text = this.buffer.toString('utf8');
    if (!this.complete) {
      // Only complete lines: drop a trailing partial line (cut by the limit or the message end).
      const lastLf = text.lastIndexOf('\n');
      if (this.truncated) text = lastLf === -1 ? '' : text.slice(0, lastLf + 1);
    }
    const fields = parseFields(text);
    const meta: HeaderMetadata = {
      messageId: null,
      subject: null,
      from: null,
      fromValues: [],
      receivedCount: 0,
      traces: [],
      complete: this.complete,
      truncated: this.truncated,
    };
    for (const { name, value } of fields) {
      switch (name) {
        case 'message-id':
          meta.messageId ??= truncateCodePoints(value, MAX_MESSAGE_ID_CHARS);
          break;
        case 'subject':
          meta.subject ??= truncateCodePoints(value, MAX_SUBJECT_CHARS);
          break;
        case 'from':
          meta.from ??= truncateCodePoints(headerAddress(value), MAX_HEADER_FROM_CHARS);
          meta.fromValues.push(value);
          break;
        case 'received':
          meta.receivedCount += 1;
          break;
        case 'x-gateway-trace':
          meta.traces.push(value);
          break;
        default:
          break;
      }
    }
    return meta;
  }
}

/** Unfolds header lines (CRLF or LF) into lower-cased names and trimmed raw values. */
export function parseFields(text: string): { name: string; value: string }[] {
  const fields: { name: string; value: string }[] = [];
  let current: { name: string; value: string } | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) break;
    if (line[0] === ' ' || line[0] === '\t') {
      // RFC 5322 unfolding: remove the line break, keep the whitespace.
      if (current) current.value += line;
      continue;
    }
    const colon = line.indexOf(':');
    // A line that is neither a field nor a continuation (e.g. an mbox "From " line) is skipped.
    if (colon <= 0 || /[\s]/.test(line.slice(0, colon))) {
      current = null;
      continue;
    }
    current = { name: line.slice(0, colon).toLowerCase(), value: line.slice(colon + 1) };
    fields.push(current);
  }
  return fields.map(({ name, value }) => ({ name, value: value.trim() }));
}
