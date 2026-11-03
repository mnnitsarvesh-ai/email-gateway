/**
 * Netstrings (https://cr.yp.to/proto/netstrings.txt) as used by Postfix's socketmap protocol
 * (https://www.postfix.org/socketmap_table.5.html): `<length>:<bytes>,`.
 */

/** Largest request payload accepted (step 2.2 D11). Postfix requests are a map name and a key. */
export const MAX_NETSTRING_BYTES = 10_000;
const MAX_LENGTH_DIGITS = String(MAX_NETSTRING_BYTES).length;
const COLON = 0x3a;
const COMMA = 0x2c;

export class NetstringError extends Error {}

/**
 * Incremental decoder: accepts arbitrary chunks (split or pipelined netstrings) and returns
 * every complete payload. Throws `NetstringError` on malformed input (non-digit length, leading
 * zeros, oversize, missing trailing comma); the caller closes the connection.
 */
export class NetstringDecoder {
  private buffer: Buffer = Buffer.alloc(0);

  constructor(private readonly maxBytes = MAX_NETSTRING_BYTES) {}

  push(chunk: Buffer): Buffer[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const payloads: Buffer[] = [];
    for (;;) {
      const colon = this.buffer.indexOf(COLON);
      if (colon === -1) {
        this.checkLengthPrefix(this.buffer.length);
        return payloads;
      }
      this.checkLengthPrefix(colon);
      const digits = this.buffer.subarray(0, colon).toString('latin1');
      if (!/^(0|[1-9][0-9]*)$/.test(digits)) throw new NetstringError('invalid netstring length');
      const length = Number(digits);
      if (length > this.maxBytes) throw new NetstringError('netstring exceeds maximum size');
      const end = colon + 1 + length;
      if (this.buffer.length < end + 1) return payloads;
      if (this.buffer[end] !== COMMA) throw new NetstringError('netstring without trailing comma');
      payloads.push(Buffer.from(this.buffer.subarray(colon + 1, end)));
      this.buffer = this.buffer.subarray(end + 1);
    }
  }

  /** Validates the bytes seen before a colon (or so far, when no colon arrived yet). */
  private checkLengthPrefix(length: number): void {
    if (length > MAX_LENGTH_DIGITS) throw new NetstringError('netstring length too long');
    for (let i = 0; i < Math.min(length, this.buffer.length); i += 1) {
      const byte = this.buffer[i]!;
      if (byte < 0x30 || byte > 0x39) throw new NetstringError('invalid netstring length');
    }
  }
}

export function encodeNetstring(payload: string): Buffer {
  const body = Buffer.from(payload, 'utf8');
  return Buffer.concat([Buffer.from(`${body.length}:`, 'latin1'), body, Buffer.from(',')]);
}
