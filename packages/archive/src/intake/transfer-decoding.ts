/**
 * Streaming Content-Transfer-Encoding decoders (RFC 2045 §6) used by the journal report
 * unwrapper: chunks may split anywhere (inside a base64 quantum, an `=XX` escape or a soft line
 * break); state between chunks is a few bytes. Both decoders are tolerant (invalid input is
 * skipped or kept literally) because a journal copy must be stored, never refused.
 */

export interface StreamDecoder {
  push(chunk: Buffer): Buffer;
  end(): Buffer;
}

export type TransferEncoding = 'identity' | 'base64' | 'quoted-printable';

/** Maps a `Content-Transfer-Encoding` value; unknown values are null. */
export function transferEncodingOf(value: string | null | undefined): TransferEncoding | null {
  const v = (value ?? '').trim().toLowerCase();
  if (v === '' || v === '7bit' || v === '8bit' || v === 'binary') return 'identity';
  if (v === 'base64') return 'base64';
  if (v === 'quoted-printable') return 'quoted-printable';
  return null;
}

class IdentityDecoder implements StreamDecoder {
  push(chunk: Buffer): Buffer {
    return chunk;
  }
  end(): Buffer {
    return Buffer.alloc(0);
  }
}

const B64 = new Int16Array(256).fill(-1);
'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  .split('')
  .forEach((c, i) => (B64[c.charCodeAt(0)] = i));

/** Base64: characters outside the alphabet (line breaks, whitespace, junk) are skipped; `=` ends a quantum. */
class Base64Decoder implements StreamDecoder {
  private readonly quantum: number[] = [];
  private done = false;

  push(chunk: Buffer): Buffer {
    const out = Buffer.allocUnsafe(Math.ceil(((chunk.length + 4) * 3) / 4));
    let n = 0;
    for (const byte of chunk) {
      if (this.done) {
        // After padding, a new quantum may start (concatenated base64); padding itself is skipped.
        if (B64[byte]! < 0) continue;
        this.done = false;
      }
      if (byte === 0x3d) {
        n = this.flushPartial(out, n);
        this.done = true;
        continue;
      }
      const v = B64[byte]!;
      if (v < 0) continue;
      this.quantum.push(v);
      if (this.quantum.length === 4) {
        const [a, b, c, d] = this.quantum as [number, number, number, number];
        out[n++] = (a << 2) | (b >> 4);
        out[n++] = ((b & 15) << 4) | (c >> 2);
        out[n++] = ((c & 3) << 6) | d;
        this.quantum.length = 0;
      }
    }
    return out.subarray(0, n);
  }

  private flushPartial(out: Buffer, start: number): number {
    let n = start;
    const q = this.quantum;
    if (q.length >= 2) out[n++] = (q[0]! << 2) | (q[1]! >> 4);
    if (q.length >= 3) out[n++] = ((q[1]! & 15) << 4) | (q[2]! >> 2);
    q.length = 0;
    return n;
  }

  end(): Buffer {
    const out = Buffer.allocUnsafe(3);
    return out.subarray(0, this.flushPartial(out, 0));
  }
}

const HEX = (c: number): number =>
  c >= 0x30 && c <= 0x39
    ? c - 0x30
    : c >= 0x41 && c <= 0x46
      ? c - 0x37
      : c >= 0x61 && c <= 0x66
        ? c - 0x57
        : -1;

/**
 * Quoted-printable: `=XX` escapes (either case), soft line breaks (`=` + optional whitespace +
 * CRLF or LF) and transport padding (whitespace before a line break is removed). An `=` that
 * starts no valid sequence is kept literally. Hard line breaks are kept as written.
 */
class QuotedPrintableDecoder implements StreamDecoder {
  /** Unprocessed tail: an incomplete `=` sequence or a run of whitespace awaiting what follows. */
  private pending = Buffer.alloc(0);

  push(chunk: Buffer): Buffer {
    const data = this.pending.length > 0 ? Buffer.concat([this.pending, chunk]) : chunk;
    const { out, rest } = this.decode(data, false);
    this.pending = Buffer.from(rest);
    return out;
  }

  end(): Buffer {
    const { out } = this.decode(this.pending, true);
    this.pending = Buffer.alloc(0);
    return out;
  }

  private decode(data: Buffer, final: boolean): { out: Buffer; rest: Buffer } {
    const out = Buffer.allocUnsafe(data.length);
    let n = 0;
    let i = 0;
    while (i < data.length) {
      const c = data[i]!;
      if (c === 0x3d) {
        // `=`: escape, soft break, or a literal.
        let j = i + 1;
        while (j < data.length && (data[j] === 0x20 || data[j] === 0x09)) j++;
        if (j >= data.length && !final) return { out: out.subarray(0, n), rest: data.subarray(i) };
        if (j < data.length && data[j] === 0x0a) {
          i = j + 1;
          continue;
        }
        if (j < data.length && data[j] === 0x0d) {
          if (j + 1 >= data.length && !final) {
            return { out: out.subarray(0, n), rest: data.subarray(i) };
          }
          if (data[j + 1] === 0x0a) {
            i = j + 2;
            continue;
          }
        }
        if (j === i + 1) {
          if (i + 2 >= data.length && !final) {
            return { out: out.subarray(0, n), rest: data.subarray(i) };
          }
          const h = i + 2 < data.length ? HEX(data[i + 1]!) : -1;
          const l = i + 2 < data.length ? HEX(data[i + 2]!) : -1;
          if (h >= 0 && l >= 0) {
            out[n++] = (h << 4) | l;
            i += 3;
            continue;
          }
        }
        out[n++] = c;
        i++;
        continue;
      }
      if (c === 0x20 || c === 0x09) {
        // Whitespace: dropped when it runs into a line break (transport padding), else kept.
        let j = i;
        while (j < data.length && (data[j] === 0x20 || data[j] === 0x09)) j++;
        if (j >= data.length) {
          if (!final) return { out: out.subarray(0, n), rest: data.subarray(i) };
          i = j;
          continue;
        }
        if (data[j] === 0x0a || (data[j] === 0x0d && data[j + 1] === 0x0a)) {
          i = j;
          continue;
        }
        if (data[j] === 0x0d && j + 1 >= data.length && !final) {
          return { out: out.subarray(0, n), rest: data.subarray(i) };
        }
        while (i < j) out[n++] = data[i++]!;
        continue;
      }
      out[n++] = c;
      i++;
    }
    return { out: out.subarray(0, n), rest: Buffer.alloc(0) };
  }
}

export function createTransferDecoder(encoding: TransferEncoding): StreamDecoder {
  switch (encoding) {
    case 'base64':
      return new Base64Decoder();
    case 'quoted-printable':
      return new QuotedPrintableDecoder();
    default:
      return new IdentityDecoder();
  }
}

/** Decodes a whole buffer. */
export function decodeTransfer(encoding: TransferEncoding, data: Buffer): Buffer {
  const d = createTransferDecoder(encoding);
  return Buffer.concat([d.push(data), d.end()]);
}
