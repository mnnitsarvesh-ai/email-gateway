import { createHash, type Hash } from 'node:crypto';
import { Transform, type TransformCallback } from 'node:stream';

/**
 * The body hash of cross-source dedupe (step 8.6 D7): SHA-256 of the bytes after the first
 * header/body separator, which is the first `CRLF CRLF` or `LF LF` byte sequence (whichever comes
 * first). A message without a separator has an empty body (SHA-256 of nothing). Chunks may split
 * anywhere, including inside the separator; state between chunks is the last three bytes.
 */
export class BodyHashState {
  private readonly hash: Hash = createHash('sha256');
  private found = false;
  /** Last three bytes seen before the separator (-1 = none). */
  private b1 = -1;
  private b2 = -1;
  private b3 = -1;
  private headerCount = 0;
  private digestHex: string | null = null;

  update(chunk: Buffer): void {
    if (this.digestHex !== null) throw new Error('BodyHashState: update after digest');
    if (chunk.length === 0) return;
    if (this.found) {
      this.hash.update(chunk);
      return;
    }
    let from = 0;
    for (;;) {
      const nl = chunk.indexOf(0x0a, from);
      if (nl < 0) break;
      const p1 = nl >= 1 ? chunk[nl - 1]! : this.b3;
      const p2 = nl >= 2 ? chunk[nl - 2]! : nl === 1 ? this.b3 : this.b2;
      const p3 = nl >= 3 ? chunk[nl - 3]! : nl === 2 ? this.b3 : nl === 1 ? this.b2 : this.b1;
      if (p1 === 0x0a || (p1 === 0x0d && p2 === 0x0a && p3 === 0x0d)) {
        this.found = true;
        this.headerCount += nl + 1;
        this.hash.update(chunk.subarray(nl + 1));
        return;
      }
      from = nl + 1;
    }
    this.headerCount += chunk.length;
    const n = chunk.length;
    if (n >= 3) {
      this.b1 = chunk[n - 3]!;
      this.b2 = chunk[n - 2]!;
      this.b3 = chunk[n - 1]!;
    } else if (n === 2) {
      this.b1 = this.b3;
      this.b2 = chunk[0]!;
      this.b3 = chunk[1]!;
    } else {
      this.b1 = this.b2;
      this.b2 = this.b3;
      this.b3 = chunk[0]!;
    }
  }

  /** Bytes of the header block including the separator (all bytes when there is none). */
  get headerBytes(): number {
    return this.headerCount;
  }

  get separatorFound(): boolean {
    return this.found;
  }

  digest(): string {
    this.digestHex ??= this.hash.digest('hex');
    return this.digestHex;
  }
}

/**
 * A pass-through Transform computing the body hash (`BodyHasher`): pipe the EML through it while
 * it is streamed (capture executor); `bodySha256` is available after `end`.
 */
export class BodyHasher extends Transform {
  private readonly state = new BodyHashState();
  private digestHex: string | null = null;

  get bodySha256(): string | null {
    return this.digestHex;
  }

  get headerBytes(): number {
    return this.state.headerBytes;
  }

  override _transform(chunk: unknown, _enc: BufferEncoding, callback: TransformCallback): void {
    try {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
      this.state.update(buf);
      callback(null, buf);
    } catch (err) {
      callback(err as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    this.digestHex = this.state.digest();
    this.emit('bodySha256', this.digestHex);
    callback();
  }
}

/** The body hash of a whole message. */
export function bodySha256Of(message: Buffer): string {
  const s = new BodyHashState();
  s.update(message);
  return s.digest();
}
