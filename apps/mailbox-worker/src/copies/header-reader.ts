import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';

/** Reads the first bytes of a stored EML (the header block for the lag, D7.8). */
export interface HeaderReader {
  /** Up to `maxBytes` leading bytes of `key`; null when the object does not exist. */
  read(key: string, maxBytes: number, signal: AbortSignal): Promise<Uint8Array | null>;
}

/** True for S3's "the key does not exist" answers (never for a missing bucket or an outage). */
export function isNoSuchKey(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const { name, $metadata } = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
  if (name === 'NoSuchKey') return true;
  return $metadata?.httpStatusCode === 404 && name !== 'NoSuchBucket';
}

/**
 * A bounded range GET (`Range: bytes=0-<maxBytes-1>`) of the mail bucket: never the whole message,
 * never buffered beyond `maxBytes` (the stream is cut if a store ignores the range).
 */
export class S3HeaderReader implements HeaderReader {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly timeoutMs = 30_000,
  ) {}

  async read(key: string, maxBytes: number, signal: AbortSignal): Promise<Uint8Array | null> {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    let body: unknown;
    try {
      const response = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: key, Range: `bytes=0-${maxBytes - 1}` }),
        { abortSignal: AbortSignal.any([signal, timeout]) },
      );
      body = response.Body;
    } catch (error) {
      if (isNoSuchKey(error)) return null;
      throw error;
    }
    if (!body || typeof (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator] !== 'function') {
      const bytes = await (
        body as { transformToByteArray?: () => Promise<Uint8Array> }
      )?.transformToByteArray?.();
      return bytes ? bytes.subarray(0, maxBytes) : new Uint8Array();
    }
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of body as AsyncIterable<Uint8Array>) {
      const buffer = Buffer.from(chunk);
      chunks.push(buffer);
      total += buffer.length;
      if (total >= maxBytes) {
        (body as { destroy?: () => void }).destroy?.();
        break;
      }
    }
    return Buffer.concat(chunks).subarray(0, maxBytes);
  }
}
