import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import type { S3Client } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { MailboxApiError } from '@email-gateway/mailbox-api';

export interface StoredEml {
  sizeBytes: number;
  sha256: string;
  /** The first `headerMaxBytes` bytes (header metadata is parsed from them, never re-read). */
  head: Uint8Array;
}

/** Where fetched copies are written (the mail bucket; a fake in unit tests). */
export interface EmlSink {
  put(
    key: string,
    body: AsyncIterable<Uint8Array>,
    options: { maxBytes: number; headerMaxBytes: number; signal: AbortSignal },
  ): Promise<StoredEml>;
}

/**
 * Hashes, measures and keeps the head of a streamed body while passing it on; more than
 * `maxBytes` fails `response_too_large` (the provider clients cap too; this is the second guard).
 */
export class MeteredBody {
  readonly hash = createHash('sha256');
  size = 0;
  private readonly headChunks: Buffer[] = [];
  private headSize = 0;

  constructor(
    private readonly maxBytes: number,
    private readonly headerMaxBytes: number,
  ) {}

  async *pipe(body: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array, void, undefined> {
    for await (const chunk of body) {
      this.size += chunk.length;
      if (this.size > this.maxBytes) {
        throw new MailboxApiError('response_too_large', { retryable: false });
      }
      this.hash.update(chunk);
      if (this.headSize < this.headerMaxBytes) {
        const take = Buffer.from(chunk).subarray(0, this.headerMaxBytes - this.headSize);
        this.headChunks.push(take);
        this.headSize += take.length;
      }
      yield chunk;
    }
  }

  result(): StoredEml {
    return {
      sizeBytes: this.size,
      sha256: this.hash.digest('hex'),
      head: Buffer.concat(this.headChunks),
    };
  }
}

const toError = (value: unknown): Error =>
  value instanceof Error ? value : new Error('eml upload failed');

/**
 * Streams a fetched copy into the mail bucket (D10.3: `org/<org>/eml/<yyyy>/<mm>/<dd>/<ref>.eml`,
 * `message/rfc822`) with SHA-256 and size, never buffering the whole message (multipart upload
 * for large bodies). The key is deterministic per (connection, mailbox, provider message), so a
 * retried fetch overwrites the same object.
 */
export class S3EmlSink implements EmlSink {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly options: { partSizeBytes?: number; queueSize?: number } = {},
  ) {}

  async put(
    key: string,
    body: AsyncIterable<Uint8Array>,
    options: { maxBytes: number; headerMaxBytes: number; signal: AbortSignal },
  ): Promise<StoredEml> {
    const metered = new MeteredBody(options.maxBytes, options.headerMaxBytes);
    let streamError: unknown;
    const source = Readable.from(
      (async function* () {
        try {
          yield* metered.pipe(body);
        } catch (error) {
          streamError = error;
          throw error;
        }
      })(),
    );
    const upload = new Upload({
      client: this.client,
      params: {
        Bucket: this.bucket,
        Key: key,
        Body: source,
        ContentType: 'message/rfc822',
      },
      queueSize: this.options.queueSize ?? 2,
      partSize: this.options.partSizeBytes ?? 5 * 1024 * 1024,
      leavePartsOnError: false,
    });
    const abort = () => void upload.abort().catch(() => undefined);
    options.signal.addEventListener('abort', abort, { once: true });
    try {
      await upload.done();
    } catch (error) {
      throw toError(streamError ?? error);
    } finally {
      options.signal.removeEventListener('abort', abort);
    }
    if (streamError !== undefined) throw toError(streamError);
    return metered.result();
  }
}
