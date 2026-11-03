import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { Readable } from 'node:stream';
import { S3Stalled, withStallTimeout } from './s3-waits';

/** The stored EML could not be found (`NoSuchKey`): a content outcome (`eml_missing`), not an outage. */
export const EML_MISSING = 'missing' as const;

/** Where the worker reads stored EMLs from (a fake in unit tests). */
export interface EmlSource {
  /**
   * Opens a streaming read of `key`. Resolves to `EML_MISSING` when the object does not exist;
   * rejects on every other failure (infrastructure, retried).
   */
  open(key: string, signal: AbortSignal): Promise<Readable | typeof EML_MISSING>;
}

/** True for S3's "the key does not exist" answers (never for a missing bucket or an outage). */
export function isNoSuchKey(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const { name, $metadata } = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
  if (name === 'NoSuchKey') return true;
  return $metadata?.httpStatusCode === 404 && name !== 'NoSuchBucket';
}

/**
 * Streaming `GetObject` of `email_messages.eml_object_key` from `S3_BUCKET_MAIL` (design M3.6,
 * M11). `timeoutMs` (MIME_S3_TIMEOUT_MS) bounds each wait on S3: the request until the response
 * arrives, then every body chunk the parser waits for (`S3Stalled`). Time the parser spends on
 * the bytes (backpressure) is not S3 time, so a large message is never cut by it. The caller's
 * signal (the parse budget) aborts the request too.
 */
export class S3EmlSource implements EmlSource {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly timeoutMs: number,
  ) {}

  async open(key: string, signal: AbortSignal): Promise<Readable | typeof EML_MISSING> {
    const request = new AbortController();
    const timer = setTimeout(
      () => request.abort(new S3Stalled('S3 GetObject did not answer in time')),
      this.timeoutMs,
    );
    timer.unref();
    let body: unknown;
    try {
      const response = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: key }),
        { abortSignal: AbortSignal.any([signal, request.signal]) },
      );
      body = response.Body;
    } catch (err) {
      if (isNoSuchKey(err)) return EML_MISSING;
      if (request.signal.aborted && !signal.aborted) throw request.signal.reason as Error;
      throw err;
    } finally {
      clearTimeout(timer);
    }
    if (body === undefined) throw new Error('S3 returned no body for the EML');
    const stream =
      body instanceof Readable
        ? body
        : // Non-Node runtimes hand out a web stream; the worker always runs on Node.
          Readable.fromWeb(
            (body as { transformToWebStream(): unknown }).transformToWebStream() as Parameters<
              typeof Readable.fromWeb
            >[0],
          );
    return withStallTimeout(stream, this.timeoutMs);
  }
}
