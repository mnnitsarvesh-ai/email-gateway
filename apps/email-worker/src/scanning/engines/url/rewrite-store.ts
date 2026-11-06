import { DeleteObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { PassThrough, type Writable } from 'node:stream';
import type { RewriteResult } from '@email-gateway/url-security';

/**
 * Where the rewritten copy of an EML goes (step 4.3 U11): a new object per attempt, written while
 * the rewriter streams (never buffered whole). `produce` writes into the sink and reports
 * whether the copy is usable; anything but `rewritten` discards the object.
 */
export interface RewriteStore {
  write(
    key: string,
    produce: (sink: Writable) => Promise<RewriteResult>,
    signal: AbortSignal,
  ): Promise<RewriteResult>;
}

/** The object tag the MinIO/S3 lifecycle rule `eg-rewrite-expiry` expires (U11). */
export const REWRITE_OBJECT_TAG = { Key: 'eg-object', Value: 'rewrite' } as const;

/** `x-amz-tagging` form of the tag, set atomically on PutObject / CreateMultipartUpload. */
export const REWRITE_OBJECT_TAGGING = `${REWRITE_OBJECT_TAG.Key}=${REWRITE_OBJECT_TAG.Value}`;

/**
 * S3 multipart `Upload` (`@aws-sdk/lib-storage`) of the rewritten EML: `ContentType:
 * message/rfc822`, `ContentDisposition: attachment`, tag `eg-object=rewrite`. The tag goes in
 * the `Tagging` parameter of the creating request (PutObject for a single part,
 * CreateMultipartUpload otherwise), so an object never exists untagged: lib-storage's `tags`
 * option would apply it with a separate PutObjectTagging AFTER the object was stored, and a
 * failure there would leave an untagged full copy of the email that the lifecycle rule never
 * expires. A skipped rewrite aborts the upload (and deletes an object a single-part upload may
 * already have completed). An upload error after a successful rewrite deletes the key (best
 * effort; the object, if any, is tagged and the lifecycle rule expires it otherwise) and is
 * thrown: an infrastructure failure (transient), never a verdict.
 */
export class S3RewriteStore implements RewriteStore {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly options: { partSizeBytes: number; queueSize: number },
  ) {}

  async write(
    key: string,
    produce: (sink: Writable) => Promise<RewriteResult>,
    signal: AbortSignal,
  ): Promise<RewriteResult> {
    const body = new PassThrough();
    const upload = new Upload({
      client: this.client,
      params: {
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: 'message/rfc822',
        ContentDisposition: 'attachment',
        Tagging: REWRITE_OBJECT_TAGGING,
      },
      partSize: this.options.partSizeBytes,
      queueSize: this.options.queueSize,
      leavePartsOnError: false,
    });
    const done = upload.done().then(
      () => ({ ok: true as const }),
      (error: unknown) => ({ ok: false as const, error }),
    );
    const onAbort = (): void => {
      body.destroy(new Error('aborted'));
      void upload.abort().catch(() => undefined);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    try {
      let result: RewriteResult;
      try {
        result = await produce(body);
      } catch (error) {
        body.destroy(error instanceof Error ? error : new Error('rewrite failed'));
        await upload.abort().catch(() => undefined);
        await done;
        throw error;
      }
      if (result.status !== 'rewritten' || signal.aborted) {
        if (!body.destroyed) body.destroy(new Error('rewrite skipped'));
        await upload.abort().catch(() => undefined);
        const outcome = await done;
        if (outcome.ok) await this.deleteQuietly(key);
        return result;
      }
      const outcome = await done;
      if (!outcome.ok) {
        // The object may exist (e.g. the response of a completed request was lost).
        await this.deleteQuietly(key);
        throw outcome.error;
      }
      return result;
    } finally {
      signal.removeEventListener('abort', onAbort);
    }
  }

  private async deleteQuietly(key: string): Promise<void> {
    await this.client
      .send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }))
      .catch(() => undefined);
  }
}
