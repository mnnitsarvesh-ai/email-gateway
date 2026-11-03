import { CopyObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { Injectable } from '@nestjs/common';
import { S3Service } from '@email-gateway/common';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';

export const EML_CONTENT_TYPE = 'message/rfc822';

export interface EmlUploadOptions {
  key: string;
  partSize: number;
  queueSize: number;
  timeoutMs: number;
}

/**
 * One streaming upload of an EML (D7 step 2d): `write` with backpressure, then `finish`.
 * Memory is bounded by lib-storage (part size × (queue size + 1)). Never throws from `write`:
 * a failed upload stops accepting data and `finish` rejects.
 */
export class EmlUpload {
  private readonly body = new PassThrough();
  private readonly abortController = new AbortController();
  private readonly timer: NodeJS.Timeout;
  private readonly done: Promise<void>;
  private failure: unknown = null;
  private settled = false;

  constructor(s3: S3Service, options: EmlUploadOptions) {
    const upload = new Upload({
      client: s3.client,
      params: {
        Bucket: s3.mailBucket,
        Key: options.key,
        Body: this.body,
        ContentType: EML_CONTENT_TYPE,
      },
      partSize: options.partSize,
      queueSize: options.queueSize,
      leavePartsOnError: false,
      abortController: this.abortController,
    });
    // Errors surface through done(); a stray 'error' on the body must not crash the process.
    this.body.on('error', () => undefined);
    this.timer = setTimeout(() => this.abort(new Error('S3 upload timed out')), options.timeoutMs);
    this.timer.unref();
    this.done = upload.done().then(
      () => {
        this.settled = true;
      },
      (err: unknown) => {
        this.settled = true;
        this.failure ??= err;
        this.body.destroy();
        throw err;
      },
    );
    // Observed through finish(); never an unhandled rejection.
    this.done.catch(() => undefined);
  }

  /** True once the upload failed (the caller stops writing and drains the source). */
  get failed(): boolean {
    return this.failure !== null;
  }

  async write(chunk: Buffer): Promise<void> {
    if (this.failed || this.settled || this.body.destroyed) return;
    if (this.body.write(chunk)) return;
    await Promise.race([
      once(this.body, 'drain').catch(() => undefined),
      this.done.catch(() => undefined),
    ]);
  }

  /** Ends the body and waits for the upload; rejects with the upload's error. */
  async finish(): Promise<void> {
    try {
      if (!this.failed) this.body.end();
      await this.done;
    } finally {
      clearTimeout(this.timer);
    }
    const failure = this.failure;
    if (failure !== null) {
      throw failure instanceof Error ? failure : new Error('S3 upload failed', { cause: failure });
    }
  }

  abort(reason: unknown): void {
    this.failure ??= reason;
    this.abortController.abort();
    this.body.destroy();
  }
}

/** S3 side of ingestion: the EML under each organization's prefix (D8). */
@Injectable()
export class EmlStore {
  constructor(private readonly s3: S3Service) {}

  startUpload(options: EmlUploadOptions): EmlUpload {
    return new EmlUpload(this.s3, options);
  }

  /** Server-side copy for an additional organization (no re-streaming). */
  async copy(sourceKey: string, targetKey: string, timeoutMs: number): Promise<void> {
    const bucket = this.s3.mailBucket;
    await this.s3.client.send(
      new CopyObjectCommand({
        Bucket: bucket,
        Key: targetKey,
        CopySource: `${bucket}/${sourceKey}`,
        ContentType: EML_CONTENT_TYPE,
        MetadataDirective: 'REPLACE',
      }),
      { abortSignal: AbortSignal.timeout(timeoutMs) },
    );
  }

  async delete(key: string, timeoutMs: number): Promise<void> {
    await this.s3.client.send(new DeleteObjectCommand({ Bucket: this.s3.mailBucket, Key: key }), {
      abortSignal: AbortSignal.timeout(timeoutMs),
    });
  }
}
