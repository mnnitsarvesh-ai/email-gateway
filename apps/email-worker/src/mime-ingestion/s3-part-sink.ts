import { DeleteObjectCommand, GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import type { PartInfo, PartSink, PartWriter, StoredPart } from '@email-gateway/mime-parser';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import { assertOrganizationKey, partKey, type PartKeyTarget } from './part-keys';

/** Object headers (M11): never rendered when opened by mistake; no filename, no header value. */
export const PART_CONTENT_TYPES = {
  text: 'text/plain; charset=utf-8',
  html: 'application/octet-stream',
  attachment: 'application/octet-stream',
} as const;
export const PART_CONTENT_DISPOSITION = 'attachment';

export interface S3PartSinkOptions {
  client: S3Client;
  bucket: string;
  /** Organization, message id and received_at of the writer row (keys, M11). */
  target: PartKeyTarget;
  partSizeBytes: number;
  queueSize: number;
  /**
   * Budget of one wait on S3 (MIME_S3_TIMEOUT_MS): a write waiting for upload capacity, the
   * finish waiting for the object to be durable, or one ranged read.
   */
  timeoutMs: number;
}

/** A sink that remembers the objects it completed (integrity-mismatch cleanup, M3.8). */
export interface RecordingPartSink extends PartSink {
  readonly writtenKeys: readonly string[];
  /** Deletes every object this attempt completed (best effort; returns the failures). */
  deleteWritten(): Promise<number>;
}

class UploadAborted extends Error {
  override readonly name = 'UploadAborted';
}

class UploadTimedOut extends Error {
  override readonly name = 'UploadTimedOut';
  readonly code = 'ETIMEDOUT';
}

/**
 * One part streamed to S3 with `@aws-sdk/lib-storage` (the step 2.2 `EmlUpload` pattern): `write`
 * honours backpressure, `finish` resolves once the object is durable, `abort` discards it. Memory
 * is bounded by lib-storage (part size × (queue size + 1)). `leavePartsOnError: false` aborts a
 * started multipart upload; a single-part upload is only sent once the body ended, so an abort
 * before `finish` never creates an object.
 */
class S3PartWriter implements PartWriter {
  private readonly body = new PassThrough();
  private readonly abortController = new AbortController();
  private readonly done: Promise<void>;
  private failure: unknown = null;
  private finished = false;

  constructor(
    private readonly options: S3PartSinkOptions,
    readonly key: string,
    kind: PartInfo['kind'],
    private readonly onFinished: (key: string) => void,
  ) {
    const upload = new Upload({
      client: options.client,
      params: {
        Bucket: options.bucket,
        Key: key,
        Body: this.body,
        ContentType: PART_CONTENT_TYPES[kind],
        ContentDisposition: PART_CONTENT_DISPOSITION,
      },
      partSize: options.partSizeBytes,
      queueSize: options.queueSize,
      leavePartsOnError: false,
      abortController: this.abortController,
    });
    // Errors surface through write/finish; a stray 'error' on the body must not crash the process.
    this.body.on('error', () => undefined);
    this.done = upload.done().then(
      () => undefined,
      (err: unknown) => {
        this.failure ??= err;
        this.body.destroy();
        throw err;
      },
    );
    this.done.catch(() => undefined);
  }

  async write(chunk: Buffer): Promise<void> {
    this.throwIfFailed();
    if (!this.body.write(chunk)) {
      await this.bounded(
        Promise.race([
          once(this.body, 'drain').catch(() => undefined),
          this.done.catch(() => undefined),
        ]),
      );
      this.throwIfFailed();
    }
  }

  async finish(): Promise<StoredPart> {
    this.throwIfFailed();
    this.body.end();
    await this.bounded(this.done.catch(() => undefined));
    this.throwIfFailed();
    this.finished = true;
    this.onFinished(this.key);
    const { client, bucket, timeoutMs } = this.options;
    const key = this.key;
    return {
      key,
      async readRange(start: number, endInclusive: number, signal: AbortSignal): Promise<Buffer> {
        if (!(Number.isSafeInteger(start) && Number.isSafeInteger(endInclusive))) {
          throw new RangeError('readRange needs integer offsets');
        }
        if (start < 0 || endInclusive < start) throw new RangeError('invalid byte range');
        const response = await client.send(
          new GetObjectCommand({
            Bucket: bucket,
            Key: key,
            Range: `bytes=${start}-${endInclusive}`,
          }),
          { abortSignal: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) },
        );
        if (!response.Body) throw new Error('S3 returned no body for a ranged read');
        return Buffer.from(await response.Body.transformToByteArray());
      },
    };
  }

  async abort(): Promise<void> {
    if (this.finished) return;
    this.fail(new UploadAborted('part upload aborted'));
    await this.done.catch(() => undefined);
  }

  /**
   * Waits on S3 for at most `timeoutMs` (MIME_S3_TIMEOUT_MS); a longer wait fails the upload
   * with `UploadTimedOut` (an infrastructure retry). Only waiting counts, so a large part fed
   * slowly by the parser is never cut by the S3 budget.
   */
  private async bounded(pending: Promise<unknown>): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<void>((resolve) => {
      timer = setTimeout(() => {
        this.fail(new UploadTimedOut('S3 part upload stalled'));
        resolve();
      }, this.options.timeoutMs);
      timer.unref();
    });
    try {
      await Promise.race([pending, timedOut]);
    } finally {
      clearTimeout(timer);
    }
  }

  private fail(reason: unknown): void {
    this.failure ??= reason;
    this.abortController.abort();
    this.body.destroy();
  }

  private throwIfFailed(): void {
    const failure = this.failure;
    if (failure === null) return;
    throw failure instanceof Error
      ? failure
      : new Error('S3 part upload failed', { cause: failure });
  }
}

/**
 * The email-worker side of the parser's `PartSink` (design M11): one deterministic object per
 * body or attachment leaf in `S3_BUCKET_MAIL`, under the writer row's organization prefix.
 */
export class S3PartSink implements RecordingPartSink {
  private readonly written: string[] = [];

  constructor(private readonly options: S3PartSinkOptions) {}

  get writtenKeys(): readonly string[] {
    return this.written;
  }

  open(part: PartInfo): Promise<PartWriter> {
    const key = partKey(this.options.target, part);
    assertOrganizationKey(key, this.options.target.organizationId);
    return Promise.resolve(
      new S3PartWriter(this.options, key, part.kind, (done) => {
        if (!this.written.includes(done)) this.written.push(done);
      }),
    );
  }

  async deleteWritten(): Promise<number> {
    let failures = 0;
    for (const key of this.written) {
      try {
        await this.options.client.send(
          new DeleteObjectCommand({ Bucket: this.options.bucket, Key: key }),
          { abortSignal: AbortSignal.timeout(this.options.timeoutMs) },
        );
      } catch {
        failures += 1;
      }
    }
    return failures;
  }
}
