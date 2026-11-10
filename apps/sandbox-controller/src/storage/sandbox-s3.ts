import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { SAMPLE_KEY_PATTERN, ARTIFACT_KEY_PATTERN } from '@email-gateway/sandbox';

/**
 * The controller's only S3 access (step 4.6 X12; ADR-0040 decision 3): the restricted sandbox
 * bucket with its own credentials (`SANDBOX_S3_*`, MinIO user / IAM policy
 * `eg-sandbox-controller`): `GetObject samples/*` and `PutObject artifacts/*`, nothing else. The
 * client refuses any other key locally as well, so a bug cannot widen the access even where a
 * policy is broader than specified.
 *
 * Failures are classified for the task handler (X7): `NoSuchKey` → `SampleMissingError`
 * (`sample_unavailable`), a body larger than allowed → `SampleTooLargeError`
 * (`sample_integrity`), everything else (network, timeout, 5xx, throttling, access denied) →
 * `StorageUnavailableError` (transient: retried with the queue's hold policy).
 */

export interface SandboxS3Options {
  bucket: string;
  region: string;
  endpoint?: string | undefined;
  forcePathStyle: boolean;
  accessKeyId: string;
  secretAccessKey: string;
  /** Per-request budget (connection + response). */
  timeoutMs: number;
}

export class SampleMissingError extends Error {
  override readonly name = 'SampleMissingError';
  constructor() {
    super('sandbox sample object does not exist');
  }
}

export class SampleTooLargeError extends Error {
  override readonly name = 'SampleTooLargeError';
  constructor() {
    super('sandbox sample object exceeds the allowed size');
  }
}

/** The sandbox bucket cannot be used now (transient). `op` is a bounded token. */
export class StorageUnavailableError extends Error {
  override readonly name = 'StorageUnavailableError';
  constructor(
    readonly op: 'get_sample' | 'put_artifact' | 'probe',
    readonly code: string,
    options?: { cause?: unknown },
  ) {
    super(`sandbox bucket unavailable (${op}: ${code})`, options);
  }
}

export class ObjectKeyRefusedError extends Error {
  override readonly name = 'ObjectKeyRefusedError';
  constructor() {
    super('object key outside the controller prefixes');
  }
}

const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;
/** The readiness probe reads a sample key that never exists (`NoSuchKey` = reachable). */
export const PROBE_SAMPLE_KEY = 'samples/0000/00/00000000-0000-0000-0000-000000000000.bin';
/** Credential failures: the endpoint answered but refused who we are (readiness fails). */
const CREDENTIAL_ERRORS = new Set([
  'InvalidAccessKeyId',
  'SignatureDoesNotMatch',
  'InvalidToken',
  'ExpiredToken',
  'AuthorizationHeaderMalformed',
]);

function errorCode(error: unknown): string {
  if (typeof error !== 'object' || error === null) return 'unknown';
  const { name, Code, code } = error as { name?: unknown; Code?: unknown; code?: unknown };
  for (const candidate of [Code, name, code]) {
    if (typeof candidate === 'string' && TOKEN.test(candidate) && candidate !== 'Error')
      return candidate;
  }
  return 'unknown';
}

export interface SampleStore {
  getSample(key: string, maxBytes: number, signal?: AbortSignal): Promise<Buffer>;
  putArtifact(key: string, body: Buffer, signal?: AbortSignal): Promise<void>;
  probe(signal?: AbortSignal): Promise<void>;
  close(): void;
}

export class SandboxS3 implements SampleStore {
  private readonly client: S3Client;

  constructor(private readonly options: SandboxS3Options) {
    this.client = new S3Client({
      region: options.region,
      ...(options.endpoint ? { endpoint: options.endpoint } : {}),
      forcePathStyle: options.forcePathStyle,
      credentials: { accessKeyId: options.accessKeyId, secretAccessKey: options.secretAccessKey },
      // One attempt: an outage is retried by the queue's hold policy (X7), not inside a task.
      maxAttempts: 1,
      // Constructor parameters of the SDK's Node HTTP handler (no direct dependency on it).
      requestHandler: {
        connectionTimeout: Math.min(options.timeoutMs, 5_000),
        requestTimeout: options.timeoutMs,
      },
    });
  }

  get bucket(): string {
    return this.options.bucket;
  }

  private signal(outer?: AbortSignal): AbortSignal {
    const timeout = AbortSignal.timeout(this.options.timeoutMs);
    return outer ? AbortSignal.any([outer, timeout]) : timeout;
  }

  /** `GetObject samples/…`, refusing a body above `maxBytes` (streamed, never fully buffered). */
  async getSample(key: string, maxBytes: number, signal?: AbortSignal): Promise<Buffer> {
    if (!SAMPLE_KEY_PATTERN.test(key)) throw new ObjectKeyRefusedError();
    const abortSignal = this.signal(signal);
    let response;
    try {
      response = await this.client.send(
        new GetObjectCommand({ Bucket: this.options.bucket, Key: key }),
        { abortSignal },
      );
    } catch (error) {
      if (errorCode(error) === 'NoSuchKey') throw new SampleMissingError();
      throw new StorageUnavailableError('get_sample', errorCode(error), { cause: error });
    }
    const length = response.ContentLength;
    if (typeof length === 'number' && length > maxBytes) {
      (response.Body as { destroy?: () => void } | undefined)?.destroy?.();
      throw new SampleTooLargeError();
    }
    const body = response.Body as AsyncIterable<Uint8Array> | undefined;
    if (!body) throw new StorageUnavailableError('get_sample', 'empty_body');
    const chunks: Buffer[] = [];
    let total = 0;
    try {
      for await (const chunk of body) {
        total += chunk.length;
        if (total > maxBytes) {
          (body as { destroy?: () => void }).destroy?.();
          throw new SampleTooLargeError();
        }
        chunks.push(Buffer.from(chunk));
      }
    } catch (error) {
      if (error instanceof SampleTooLargeError) throw error;
      throw new StorageUnavailableError('get_sample', errorCode(error), { cause: error });
    }
    return Buffer.concat(chunks, total);
  }

  /** `PutObject artifacts/…` (one run id per run: a retried task writes new keys). */
  async putArtifact(key: string, body: Buffer, signal?: AbortSignal): Promise<void> {
    if (!ARTIFACT_KEY_PATTERN.test(key)) throw new ObjectKeyRefusedError();
    try {
      await this.client.send(
        new PutObjectCommand({
          Bucket: this.options.bucket,
          Key: key,
          Body: body,
          ContentLength: body.length,
          ContentType: 'application/octet-stream',
        }),
        { abortSignal: this.signal(signal) },
      );
    } catch (error) {
      throw new StorageUnavailableError('put_artifact', errorCode(error), { cause: error });
    }
  }

  /**
   * Readiness: a `GetObject` of a sample key that never exists. `NoSuchKey` (or `AccessDenied`
   * where the policy hides missing keys, as AWS does without `s3:ListBucket`) proves the endpoint
   * is reachable, the bucket exists and the credentials are valid; credential errors, a missing
   * bucket and network failures reject. (The user may not `HeadBucket`: it has no bucket-level
   * permission, by design.)
   */
  async probe(signal?: AbortSignal): Promise<void> {
    try {
      const response = await this.client.send(
        new GetObjectCommand({ Bucket: this.options.bucket, Key: PROBE_SAMPLE_KEY }),
        { abortSignal: this.signal(signal) },
      );
      (response.Body as { destroy?: () => void } | undefined)?.destroy?.();
    } catch (error) {
      const code = errorCode(error);
      if (code === 'NoSuchKey' || code === 'AccessDenied') return;
      if (CREDENTIAL_ERRORS.has(code) || code === 'NoSuchBucket') {
        throw new StorageUnavailableError('probe', code);
      }
      throw new StorageUnavailableError('probe', code, { cause: error });
    }
  }

  close(): void {
    this.client.destroy();
  }
}
