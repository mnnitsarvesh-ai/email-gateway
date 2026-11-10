import {
  DeleteObjectCommand,
  HeadBucketCommand,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { NonRetryableError } from '@email-gateway/common';
import {
  ARTIFACT_KEY_PATTERN,
  parseArtifactKey,
  parseOptionalSymmetricKey,
  parseSymmetricKey,
  SAMPLE_KEY_PATTERN,
  sealSample,
  taskIdOfSampleKey,
} from '@email-gateway/sandbox';
import type { PartSource } from '../parts/part-reader';

/**
 * Staging of one sandbox sample (step 4.6 X13 step 6, X12): a bounded read of the submission's
 * part from the **mail** bucket (key = the submission's `object_key`, its `org/<org>/part/`
 * prefix re-checked against the submission's organization, at most the submission's size, which
 * the dispatcher already bounded by the tenant's `maxSampleBytes`; SCAN_S3_TIMEOUT_MS per wait),
 * the SHA-256 must equal the submission's, then `sandbox-sample/1` sealing under
 * `SANDBOX_SAMPLE_KEY` and a `PutObject` to the deterministic `samples/<yyyy>/<mm>/<taskId>.bin`
 * key in `SANDBOX_S3_BUCKET` with the worker's own S3 client (an idempotent overwrite on a
 * redelivery). The plaintext lives in memory only and is zeroed after sealing.
 *
 * `NoSuchKey` → `sample_unavailable`, more bytes or another hash → `sample_integrity` (both final:
 * the analysis and the submission fail); every other S3 failure is thrown (transient, retried).
 */

export type StageResult =
  | { kind: 'staged'; objectSize: number }
  | { kind: 'failed'; errorCode: 'sample_unavailable' | 'sample_integrity' };

export interface StageInput {
  organizationId: bigint;
  /** The submission's part key in the mail bucket. */
  partKey: string;
  sizeBytes: number;
  sha256: string;
  /** The analysis public id (task id) and its deterministic sample key. */
  taskId: string;
  sampleKey: string;
}

/** The objects of the sandbox bucket the email-worker writes and deletes. */
export interface SandboxObjects {
  put(key: string, body: Buffer, sha256Hex: string, signal?: AbortSignal): Promise<void>;
  /** Resolves when the object is gone (deleting a missing object succeeds). */
  delete(key: string, signal?: AbortSignal): Promise<void>;
  /** Readiness: the bucket exists and is reachable. */
  check(signal?: AbortSignal): Promise<void>;
}

/** A key of the sandbox bucket the worker may delete (samples and artifacts only). */
export const isSandboxSampleKey = (key: string): boolean =>
  SAMPLE_KEY_PATTERN.test(key) && taskIdOfSampleKey(key) !== null;
export const isSandboxArtifactKey = (key: string): boolean =>
  ARTIFACT_KEY_PATTERN.test(key) && parseArtifactKey(key) !== null;

export class S3SandboxObjects implements SandboxObjects {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly timeoutMs: number,
  ) {}

  private signal(signal?: AbortSignal): AbortSignal {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    return signal ? AbortSignal.any([signal, timeout]) : timeout;
  }

  async put(key: string, body: Buffer, sha256Hex: string, signal?: AbortSignal): Promise<void> {
    if (!isSandboxSampleKey(key)) throw new NonRetryableError('sandbox_sample_key_invalid');
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: 'application/octet-stream',
        ChecksumSHA256: Buffer.from(sha256Hex, 'hex').toString('base64'),
      }),
      { abortSignal: this.signal(signal) },
    );
  }

  async delete(key: string, signal?: AbortSignal): Promise<void> {
    if (!isSandboxSampleKey(key) && !isSandboxArtifactKey(key)) {
      throw new NonRetryableError('sandbox_object_key_invalid');
    }
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }), {
      abortSignal: this.signal(signal),
    });
  }

  async check(signal?: AbortSignal): Promise<void> {
    await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }), {
      abortSignal: this.signal(signal),
    });
  }
}

export interface SampleStagerOptions {
  parts: PartSource;
  objects: SandboxObjects;
  /** SANDBOX_SAMPLE_KEY and SANDBOX_SAMPLE_KEY_PREVIOUS (64 hex). */
  sampleKey: string;
  previousSampleKey?: string;
  /** SCAN_S3_TIMEOUT_MS x 4: the whole staging (read, seal, put) of one sample. */
  timeoutMs: number;
}

export class SampleStager {
  constructor(private readonly options: SampleStagerOptions) {
    // Fail at construction (start-up), not at the first sample.
    parseSymmetricKey('SANDBOX_SAMPLE_KEY', options.sampleKey).fill(0);
  }

  async stage(input: StageInput): Promise<StageResult> {
    const prefix = `org/${input.organizationId.toString()}/part/`;
    if (!input.partKey.startsWith(prefix) || input.partKey.split('/').includes('..')) {
      // The event and the row were checked already: a key outside the tenant's parts is never read.
      throw new NonRetryableError('tenant_mismatch');
    }
    if (taskIdOfSampleKey(input.sampleKey) !== input.taskId) {
      throw new NonRetryableError('sandbox_sample_key_invalid');
    }
    const signal = AbortSignal.timeout(this.options.timeoutMs);
    const read = await this.options.parts.read(
      input.partKey,
      input.sizeBytes,
      input.sha256,
      signal,
    );
    if (read.kind === 'missing') return { kind: 'failed', errorCode: 'sample_unavailable' };
    if (read.kind === 'integrity') return { kind: 'failed', errorCode: 'sample_integrity' };
    const current = parseSymmetricKey('SANDBOX_SAMPLE_KEY', this.options.sampleKey);
    const previous = parseOptionalSymmetricKey(
      'SANDBOX_SAMPLE_KEY_PREVIOUS',
      this.options.previousSampleKey ?? '',
      current,
    );
    let sealed;
    try {
      sealed = sealSample({ current, previous }, read.bytes, {
        taskId: input.taskId,
        sha256: input.sha256,
      });
    } finally {
      current.fill(0);
      previous?.fill(0);
      read.bytes.fill(0);
    }
    await this.options.objects.put(input.sampleKey, sealed.object, sealed.objectSha256, signal);
    return { kind: 'staged', objectSize: sealed.size };
  }
}
