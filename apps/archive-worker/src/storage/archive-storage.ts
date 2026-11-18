import { Readable } from 'node:stream';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  GetObjectRetentionCommand,
  HeadObjectCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  PutObjectRetentionCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { ARCHIVE_OBJECT_CONTENT_TYPE, type ObjectLockMode } from '@email-gateway/archive';

/**
 * Shortest lock a new or extended version gets: a retain-until date must lie in the future when
 * the request reaches S3 (a late capture or refresh of a record whose retention already ended).
 */
export const LOCK_FLOOR_MS = 10_000;

/** Object Lock of one upload or extension (locked tenants only, A10). */
export interface ObjectLockSpec {
  mode: Exclude<ObjectLockMode, 'none'>;
  until: Date;
}

export interface StoredVersion {
  key: string;
  versionId: string | null;
}

export interface ListedVersion {
  key: string;
  versionId: string;
  lastModified: Date | null;
  deleteMarker: boolean;
}

export type DeleteVersionResult = 'deleted' | 'missing' | 'locked';

const s3Mode = (mode: ObjectLockSpec['mode']): 'GOVERNANCE' | 'COMPLIANCE' =>
  mode === 'compliance' ? 'COMPLIANCE' : 'GOVERNANCE';

const statusOf = (error: unknown): number | undefined =>
  (error as { $metadata?: { httpStatusCode?: number } } | null)?.$metadata?.httpStatusCode;

const nameOf = (error: unknown): string | undefined => (error as { name?: string } | null)?.name;

/** NoSuchKey / NoSuchVersion / 404. */
export function isMissing(error: unknown): boolean {
  const name = nameOf(error);
  return (
    statusOf(error) === 404 ||
    name === 'NoSuchKey' ||
    name === 'NotFound' ||
    name === 'NoSuchVersion'
  );
}

/** The WORM refusal of a locked version (MinIO: 400 InvalidRequest; AWS: 403 AccessDenied). */
export function isLockRefusal(error: unknown): boolean {
  const name = nameOf(error);
  const status = statusOf(error);
  return (
    (status === 400 && (name === 'InvalidRequest' || name === 'ObjectLocked')) ||
    (status === 403 && name === 'AccessDenied')
  );
}

/**
 * The archive-worker's view of S3 (A5, A10, A14, A15): streaming multipart uploads with Object
 * Lock headers, buffer puts, bounded reads, version listing and deletion (governance bypass only
 * when asked), retention extension and the Object Lock probe. Every call has a timeout. Keys are
 * checked by the callers against the row's organization before they reach this class.
 */
export class ArchiveStorage {
  constructor(
    readonly client: S3Client,
    readonly buckets: { mail: string; archive: string },
    private readonly options: { timeoutMs: number; partSizeBytes: number },
  ) {}

  private signal(): { abortSignal: AbortSignal } {
    return { abortSignal: AbortSignal.timeout(this.options.timeoutMs) };
  }

  /** `GetObjectLockConfiguration` of the archive bucket: true when Object Lock is enabled. */
  async probeObjectLock(): Promise<boolean> {
    try {
      const out = await this.client.send(
        new GetObjectLockConfigurationCommand({ Bucket: this.buckets.archive }),
        this.signal(),
      );
      return out.ObjectLockConfiguration?.ObjectLockEnabled === 'Enabled';
    } catch (error) {
      const name = nameOf(error);
      if (
        name === 'ObjectLockConfigurationNotFoundError' ||
        name === 'ObjectLockConfigurationNotFound' ||
        statusOf(error) === 404
      ) {
        return false;
      }
      throw error;
    }
  }

  /** Streams `body` into one object (lib-storage multipart; a single PUT below the part size). */
  async uploadStream(input: {
    bucket?: string;
    key: string;
    body: Readable;
    lock?: ObjectLockSpec | null;
    tagging?: string;
  }): Promise<StoredVersion> {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), this.options.timeoutMs);
    timer.unref();
    const upload = new Upload({
      client: this.client,
      params: {
        Bucket: input.bucket ?? this.buckets.archive,
        Key: input.key,
        Body: input.body,
        ContentType: ARCHIVE_OBJECT_CONTENT_TYPE,
        ...(input.tagging ? { Tagging: input.tagging } : {}),
        ...(input.lock
          ? { ObjectLockMode: s3Mode(input.lock.mode), ObjectLockRetainUntilDate: input.lock.until }
          : {}),
      },
      partSize: this.options.partSizeBytes,
      queueSize: 2,
      leavePartsOnError: false,
      abortController: abort,
    });
    // A failing source must abort the upload (no object is completed from a partial body).
    const onError = (): void => abort.abort();
    input.body.once('error', onError);
    try {
      const out = (await upload.done()) as { VersionId?: string };
      return { key: input.key, versionId: out.VersionId ?? null };
    } finally {
      clearTimeout(timer);
      input.body.off('error', onError);
    }
  }

  /** One small object (journal, scan snapshot). */
  async putBuffer(input: {
    key: string;
    body: Buffer;
    lock?: ObjectLockSpec | null;
  }): Promise<StoredVersion> {
    const out = await this.client.send(
      new PutObjectCommand({
        Bucket: this.buckets.archive,
        Key: input.key,
        Body: input.body,
        ContentType: ARCHIVE_OBJECT_CONTENT_TYPE,
        ...(input.lock
          ? { ObjectLockMode: s3Mode(input.lock.mode), ObjectLockRetainUntilDate: input.lock.until }
          : {}),
      }),
      this.signal(),
    );
    return { key: input.key, versionId: out.VersionId ?? null };
  }

  /** A readable body of an object (or one version); throws `isMissing` errors when gone. */
  async getStream(bucket: string, key: string, versionId?: string | null): Promise<Readable> {
    const out = await this.client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ...(versionId ? { VersionId: versionId } : {}),
      }),
      { abortSignal: AbortSignal.timeout(this.options.timeoutMs) },
    );
    const body = out.Body;
    if (!(body instanceof Readable)) throw new Error('S3 returned no stream');
    return body;
  }

  /** A whole (small) object version. */
  async getBuffer(bucket: string, key: string, versionId?: string | null): Promise<Buffer> {
    const stream = await this.getStream(bucket, key, versionId);
    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
    }
    return Buffer.concat(chunks);
  }

  /** The first `maxBytes` of an object (`Range`); `truncated` when it is larger (A5 step 4). */
  async readRange(
    bucket: string,
    key: string,
    maxBytes: number,
  ): Promise<{ bytes: Buffer; truncated: boolean }> {
    let out: { Body?: unknown; ContentRange?: string };
    try {
      out = await this.client.send(
        new GetObjectCommand({ Bucket: bucket, Key: key, Range: `bytes=0-${maxBytes - 1}` }),
        this.signal(),
      );
    } catch (error) {
      // An empty object answers 416 to a range request.
      if (statusOf(error) === 416) return { bytes: Buffer.alloc(0), truncated: false };
      throw error;
    }
    const body = out.Body;
    if (!(body instanceof Readable)) throw new Error('S3 returned no stream');
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      size += b.length;
      chunks.push(b);
      if (size >= maxBytes) {
        body.destroy();
        break;
      }
    }
    const total = /\/(\d+)$/.exec(out.ContentRange ?? '')?.[1];
    return {
      bytes: Buffer.concat(chunks).subarray(0, maxBytes),
      truncated: total !== undefined ? Number(total) > maxBytes : size > maxBytes,
    };
  }

  /** True when the object (or version) exists. */
  async exists(bucket: string, key: string, versionId?: string | null): Promise<boolean> {
    try {
      await this.client.send(
        new HeadObjectCommand({
          Bucket: bucket,
          Key: key,
          ...(versionId ? { VersionId: versionId } : {}),
        }),
        this.signal(),
      );
      return true;
    } catch (error) {
      if (isMissing(error)) return false;
      // A HEAD of a delete marker version answers 405.
      if (statusOf(error) === 405) return false;
      throw error;
    }
  }

  /** Deletes one version; `locked` when Object Lock refuses it (retried after its lock). */
  async deleteVersion(
    bucket: string,
    key: string,
    versionId: string,
    options: { bypassGovernance?: boolean } = {},
  ): Promise<DeleteVersionResult> {
    try {
      await this.client.send(
        new DeleteObjectCommand({
          Bucket: bucket,
          Key: key,
          VersionId: versionId,
          ...(options.bypassGovernance ? { BypassGovernanceRetention: true } : {}),
        }),
        this.signal(),
      );
      return 'deleted';
    } catch (error) {
      if (isMissing(error)) return 'missing';
      if (isLockRefusal(error)) return 'locked';
      throw error;
    }
  }

  /** Every version and delete marker under `prefix` (paged, in key order). */
  async *listVersions(bucket: string, prefix: string): AsyncGenerator<ListedVersion> {
    let keyMarker: string | undefined;
    let versionMarker: string | undefined;
    do {
      const page = await this.client.send(
        new ListObjectVersionsCommand({
          Bucket: bucket,
          Prefix: prefix,
          KeyMarker: keyMarker,
          VersionIdMarker: versionMarker,
          MaxKeys: 1_000,
        }),
        this.signal(),
      );
      for (const v of page.Versions ?? []) {
        if (v.Key === undefined || v.VersionId === undefined) continue;
        yield {
          key: v.Key,
          versionId: v.VersionId,
          lastModified: v.LastModified ?? null,
          deleteMarker: false,
        };
      }
      for (const m of page.DeleteMarkers ?? []) {
        if (m.Key === undefined || m.VersionId === undefined) continue;
        yield {
          key: m.Key,
          versionId: m.VersionId,
          lastModified: m.LastModified ?? null,
          deleteMarker: true,
        };
      }
      keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
      versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
    } while (keyMarker !== undefined);
  }

  /** Extends (never shortens) the retention of one version (A10). */
  async putRetention(
    bucket: string,
    key: string,
    versionId: string | null,
    lock: ObjectLockSpec,
    options: { bypassGovernance?: boolean } = {},
  ): Promise<void> {
    await this.client.send(
      new PutObjectRetentionCommand({
        Bucket: bucket,
        Key: key,
        ...(versionId ? { VersionId: versionId } : {}),
        Retention: { Mode: s3Mode(lock.mode), RetainUntilDate: lock.until },
        ...(options.bypassGovernance ? { BypassGovernanceRetention: true } : {}),
      }),
      this.signal(),
    );
  }

  /** The retention of one version (null when none). */
  async getRetention(
    bucket: string,
    key: string,
    versionId: string | null,
  ): Promise<{ mode: 'governance' | 'compliance'; until: Date } | null> {
    try {
      const out = await this.client.send(
        new GetObjectRetentionCommand({
          Bucket: bucket,
          Key: key,
          ...(versionId ? { VersionId: versionId } : {}),
        }),
        this.signal(),
      );
      const mode = out.Retention?.Mode;
      const until = out.Retention?.RetainUntilDate;
      if ((mode !== 'GOVERNANCE' && mode !== 'COMPLIANCE') || !(until instanceof Date)) return null;
      return { mode: mode === 'COMPLIANCE' ? 'compliance' : 'governance', until };
    } catch (error) {
      if (isMissing(error)) return null;
      if (nameOf(error) === 'NoSuchObjectLockConfiguration') return null;
      throw error;
    }
  }
}

/** The Object Lock availability of the archive bucket, probed once at start (A10). */
export class ObjectLockState {
  private value: boolean | null = null;

  constructor(private readonly mode: 'auto' | 'disabled') {}

  /** null before the probe ran; false when disabled by configuration. */
  get available(): boolean | null {
    return this.mode === 'disabled' ? false : this.value;
  }

  get probed(): boolean {
    return this.mode === 'disabled' || this.value !== null;
  }

  set(available: boolean): void {
    this.value = available;
  }
}
