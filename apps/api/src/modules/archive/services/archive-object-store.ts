import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { isKeyOfOrganization } from '@email-gateway/archive';
import { S3Service } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import type { ArchiveConfig } from '../archive.constants';

interface S3Commands {
  GetObjectCommand: new (input: { Bucket: string; Key: string; VersionId?: string }) => object;
  GetObjectLockConfigurationCommand: new (input: { Bucket: string }) => object;
}

/** The command classes of the SDK `@email-gateway/common` owns (QuarantineObjectStore pattern). */
function s3Commands(): S3Commands {
  const fromCommon = createRequire(require.resolve('@email-gateway/common'));
  return fromCommon('@aws-sdk/client-s3') as S3Commands;
}

/** Why an archive object could not be read (codes only; keys and bytes are never logged). */
export type ArchiveObjectFailure = 'foreign_key' | 'not_found' | 'no_stream' | 'too_large';

export class ArchiveObjectError extends Error {
  override readonly name = 'ArchiveObjectError';
  constructor(readonly why: ArchiveObjectFailure) {
    super(`archive object unavailable (${why})`);
  }
}

const isNotFound = (error: unknown): boolean => {
  const e = error as { name?: unknown; Code?: unknown; $metadata?: { httpStatusCode?: number } };
  return (
    e.name === 'NoSuchKey' ||
    e.name === 'NotFound' ||
    e.name === 'NoSuchVersion' ||
    e.Code === 'NoSuchKey' ||
    e.$metadata?.httpStatusCode === 404
  );
};

/** How long the Object Lock probe result is reused (A10: "probed at start, cached"). */
const LOCK_PROBE_TTL_MS = 10 * 60_000;

/**
 * The api's read-only view of the archive bucket (step 8.1 A10, A19, §4.8 IAM: `GetObject`,
 * `GetObjectVersion`, `GetBucketObjectLockConfiguration`). Every key must start with
 * `org/<organizationId>/archive/` (records) or `org/<organizationId>/exports/` (exports) of the
 * row being read (invariant 2); objects are read by their recorded version id. The api never
 * writes, deletes or lists archive objects and never hands out an S3 URL.
 */
@Injectable()
export class ArchiveObjectStore {
  private readonly logger = new Logger(ArchiveObjectStore.name);
  private commands: S3Commands | undefined;
  private lockProbe: { available: boolean; at: number } | null = null;

  constructor(
    private readonly s3: S3Service,
    @Inject(API_CONFIG) private readonly config: Pick<ArchiveConfig, 'ARCHIVE_OBJECT_LOCK'>,
  ) {}

  private get cmd(): S3Commands {
    this.commands ??= s3Commands();
    return this.commands;
  }

  /** A stream of one object version (refused above `maxBytes` and outside the organization). */
  async open(
    organizationId: bigint,
    area: 'archive' | 'exports',
    key: string,
    versionId: string | null,
    maxBytes: number,
  ): Promise<{ body: Readable; sizeBytes: number }> {
    if (!isKeyOfOrganization(key, organizationId, area)) {
      throw new ArchiveObjectError('foreign_key');
    }
    let result: { Body?: unknown; ContentLength?: number };
    try {
      result = (await this.s3.client.send(
        new this.cmd.GetObjectCommand({
          Bucket: this.s3.archiveBucket,
          Key: key,
          ...(versionId !== null && { VersionId: versionId }),
        }) as never,
      )) as typeof result;
    } catch (error) {
      if (isNotFound(error)) throw new ArchiveObjectError('not_found');
      throw error;
    }
    const body = result.Body;
    if (!(body instanceof Readable) || typeof result.ContentLength !== 'number') {
      if (body instanceof Readable) body.destroy();
      throw new ArchiveObjectError('no_stream');
    }
    if (result.ContentLength > maxBytes) {
      body.destroy();
      throw new ArchiveObjectError('too_large');
    }
    return { body, sizeBytes: result.ContentLength };
  }

  /** The whole object version as a buffer (small objects: journal reports, scan snapshots). */
  async read(
    organizationId: bigint,
    key: string,
    versionId: string | null,
    maxBytes: number,
  ): Promise<Buffer> {
    const { body } = await this.open(organizationId, 'archive', key, versionId, maxBytes);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      size += buffer.length;
      if (size > maxBytes) {
        body.destroy();
        throw new ArchiveObjectError('too_large');
      }
      chunks.push(buffer);
    }
    return Buffer.concat(chunks);
  }

  /**
   * Whether the archive bucket has Object Lock enabled (`GetObjectLockConfiguration`, cached;
   * `ARCHIVE_OBJECT_LOCK=disabled` → false without probing). A failed probe counts as
   * unavailable (the honest fallback of A10) and is retried after the cache period.
   */
  async objectLockAvailable(now = Date.now()): Promise<boolean> {
    if (this.config.ARCHIVE_OBJECT_LOCK === 'disabled') return false;
    if (this.lockProbe !== null && now - this.lockProbe.at < LOCK_PROBE_TTL_MS) {
      return this.lockProbe.available;
    }
    let available = false;
    try {
      const result = (await this.s3.client.send(
        new this.cmd.GetObjectLockConfigurationCommand({ Bucket: this.s3.archiveBucket }) as never,
      )) as { ObjectLockConfiguration?: { ObjectLockEnabled?: string } };
      available = result.ObjectLockConfiguration?.ObjectLockEnabled === 'Enabled';
    } catch (error) {
      const name = (error as { name?: unknown }).name;
      this.logger.warn({
        message: 'archive Object Lock probe failed: treated as unavailable',
        error: typeof name === 'string' ? name : 'unknown',
      });
    }
    this.lockProbe = { available, at: now };
    return available;
  }
}
