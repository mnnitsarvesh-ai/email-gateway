import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { Injectable } from '@nestjs/common';
import { S3Service } from '@email-gateway/common';
import { REPORT_CONTENT_TYPE, REPORT_OBJECT_PREFIX } from '../../assistant.constants';

/** The S3 commands the store needs, as `@aws-sdk/client-s3` defines them. */
interface S3Commands {
  PutObjectCommand: new (input: {
    Bucket: string;
    Key: string;
    Body: Buffer;
    ContentType: string;
    ChecksumSHA256: string;
  }) => object;
  GetObjectCommand: new (input: { Bucket: string; Key: string }) => object;
  DeleteObjectCommand: new (input: { Bucket: string; Key: string; VersionId?: string }) => object;
  ListObjectVersionsCommand: new (input: {
    Bucket: string;
    Prefix: string;
    KeyMarker?: string;
    VersionIdMarker?: string;
  }) => object;
}

/** The part of a `ListObjectVersions` answer the store reads. */
interface VersionPage {
  Versions?: Array<{ Key?: string; VersionId?: string }>;
  DeleteMarkers?: Array<{ Key?: string; VersionId?: string }>;
  IsTruncated?: boolean;
  NextKeyMarker?: string;
  NextVersionIdMarker?: string;
}

/**
 * `@aws-sdk/client-s3` is a dependency of `@email-gateway/common` (whose `S3Service` owns the
 * client), not of the api package; the command classes are resolved from there (as the
 * quarantine object store and DLP evidence store do).
 */
function s3Commands(): S3Commands {
  const fromCommon = createRequire(require.resolve('@email-gateway/common'));
  return fromCommon('@aws-sdk/client-s3') as S3Commands;
}

/** Why a report object could not be read (reason codes only). */
export type ReportObjectFailure =
  'foreign_key' | 'not_found' | 'no_stream' | 'too_large' | 'integrity';

export class ReportObjectError extends Error {
  constructor(readonly why: ReportObjectFailure) {
    super(`assistant report object unavailable (${why})`);
    this.name = 'ReportObjectError';
  }
}

const isNoSuchKey = (error: unknown): boolean => {
  const e = error as { name?: unknown; Code?: unknown; $metadata?: { httpStatusCode?: number } };
  return (
    e.name === 'NoSuchKey' ||
    e.name === 'NotFound' ||
    e.Code === 'NoSuchKey' ||
    e.$metadata?.httpStatusCode === 404
  );
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** `org/<org>/assistant/report/…` without empty, `.` or `..` segments (D6). */
export function isReportKeyOf(key: string, organizationId: bigint): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/${REPORT_OBJECT_PREFIX}`) &&
    !key.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
  );
}

/**
 * The object key of a report (D6): `org/<organizationId>/assistant/report/<yyyy>/<mm>/<dd>/
 * <reportPublicId>.html` with the UTC date of generation and the internal organization id (as
 * every mail-bucket key). Never returned to a client, never logged.
 */
export function reportObjectKey(
  organizationId: bigint,
  reportPublicId: string,
  generatedAt: Date,
): string {
  if (!UUID.test(reportPublicId)) throw new Error('report object key: not a lower-case UUID');
  const iso = generatedAt.toISOString();
  const [yyyy, mm, dd] = [iso.slice(0, 4), iso.slice(5, 7), iso.slice(8, 10)];
  return `org/${organizationId.toString()}/${REPORT_OBJECT_PREFIX}${yyyy}/${mm}/${dd}/${reportPublicId}.html`;
}

export const sha256Hex = (bytes: Buffer): string =>
  createHash('sha256').update(bytes).digest('hex');

/**
 * The assistant's report objects in the mail bucket (step AI-R D6, ADR-0095): `put` with the
 * content type `text/html; charset=utf-8` and the SHA-256 checksum the store verifies, a bounded
 * `get` (at most `maxBytes`, SHA-256 compared with the row's), and an idempotent `delete` of
 * every version of the key (a missing object counts as deleted). Every key is checked against the organization's
 * `org/<org>/assistant/report/` prefix before any request. Keys and bytes are never logged.
 */
@Injectable()
export class ReportObjectStore {
  private commands: S3Commands | undefined;

  constructor(private readonly s3: S3Service) {}

  private get cmd(): S3Commands {
    this.commands ??= s3Commands();
    return this.commands;
  }

  async put(organizationId: bigint, key: string, bytes: Buffer, sha256: string): Promise<void> {
    if (!isReportKeyOf(key, organizationId)) throw new ReportObjectError('foreign_key');
    await this.s3.client.send(
      new this.cmd.PutObjectCommand({
        Bucket: this.s3.mailBucket,
        Key: key,
        Body: bytes,
        ContentType: REPORT_CONTENT_TYPE,
        ChecksumSHA256: Buffer.from(sha256, 'hex').toString('base64'),
      }) as never,
    );
  }

  /**
   * The stored HTML, read as a stream bounded by `maxBytes + 1`; `too_large` beyond `maxBytes`,
   * `integrity` when its SHA-256 is not `sha256`.
   */
  async get(
    organizationId: bigint,
    key: string,
    maxBytes: number,
    sha256: string,
  ): Promise<Buffer> {
    if (!isReportKeyOf(key, organizationId)) throw new ReportObjectError('foreign_key');
    let result: { Body?: unknown; ContentLength?: number };
    try {
      result = (await this.s3.client.send(
        new this.cmd.GetObjectCommand({ Bucket: this.s3.mailBucket, Key: key }) as never,
      )) as { Body?: unknown; ContentLength?: number };
    } catch (error) {
      if (isNoSuchKey(error)) throw new ReportObjectError('not_found');
      throw error;
    }
    const body = result.Body;
    if (!(body instanceof Readable)) throw new ReportObjectError('no_stream');
    if (typeof result.ContentLength === 'number' && result.ContentLength > maxBytes) {
      body.destroy();
      throw new ReportObjectError('too_large');
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      size += buffer.length;
      if (size > maxBytes) {
        body.destroy();
        throw new ReportObjectError('too_large');
      }
      chunks.push(buffer);
    }
    const bytes = Buffer.concat(chunks);
    if (sha256Hex(bytes) !== sha256.toLowerCase()) throw new ReportObjectError('integrity');
    return bytes;
  }

  /**
   * Deletes one report object for good (D7): the mail bucket is versioned, so a plain delete
   * would only add a delete marker and leave the HTML as a noncurrent version that no lifecycle
   * rule expires. Every version and delete marker of exactly this key is listed
   * (`ListObjectVersions`, prefix = key, paged) and deleted by `VersionId`; returns how many were
   * removed. A missing object (no version left) is success; other errors propagate so the caller
   * retries.
   */
  async delete(organizationId: bigint, key: string): Promise<number> {
    if (!isReportKeyOf(key, organizationId)) throw new ReportObjectError('foreign_key');
    let removed = 0;
    let keyMarker: string | undefined;
    let versionMarker: string | undefined;
    for (;;) {
      let page: VersionPage;
      try {
        page = (await this.s3.client.send(
          new this.cmd.ListObjectVersionsCommand({
            Bucket: this.s3.mailBucket,
            Prefix: key,
            ...(keyMarker !== undefined && { KeyMarker: keyMarker }),
            ...(versionMarker !== undefined && { VersionIdMarker: versionMarker }),
          }) as never,
        )) as VersionPage;
      } catch (error) {
        if (isNoSuchKey(error)) return removed;
        throw error;
      }
      for (const entry of [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]) {
        // The prefix also matches longer keys; only this exact key is deleted.
        if (entry.Key !== key) continue;
        try {
          await this.s3.client.send(
            new this.cmd.DeleteObjectCommand({
              Bucket: this.s3.mailBucket,
              Key: key,
              ...(entry.VersionId !== undefined && { VersionId: entry.VersionId }),
            }) as never,
          );
        } catch (error) {
          if (!isNoSuchKey(error)) throw error;
        }
        removed += 1;
      }
      if (page.IsTruncated !== true || page.NextKeyMarker === undefined) return removed;
      keyMarker = page.NextKeyMarker;
      versionMarker = page.NextVersionIdMarker;
    }
  }
}
