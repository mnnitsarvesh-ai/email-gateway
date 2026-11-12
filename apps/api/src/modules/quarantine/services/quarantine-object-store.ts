import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { Injectable } from '@nestjs/common';
import { S3Service } from '@email-gateway/common';

interface S3Commands {
  GetObjectCommand: new (input: { Bucket: string; Key: string; Range?: string }) => object;
  HeadObjectCommand: new (input: { Bucket: string; Key: string }) => object;
}

/** The command classes of the SDK `@email-gateway/common` owns (as EmlStore, DlpEvidenceStore). */
function s3Commands(): S3Commands {
  const fromCommon = createRequire(require.resolve('@email-gateway/common'));
  return fromCommon('@aws-sdk/client-s3') as S3Commands;
}

/** Why an object could not be served (reason codes only). */
export type ObjectFailure = 'foreign_key' | 'not_found' | 'no_stream' | 'too_large';

export class QuarantineObjectError extends Error {
  constructor(readonly why: ObjectFailure) {
    super(`quarantine object unavailable (${why})`);
    this.name = 'QuarantineObjectError';
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

/** A key under `org/<org>/<prefix>` without empty, `.` or `..` segments. */
export function isKeyOf(key: string, organizationId: bigint, prefix = ''): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/${prefix}`) &&
    !key.split('/').some((s) => s === '' || s === '.' || s === '..')
  );
}

/**
 * The quarantine's view of the mail bucket (step 5.3 Q7, Q11, Q12): bounded Range reads of
 * decoded parts (`org/<org>/part/…`, never the raw EML), presence checks of the EML and streams
 * of a downloadable object. Every key is checked against the organization's prefix first; keys
 * and bytes are never logged. The api never hands out an S3 URL (§2.0 invariant 2).
 */
@Injectable()
export class QuarantineObjectStore {
  private commands: S3Commands | undefined;

  constructor(private readonly s3: S3Service) {}

  private get cmd(): S3Commands {
    this.commands ??= s3Commands();
    return this.commands;
  }

  /**
   * The first `maxBytes` of a decoded part (`Range: bytes=0-(maxBytes-1)`); `truncated` when the
   * object is larger. Only under `org/<org>/part/`.
   */
  async readPart(
    organizationId: bigint,
    key: string,
    maxBytes: number,
  ): Promise<{ bytes: Buffer; truncated: boolean }> {
    if (!isKeyOf(key, organizationId, 'part/')) throw new QuarantineObjectError('foreign_key');
    let result: { Body?: unknown; ContentRange?: string; ContentLength?: number };
    try {
      result = (await this.s3.client.send(
        new this.cmd.GetObjectCommand({
          Bucket: this.s3.mailBucket,
          Key: key,
          Range: `bytes=0-${maxBytes - 1}`,
        }) as never,
      )) as typeof result;
    } catch (error) {
      if (isNoSuchKey(error)) throw new QuarantineObjectError('not_found');
      // An empty object answers 416 to a range request.
      if (
        (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 416
      ) {
        return { bytes: Buffer.alloc(0), truncated: false };
      }
      throw error;
    }
    const body = result.Body;
    if (!(body instanceof Readable)) throw new QuarantineObjectError('no_stream');
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      size += buffer.length;
      chunks.push(buffer);
      if (size >= maxBytes) {
        body.destroy();
        break;
      }
    }
    const bytes = Buffer.concat(chunks).subarray(0, maxBytes);
    const total = /\/(\d+)$/.exec(result.ContentRange ?? '')?.[1];
    const truncated = total !== undefined ? Number(total) > maxBytes : size > maxBytes;
    return { bytes, truncated };
  }

  /** True when the object exists (HEAD); keys outside the organization's prefix are refused. */
  async exists(organizationId: bigint, key: string): Promise<boolean> {
    if (!isKeyOf(key, organizationId)) throw new QuarantineObjectError('foreign_key');
    try {
      await this.s3.client.send(
        new this.cmd.HeadObjectCommand({ Bucket: this.s3.mailBucket, Key: key }) as never,
      );
      return true;
    } catch (error) {
      if (isNoSuchKey(error)) return false;
      throw error;
    }
  }

  /** A stream of the object (download door), refused above `maxBytes`. */
  async open(
    organizationId: bigint,
    key: string,
    prefix: '' | 'part/',
    maxBytes: number,
  ): Promise<{ body: Readable; sizeBytes: number }> {
    if (!isKeyOf(key, organizationId, prefix)) throw new QuarantineObjectError('foreign_key');
    let result: { Body?: unknown; ContentLength?: number };
    try {
      result = (await this.s3.client.send(
        new this.cmd.GetObjectCommand({ Bucket: this.s3.mailBucket, Key: key }) as never,
      )) as typeof result;
    } catch (error) {
      if (isNoSuchKey(error)) throw new QuarantineObjectError('not_found');
      throw error;
    }
    const body = result.Body;
    if (!(body instanceof Readable) || typeof result.ContentLength !== 'number') {
      if (body instanceof Readable) body.destroy();
      throw new QuarantineObjectError('no_stream');
    }
    if (result.ContentLength > maxBytes) {
      body.destroy();
      throw new QuarantineObjectError('too_large');
    }
    return { body, sizeBytes: result.ContentLength };
  }
}
