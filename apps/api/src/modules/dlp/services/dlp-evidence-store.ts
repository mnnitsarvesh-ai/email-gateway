import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { Injectable } from '@nestjs/common';
import { S3Service } from '@email-gateway/common';

/** The S3 commands the store needs, as `@aws-sdk/client-s3` defines them. */
interface S3Commands {
  GetObjectCommand: new (input: { Bucket: string; Key: string }) => object;
  DeleteObjectCommand: new (input: { Bucket: string; Key: string }) => object;
}

/**
 * `@aws-sdk/client-s3` is a dependency of `@email-gateway/common` (whose `S3Service` owns the
 * client), not of the api package; the command classes are resolved from there (as EmlStore).
 */
function s3Commands(): S3Commands {
  const fromCommon = createRequire(require.resolve('@email-gateway/common'));
  return fromCommon('@aws-sdk/client-s3') as S3Commands;
}

/** Why an evidence object could not be read (`read_failed` reasons, D16). */
export type EvidenceObjectFailure = 'foreign_key' | 'not_found' | 'too_large' | 'no_stream';

export class EvidenceObjectError extends Error {
  constructor(readonly why: EvidenceObjectFailure) {
    super(`DLP evidence object unavailable (${why})`);
    this.name = 'EvidenceObjectError';
  }
}

/** Largest object the api reads (the evidence JSON is ≤ 32 KiB plus the envelope, D16). */
export const EVIDENCE_OBJECT_MAX_BYTES = 256 * 1024;

const isNoSuchKey = (error: unknown): boolean => {
  const e = error as { name?: unknown; Code?: unknown; $metadata?: { httpStatusCode?: number } };
  return e.name === 'NoSuchKey' || e.Code === 'NoSuchKey' || e.$metadata?.httpStatusCode === 404;
};

/** `org/<org>/dlp-evidence/…` without empty, `.` or `..` segments (D16, D19). */
export function isEvidenceKeyOf(key: string, organizationId: bigint): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/dlp-evidence/`) &&
    !key.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
  );
}

/**
 * The DLP evidence objects in the mail bucket (step 4.5 D16): bounded reads of a ciphertext
 * object and idempotent deletes (a missing object is success), only under the organization's
 * `org/<org>/dlp-evidence/` prefix. Never logs keys or content.
 */
@Injectable()
export class DlpEvidenceStore {
  private commands: S3Commands | undefined;

  constructor(private readonly s3: S3Service) {}

  private get cmd(): S3Commands {
    this.commands ??= s3Commands();
    return this.commands;
  }

  async read(organizationId: bigint, key: string): Promise<Buffer> {
    if (!isEvidenceKeyOf(key, organizationId)) throw new EvidenceObjectError('foreign_key');
    let result: { Body?: unknown; ContentLength?: number };
    try {
      result = (await this.s3.client.send(
        new this.cmd.GetObjectCommand({ Bucket: this.s3.mailBucket, Key: key }) as never,
      )) as { Body?: unknown; ContentLength?: number };
    } catch (error) {
      if (isNoSuchKey(error)) throw new EvidenceObjectError('not_found');
      throw error;
    }
    const body = result.Body;
    if (!(body instanceof Readable)) throw new EvidenceObjectError('no_stream');
    if (
      typeof result.ContentLength === 'number' &&
      result.ContentLength > EVIDENCE_OBJECT_MAX_BYTES
    ) {
      body.destroy();
      throw new EvidenceObjectError('too_large');
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      size += buffer.length;
      if (size > EVIDENCE_OBJECT_MAX_BYTES) {
        body.destroy();
        throw new EvidenceObjectError('too_large');
      }
      chunks.push(buffer);
    }
    return Buffer.concat(chunks);
  }

  /** Deletes one evidence object; a missing object is success. Refuses keys outside the prefix. */
  async delete(organizationId: bigint, key: string): Promise<void> {
    if (!isEvidenceKeyOf(key, organizationId)) throw new EvidenceObjectError('foreign_key');
    try {
      await this.s3.client.send(
        new this.cmd.DeleteObjectCommand({ Bucket: this.s3.mailBucket, Key: key }) as never,
      );
    } catch (error) {
      if (!isNoSuchKey(error)) throw error;
    }
  }
}
