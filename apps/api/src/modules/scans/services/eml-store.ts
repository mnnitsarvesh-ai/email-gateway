import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { Injectable } from '@nestjs/common';
import { S3Service } from '@email-gateway/common';

/** The S3 command the store needs, as `@aws-sdk/client-s3` defines it. */
type GetObjectCommandClass = new (input: { Bucket: string; Key: string }) => object;

/**
 * `@aws-sdk/client-s3` is a dependency of `@email-gateway/common` (whose `S3Service` owns the
 * client), not of the api package; the command class is resolved from there so the api uses the
 * same SDK instance as the client it sends it with.
 */
function getObjectCommand(): GetObjectCommandClass {
  const fromCommon = createRequire(require.resolve('@email-gateway/common'));
  return (fromCommon('@aws-sdk/client-s3') as { GetObjectCommand: GetObjectCommandClass })
    .GetObjectCommand;
}

/** The EML object is missing (expired, deleted) or outside the organization's prefix. */
export class EmlUnavailableError extends Error {
  constructor(readonly why: 'not_found' | 'foreign_key' | 'no_stream') {
    super(`EML unavailable (${why})`);
    this.name = 'EmlUnavailableError';
  }
}

export interface OpenedEml {
  body: Readable;
  sizeBytes: number;
}

function isNoSuchKey(error: unknown): boolean {
  const e = error as { name?: unknown; Code?: unknown; $metadata?: { httpStatusCode?: number } };
  return e.name === 'NoSuchKey' || e.Code === 'NoSuchKey' || e.$metadata?.httpStatusCode === 404;
}

/**
 * Opens a message's EML in the mail bucket as a stream (never buffered whole; §2.0 invariant
 * 2), after checking that the key is under `org/<organizationId>/` (invariant 5). The size comes
 * from S3 (`ContentLength`), so the stream can be sent with an exact Content-Length.
 */
@Injectable()
export class EmlStore {
  private command: GetObjectCommandClass | undefined;

  constructor(private readonly s3: S3Service) {}

  async open(organizationId: bigint, key: string, signal?: AbortSignal): Promise<OpenedEml> {
    if (!key.startsWith(`org/${organizationId.toString()}/`)) {
      throw new EmlUnavailableError('foreign_key');
    }
    this.command ??= getObjectCommand();
    let result: { Body?: unknown; ContentLength?: number };
    try {
      result = (await this.s3.client.send(
        new this.command({ Bucket: this.s3.mailBucket, Key: key }) as never,
        signal ? { abortSignal: signal } : {},
      )) as { Body?: unknown; ContentLength?: number };
    } catch (error) {
      if (isNoSuchKey(error)) throw new EmlUnavailableError('not_found');
      throw error;
    }
    const body = result.Body;
    if (!(body instanceof Readable) || typeof result.ContentLength !== 'number') {
      if (body instanceof Readable) body.destroy();
      throw new EmlUnavailableError('no_stream');
    }
    return { body, sizeBytes: result.ContentLength };
  }
}
