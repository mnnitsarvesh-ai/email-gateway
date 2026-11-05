import type { S3Client } from '@aws-sdk/client-s3';
import { createHash } from 'node:crypto';
import { EML_MISSING, S3EmlSource } from '../../../mime-ingestion/eml-source';

/**
 * Full, bounded reads of attachment part objects (step 4.2 A3 d): `GetObject` of the row's key
 * with SCAN_S3_TIMEOUT_MS per wait into one Buffer of at most `sizeBytes + 1` bytes. The bytes
 * live in memory only (never written anywhere, §2.0 invariant 2).
 */
export type PartRead =
  | { kind: 'ok'; bytes: Buffer }
  /** `NoSuchKey`: not retryable (`part_unavailable`). */
  | { kind: 'missing' }
  /** More bytes than the row says, or another SHA-256: not retryable (`part_integrity`). */
  | { kind: 'integrity' };

export interface PartSource {
  read(key: string, sizeBytes: number, sha256: string, signal: AbortSignal): Promise<PartRead>;
}

export class S3PartReader implements PartSource {
  private readonly source: S3EmlSource;

  constructor(client: S3Client, bucket: string, timeoutMs: number) {
    this.source = new S3EmlSource(client, bucket, timeoutMs);
  }

  /** Other S3 failures are thrown (infrastructure, transient: no attempt consumed). */
  async read(
    key: string,
    sizeBytes: number,
    sha256: string,
    signal: AbortSignal,
  ): Promise<PartRead> {
    const opened = await this.source.open(key, signal);
    if (opened === EML_MISSING) return { kind: 'missing' };
    const limit = sizeBytes + 1;
    const chunks: Buffer[] = [];
    let total = 0;
    const hash = createHash('sha256');
    try {
      for await (const chunk of opened as AsyncIterable<Buffer>) {
        total += chunk.length;
        if (total > limit) return { kind: 'integrity' };
        hash.update(chunk);
        chunks.push(chunk);
      }
    } finally {
      if (!opened.destroyed) opened.destroy();
    }
    if (total !== sizeBytes || hash.digest('hex') !== sha256) return { kind: 'integrity' };
    return { kind: 'ok', bytes: chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, total) };
  }
}
