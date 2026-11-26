import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import type { S3Service } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { InconsistentNotificationReadError } from './notification-reads';

type Tx = Prisma.TransactionClient;

/** The prefix of every stored assistant report under its organization (step AI-R D6). */
export const REPORT_KEY_PREFIX = 'assistant/report/';

/**
 * True for `org/<organizationId>/assistant/report/…` without empty, `.` or `..` segments (the
 * `isKeyOf` rule of the api's object stores, D6). Any other key is never read.
 */
export function isReportKeyOf(key: string, organizationId: bigint): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/${REPORT_KEY_PREFIX}`) &&
    !key.split('/').some((s) => s === '' || s === '.' || s === '..')
  );
}

/** The delivery, its report and the organization name, as the handler needs them. */
export interface ReportDeliveryRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  status: 'queued' | 'sent' | 'failed';
  /** Normalized address; NULL after the conversation's content purge (D7). */
  recipientAddress: string | null;
  organizationName: string;
  report: {
    id: bigint;
    publicId: string;
    status: 'queued' | 'pending' | 'available' | 'failed' | 'purged';
    title: string;
    periodFrom: Date;
    periodTo: Date;
    figures: unknown;
    objectKey: string | null;
    sizeBytes: number | null;
    sha256: string | null;
    createdAt: Date;
  };
}

/**
 * The writer reads and the status writes of the assistant report emails (step AI-R D8), inside
 * the consumer's idempotency transaction, every statement scoped to the envelope's organization
 * and echo-checked (4.2 §6): a delivery of another organization is never returned, read or
 * updated. Writes only the delivery's status columns, and only while it is `queued`.
 */
export class AssistantReportReads {
  async delivery(
    tx: Tx,
    organizationId: bigint,
    deliveryPublicId: string,
  ): Promise<ReportDeliveryRow | null> {
    const row = await tx.aiChatReportDelivery.findFirst({
      where: { publicId: deliveryPublicId, organizationId },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        status: true,
        recipientAddress: true,
        organization: { select: { id: true, name: true } },
        report: {
          select: {
            id: true,
            publicId: true,
            organizationId: true,
            status: true,
            title: true,
            periodFrom: true,
            periodTo: true,
            figures: true,
            objectKey: true,
            sizeBytes: true,
            sha256: true,
            createdAt: true,
          },
        },
      },
    });
    if (row === null) return null;
    if (
      row.organizationId !== organizationId ||
      row.organization.id !== organizationId ||
      row.report.organizationId !== organizationId
    ) {
      throw new InconsistentNotificationReadError('assistant_report_delivery');
    }
    const { organizationId: _reportOrg, ...report } = row.report;
    return {
      id: row.id,
      publicId: row.publicId,
      organizationId: row.organizationId,
      status: row.status,
      recipientAddress: row.recipientAddress,
      organizationName: row.organization.name,
      report,
    };
  }

  /** `queued → failed` with the reason code; false when the row was no longer `queued`. */
  async markFailed(
    tx: Tx,
    organizationId: bigint,
    deliveryId: bigint,
    errorCode: string,
  ): Promise<boolean> {
    const { count } = await tx.aiChatReportDelivery.updateMany({
      where: { id: deliveryId, organizationId, status: 'queued' },
      data: { status: 'failed', errorCode },
    });
    return count === 1;
  }

  /** `queued → sent` with the time and the Message-ID; false when no longer `queued`. */
  async markSent(
    tx: Tx,
    organizationId: bigint,
    deliveryId: bigint,
    messageId: string,
    sentAt: Date,
  ): Promise<boolean> {
    const { count } = await tx.aiChatReportDelivery.updateMany({
      where: { id: deliveryId, organizationId, status: 'queued' },
      data: { status: 'sent', sentAt, messageId, errorCode: null },
    });
    return count === 1;
  }
}

/** Outcome of a report object read: the bytes, or why they cannot be mailed. */
export type ReportObjectRead =
  | { kind: 'ok'; bytes: Buffer }
  | { kind: 'missing' }
  | { kind: 'foreign_key' }
  | { kind: 'too_large' }
  | { kind: 'sha_mismatch' };

/** Reads the stored report HTML (as `ReportObjectStore.get`, D6). */
export interface ReportObjectReader {
  read(
    organizationId: bigint,
    key: string,
    expected: { sizeBytes: number; sha256: string },
    maxBytes: number,
  ): Promise<ReportObjectRead>;
}

interface S3Commands {
  GetObjectCommand: new (input: { Bucket: string; Key: string; Range?: string }) => object;
}

/** The command classes of the SDK `@email-gateway/common` owns (as the api's object stores). */
function s3Commands(): S3Commands {
  const fromCommon = createRequire(require.resolve('@email-gateway/common'));
  return fromCommon('@aws-sdk/client-s3') as S3Commands;
}

const httpStatusOf = (error: unknown): number | undefined =>
  (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;

const isNoSuchKey = (error: unknown): boolean => {
  const e = error as { name?: unknown; Code?: unknown };
  return (
    e.name === 'NoSuchKey' ||
    e.name === 'NotFound' ||
    e.Code === 'NoSuchKey' ||
    httpStatusOf(error) === 404
  );
};

/**
 * The mail-bucket reader of the report emails: the key is checked against
 * `org/<organizationId>/assistant/report/` first; the read is a `Range` request for at most
 * `maxBytes + 1` bytes and the stream is cut there (a larger object is `too_large`, never
 * buffered whole); the bytes must have exactly the row's size and SHA-256. Keys and bytes are
 * never logged. Other S3 errors propagate (the consumer retries the event).
 */
export class S3ReportObjectReader implements ReportObjectReader {
  private commands: S3Commands | undefined;

  constructor(private readonly s3: Pick<S3Service, 'client' | 'mailBucket'>) {}

  private get cmd(): S3Commands {
    this.commands ??= s3Commands();
    return this.commands;
  }

  async read(
    organizationId: bigint,
    key: string,
    expected: { sizeBytes: number; sha256: string },
    maxBytes: number,
  ): Promise<ReportObjectRead> {
    if (!isReportKeyOf(key, organizationId)) return { kind: 'foreign_key' };
    const limit = Math.min(expected.sizeBytes, maxBytes);
    let result: { Body?: unknown };
    try {
      result = (await this.s3.client.send(
        new this.cmd.GetObjectCommand({
          Bucket: this.s3.mailBucket,
          Key: key,
          Range: `bytes=0-${String(limit)}`,
        }) as never,
      )) as typeof result;
    } catch (error) {
      if (isNoSuchKey(error)) return { kind: 'missing' };
      // An empty object answers 416 to a range request: it cannot match a stored report.
      if (httpStatusOf(error) === 416) return { kind: 'sha_mismatch' };
      throw error;
    }
    const body = result.Body;
    if (!(body instanceof Readable)) return { kind: 'missing' };
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      size += buffer.length;
      chunks.push(buffer);
      if (size > limit) {
        body.destroy();
        break;
      }
    }
    if (size > limit) return { kind: 'too_large' };
    const bytes = Buffer.concat(chunks);
    if (bytes.length !== expected.sizeBytes) return { kind: 'sha_mismatch' };
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (sha256 !== expected.sha256.toLowerCase()) return { kind: 'sha_mismatch' };
    return { kind: 'ok', bytes };
  }
}
