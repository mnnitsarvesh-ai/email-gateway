import { createHash } from 'node:crypto';
import { isUniqueViolation, uuidv7, withTransactionDefaults } from '@email-gateway/common';
import type { ApiCopyDirection, Prisma, PrismaClient } from '@email-gateway/database';
import { EventTypes, messageReceivedV1 } from '@email-gateway/event-contracts';
import { initialLifecycle, writeInitialHistory } from '@email-gateway/message-lifecycle';
import { MESSAGE_AGGREGATE_TYPE, SOURCE_SERVICE } from '../feeds/mailbox-copy.repository';
import { TX_MAX_WAIT_MS, TX_TIMEOUT_MS } from '../shared/db';

const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/** C10.4 / §5: the ingest key of a report original — `v2:rpt:` + SHA-256(report public id). */
export function reportIngestKey(reportPublicId: string): string {
  return `v2:rpt:${sha256Hex(reportPublicId)}`;
}

/**
 * The mail-bucket key of a report original (the smtp-adapter's layout):
 * `org/<organizationId>/eml/<yyyy>/<mm>/<dd>/<ref>.eml`, `ref` = the first 32 hex characters of
 * SHA-256(`rpt|<reportPublicId>|<organizationId>`) — deterministic, so a retried ingest overwrites
 * the same object.
 */
export function reportOriginalObjectKey(
  organizationId: bigint,
  reportPublicId: string,
  at: Date,
): string {
  const iso = at.toISOString();
  const ref = sha256Hex(`rpt|${reportPublicId}|${organizationId.toString()}`).slice(0, 32);
  return `org/${organizationId.toString()}/eml/${iso.slice(0, 4)}/${iso.slice(5, 7)}/${iso.slice(8, 10)}/${ref}.eml`;
}

/** One report original as the `reports` role commits it (C10.4). */
export interface ReportOriginalCommit {
  organizationId: bigint;
  report: { id: bigint; publicId: string; rowVersion: number };
  /** The reporter's address (the registry recipient, status `journaled`). */
  reporterAddress: string;
  /** The reporter's organization domain (`email_messages.domain_id`). */
  domainId: bigint | null;
  receivedAt: Date;
  /** D7.4 direction of the reporter as the recipient of the original. */
  direction: ApiCopyDirection;
  internetMessageId: string | null;
  headerFrom: string | null;
  subject: string | null;
  sizeBytes: number;
  emlObjectKey: string;
  emlSha256: string;
  /**
   * When the original's scan is overdue (`API_MODE_REPORT_SCAN_TIMEOUT_MINUTES` after the ingest):
   * stored in `next_attempt_at` of the `scanning` report; the reports role then falls back to
   * the report copy's scan.
   */
  scanDeadline: Date;
}

export interface ReportOriginalResult {
  status: 'committed' | 'duplicate' | 'lost';
  messageId: bigint;
  receivedAt: Date;
}

/**
 * Writer-only persistence of an ingested report original (step API-3 C10.4; modelled on
 * `MailboxCopyRepository.commit`, **without a copy row and without a dedupe claim**). One
 * transaction: the registry row (`message_identities`, ingest key `v2:rpt:…`), the message
 * (`ingest_source = mailbox_api`, born `persisted` with history E1/E2), one recipient row (the
 * reporter, status `journaled`), the `received` event (`details.userReport = { reportId }`), the
 * `mail.message.received.v1` outbox row (`ingestSource: 'mailbox_api'`: the email-worker scans it
 * in detect mode, never delivers or archives it, N1/D7.6) and the report's move to `scanning`
 * (`original_ingested = 1`, `original_message_*`, CAS on its `row_version`). A committed ingest
 * key is a duplicate. No content in MySQL (N4): the EML is in the mail bucket.
 */
export class ReportOriginalRepository {
  private readonly prisma: PrismaClient;

  constructor(prisma: PrismaClient) {
    this.prisma = withTransactionDefaults(prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  async findCommitted(
    organizationId: bigint,
    ingestKey: string,
  ): Promise<{ messageId: bigint; receivedAt: Date } | null> {
    const identity = await this.prisma.messageIdentity.findUnique({
      where: { organizationId_ingestKey: { organizationId, ingestKey } },
      select: { id: true, receivedAt: true, organizationId: true },
    });
    if (!identity || identity.organizationId !== organizationId) return null;
    return { messageId: identity.id, receivedAt: identity.receivedAt };
  }

  /**
   * Commits the original and moves the report to `scanning` in one transaction. `extra` runs in
   * the same transaction (the acknowledgement outbox row). `lost`: the report changed meanwhile
   * (nothing written).
   */
  async commit(
    data: ReportOriginalCommit,
    extra: (tx: Prisma.TransactionClient) => Promise<void>,
  ): Promise<ReportOriginalResult> {
    const ingestKey = reportIngestKey(data.report.publicId);
    try {
      return await this.prisma.$transaction(async (tx) => {
        const written = await this.write(tx, data, ingestKey);
        const moved = await this.moveReport(tx, data, written.messageId, written.receivedAt);
        if (!moved) throw new ReportChanged();
        await extra(tx);
        return written;
      });
    } catch (error) {
      if (error instanceof ReportChanged) {
        return { status: 'lost', messageId: 0n, receivedAt: data.receivedAt };
      }
      if (!isUniqueViolation(error)) throw error;
      // A crashed earlier attempt committed the original but not the report move cannot happen
      // (one transaction); a duplicate key means another replica committed both.
      const committed = await this.findCommitted(data.organizationId, ingestKey);
      if (!committed) throw error;
      return { status: 'duplicate', ...committed };
    }
  }

  private async moveReport(
    tx: Prisma.TransactionClient,
    data: ReportOriginalCommit,
    messageId: bigint,
    receivedAt: Date,
  ): Promise<boolean> {
    const n = await tx.$executeRaw`
      UPDATE api_user_reports
      SET status = 'scanning', original_ingested = 1, original_message_id = ${messageId},
          original_received_at = ${receivedAt}, lease_until = NULL,
          next_attempt_at = ${data.scanDeadline}, last_error_code = NULL, row_version = row_version + 1, updated_at = ${data.receivedAt}
      WHERE id = ${data.report.id} AND organization_id = ${data.organizationId}
        AND row_version = ${data.report.rowVersion} AND status = 'parsing'`;
    return n === 1;
  }

  private async write(
    tx: Prisma.TransactionClient,
    data: ReportOriginalCommit,
    ingestKey: string,
  ): Promise<ReportOriginalResult> {
    const eventId = uuidv7(data.receivedAt.getTime());
    const identity = await tx.messageIdentity.create({
      data: { organizationId: data.organizationId, ingestKey, receivedAt: data.receivedAt },
      select: { id: true },
    });
    const messageId = identity.id;
    const correlationId = `rpt:${data.report.publicId}`.slice(0, 128);
    const lifecycle = initialLifecycle({
      messageId,
      receivedAt: data.receivedAt,
      organizationId: data.organizationId,
      causationEventId: eventId,
      correlationId,
      service: SOURCE_SERVICE,
      at: data.receivedAt,
    });
    const envelopeFrom = data.headerFrom ?? '';
    const payload = messageReceivedV1.parse({
      messageId: messageId.toString(),
      receivedAt: data.receivedAt.toISOString(),
      direction: data.direction,
      emlS3Key: data.emlObjectKey,
      sizeBytes: data.sizeBytes,
      envelopeFrom,
      recipientCount: 1,
      ingestSource: 'mailbox_api',
    });
    await tx.emailMessage.create({
      data: {
        id: messageId,
        receivedAt: data.receivedAt,
        organizationId: data.organizationId,
        domainId: data.domainId,
        direction: data.direction,
        ingestSource: 'mailbox_api',
        ...lifecycle.messageFields,
        internetMessageId: data.internetMessageId?.slice(0, 998) ?? null,
        envelopeFrom: envelopeFrom.slice(0, 320),
        headerFrom: data.headerFrom?.slice(0, 320) ?? null,
        subject: data.subject?.slice(0, 998) ?? null,
        sizeBytes: data.sizeBytes,
        recipientCount: 1,
        emlObjectKey: data.emlObjectKey,
        emlSha256: data.emlSha256,
        clientIp: null,
        clientHelo: null,
        clientName: null,
        mtaQueueId: null,
      },
      select: { id: true },
    });
    await writeInitialHistory(tx, lifecycle);
    await tx.emailRecipient.create({
      data: {
        receivedAt: data.receivedAt,
        messageId,
        organizationId: data.organizationId,
        rcptSeq: 0,
        address: data.reporterAddress.slice(0, 320),
        status: 'journaled',
        direction: data.direction,
      },
      select: { id: true },
    });
    await tx.emailEvent.create({
      data: {
        receivedAt: data.receivedAt,
        messageId,
        organizationId: data.organizationId,
        eventType: 'received',
        occurredAt: data.receivedAt,
        sourceService: SOURCE_SERVICE,
        details: {
          direction: 'mailbox_api',
          messageDirection: data.direction,
          recipientCount: 1,
          sizeBytes: data.sizeBytes,
          userReport: { reportId: data.report.publicId },
        },
      },
      select: { id: true },
    });
    await tx.messageOutbox.create({
      data: {
        eventId,
        organizationId: data.organizationId,
        eventType: EventTypes.MessageReceived,
        aggregateType: MESSAGE_AGGREGATE_TYPE,
        aggregateId: messageId.toString(),
        correlationId,
        payload,
      },
      select: { id: true },
    });
    return { status: 'committed', messageId, receivedAt: data.receivedAt };
  }
}

class ReportChanged extends Error {
  constructor() {
    super('report changed');
    this.name = 'ReportChanged';
  }
}
