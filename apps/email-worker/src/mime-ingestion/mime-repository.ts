import {
  type HandleOutcome,
  isUniqueViolation,
  uuidv7,
  withTransactionDefaults,
} from '@email-gateway/common';
import { type Prisma, processOnce, type PrismaClient } from '@email-gateway/database';
import { EventTypes } from '@email-gateway/event-contracts';
import type { MimeParseResult } from '@email-gateway/mime-parser';
import type {
  FinalizeInput,
  FinalizeResult,
  MarkParsingResult,
  MessageRecord,
  MimeStore,
  ParseRowState,
} from './mime-store';
import { buildParsedPayload, buildParseFailedPayload } from './payloads';

/** `email_events.source_service` and the producer of the parse events. */
export const SOURCE_SERVICE = 'email-worker';

/** Another worker finalized the parse row first (M3.9.1); rolls the transaction back. */
export class AlreadyFinalized extends Error {
  override readonly name = 'AlreadyFinalized';
}

const json = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;

/**
 * MySQL side of the MIME ingestion stage, on the **writer** only (ADR-0014). Every statement is
 * scoped by `(message_id, received_at, organization_id)` of the writer row, so one message's
 * graph stays in one partition and never crosses tenants.
 */
export class MimeRepository implements MimeStore {
  private readonly txPrisma: PrismaClient;

  constructor(
    private readonly prisma: PrismaClient,
    /** Budget of the finalize transaction (MIME_DB_TIMEOUT_MS). */
    txTimeoutMs: number,
  ) {
    this.txPrisma = withTransactionDefaults(prisma, { timeoutMs: txTimeoutMs });
  }

  async isProcessed(consumer: string, eventId: string): Promise<boolean> {
    const row = await this.prisma.messageIdempotency.findUnique({
      where: { consumer_eventId: { consumer, eventId } },
      select: { eventId: true },
    });
    return row !== null;
  }

  async recordNoop(consumer: string, eventId: string): Promise<HandleOutcome> {
    const result = await processOnce(this.txPrisma, consumer, eventId, () => Promise.resolve());
    return result.status === 'duplicate' ? 'duplicate' : 'handled';
  }

  async loadMessage(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<MessageRecord | null> {
    return this.prisma.emailMessage.findFirst({
      where: { id: messageId, receivedAt, organizationId },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        direction: true,
        emlObjectKey: true,
        emlSha256: true,
        sizeBytes: true,
      },
    });
  }

  loadParse(message: MessageRecord): Promise<ParseRowState | null> {
    return this.prisma.emailMessageParse.findFirst({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
      },
      select: { status: true, attempts: true },
    });
  }

  async markParsing(
    message: MessageRecord,
    start: { eventId: string; parserVersion: string; startedAt: Date },
  ): Promise<MarkParsingResult> {
    const existing = await this.loadParse(message);
    if (existing === null) {
      try {
        await this.prisma.emailMessageParse.create({
          data: {
            receivedAt: message.receivedAt,
            messageId: message.id,
            organizationId: message.organizationId,
            status: 'parsing',
            attempts: 1,
            parserVersion: start.parserVersion,
            eventId: start.eventId,
            startedAt: start.startedAt,
          },
          select: { id: true },
        });
        return { kind: 'parsing', attempts: 1 };
      } catch (err) {
        // Another worker inserted the row first: count this attempt on it.
        if (!isUniqueViolation(err)) throw err;
      }
    } else if (existing.status !== 'parsing') {
      return { kind: 'final' };
    }
    return this.prisma.$transaction(async (tx) => {
      const where = {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        status: 'parsing' as const,
      };
      const updated = await tx.emailMessageParse.updateMany({
        where,
        data: { attempts: { increment: 1 }, startedAt: start.startedAt },
      });
      if (updated.count === 0) return { kind: 'final' } as const;
      const row = await tx.emailMessageParse.findFirst({ where, select: { attempts: true } });
      return row
        ? ({ kind: 'parsing', attempts: row.attempts } as const)
        : ({ kind: 'final' } as const);
    });
  }

  async decrementAttempts(message: MessageRecord): Promise<void> {
    await this.prisma.emailMessageParse.updateMany({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        status: 'parsing',
        attempts: { gt: 0 },
      },
      data: { attempts: { decrement: 1 } },
    });
  }

  async finalize(input: FinalizeInput): Promise<FinalizeResult> {
    const outboxEventId = uuidv7(input.completedAt.getTime());
    try {
      const result = await processOnce(this.txPrisma, input.consumer, input.event.eventId, (tx) =>
        this.applyFinal(tx, input, outboxEventId),
      );
      return result.status === 'duplicate'
        ? { outcome: 'duplicate' }
        : { outcome: 'handled', outboxEventId };
    } catch (err) {
      if (err instanceof AlreadyFinalized) return { outcome: 'duplicate' };
      throw err;
    }
  }

  private async applyFinal(
    tx: Prisma.TransactionClient,
    input: FinalizeInput,
    outboxEventId: string,
  ): Promise<void> {
    const { message, outcome } = input;
    const scope = {
      messageId: message.id,
      receivedAt: message.receivedAt,
      organizationId: message.organizationId,
    };
    // Validated before anything is written: a contract violation rolls everything back.
    const payload =
      outcome.status === 'parse_failed'
        ? buildParseFailedPayload(input)
        : buildParsedPayload(input);
    const result = outcome.result;
    const stats = outcome.stats;

    // 1. parsing → final, only if nobody finalized it in between.
    const updated = await tx.emailMessageParse.updateMany({
      where: { ...scope, status: 'parsing' },
      data: {
        status: outcome.status,
        attempts: input.attempts,
        failureReason: outcome.failureReason,
        limitsExceeded: json(outcome.limitsExceeded),
        defects: json(outcome.defects),
        bytesRead: stats ? BigInt(stats.bytesRead) : null,
        ...(result ? parseColumns(result) : {}),
        completedAt: input.completedAt,
        durationMs: Math.max(0, Math.round(input.durationMs)),
      },
    });
    if (updated.count === 0) throw new AlreadyFinalized('parse row already finalized');

    if (result) {
      // 2. Header and attachment rows (unique keys are the backstop, M12).
      if (result.headers.length > 0) {
        await tx.emailHeader.createMany({
          data: result.headers.map((h) => ({ ...scope, seq: h.seq, name: h.name, value: h.value })),
        });
      }
      if (result.attachments.length > 0) {
        await tx.emailAttachment.createMany({
          data: result.attachments.map((a) => ({
            ...scope,
            partIndex: a.partIndex,
            partPath: a.partPath,
            depth: a.depth,
            disposition: a.disposition,
            filename: a.filename,
            originalFilename: a.originalFilename,
            declaredContentType: a.declaredContentType,
            detectedContentType: a.detectedContentType,
            sizeBytes: a.sizeBytes,
            encodedSizeBytes: a.encodedSizeBytes,
            sha256: a.sha256,
            objectKey: a.key,
            flags: json(a.flags),
            ...(a.archiveInfo ? { archiveInfo: json(a.archiveInfo) } : {}),
          })),
        });
      }
      // 3. Decoded subject and attachment count only: never status, status_changed_at or
      // version (step 3.3 owns the lifecycle, M13).
      await tx.emailMessage.updateMany({
        where: {
          id: message.id,
          receivedAt: message.receivedAt,
          organizationId: message.organizationId,
        },
        data: {
          attachmentCount: result.attachments.length,
          ...(result.subject !== null ? { subject: result.subject } : {}),
        },
      });
    }

    // 4. The processing event (codes and counts only).
    await tx.emailEvent.create({
      data: {
        ...scope,
        eventType: outcome.status === 'parse_failed' ? 'parse_failed' : 'parsed',
        occurredAt: input.completedAt,
        sourceService: SOURCE_SERVICE,
        eventId: outboxEventId,
        details: json({
          status: outcome.status,
          ...(outcome.failureReason ? { failureReason: outcome.failureReason } : {}),
          limitsExceeded: outcome.limitsExceeded,
          defectCount: outcome.defects.length,
          attachmentCount: result?.attachments.length ?? 0,
          parserVersion: input.parserVersion,
        }),
      },
      select: { id: true },
    });

    // 5. The transactional outbox event (M14).
    await tx.messageOutbox.create({
      data: {
        eventId: outboxEventId,
        organizationId: message.organizationId,
        eventType:
          outcome.status === 'parse_failed'
            ? EventTypes.MessageParseFailed
            : EventTypes.MessageParsed,
        aggregateType: 'message',
        aggregateId: message.id.toString(),
        correlationId: input.event.correlationId,
        payload: json(payload),
      },
      select: { id: true },
    });
  }
}

/** The content columns of `email_message_parses` (M3, §3); keys, hashes, sizes and codes only. */
function parseColumns(result: MimeParseResult) {
  const { stats, textBody, htmlBody } = result;
  return {
    partCount: stats.partCount,
    attachmentCount: result.attachments.length,
    maxDepth: stats.maxDepth,
    headerCount: stats.headerCount,
    decodedBytes: BigInt(stats.decodedBytes),
    textBodyObjectKey: textBody?.key ?? null,
    textBodySha256: textBody?.sha256 ?? null,
    textBodySizeBytes: textBody?.sizeBytes ?? null,
    textBodyCharset: textBody?.charset ?? null,
    htmlBodyObjectKey: htmlBody?.key ?? null,
    htmlBodySha256: htmlBody?.sha256 ?? null,
    htmlBodySizeBytes: htmlBody?.sizeBytes ?? null,
    htmlBodyCharset: htmlBody?.charset ?? null,
    structure: json(result.structure),
  };
}
