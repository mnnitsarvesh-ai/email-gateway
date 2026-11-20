import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import {
  type JournalEnvelope,
  type JournalIntakeProof,
  resolveArchiveSettings,
} from '@email-gateway/archive';
import type { Prisma } from '@email-gateway/database';
import { EventTypes, messageReceivedV1 } from '@email-gateway/event-contracts';
import type { JournalIntakeKind } from '@email-gateway/mail-routing';
import { initialLifecycle, writeInitialHistory } from '@email-gateway/message-lifecycle';
import {
  type CommittedMessage,
  MESSAGE_AGGREGATE_TYPE,
  SOURCE_SERVICE,
} from '../ingestion/ingestion.repository';
import type { IntakeFormat } from './journal-intake.metrics';

type MessageDirection = 'inbound' | 'outbound' | 'internal';

/** Everything one intake message's writer transaction writes (D2.6 `pass`). */
export interface IntakeCommit {
  organizationId: bigint;
  /** The org-side domain (D3), else the organization's lowest-id verified domain, else null. */
  domainId: bigint | null;
  ingestKey: string;
  receivedAt: Date;
  /** `email_messages.direction` from the parties (D3). */
  direction: MessageDirection;
  envelopeFrom: string;
  /** Header metadata of the STORED message (the unwrapped original for reports). */
  internetMessageId: string | null;
  headerFrom: string | null;
  subject: string | null;
  /** Size and SHA-256 of the stored bytes. */
  sizeBytes: number;
  emlObjectKey: string;
  emlSha256: string;
  clientIp: string | null;
  clientHelo: string | null;
  clientName: string | null;
  queueId: string;
  /** Envelope recipients in order with their direction (NULL = external to external). */
  recipients: readonly { address: string; direction: MessageDirection | null }[];
  source: { id: bigint; publicId: string; kind: JournalIntakeKind };
  format: Exclude<IntakeFormat, never>;
  envelope: JournalEnvelope;
  proof: JournalIntakeProof;
  /** SHA-256 and size of the message as received (the report for report kinds). */
  reportSha256: string;
  reportSizeBytes: number;
}

/** `details` of the intake message's `received` event (bounded, ids and codes only). */
export interface IntakeEventDetails {
  sourceId: string;
  kind: JournalIntakeKind;
  format: IntakeFormat;
}

/**
 * `archive-settings/1` `intake.scanEnabled` of an organization (D8; false without a row or with
 * a document that does not parse, which the api never stores: scanning is opt-in).
 */
export function scanRequestedOf(settings: Prisma.JsonValue | null | undefined): boolean {
  try {
    return resolveArchiveSettings(settings ?? null).intake.scanEnabled;
  } catch {
    return false;
  }
}

/** Writer-only persistence of the journal LMTP (ADR-0014, step 8.6 D2.6, D3). */
@Injectable()
export class JournalIntakeRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** The committed message of a duplicate delivery (pre-check and the P2002 race). */
  async findCommitted(organizationId: bigint, ingestKey: string): Promise<CommittedMessage | null> {
    const identity = await this.prisma.messageIdentity.findUnique({
      where: { organizationId_ingestKey: { organizationId, ingestKey } },
      select: { id: true, receivedAt: true },
    });
    if (!identity) return null;
    const message = await this.prisma.emailMessage.findUnique({
      where: { id_receivedAt: { id: identity.id, receivedAt: identity.receivedAt } },
      select: { emlObjectKey: true },
    });
    return {
      messageId: identity.id,
      receivedAt: identity.receivedAt,
      emlObjectKey: message?.emlObjectKey ?? null,
    };
  }

  /**
   * One writer transaction (modelled on `IngestionRepository.commit`): registry row, message
   * (`ingest_source = journal_intake`, born `persisted` with history E1/E2), envelope recipients
   * (status `journaled`), `journal_intake_messages` (envelope, proof, format, report hash and
   * size, `scan_requested` = the organization's `intake.scanEnabled` read in this transaction),
   * one `received` event (`details.intake`) and the `mail.message.received.v1` outbox row with
   * `ingestSource: 'journal_intake'`, all with one `received_at`. Throws P2002 on a committed
   * ingest key (a concurrent duplicate).
   */
  async commit(
    data: IntakeCommit,
    timeoutMs: number,
  ): Promise<{ messageId: bigint; eventId: string; scanRequested: boolean }> {
    const eventId = randomUUID();
    return this.prisma.$transaction(
      async (tx) => {
        const identity = await tx.messageIdentity.create({
          data: {
            organizationId: data.organizationId,
            ingestKey: data.ingestKey,
            receivedAt: data.receivedAt,
          },
          select: { id: true },
        });
        const messageId = identity.id;
        const settings = await tx.archiveSetting.findUnique({
          where: { organizationId: data.organizationId },
          select: { settings: true },
        });
        const scanRequested = scanRequestedOf(settings?.settings);
        const correlationId = `lmtp:${data.queueId}`;
        const lifecycle = initialLifecycle({
          messageId,
          receivedAt: data.receivedAt,
          organizationId: data.organizationId,
          causationEventId: eventId,
          correlationId,
          service: SOURCE_SERVICE,
          at: data.receivedAt,
        });
        const payload = messageReceivedV1.parse({
          messageId: messageId.toString(),
          receivedAt: data.receivedAt.toISOString(),
          direction: data.direction,
          emlS3Key: data.emlObjectKey,
          sizeBytes: data.sizeBytes,
          envelopeFrom: data.envelopeFrom,
          // received.v1 requires ≥ 1: an envelope that names nobody (an unparsed report whose
          // only header recipient was the intake address) still had the journal recipient.
          recipientCount: Math.max(1, data.recipients.length),
          ingestSource: 'journal_intake',
        });
        await tx.emailMessage.create({
          data: {
            id: messageId,
            receivedAt: data.receivedAt,
            organizationId: data.organizationId,
            domainId: data.domainId,
            direction: data.direction,
            ingestSource: 'journal_intake',
            ...lifecycle.messageFields,
            internetMessageId: data.internetMessageId,
            envelopeFrom: data.envelopeFrom,
            headerFrom: data.headerFrom,
            subject: data.subject,
            sizeBytes: data.sizeBytes,
            recipientCount: data.recipients.length,
            emlObjectKey: data.emlObjectKey,
            emlSha256: data.emlSha256,
            clientIp: data.clientIp,
            clientHelo: data.clientHelo,
            clientName: data.clientName,
            mtaQueueId: data.queueId,
          },
          select: { id: true },
        });
        await writeInitialHistory(tx, lifecycle);
        if (data.recipients.length > 0) {
          await tx.emailRecipient.createMany({
            data: data.recipients.map((recipient, rcptSeq) => ({
              receivedAt: data.receivedAt,
              messageId,
              organizationId: data.organizationId,
              rcptSeq,
              address: recipient.address,
              status: 'journaled' as const,
              direction: recipient.direction,
            })),
          });
        }
        await tx.journalIntakeMessage.create({
          data: {
            messageId,
            receivedAt: data.receivedAt,
            organizationId: data.organizationId,
            sourceId: data.source.id,
            kind: data.source.kind,
            format: data.format,
            envelope: data.envelope,
            proof: data.proof,
            reportSha256: data.reportSha256,
            reportSizeBytes: data.reportSizeBytes,
            scanRequested,
          },
          select: { messageId: true },
        });
        const intake: IntakeEventDetails = {
          sourceId: data.source.publicId,
          kind: data.source.kind,
          format: data.format,
        };
        await tx.emailEvent.create({
          data: {
            receivedAt: data.receivedAt,
            messageId,
            organizationId: data.organizationId,
            eventType: 'received',
            occurredAt: data.receivedAt,
            sourceService: SOURCE_SERVICE,
            details: {
              direction: 'journal',
              messageDirection: data.direction,
              queueId: data.queueId,
              recipientCount: data.recipients.length,
              sizeBytes: data.sizeBytes,
              intake: { ...intake },
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
        return { messageId, eventId, scanRequested };
      },
      { timeout: timeoutMs, maxWait: timeoutMs },
    );
  }
}
