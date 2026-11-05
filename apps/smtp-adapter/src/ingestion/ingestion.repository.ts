import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { EventTypes, messageReceivedV1 } from '@email-gateway/event-contracts';
import type { RoutedDirection } from '@email-gateway/mail-routing';
import { initialLifecycle, writeInitialHistory } from '@email-gateway/message-lifecycle';
import type { IngestDirection } from './ingestion-keys';

export const MESSAGE_AGGREGATE_TYPE = 'message';
export const SOURCE_SERVICE = 'smtp-adapter';

/** Everything one organization's ingestion transaction writes (D7 step 6). */
export interface IngestCommit {
  organizationId: bigint;
  domainId: bigint;
  ingestKey: string;
  receivedAt: Date;
  /**
   * The LISTENER direction (`:10050` inbound, `:10051` outbound). It is part of the ingest key
   * and the S3 object key and is what the loop check counts (2.2 D7, D8, D14); it is kept in
   * the `received` event details as `direction`.
   */
  direction: IngestDirection;
  /**
   * `email_messages.direction` and the `mail.message.received.v1` payload direction (step 2.3
   * R1): `internal` when the listener is outbound and every recipient is internal, else the
   * listener direction (messageDirection).
   */
  messageDirection: RoutedDirection;
  envelopeFrom: string;
  internetMessageId: string | null;
  headerFrom: string | null;
  subject: string | null;
  sizeBytes: number;
  emlObjectKey: string;
  emlSha256: string;
  clientIp: string | null;
  clientHelo: string | null;
  /** Verified client host name from XFORWARD NAME (`email_messages.client_name`, step 4.1). */
  clientName: string | null;
  queueId: string;
  /** In RCPT order (`rcpt_seq` 0..n-1). */
  recipients: readonly string[];
  /** `email_recipients.direction` per recipient, same order and length as `recipients`. */
  recipientDirections: readonly RoutedDirection[];
}

export interface CommittedMessage {
  messageId: bigint;
  receivedAt: Date;
  emlObjectKey: string | null;
}

/** P2002: unique constraint violation (here: `(organization_id, ingest_key)`). */
export const isUniqueViolation = (err: unknown): boolean =>
  err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';

/** Writer-only persistence of LMTP ingestion (ADR-0014, D7). */
@Injectable()
export class IngestionRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** The committed message of a duplicate delivery, if any (pre-check and P2002 race). */
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
   * One writer transaction: registry row, message, recipients, one `received` event and the
   * `mail.message.received.v1` outbox row, all with the same `received_at`. Throws P2002 when the
   * ingest key is already committed (a concurrent duplicate).
   *
   * Lifecycle (step 3.3 L8.1, edges E1 and E2): the message is born `persisted` (version 1,
   * round 0, reason `committed`) with its two history rows (`received`, `persisted`; actor
   * `ingestion`/`smtp-adapter`, causation = the received event id, correlation
   * `lmtp:<queueId>`) through @email-gateway/message-lifecycle; one `createMany`, no lock, no
   * read, no `state_changed` outbox row (`mail.message.received.v1` notifies `persisted`).
   */
  async commit(
    data: IngestCommit,
    timeoutMs: number,
  ): Promise<{ messageId: bigint; eventId: string }> {
    if (data.recipientDirections.length !== data.recipients.length) {
      throw new Error('recipientDirections must have one entry per recipient');
    }
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
        const lifecycle = initialLifecycle({
          messageId,
          receivedAt: data.receivedAt,
          organizationId: data.organizationId,
          causationEventId: eventId,
          correlationId: `lmtp:${data.queueId}`,
          service: SOURCE_SERVICE,
          at: data.receivedAt,
        });
        const payload = messageReceivedV1.parse({
          messageId: messageId.toString(),
          receivedAt: data.receivedAt.toISOString(),
          direction: data.messageDirection,
          emlS3Key: data.emlObjectKey,
          sizeBytes: data.sizeBytes,
          envelopeFrom: data.envelopeFrom,
          recipientCount: data.recipients.length,
        });
        await tx.emailMessage.create({
          data: {
            id: messageId,
            receivedAt: data.receivedAt,
            organizationId: data.organizationId,
            domainId: data.domainId,
            direction: data.messageDirection,
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
        await tx.emailRecipient.createMany({
          data: data.recipients.map((address, rcptSeq) => ({
            receivedAt: data.receivedAt,
            messageId,
            organizationId: data.organizationId,
            rcptSeq,
            address,
            status: 'pending' as const,
            direction: data.recipientDirections[rcptSeq]!,
          })),
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
              direction: data.direction,
              messageDirection: data.messageDirection,
              queueId: data.queueId,
              recipientCount: data.recipients.length,
              sizeBytes: data.sizeBytes,
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
            correlationId: `lmtp:${data.queueId}`,
            payload,
          },
          select: { id: true },
        });
        return { messageId, eventId };
      },
      { timeout: timeoutMs, maxWait: timeoutMs },
    );
  }
}
