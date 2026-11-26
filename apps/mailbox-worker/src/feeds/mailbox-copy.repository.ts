import { isUniqueViolation, uuidv7, withTransactionDefaults } from '@email-gateway/common';
import type {
  ApiCopyDeliveredBasis,
  ApiCopyDirection,
  ApiCopySource,
  IntegrationProvider,
  Prisma,
  PrismaClient,
} from '@email-gateway/database';
import { EventTypes, messageReceivedV1 } from '@email-gateway/event-contracts';
import { initialLifecycle, writeInitialHistory } from '@email-gateway/message-lifecycle';
import { TX_MAX_WAIT_MS, TX_TIMEOUT_MS, big } from '../shared/db';

/** `source_service` of the registry rows the mailbox-worker writes. */
export const SOURCE_SERVICE = 'mailbox-worker';
export const MESSAGE_AGGREGATE_TYPE = 'message';

/** One fetched copy as the feed commits it (D10.3 step c). */
export interface FeedCopyCommit {
  organizationId: bigint;
  apiConnection: { id: bigint; publicId: string; provider: IntegrationProvider };
  mailbox: { id: bigint; publicId: string; primaryAddress: string; domainId: bigint | null };
  source: Extract<ApiCopySource, 'graph' | 'gmail'>;
  providerMessageId: string;
  /** `ingestKeyForCopy(...)` (`v2:mbx:` + SHA-256). */
  ingestKey: string;
  /** Registry time of the copy (ingest time). */
  receivedAt: Date;
  /** Graph `receivedDateTime` / Gmail `internalDate`. */
  providerDeliveredAt: Date | null;
  deliveredBasis: ApiCopyDeliveredBasis;
  /** D7.4 direction of the mailbox recipient (`email_messages.direction` and the copy's). */
  direction: ApiCopyDirection;
  internetMessageId: string | null;
  headerFrom: string | null;
  subject: string | null;
  /** Header From addr-spec, or '' (no client facts for API copies). */
  envelopeFrom: string;
  sizeBytes: number;
  emlObjectKey: string;
  emlSha256: string;
  messageIdHash: string | null;
  /** The feed's in-flight dedupe claim (`api_copy_dedupe_keys.id`), null without Message-ID. */
  dedupeClaimId: bigint | null;
}

export interface FeedCommitResult {
  /** `duplicate`: the ingest key was committed before (nothing else was written). */
  status: 'committed' | 'duplicate';
  messageId: bigint;
  receivedAt: Date;
  /** The journal took the dedupe claim over while this copy was fetched (copy marked seen). */
  claimTakenOver: boolean;
}

/** A too-large message (D10.3 b): a copy row without content, never scanned. */
export interface TooLargeCommit {
  organizationId: bigint;
  apiConnectionId: bigint;
  mailbox: { id: bigint };
  source: Extract<ApiCopySource, 'graph' | 'gmail'>;
  providerMessageId: string;
  ingestKey: string;
  receivedAt: Date;
  providerDeliveredAt: Date | null;
  deliveredBasis: ApiCopyDeliveredBasis;
  messageIdHash: string | null;
  dedupeClaimId: bigint | null;
}

const PREFIX = 'mbx';

/**
 * Writer-only persistence of fetched copies (ADR-0014; modelled on the smtp-adapter's
 * `JournalIntakeRepository.commit`, step 8.6 D2.6). One transaction per copy: the registry row
 * (`message_identities`, ingest key `v2:mbx:…`), the message (`ingest_source = mailbox_api`, born
 * `persisted` with history E1/E2 through `@email-gateway/message-lifecycle`), one recipient row
 * (the mailbox's primary address, status `journaled`), the `received` event (`details.mailboxApi`),
 * the pending `api_message_copies` row, the dedupe claim's copy ref and the
 * `mail.message.received.v1` outbox row (`ingestSource: 'mailbox_api'`), all with one
 * `received_at`. A committed ingest key is a duplicate: nothing else is written (idempotent).
 * No content in MySQL (N4): the EML is in the mail bucket.
 */
export class MailboxCopyRepository {
  private readonly prisma: PrismaClient;

  constructor(prisma: PrismaClient) {
    this.prisma = withTransactionDefaults(prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  /** The committed registry message of an ingest key, if any. */
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

  async commit(data: FeedCopyCommit): Promise<FeedCommitResult> {
    try {
      return await this.prisma.$transaction((tx) => this.write(tx, data));
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const committed = await this.findCommitted(data.organizationId, data.ingestKey);
      if (!committed) throw error;
      return { status: 'duplicate', ...committed, claimTakenOver: false };
    }
  }

  private async write(
    tx: Prisma.TransactionClient,
    data: FeedCopyCommit,
  ): Promise<FeedCommitResult> {
    const eventId = uuidv7(data.receivedAt.getTime());
    const identity = await tx.messageIdentity.create({
      data: {
        organizationId: data.organizationId,
        ingestKey: data.ingestKey,
        receivedAt: data.receivedAt,
      },
      select: { id: true },
    });
    const messageId = identity.id;
    const correlationId = `${PREFIX}:${data.mailbox.publicId}`.slice(0, 128);
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
      recipientCount: 1,
      ingestSource: 'mailbox_api',
    });
    await tx.emailMessage.create({
      data: {
        id: messageId,
        receivedAt: data.receivedAt,
        organizationId: data.organizationId,
        domainId: data.mailbox.domainId,
        direction: data.direction,
        ingestSource: 'mailbox_api',
        ...lifecycle.messageFields,
        internetMessageId: data.internetMessageId?.slice(0, 998) ?? null,
        envelopeFrom: data.envelopeFrom.slice(0, 320),
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
        address: data.mailbox.primaryAddress,
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
          mailboxApi: {
            connectionId: data.apiConnection.publicId,
            mailboxId: data.mailbox.publicId,
            provider: data.apiConnection.provider,
          },
        },
      },
      select: { id: true },
    });
    const copyPublicId = uuidv7(data.receivedAt.getTime());
    await tx.$executeRaw`
      INSERT INTO api_message_copies
        (received_at, public_id, organization_id, api_connection_id, mailbox_id, message_id,
         source, seen_journal, seen_api, direction, message_id_hash, provider_message_id,
         provider_delivered_at, delivered_basis, status, created_at, updated_at)
      VALUES (${data.receivedAt}, ${copyPublicId}, ${data.organizationId}, ${data.apiConnection.id},
              ${data.mailbox.id}, ${messageId}, ${data.source}, 0, 1, ${data.direction},
              ${data.messageIdHash}, ${data.providerMessageId.slice(0, 256)},
              ${data.providerDeliveredAt}, ${data.deliveredBasis}, 'pending', ${data.receivedAt},
              ${data.receivedAt})`;
    const claimTakenOver = await this.linkClaim(tx, {
      organizationId: data.organizationId,
      claimId: data.dedupeClaimId,
      messageId,
      receivedAt: data.receivedAt,
      mailboxId: data.mailbox.id,
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
    await tx.$executeRaw`
      UPDATE api_mailboxes SET last_change_at = ${data.receivedAt}, updated_at = ${data.receivedAt}
      WHERE id = ${data.mailbox.id} AND organization_id = ${data.organizationId}`;
    return { status: 'committed', messageId, receivedAt: data.receivedAt, claimTakenOver };
  }

  /**
   * Writes the copy ref into the feed's dedupe claim if it is still in flight. When the journal
   * took the claim over meanwhile (D7 step 6), this copy stays recorded and is marked
   * `seen_journal`. True when the claim was taken over.
   */
  private async linkClaim(
    tx: Prisma.TransactionClient,
    input: {
      organizationId: bigint;
      claimId: bigint | null;
      messageId: bigint;
      receivedAt: Date;
      mailboxId: bigint;
    },
  ): Promise<boolean> {
    if (input.claimId === null) return false;
    const rows = await tx.$queryRaw<Array<{ id: bigint | number }>>`
      SELECT id FROM api_message_copies
      WHERE message_id = ${input.messageId} AND received_at = ${input.receivedAt}
        AND mailbox_id = ${input.mailboxId}`;
    const copyId = rows[0] ? big(rows[0].id) : null;
    if (copyId === null) throw new Error('api_message_copies insert not visible');
    const linked = await tx.$executeRaw`
      UPDATE api_copy_dedupe_keys
      SET copy_id = ${copyId}, copy_received_at = ${input.receivedAt}, claim_expires_at = NULL
      WHERE id = ${input.claimId} AND organization_id = ${input.organizationId}
        AND copy_id IS NULL`;
    if (linked === 1) return false;
    await tx.$executeRaw`
      UPDATE api_message_copies SET seen_journal = 1
      WHERE id = ${copyId} AND received_at = ${input.receivedAt}`;
    return true;
  }

  /**
   * D10.3 b / API1-13: a message above `API_MODE_MAX_MESSAGE_BYTES` gets a copy row `too_large`
   * (no content, no registry message, never scanned). Its `message_id` is a registry id reserved in
   * `message_identities` under the same ingest key, so a replay is idempotent.
   */
  async commitTooLarge(data: TooLargeCommit): Promise<'committed' | 'duplicate'> {
    try {
      await this.prisma.$transaction(async (tx) => {
        const identity = await tx.messageIdentity.create({
          data: {
            organizationId: data.organizationId,
            ingestKey: data.ingestKey,
            receivedAt: data.receivedAt,
          },
          select: { id: true },
        });
        await tx.$executeRaw`
          INSERT INTO api_message_copies
            (received_at, public_id, organization_id, api_connection_id, mailbox_id, message_id,
             source, seen_journal, seen_api, direction, message_id_hash, provider_message_id,
             provider_delivered_at, delivered_basis, status, created_at, updated_at)
          VALUES (${data.receivedAt}, ${uuidv7(data.receivedAt.getTime())}, ${data.organizationId},
                  ${data.apiConnectionId}, ${data.mailbox.id}, ${identity.id}, ${data.source}, 0, 1,
                  'inbound', ${data.messageIdHash}, ${data.providerMessageId.slice(0, 256)},
                  ${data.providerDeliveredAt}, ${data.deliveredBasis}, 'too_large',
                  ${data.receivedAt}, ${data.receivedAt})`;
        await this.linkClaim(tx, {
          organizationId: data.organizationId,
          claimId: data.dedupeClaimId,
          messageId: identity.id,
          receivedAt: data.receivedAt,
          mailboxId: data.mailbox.id,
        });
      });
      return 'committed';
    } catch (error) {
      if (isUniqueViolation(error)) return 'duplicate';
      throw error;
    }
  }
}
