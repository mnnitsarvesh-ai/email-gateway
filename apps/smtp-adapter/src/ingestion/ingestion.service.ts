import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { type DomainOwner, resolveDomainOwner } from '@email-gateway/database';
import { createLogger, type Logger } from '@email-gateway/logger';
import {
  classifyRecipient,
  messageDirection,
  type RoutedDirection,
} from '@email-gateway/mail-routing';
import type { SMTPServerDataStream } from 'smtp-server';
import type { LmtpClientInfo, LmtpHandler } from '../lmtp/lmtp-listener';
import { LmtpReplyException } from '../lmtp/lmtp-reply';
import { withTimeout } from '../lmtp/timeout';
import { LMTP_TEMPFAIL, type SmtpReply } from '../shared/replies';
import { EmlStore } from './eml-store';
import type { HeaderMetadata } from './header-scanner';
import { emlObjectKey, type IngestDirection, ingestKey, type QueueFileRef } from './ingestion-keys';
import { IngestionMetrics } from './ingestion.metrics';
import { INGESTION_OPTIONS, type IngestionModuleOptions } from './ingestion.options';
import { IngestionRepository, isUniqueViolation } from './ingestion.repository';
import { readMessage } from './message-reader';
import {
  fromMatchesSender,
  groupByOrganization,
  type IngestRecipient,
  isLooping,
  type OrganizationGroup,
  type OrganizationOutcome,
  repliesFor,
  splitRecipient,
} from './tenant-split';

/** State of one LMTP transaction (MAIL FROM to the replies after DATA). */
export interface IngestTransaction {
  direction: IngestDirection;
  ref: QueueFileRef;
  envelopeFrom: string;
  clientIp: string | null;
  clientHelo: string | null;
  /** Owner lookups of this transaction by domain (one query per domain). */
  owners: Map<string, Promise<DomainOwner | null>>;
}

const MAX_ENVELOPE_FROM = 320;
const MAX_CLIENT_HELO = 255;
/** Best-effort cleanup of a superseded object must not hold the replies for long. */
const DELETE_TIMEOUT_MS = 10_000;

const domainOf = (address: string): string => address.slice(address.lastIndexOf('@') + 1);

/**
 * Durable LMTP ingestion (step 2.2 D7, D8, D14): one service, two listeners (the port decides
 * the direction). `250` per recipient only after the EML is in S3 and that organization's writer
 * transaction committed; every infrastructure failure is `451 4.3.0`.
 */
@Injectable()
export class IngestionService {
  private readonly logger: Logger;

  constructor(
    @Inject(INGESTION_OPTIONS) private readonly options: IngestionModuleOptions,
    private readonly prisma: PrismaService,
    private readonly repository: IngestionRepository,
    private readonly store: EmlStore,
    private readonly metrics: IngestionMetrics,
  ) {
    this.logger = createLogger({ service: 'smtp-adapter', level: options.logLevel }).child({
      component: 'lmtp-ingestion',
    });
  }

  /** The LMTP handler of one listener. */
  handler(direction: IngestDirection): LmtpHandler<IngestTransaction, IngestRecipient> {
    return {
      beginTransaction: (client, mailFrom) =>
        Promise.resolve().then(() => this.beginTransaction(direction, client, mailFrom)),
      acceptRecipient: (transaction, address) => this.acceptRecipient(transaction, address),
      handleData: (transaction, recipients, stream) =>
        this.handleData(transaction, recipients, stream),
    };
  }

  beginTransaction(
    direction: IngestDirection,
    client: LmtpClientInfo,
    mailFrom: string,
  ): IngestTransaction {
    if (client.queueId === null || client.lhloName === null) {
      // The ingest key needs both; Postfix sends them (lmtp_send_xforward_command = yes).
      this.logger.error(
        {
          direction,
          connectionId: client.connectionId,
          hasQueueId: client.queueId !== null,
          hasLhloName: client.lhloName !== null,
        },
        'LMTP transaction without XFORWARD IDENT or LHLO name; tempfailing',
      );
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    if (mailFrom.length > MAX_ENVELOPE_FROM) {
      this.logger.error(
        { direction, queueId: client.queueId },
        'envelope sender longer than 320 characters; tempfailing',
      );
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    return {
      direction,
      ref: { mtaId: client.lhloName, queueId: client.queueId, direction },
      envelopeFrom: mailFrom,
      clientIp: client.clientAddress,
      clientHelo: client.clientHelo === null ? null : client.clientHelo.slice(0, MAX_CLIENT_HELO),
      owners: new Map(),
    };
  }

  async acceptRecipient(transaction: IngestTransaction, address: string): Promise<IngestRecipient> {
    const { queueId, direction } = transaction.ref;
    const recipient = splitRecipient(address);
    if (!recipient) {
      this.logger.warn({ direction, queueId }, 'unusable LMTP recipient address; tempfailing');
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    // Inbound: the recipient domain's owner. Outbound: the sender domain's owner (the policy
    // already proved in-session that the authenticated connector belongs to it).
    const lookupDomain =
      direction === 'inbound'
        ? recipient.domain
        : transaction.envelopeFrom === ''
          ? null
          : domainOf(transaction.envelopeFrom).toLowerCase();
    const owner = lookupDomain === null ? null : await this.owner(transaction, lookupDomain);
    if (!owner) {
      this.logger.warn(
        { direction, queueId, domain: lookupDomain },
        direction === 'inbound'
          ? 'no owner for the recipient domain; tempfailing the recipient'
          : 'no owner for the envelope sender domain; tempfailing the recipient',
      );
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    return {
      address: recipient.address,
      domain: recipient.domain,
      organizationId: owner.organizationId,
      domainId: owner.domainId,
      direction: await this.classify(transaction, owner.organizationId, recipient.domain),
    };
  }

  /**
   * Step 2.3 R1 at ingestion: the routed direction of one recipient. Inbound listener → always
   * `inbound` (no lookup). Outbound listener → the recipient domain's owner with
   * `resolveActiveDomain` semantics (verified, `active` domain of an `active` organization),
   * read from the writer through the transaction's owner memo (one query per distinct domain,
   * shared with the sender lookup); `internal` when it is the sender's organization. A lookup
   * error propagates: the recipient is tempfailed (451) like every other ingestion lookup.
   */
  private async classify(
    transaction: IngestTransaction,
    organizationId: bigint,
    recipientDomain: string,
  ): Promise<RoutedDirection> {
    if (transaction.direction === 'inbound') return 'inbound';
    const owner = await this.owner(transaction, recipientDomain);
    const active =
      owner !== null && owner.status === 'active' && owner.organizationStatus === 'active';
    return classifyRecipient({
      listenerDirection: 'outbound',
      messageOrganizationId: organizationId,
      recipientDomainOwner: active ? { organizationId: owner.organizationId } : null,
    });
  }

  private async owner(transaction: IngestTransaction, domain: string): Promise<DomainOwner | null> {
    let lookup = transaction.owners.get(domain);
    if (!lookup) {
      lookup = withTimeout(
        resolveDomainOwner(this.prisma, domain),
        this.options.config.INGEST_DB_TIMEOUT_MS,
        'domain owner lookup',
      );
      transaction.owners.set(domain, lookup);
    }
    try {
      return await lookup;
    } catch (err) {
      transaction.owners.delete(domain);
      this.metrics.dbError();
      throw err;
    }
  }

  async handleData(
    transaction: IngestTransaction,
    recipients: readonly IngestRecipient[],
    stream: SMTPServerDataStream,
  ): Promise<SmtpReply[]> {
    const config = this.options.config;
    const { ref } = transaction;
    const startedAt = process.hrtime.bigint();
    const attemptAt = new Date();
    const groups = groupByOrganization(recipients);
    const outcomes = new Map<bigint, OrganizationOutcome>();
    // Set while reading (the closure below), read afterwards.
    const plan: { primary: OrganizationGroup | null; primaryKey: string } = {
      primary: null,
      primaryKey: '',
    };

    const read = await readMessage(stream, {
      headerMaxBytes: config.INGEST_HEADER_MAX_BYTES,
      onHeaders: (headers) => {
        this.screen(transaction, groups, headers, outcomes);
        const primary = groups.find((group) => !outcomes.has(group.organizationId)) ?? null;
        plan.primary = primary;
        if (primary === null) return null;
        plan.primaryKey = emlObjectKey(ref, primary.organizationId, attemptAt);
        return this.store.startUpload({
          key: plan.primaryKey,
          partSize: config.INGEST_S3_PART_SIZE_BYTES,
          queueSize: config.INGEST_S3_QUEUE_SIZE,
          timeoutMs: config.INGEST_S3_TIMEOUT_MS,
        });
      },
    });

    const storeGroups = groups.filter((group) => !outcomes.has(group.organizationId));
    const failAll = (outcome: OrganizationOutcome) => {
      for (const group of storeGroups) outcomes.set(group.organizationId, outcome);
    };
    const deletions: string[] = [];

    if (read.outcome !== 'complete') {
      if (read.outcome === 'failed') {
        this.logger.error({ err: read.failure, queueId: ref.queueId }, 'ingestion read failed');
      } else {
        this.logger.warn(
          { queueId: ref.queueId, direction: ref.direction, reason: read.outcome },
          'message not ingested',
        );
      }
      failAll('tempfail');
    } else if (storeGroups.length > 0 && read.sink !== null && read.headers !== null) {
      let uploaded = false;
      try {
        await read.sink.finish();
        uploaded = true;
      } catch (err) {
        this.metrics.s3Error();
        this.logger.error(
          { err, queueId: ref.queueId, direction: ref.direction },
          'EML upload to S3 failed; tempfailing',
        );
        failAll('tempfail');
      }
      const { primary, primaryKey } = plan;
      if (uploaded && primary !== null) {
        for (const group of storeGroups) {
          outcomes.set(
            group.organizationId,
            await this.storeOrganization({
              transaction,
              group,
              isPrimary: group === primary,
              primaryKey,
              objectKey:
                group === primary ? primaryKey : emlObjectKey(ref, group.organizationId, attemptAt),
              // Per organization: its recipient set is part of the key (D7).
              ingestKey: ingestKey(
                ref,
                read.sha256,
                group.recipients.map((recipient) => recipient.address),
              ),
              sha256: read.sha256,
              sizeBytes: read.bytes,
              headers: read.headers,
              deletions,
              startedAt,
            }),
          );
        }
      }
    }

    for (const key of deletions) {
      try {
        await this.store.delete(key, DELETE_TIMEOUT_MS);
      } catch (err) {
        this.metrics.s3Error();
        this.logger.warn(
          { err, queueId: ref.queueId },
          'could not delete the superseded object of a duplicate delivery',
        );
      }
    }

    const seconds = Number(process.hrtime.bigint() - startedAt) / 1e9;
    this.metrics.transaction(ref.direction, seconds, read.bytes);
    for (const group of groups) {
      const outcome = outcomes.get(group.organizationId) ?? 'tempfail';
      this.metrics.outcome(ref.direction, outcome);
      if (outcome !== 'stored') {
        this.logger.info(
          {
            queueId: ref.queueId,
            direction: ref.direction,
            organizationId: group.organizationId.toString(),
            outcome,
            recipients: group.recipients.length,
            domains: [...new Set(group.recipients.map((r) => r.domain))],
            durationMs: Math.round(seconds * 1000),
          },
          'lmtp ingestion result',
        );
      }
    }
    return repliesFor(recipients.length, groups, outcomes);
  }

  /** D7 steps 4–5 (before anything is stored): loop check per organization, outbound From. */
  private screen(
    transaction: IngestTransaction,
    groups: readonly OrganizationGroup[],
    headers: HeaderMetadata,
    outcomes: Map<bigint, OrganizationOutcome>,
  ): void {
    const config = this.options.config;
    if (
      transaction.direction === 'outbound' &&
      !fromMatchesSender(headers.fromValues, transaction.envelopeFrom)
    ) {
      for (const group of groups) outcomes.set(group.organizationId, 'from_mismatch');
      return;
    }
    for (const group of groups) {
      const looping = isLooping(headers.traces, group.organizationId, {
        secret: config.GATEWAY_TRACE_SECRET,
        gatewayId: config.GATEWAY_TRACE_ID,
        maxPasses: config.SMTP_LOOP_MAX_PASSES,
        direction: transaction.direction,
      });
      if (looping) outcomes.set(group.organizationId, 'loop');
    }
  }

  private async storeOrganization(input: {
    transaction: IngestTransaction;
    group: OrganizationGroup;
    isPrimary: boolean;
    primaryKey: string;
    objectKey: string;
    ingestKey: string;
    sha256: string;
    sizeBytes: number;
    headers: HeaderMetadata;
    deletions: string[];
    startedAt: bigint;
  }): Promise<OrganizationOutcome> {
    const { transaction, group, objectKey } = input;
    const { ref } = transaction;
    const config = this.options.config;
    const organizationId = group.organizationId;
    const logContext = {
      queueId: ref.queueId,
      direction: ref.direction,
      organizationId: organizationId.toString(),
    };

    let committed;
    try {
      committed = await withTimeout(
        this.repository.findCommitted(organizationId, input.ingestKey),
        config.INGEST_DB_TIMEOUT_MS,
        'duplicate pre-check',
      );
    } catch (err) {
      this.metrics.dbError();
      this.logger.error({ err, ...logContext }, 'duplicate pre-check failed; tempfailing');
      return 'tempfail';
    }
    if (committed) {
      // Only the primary organization's object was written in this attempt.
      if (input.isPrimary && committed.emlObjectKey !== objectKey) input.deletions.push(objectKey);
      this.logger.info(
        { ...logContext, messageId: committed.messageId.toString() },
        'duplicate LMTP delivery; already committed',
      );
      return 'duplicate';
    }

    if (!input.isPrimary) {
      try {
        await this.store.copy(input.primaryKey, objectKey, config.INGEST_S3_TIMEOUT_MS);
      } catch (err) {
        this.metrics.s3Error();
        this.logger.error({ err, ...logContext }, 'S3 copy for an organization failed');
        return 'tempfail';
      }
    }

    const receivedAt = new Date();
    try {
      const { messageId } = await withTimeout(
        this.repository.commit(
          {
            organizationId,
            domainId: group.domainId,
            ingestKey: input.ingestKey,
            receivedAt,
            direction: ref.direction,
            messageDirection: messageDirection(
              ref.direction,
              group.recipients.map((recipient) => recipient.direction),
            ),
            envelopeFrom: transaction.envelopeFrom,
            internetMessageId: input.headers.messageId,
            headerFrom: input.headers.from,
            subject: input.headers.subject,
            sizeBytes: input.sizeBytes,
            emlObjectKey: objectKey,
            emlSha256: input.sha256,
            clientIp: transaction.clientIp,
            clientHelo: transaction.clientHelo,
            queueId: ref.queueId,
            recipients: group.recipients.map((recipient) => recipient.address),
            recipientDirections: group.recipients.map((recipient) => recipient.direction),
          },
          config.INGEST_DB_TIMEOUT_MS,
        ),
        // The transaction's own timeout fires first; this bounds connection acquisition too.
        config.INGEST_DB_TIMEOUT_MS * 2,
        'ingestion transaction',
      );
      this.logger.info(
        {
          ...logContext,
          messageId: messageId.toString(),
          outcome: 'stored',
          recipients: group.recipients.length,
          domains: [...new Set(group.recipients.map((r) => r.domain))],
          receivedHeaders: input.headers.receivedCount,
          sizeBytes: input.sizeBytes,
          durationMs: Math.round(Number(process.hrtime.bigint() - input.startedAt) / 1e6),
        },
        'lmtp message stored',
      );
      return 'stored';
    } catch (err) {
      if (isUniqueViolation(err)) {
        // A concurrent delivery of the same queue file committed first.
        try {
          const winner = await withTimeout(
            this.repository.findCommitted(organizationId, input.ingestKey),
            config.INGEST_DB_TIMEOUT_MS,
            'duplicate lookup',
          );
          if (winner && winner.emlObjectKey !== objectKey) input.deletions.push(objectKey);
        } catch (lookupErr) {
          this.logger.warn({ err: lookupErr, ...logContext }, 'duplicate lookup failed');
        }
        return 'duplicate';
      }
      this.metrics.dbError();
      this.logger.error({ err, ...logContext }, 'ingestion transaction failed; tempfailing');
      return 'tempfail';
    }
  }
}
