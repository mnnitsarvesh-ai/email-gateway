import { createHash } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import {
  buildCopyEnvelope,
  classifyIntakeParties,
  HeaderFieldStripper,
  intakeAddressHash,
  intakeLocalPart,
  JOURNAL_ENVELOPE_MAX_RECIPIENTS,
  type JournalEnvelope,
  journalEnvelopeSchema,
  journalIntakeProofSchema,
  JournalReportSplitter,
  JOURNAL_TOKEN_HEADER_NAME,
  parseIntakeLocalPart,
  parseJournalEnvelope,
} from '@email-gateway/archive';
import { createLogger, type Logger } from '@email-gateway/logger';
import {
  evaluateIntakeProof,
  type IntakeProofOutcome,
  isJournalReportKind,
  type JournalIntakeKind,
} from '@email-gateway/mail-routing';
import type { SMTPServerDataStream } from 'smtp-server';
import { EmlStore, type EmlUpload } from '../ingestion/eml-store';
import { type HeaderMetadata, HeaderScanner } from '../ingestion/header-scanner';
import { emlObjectKey, ingestKey, type QueueFileRef } from '../ingestion/ingestion-keys';
import { isUniqueViolation } from '../ingestion/ingestion.repository';
import { type MessageSink, readMessage } from '../ingestion/message-reader';
import type { LmtpClientInfo, LmtpHandler } from '../lmtp/lmtp-listener';
import { LmtpReplyException } from '../lmtp/lmtp-reply';
import { withTimeout } from '../lmtp/timeout';
import { EgressIndexService } from '../provider-relay/egress-index.service';
import { ProofVerifier } from '../provider-relay/proof-verifier';
import { LMTP_INTAKE_DROPPED, LMTP_OK, LMTP_TEMPFAIL, type SmtpReply } from '../shared/replies';
import { admitIntakeRecipient } from './admission';
import { type IntakeMarker, IntakeStateStore } from './intake-state.store';
import {
  isUnderIntakeDomain,
  journalIntakeDomain,
  normalizeIntakeDomain,
} from './journal-intake.config';
import { JournalIntakeCountersService } from './journal-intake-counters.service';
import {
  type IntakeFormat,
  type IntakeMessageOutcome,
  JournalIntakeMetrics,
} from './journal-intake.metrics';
import { JOURNAL_INTAKE_OPTIONS, type JournalIntakeModuleOptions } from './journal-intake.options';
import { JournalIntakeRepository } from './journal-intake.repository';
import { type IntakeSourceSnapshot, JournalIntakeSourceRepository } from './source-snapshot';

/** State of one journal LMTP transaction (MAIL FROM to the reply after DATA). */
export interface IntakeTransaction {
  ref: QueueFileRef<'journal'>;
  envelopeFrom: string;
  clientIp: string | null;
  clientHelo: string | null;
  clientName: string | null;
  /** The one intake recipient of the transaction (D2.5). */
  recipient: IntakeRecipient | null;
}

/** An intake recipient accepted by the writer re-check (D2.5). */
export interface IntakeRecipient {
  address: string;
  addressHash: string;
  snapshot: IntakeSourceSnapshot;
  marker: IntakeMarker;
  network: 'provider_egress' | 'source_networks';
  clientCertMatched: boolean;
}

const MAX_ENVELOPE_FROM = 320;
const MAX_CLIENT_HELO = 255;
const MAX_CLIENT_NAME = 255;
const DELETE_TIMEOUT_MS = 10_000;

/** Ends of one DATA: the reply and what the metrics and counters record. */
interface DataOutcome {
  reply: SmtpReply;
  outcome: IntakeMessageOutcome;
}

/**
 * Journal intake LMTP (step 8.6 D2.4–D2.7, ADR-0087) behind the listener on LMTP_JOURNAL_PORT.
 * Answers only `250` or `451` (never `5xx`, I2):
 *
 * - RCPT: one intake recipient per transaction; the source is re-read on the writer (address
 *   hash, current or unexpired previous) and admitted with the XFORWARD client address and the
 *   TLS / certificate facts of the END-OF-MESSAGE marker (`admitIntakeRecipient`); any failure
 *   is `451`;
 * - DATA, streaming with bounded memory: the raw bytes go through the WP2 journal report
 *   unwrapper (report kinds), the `X-EG-Journal-Token` stripper and into the S3 upload
 *   (`org/<org>/eml/<yyyy>/<mm>/<dd>/<objectRef>.eml`) with its SHA-256; the raw bytes are teed
 *   into the DKIM verifier for Microsoft 365 evidence;
 * - proof (`evaluateIntakeProof`, outer message): `fail` → the upload is aborted and deleted,
 *   nothing is stored, `250 2.0.0 Ok: dropped`; `temperror` → `451`; `pass` → one writer
 *   transaction (`JournalIntakeRepository.commit`), then `250`. A committed ingest key is a
 *   duplicate (`250`).
 *
 * Logs carry the source public id, codes and sizes only, never addresses or subjects.
 */
@Injectable()
export class JournalIntakeService {
  private readonly logger: Logger;
  private readonly domain: string | null;

  constructor(
    @Inject(JOURNAL_INTAKE_OPTIONS) private readonly options: JournalIntakeModuleOptions,
    private readonly sources: JournalIntakeSourceRepository,
    private readonly repository: JournalIntakeRepository,
    private readonly store: EmlStore,
    private readonly state: IntakeStateStore,
    private readonly egress: EgressIndexService,
    private readonly proofs: ProofVerifier,
    private readonly counters: JournalIntakeCountersService,
    private readonly metrics: JournalIntakeMetrics,
  ) {
    this.logger = createLogger({ service: 'smtp-adapter', level: options.logLevel }).child({
      component: 'lmtp-journal',
    });
    this.domain = journalIntakeDomain(options.config);
  }

  handler(): LmtpHandler<IntakeTransaction, IntakeRecipient> {
    return {
      beginTransaction: (client, mailFrom) =>
        Promise.resolve().then(() => this.beginTransaction(client, mailFrom)),
      acceptRecipient: (transaction, address) => this.acceptRecipient(transaction, address),
      handleData: (transaction, recipients, stream) =>
        this.handleData(transaction, recipients, stream),
    };
  }

  beginTransaction(client: LmtpClientInfo, mailFrom: string): IntakeTransaction {
    if (client.queueId === null || client.lhloName === null) {
      this.logger.error(
        { connectionId: client.connectionId },
        'journal LMTP transaction without XFORWARD IDENT or LHLO name; tempfailing',
      );
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    if (mailFrom.length > MAX_ENVELOPE_FROM) {
      this.logger.error({ queueId: client.queueId }, 'envelope sender too long; tempfailing');
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    return {
      ref: { mtaId: client.lhloName, queueId: client.queueId, direction: 'journal' },
      envelopeFrom: mailFrom,
      clientIp: client.clientAddress,
      clientHelo: client.clientHelo === null ? null : client.clientHelo.slice(0, MAX_CLIENT_HELO),
      clientName: client.clientName === null ? null : client.clientName.slice(0, MAX_CLIENT_NAME),
      recipient: null,
    };
  }

  async acceptRecipient(transaction: IntakeTransaction, address: string): Promise<IntakeRecipient> {
    const { queueId } = transaction.ref;
    const at = address.lastIndexOf('@');
    const domain = at > 0 ? normalizeIntakeDomain(address.slice(at + 1)) : '';
    const token = at > 0 ? parseIntakeLocalPart(address.slice(0, at)) : null;
    if (this.domain === null || domain !== this.domain || token === null) {
      this.metrics.refused('lmtp', 'unknown_address');
      this.logger.warn({ queueId }, 'journal LMTP recipient is not an intake address; tempfailing');
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    const addressHash = intakeAddressHash(intakeLocalPart(token));
    if (transaction.recipient !== null) {
      // A case variant of the same address is the same recipient; another one is refused (D2.5).
      if (transaction.recipient.addressHash === addressHash) return transaction.recipient;
      this.metrics.refused('lmtp', 'second_recipient');
      this.logger.warn({ queueId }, 'second intake recipient in one LMTP transaction; tempfailing');
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    const timeout = this.options.config.INGEST_DB_TIMEOUT_MS;
    const now = new Date();
    const [snapshot, marker] = await Promise.all([
      withTimeout(this.sources.loadByAddressHash(addressHash), timeout, 'intake source lookup'),
      this.state.readMarker(queueId),
    ]);
    if (marker === null || snapshot === null || marker.sourceId !== snapshot.source.id) {
      this.metrics.refused('lmtp', snapshot === null ? 'unknown_address' : 'marker_missing');
      this.logger.warn(
        { queueId, sourceId: snapshot?.source.publicId ?? null, marker: marker !== null },
        'journal LMTP recipient without a matching source or END-OF-MESSAGE marker; tempfailing',
      );
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    const admission = admitIntakeRecipient(snapshot, {
      now,
      clientAddress: transaction.clientIp,
      tls: marker.tls,
      certFingerprints: marker.certFingerprints,
      egress: () => this.egress.current(),
    });
    if (!admission.ok) {
      this.metrics.refused('lmtp', admission.refusal);
      if (admission.counter !== null) {
        this.counters.record(
          BigInt(snapshot.source.id),
          {
            counts: { [admission.counter]: 1 },
            refusedAt: now,
            refusalCode: admission.code ?? admission.counter,
          },
          now,
        );
      }
      this.logger.info(
        { queueId, sourceId: snapshot.source.publicId, code: admission.code },
        'journal LMTP re-check refused the recipient; tempfailing',
      );
      throw new LmtpReplyException(LMTP_TEMPFAIL);
    }
    const recipient: IntakeRecipient = {
      address: `${intakeLocalPart(token)}@${domain}`,
      addressHash,
      snapshot,
      marker,
      network: admission.network,
      clientCertMatched: admission.clientCertMatched,
    };
    transaction.recipient = recipient;
    return recipient;
  }

  async handleData(
    transaction: IntakeTransaction,
    recipients: readonly IntakeRecipient[],
    stream: SMTPServerDataStream,
  ): Promise<SmtpReply[]> {
    const recipient = recipients[0];
    if (recipients.length !== 1 || recipient === undefined) {
      throw new Error('journal LMTP transaction must have exactly one recipient');
    }
    const kind = recipient.snapshot.source.kind;
    const startedAt = process.hrtime.bigint();
    let result: DataOutcome;
    try {
      result = await this.ingest(transaction, recipient, stream);
    } catch (err) {
      this.logger.error(
        { err, queueId: transaction.ref.queueId, sourceId: recipient.snapshot.source.publicId },
        'journal intake failed; tempfailing',
      );
      result = { reply: LMTP_TEMPFAIL, outcome: 'tempfail' };
    }
    this.metrics.message(kind, result.outcome);
    this.metrics.transaction(kind, Number(process.hrtime.bigint() - startedAt) / 1e9);
    return [result.reply];
  }

  private async ingest(
    transaction: IntakeTransaction,
    recipient: IntakeRecipient,
    stream: SMTPServerDataStream,
  ): Promise<DataOutcome> {
    const config = this.options.config;
    const { ref } = transaction;
    const { snapshot } = recipient;
    const source = snapshot.source;
    const kind: JournalIntakeKind = source.kind;
    const sourceId = BigInt(source.id);
    const organizationId = BigInt(source.organizationId);
    const attemptAt = new Date();
    const objectKey = emlObjectKey(ref, organizationId, attemptAt);
    const logContext = { queueId: ref.queueId, sourceId: source.publicId, kind };

    // Stored-message pipeline: unwrapper (report kinds) → token stripper → hash, header scan, S3.
    const splitter = isJournalReportKind(kind)
      ? new JournalReportSplitter({ envelopeMaxBytes: config.JOURNAL_INTAKE_ENVELOPE_MAX_BYTES })
      : null;
    const stripper = new HeaderFieldStripper([JOURNAL_TOKEN_HEADER_NAME]);
    const stored = new StoredMessage(config.INGEST_HEADER_MAX_BYTES);
    let upload: EmlUpload | null = null;
    const dkim = kind === 'microsoft_365_journal' ? this.proofs.startDkim(attemptAt) : null;

    const emitStored = async (pieces: readonly Buffer[]) => {
      for (const piece of pieces) {
        for (const out of stripper.push(piece)) {
          stored.push(out);
          await upload?.write(out);
        }
      }
    };
    const sink: MessageSink = {
      get failed() {
        return upload?.failed ?? false;
      },
      write: async (chunk) => emitStored(splitter ? splitter.push(chunk) : [chunk]),
      finish: () => Promise.resolve(),
      abort: (reason) => upload?.abort(reason),
    };

    let outer: HeaderMetadata | null = null;
    const read = await readMessage(stream, {
      headerMaxBytes: config.INGEST_HEADER_MAX_BYTES,
      tee: dkim,
      onHeaders: (headers) => {
        outer = headers;
        upload = this.store.startUpload({
          key: objectKey,
          partSize: config.INGEST_S3_PART_SIZE_BYTES,
          queueSize: config.INGEST_S3_QUEUE_SIZE,
          timeoutMs: config.INGEST_S3_TIMEOUT_MS,
        });
        return sink;
      },
    });
    const outerHeaders = outer as HeaderMetadata | null;
    const activeUpload = upload as EmlUpload | null;
    // Nothing of a discarded message is kept: the upload is aborted before it completes, so no
    // object of this attempt exists (and an object of an earlier, committed attempt of the same
    // queue file is never touched).
    const discard = (reason: string): Promise<void> => {
      dkim?.abort();
      activeUpload?.abort(new Error(reason));
      return Promise.resolve();
    };

    if (read.outcome !== 'complete' || outerHeaders === null || activeUpload === null) {
      if (read.outcome === 'failed') {
        this.logger.error({ err: read.failure, ...logContext }, 'journal intake read failed');
      } else {
        this.logger.warn(
          { ...logContext, reason: read.outcome },
          'journal intake message not read',
        );
      }
      await discard(`message ${read.outcome}`);
      return { reply: LMTP_TEMPFAIL, outcome: 'tempfail' };
    }

    // Flush the pipeline: the unwrapper's tail, then the stripper's.
    try {
      if (splitter) await emitStored(splitter.end());
      for (const out of stripper.end()) {
        stored.push(out);
        await activeUpload.write(out);
      }
    } catch (err) {
      this.logger.error({ err, ...logContext }, 'journal intake pipeline failed; tempfailing');
      await discard('pipeline failed');
      return { reply: LMTP_TEMPFAIL, outcome: 'tempfail' };
    }
    stored.finish();

    // Proof on the outer message (D2.6).
    const dkimRun = dkim ? await dkim.finish() : null;
    const proof = evaluateIntakeProof(
      {
        kind,
        network: recipient.network,
        tls: recipient.marker.tls,
        clientCertMatched: recipient.clientCertMatched,
        headerBlockComplete: outerHeaders.complete,
        tenantHeaderValues: outerHeaders.crossTenantIds ?? [],
        headerTokens: outerHeaders.journalTokens ?? [],
        dkim:
          dkimRun === null
            ? null
            : dkimRun.ok
              ? { signatures: dkimRun.signatures, verifierError: false }
              : { signatures: [], verifierError: true },
      },
      {
        expectedTenantId: snapshot.connection?.externalTenantId ?? null,
        linkedDomains: snapshot.connection?.linkedDomains ?? [],
        headerTokenSha256: source.headerTokenHash,
        previousHeaderTokenSha256: source.previousHeaderTokenHash,
        previousValidUntil: source.previousValidUntil ? new Date(source.previousValidUntil) : null,
        now: attemptAt,
      },
    );
    this.metrics.proofResult(kind, proof.failedRule ?? 'none', proof.result);
    if (proof.result !== 'pass') return this.proofFailed(proof, sourceId, logContext, discard);

    try {
      await activeUpload.finish();
    } catch (err) {
      this.logger.error({ err, ...logContext }, 'journal intake upload to S3 failed; tempfailing');
      return { reply: LMTP_TEMPFAIL, outcome: 'tempfail' };
    }

    const decision = splitter?.decision ?? null;
    const format: IntakeFormat =
      splitter === null ? 'copy' : (decision?.format ?? 'journal_report_unparsed');
    const unwrapResult = splitter === null ? 'ok' : (decision?.reason ?? 'ok');
    const storedHeaders = stored.headers();
    const envelope = this.envelopeOf(
      transaction,
      kind,
      decision,
      storedHeaders,
      stored.headerBlock(),
    );

    const deletions: string[] = [];
    const ingest = ingestKey(ref, read.sha256, [recipient.address]);
    const outcome = await this.commit({
      transaction,
      recipient,
      ingest,
      objectKey,
      format,
      envelope,
      proofDocument: journalIntakeProofSchema.parse(proof.document),
      storedHeaders,
      storedSha256: stored.sha256(),
      storedBytes: stored.bytes,
      reportSha256: read.sha256,
      reportBytes: read.bytes,
      deletions,
      logContext,
    });
    for (const key of deletions) await this.deleteObject(key, logContext);

    const now = new Date();
    if (outcome.outcome === 'accepted') {
      this.metrics.unwrapped(format, unwrapResult);
      this.metrics.accepted(kind, read.bytes);
      this.counters.record(
        sourceId,
        {
          counts: {
            accepted: 1,
            bytes: read.bytes,
            ...(format === 'journal_report_unparsed' ? { unwrap_failed: 1 } : {}),
          },
          acceptedAt: now,
        },
        now,
      );
    } else if (outcome.outcome === 'duplicate') {
      this.counters.record(sourceId, { counts: { duplicates: 1 }, acceptedAt: now }, now);
    }
    return outcome;
  }

  private async proofFailed(
    proof: IntakeProofOutcome,
    sourceId: bigint,
    logContext: Record<string, unknown>,
    discard: (reason: string) => Promise<void>,
  ): Promise<DataOutcome> {
    await discard(`journal intake proof ${proof.result}`);
    if (proof.result === 'temperror') {
      this.logger.warn(
        { ...logContext, rule: proof.failedRule, code: proof.failureCode },
        'journal intake proof could not be checked; tempfailing',
      );
      return { reply: LMTP_TEMPFAIL, outcome: 'tempfail' };
    }
    // D2.7 accept-and-drop: nothing stored, no DSN to an envelope sender we cannot trust.
    const now = new Date();
    this.counters.record(
      sourceId,
      {
        counts: { dropped_proof: 1 },
        refusedAt: now,
        refusalCode: `proof_${proof.failedRule ?? 'unknown'}`,
      },
      now,
    );
    this.logger.info(
      { ...logContext, rule: proof.failedRule, code: proof.failureCode },
      'journal intake proof failed; message dropped',
    );
    return { reply: LMTP_INTAKE_DROPPED, outcome: 'dropped' };
  }

  /** `journal-envelope/1` of the stored message (D2.6), without intake-domain recipients. */
  private envelopeOf(
    transaction: IntakeTransaction,
    kind: JournalIntakeKind,
    decision: JournalReportSplitter['decision'],
    storedHeaders: HeaderMetadata,
    storedHeaderBlock: Buffer,
  ): JournalEnvelope {
    // Parsed at the schema bound; intake-domain addresses removed; then JOURNAL_INTAKE_MAX_RECIPIENTS.
    let envelope: JournalEnvelope;
    if (decision?.format === 'journal_report') {
      envelope = parseJournalEnvelope(decision.envelopeText, {
        maxRecipients: JOURNAL_ENVELOPE_MAX_RECIPIENTS,
        embeddedMessageId: storedHeaders.messageId,
      });
    } else {
      // Copies, and reports stored as received (unparsed): the header recipients of the stored
      // message (Google: X-Gm-Original-To first), the envelope sender from MAIL FROM.
      envelope = buildCopyEnvelope({
        kind: kind === 'google_workspace_copy' ? 'google_workspace_copy' : 'smtp_bcc',
        headerBlock: storedHeaderBlock,
        mailFrom: transaction.envelopeFrom === '' ? null : transaction.envelopeFrom,
        maxRecipients: JOURNAL_ENVELOPE_MAX_RECIPIENTS,
      });
    }
    // An intake address is never a party of the archived message.
    const parties = envelope.recipients.filter((r) => {
      const at = r.address.lastIndexOf('@');
      return !isUnderIntakeDomain(r.address.slice(at + 1), this.domain);
    });
    const cap = this.options.config.JOURNAL_INTAKE_MAX_RECIPIENTS;
    const recipients = parties.slice(0, cap);
    const truncated = envelope.truncated || parties.length > cap;
    return journalEnvelopeSchema.parse({ ...envelope, recipients, truncated });
  }

  private async commit(input: {
    transaction: IntakeTransaction;
    recipient: IntakeRecipient;
    ingest: string;
    objectKey: string;
    format: IntakeFormat;
    envelope: JournalEnvelope;
    proofDocument: ReturnType<typeof journalIntakeProofSchema.parse>;
    storedHeaders: HeaderMetadata;
    storedSha256: string;
    storedBytes: number;
    reportSha256: string;
    reportBytes: number;
    deletions: string[];
    logContext: Record<string, unknown>;
  }): Promise<DataOutcome> {
    const { transaction, recipient, logContext } = input;
    const config = this.options.config;
    const snapshot = recipient.snapshot;
    const organizationId = BigInt(snapshot.source.organizationId);

    try {
      const committed = await withTimeout(
        this.repository.findCommitted(organizationId, input.ingest),
        config.INGEST_DB_TIMEOUT_MS,
        'duplicate pre-check',
      );
      if (committed) {
        if (committed.emlObjectKey !== input.objectKey) input.deletions.push(input.objectKey);
        this.logger.info(
          { ...logContext, messageId: committed.messageId.toString() },
          'duplicate journal LMTP delivery; already committed',
        );
        return { reply: LMTP_OK, outcome: 'duplicate' };
      }
    } catch (err) {
      this.logger.error({ err, ...logContext }, 'duplicate pre-check failed; tempfailing');
      return { reply: LMTP_TEMPFAIL, outcome: 'tempfail' };
    }

    const parties = classifyIntakeParties({
      sender: input.envelope.sender ?? (transaction.envelopeFrom || null),
      headerFrom: input.storedHeaders.from,
      recipients: input.envelope.recipients,
      orgDomains: snapshot.domains.map((d) => d.name),
    });
    const domainId = this.domainIdOf(snapshot, parties.orgSideDomain);
    const receivedAt = new Date();
    try {
      const { messageId } = await withTimeout(
        this.repository.commit(
          {
            organizationId,
            domainId,
            ingestKey: input.ingest,
            receivedAt,
            direction: parties.direction,
            envelopeFrom: transaction.envelopeFrom,
            internetMessageId: input.storedHeaders.messageId,
            headerFrom: input.storedHeaders.from,
            subject: input.storedHeaders.subject,
            sizeBytes: input.storedBytes,
            emlObjectKey: input.objectKey,
            emlSha256: input.storedSha256,
            clientIp: transaction.clientIp,
            clientHelo: transaction.clientHelo,
            clientName: transaction.clientName,
            queueId: transaction.ref.queueId,
            recipients: parties.recipients.map((r) => ({
              address: r.address,
              direction: r.direction,
            })),
            source: {
              id: BigInt(snapshot.source.id),
              publicId: snapshot.source.publicId,
              kind: snapshot.source.kind,
            },
            format: input.format,
            envelope: input.envelope,
            proof: input.proofDocument,
            reportSha256: input.reportSha256,
            reportSizeBytes: input.reportBytes,
          },
          config.INGEST_DB_TIMEOUT_MS,
        ),
        config.INGEST_DB_TIMEOUT_MS * 2,
        'journal intake transaction',
      );
      this.logger.info(
        {
          ...logContext,
          messageId: messageId.toString(),
          outcome: 'stored',
          format: input.format,
          recipients: parties.recipients.length,
          truncated: input.envelope.truncated,
          sizeBytes: input.storedBytes,
        },
        'journal intake message stored',
      );
      return { reply: LMTP_OK, outcome: 'accepted' };
    } catch (err) {
      if (isUniqueViolation(err)) {
        try {
          const winner = await this.repository.findCommitted(organizationId, input.ingest);
          if (winner && winner.emlObjectKey !== input.objectKey)
            input.deletions.push(input.objectKey);
        } catch (lookupErr) {
          this.logger.warn({ err: lookupErr, ...logContext }, 'duplicate lookup failed');
        }
        return { reply: LMTP_OK, outcome: 'duplicate' };
      }
      this.logger.error({ err, ...logContext }, 'journal intake transaction failed; tempfailing');
      return { reply: LMTP_TEMPFAIL, outcome: 'tempfail' };
    }
  }

  /** D3 `domain_id`: the org-side party's domain, else the lowest-id verified domain, else null. */
  private domainIdOf(snapshot: IntakeSourceSnapshot, orgSideDomain: string | null): bigint | null {
    const match =
      (orgSideDomain !== null && snapshot.domains.find((d) => d.name === orgSideDomain)) ||
      snapshot.domains.find((d) => d.status === 'verified' || d.status === 'active') ||
      null;
    return match ? BigInt(match.id) : null;
  }

  private async deleteObject(key: string, logContext: Record<string, unknown>): Promise<void> {
    try {
      await this.store.delete(key, DELETE_TIMEOUT_MS);
    } catch (err) {
      this.logger.warn(
        { err, ...logContext },
        'could not delete a discarded journal intake object',
      );
    }
  }
}

/** The stored bytes as they leave the pipeline: SHA-256, size and the bounded header block. */
class StoredMessage {
  private readonly hash = createHash('sha256');
  private readonly scanner: HeaderScanner;
  private readonly block: Buffer[] = [];
  private blockBytes = 0;
  bytes = 0;

  constructor(private readonly headerMaxBytes: number) {
    this.scanner = new HeaderScanner(headerMaxBytes);
  }

  push(chunk: Buffer): void {
    if (chunk.length === 0) return;
    this.hash.update(chunk);
    this.bytes += chunk.length;
    if (!this.scanner.done) {
      this.scanner.push(chunk);
      if (this.blockBytes < this.headerMaxBytes) {
        const piece = chunk.subarray(0, this.headerMaxBytes - this.blockBytes);
        this.block.push(Buffer.from(piece));
        this.blockBytes += piece.length;
      }
    }
  }

  finish(): void {
    this.scanner.finish();
  }

  sha256(): string {
    return this.hash.digest('hex');
  }

  headers(): HeaderMetadata {
    return this.scanner.result();
  }

  headerBlock(): Buffer {
    return Buffer.concat(this.block);
  }
}
