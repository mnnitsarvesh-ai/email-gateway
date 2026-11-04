import { Inject, Injectable } from '@nestjs/common';
import {
  type Counter,
  countGatewayPasses,
  MetricsService,
  PrismaService,
} from '@email-gateway/common';
import { resolveDomainOwner } from '@email-gateway/database';
import { createLogger, type Logger } from '@email-gateway/logger';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';
import {
  classifyDeliveryError,
  type DeliveryStatus,
  dsnSignalKey,
  recordDeliverySignal,
  reinjectionToken,
} from '@email-gateway/mail-routing';
import type { SMTPServerDataStream } from 'smtp-server';
import type { LmtpClientInfo, LmtpHandler } from '../lmtp/lmtp-listener';
import { LmtpReplyException } from '../lmtp/lmtp-reply';
import { withTimeout } from '../lmtp/timeout';
import {
  LMTP_BOUNCE_SENDER_REFUSED,
  LMTP_OK,
  LMTP_TEMPFAIL,
  LMTP_UNKNOWN_RECIPIENT,
  type SmtpReply,
} from '../shared/replies';
import { lifecycleMetrics } from '../shared/lifecycle-metrics';
import { ReputationRecorder } from '../shared/reputation';
import { bounceDedupeKey, classifyBounce } from './bounce-classifier';
import { BOUNCES_OPTIONS, type BouncesModuleOptions } from './bounces.options';
import { BouncesRepository, type MatchedReinjection } from './bounces.repository';
import { type DsnNotice, type DsnRecipient, parseDsnNotice } from './dsn-parser';

/** Local part of the bounce-notice recipient (postfix-outbound `*_notice_recipient`). */
export const BOUNCE_NOTICE_LOCAL_PART = 'bounce-notices';
/** Budget of each lookup and per-recipient transaction. */
export const BOUNCE_DB_TIMEOUT_MS = 15_000;
/** Postfix `double_bounce_sender` (default): the envelope sender of postmaster copies. */
export const DOUBLE_BOUNCE_LOCAL_PART = 'double-bounce';
/** `email_events.source_service` of the delivery signals recorded here. */
export const BOUNCE_SIGNAL_SOURCE_SERVICE = 'smtp-adapter';

/** The `Diagnostic-Code` text after its type (`smtp; 550 …` → `550 …`), for classification. */
export function diagnosticText(recipient: DsnRecipient): string {
  const value = recipient.diagnosticCode ?? '';
  const semicolon = value.indexOf(';');
  return (semicolon === -1 ? value : value.slice(semicolon + 1)).trim();
}

/**
 * Delivery status of a notice recipient (step 2.3 R9): `failed` + `5.x.x` (or no status) →
 * `bounced`; `failed` + `4.x.x` (Postfix gave up after transient errors) → `expired`;
 * `delayed` → `deferred`; anything else → null (no signal).
 */
export function noticeDeliveryStatus(recipient: DsnRecipient): DeliveryStatus | null {
  if (recipient.action === 'delayed') return 'deferred';
  if (recipient.action !== 'failed') return null;
  return recipient.status?.startsWith('4.') === true ? 'expired' : 'bounced';
}

export type BounceNoticeOutcome =
  'recorded' | 'duplicate' | 'ignored' | 'unparseable' | 'tempfail' | 'refused';

interface BounceTransaction {
  queueId: string | null;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Bounce handler (step 2.2 D13): postmaster copies of postfix-outbound's DSNs arrive over LMTP
 * `:10052`; failed and delayed recipients become `bounce_events`, address failures become
 * `hard_bounce` suppressions, and newly recorded bounces count as reputation events.
 */
@Injectable()
export class BounceNoticeService {
  private readonly logger: Logger;
  private readonly notices: Counter<'outcome'>;
  private readonly lifecycleMetrics: LifecycleMetrics;
  private readonly recipientAddress: string;
  private readonly doubleBounceSender: string;

  constructor(
    @Inject(BOUNCES_OPTIONS) private readonly options: BouncesModuleOptions,
    private readonly prisma: PrismaService,
    private readonly repository: BouncesRepository,
    private readonly reputation: ReputationRecorder,
    metrics: MetricsService,
  ) {
    this.logger = createLogger({ service: 'smtp-adapter', level: options.logLevel }).child({
      component: 'lmtp-bounces',
    });
    this.notices = metrics.counter(
      'smtp_bounce_notices_total',
      'Bounce notices (postmaster DSN copies) handled, by outcome; outcome="matched" also counts ' +
        'every notice matched to a reinjection (in addition to its final outcome)',
      ['outcome'],
    );
    this.lifecycleMetrics = lifecycleMetrics(metrics);
    this.recipientAddress = `${BOUNCE_NOTICE_LOCAL_PART}@${options.config.POSTFIX_BOUNCE_DOMAIN}`;
    this.doubleBounceSender =
      `${DOUBLE_BOUNCE_LOCAL_PART}@${options.config.POSTFIX_OUTBOUND_MYHOSTNAME}`.toLowerCase();
  }

  handler(): LmtpHandler<BounceTransaction, string> {
    return {
      beginTransaction: (client: LmtpClientInfo, mailFrom: string) =>
        Promise.resolve().then(() => this.beginTransaction(client, mailFrom)),
      acceptRecipient: (_transaction, address) =>
        Promise.resolve().then(() => this.acceptRecipient(address)),
      handleData: async (transaction, recipients, stream) => {
        const reply = await this.handleNotice(stream, transaction);
        return recipients.map(() => reply);
      },
    };
  }

  /**
   * Postfix's bounce daemon sends postmaster copies from `double-bounce@$myhostname` (delay and
   * bounce copies) or the null sender. Anything else was not generated by postfix-outbound's
   * bounce daemon (defence in depth behind the policy's refusal of the bounce-notice domain).
   */
  beginTransaction(client: LmtpClientInfo, mailFrom: string): BounceTransaction {
    const sender = mailFrom.toLowerCase();
    if (sender !== '' && sender !== this.doubleBounceSender) {
      this.notices.inc({ outcome: 'refused' });
      this.logger.warn(
        { lmtpQueueId: client.queueId, peer: client.peerAddress },
        'bounce notice from a sender other than the bounce daemon; refused',
      );
      throw new LmtpReplyException(LMTP_BOUNCE_SENDER_REFUSED);
    }
    return { queueId: client.queueId };
  }

  acceptRecipient(address: string): string {
    const normalized = address.toLowerCase();
    if (normalized !== this.recipientAddress) {
      throw new LmtpReplyException(LMTP_UNKNOWN_RECIPIENT);
    }
    return normalized;
  }

  private async handleNotice(
    stream: SMTPServerDataStream,
    transaction: BounceTransaction,
  ): Promise<SmtpReply> {
    const limit = this.options.config.BOUNCE_MAX_MESSAGE_BYTES;
    const chunks: Buffer[] = [];
    let size = 0;
    let oversized = false;
    try {
      for await (const raw of stream as AsyncIterable<unknown>) {
        const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
        size += chunk.length;
        if (size > limit) {
          oversized = true;
          chunks.length = 0;
          continue;
        }
        chunks.push(chunk);
      }
    } catch {
      return this.finish('tempfail', transaction, 'notice connection aborted');
    }
    if (oversized) {
      return this.finish(
        'unparseable',
        transaction,
        'bounce notice exceeds BOUNCE_MAX_MESSAGE_BYTES',
      );
    }
    const outcome = await this.process(Buffer.concat(chunks), transaction);
    return this.finish(outcome, transaction);
  }

  private finish(
    outcome: BounceNoticeOutcome,
    transaction: BounceTransaction,
    reason?: string,
  ): SmtpReply {
    this.notices.inc({ outcome });
    if (outcome === 'unparseable') {
      this.logger.warn({ lmtpQueueId: transaction.queueId, reason }, 'unparseable bounce notice');
    }
    return outcome === 'tempfail' ? LMTP_TEMPFAIL : LMTP_OK;
  }

  /** Parses and records one notice. Exposed for tests. */
  async process(raw: Buffer, transaction: BounceTransaction): Promise<BounceNoticeOutcome> {
    let notice: DsnNotice | null;
    try {
      notice = await parseDsnNotice(raw);
    } catch (err) {
      this.logger.warn({ err, lmtpQueueId: transaction.queueId }, 'bounce notice parse error');
      return 'unparseable';
    }
    if (!notice || notice.queueId === null || notice.occurredAt === null) return 'unparseable';
    const queueId = notice.queueId;
    const occurredAt = notice.occurredAt;
    const classified = notice.recipients.flatMap((recipient) => {
      const classification = classifyBounce(recipient);
      return classification ? [{ recipient, classification }] : [];
    });
    if (notice.recipients.length === 0) return 'unparseable';
    if (classified.length === 0) {
      this.logger.debug({ queueId }, 'bounce notice without failed/delayed recipients; ignored');
      return 'ignored';
    }

    // Step 2.3 R9: the delivery status of the reinjection this notice belongs to (any direction).
    let reinjection: MatchedReinjection | null;
    try {
      reinjection = await withTimeout(
        this.repository.findReinjection(queueId, notice.envelopeId),
        BOUNCE_DB_TIMEOUT_MS,
        'bounce reinjection lookup',
      );
    } catch (err) {
      this.logger.error({ err, queueId }, 'bounce reinjection lookup failed; tempfailing');
      return 'tempfail';
    }
    let signalsApplied = 0;
    if (reinjection) {
      this.notices.inc({ outcome: 'matched' });
      try {
        signalsApplied = await this.recordSignals(notice, queueId, reinjection, classified);
      } catch (err) {
        this.logger.error(
          { err, queueId, reinjectionId: reinjection.id.toString() },
          'delivery status from a bounce notice failed; tempfailing',
        );
        return 'tempfail';
      }
      if (reinjection.direction !== 'outbound') {
        // Inbound and internal deliveries: no bounce_events, suppressions or reputation.
        return signalsApplied > 0 ? 'recorded' : 'duplicate';
      }
    }
    if (!notice.sender) {
      this.logger.debug({ queueId }, 'bounce notice without a tenant sender; ignored');
      return reinjection && signalsApplied > 0 ? 'recorded' : 'ignored';
    }

    const senderDomain = notice.sender.slice(notice.sender.lastIndexOf('@') + 1);
    let owner;
    try {
      owner = await withTimeout(
        resolveDomainOwner(this.prisma, senderDomain),
        BOUNCE_DB_TIMEOUT_MS,
        'bounce sender owner lookup',
      );
    } catch (err) {
      this.logger.error({ err, queueId }, 'bounce owner lookup failed; tempfailing');
      return 'tempfail';
    }
    if (!owner) {
      // E.g. an unmatched reinject-inbound failure: the sender is external.
      this.logger.info({ queueId, senderDomain }, 'bounce notice for a non-tenant sender; ignored');
      return reinjection && signalsApplied > 0 ? 'recorded' : 'ignored';
    }

    const organizationId = owner.organizationId;
    // Only mail the gateway itself reinjected for delivery (10027, which carries an outbound
    // X-Gateway-Trace of the organization, D14) says anything about the tenant's deliverability.
    // Failures of the ingestion hop on postfix-outbound (content_filter LMTP 10051: the From
    // check, the loop check, an adapter/S3/DB outage longer than delay_warning_time) have no
    // such trace and are not tenant bounces (review finding, §12.7). The HMAC also binds the
    // notice to the organization: a notice naming another tenant's sender domain cannot carry
    // that tenant's valid trace.
    const passes = countGatewayPasses(notice.originalTraces, {
      secret: this.options.config.GATEWAY_TRACE_SECRET,
      gatewayId: this.options.config.GATEWAY_TRACE_ID,
      organizationId,
      direction: 'out',
    });
    if (passes === 0) {
      this.logger.info(
        { queueId, organizationId: organizationId.toString() },
        'bounce notice for mail the gateway did not deliver (no outbound trace); ignored',
      );
      return reinjection && signalsApplied > 0 ? 'recorded' : 'ignored';
    }
    // The message reference only when the reinjection belongs to the same organization.
    const message =
      reinjection && reinjection.organizationId === organizationId
        ? { messageId: reinjection.messageId, messageReceivedAt: reinjection.receivedAt }
        : { messageId: null, messageReceivedAt: null };

    const suppressUntil = new Date(
      Date.now() + this.options.config.SUPPRESSION_HARD_BOUNCE_DAYS * DAY_MS,
    );
    let inserted = 0;
    for (const { recipient, classification } of classified) {
      let result;
      try {
        result = await withTimeout(
          this.repository.record(
            {
              organizationId,
              occurredAt,
              recipientAddress: recipient.finalRecipient,
              bounceType: classification.bounceType,
              smtpCode: recipient.smtpCode,
              enhancedStatus: recipient.status,
              diagnostic: recipient.diagnosticCode,
              reportingMta: notice.reportingMta,
              dedupeKey: bounceDedupeKey(queueId, recipient),
              suppressUntil: classification.suppress ? suppressUntil : null,
              ...message,
            },
            BOUNCE_DB_TIMEOUT_MS,
          ),
          BOUNCE_DB_TIMEOUT_MS * 2,
          'bounce transaction',
        );
      } catch (err) {
        // Recipients already committed are deduplicated when Postfix redelivers the notice.
        this.logger.error(
          { err, queueId, organizationId: organizationId.toString() },
          'bounce transaction failed; tempfailing the notice',
        );
        return 'tempfail';
      }
      if (result.inserted) {
        inserted += 1;
        await this.reputation.record(organizationId, classification.reputationEvent);
      }
      this.logger.info(
        {
          queueId,
          organizationId: organizationId.toString(),
          recipientDomain: recipient.finalRecipient.slice(
            recipient.finalRecipient.lastIndexOf('@') + 1,
          ),
          action: recipient.action,
          status: recipient.status,
          bounceType: classification.bounceType,
          recorded: result.inserted,
          suppression: result.suppression,
        },
        'bounce recorded',
      );
    }
    return inserted > 0 || signalsApplied > 0 ? 'recorded' : 'duplicate';
  }

  /**
   * One `bounce_notice` signal per failed or delayed recipient (step 2.3 R9) through the shared
   * recorder, matched by the reinjection's token and the address, so the organization and the
   * delivery always come from the reinjection row. Signal key = `dsn|queue|address|action|
   * status|arrival` (the inputs of the 2.2 bounce dedupe key): a redelivered notice is a
   * `duplicate`. The recorder also derives the message lifecycle state (step 3.3 L9, e.g. the
   * last recipient bouncing moves the message to `rejected/delivery_failed`), counted on the
   * shared `lifecycle_*` series. Returns the number of applied transitions; database errors
   * propagate.
   */
  private async recordSignals(
    notice: DsnNotice,
    queueId: string,
    reinjection: MatchedReinjection,
    classified: readonly { recipient: DsnRecipient }[],
  ): Promise<number> {
    const token = reinjectionToken(reinjection.publicId);
    const arrival = notice.occurredAt!;
    const occurredAt = notice.noticeDate ?? new Date();
    let applied = 0;
    for (const { recipient } of classified) {
      const status = noticeDeliveryStatus(recipient);
      if (status === null) continue;
      const result = await withTimeout(
        recordDeliverySignal(
          this.prisma,
          {
            match: { token, address: recipient.finalRecipient },
            status,
            occurredAt,
            source: 'bounce_notice',
            signalKey: dsnSignalKey({
              queueId,
              address: recipient.finalRecipient,
              action: recipient.action,
              status: recipient.status,
              arrivalDate: arrival,
            }),
            smtpCode: recipient.smtpCode,
            enhancedStatus: recipient.status,
            errorClass: classifyDeliveryError(diagnosticText(recipient), recipient.status),
            detail: recipient.diagnosticCode,
            queueId,
          },
          {
            sourceService: BOUNCE_SIGNAL_SOURCE_SERVICE,
            timeoutMs: BOUNCE_DB_TIMEOUT_MS,
            logger: this.logger,
            lifecycleMetrics: this.lifecycleMetrics,
          },
        ),
        BOUNCE_DB_TIMEOUT_MS * 2,
        'bounce delivery signal',
      );
      if (result.result === 'applied') applied += 1;
      this.logger.info(
        {
          queueId,
          reinjectionId: reinjection.id.toString(),
          matchedBy: reinjection.matchedBy,
          organizationId: reinjection.organizationId.toString(),
          deliveryId: result.deliveryId?.toString() ?? null,
          direction: reinjection.direction,
          action: recipient.action,
          status: recipient.status,
          signal: status,
          result: result.result,
          messageState: result.messageState ?? null,
        },
        'bounce notice delivery signal',
      );
    }
    return applied;
  }
}
