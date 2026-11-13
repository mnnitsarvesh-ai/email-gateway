import { NonRetryableError } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { EventEnvelope, PolicyNotificationRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { NoticeMailer } from './mailer';
import type { NotificationMetrics, NoticeResult } from './notification-metrics';
import type { NotificationReads } from './notification-reads';
import type { PreferenceFilter } from './preference-filter';
import {
  noticeMessageId,
  type NoticeFacts,
  renderPolicyAlert,
  renderSenderNonDelivery,
} from './templates';

/** The ledger consumer of `email.notifications` (topology v9, P15). */
export const POLICY_NOTIFICATION_CONSUMER = 'notification-worker.policy';

export interface PolicyNotificationOptions {
  maxRecipients: number;
  portalUrl: string;
}

/** Lower-cased address and its domain, or null when it is not `local@domain`. */
export function addressDomain(raw: string): { address: string; domain: string } | null {
  const address = raw.trim().toLowerCase();
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1 || /[\s<>,;]/.test(address)) return null;
  return { address, domain: address.slice(at + 1).replace(/\.$/, '') };
}

/**
 * Handles one `mail.policy.notification_requested.v1` (step 5.2 P25) inside the consumer's
 * idempotency transaction (`processOnceHandler`, ledger `notification-worker.policy`): resolves
 * the recipients on the writer (`policy_alert`: the organization's policy administrators minus
 * those who opted out of `policy_alert`, step 6.2 N4;
 * `sender_non_delivery`: the message's envelope sender, only when its domain is an active domain
 * of the organization, never an external address), renders a fixed plain-text notice without
 * message content and sends it through the relay with a deterministic Message-ID. The send runs
 * before the ledger commits, so a crash between them may send twice (at least once, same
 * Message-ID). A relay failure is thrown (retryable: the topology retries, then dead-letters).
 * `alerts.enabled` is evaluated by the policy-engine (an ALERT it records is never requested).
 */
export class PolicyNotificationHandler {
  constructor(
    private readonly reads: NotificationReads,
    private readonly mailer: NoticeMailer,
    private readonly metrics: NotificationMetrics,
    private readonly logger: Logger,
    private readonly options: PolicyNotificationOptions,
    private readonly preferences: PreferenceFilter,
  ) {}

  async handle(
    event: EventEnvelope<PolicyNotificationRequestedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<NoticeResult> {
    const p = event.payload;
    const kind = p.kind;
    const organizationId = BigInt(event.organizationId);
    const log = this.logger.child({
      eventId: event.eventId,
      organizationId: event.organizationId,
      kind,
    });
    const message = await this.reads.message(
      tx,
      organizationId,
      BigInt(p.messageId),
      new Date(p.receivedAt),
    );
    if (message === null) {
      // Committed with the evaluation that requested it: missing = purged or a defect.
      this.count(kind, 'failed');
      throw new NonRetryableError('message_not_found');
    }
    const recipients = await this.recipients(tx, organizationId, p, message.envelopeFrom);
    if (recipients.length === 0) {
      this.count(kind, 'no_recipients');
      log.info({ message: 'policy notice has no recipient' });
      return 'no_recipients';
    }
    if (!this.mailer.configured || this.mailer.from === null) {
      this.count(kind, 'disabled');
      log.warn({ message: 'policy notice not sent: no relay configured (NOTIFY_SMTP_HOST)' });
      return 'disabled';
    }
    const facts: NoticeFacts = {
      organizationName: (await this.reads.organizationName(tx, organizationId)) ?? '',
      messagePublicId: message.publicId ?? p.messageId,
      receivedAt: message.receivedAt.toISOString(),
      direction: p.direction,
      disposition: p.disposition,
      severity: p.severity,
      decisive: p.decisive,
      policyName:
        p.decisive.policyId === null
          ? null
          : await this.reads.policyName(tx, organizationId, p.decisive.policyId),
      portalUrl: this.options.portalUrl,
      internetMessageId: message.internetMessageId,
      recipientCount: message.recipientCount,
    };
    const notice =
      kind === 'policy_alert' ? renderPolicyAlert(facts) : renderSenderNonDelivery(facts);
    const stop = this.metrics.sendDuration.startTimer({ kind });
    try {
      await this.mailer.send({
        recipients,
        subject: notice.subject,
        text: notice.text,
        messageId: noticeMessageId(event.eventId, this.mailer.from),
      });
    } catch (error) {
      this.count(kind, 'failed');
      log.warn({
        message: 'policy notice send failed (retried)',
        responseCode: (error as { responseCode?: number }).responseCode,
      });
      throw error;
    } finally {
      stop();
    }
    this.count(kind, 'sent');
    log.info({ message: 'policy notice sent', recipientCount: recipients.length });
    return 'sent';
  }

  private async recipients(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    p: PolicyNotificationRequestedV1,
    envelopeFrom: string,
  ): Promise<string[]> {
    if (p.kind === 'policy_alert') {
      const { emails } = await this.preferences.collect(
        tx,
        organizationId,
        'policy_alert',
        (afterId, take) => this.reads.alertRecipients(tx, organizationId, take, afterId),
        this.options.maxRecipients,
      );
      return emails;
    }
    // Sender notice: only the organization's own sender (P25), never an external address.
    if (p.direction === 'inbound' || p.disposition !== 'reject') return [];
    const sender = addressDomain(envelopeFrom);
    if (sender === null) return [];
    return (await this.reads.activeDomain(tx, organizationId, sender.domain))
      ? [sender.address]
      : [];
  }

  private count(kind: PolicyNotificationRequestedV1['kind'], result: NoticeResult): void {
    this.metrics.messages.inc({ kind, result });
  }
}
