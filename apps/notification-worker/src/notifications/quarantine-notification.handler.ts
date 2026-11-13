import { NonRetryableError } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type {
  EventEnvelope,
  QuarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { NoticeMailer } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import type { NotificationReads } from './notification-reads';
import { addressDomain } from './policy-notification.handler';
import type { PreferenceFilter } from './preference-filter';
import type { QuarantineNotificationReads } from './quarantine-reads';
import {
  quarantineNoticeMessageId,
  renderAdminAlert,
  renderApprovalDecided,
  renderApprovalRequested,
  renderReleaseBlocked,
  renderSenderRejected,
  renderUserDigest,
} from './quarantine-templates';
import type { RenderedNotice } from './templates';

export type QuarantineNoticeKind = QuarantineNotificationRequestedV1['kind'];
/** `notification_quarantine_messages_total{result}`. */
export type QuarantineNoticeResult =
  'sent' | 'no_recipients' | 'no_entries' | 'not_applicable' | 'disabled' | 'failed';

export interface QuarantineNotificationOptions {
  maxRecipients: number;
  portalUrl: string;
  now?: () => Date;
}

/**
 * Handles one `mail.quarantine.notification_requested.v1` (step 5.3 Q16, Q20) inside the
 * consumer's idempotency transaction (ledger `notification-worker.policy`): resolves what to say
 * and to whom on the writer **at send time**, renders a fixed plain-text notice (no body,
 * attachment or URL of any message) and sends it through the relay with the deterministic
 * Message-ID `<quarantine-notice.<eventId>@<from domain>>` (at least once):
 *
 * - `user_digest` → the digest's user (active, verified, not opted out, `endUser.enabled`):
 *   their `held`/`pending_approval` entries of the window (≤ `digest.maxEntries`; sender,
 *   subject only with `digest.includeSubject`, reason, expiry, portal link);
 * - `approval_requested` → users holding `quarantine:approve`, never the requester(s), minus
 *   users who opted out of `quarantine_approval_requested` (step 6.2 N4),
 *   ≤ NOTIFICATION_MAX_RECIPIENTS, Bcc;
 * - `approval_decided`, `release_blocked` → the requesting user (API keys get none);
 * - `admin_alert` → as `approval_requested` (opt-out kind `quarantine_admin_alert`), counts and
 *   a link;
 * - `sender_rejected` → the envelope sender of an outbound/internal message, only when its
 *   domain is an active domain of the organization; never for inbound mail (no backscatter).
 *
 * A relay failure is thrown (retryable); a missing referenced row is dead-lettered.
 */
export class QuarantineNotificationHandler {
  private readonly now: () => Date;

  constructor(
    private readonly reads: QuarantineNotificationReads,
    private readonly common: Pick<
      NotificationReads,
      'organizationName' | 'message' | 'activeDomain'
    >,
    private readonly mailer: NoticeMailer,
    private readonly metrics: NotificationMetrics,
    private readonly logger: Logger,
    private readonly options: QuarantineNotificationOptions,
    private readonly preferences: PreferenceFilter,
  ) {
    this.now = options.now ?? (() => new Date());
  }

  async handle(
    event: EventEnvelope<QuarantineNotificationRequestedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<QuarantineNoticeResult> {
    const p = event.payload;
    const kind = p.kind;
    const organizationId = BigInt(event.organizationId);
    const log = this.logger.child({
      eventId: event.eventId,
      organizationId: event.organizationId,
      kind,
    });
    const built = await this.build(tx, organizationId, p);
    if ('skip' in built) {
      this.count(kind, built.skip);
      log.info({ message: 'quarantine notice not sent', result: built.skip });
      return built.skip;
    }
    if (!this.mailer.configured || this.mailer.from === null) {
      this.count(kind, 'disabled');
      log.warn({ message: 'quarantine notice not sent: no relay configured (NOTIFY_SMTP_HOST)' });
      return 'disabled';
    }
    const stop = this.metrics.sendDuration.startTimer({ kind });
    try {
      await this.mailer.send({
        recipients: built.recipients,
        subject: built.notice.subject,
        text: built.notice.text,
        messageId: quarantineNoticeMessageId(event.eventId, this.mailer.from),
      });
    } catch (error) {
      this.count(kind, 'failed');
      log.warn({
        message: 'quarantine notice send failed (retried)',
        responseCode: (error as { responseCode?: number }).responseCode,
      });
      throw error;
    } finally {
      stop();
    }
    this.count(kind, 'sent');
    log.info({ message: 'quarantine notice sent', recipientCount: built.recipients.length });
    return 'sent';
  }

  private async build(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    p: QuarantineNotificationRequestedV1,
  ): Promise<{ recipients: string[]; notice: RenderedNotice } | { skip: QuarantineNoticeResult }> {
    const organizationName = (await this.common.organizationName(tx, organizationId)) ?? '';
    const portalUrl = this.options.portalUrl;
    switch (p.kind) {
      case 'user_digest': {
        const digest = await this.reads.digest(tx, organizationId, p.refs.digestId!);
        if (digest === null) throw new NonRetryableError('digest_not_found');
        const user = await this.reads.activeUser(tx, organizationId, p.refs.userId!);
        if (user === null || user.id !== digest.userId) return { skip: 'no_recipients' };
        const settings = await this.reads.settings(tx, organizationId);
        if (!settings.endUser.enabled || !settings.digestSchedule.enabled) {
          return { skip: 'not_applicable' };
        }
        if (
          settings.digest.allowOptOut &&
          (await this.reads.digestOptOut(tx, organizationId, user.id))
        ) {
          return { skip: 'not_applicable' };
        }
        const window = { from: new Date(p.window!.from), to: new Date(p.window!.to) };
        const { entries, total } = await this.reads.digestEntries(
          tx,
          organizationId,
          user.email,
          window,
          settings.digest.maxEntries,
        );
        if (entries.length === 0) return { skip: 'no_entries' };
        return {
          recipients: [user.email],
          notice: renderUserDigest({
            organizationName,
            portalUrl,
            window: { from: p.window!.from, to: p.window!.to },
            includeSubject: settings.digest.includeSubject,
            more: Math.max(0, total - entries.length),
            entries: entries.map((e) => ({
              entryId: e.publicId,
              receivedAt: e.messageReceivedAt.toISOString(),
              sender: e.envelopeFrom,
              subject: e.subject,
              reason: e.reason,
              expiresAt: e.expiresAt.toISOString(),
            })),
          }),
        };
      }
      case 'approval_requested': {
        const requests = await this.reads.approvalRequests(
          tx,
          organizationId,
          p.refs.approvalRequestIds!,
        );
        const pending = requests.filter((r) => r.status === 'pending');
        if (pending.length === 0) return { skip: 'not_applicable' };
        const requesters = pending
          .map((r) => r.requestedByUserId)
          .filter((id): id is bigint => id !== null);
        const { emails: recipients } = await this.preferences.collect(
          tx,
          organizationId,
          'quarantine_approval_requested',
          (afterId, take) => this.reads.approvers(tx, organizationId, requesters, take, afterId),
          this.options.maxRecipients,
        );
        if (recipients.length === 0) return { skip: 'no_recipients' };
        return {
          recipients,
          notice: renderApprovalRequested({
            organizationName,
            portalUrl,
            requests: pending.map((r) => ({
              id: r.publicId,
              kind: r.kind,
              reason: r.reason,
              approvalReasons: r.approvalReasons,
            })),
          }),
        };
      }
      case 'approval_decided': {
        const requests = await this.reads.approvalRequests(
          tx,
          organizationId,
          p.refs.approvalRequestIds!,
        );
        const requesterIds = [
          ...new Set(
            requests.map((r) => r.requestedByUserId).filter((id): id is bigint => id !== null),
          ),
        ];
        const recipients: string[] = [];
        for (const id of requesterIds) {
          const user = await this.reads.activeUserById(tx, organizationId, id);
          if (user !== null) recipients.push(user.email);
        }
        if (recipients.length === 0) return { skip: 'no_recipients' };
        return {
          recipients: [...new Set(recipients)],
          notice: renderApprovalDecided({
            organizationName,
            portalUrl,
            decision: p.decision!,
            requestIds: requests.map((r) => r.publicId),
          }),
        };
      }
      case 'release_blocked': {
        const release = await this.reads.release(tx, organizationId, p.refs.releaseId!);
        const requester =
          p.refs.userId ?? (release.requestedByType === 'user' ? release.requestedById : null);
        if (requester === null) return { skip: 'no_recipients' };
        const user = await this.reads.activeUser(tx, organizationId, requester);
        if (user === null) return { skip: 'no_recipients' };
        return {
          recipients: [user.email],
          notice: renderReleaseBlocked({
            organizationName,
            portalUrl,
            releaseId: p.refs.releaseId!,
            outcomes: release.outcomes,
          }),
        };
      }
      case 'admin_alert': {
        const window = p.window
          ? { from: new Date(p.window.from), to: new Date(p.window.to) }
          : null;
        const counts = await this.reads.alertCounts(tx, organizationId, window, this.now());
        if (counts.hardBlocks === 0 && counts.pendingApprovals === 0) {
          return { skip: 'not_applicable' };
        }
        const { emails: recipients } = await this.preferences.collect(
          tx,
          organizationId,
          'quarantine_admin_alert',
          (afterId, take) => this.reads.approvers(tx, organizationId, [], take, afterId),
          this.options.maxRecipients,
        );
        if (recipients.length === 0) return { skip: 'no_recipients' };
        return {
          recipients,
          notice: renderAdminAlert({
            organizationName,
            portalUrl,
            ...counts,
            window: p.window ?? null,
          }),
        };
      }
      case 'sender_rejected': {
        const entry = await this.reads.entry(tx, organizationId, p.refs.entryId!);
        if (entry === null) throw new NonRetryableError('entry_not_found');
        if (
          entry.messageId.toString() !== p.refs.messageId ||
          entry.messageReceivedAt.toISOString() !== p.refs.receivedAt
        ) {
          throw new NonRetryableError('entry_message_mismatch');
        }
        // Never a notice for inbound mail (no backscatter to external senders).
        if (entry.direction === 'inbound') return { skip: 'not_applicable' };
        const message = await this.common.message(
          tx,
          organizationId,
          entry.messageId,
          entry.messageReceivedAt,
        );
        if (message === null) throw new NonRetryableError('message_not_found');
        const sender = addressDomain(message.envelopeFrom);
        if (sender === null) return { skip: 'no_recipients' };
        if (!(await this.common.activeDomain(tx, organizationId, sender.domain))) {
          return { skip: 'no_recipients' };
        }
        return {
          recipients: [sender.address],
          notice: renderSenderRejected({
            organizationName,
            messagePublicId: message.publicId ?? p.refs.messageId,
            receivedAt: message.receivedAt.toISOString(),
            internetMessageId: message.internetMessageId,
          }),
        };
      }
    }
  }

  private count(kind: QuarantineNoticeKind, result: QuarantineNoticeResult): void {
    this.metrics.quarantineMessages.inc({ kind, result });
  }
}
