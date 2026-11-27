import type { Prisma } from '@email-gateway/database';
import type { EventEnvelope, ReportFeedbackRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { NoticeMailer } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import { addressDomain } from './policy-notification.handler';
import type { ReportFeedbackReads } from './report-feedback-reads';
import {
  type FeedbackVerdict,
  renderReportFeedback,
  reportFeedbackMessageId,
} from './report-feedback-templates';

type Tx = Prisma.TransactionClient;

/**
 * The handler's own ledger consumer (step API-3 C12, contracts §38), written in the same
 * transaction as the queue consumer's `notification-worker.policy` row.
 */
export const REPORT_FEEDBACK_CONSUMER = 'notification-worker.report-feedback';

/**
 * `notification_report_feedback_messages_total{result}` (C12): `sent`; `duplicate` (the handler
 * ledger row existed); not sent because the report is gone or of another organization
 * (`report_missing`), was rejected (`rejected`), has no analyst verdict for a result
 * (`no_verdict`), names a reporter outside the organization's own domains
 * (`external_reporter`) or no longer resolving to an organization mailbox or user
 * (`reporter_unresolved`); no relay (`disabled`); a relay failure (`failed`, retried).
 */
export type ReportFeedbackResult =
  | 'sent'
  | 'duplicate'
  | 'report_missing'
  | 'rejected'
  | 'no_verdict'
  | 'external_reporter'
  | 'reporter_unresolved'
  | 'disabled'
  | 'failed';

const VERDICTS: ReadonlySet<string> = new Set<FeedbackVerdict>([
  'malicious',
  'phishing_simulation',
  'spam',
  'clean',
  'inconclusive',
]);

/**
 * Handles one `mail.report.feedback_requested.v1` (step API-3 C12, ADR-0104) inside the
 * consumer's idempotency transaction (queue ledger `notification-worker.policy`, plus the
 * handler's ledger `notification-worker.report-feedback`). Everything is decided at **send
 * time** on the writer, scoped to the envelope's organization:
 *
 * 1. the report by public id (a report of another organization is not found); missing → ack with
 *    `report_missing` (purged, or a forged reference: nothing to send);
 * 2. `rejected` → nothing (`rejected`); a `resolved` request needs the analyst verdict
 *    (`no_verdict` otherwise);
 * 3. the reporter address must be on a verified or active domain of the organization
 *    (`external_reporter`) and still resolve to an organization mailbox address or an active user
 *    (`reporter_unresolved`) — feedback is never sent outside the tenant;
 * 4. one fixed mail (text + HTML) `To:` the reporter through the existing notification relay
 *    (`NOTIFY_SMTP_*`), `Message-ID: <report-feedback.<eventId>@…>`, sent before the ledger
 *    commits (at least once). It carries the report date and public id, never the reported
 *    message's subject, sender or body.
 *
 * Logs and metrics carry ids and codes only, never the reporter address.
 */
export class ReportFeedbackHandler {
  constructor(
    private readonly reads: ReportFeedbackReads,
    private readonly mailer: NoticeMailer,
    private readonly metrics: NotificationMetrics,
    private readonly logger: Logger,
  ) {}

  async handle(
    event: EventEnvelope<ReportFeedbackRequestedV1>,
    tx: Tx,
  ): Promise<ReportFeedbackResult> {
    const p = event.payload;
    const organizationId = BigInt(event.organizationId);
    const log = this.logger.child({
      eventId: event.eventId,
      organizationId: event.organizationId,
      reportId: p.reportId,
      kind: p.kind,
    });
    const ledger = await tx.messageIdempotency.createMany({
      data: [{ consumer: REPORT_FEEDBACK_CONSUMER, eventId: event.eventId }],
      skipDuplicates: true,
    });
    if (ledger.count === 0) return this.done(p.kind, 'duplicate', log, 'already handled');

    const report = await this.reads.report(tx, organizationId, p.reportId);
    if (report === null) {
      return this.done(p.kind, 'report_missing', log, 'report not found in the organization');
    }
    if (report.status === 'rejected') {
      return this.done(p.kind, 'rejected', log, 'report rejected: no feedback');
    }
    let verdict: FeedbackVerdict | null = null;
    if (p.kind === 'resolved') {
      if (report.analystVerdict === null || !VERDICTS.has(report.analystVerdict)) {
        return this.done(p.kind, 'no_verdict', log, 'report has no analyst verdict');
      }
      verdict = report.analystVerdict as FeedbackVerdict;
    }
    const reporter = addressDomain(report.reporterAddress);
    if (reporter === null || !(await this.reads.ownDomain(tx, organizationId, reporter.domain))) {
      return this.done(p.kind, 'external_reporter', log, 'reporter outside the organization');
    }
    if (!(await this.reads.reporterResolves(tx, organizationId, reporter.address))) {
      return this.done(p.kind, 'reporter_unresolved', log, 'reporter no longer resolves');
    }
    if (!this.mailer.configured || this.mailer.from === null) {
      log.warn({ message: 'reporter feedback not sent: no relay configured (NOTIFY_SMTP_HOST)' });
      this.count(p.kind, 'disabled');
      return 'disabled';
    }
    const organizationName = (await this.reads.organizationName(tx, organizationId)) ?? '';
    const common = {
      organizationName,
      reportPublicId: report.publicId,
      reportedAt: report.reportedAt,
    };
    const notice = renderReportFeedback(
      verdict === null ? { kind: 'received', ...common } : { kind: 'resolved', verdict, ...common },
    );
    const metricKind = `report_feedback_${p.kind}`;
    const stop = this.metrics.sendDuration.startTimer({ kind: metricKind });
    try {
      await this.mailer.send({
        recipients: [],
        to: reporter.address,
        subject: notice.subject,
        text: notice.text,
        html: notice.html,
        messageId: reportFeedbackMessageId(event.eventId, this.mailer.from),
      });
    } catch (error) {
      this.count(p.kind, 'failed');
      log.warn({
        message: 'reporter feedback send failed (retried)',
        responseCode: (error as { responseCode?: number }).responseCode,
      });
      throw error;
    } finally {
      stop();
    }
    this.count(p.kind, 'sent');
    log.info({ message: 'reporter feedback sent', ...(verdict ? { verdict } : {}) });
    return 'sent';
  }

  private done(
    kind: ReportFeedbackRequestedV1['kind'],
    result: ReportFeedbackResult,
    log: Logger,
    message: string,
  ): ReportFeedbackResult {
    this.count(kind, result);
    log.info({ message: `reporter feedback not sent: ${message}`, result });
    return result;
  }

  private count(kind: ReportFeedbackRequestedV1['kind'], result: ReportFeedbackResult): void {
    this.metrics.reportFeedback.inc({ kind: `report_feedback_${kind}`, result });
  }
}
