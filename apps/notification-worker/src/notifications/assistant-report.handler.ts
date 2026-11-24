import { NonRetryableError } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type {
  AssistantReportEmailRequestedV1,
  EventEnvelope,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type {
  AssistantReportReads,
  ReportDeliveryRow,
  ReportObjectReader,
} from './assistant-report-reads';
import {
  renderReportEmailText,
  reportAttachmentName,
  reportEmailMessageId,
  reportEmailSubject,
} from './assistant-report-templates';
import type { NoticeMailer } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import { addressDomain } from './policy-notification.handler';

type Tx = Prisma.TransactionClient;

/** `notification_assistant_report_emails_total{result}` (D8). */
export type ReportEmailResult = 'sent' | 'failed' | 'not_applicable' | 'skipped';

/** The `error_code` the worker writes on a `failed` delivery (D7, D8). */
export type ReportEmailFailure =
  | 'assistant_report_purged'
  | 'relay_not_configured'
  | 'assistant_report_missing'
  | 'assistant_report_integrity'
  | 'assistant_report_recipient_invalid';

export interface AssistantReportEmailOptions {
  portalUrl: string;
  /** `NOTIFICATION_REPORT_MAX_HTML_BYTES`. */
  maxHtmlBytes: number;
}

const SHA256_HEX = /^[0-9a-f]{64}$/i;
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** The stored bytes as UTF-8 text, or null when they are not valid UTF-8. */
function decodeUtf8(bytes: Buffer): string | null {
  try {
    return utf8.decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Handles one `assistant.report.email_requested.v1` (step AI-R D8, docs/plan/steps/
 * 31-ai-chat-reports.md) inside the consumer's idempotency transaction (ledger
 * `notification-worker.policy`, at least once). Every read and write is on the writer and scoped
 * to the envelope's organization, so an envelope naming another organization's delivery finds
 * nothing and sends nothing.
 *
 * 1. The delivery by public id with its report and the organization name; missing →
 *    `not_applicable` (organization or conversation purged, or not this organization's).
 * 2. Delivery not `queued` → `skipped` (a redelivery after the row was settled).
 * 3. Report not `available` (or the recipient purged) → delivery `failed`
 *    `assistant_report_purged`.
 * 4. No relay (`NOTIFY_SMTP_HOST` unset) → `failed` `relay_not_configured`.
 * 5. The stored HTML: key under `org/<organizationId>/assistant/report/`, bounded read of at most
 *    `min(size_bytes, NOTIFICATION_REPORT_MAX_HTML_BYTES) + 1` bytes, size and SHA-256 equal to
 *    the row and valid UTF-8; a missing object → `failed` `assistant_report_missing`; anything
 *    else → `failed` `assistant_report_integrity`. Nothing is sent in any of these cases.
 * 6. One mail `To:` the stored recipient (no Bcc): fixed plain-text part, the stored HTML as the
 *    HTML part and the same bytes attached; `Message-ID: <assistant-report.<deliveryId>@…>`. A
 *    relay failure throws `NoticeSendError` (the queue's retry; the api sweep fails the row after
 *    25 h). Then `queued → sent` with `sent_at` and the Message-ID.
 *
 * Logs and metrics carry ids and codes only: never the address, the subject, the title or HTML.
 * No audit row (the request is audited by the api, R-6).
 */
export class AssistantReportEmailHandler {
  constructor(
    private readonly reads: AssistantReportReads,
    private readonly objects: ReportObjectReader,
    private readonly mailer: NoticeMailer,
    private readonly metrics: NotificationMetrics,
    private readonly logger: Logger,
    private readonly options: AssistantReportEmailOptions,
  ) {}

  async handle(
    event: EventEnvelope<AssistantReportEmailRequestedV1>,
    tx: Tx,
  ): Promise<ReportEmailResult> {
    const p = event.payload;
    const organizationId = BigInt(event.organizationId);
    const log = this.logger.child({
      eventId: event.eventId,
      organizationId: event.organizationId,
      deliveryId: p.deliveryId,
      reportId: p.reportId,
    });
    const delivery = await this.reads.delivery(tx, organizationId, p.deliveryId);
    if (delivery === null) {
      log.info({ message: 'report email not sent: no such delivery for the organization' });
      return this.count('not_applicable');
    }
    if (delivery.report.publicId !== p.reportId) {
      // The api writes both ids from the same rows; a mismatch is a defect (dead-lettered).
      this.count('failed');
      throw new NonRetryableError('assistant_report_delivery_mismatch');
    }
    if (delivery.status !== 'queued') {
      log.info({ message: 'report email already settled', status: delivery.status });
      return this.count('skipped');
    }
    if (delivery.report.status !== 'available' || delivery.recipientAddress === null) {
      return this.fail(tx, delivery, 'assistant_report_purged', log);
    }
    const recipient = addressDomain(delivery.recipientAddress);
    if (recipient === null)
      return this.fail(tx, delivery, 'assistant_report_recipient_invalid', log);
    if (!this.mailer.configured || this.mailer.from === null) {
      log.warn({ message: 'report email not sent: no relay configured (NOTIFY_SMTP_HOST)' });
      return this.fail(tx, delivery, 'relay_not_configured', log);
    }
    const html = await this.readHtml(delivery);
    if (html === 'missing' || html === 'integrity') {
      return this.fail(
        tx,
        delivery,
        html === 'missing' ? 'assistant_report_missing' : 'assistant_report_integrity',
        log,
      );
    }

    const facts = {
      reportPublicId: delivery.report.publicId,
      title: delivery.report.title,
      organizationName: delivery.organizationName,
      periodFrom: delivery.report.periodFrom,
      periodTo: delivery.report.periodTo,
      figures: delivery.report.figures,
      portalUrl: this.options.portalUrl,
    };
    const messageId = reportEmailMessageId(delivery.publicId, this.mailer.from);
    const stop = this.metrics.sendDuration.startTimer({ kind: 'assistant_report' });
    try {
      await this.mailer.send({
        recipients: [recipient.address],
        to: recipient.address,
        subject: reportEmailSubject(facts),
        text: renderReportEmailText(facts),
        html: html.text,
        attachments: [
          {
            filename: reportAttachmentName(delivery.report.createdAt),
            content: html.bytes,
            contentType: 'text/html; charset=utf-8',
          },
        ],
        messageId,
      });
    } catch (error) {
      this.count('failed');
      log.warn({
        message: 'report email send failed (retried)',
        responseCode: (error as { responseCode?: number }).responseCode,
      });
      throw error;
    } finally {
      stop();
    }
    const updated = await this.reads.markSent(
      tx,
      organizationId,
      delivery.id,
      messageId,
      new Date(),
    );
    if (!updated) {
      log.warn({ message: 'report email sent but the delivery was settled concurrently' });
    }
    log.info({ message: 'report email sent', sizeBytes: html.bytes.length });
    return this.count('sent');
  }

  /** The verified stored HTML, or why it cannot be mailed. */
  private async readHtml(
    delivery: ReportDeliveryRow,
  ): Promise<{ bytes: Buffer; text: string } | 'missing' | 'integrity'> {
    const { objectKey, sizeBytes, sha256 } = delivery.report;
    if (objectKey === null) return 'missing';
    if (
      sizeBytes === null ||
      sha256 === null ||
      !SHA256_HEX.test(sha256) ||
      sizeBytes <= 0 ||
      sizeBytes > this.options.maxHtmlBytes
    ) {
      return 'integrity';
    }
    const read = await this.objects.read(
      delivery.organizationId,
      objectKey,
      { sizeBytes, sha256 },
      this.options.maxHtmlBytes,
    );
    if (read.kind === 'missing') return 'missing';
    if (read.kind !== 'ok') return 'integrity';
    const text = decodeUtf8(read.bytes);
    return text === null ? 'integrity' : { bytes: read.bytes, text };
  }

  private async fail(
    tx: Tx,
    delivery: ReportDeliveryRow,
    code: ReportEmailFailure,
    log: Logger,
  ): Promise<ReportEmailResult> {
    const updated = await this.reads.markFailed(tx, delivery.organizationId, delivery.id, code);
    if (!updated) {
      log.info({ message: 'report email already settled' });
      return this.count('skipped');
    }
    log.warn({ message: 'report email not sent', code });
    return this.count('failed');
  }

  private count(result: ReportEmailResult): ReportEmailResult {
    this.metrics.assistantReportEmails.inc({ result });
    return result;
  }
}
