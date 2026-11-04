import type { Counter, Histogram, MetricsService } from '@email-gateway/common';
import type { FinalOutcome } from './mime-store';

/** `mime_parse_messages_total{status}`: the final statuses plus the no-op outcomes (M16). */
export type MessageOutcomeLabel = FinalOutcome['status'] | 'duplicate' | 'message_missing';

/** `mime_retries_total{class}`: which dependency failed an attempt. */
export type RetryClass = 's3' | 'db' | 'other';

/**
 * Every series of design M16, registered once through MetricsService (GET /metrics). The 3.1
 * outbox-poller series (`mime_outbox_poll_lag_seconds`, `mime_outbox_invalid_total`) were removed
 * with the poller in step 3.2: the transport's series are the shared `amqp_consumer_*` ones of
 * the `email.received` consumer (§5.3).
 */
export class MimeMetrics {
  readonly messages: Counter<'status'>;
  readonly duration: Histogram;
  readonly bytes: Counter;
  readonly limits: Counter<'limit'>;
  readonly defects: Counter<'defect'>;
  readonly failures: Counter<'reason'>;
  readonly attachments: Counter;
  readonly attachmentFlags: Counter<'flag'>;
  readonly retries: Counter<'class'>;

  constructor(metrics: MetricsService) {
    this.messages = metrics.counter(
      'mime_parse_messages_total',
      'MIME ingestion outcomes per received event (final statuses, duplicate, message_missing)',
      ['status'],
    );
    this.duration = metrics.histogram(
      'mime_parse_duration_seconds',
      'Duration of one parse, from the EML download to the commit',
      [],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300],
    );
    this.bytes = metrics.counter('mime_parse_bytes_total', 'EML bytes read by the MIME parser');
    this.limits = metrics.counter(
      'mime_limit_exceeded_total',
      'MIME limits exceeded, by limit name',
      ['limit'],
    );
    this.defects = metrics.counter('mime_defects_total', 'MIME defects recorded, by code', [
      'defect',
    ]);
    this.failures = metrics.counter(
      'mime_parse_failures_total',
      'Messages recorded parse_failed, by reason',
      ['reason'],
    );
    this.attachments = metrics.counter('mime_attachments_total', 'Attachment rows recorded');
    this.attachmentFlags = metrics.counter(
      'mime_attachment_flags_total',
      'Attachment flags recorded, by flag',
      ['flag'],
    );
    this.retries = metrics.counter(
      'mime_retries_total',
      'Parse attempts given back after an infrastructure failure, by failing dependency',
      ['class'],
    );
  }

  outcome(status: MessageOutcomeLabel): void {
    this.messages.inc({ status });
  }

  /** One committed final outcome; `seconds` is null when nothing was downloaded. */
  finalized(outcome: FinalOutcome, seconds: number | null): void {
    this.outcome(outcome.status);
    if (seconds !== null) this.duration.observe(seconds);
    if (outcome.stats && outcome.stats.bytesRead > 0) this.bytes.inc(outcome.stats.bytesRead);
    for (const limit of outcome.limitsExceeded) this.limits.inc({ limit });
    for (const defect of outcome.defects) this.defects.inc({ defect });
    if (outcome.failureReason) this.failures.inc({ reason: outcome.failureReason });
    const attachments = outcome.result?.attachments ?? [];
    if (attachments.length > 0) this.attachments.inc(attachments.length);
    for (const attachment of attachments) {
      for (const flag of attachment.flags) this.attachmentFlags.inc({ flag });
    }
  }

  retry(retryClass: RetryClass): void {
    this.retries.inc({ class: retryClass });
  }
}
