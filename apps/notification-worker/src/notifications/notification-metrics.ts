import { type Counter, type Histogram, type MetricsService } from '@email-gateway/common';

export type NoticeKind = 'policy_alert' | 'sender_non_delivery';
/** `sent`, `no_recipients`, `disabled` (no relay configured), `failed` (P24). */
export type NoticeResult = 'sent' | 'no_recipients' | 'disabled' | 'failed';

/** Results of a security alert (step 6.2 N3, N4): `disabled` = kind off or no relay. */
export type AlertResult = 'sent' | 'no_recipients' | 'disabled' | 'failed';
/**
 * Why a recipient or an alert was left out at send time (step 6.2 N4): `opt_out` (a user's
 * preference), `disabled` (the tenant switched the kind off, or raised `minSeverity`, after the
 * request), `invalid_contact` (`organization_settings.notification_email` is not an address).
 */
export type AlertSuppressionReason = 'opt_out' | 'disabled' | 'invalid_contact';

/**
 * The notification-worker's series (step 5.2 P24): `notification_policy_messages_total{kind,
 * result}` and `notification_send_duration_seconds`; step 5.3 Q20 adds
 * `notification_quarantine_messages_total{kind,result}`; step 6.2 N4 adds
 * `notification_alert_messages_total{kind,result}` and
 * `notification_alerts_suppressed_total{kind,reason}`. Bounded labels; never a tenant or address.
 */
export class NotificationMetrics {
  readonly messages: Counter<'kind' | 'result'>;
  readonly quarantineMessages: Counter<'kind' | 'result'>;
  readonly alertMessages: Counter<'kind' | 'result'>;
  readonly alertsSuppressed: Counter<'kind' | 'reason'>;
  readonly sendDuration: Histogram<'kind'>;

  constructor(metrics: MetricsService) {
    this.messages = metrics.counter(
      'notification_policy_messages_total',
      'Policy notification events handled, by kind (policy_alert, sender_non_delivery) and result (sent, no_recipients, disabled, failed)',
      ['kind', 'result'],
    );
    this.quarantineMessages = metrics.counter(
      'notification_quarantine_messages_total',
      'Quarantine notification events handled (step 5.3 Q20), by kind (user_digest, approval_requested, approval_decided, release_blocked, admin_alert, sender_rejected) and result (sent, no_recipients, no_entries, not_applicable, disabled, failed)',
      ['kind', 'result'],
    );
    this.alertMessages = metrics.counter(
      'notification_alert_messages_total',
      'Security alert events handled (step 6.2 N4), by kind (threat_detected, domain_dns_failed, webhook_disabled) and result (sent, no_recipients, disabled, failed)',
      ['kind', 'result'],
    );
    this.alertsSuppressed = metrics.counter(
      'notification_alerts_suppressed_total',
      'Recipients or alerts left out at send time (step 6.2 N4), by kind (alert kinds, policy_alert, quarantine_admin_alert, quarantine_approval_requested) and reason (opt_out, disabled, invalid_contact)',
      ['kind', 'reason'],
    );
    this.sendDuration = metrics.histogram(
      'notification_send_duration_seconds',
      'Duration of one SMTP submission of a policy, quarantine or security alert notice to the relay, by kind',
      ['kind'],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20],
    );
  }
}
