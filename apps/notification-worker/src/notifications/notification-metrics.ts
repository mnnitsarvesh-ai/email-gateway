import { type Counter, type Histogram, type MetricsService } from '@email-gateway/common';

export type NoticeKind = 'policy_alert' | 'sender_non_delivery';
/** `sent`, `no_recipients`, `disabled` (no relay configured), `failed` (P24). */
export type NoticeResult = 'sent' | 'no_recipients' | 'disabled' | 'failed';

/**
 * The notification-worker's series (step 5.2 P24): `notification_policy_messages_total{kind,
 * result}` and `notification_send_duration_seconds`. Bounded labels; never a tenant or address.
 */
export class NotificationMetrics {
  readonly messages: Counter<'kind' | 'result'>;
  readonly sendDuration: Histogram<'kind'>;

  constructor(metrics: MetricsService) {
    this.messages = metrics.counter(
      'notification_policy_messages_total',
      'Policy notification events handled, by kind (policy_alert, sender_non_delivery) and result (sent, no_recipients, disabled, failed)',
      ['kind', 'result'],
    );
    this.sendDuration = metrics.histogram(
      'notification_send_duration_seconds',
      'Duration of one SMTP submission of a policy notice to the relay, by kind',
      ['kind'],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20],
    );
  }
}
