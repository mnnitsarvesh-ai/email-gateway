import type { Counter, MetricsService } from '@email-gateway/common';

/** `kind` of `api_message_reveal_total` (§3.7). */
export type RevealKind = 'bulk' | 'message';
/** `field` of `api_message_reveal_values_total` (§3.7). */
export type RevealValueField = 'subject' | 'headers' | 'recipients';

/**
 * The step 7.2 reveal series (§3.7) on the api registry (`GET /metrics`): reveal operations
 * answered (after their audit rows committed) by kind, and the values they returned by field
 * (subjects, header rows, recipients). No tenant, principal or id labels. `MetricsService.counter`
 * is get-or-create, so every holder shares one series.
 */
export class MessageRevealMetrics {
  readonly reveals: Counter<'kind'>;
  readonly values: Counter<'field'>;

  constructor(metrics: MetricsService) {
    this.reveals = metrics.counter(
      'api_message_reveal_total',
      'Audited reveal operations answered: bulk (POST /messages/reveal) or message ' +
        '(POST /messages/{id}/reveal)',
      ['kind'],
    );
    this.values = metrics.counter(
      'api_message_reveal_values_total',
      'Values returned by the audited reveal operations: subjects, header rows, recipients',
      ['field'],
    );
  }
}
