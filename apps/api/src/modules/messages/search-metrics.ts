import type { Counter, MetricsService } from '@email-gateway/common';

/** `reason` of `api_message_search_refused_total` (§3.7). */
export type SearchRefusal = 'too_broad' | 'timeout';

/**
 * The step 7.2 message search series (§3.7) on the api registry (`GET /metrics`): the plan of
 * each `GET /messages` request (`driver`, `budgeted` = `true`/`false`) and the refused subject
 * prefix searches. No tenant, principal, filter value or id labels. `MetricsService.counter` is
 * get-or-create, so every holder shares one series.
 */
export class MessageSearchMetrics {
  readonly plans: Counter<'driver' | 'budgeted'>;
  readonly refused: Counter<'reason'>;

  constructor(metrics: MetricsService) {
    this.plans = metrics.counter(
      'api_message_list_plan_total',
      'GET /messages requests by search driver and whether the scan budget bounds the page',
      ['driver', 'budgeted'],
    );
    this.refused = metrics.counter(
      'api_message_search_refused_total',
      'Subject prefix searches refused: too_broad (422, above API_MESSAGES_SEARCH_MAX_MATCHES) ' +
        'or timeout (503, MAX_EXECUTION_TIME)',
      ['reason'],
    );
  }
}
