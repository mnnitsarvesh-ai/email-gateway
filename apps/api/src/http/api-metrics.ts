import { Injectable } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';

/** `scope` of `api_rate_limited_total` (D8). */
export type RateLimitScope = 'principal' | 'tenant' | 'sensitive' | 'expensive' | 'route';

/** `outcome` of `api_idempotency_total` (D16). */
export type IdempotencyOutcome =
  'stored' | 'replayed' | 'reused' | 'in_progress' | 'missing_legacy';

/** Seconds; request latencies of a control-plane API (10 ms … 30 s). */
const DURATION_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30];

/**
 * The step 6.1 series of the api (D16) on its registry (`GET /metrics`). Labels are route
 * templates, methods, status classes, scopes and outcomes only: never tenant, principal, address
 * or id labels.
 */
@Injectable()
export class ApiConventionMetrics {
  readonly httpRequests: Counter<'method' | 'route' | 'status_class'>;
  readonly httpDuration: Histogram<'method' | 'route'>;
  readonly rateLimited: Counter<'scope'>;
  readonly rateLimitStoreErrors: Counter;
  readonly idempotency: Counter<'outcome'>;
  readonly cursorRejected: Counter;
  readonly scanBudgetExhausted: Counter<'resource'>;

  constructor(metrics: MetricsService) {
    this.httpRequests = metrics.counter(
      'api_http_requests_total',
      'HTTP requests by method, route template (or unmatched) and status class (2xx, 4xx, 5xx)',
      ['method', 'route', 'status_class'],
    );
    this.httpDuration = metrics.histogram(
      'api_http_request_duration_seconds',
      'HTTP request duration by method and route template (or unmatched)',
      ['method', 'route'],
      DURATION_BUCKETS,
    );
    this.rateLimited = metrics.counter(
      'api_rate_limited_total',
      'Requests refused with 429 by limit scope (principal, tenant, sensitive, expensive, route)',
      ['scope'],
    );
    this.rateLimitStoreErrors = metrics.counter(
      'api_rate_limit_store_errors_total',
      'Rate-limit counter store (Redis) failures; the request is refused with 503 (fail closed)',
    );
    this.idempotency = metrics.counter(
      'api_idempotency_total',
      'Idempotency-Key handling by outcome (stored, replayed, reused, in_progress, missing_legacy)',
      ['outcome'],
    );
    this.cursorRejected = metrics.counter(
      'api_cursor_rejected_total',
      'v1 list cursors refused with 400 cursor_invalid (any failed check)',
    );
    this.scanBudgetExhausted = metrics.counter(
      'api_list_scan_budget_exhausted_total',
      'v1 list pages that ended short because the scan budget was used up, by resource',
      ['resource'],
    );
  }
}
