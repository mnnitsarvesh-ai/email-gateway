import { Injectable } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';

/** Seconds; report queries are bounded by `REPORTS_QUERY_TIMEOUT_MS` (≤ 30 s). */
const REPORT_DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30];

/** `outcome` of `api_report_cache_total`. */
export type ReportCacheOutcome = 'hit' | 'miss' | 'error';

/**
 * The report series of step 6.1 D16 on the api registry. The only label is the report name (and
 * the cache outcome): never tenant, principal or parameter labels.
 */
@Injectable()
export class ReportMetrics {
  readonly duration: Histogram<'report'>;
  readonly cache: Counter<'report' | 'outcome'>;
  readonly timeouts: Counter<'report'>;

  constructor(metrics: MetricsService) {
    this.duration = metrics.histogram(
      'api_report_duration_seconds',
      'Time to compute a report from the replica (cache misses only), by report',
      ['report'],
      REPORT_DURATION_BUCKETS,
    );
    this.cache = metrics.counter(
      'api_report_cache_total',
      'Report cache lookups by report and outcome (hit, miss, error)',
      ['report', 'outcome'],
    );
    this.timeouts = metrics.counter(
      'api_report_timeouts_total',
      'Report queries interrupted by MAX_EXECUTION_TIME (503 report_timeout), by report',
      ['report'],
    );
  }
}
