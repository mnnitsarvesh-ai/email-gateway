import { Injectable } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';

/**
 * The api's archive series (step 8.1 A27). Labels are bounded enums; never a tenant, a
 * principal, an address, an id or a value.
 */
@Injectable()
export class ArchiveMetrics {
  /** `GET /archive/messages` by result (`ok`, `forbidden_filter`, `unavailable`, `invalid`). */
  readonly searches: Counter<'result'>;
  readonly searchDuration: Histogram<never>;
  /** Content accesses by kind (journal, security, reveal, preview, download, export) and result. */
  readonly contentAccess: Counter<'kind' | 'result'>;

  constructor(metrics: MetricsService) {
    this.searches = metrics.counter(
      'archive_search_requests_total',
      'Archive metadata searches of the api by result',
      ['result'],
    );
    this.searchDuration = metrics.histogram(
      'archive_search_duration_seconds',
      'Duration of archive metadata searches through the tenant alias',
      [],
      [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    );
    this.contentAccess = metrics.counter(
      'archive_content_access_total',
      'Archived content accesses of the api by kind and result',
      ['kind', 'result'],
    );
  }
}
