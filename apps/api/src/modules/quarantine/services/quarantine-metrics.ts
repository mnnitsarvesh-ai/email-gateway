import { Injectable } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';

/** `operation` of `quarantine_requests_total` (bounded). */
export type QuarantineOperation =
  | 'search'
  | 'view'
  | 'history'
  | 'preview'
  | 'release'
  | 'self_release'
  | 'request_release'
  | 'reject'
  | 'delete'
  | 'manual'
  | 'approve'
  | 'deny'
  | 'cancel'
  | 'bulk'
  | 'settings'
  | 'preferences';

/**
 * The api's quarantine series (step 5.3 Q29). Labels are bounded enums; never a tenant, an
 * address, an entry id or a value.
 */
@Injectable()
export class QuarantineMetrics {
  readonly requests: Counter<'operation' | 'result'>;
  readonly previews: Counter<'result'>;
  readonly downloads: Counter<'stage' | 'result'>;
  readonly bulkItems: Counter<'action' | 'result'>;
  readonly approvalDecisions: Counter<'decision'>;
  readonly inconsistentReads: Counter<'read'>;

  constructor(metrics: MetricsService) {
    this.requests = metrics.counter(
      'quarantine_requests_total',
      'Quarantine api requests by operation and result (e.g. release queued, approval_requested, refused, conflict, not_found)',
      ['operation', 'result'],
    );
    this.previews = metrics.counter(
      'quarantine_previews_total',
      'Quarantine previews by result (ok, unavailable, purged, failed)',
      ['result'],
    );
    this.downloads = metrics.counter(
      'quarantine_downloads_total',
      'Quarantine download grants and downloads by stage (grant, download) and result',
      ['stage', 'result'],
    );
    this.bulkItems = metrics.counter(
      'quarantine_bulk_items_total',
      'Items of quarantine bulk requests by action and per-item result',
      ['action', 'result'],
    );
    this.approvalDecisions = metrics.counter(
      'quarantine_approval_decisions_total',
      'Quarantine approval decisions by decision (approved, denied, cancelled)',
      ['decision'],
    );
    this.inconsistentReads = metrics.counter(
      'quarantine_inconsistent_reads_total',
      'Echo-check mismatches of deciding quarantine reads (retried once), by read',
      ['read'],
    );
  }

  request(operation: QuarantineOperation, result: string): void {
    this.requests.inc({ operation, result });
  }
}
