import { Injectable } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';
import type { IngestDirection } from './ingestion-keys';
import type { OrganizationOutcome } from './tenant-split';

/** Ingestion metrics (step 2.2 D7 step 8, D16; names are a dashboard contract). */
@Injectable()
export class IngestionMetrics {
  private readonly messages: Counter<'direction' | 'outcome'>;
  private readonly duration: Histogram<'direction'>;
  private readonly bytes: Counter<'direction'>;
  private readonly s3Errors: Counter;
  private readonly dbErrors: Counter;

  constructor(metrics: MetricsService) {
    this.messages = metrics.counter(
      'smtp_ingest_messages_total',
      'LMTP ingestion results per organization of a message',
      ['direction', 'outcome'],
    );
    this.duration = metrics.histogram(
      'smtp_ingest_duration_seconds',
      'Duration of one LMTP ingestion transaction (DATA to replies)',
      ['direction'],
      [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120],
    );
    this.bytes = metrics.counter(
      'smtp_ingest_bytes_total',
      'Message bytes received by LMTP ingestion',
      ['direction'],
    );
    this.s3Errors = metrics.counter('smtp_ingest_s3_errors_total', 'S3 failures during ingestion');
    this.dbErrors = metrics.counter(
      'smtp_ingest_db_errors_total',
      'Database failures during ingestion',
    );
  }

  outcome(direction: IngestDirection, outcome: OrganizationOutcome): void {
    this.messages.inc({ direction, outcome });
  }

  transaction(direction: IngestDirection, seconds: number, bytes: number): void {
    this.duration.observe({ direction }, seconds);
    if (bytes > 0) this.bytes.inc({ direction }, bytes);
  }

  s3Error(): void {
    this.s3Errors.inc();
  }

  dbError(): void {
    this.dbErrors.inc();
  }
}
