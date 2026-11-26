import { Injectable } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';

/** Seconds; a search runs at most ASSISTANT_SEARCH_TIMEOUT_MS (≤ 10 s) plus the page reads. */
const SEARCH_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

/**
 * The series of step AI-6 D8 owned by the insights routes (api registry, `GET /metrics`). Labels
 * are a rating and a search outcome only: never an organization, user, conversation or text.
 */
@Injectable()
export class InsightsMetrics {
  readonly feedback: Counter<'rating'>;
  readonly searchSeconds: Histogram<'outcome'>;

  constructor(metrics: MetricsService) {
    this.feedback = metrics.counter(
      'assistant_feedback_total',
      'Ratings of assistant answers recorded or changed, by rating (up, down)',
      ['rating'],
    );
    this.searchSeconds = metrics.histogram(
      'assistant_search_seconds',
      'Duration of assistant content searches by outcome (ok, timeout, error)',
      ['outcome'],
      SEARCH_BUCKETS,
    );
  }
}
