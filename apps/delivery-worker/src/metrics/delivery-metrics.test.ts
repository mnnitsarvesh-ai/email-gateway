import { MetricsService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { DeliveryMetrics } from './delivery-metrics';

describe('DeliveryMetrics.outboxPoller', () => {
  it('maps the shared poller metrics onto the unchanged step 2.3 series', async () => {
    const service = new MetricsService({ service: 'test' });
    const metrics = new DeliveryMetrics(service).outboxPoller();
    metrics.pollLag('delivery-worker.planner', 12.5);
    metrics.invalid('delivery-worker.planner');
    metrics.invalid('delivery-worker.planner');
    const text = await service.metrics();
    expect(text).toContain(
      'delivery_outbox_poll_lag_seconds{consumer="delivery-worker.planner",service="test"} 12.5',
    );
    expect(text).toContain(
      'delivery_outbox_invalid_events_total{consumer="delivery-worker.planner",service="test"} 2',
    );
  });
});
