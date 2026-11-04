import { MetricsService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { RelayMetrics } from './relay-metrics';

describe('RelayMetrics', () => {
  it('registers exactly the outbox_* and reconcile_* series of §5.3', async () => {
    const service = new MetricsService({ service: 'event-relay-test' });
    new RelayMetrics(service);
    const names = (await service.registry.getMetricsAsJSON())
      .map((m) => m.name)
      .filter((n) => n.startsWith('outbox_') || n.startsWith('reconcile_'))
      .sort();
    expect(names).toEqual(
      [
        'outbox_poison_rows',
        'outbox_relay_batch_seconds',
        'outbox_relay_failures_total',
        'outbox_relay_lag_seconds',
        'outbox_relay_published_total',
        'outbox_relay_shards_held',
        'outbox_unpublished_oldest_seconds',
        'outbox_unpublished_rows',
        'reconcile_exhausted_total',
        'reconcile_redriven_total',
        'reconcile_run_seconds',
        'reconcile_skipped_total',
        'reconcile_unconsumed_rows',
      ].sort(),
    );
    const types = Object.fromEntries(
      (await service.registry.getMetricsAsJSON()).map((m) => [m.name, String(m.type)]),
    );
    expect(types).toMatchObject({
      outbox_relay_published_total: 'counter',
      outbox_relay_failures_total: 'counter',
      outbox_relay_lag_seconds: 'gauge',
      outbox_relay_batch_seconds: 'histogram',
      outbox_relay_shards_held: 'gauge',
      outbox_unpublished_rows: 'gauge',
      outbox_unpublished_oldest_seconds: 'gauge',
      outbox_poison_rows: 'gauge',
      reconcile_redriven_total: 'counter',
      reconcile_exhausted_total: 'counter',
      reconcile_unconsumed_rows: 'gauge',
      reconcile_run_seconds: 'histogram',
    });
  });

  it('is idempotent on one registry (two instances share the series)', () => {
    const service = new MetricsService({ service: 'event-relay-test' });
    expect(() => {
      new RelayMetrics(service);
      new RelayMetrics(service);
    }).not.toThrow();
  });
});
