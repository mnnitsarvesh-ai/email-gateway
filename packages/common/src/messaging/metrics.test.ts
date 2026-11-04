import { describe, expect, it } from 'vitest';
import { MetricsService } from '../metrics/metrics.service';
import { createMessagingMetrics } from './metrics';

const SERIES = [
  'amqp_connection_up',
  'amqp_connection_blocked',
  'amqp_reconnects_total',
  'amqp_publish_total',
  'amqp_publish_confirm_seconds',
  'amqp_consumer_deliveries_total',
  'amqp_consumer_messages_total',
  'amqp_consumer_retries_total',
  'amqp_consumer_dead_lettered_total',
  'amqp_consumer_handle_seconds',
  'amqp_consumer_in_flight',
  'amqp_consumer_active',
];

describe('createMessagingMetrics', () => {
  it('registers exactly the §5.3 amqp_* series with their labels', async () => {
    const service = new MetricsService({ service: 'test' });
    const m = createMessagingMetrics(service);
    createMessagingMetrics(service); // idempotent
    m.connectionUp('c', true);
    m.connectionBlocked('c', false);
    m.reconnected('c');
    m.published('email.events', 'confirmed');
    m.confirmSeconds('email.events', 0.01);
    m.delivery('email.received', true);
    m.message('email.received', 'handled');
    m.retry('email.received', 'transient');
    m.deadLettered('email.received', 'max_attempts_exceeded');
    m.handleSeconds('email.received', 0.2);
    m.inFlight('email.received', 3);
    m.consumerActive('email.received', true);

    const json = await service.registry.getMetricsAsJSON();
    const amqp = json.map((metric) => metric.name).filter((name) => name.startsWith('amqp_'));
    expect(amqp.sort()).toEqual([...SERIES].sort());
    const text = await service.metrics();
    expect(text).toContain('amqp_connection_up{connection="c",service="test"} 1');
    expect(text).toContain(
      'amqp_publish_total{exchange="email.events",outcome="confirmed",service="test"} 1',
    );
    expect(text).toContain(
      'amqp_consumer_deliveries_total{queue="email.received",redelivered="true",service="test"} 1',
    );
    expect(text).toContain(
      'amqp_consumer_retries_total{queue="email.received",class="transient",service="test"} 1',
    );
    expect(text).toContain(
      'amqp_consumer_dead_lettered_total{queue="email.received",reason="max_attempts_exceeded",service="test"} 1',
    );
    expect(text).toContain('amqp_consumer_in_flight{queue="email.received",service="test"} 3');
  });
});
