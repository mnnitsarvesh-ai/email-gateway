import type { MetricsService } from '../metrics/metrics.service';

export type PublishMetricOutcome = 'confirmed' | 'nacked' | 'returned' | 'timeout' | 'refused';
export type ConsumerMetricOutcome =
  'handled' | 'duplicate' | 'retried' | 'dead_lettered' | 'requeued';

/**
 * The AMQP client series of step 3.2 §5.3 (a contract for the alert rules and the 10.3
 * dashboards). Labels are bounded: connection names, exchange and queue names of the topology,
 * outcomes and failure reason codes.
 */
export interface MessagingMetrics {
  /** `amqp_connection_up{connection}`. */
  connectionUp(connection: string, up: boolean): void;
  /** `amqp_connection_blocked{connection}`. */
  connectionBlocked(connection: string, blocked: boolean): void;
  /** `amqp_reconnects_total{connection}`. */
  reconnected(connection: string): void;
  /** `amqp_publish_total{exchange, outcome}`. */
  published(exchange: string, outcome: PublishMetricOutcome): void;
  /** `amqp_publish_confirm_seconds{exchange}`. */
  confirmSeconds(exchange: string, seconds: number): void;
  /** `amqp_consumer_deliveries_total{queue, redelivered}`. */
  delivery(queue: string, redelivered: boolean): void;
  /** `amqp_consumer_messages_total{queue, outcome}`. */
  message(queue: string, outcome: ConsumerMetricOutcome): void;
  /** `amqp_consumer_retries_total{queue, class}`. */
  retry(queue: string, failureClass: 'transient' | 'retryable'): void;
  /** `amqp_consumer_dead_lettered_total{queue, reason}`. */
  deadLettered(queue: string, reason: string): void;
  /** `amqp_consumer_handle_seconds{queue}`. */
  handleSeconds(queue: string, seconds: number): void;
  /** `amqp_consumer_in_flight{queue}`. */
  inFlight(queue: string, count: number): void;
  /** `amqp_consumer_active{queue}`: 1 while subscribed. */
  consumerActive(queue: string, active: boolean): void;
}

const CONFIRM_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 15];
const HANDLE_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60];

/** Registers the §5.3 `amqp_*` series on a service's registry (idempotent). */
export function createMessagingMetrics(metrics: MetricsService): MessagingMetrics {
  const up = metrics.gauge('amqp_connection_up', '1 while the AMQP connection is open', [
    'connection',
  ]);
  const blocked = metrics.gauge(
    'amqp_connection_blocked',
    '1 while the broker blocks publishing on this connection (memory or disk alarm)',
    ['connection'],
  );
  const reconnects = metrics.counter(
    'amqp_reconnects_total',
    'AMQP connections re-established after a loss',
    ['connection'],
  );
  const publishes = metrics.counter('amqp_publish_total', 'AMQP publishes by outcome', [
    'exchange',
    'outcome',
  ]);
  const confirm = metrics.histogram(
    'amqp_publish_confirm_seconds',
    'Time from publish to broker confirm',
    ['exchange'],
    CONFIRM_BUCKETS,
  );
  const deliveries = metrics.counter(
    'amqp_consumer_deliveries_total',
    'Deliveries received by queue consumers',
    ['queue', 'redelivered'],
  );
  const messages = metrics.counter(
    'amqp_consumer_messages_total',
    'Deliveries settled by queue consumers, by outcome',
    ['queue', 'outcome'],
  );
  const retries = metrics.counter('amqp_consumer_retries_total', 'Retry hops by failure class', [
    'queue',
    'class',
  ]);
  const deadLetters = metrics.counter(
    'amqp_consumer_dead_lettered_total',
    'Deliveries dead-lettered by queue consumers, by reason',
    ['queue', 'reason'],
  );
  const handle = metrics.histogram(
    'amqp_consumer_handle_seconds',
    'Handler duration per delivery',
    ['queue'],
    HANDLE_BUCKETS,
  );
  const inFlight = metrics.gauge('amqp_consumer_in_flight', 'Deliveries being handled or held', [
    'queue',
  ]);
  const active = metrics.gauge('amqp_consumer_active', '1 while the consumer is subscribed', [
    'queue',
  ]);
  return {
    connectionUp: (connection, isUp) => up.set({ connection }, isUp ? 1 : 0),
    connectionBlocked: (connection, isBlocked) => blocked.set({ connection }, isBlocked ? 1 : 0),
    reconnected: (connection) => reconnects.inc({ connection }),
    published: (exchange, outcome) => publishes.inc({ exchange, outcome }),
    confirmSeconds: (exchange, seconds) => confirm.observe({ exchange }, seconds),
    delivery: (queue, redelivered) =>
      deliveries.inc({ queue, redelivered: redelivered ? 'true' : 'false' }),
    message: (queue, outcome) => messages.inc({ queue, outcome }),
    retry: (queue, failureClass) => retries.inc({ queue, class: failureClass }),
    deadLettered: (queue, reason) => deadLetters.inc({ queue, reason }),
    handleSeconds: (queue, seconds) => handle.observe({ queue }, seconds),
    inFlight: (queue, count) => inFlight.set({ queue }, count),
    consumerActive: (queue, isActive) => active.set({ queue }, isActive ? 1 : 0),
  };
}
