import { Test } from '@nestjs/testing';
import {
  AmqpConnection,
  HealthService,
  MetricsService,
  PrismaReadService,
  PrismaService,
  QueueConsumer,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { EventTypes } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { DeliveryApprovalConsumer, PLANNER_CONSUMER } from './approvals/delivery-approval.consumer';
import { loadWorkerConfig } from './config';
import { WorkerLifecycle } from './worker-lifecycle';

const env = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_DELIVERY_WORKER_URL: 'amqp://test:test@localhost:5672/email-gateway',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  GATEWAY_TRACE_SECRET: 't'.repeat(32),
  LOG_LEVEL: 'fatal',
  // No background loop may touch the (stubbed) infrastructure in this wiring test.
  DELIVERY_APPROVALS_ENABLED: 'false',
  DELIVERY_REINJECTION_ENABLED: 'false',
  DELIVERY_STATUS_LOG_ENABLED: 'false',
};
const config = loadWorkerConfig(env);

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** An AMQP connection that never connects: consumers register their setup and idle. */
function idleAmqp() {
  const calls = {
    setups: 0,
    unregistered: 0,
    closed: 0,
    topology: [] as { exchanges?: string[]; queues?: string[] }[],
  };
  const connection = stub('rabbitmq', {
    connected: false,
    blocked: false,
    start: () => undefined,
    close: () => {
      calls.closed += 1;
      return Promise.resolve();
    },
    requireTopology: (objects: { exchanges?: string[]; queues?: string[] }) =>
      void calls.topology.push(objects),
    onConnected: () => {
      calls.setups += 1;
      return () => void (calls.unregistered += 1);
    },
  });
  return { connection, calls };
}

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider, exposes metrics and reports the expected readiness checks', async () => {
    const amqp = idleAmqp();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(AmqpConnection)
      .useValue(amqp.connection)
      .overrideProvider(RedisService)
      .useValue(stub('redis', { client: {} }))
      .overrideProvider(S3Service)
      .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
      .compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
      expect(report.status).toBe('ok');
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      // Every R14 series is registered on the service's registry.
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of [
        'delivery_approvals_total',
        'delivery_reinjections_total',
        'delivery_reinjection_seconds',
        'delivery_status_signals_total',
        'delivery_status_transitions_total',
        'delivery_status_log_lag_seconds',
        'delivery_outbox_poll_lag_seconds',
        'delivery_rate_limited_total',
        'delivery_reconciler_actions_total',
      ]) {
        expect(metrics).toContain(`# TYPE ${name} `);
      }
      // The transport's series (step 3.2 §5.3).
      expect(metrics).toContain('# TYPE amqp_connection_up ');
      expect(metrics).toContain('# TYPE amqp_consumer_messages_total ');
      // Roles disabled: nothing was started.
      expect(moduleRef.get(WorkerLifecycle, { strict: false }).startedRoles).toEqual([]);
      expect(amqp.calls.setups).toBe(0);
      expect(amqp.calls.topology).toContainEqual({
        exchanges: ['email.delivery', 'email.events'],
        queues: ['email.delivery.pending'],
      });
    } finally {
      await moduleRef.close();
    }
  });

  it('consumes approvals from email.delivery.pending with the Q13 QueueConsumer', async () => {
    const amqp = idleAmqp();
    const moduleRef = await Test.createTestingModule({
      imports: [
        AppModule.forRoot(
          loadWorkerConfig({
            ...env,
            DELIVERY_APPROVALS_ENABLED: 'true',
            DELIVERY_APPROVAL_PREFETCH: '7',
          }),
        ),
      ],
    })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(AmqpConnection)
      .useValue(amqp.connection)
      .overrideProvider(RedisService)
      .useValue(stub('redis', { client: {} }))
      .overrideProvider(S3Service)
      .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
      .compile();
    const approvals = moduleRef.get(DeliveryApprovalConsumer, { strict: false });
    const feed = (approvals as unknown as { feed: QueueConsumer<unknown> }).feed;
    expect(feed).toBeInstanceOf(QueueConsumer);
    expect(feed.queue).toBe('email.delivery.pending');
    expect(feed.consumerName).toBe(PLANNER_CONSUMER);
    // The topology's delay-queue policy (Q8): copies wait in email.delivery.retry.
    expect(feed.retryPolicy).toEqual({
      strategy: 'delay-queue',
      maxAttempts: 10,
      baseDelayMs: 5_000,
      maxDelayMs: 15 * 60_000,
      maxRetryAgeMs: 48 * 3600 * 1000,
      delayQueue: 'email.delivery.retry',
    });
    const options = (feed as unknown as { options: { prefetch: number; eventTypes: string[] } })
      .options;
    expect(options.prefetch).toBe(7);
    expect(options.eventTypes).toEqual([EventTypes.DeliveryApproved]);

    await moduleRef.init();
    expect(moduleRef.get(WorkerLifecycle, { strict: false }).startedRoles).toEqual(['approvals']);
    expect(amqp.calls.setups).toBe(1);
    expect(amqp.calls.topology).toContainEqual({
      queues: ['email.delivery.pending'],
      exchanges: ['email.delivery', 'email.events'],
    });
    await moduleRef.close();
    // Stop order: the consumer unsubscribed, then the AMQP connection closed.
    expect(amqp.calls.unregistered).toBe(1);
    expect(amqp.calls.closed).toBeGreaterThanOrEqual(1);
  });
});
