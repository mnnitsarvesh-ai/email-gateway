import { Test } from '@nestjs/testing';
import {
  HealthService,
  MetricsService,
  PrismaReadService,
  PrismaService,
  RabbitMqService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadWorkerConfig } from './config';
import { WorkerLifecycle } from './worker-lifecycle';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_URL: 'amqp://test:test@localhost:5672',
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
});

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider, exposes metrics and reports the expected readiness checks', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(RabbitMqService)
      .useValue(stub('rabbitmq'))
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
      // Roles disabled: nothing was started.
      expect(moduleRef.get(WorkerLifecycle, { strict: false }).startedRoles).toEqual([]);
    } finally {
      await moduleRef.close();
    }
  });
});
