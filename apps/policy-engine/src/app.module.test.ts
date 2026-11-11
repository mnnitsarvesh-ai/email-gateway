import { Test } from '@nestjs/testing';
import {
  AmqpConnection,
  HealthService,
  MetricsService,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadWorkerConfig } from './config';
import { PolicyEvaluateConsumer } from './evaluation/policy-evaluate.consumer';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  RABBITMQ_POLICY_ENGINE_URL: 'amqp://test:test@localhost:5672/email-gateway',
  LOG_LEVEL: 'fatal',
});

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** An AMQP connection that never connects: the consumer registers its setup and idles. */
function idleAmqp() {
  const calls = { setups: 0, topology: [] as { exchanges?: string[]; queues?: string[] }[] };
  const connection = stub('rabbitmq', {
    connected: false,
    blocked: false,
    start: () => undefined,
    close: () => Promise.resolve(),
    requireTopology: (objects: { exchanges?: string[]; queues?: string[] }) =>
      void calls.topology.push(objects),
    onConnected: () => {
      calls.setups += 1;
      return () => undefined;
    },
  });
  return { connection, calls };
}

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider, exposes the P24 metrics and reports mysql, rabbitmq, redis, s3', async () => {
    const amqp = idleAmqp();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(AmqpConnection)
      .useValue(amqp.connection)
      .overrideProvider(RedisService)
      .useValue(stub('redis'))
      .overrideProvider(S3Service)
      .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
      .compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of ['policy_evaluations_total', 'policy_copy_total', 'amqp_connection_up']) {
        expect(metrics).toContain(`# TYPE ${name} `);
      }
      const consumer = moduleRef.get(PolicyEvaluateConsumer, { strict: false });
      expect(consumer).toBeInstanceOf(PolicyEvaluateConsumer);
      // Started at bootstrap: subscribed once the broker connects.
      expect(amqp.calls.setups).toBe(1);
      expect(amqp.calls.topology).toContainEqual({
        exchanges: ['email.policy', 'email.events'],
        queues: ['email.policy.evaluate'],
      });
    } finally {
      await moduleRef.close();
    }
  });
});
