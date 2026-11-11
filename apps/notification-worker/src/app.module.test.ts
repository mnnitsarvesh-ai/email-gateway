import { Test } from '@nestjs/testing';
import {
  AmqpConnection,
  HealthService,
  MetricsService,
  PrismaService,
} from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadWorkerConfig } from './config';
import { PolicyNotificationHandler } from './notifications/policy-notification.handler';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_NOTIFICATION_URL: 'amqp://test:test@localhost:5672/email-gateway',
  LOG_LEVEL: 'fatal',
});

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider, registers the metrics and checks mysql and rabbitmq', async () => {
    const topology: Array<{ exchanges?: string[]; queues?: string[] }> = [];
    let setups = 0;
    const connection = stub('rabbitmq', {
      connected: false,
      blocked: false,
      start: () => undefined,
      close: () => Promise.resolve(),
      requireTopology: (objects: { exchanges?: string[]; queues?: string[] }) =>
        void topology.push(objects),
      onConnected: () => {
        setups += 1;
        return () => undefined;
      },
    });
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(AmqpConnection)
      .useValue(connection)
      .compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq']);
      expect(moduleRef.get(PolicyNotificationHandler)).toBeInstanceOf(PolicyNotificationHandler);
      expect(setups).toBeGreaterThanOrEqual(1);
      expect(JSON.stringify(topology)).toContain('email.notifications');
      const text = await moduleRef.get(MetricsService).metrics();
      expect(text).toContain('notification_policy_messages_total');
      expect(text).toContain('notification_send_duration_seconds');
    } finally {
      await moduleRef.close();
    }
  });
});
