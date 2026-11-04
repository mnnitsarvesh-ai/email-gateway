import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import { HEALTH_INDICATORS, type HealthIndicator } from '../health/health-indicator';
import { HealthModule } from '../health/health.module';
import { MetricsModule } from '../metrics/metrics.module';
import { MetricsService } from '../metrics/metrics.service';
import { AMQP_MESSAGING_METRICS, AmqpModule } from './amqp.module';
import { AmqpConnection } from './connection';
import { ConfirmPublisher } from './publisher';
import { memoryLogger } from './testing/fake-amqp';

describe('AmqpModule', () => {
  it('provides the connection (rabbitmq health indicator) and publisher without awaiting the broker', async () => {
    const { logger, raw } = memoryLogger();
    const moduleRef = await Test.createTestingModule({
      imports: [
        MetricsModule.forRoot({ service: 'amqp-module-test' }),
        AmqpModule.forRoot({
          // Nothing listens here: init must not wait for (or fail on) the broker.
          urls: ['amqp://user:module-secret@127.0.0.1:1/vh'],
          connectionName: 'module-test',
          appId: 'module-test',
          verify: { exchanges: ['email.events'] },
          logger,
          reconnect: { baseMs: 10, maxMs: 20 },
        }),
        HealthModule.forRoot({
          service: { name: 'x', version: '0' },
          indicators: [AmqpConnection],
        }),
      ],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const connection = app.get(AmqpConnection);
    expect(connection).toBeInstanceOf(AmqpConnection);
    expect(app.get(ConfirmPublisher)).toBeInstanceOf(ConfirmPublisher);
    expect(app.get(AMQP_MESSAGING_METRICS)).not.toBeNull();
    const indicators = app.get<HealthIndicator[]>(HEALTH_INDICATORS);
    expect(indicators.map((i) => i.healthName)).toEqual(['rabbitmq']);
    await expect(connection.checkHealth()).rejects.toThrow(/disconnected/);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const metrics = await app.get(MetricsService).metrics();
    expect(metrics).toContain(
      'amqp_connection_up{connection="module-test",service="amqp-module-test"} 0',
    );
    await app.close();
    expect(connection.connected).toBe(false);
    expect(raw()).not.toContain('module-secret');
    expect(raw()).toContain('AMQP connect failed; retrying');
  });
});
