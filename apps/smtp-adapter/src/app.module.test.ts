import { Test } from '@nestjs/testing';
import { HealthService, PrismaService, RedisService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadSmtpAdapterConfig } from './config';

const config = loadSmtpAdapterConfig({
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_URL: 'amqp://test:test@localhost:5672',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  // Ephemeral high port so the real policy listener can bind during the test.
  POLICY_PORT: String(40_000 + Math.floor(Math.random() * 10_000)),
  POLICY_HOST: '127.0.0.1',
});

const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider and reports the expected readiness checks', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(RedisService)
      .useValue(stub('redis'))
      .compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'redis', 'policy-listener']);
      expect(report.status).toBe('ok');
    } finally {
      await moduleRef.close();
    }
  });
});
