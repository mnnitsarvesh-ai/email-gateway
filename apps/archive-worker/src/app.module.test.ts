import { Test } from '@nestjs/testing';
import {
  HealthService,
  PrismaReadService,
  PrismaService,
  RabbitMqService,
  S3Service,
} from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadWorkerConfig } from './config';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_URL: 'amqp://test:test@localhost:5672',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
});

const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider and reports the expected readiness checks', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(RabbitMqService)
      .useValue(stub('rabbitmq'))
      .overrideProvider(S3Service)
      .useValue(stub('s3'))
      .compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 's3']);
      expect(report.status).toBe('ok');
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
    } finally {
      await moduleRef.close();
    }
  });
});
