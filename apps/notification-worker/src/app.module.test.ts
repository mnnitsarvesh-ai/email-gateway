import { Test } from '@nestjs/testing';
import { HealthService, PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadWorkerConfig } from './config';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
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
      .compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql']);
      expect(report.status).toBe('ok');
    } finally {
      await moduleRef.close();
    }
  });
});
