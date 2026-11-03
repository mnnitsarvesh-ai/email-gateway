import { Test } from '@nestjs/testing';
import {
  AdvisoryLocks,
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
import { MimeIngestionRuntime } from './mime-ingestion/mime-ingestion.module';

const env = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_URL: 'amqp://test:test@localhost:5672',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  LOG_LEVEL: 'fatal',
};

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** A lock connection that never wins: the feed's pollers idle and touch no database. */
const idleLocks = {
  ensure: () => Promise.resolve(false),
  isHeld: () => false,
  heldCount: () => 0,
  release: () => Promise.resolve(),
  close: () => Promise.resolve(),
};

async function compile(overrides: Record<string, string> = {}) {
  const config = loadWorkerConfig({ ...env, ...overrides });
  return Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
    .overrideProvider(PrismaService)
    .useValue(stub('mysql'))
    .overrideProvider(RabbitMqService)
    .useValue(stub('rabbitmq'))
    .overrideProvider(RedisService)
    .useValue(stub('redis', { client: {} }))
    .overrideProvider(S3Service)
    .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
    .overrideProvider(AdvisoryLocks)
    .useValue(idleLocks)
    .compile();
}

const MIME_SERIES = [
  'mime_parse_messages_total',
  'mime_parse_duration_seconds',
  'mime_parse_bytes_total',
  'mime_limit_exceeded_total',
  'mime_defects_total',
  'mime_parse_failures_total',
  'mime_attachments_total',
  'mime_attachment_flags_total',
  'mime_retries_total',
  'mime_outbox_poll_lag_seconds',
  'mime_outbox_invalid_total',
];

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider, starts MIME ingestion and reports the readiness checks', async () => {
    const moduleRef = await compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
      expect(report.status).toBe('ok');
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      // The stage runs after bootstrap, and every M16 series is on GET /metrics.
      expect(moduleRef.get(MimeIngestionRuntime, { strict: false }).running).toBe(true);
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of MIME_SERIES) expect(metrics).toContain(`# TYPE ${name} `);
    } finally {
      await moduleRef.close();
    }
    expect(moduleRef.get(MimeIngestionRuntime, { strict: false }).running).toBe(false);
  });

  it('does not wire the stage when MIME_INGESTION_ENABLED is false', async () => {
    const moduleRef = await compile({ MIME_INGESTION_ENABLED: 'false' });
    await moduleRef.init();
    try {
      expect(() => moduleRef.get(MimeIngestionRuntime, { strict: false })).toThrow();
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
    } finally {
      await moduleRef.close();
    }
  });
});
