import { Test } from '@nestjs/testing';
import type { Type } from '@nestjs/common';
import {
  type HealthIndicator,
  HealthService,
  MetricsService,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { BOUNCES_HEALTH_INDICATORS } from './bounces/bounces.module';
import { loadSmtpAdapterConfig } from './config';
import { INGESTION_HEALTH_INDICATORS } from './ingestion/ingestion.module';

/** Six distinct ephemeral high ports so the real listeners can bind during the test. */
const base = 40_000 + Math.floor(Math.random() * 2_000) * 10;
const config = loadSmtpAdapterConfig({
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  GATEWAY_TRACE_SECRET: 'test-trace-secret-0123456789abcdef0123456789',
  POLICY_HOST: '127.0.0.1',
  MAIL_LISTEN_HOST: '127.0.0.1',
  POLICY_PORT: String(base),
  SOCKETMAP_PORT: String(base + 1),
  SASL_AUTH_PORT: String(base + 2),
  LMTP_INBOUND_PORT: String(base + 3),
  LMTP_OUTBOUND_PORT: String(base + 4),
  LMTP_BOUNCE_PORT: String(base + 5),
  // The invalidator would query the (stubbed) database on boot.
  SMTP_CACHE_INVALIDATION_POLL_MS: '0',
  LOG_LEVEL: 'fatal',
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
      .overrideProvider(S3Service)
      .useValue(stub('s3'))
      .compile();
    await moduleRef.init();
    try {
      const lmtpChecks = [...INGESTION_HEALTH_INDICATORS, ...BOUNCES_HEALTH_INDICATORS].map(
        (type: Type<HealthIndicator>) => moduleRef.get(type, { strict: false }).healthName,
      );
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual([
        'mysql',
        'redis',
        's3',
        'policy-listener',
        'socketmap-listener',
        'sasl-listener',
        ...lmtpChecks,
      ]);
      expect(lmtpChecks.length).toBeGreaterThanOrEqual(3);
      expect(report.status).toBe('ok');
      // Metrics registry is global (GET /metrics) and shared by every component.
      expect(moduleRef.get(MetricsService, { strict: false })).toBeInstanceOf(MetricsService);
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
    } finally {
      await moduleRef.close();
    }
  });

  it('refuses an invalid internal network list or MX host list at startup', () => {
    const env = {
      DATABASE_URL: 'mysql://test:test@localhost:3306/test',
      REDIS_URL: 'redis://localhost:6379',
      S3_REGION: 'ap-south-1',
      S3_BUCKET_MAIL: 'test-mail',
      S3_BUCKET_ARCHIVE: 'test-archive',
      GATEWAY_TRACE_SECRET: 'test-trace-secret-0123456789abcdef0123456789',
    };
    expect(() =>
      loadSmtpAdapterConfig({ ...env, SMTP_INTERNAL_CLIENT_NETWORKS: '10.0.0.0/33' }),
    ).toThrow('SMTP_INTERNAL_CLIENT_NETWORKS');
    expect(() => loadSmtpAdapterConfig({ ...env, GATEWAY_MX_HOSTS: 'mx.example.com' })).toThrow(
      'GATEWAY_MX_HOSTS',
    );
  });
});
