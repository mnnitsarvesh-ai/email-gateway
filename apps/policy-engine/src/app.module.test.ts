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
import { SWEEPER_LOCKS } from './quarantine/quarantine.module';
import { QuarantineReleaseConsumer } from './quarantine/release.consumer';
import { QuarantineSweeper } from './quarantine/sweeper';

const env = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  RABBITMQ_POLICY_ENGINE_URL: 'amqp://test:test@localhost:5672/email-gateway',
  URL_TOKEN_KEY_CURRENT: 'ab'.repeat(32),
  LOG_LEVEL: 'fatal',
};
const config = loadWorkerConfig(env);

/** A lock connection that never leads (the sweeper idles). */
const idleLocks = {
  ensure: () => Promise.resolve(false),
  release: () => Promise.resolve(),
  close: () => Promise.resolve(),
};

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
      .overrideProvider(SWEEPER_LOCKS)
      .useValue(idleLocks)
      .compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of [
        'policy_evaluations_total',
        'policy_copy_total',
        'policy_url_rewrite_total',
        'policy_body_banner_total',
        'policy_recipient_split_total',
        'quarantine_entries_created_total',
        'quarantine_releases_total',
        'quarantine_sweep_last_success_timestamp_seconds',
        'quarantine_entries',
        'quarantine_pending_approvals',
        'amqp_connection_up',
      ]) {
        expect(metrics).toContain(`# TYPE ${name} `);
      }
      const consumer = moduleRef.get(PolicyEvaluateConsumer, { strict: false });
      expect(consumer).toBeInstanceOf(PolicyEvaluateConsumer);
      expect(moduleRef.get(QuarantineReleaseConsumer, { strict: false })).toBeInstanceOf(
        QuarantineReleaseConsumer,
      );
      expect(moduleRef.get(QuarantineSweeper, { strict: false }).running).toBe(true);
      // Started at bootstrap: both consumers subscribe once the broker connects.
      expect(amqp.calls.setups).toBe(2);
      expect(amqp.calls.topology).toContainEqual({
        exchanges: ['email.policy', 'email.events'],
        queues: ['email.policy.evaluate', 'email.quarantine'],
      });
    } finally {
      await moduleRef.close();
    }
  });

  it.each([
    ['evaluate', ['email.policy.evaluate'], true, false],
    ['quarantine', ['email.quarantine'], false, true],
  ] as const)(
    'POLICY_ENGINE_ROLES=%s loads only its modules (Q28)',
    async (roles, queues, evaluate, quarantine) => {
      const amqp = idleAmqp();
      const moduleRef = await Test.createTestingModule({
        imports: [AppModule.forRoot(loadWorkerConfig({ ...env, POLICY_ENGINE_ROLES: roles }))],
      })
        .overrideProvider(PrismaService)
        .useValue(stub('mysql'))
        .overrideProvider(AmqpConnection)
        .useValue(amqp.connection)
        .overrideProvider(RedisService)
        .useValue(stub('redis'))
        .overrideProvider(S3Service)
        .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
        .overrideProvider(SWEEPER_LOCKS)
        .useValue(idleLocks)
        .compile();
      await moduleRef.init();
      try {
        const has = (token: unknown) => {
          try {
            moduleRef.get(token as never, { strict: false });
            return true;
          } catch {
            return false;
          }
        };
        expect(has(PolicyEvaluateConsumer)).toBe(evaluate);
        expect(has(QuarantineReleaseConsumer)).toBe(quarantine);
        expect(has(QuarantineSweeper)).toBe(quarantine);
        expect(amqp.calls.setups).toBe(1);
        expect(amqp.calls.topology).toContainEqual({
          exchanges: ['email.policy', 'email.events'],
          queues: [...queues],
        });
        const report = await moduleRef.get(HealthService).readiness();
        expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
      } finally {
        await moduleRef.close();
      }
    },
  );
});
