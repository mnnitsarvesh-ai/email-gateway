import { Test } from '@nestjs/testing';
import {
  AmqpConnection,
  HealthService,
  MetricsService,
  PrismaReadService,
  PrismaService,
  RedisService,
} from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { AppModule, SERVICE_NAME } from './app.module';
import { loadWorkerConfig } from './config';
import {
  DELIVERY_COMPONENTS,
  type DeliveryComponents,
  MAINTENANCE_LOCKS,
} from './delivery/delivery.module';
import { FanoutService } from './fanout/fanout.service';

const env = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379/0',
  RABBITMQ_WEBHOOK_URL: 'amqp://test:test@localhost:5672/email-gateway',
  WEBHOOK_SECRET_ENCRYPTION_KEY: 'a'.repeat(64),
  LOG_LEVEL: 'fatal',
};

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** A writer that has no due work (the loops idle). */
const idlePrisma = () =>
  stub('mysql', {
    $queryRaw: () => Promise.resolve([]),
    $executeRaw: () => Promise.resolve(0),
    webhookReplay: { findMany: () => Promise.resolve([]) },
    webhookSubscription: { findMany: () => Promise.resolve([]) },
  });

const idleRedis = () =>
  stub('redis', {
    client: {
      ping: () => Promise.resolve('PONG'),
      get: () => Promise.resolve(null),
      eval: () => Promise.resolve(0),
    },
  });

const idleLocks = {
  ensure: () => Promise.resolve(false),
  release: () => Promise.resolve(),
  close: () => Promise.resolve(),
};

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

async function compile(roles: string) {
  const amqp = idleAmqp();
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule.forRoot(loadWorkerConfig({ ...env, WEBHOOK_WORKER_ROLES: roles }))],
  })
    .overrideProvider(PrismaService)
    .useValue(idlePrisma())
    .overrideProvider(AmqpConnection)
    .useValue(amqp.connection)
    .overrideProvider(RedisService)
    .useValue(idleRedis())
    .overrideProvider(MAINTENANCE_LOCKS)
    .useValue(idleLocks)
    .compile();
  await moduleRef.init();
  return { moduleRef, amqp };
}

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('runs both roles: fanout consumer, delivery loops, every webhook metric, three probes', async () => {
    const { moduleRef, amqp } = await compile('fanout,delivery');
    try {
      expect(SERVICE_NAME).toBe('webhook-worker');
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis']);
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      expect(moduleRef.get(FanoutService, { strict: false })).toBeInstanceOf(FanoutService);
      const components = moduleRef.get<DeliveryComponents>(DELIVERY_COMPONENTS, { strict: false });
      expect(components.loop.running).toBe(true);
      expect(components.replayLoop.running).toBe(true);
      expect(amqp.calls.setups).toBe(1);
      expect(amqp.calls.topology).toContainEqual({
        exchanges: ['email.events'],
        queues: ['email.webhooks'],
      });
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of [
        'webhook_fanout_events_total',
        'webhook_events_created_total',
        'webhook_deliveries_created_total',
        'webhook_delivery_attempts_total',
        'webhook_delivery_duration_seconds',
        'webhook_deliveries_dead_total',
        'webhook_subscriptions_disabled_total',
        'webhook_due_backlog',
        'webhook_oldest_due_age_seconds',
        'webhook_ssrf_blocked_total',
        'webhook_rate_limited_total',
        'webhook_rate_limit_store_errors_total',
        'webhook_replays_total',
        'webhook_alert_requests_total',
        'webhook_inconsistent_reads_total',
        'amqp_connection_up',
      ]) {
        expect(metrics).toContain(`# TYPE ${name} `);
      }
    } finally {
      await moduleRef.close();
    }
  });

  it('fanout only: no Redis, no delivery loop', async () => {
    const { moduleRef, amqp } = await compile('fanout');
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq']);
      expect(() => moduleRef.get<unknown>(DELIVERY_COMPONENTS, { strict: false })).toThrow();
      expect(amqp.calls.setups).toBe(1);
    } finally {
      await moduleRef.close();
    }
  });

  it('delivery only: no broker connection, no fanout consumer', async () => {
    const { moduleRef, amqp } = await compile('delivery');
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'redis']);
      expect(() => moduleRef.get(FanoutService, { strict: false })).toThrow();
      expect(amqp.calls.setups).toBe(0);
      expect(amqp.calls.topology).toEqual([]);
    } finally {
      await moduleRef.close();
    }
  });
});
