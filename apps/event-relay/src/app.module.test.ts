import { Test } from '@nestjs/testing';
import {
  AdvisoryLocks,
  AmqpConnection,
  HealthService,
  MetricsService,
  PrismaReadService,
  PrismaService,
} from '@email-gateway/common';
import { EXCHANGE_NAMES } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadRelayConfig } from './config';
import { RelayLifecycle } from './relay-lifecycle';

const baseEnv = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_RELAY_URL: 'amqp://test:test@localhost:5672/email-gateway',
  LOG_LEVEL: 'fatal',
};

/** Stubs of the infrastructure clients: no background loop reaches a real server. */
function stubs() {
  const required: string[] = [];
  const connection = {
    healthName: 'rabbitmq',
    connected: false,
    blocked: false,
    start: () => undefined,
    close: () => Promise.resolve(),
    requireTopology: (objects: { exchanges?: string[] }) =>
      required.push(...(objects.exchanges ?? [])),
    checkHealth: () => Promise.resolve(),
    waitUntilUnblocked: () => Promise.resolve(true),
    createConfirmChannel: () => Promise.reject(new Error('stub')),
  };
  const locks = {
    ensure: () => Promise.resolve(false),
    isHeld: () => false,
    heldCount: () => 0,
    release: () => Promise.resolve(),
    close: () => Promise.resolve(),
  };
  const prisma = { healthName: 'mysql', checkHealth: () => Promise.resolve() };
  return { connection, locks, prisma, required };
}

async function compile(env: Record<string, string>) {
  const s = stubs();
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule.forRoot(loadRelayConfig({ ...baseEnv, ...env }))],
  })
    .overrideProvider(PrismaService)
    .useValue(s.prisma)
    .overrideProvider(AmqpConnection)
    .useValue(s.connection)
    .overrideProvider(AdvisoryLocks)
    .useValue(s.locks)
    .compile();
  await moduleRef.init();
  return { moduleRef, ...s };
}

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider, verifies the six exchanges and reports mysql + rabbitmq', async () => {
    const { moduleRef, required } = await compile({});
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq']);
      expect(report.status).toBe('ok');
      expect([...required].sort()).toEqual([...EXCHANGE_NAMES].sort());
      // Data plane is writer-only (ADR-0014).
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of [
        'outbox_relay_published_total',
        'outbox_relay_lag_seconds',
        'outbox_poison_rows',
        'reconcile_redriven_total',
        'amqp_connection_up',
        'amqp_publish_total',
      ]) {
        expect(metrics).toContain(`# TYPE ${name} `);
      }
    } finally {
      await moduleRef.close();
    }
  });

  it('starts only the enabled roles', async () => {
    for (const [env, roles] of [
      [{}, ['relay', 'reconciler']],
      [{ RELAY_ENABLED: 'false' }, ['reconciler']],
      [{ RECONCILE_ENABLED: 'false' }, ['relay']],
      [{ RELAY_ENABLED: 'false', RECONCILE_ENABLED: 'false' }, []],
    ] as const) {
      const { moduleRef } = await compile(env);
      const app = moduleRef.createNestApplication();
      await app.init();
      try {
        expect(app.get(RelayLifecycle, { strict: false }).startedRoles).toEqual(roles);
      } finally {
        await app.close();
      }
    }
  });
});
