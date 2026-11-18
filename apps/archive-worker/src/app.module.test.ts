import { randomBytes } from 'node:crypto';
import { Test } from '@nestjs/testing';
import {
  AmqpConnection,
  HealthService,
  MetricsService,
  OpenSearchService,
  PrismaReadService,
  PrismaService,
  S3Service,
} from '@email-gateway/common';
import { generateExportSigningKeyPair } from '@email-gateway/archive';
import { describe, expect, it } from 'vitest';
import { ARCHIVE_COMPONENTS, ARCHIVE_LOCKS, AppModule, SERVICE_NAME } from './app.module';
import type { ArchiveComponents } from './components';
import { loadWorkerConfig } from './config';

const env = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  ARCHIVE_ROOT_KEY: randomBytes(32).toString('hex'),
  ARCHIVE_SEARCH_URL: 'http://127.0.0.1:9',
  RABBITMQ_ARCHIVE_URL: 'amqp://test:test@localhost:5672/email-gateway',
  ARCHIVE_EXPORT_SIGNING_KEY: generateExportSigningKeyPair().privateKey,
  LOG_LEVEL: 'fatal',
};

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** A writer with no work at all: every model call and raw query answers "nothing". */
function idlePrisma() {
  const model = new Proxy(
    {},
    {
      get: (_t, prop) => {
        if (prop === 'findMany' || prop === 'groupBy') return () => Promise.resolve([]);
        if (prop === 'count') return () => Promise.resolve(0);
        if (prop === 'deleteMany' || prop === 'updateMany')
          return () => Promise.resolve({ count: 0 });
        return () => Promise.resolve(null);
      },
    },
  );
  const client: Record<string | symbol, unknown> = {
    healthName: 'mysql',
    checkHealth: () => Promise.resolve(),
    $queryRaw: () => Promise.resolve([]),
    $queryRawUnsafe: () => Promise.resolve([]),
    $executeRaw: () => Promise.resolve(0),
    $transaction: (fn: (tx: unknown) => unknown) => Promise.resolve(fn(proxy)),
  };
  const proxy: unknown = new Proxy(client, {
    get: (target, prop) => (prop in target ? target[prop] : model),
  });
  return proxy;
}

const s3 = (lock: boolean) =>
  stub('s3', {
    client: {
      send: (command: { constructor: { name: string } }) =>
        command.constructor.name === 'GetObjectLockConfigurationCommand'
          ? Promise.resolve({
              ObjectLockConfiguration: { ObjectLockEnabled: lock ? 'Enabled' : undefined },
            })
          : Promise.resolve({}),
      destroy: () => undefined,
    },
    mailBucket: 'test-mail',
    archiveBucket: 'test-archive',
  });

const idleLocks = {
  ensure: () => Promise.resolve(false),
  release: () => Promise.resolve(),
  close: () => Promise.resolve(),
};

function idleAmqp() {
  const calls = { topology: [] as { exchanges?: string[]; queues?: string[] }[], setups: 0 };
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

async function compile(roles: string, extra: Record<string, string | undefined> = {}) {
  const amqp = idleAmqp();
  const config = loadWorkerConfig({ ...env, ARCHIVE_WORKER_ROLES: roles, ...extra });
  const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
    .overrideProvider(PrismaService)
    .useValue(idlePrisma())
    .overrideProvider(S3Service)
    .useValue(s3(true))
    .overrideProvider(AmqpConnection)
    .useValue(amqp.connection)
    .overrideProvider(ARCHIVE_LOCKS)
    .useValue(idleLocks)
    .compile();
  await moduleRef.init();
  return { moduleRef, amqp };
}

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring (A1, A27)', () => {
  it('runs every role: consumer, loops, metrics, probes mysql/s3/rabbitmq (never opensearch)', async () => {
    const { moduleRef, amqp } = await compile('capture,index,lifecycle,ediscovery');
    try {
      expect(SERVICE_NAME).toBe('archive-worker');
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 's3', 'rabbitmq']);
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      expect(moduleRef.get(OpenSearchService, { strict: false })).toBeInstanceOf(OpenSearchService);
      expect(amqp.calls.topology).toContainEqual({
        exchanges: ['email.archive', 'email.events'],
        queues: ['email.archive'],
      });
      const components = moduleRef.get<ArchiveComponents>(ARCHIVE_COMPONENTS, { strict: false });
      expect(components.capture?.loops.scheduler.running).toBe(true);
      expect(components.capture?.loops.journal.running).toBe(true);
      expect(components.index?.loops.sync.running).toBe(true);
      expect(components.lifecycle?.loops.disposal.running).toBe(true);
      expect(components.ediscovery?.loops.searches.running).toBe(true);
      expect(components.lockState.available).toBe(true);
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of [
        'archive_capture_total',
        'archive_capture_duration_seconds',
        'archive_capture_bytes_total',
        'archive_intents_pending',
        'archive_intent_oldest_pending_seconds',
        'archive_sweep_lag_seconds',
        'archive_consumer_events_total',
        'archive_scope_unresolved_total',
        'archive_index_queue_depth',
        'archive_index_oldest_seconds',
        'archive_index_ops_total',
        'archive_index_bulk_duration_seconds',
        'archive_reconcile_days_total',
        'archive_expiry_total',
        'archive_disposals_total',
        'archive_disposals_pending',
        'archive_disposal_oldest_pending_seconds',
        'archive_object_lock_total',
        'archive_root_rewrap_pending',
        'archive_orphans_total',
        'archive_ediscovery_searches_total',
        'archive_exports_total',
        'archive_export_bytes_total',
        'archive_integrity_failures_total',
      ]) {
        expect(metrics, name).toContain(`# HELP ${name} `);
      }
    } finally {
      await moduleRef.close();
    }
  });

  it('Kubernetes archive-worker (capture,index): rabbitmq probe, no lifecycle or eDiscovery loops', async () => {
    const { moduleRef } = await compile('capture,index');
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 's3', 'rabbitmq']);
      const components = moduleRef.get<ArchiveComponents>(ARCHIVE_COMPONENTS, { strict: false });
      expect(components.lifecycle).toBeNull();
      expect(components.ediscovery).toBeNull();
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
    } finally {
      await moduleRef.close();
    }
  });

  it('Kubernetes archive-jobs (lifecycle,ediscovery): no broker at all, mysql and s3 only', async () => {
    const { moduleRef } = await compile('lifecycle,ediscovery', {
      RABBITMQ_ARCHIVE_URL: undefined,
    });
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 's3']);
      expect(() => moduleRef.get(AmqpConnection, { strict: false })).toThrow();
      const components = moduleRef.get<ArchiveComponents>(ARCHIVE_COMPONENTS, { strict: false });
      expect(components.capture).toBeNull();
      expect(components.index).toBeNull();
      expect(components.lifecycle?.loops.lifecycle.running).toBe(true);
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
    } finally {
      await moduleRef.close();
    }
  });

  it('lifecycle without a search URL registers no OpenSearch client', async () => {
    const { moduleRef } = await compile('lifecycle', {
      RABBITMQ_ARCHIVE_URL: undefined,
      ARCHIVE_SEARCH_URL: undefined,
      ARCHIVE_EXPORT_SIGNING_KEY: undefined,
    });
    try {
      expect(() => moduleRef.get(OpenSearchService, { strict: false })).toThrow();
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 's3']);
    } finally {
      await moduleRef.close();
    }
  });
});
