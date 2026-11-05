import { Test } from '@nestjs/testing';
import {
  AmqpConnection,
  HealthService,
  MetricsService,
  PrismaReadService,
  PrismaService,
  QueueConsumer,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { EventTypes } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { AppModule } from './app.module';
import { loadWorkerConfig } from './config';
import {
  classifyMimeFailure,
  MIME_FEED,
  MimeIngestionRuntime,
} from './mime-ingestion/mime-ingestion.module';
import { MIME_CONSUMER } from './mime-ingestion/mime-ingestion.service';
import { classifyScanFailure } from './scanning/engine-consumer';
import { ATTACHMENT_CONSUMER } from './scanning/engines/attachment/registration';
import { RSPAMD_CONSUMER } from './scanning/engines/rspamd/registration';
import {
  ATTACHMENT_JOBS,
  type AttachmentJobs,
  type EngineRuntime,
  SCAN_ENGINES,
  SCAN_LOCKS,
  SCANNER_AMQP_CONNECTION,
  ScanningRuntime,
} from './scanning/scanning.module';

const env = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://test:test@localhost:5672/email-gateway',
  RABBITMQ_SCANNER_URL: 'amqp://scan:test@localhost:5672/email-gateway',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  LOG_LEVEL: 'fatal',
  // The step 4.1 wiring tests run the Rspamd engine alone; the attachment wiring has its own.
  SCAN_ENGINES: 'rspamd',
};

const stub = (healthName: string, extra: Record<string, unknown> = {}) => ({
  healthName,
  checkHealth: () => Promise.resolve(),
  ...extra,
});

/** An AMQP connection that never connects: the consumer registers its setup and idles. */
function idleAmqp() {
  const calls = {
    started: 0,
    closed: 0,
    setups: 0,
    unregistered: 0,
    topology: [] as { exchanges?: string[]; queues?: string[] }[],
  };
  const connection = stub('rabbitmq', {
    connected: false,
    blocked: false,
    start: () => void (calls.started += 1),
    close: () => {
      calls.closed += 1;
      return Promise.resolve();
    },
    requireTopology: (objects: { exchanges?: string[]; queues?: string[] }) =>
      void calls.topology.push(objects),
    onConnected: () => {
      calls.setups += 1;
      return () => void (calls.unregistered += 1);
    },
  });
  return { connection, calls };
}

/** The sweeper's lock connection: never the leader, records its close. */
function idleLocks() {
  const calls = { ensured: 0, closed: 0 };
  const locks = {
    ensure: () => {
      calls.ensured += 1;
      return Promise.resolve(false);
    },
    release: () => Promise.resolve(),
    close: () => {
      calls.closed += 1;
      return Promise.resolve();
    },
  };
  return { locks, calls };
}

async function compile(overrides: Record<string, string> = {}) {
  const config = loadWorkerConfig({ ...env, ...overrides });
  const amqp = idleAmqp();
  const scanner = idleAmqp();
  const locks = idleLocks();
  const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
    .overrideProvider(PrismaService)
    .useValue(stub('mysql'))
    .overrideProvider(AmqpConnection)
    .useValue(amqp.connection)
    .overrideProvider(SCANNER_AMQP_CONNECTION)
    .useValue(scanner.connection)
    .overrideProvider(SCAN_LOCKS)
    .useValue(locks.locks)
    .overrideProvider(RedisService)
    .useValue(stub('redis', { client: {} }))
    .overrideProvider(S3Service)
    .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
    .compile();
  return { moduleRef, amqp, scanner, locks };
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
];
/** The scan stage's series (step 4.1 S17). */
const SCAN_SERIES = [
  'scan_engine_results_total',
  'scan_engine_duration_seconds',
  'scan_engine_failures_total',
  'scan_engine_circuit_state',
  'scan_engine_circuit_transitions_total',
  'scan_rounds_completed_total',
  'scan_round_duration_seconds',
  'scan_event_lag_seconds',
  'scan_events_skipped_total',
  'scan_rounds_superseded_total',
  'scan_deadline_finalized_total',
  'scan_settings_cache_total',
  'scan_settings_invalid_total',
  'scan_engine_info',
  'lifecycle_transitions_total',
];
/** The transport's series (step 3.2 §5.3) of the shared AMQP client. */
const AMQP_SERIES = [
  'amqp_connection_up',
  'amqp_consumer_messages_total',
  'amqp_consumer_in_flight',
  'amqp_consumer_active',
];

/** Compiles the real module graph (infra clients stubbed) so DI wiring errors fail in CI. */
describe('AppModule wiring', () => {
  it('resolves every provider, starts MIME ingestion and reports the readiness checks', async () => {
    const { moduleRef, amqp } = await compile();
    await moduleRef.init();
    try {
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual([
        'mysql',
        'rabbitmq',
        'rabbitmq-scanner',
        'redis',
        's3',
      ]);
      expect(report.status).toBe('ok');
      // Data plane is writer-only (ADR-0014): the read replica is not even registered.
      expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
      // The stage runs after bootstrap, and every M16 series is on GET /metrics.
      expect(moduleRef.get(MimeIngestionRuntime, { strict: false }).running).toBe(true);
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of [...MIME_SERIES, ...AMQP_SERIES]) {
        expect(metrics).toContain(`# TYPE ${name} `);
      }
      // The 3.1 outbox-poller series went with the poller (step 3.2 §5.3).
      expect(metrics).not.toContain('mime_outbox_');
      // AMQP: started in the background, the consumer subscribed on (re)connect, and the
      // objects it consumes from / publishes to are verified passively for readiness.
      expect(amqp.calls.started).toBe(1);
      expect(amqp.calls.setups).toBe(1);
      expect(amqp.calls.topology).toContainEqual({
        exchanges: ['email.ingestion', 'email.events'],
        queues: ['email.received'],
      });
    } finally {
      await moduleRef.close();
    }
    expect(moduleRef.get(MimeIngestionRuntime, { strict: false }).running).toBe(false);
    // Stop order: consumer (unregistered), then the AMQP connection.
    expect(amqp.calls.unregistered).toBe(1);
    expect(amqp.calls.closed).toBeGreaterThanOrEqual(1);
  });

  it('builds the email.received QueueConsumer of design Q13', async () => {
    const { moduleRef } = await compile({
      MIME_CONCURRENCY: '6',
      MIME_RETRY_BASE_MS: '250',
      MIME_RETRY_MAX_MS: '20000',
    });
    const feed = moduleRef.get<QueueConsumer<unknown>>(MIME_FEED, { strict: false });
    expect(feed).toBeInstanceOf(QueueConsumer);
    expect(feed.queue).toBe('email.received');
    expect(feed.consumerName).toBe(MIME_CONSUMER);
    expect(feed.retryPolicy).toEqual({
      strategy: 'hold',
      maxAttempts: 8,
      baseDelayMs: 250,
      maxDelayMs: 20_000,
      maxRetryAgeMs: 24 * 3600 * 1000,
    });
    const options = (
      feed as unknown as {
        options: { prefetch: number; eventTypes: string[]; classify: unknown };
      }
    ).options;
    expect(options.prefetch).toBe(6);
    expect(options.eventTypes).toEqual([EventTypes.MessageReceived]);
    expect(options.classify).toBe(classifyMimeFailure);
    await moduleRef.close();
  });

  it('classifies the stage transient failures as transient and everything else as retryable', () => {
    const outage = new Prisma.PrismaClientKnownRequestError("Can't reach database server", {
      code: 'P1001',
      clientVersion: 'test',
    });
    expect(classifyMimeFailure(outage)).toBe('transient');
    expect(classifyMimeFailure({ name: 'S3Stalled' })).toBe('transient');
    expect(classifyMimeFailure({ $metadata: { httpStatusCode: 403 } })).toBe('transient');
    expect(classifyMimeFailure(new Error('unexpected'))).toBe('retryable');
    const unique = new Prisma.PrismaClientKnownRequestError('unique', {
      code: 'P2002',
      clientVersion: 'test',
    });
    expect(classifyMimeFailure(unique)).toBe('retryable');
  });

  it('runs scan-only without the email-worker broker user when MIME_INGESTION_ENABLED is false', async () => {
    const { RABBITMQ_EMAIL_WORKER_URL: _omitted, ...scanOnlyEnv } = env;
    const config = loadWorkerConfig({ ...scanOnlyEnv, MIME_INGESTION_ENABLED: 'false' });
    const scanner = idleAmqp();
    const locks = idleLocks();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(SCANNER_AMQP_CONNECTION)
      .useValue(scanner.connection)
      .overrideProvider(SCAN_LOCKS)
      .useValue(locks.locks)
      .overrideProvider(RedisService)
      .useValue(stub('redis', { client: {} }))
      .overrideProvider(S3Service)
      .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
      .compile();
    await moduleRef.init();
    try {
      expect(() => moduleRef.get(MimeIngestionRuntime, { strict: false })).toThrow();
      // The global AMQP client (eg-email-worker) is not even registered.
      expect(() => moduleRef.get(AmqpConnection, { strict: false })).toThrow();
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual([
        'mysql',
        'rabbitmq-scanner',
        'redis',
        's3',
      ]);
      expect(moduleRef.get(ScanningRuntime, { strict: false }).running).toBe(true);
    } finally {
      await moduleRef.close();
    }
  });

  it('does not wire the scan stage when SCAN_ENABLED is false', async () => {
    const { moduleRef, amqp } = await compile({ SCAN_ENABLED: 'false' });
    await moduleRef.init();
    try {
      expect(() => moduleRef.get(ScanningRuntime, { strict: false })).toThrow();
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
      expect(amqp.calls.setups).toBe(1);
      const metrics = await moduleRef.get(MetricsService).metrics();
      expect(metrics).not.toContain('scan_engine_results_total');
    } finally {
      await moduleRef.close();
    }
  });

  it('wires one scan.spam consumer per enabled engine on its own broker connection (S1, S5)', async () => {
    const { moduleRef, scanner, locks } = await compile({
      SCAN_RSPAMD_CONCURRENCY: '5',
      SCAN_RETRY_BASE_MS: '500',
      SCAN_RETRY_MAX_MS: '30000',
    });
    await moduleRef.init();
    try {
      const engines = moduleRef.get<EngineRuntime[]>(SCAN_ENGINES, { strict: false });
      expect(engines.map((e) => e.registration.catalog.name)).toEqual(['rspamd']);
      const feed = engines[0]!.consumer;
      expect(feed).toBeInstanceOf(QueueConsumer);
      expect(feed.queue).toBe('scan.spam');
      expect(feed.consumerName).toBe(RSPAMD_CONSUMER);
      expect(feed.retryPolicy).toEqual({
        strategy: 'hold',
        maxAttempts: 10,
        baseDelayMs: 500,
        maxDelayMs: 30_000,
        maxRetryAgeMs: 24 * 3600 * 1000,
      });
      const options = (
        feed as unknown as {
          options: { prefetch: number; eventTypes: string[]; classify: unknown };
        }
      ).options;
      expect(options.prefetch).toBe(5);
      expect(options.eventTypes).toEqual([
        EventTypes.MessageParsed,
        EventTypes.MessageRescanRequested,
      ]);
      expect(options.classify).toBe(classifyScanFailure);
      // Its own connection: started, verified passively, the consumer subscribed on connect.
      expect(scanner.calls.started).toBe(1);
      expect(scanner.calls.topology).toContainEqual({
        exchanges: ['email.security', 'email.events'],
        queues: ['scan.spam'],
      });
      expect(scanner.calls.setups).toBe(1);
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of SCAN_SERIES) expect(metrics).toContain(`# TYPE ${name} `);
      expect(metrics).toContain(
        'scan_engine_circuit_state{engine="rspamd",service="email-worker"} 0',
      );
    } finally {
      await moduleRef.close();
    }
    expect(scanner.calls.unregistered).toBe(1);
    expect(scanner.calls.closed).toBe(1);
    expect(locks.calls.closed).toBe(1);
  });

  it('wires the attachment consumer, its readiness checks and background jobs (step 4.2 A1, A12)', async () => {
    const { RABBITMQ_EMAIL_WORKER_URL: _omitted, ...scanOnlyEnv } = env;
    const config = loadWorkerConfig({
      ...scanOnlyEnv,
      MIME_INGESTION_ENABLED: 'false',
      SCAN_ENGINES: 'rspamd,attachment',
      SCAN_CONSUMERS: 'attachment',
      ATTACHMENT_INSPECTOR_RLIMITS: 'best_effort',
      ATTACHMENT_INSPECTOR_POOL_SIZE: '1',
      // A closed port: clamd readiness fails, nothing else depends on it here.
      CLAMAV_PORT: '1',
    });
    const scanner = idleAmqp();
    const locks = idleLocks();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(SCANNER_AMQP_CONNECTION)
      .useValue(scanner.connection)
      .overrideProvider(SCAN_LOCKS)
      .useValue(locks.locks)
      .overrideProvider(RedisService)
      .useValue(stub('redis', { client: {} }))
      .overrideProvider(S3Service)
      .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
      .compile();
    await moduleRef.init();
    try {
      const engines = moduleRef.get<EngineRuntime[]>(SCAN_ENGINES, { strict: false });
      expect(engines.map((e) => e.registration.catalog.name)).toEqual(['attachment']);
      const feed = engines[0]!.consumer;
      expect(feed.queue).toBe('scan.attachment');
      expect(feed.consumerName).toBe(ATTACHMENT_CONSUMER);
      expect(feed.retryPolicy.maxAttempts).toBe(10);
      expect((feed as unknown as { options: { prefetch: number } }).options.prefetch).toBe(4);
      expect(scanner.calls.topology).toContainEqual({
        exchanges: ['email.security', 'email.events'],
        queues: ['scan.attachment'],
      });
      const jobs = moduleRef.get<AttachmentJobs | null>(ATTACHMENT_JOBS, { strict: false });
      expect(jobs?.watcher.running).toBe(true);
      expect(jobs?.runner.running).toBe(true);
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual([
        'mysql',
        'rabbitmq-scanner',
        'clamav',
        'attachment-inspector',
        'redis',
        's3',
      ]);
      const inspector = report.checks.find((c) => c.name === 'attachment-inspector')!;
      expect(inspector.status).toBe('ok');
      expect(report.checks.find((c) => c.name === 'clamav')!.status).not.toBe('ok');
      const metrics = await moduleRef.get(MetricsService).metrics();
      for (const name of [
        'scan_attachment_files_total',
        'scan_attachment_inspector_pool',
        'scan_attachment_memory_budget_bytes',
        'scan_attachment_inspector_kills_total',
        'clamav_requests_total',
        'scan_attachment_signature_info',
      ]) {
        expect(metrics).toContain(`# TYPE ${name} `);
      }
      expect(metrics).toContain(
        'scan_engine_circuit_state{engine="attachment",service="email-worker"} 0',
      );
    } finally {
      await moduleRef.close();
    }
    const jobs = moduleRef.get<AttachmentJobs | null>(ATTACHMENT_JOBS, { strict: false });
    expect(jobs?.watcher.running).toBe(false);
  });
});
