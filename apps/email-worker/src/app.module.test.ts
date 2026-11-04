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

const env = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://test:test@localhost:5672/email-gateway',
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

async function compile(overrides: Record<string, string> = {}) {
  const config = loadWorkerConfig({ ...env, ...overrides });
  const amqp = idleAmqp();
  const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
    .overrideProvider(PrismaService)
    .useValue(stub('mysql'))
    .overrideProvider(AmqpConnection)
    .useValue(amqp.connection)
    .overrideProvider(RedisService)
    .useValue(stub('redis', { client: {} }))
    .overrideProvider(S3Service)
    .useValue(stub('s3', { client: {}, mailBucket: 'test-mail' }))
    .compile();
  return { moduleRef, amqp };
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
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
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

  it('does not wire the stage when MIME_INGESTION_ENABLED is false', async () => {
    const { moduleRef, amqp } = await compile({ MIME_INGESTION_ENABLED: 'false' });
    await moduleRef.init();
    try {
      expect(() => moduleRef.get(MimeIngestionRuntime, { strict: false })).toThrow();
      const report = await moduleRef.get(HealthService).readiness();
      expect(report.checks.map((c) => c.name)).toEqual(['mysql', 'rabbitmq', 'redis', 's3']);
      expect(amqp.calls.setups).toBe(0);
    } finally {
      await moduleRef.close();
    }
  });
});
