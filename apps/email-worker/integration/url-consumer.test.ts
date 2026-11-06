import { randomUUID } from 'node:crypto';
import {
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  MetricsService,
  RedisService,
} from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createEngineConsumer } from '../src/scanning/engine-consumer';
import { urlRegistration } from '../src/scanning/engines/url/registration';
import { ScanMetrics } from '../src/scanning/scan-metrics';
import { createRoundService, createScanInfrastructure } from '../src/scanning/scanning.module';
import { eventually } from './support/broker';
import { requireEnv, silentLogger, workerConfig } from './support/fixtures';
import { ScanBroker, ScanFixtures } from './support/scan';
import {
  emlWithBodies,
  linksHtml,
  requireUrlTest,
  testCaFile,
  UrlFixtures,
  urlOnly,
} from './support/urls';

/**
 * The url engine as ScanningModule wires it (registration from ENGINE_REGISTRY, round service,
 * `scan.url` queue consumer of topology v5 with prefetch SCAN_URL_CONCURRENCY) on a throwaway
 * vhost: a `parsed.v1` published as the relay does is scanned once, also when it is published
 * three times (U16, §2.0 invariant 4).
 */

const fx = new ScanFixtures();
const ufx = new UrlFixtures(fx);
let ca: ReturnType<typeof testCaFile>;
let broker: ScanBroker;

beforeAll(async () => {
  ca = testCaFile();
  await requireUrlTest();
  broker = await ScanBroker.start();
});

afterAll(async () => {
  await broker?.close();
  await ufx.cleanup();
  await fx.cleanup();
  ca?.cleanup();
});

describe('scan.url consumer (U1, U2)', () => {
  it('scans a published parsed.v1 once, also when it is redelivered', async () => {
    const config = workerConfig(urlOnly(ca.path));
    const registry = new MetricsService({
      service: `email-worker-it-url-${randomUUID().slice(0, 6)}`,
    });
    const metrics = new ScanMetrics(registry);
    const messaging = createMessagingMetrics(registry);
    const redis = new RedisService({ url: requireEnv('REDIS_URL') });
    const consumerName = fx.consumer(`url-consumer-${randomUUID().slice(0, 4)}`);
    const infra = createScanInfrastructure({
      config,
      prisma: fx.prisma,
      s3: fx.s3,
      metrics,
      logger: silentLogger,
    });
    const { service } = createRoundService({
      config,
      registration: urlRegistration,
      ...infra,
      metrics,
      logger: silentLogger,
      consumer: consumerName,
      deps: { prisma: fx.prisma, s3: fx.s3, redis, registry },
    });
    const connection = new AmqpConnection({
      urls: [broker.vhost.adminUrl],
      connectionName: 'email-worker-scanner',
      logger: silentLogger,
      metrics: messaging,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    const publisher = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      metrics: messaging,
      appId: 'email-worker',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    const consumer = createEngineConsumer({
      config,
      registration: urlRegistration,
      connection,
      publisher,
      logger: silentLogger,
      metrics: messaging,
      consumer: consumerName,
    });
    consumer.start((event) => service.handle(event));
    connection.start();
    try {
      await connection.waitUntilConnected(15_000);
      await eventually(
        async () =>
          /amqp_consumer_active\{[^}]*queue="scan.url"[^}]*\} 1/.test(await registry.metrics()),
        15_000,
        'the scan.url consumer to subscribe',
      );
      const org = await fx.organization('consumer');
      const message = await ufx.message(
        org,
        emlWithBodies(
          'http://clean-site.test/landing',
          linksHtml('http://clean-site.test/landing'),
        ),
      );
      const event = fx.parsed(message);
      await broker.publish([event, event, event]);
      await eventually(
        async () => (await fx.ledgerRows(consumerName, [event.eventId])) === 1,
        60_000,
        'the parsed event to be handled',
      );
      await eventually(
        async () => (await ufx.state(message)).scans[0]?.status === 'completed',
        30_000,
        'the round to complete',
      );
      const state = await ufx.state(message);
      expect(state.finals).toHaveLength(1);
      expect(state.finals[0]).toMatchObject({ outcome: 'clean', engine: 'url' });
      expect(state.results).toHaveLength(1);
      expect(state.rewrites).toHaveLength(1);
      expect(state.scans[0]).toMatchObject({ status: 'completed', scanVerdict: 'clean' });
      // Concurrent redeliveries may each run the engine (counted); only one final is written.
      expect(await registry.metrics()).toMatch(
        /scan_url_urls_total\{[^}]*verdict="clean"[^}]*\} [1-3]\n/,
      );
    } finally {
      await consumer.stop();
      await publisher.close();
      await connection.close();
      await redis.onModuleDestroy();
    }
  });
});
