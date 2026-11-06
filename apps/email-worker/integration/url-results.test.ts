import { randomUUID } from 'node:crypto';
import {
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  uuidv7,
} from '@email-gateway/common';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { InspectionSweeper } from '../src/scanning/engines/url/inspection-sweeper';
import { createUrlJobs } from '../src/scanning/scanning.module';
import { eventually } from './support/broker';
import { silentLogger } from './support/fixtures';
import { ScanBroker, ScanFixtures, type ScanMessage } from './support/scan';
import { testLocks } from './support/attachments';
import {
  emlWithBodies,
  linksHtml,
  requireUrlTest,
  testCaFile,
  UrlFixtures,
  UrlPipeline,
} from './support/urls';

/**
 * The results consumer and the pending-inspection sweeper of U15 against the real writer and
 * Redis (and, for the consumer wiring, a throwaway vhost with topology v5).
 */

const fx = new ScanFixtures();
const ufx = new UrlFixtures(fx);
let ca: ReturnType<typeof testCaFile>;
let pipeline: UrlPipeline;

beforeAll(async () => {
  ca = testCaFile();
  await requireUrlTest();
  pipeline = UrlPipeline.start(fx, ca.path);
});

afterAll(async () => {
  await pipeline?.close();
  await ufx.cleanup();
  await fx.cleanup();
  ca?.cleanup();
});

/** A scanned message with one pending inspection (`url` must end suspicious or unknown). */
async function inspected(label: string, url: string) {
  const org = await fx.organization(label);
  const message = await ufx.message(org, emlWithBodies('', linksHtml(url)));
  expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
  const state = await ufx.state(message);
  expect(state.inspections).toHaveLength(1);
  return { org, message, inspection: state.inspections[0]! };
}

const base = (
  message: ScanMessage,
  inspection: { id: bigint; urlSeq: number; urlSha256: string },
) => ({
  inspectionId: inspection.id.toString(),
  messageId: message.messageId.toString(),
  receivedAt: message.receivedAt.toISOString(),
  urlSeq: inspection.urlSeq,
  urlSha256: inspection.urlSha256,
});

describe('results consumer (U15)', () => {
  it('applies a completed result once, writes the dynamic cache entry, ignores duplicates', async () => {
    const { org, message, inspection } = await inspected(
      'results-completed',
      'http://new-domain.test/results',
    );
    ufx.track('http://new-domain.test/results');
    const service = pipeline.results(fx);
    const event = ufx.completed(org, {
      ...base(message, inspection),
      finalUrlSha256: inspection.urlSha256,
      finalHost: 'new-domain.test',
    });
    expect(await service.handle(event)).toBe('handled');
    expect(await service.handle(event)).toBe('duplicate');
    const row = (await ufx.state(message)).inspections[0]!;
    expect(row).toMatchObject({
      status: 'completed',
      verdict: 'clean',
      finalHost: 'new-domain.test',
      workerVersion: 'url-browser-worker/it',
      errorCode: null,
    });
    expect(row.reasonCodes).toEqual(['clean.no_findings']);
    const cached = await pipeline.engine.cache!.getDynamic(inspection.urlSha256);
    expect(cached).toMatchObject({
      result: 'hit',
      value: { inspectionId: inspection.id.toString(), status: 'completed', verdict: 'clean' },
    });
    // Another event for the same inspection: no longer pending, a no-op.
    const later = ufx.completed(org, {
      ...base(message, inspection),
      status: 'failed',
      errorCode: 'job_timeout',
    });
    expect(await service.handle(later)).toBe('handled');
    expect((await ufx.state(message)).inspections[0]).toMatchObject({ status: 'completed' });
  });

  it('maps M5 (password form on a high-confidence lookalike) to malicious and U3 to unknown', async () => {
    const lookalike = await inspected('results-m5', 'http://examplebank-secure.test/login');
    const service = pipeline.results(fx);
    const signals = {
      passwordFields: 1,
      forms: 1,
      crossOriginFormAction: true,
      formActionHosts: ['collector-site.test'],
      downloadAttempted: false,
      blockedRequests: 0,
      requests: 3,
      bytes: 2048,
      titleBrandMatches: [],
      jsRedirect: false,
      dialogs: 0,
    };
    await service.handle(
      ufx.completed(lookalike.org, { ...base(lookalike.message, lookalike.inspection), signals }),
    );
    const row = (await ufx.state(lookalike.message)).inspections[0]!;
    expect(row).toMatchObject({ status: 'completed', verdict: 'malicious' });
    expect(row.reasonCodes as string[]).toEqual(
      expect.arrayContaining(['url.dynamic_phishing', 'url.dynamic_cross_origin_form']),
    );

    const failed = await inspected('results-failed', 'http://new-domain.test/failed');
    await service.handle(
      ufx.completed(failed.org, {
        ...base(failed.message, failed.inspection),
        status: 'failed',
        errorCode: 'navigation_timeout',
      }),
    );
    expect((await ufx.state(failed.message)).inspections[0]).toMatchObject({
      status: 'failed',
      verdict: 'unknown',
      reasonCodes: ['url.dynamic_failed'],
      errorCode: 'navigation_timeout',
    });
  });

  it('drops a forged result (unknown inspection id, another organization, another URL)', async () => {
    const { org, message, inspection } = await inspected(
      'results-forged',
      'http://new-domain.test/forged',
    );
    const other = await fx.organization('results-other');
    const service = pipeline.results(fx);
    for (const event of [
      ufx.completed(org, { ...base(message, inspection), inspectionId: '999999999999' }),
      ufx.completed(other, base(message, inspection)),
      ufx.completed(org, { ...base(message, inspection), urlSha256: 'f'.repeat(64) }),
      ufx.completed(org, { ...base(message, inspection), urlSeq: inspection.urlSeq + 1 }),
    ]) {
      expect(await service.handle(event)).toBe('handled');
    }
    expect((await ufx.state(message)).inspections[0]).toMatchObject({
      status: 'pending',
      verdict: null,
    });
    expect(await pipeline.text()).toMatch(
      /scan_url_dynamic_inspections_total\{[^}]*status="dropped"[^}]*\} [4-9]/,
    );
  });

  it('consumes scan.url.results through the broker (ledger consumer, topology v5)', async () => {
    const { org, message, inspection } = await inspected(
      'results-broker',
      'http://new-domain.test/broker',
    );
    const broker = await ScanBroker.start();
    const registry = pipeline.registry;
    const messaging = createMessagingMetrics(registry);
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
    const jobs = createUrlJobs({
      config: pipeline.config,
      prisma: fx.prisma,
      engine: pipeline.engine,
      locks: testLocks(),
      registry,
      connection,
      publisher,
      messaging,
      logger: silentLogger,
      consumer: fx.consumer(`url-results-broker-${randomUUID().slice(0, 4)}`),
    });
    jobs.consumer.start((event) => jobs.results.handle(event));
    connection.start();
    try {
      await connection.waitUntilConnected(15_000);
      const event = ufx.completed(org, base(message, inspection), uuidv7());
      await broker.publish([event as unknown as EventEnvelope<never>]);
      await eventually(
        async () => (await ufx.state(message)).inspections[0]!.status === 'completed',
        30_000,
        'the inspection result to be applied',
      );
      expect(await fx.ledgerRows(jobs.results.consumer, [event.eventId])).toBe(1);
    } finally {
      await jobs.consumer.stop();
      await publisher.close();
      await connection.close();
      await broker.close();
    }
  });
});

describe('pending-inspection sweeper (U15)', () => {
  it('expires pending rows older than the TTL and leaves fresh ones', async () => {
    const old = await inspected('sweep-old', 'http://new-domain.test/sweep-old');
    const fresh = await inspected('sweep-fresh', 'http://new-domain.test/sweep-fresh');
    await fx.prisma.urlDynamicInspection.updateMany({
      where: { id: old.inspection.id, receivedAt: old.inspection.receivedAt },
      data: { createdAt: new Date(Date.now() - 2 * 3_600_000) },
    });
    const locks = testLocks();
    const sweeper = new InspectionSweeper({
      prisma: fx.prisma,
      locks,
      metrics: pipeline.urlMetrics,
      logger: silentLogger,
      intervalMs: 60_000,
      pendingTtlSeconds: 3_600,
      txTimeoutMs: pipeline.config.SCAN_DB_TIMEOUT_MS,
      lockName: `it-url:inspections:${fx.suffix}`,
      organizationIds: [old.org, fresh.org],
    });
    try {
      expect(await sweeper.sweepOnce()).toEqual({ outcome: 'swept', expired: 1 });
      expect((await ufx.state(old.message)).inspections[0]).toMatchObject({ status: 'expired' });
      expect((await ufx.state(fresh.message)).inspections[0]).toMatchObject({ status: 'pending' });
      expect(await sweeper.sweepOnce()).toEqual({ outcome: 'swept', expired: 0 });
      // A late result for an expired inspection is a no-op.
      const service = pipeline.results(fx);
      await service.handle(ufx.completed(old.org, base(old.message, old.inspection)));
      expect((await ufx.state(old.message)).inspections[0]).toMatchObject({ status: 'expired' });
    } finally {
      await sweeper.stop();
      await locks.close();
    }
  });
});
