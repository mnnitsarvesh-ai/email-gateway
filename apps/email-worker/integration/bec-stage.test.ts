import {
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  type QueueConsumer,
} from '@email-gateway/common';
import { MetricsService, uuidv7 } from '@email-gateway/common';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createEngineConsumer } from '../src/scanning/engine-consumer';
import { becRegistration } from '../src/scanning/engines/bec/registration';
import { rspamdRegistration } from '../src/scanning/engines/rspamd/registration';
import { urlRegistration } from '../src/scanning/engines/url/registration';
import type { ScanTriggerPayload } from '../src/scanning/round-service';
import { ScanMetrics } from '../src/scanning/scan-metrics';
import type { FinalRowInput } from '../src/scanning/scan-store';
import { BecFixtures, BecPipeline } from './support/bec';
import { eventually } from './support/broker';
import { silentLogger, workerConfig } from './support/fixtures';
import { corpusEml, loadCorpus, ScanBroker, ScanFixtures, sweeper } from './support/scan';
import { requireUrlTest, testCaFile, UrlFixtures } from './support/urls';

/**
 * The stage trigger end to end on the broker (step 4.4 B2, B3, §9): the three engine consumers
 * of topology v6 on a throwaway vhost (`scan.spam`, `scan.url` bind parsed/rescan; `scan.bec`
 * binds only `scan_stage_ready.v1`), a `parsed.v1` published as the event-relay does, the last
 * dependency final writing exactly one `scan_stage_ready.v1` outbox row, the row relayed to the
 * vhost (as the event-relay would: same event id, `org.<id>.<type>` on `email.security`), the
 * bec final and the round `scanned`. Re-publishing the stage event (the outbox reconciler's
 * re-drive) adds nothing.
 */

const fx = new ScanFixtures();
const ufx = new UrlFixtures(fx);
const bfx = new BecFixtures(fx);
let ca: ReturnType<typeof testCaFile>;
let broker: ScanBroker;
let pipeline: BecPipeline;
const consumers: QueueConsumer<ScanTriggerPayload>[] = [];
let connection: AmqpConnection;
let publisher: ConfirmPublisher;

beforeAll(async () => {
  ca = testCaFile();
  await requireUrlTest();
  broker = await ScanBroker.start();
  pipeline = BecPipeline.start(fx, ca.path);
  const messaging = createMessagingMetrics(pipeline.registry);
  connection = new AmqpConnection({
    urls: [broker.vhost.adminUrl],
    connectionName: 'email-worker-scanner',
    logger: silentLogger,
    metrics: messaging,
    reconnect: { baseMs: 50, maxMs: 500 },
  });
  publisher = new ConfirmPublisher({
    connection,
    logger: silentLogger,
    metrics: messaging,
    appId: 'email-worker',
    confirmTimeoutMs: 15_000,
    maxMessageBytes: 131_072,
  });
  for (const registration of [rspamdRegistration, urlRegistration, becRegistration]) {
    const name = registration.catalog.name as 'rspamd' | 'url' | 'bec';
    const consumer = createEngineConsumer({
      config: pipeline.config,
      registration,
      connection,
      publisher,
      logger: silentLogger,
      metrics: messaging,
      consumer: pipeline.consumers.get(name)!,
    });
    const service = pipeline.service(name);
    consumer.start((event) => service.handle(event));
    consumers.push(consumer);
  }
  connection.start();
  await connection.waitUntilConnected(15_000);
  await eventually(
    async () => {
      const text = await pipeline.text();
      return ['scan.spam', 'scan.url', 'scan.bec'].every((q) =>
        new RegExp(`amqp_consumer_active\\{[^}]*queue="${q}"[^}]*\\} 1`).test(text),
      );
    },
    15_000,
    'the scan.spam, scan.url and scan.bec consumers to subscribe',
  );
});

afterAll(async () => {
  for (const consumer of consumers) await consumer.stop().catch(() => undefined);
  await publisher?.close().catch(() => undefined);
  await connection?.close().catch(() => undefined);
  await broker?.close();
  await pipeline?.close();
  await bfx.cleanup();
  await ufx.cleanup();
  await fx.cleanup();
  ca?.cleanup();
});

describe('stage trigger on the broker (B2)', () => {
  it('rspamd + url finals → one stage outbox row → relay → scan.bec → bec final → round scanned', async () => {
    const org = await fx.organization('stage');
    const domain = `it-bec-${fx.suffix}-stage.test`;
    await bfx.domain(org, domain);
    const fixture = loadCorpus().find((f) => f.file === 'clean/clean-dkim-aligned.eml')!;
    const message = await bfx.message(org, corpusEml(fixture), {
      ...fixture.envelope,
      rcpt: [`bob@${domain}`],
    });
    const parsed = fx.parsed(message);
    await broker.publish([parsed]);

    // The last dependency final writes exactly one trigger (the bec queue gets nothing else).
    await eventually(
      async () => (await bfx.stageEvents(message)).length === 1,
      60_000,
      'the stage trigger outbox row',
    );
    const [stage] = await bfx.stageEvents(message);
    expect(stage!.payload).toMatchObject({
      engine: 'bec',
      lifecycleRound: 0,
      scanKind: 'initial',
      emlS3Key: message.emlObjectKey,
    });
    let state = await bfx.state(message);
    expect(state.finals.map((f) => f.engine).sort()).toEqual(['rspamd', 'url']);
    expect(state.message.status).toBe('scanning');

    // Relay it as the event-relay does (outbox event id, org routing key).
    await broker.publish([stage as EventEnvelope<ScanTriggerPayload>]);
    await eventually(
      async () => (await bfx.state(message)).message.status === 'scanned',
      60_000,
      'the round to complete with the bec final',
    );
    state = await bfx.state(message);
    expect(state.finals.map((f) => f.engine).sort()).toEqual(['bec', 'rspamd', 'url']);
    expect(state.bec).toHaveLength(1);
    expect(state.bec[0]).toMatchObject({ verdict: 'clean', lifecycleRound: 0 });
    expect(state.scans[0]).toMatchObject({ status: 'completed', scanVerdict: 'clean' });
    expect(await fx.ledgerRows(pipeline.consumers.get('bec')!, [stage!.eventId])).toBe(1);

    // The reconciler's re-drive (same event id, twice): nothing new.
    await broker.publish([
      stage as EventEnvelope<ScanTriggerPayload>,
      stage as EventEnvelope<ScanTriggerPayload>,
    ]);
    await eventually(
      async () =>
        (await pipeline.text())
          .split('\n')
          .some(
            (line) =>
              line.startsWith('amqp_consumer_messages_total{') &&
              line.includes('queue="scan.bec"') &&
              line.includes('outcome="duplicate"') &&
              line.endsWith(' 2'),
          ),
      30_000,
      'the re-driven stage events to be acknowledged as duplicates',
    );
    state = await bfx.state(message);
    expect(state.finals.filter((f) => f.engine === 'bec')).toHaveLength(1);
    expect(state.bec).toHaveLength(1);
    expect(state.stageEvents).toHaveLength(1);
    expect(await pipeline.text()).toMatch(/scan_stage_triggers_total\{engine="bec"[^}]*\} 1/);
  });

  it('a message deleted while its round is open: the last dependency final writes no trigger and is handled', async () => {
    // Step 4.4 §12 WP5: the whole-chain runs dead-lettered `scan.url` deliveries with
    // `stage_ready_payload_invalid` when a fixture cleanup deleted the message between the url
    // engine's round open and its final (null lifecycle snapshot → payload without direction or
    // EML key). The real repository on the writer: no trigger, no throw, the final is kept.
    const config = workerConfig({ SCAN_ENGINES: 'rspamd,url,bec' });
    const { store } = sweeper(
      fx,
      new ScanMetrics(new MetricsService({ service: 'it-bec-gone' })),
      config,
    );
    const org = await fx.organization('gone');
    const domain = `it-bec-${fx.suffix}-gone.test`;
    await bfx.domain(org, domain);
    const fixture = loadCorpus().find((f) => f.file === 'clean/clean-dkim-aligned.eml')!;
    const message = await bfx.message(org, corpusEml(fixture), {
      ...fixture.envelope,
      rcpt: [`bob@${domain}`],
    });
    const row = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: message.messageId, receivedAt: message.receivedAt },
    });
    const opened = await store.openRound({
      message: {
        id: row.id,
        receivedAt: row.receivedAt,
        organizationId: row.organizationId,
        direction: row.direction,
        emlObjectKey: row.emlObjectKey,
        sizeBytes: row.sizeBytes,
        clientIp: row.clientIp,
        clientHelo: row.clientHelo,
        clientName: row.clientName,
        envelopeFrom: row.envelopeFrom,
        mtaQueueId: row.mtaQueueId,
        recipients: [],
      },
      round: 0,
      scanKind: 'initial',
      trigger: 'parsed',
      engine: 'rspamd',
      eventId: uuidv7(),
      correlationId: 'it-bec-gone',
      requiredEngines: ['rspamd', 'url', 'bec'],
      deadlineSeconds: 600,
      now: new Date(),
    });
    if (opened.kind !== 'open') throw new Error(`round not opened: ${opened.reason}`);
    const final = (engine: string): FinalRowInput => ({
      engine,
      attempt: 1,
      outcome: 'clean',
      errorCode: null,
      engineVersion: `${engine}/it`,
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: ['clean.below_threshold'],
      evidence: null,
      durationMs: 1,
      settingsVersion: null,
      auth: null,
    });
    const finalize = (engine: string) =>
      store.finalize({
        consumer: `it-bec-gone.${engine}`,
        eventId: uuidv7(),
        round: opened.round,
        final: final(engine),
        completion: { causationEventId: null, correlationId: 'it-bec-gone', now: new Date() },
      });
    expect(await finalize('rspamd')).toMatchObject({ kind: 'handled', stageTriggers: [] });
    // The message row disappears (organization purge / cleanup) while url is scanning.
    await fx.prisma.emailMessage.deleteMany({
      where: { id: message.messageId, receivedAt: message.receivedAt },
    });
    expect(await finalize('url')).toMatchObject({
      kind: 'handled',
      inserted: true,
      stageTriggers: [],
      completion: { kind: 'not_complete' },
    });
    expect(
      await fx.prisma.messageOutbox.count({
        where: {
          organizationId: org,
          aggregateId: message.messageId.toString(),
          eventType: EventTypes.MessageScanStageReady,
        },
      }),
    ).toBe(0);
    expect(
      await fx.prisma.scanEngineResult.count({
        where: { scanId: opened.round.scanId, receivedAt: opened.round.receivedAt, isFinal: true },
      }),
    ).toBe(2);
  });
});
