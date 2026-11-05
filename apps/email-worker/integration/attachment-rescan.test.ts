import * as corpus from '@email-gateway/attachment-corpus';
import { MetricsService } from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  messageRescanRequestedV1,
} from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AttachmentMetrics } from '../src/scanning/engines/attachment/attachment-metrics';
import {
  RescanJobRunner,
  SYSTEM_REQUESTED_BY,
} from '../src/scanning/engines/attachment/rescan-runner';
import {
  type ComponentVersion,
  SignatureWatcher,
} from '../src/scanning/engines/attachment/signature-watcher';
import type { ScanTriggerPayload } from '../src/scanning/round-service';
import {
  AttachmentFixtures,
  type AttachmentMessage,
  AttachmentPipeline,
  testLocks,
} from './support/attachments';
import { silentLogger } from './support/fixtures';
import { ScanFixtures } from './support/scan';

/**
 * Signature updates and rescan jobs (step 4.2 A13) on the real writer: an admin job (as the api
 * writes it) and a detector job (a component version change recorded by the SignatureWatcher
 * through a version-source override) are executed by the RescanJobRunner: candidates selected
 * on the writer (window, states, organization, attachments, latest round not malicious), E19
 * `scanner`/`signature_rescan` per candidate with the `rescan_requested.v1` outbox row, batch
 * limits, counts, cursor, cancellation; the requested rescans then complete new rounds through
 * the attachment engine. Jobs are scoped to the run's organization (the shared writer holds
 * other messages in the same window).
 */
let fx: ScanFixtures;
let att: AttachmentFixtures;
let pipeline: AttachmentPipeline;
let org: bigint;
let locks: ReturnType<typeof testLocks>;
const registry = new MetricsService({ service: 'email-worker-it-rescan' });
const metrics = AttachmentMetrics.for(registry);

beforeAll(async () => {
  fx = new ScanFixtures();
  att = new AttachmentFixtures(fx);
  org = await fx.organization('att-rescan');
  pipeline = await AttachmentPipeline.start(fx);
  locks = testLocks();
});

afterAll(async () => {
  await pipeline?.stop();
  await locks?.close();
  await att?.cleanup();
  await fx?.cleanup();
});

async function scanned(
  specs: Parameters<AttachmentFixtures['message']>[1],
  receivedAt?: Date,
): Promise<AttachmentMessage> {
  const message = await att.message(org, specs, {}, receivedAt);
  await pipeline.handle(fx.parsed(message));
  return message;
}

function runner(jobIds: bigint[], batchSize: number) {
  return new RescanJobRunner({
    prisma: fx.prisma,
    locks,
    metrics,
    logger: silentLogger,
    intervalMs: 100,
    batchSize,
    txTimeoutMs: 15_000,
    lockName: `it-rescan:${fx.suffix}`,
    jobIds,
  });
}

async function adminJob(windowStart: Date, windowEnd: Date, maxMessages = 100) {
  const job = await fx.prisma.attachmentRescanJob.create({
    data: {
      trigger: 'admin',
      status: 'pending',
      organizationId: org,
      windowStart,
      windowEnd,
      states: ['scanned', 'scan_failed'],
      maxMessages,
      reason: 'it admin rescan',
    },
  });
  att.jobIds.add(job.id);
  return job;
}

async function rescanEvents(
  message: AttachmentMessage,
): Promise<Array<EventEnvelope<ScanTriggerPayload>>> {
  const rows = await fx.prisma.messageOutbox.findMany({
    where: {
      organizationId: org,
      aggregateId: message.messageId.toString(),
      eventType: EventTypes.MessageRescanRequested,
    },
    orderBy: { id: 'asc' },
  });
  return rows.map((row) => ({
    eventId: row.eventId,
    eventType: EventTypes.MessageRescanRequested,
    occurredAt: row.createdAt.toISOString(),
    correlationId: row.correlationId,
    organizationId: row.organizationId.toString(),
    payload: messageRescanRequestedV1.parse(row.payload),
  }));
}

describe('rescan jobs (A13)', () => {
  it('an admin job rescans eligible messages in batches and the rescans complete new rounds', async () => {
    const windowStart = new Date(Date.now() - 60_000);
    const old = await scanned(
      [{ bytes: corpus.pdfLike(4096, 801), filename: 'old.pdf' }],
      new Date(Date.now() - 2 * 3_600_000),
    );
    const clean1 = await scanned([{ bytes: corpus.pdfLike(4096, 802), filename: 'a.pdf' }]);
    const clean2 = await scanned([{ bytes: corpus.pdfLike(4096, 803), filename: 'b.pdf' }]);
    const failed = await scanned([
      { bytes: corpus.pdfLike(4096, 804), filename: 'c.pdf', upload: false },
    ]);
    const malicious = await scanned([{ bytes: corpus.eicar(), filename: 'e.txt' }]);
    const empty = await scanned([]);
    expect((await fx.state(failed)).message.status).toBe('scan_failed');
    expect((await fx.state(malicious)).message.status).toBe('scanned');

    const job = await adminJob(windowStart, new Date(Date.now() + 60_000));
    const run = runner([job.id], 2);
    const first = await run.runBatch();
    expect(first).toMatchObject({
      outcome: 'batch',
      jobId: job.id,
      selected: 2,
      requested: 2,
      skipped: 0,
    });
    const second = await run.runBatch();
    expect(second).toMatchObject({ outcome: 'batch', selected: 1, requested: 1 });
    expect((await run.runBatch()).outcome).toBe('completed');
    const row = await fx.prisma.attachmentRescanJob.findUniqueOrThrow({ where: { id: job.id } });
    expect(row).toMatchObject({
      status: 'completed',
      selectedCount: 3,
      requestedCount: 3,
      skippedCount: 0,
    });
    expect(row.startedAt).not.toBeNull();
    expect(row.cursorMessageId).not.toBeNull();

    for (const message of [clean1, clean2, failed]) {
      const state = await fx.state(message);
      expect(state.message).toMatchObject({ status: 'scanning', lifecycleRound: 1 });
      const history = state.history.at(-1)!;
      expect(history).toMatchObject({
        toStatus: 'scanning',
        reasonCode: 'signature_rescan',
        actorRole: 'scanner',
      });
      const events = await rescanEvents(message);
      expect(events).toHaveLength(1);
      expect(events[0]!.payload).toMatchObject({
        lifecycleRound: 1,
        scanKind: 'rescan',
        requestedBy: 'user',
      });
    }
    // Not selected: out of window, malicious latest round, no attachments.
    for (const message of [old, malicious, empty]) {
      expect((await fx.state(message)).message).toMatchObject({
        status: 'scanned',
        lifecycleRound: 0,
      });
    }

    // The requested rescan goes through the existing path: a new round of the engine.
    const [event] = await rescanEvents(clean1);
    expect((await pipeline.handle(event!)).outcome).toBe('handled');
    const round1 = await att.finalOf(clean1, 1);
    expect(round1.scan).toMatchObject({ scanKind: 'rescan', status: 'completed' });
    expect(round1.final!.outcome).toBe('clean');
    expect((await att.results(clean1)).map((r) => r.scanId)).toEqual([
      expect.any(BigInt),
      round1.scan.id,
    ]);
    expect((await fx.state(clean1)).message).toMatchObject({
      status: 'scanned',
      lifecycleRound: 1,
    });
  });

  it('respects max_messages and cancellation between batches', async () => {
    const windowStart = new Date(Date.now() - 1_000);
    for (let i = 0; i < 3; i += 1)
      await scanned([{ bytes: corpus.pdfLike(2048, 900 + i), filename: `${String(i)}.pdf` }]);
    const capped = await adminJob(windowStart, new Date(Date.now() + 60_000), 1);
    const capRun = runner([capped.id], 5);
    expect(await capRun.runBatch()).toMatchObject({
      outcome: 'completed',
      selected: 1,
      requested: 1,
    });

    const cancelled = await adminJob(windowStart, new Date(Date.now() + 60_000));
    const cancelRun = runner([cancelled.id], 1);
    expect((await cancelRun.runBatch()).outcome).toBe('batch');
    await fx.prisma.attachmentRescanJob.update({
      where: { id: cancelled.id },
      data: { status: 'cancelled', completedAt: new Date() },
    });
    expect(await cancelRun.runBatch()).toMatchObject({ outcome: 'idle', selected: 0 });
    const row = await fx.prisma.attachmentRescanJob.findUniqueOrThrow({
      where: { id: cancelled.id },
    });
    expect(row).toMatchObject({ status: 'cancelled', selectedCount: 1 });
  });

  it('a signature change recorded by the watcher creates a pending job that rescans as scanner', async () => {
    let versions: ComponentVersion[] = [{ component: 'clamav_db', version: `it-${fx.suffix}-1` }];
    const watcher = new SignatureWatcher({
      prisma: fx.prisma,
      locks,
      source: { current: () => Promise.resolve({ versions, clamavDbTime: new Date() }) },
      metrics,
      logger: silentLogger,
      intervalMs: 1000,
      mode: 'rescan',
      windowHours: 1,
      maxMessages: 50,
      txTimeoutMs: 120_000,
      lockName: `it-sig:${fx.suffix}`,
      engine: att.signatureEngine,
    });
    expect((await watcher.poll()).changes).toEqual([]);
    // Received before the change: inside the detector job's window [change - 1 h, change].
    const message = await scanned([{ bytes: corpus.pdfLike(2048, 950), filename: 'sig.pdf' }]);
    versions = [{ component: 'clamav_db', version: `it-${fx.suffix}-2` }];
    const report = await watcher.poll();
    expect(report.changes).toEqual([
      {
        component: 'clamav_db',
        from: `it-${fx.suffix}-1`,
        to: `it-${fx.suffix}-2`,
        jobCreated: true,
      },
    ]);
    // The same change seen again (another replica): no second job.
    versions = [{ component: 'clamav_db', version: `it-${fx.suffix}-2` }];
    expect((await watcher.poll()).changes).toEqual([]);
    const jobs = await fx.prisma.attachmentRescanJob.findMany({
      where: { dedupeKey: `sig:clamav_db:it-${fx.suffix}-2` },
    });
    expect(jobs).toHaveLength(1);
    const job = jobs[0]!;
    att.jobIds.add(job.id);
    expect(job).toMatchObject({
      trigger: 'signature_update',
      status: 'pending',
      component: 'clamav_db',
      organizationId: null,
    });
    // Test scoping: the shared writer holds other tenants' messages in the same window.
    await fx.prisma.attachmentRescanJob.update({
      where: { id: job.id },
      data: { organizationId: org },
    });
    const run = runner([job.id], 50);
    expect((await run.runBatch()).requested).toBeGreaterThanOrEqual(1);
    const events = await rescanEvents(message);
    expect(events).toHaveLength(1);
    expect(events[0]!.payload).toMatchObject({
      requestedBy: SYSTEM_REQUESTED_BY,
      lifecycleRound: 1,
    });
    await watcher.stop();
    expect(await registry.metrics()).toMatch(
      /scan_attachment_rescan_messages_total\{[^}]*result="requested"[^}]*trigger="signature_update"[^}]*\} [1-9]/,
    );
  });
});
