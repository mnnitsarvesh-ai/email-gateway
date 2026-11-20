import { MetricsService, uuidv7 } from '@email-gateway/common';
import { EventTypes } from '@email-gateway/event-contracts';
import type { AuthResults } from '@email-gateway/security-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DeadlineSweeper } from '../src/scanning/deadline-sweeper';
import { createRiskScorer } from '../src/scanning/risk/risk-scorer';
import { ScanMetrics } from '../src/scanning/scan-metrics';
import { ScanRepository } from '../src/scanning/scan-repository';
import type { FinalRowInput } from '../src/scanning/scan-store';
import { testLocks } from './support/attachments';
import { Fixtures, type MessageFixture, silentLogger, workerConfig } from './support/fixtures';
import { multipartMessage } from './support/messages';
import { ScanFixtures, type ScanMessage } from './support/scan';

/**
 * Journal intake gates of the email-worker (step 8.6 D4, ADR-0087,
 * docs/plan/steps/27-journal-intake-and-archive-split.md §9.3) on the real MySQL writer and MinIO:
 * the MIME commit of an intake message without a requested scan ends it in `journaled` (E30) with
 * no `parsed.v1` / `parse_failed.v1`; with a requested scan it writes `parsed.v1`, and a parse
 * failure is E30 `intake_parse_failed` (never `parse_failed.v1`); the scan completion of an intake
 * round (engine finals and the deadline sweeper) applies E31 / E32 in place of `scanned.v1`, with
 * the round's risk score recorded. Intake messages are inserted as the smtp-adapter's
 * `JournalIntakeRepository` commits them (`persisted`, `ingest_source = journal_intake`, a
 * `journal_intake_messages` row with `scan_requested`).
 */
const fx = new Fixtures();
const sfx = new ScanFixtures();
const config = workerConfig({ SCAN_ENGINES: 'rspamd' });
const registry = new MetricsService({ service: `it-intake-${fx.suffix}` });
const metrics = new ScanMetrics(registry);
let repo: ScanRepository;
let org: bigint;
let scanOrg: bigint;

beforeAll(async () => {
  org = await fx.organization('intake');
  scanOrg = await sfx.organization('intake-scan');
  const risk = createRiskScorer({ config, metrics: metrics.risk, logger: silentLogger });
  repo = new ScanRepository(sfx.prisma, config.SCAN_DB_TIMEOUT_MS, risk, metrics.lifecycle);
});

afterAll(async () => {
  const ids = [...fx.organizationIds, ...sfx.organizationIds];
  await fx.prisma.journalIntakeMessage.deleteMany({ where: { organizationId: { in: ids } } });
  await sfx.prisma.messageOutbox.deleteMany({
    where: { organizationId: { in: sfx.organizationIds } },
  });
  await fx.prisma.messageOutbox.deleteMany({
    where: { organizationId: { in: fx.organizationIds } },
  });
  await fx.cleanup();
  await sfx.cleanup();
});

/** Turns a fixture message into a journal intake message (as the intake LMTP commits it). */
async function asIntake(
  prisma: Fixtures['prisma'],
  message: { messageId: bigint; receivedAt: Date; organizationId: bigint },
  scanRequested: boolean,
): Promise<void> {
  await prisma.emailMessage.update({
    where: { id_receivedAt: { id: message.messageId, receivedAt: message.receivedAt } },
    data: { ingestSource: 'journal_intake', status: 'persisted', version: 1 },
  });
  await prisma.journalIntakeMessage.create({
    data: {
      messageId: message.messageId,
      receivedAt: message.receivedAt,
      organizationId: message.organizationId,
      sourceId: 1n,
      kind: 'smtp_bcc',
      format: 'copy',
      envelope: {
        v: 1,
        sender: 'sender@example.org',
        onBehalfOf: null,
        messageId: null,
        recipients: [{ address: 'rcpt@example.net', field: 'header' }],
        truncated: false,
        envelopeMismatch: false,
      },
      proof: { v: 1, result: 'pass' },
      reportSha256: 'a'.repeat(64),
      reportSizeBytes: 1,
      scanRequested,
    },
  });
}

async function outboxTypes(organizationId: bigint, messageId: bigint): Promise<string[]> {
  const rows = await fx.prisma.messageOutbox.findMany({
    where: { organizationId, aggregateId: messageId.toString() },
    orderBy: { id: 'asc' },
    select: { eventType: true },
  });
  return rows.map((r) => r.eventType);
}

async function lifecycle(message: { messageId: bigint; receivedAt: Date }) {
  const row = await fx.prisma.emailMessage.findFirstOrThrow({
    where: { id: message.messageId, receivedAt: message.receivedAt },
    select: { status: true, statusReason: true },
  });
  const history = await fx.prisma.emailMessageStatusHistory.findMany({
    where: { messageId: message.messageId, receivedAt: message.receivedAt },
    orderBy: { version: 'asc' },
    select: { fromStatus: true, toStatus: true, reasonCode: true, actorRole: true },
  });
  return { ...row, history };
}

async function parse(message: MessageFixture, overrides: Record<string, string> = {}) {
  const ingestion = fx.ingestion({ overrides });
  const outcome = await ingestion.service.handle(fx.received(message));
  return { outcome, metrics: await ingestion.registry.metrics() };
}

describe('MIME commit of journal intake messages (D4)', () => {
  it('scan not requested: parsed, E30 intake_unscanned, no parsed.v1 / parse_failed.v1', async () => {
    const message = await fx.message(org, { eml: multipartMessage() });
    await asIntake(fx.prisma, message, false);
    const { outcome, metrics: text } = await parse(message);
    expect(outcome).toBe('handled');
    const state = await fx.state(message);
    expect(state.parses[0]?.status).toBe('parsed');
    expect(state.outbox).toEqual([]);
    expect(state.events.map((e) => e.eventType)).toEqual(['parsed']);
    const life = await lifecycle(message);
    expect(life).toMatchObject({ status: 'journaled', statusReason: 'intake_unscanned' });
    expect(life.history).toEqual([
      {
        fromStatus: 'persisted',
        toStatus: 'journaled',
        reasonCode: 'intake_unscanned',
        actorRole: 'scanner',
      },
    ]);
    // state_changed.v1 is written as for any transition; nothing toward the policy engine.
    expect(await outboxTypes(org, message.messageId)).toEqual([EventTypes.MessageStateChanged]);
    expect(text).toMatch(/mime_intake_messages_total\{[^}]*result="journaled"[^}]*\} 1/);
  });

  it('scan not requested and the parse fails: E30 intake_parse_failed, no parse_failed.v1', async () => {
    const message = await fx.message(org, { eml: 'x', upload: false });
    await asIntake(fx.prisma, message, false);
    expect((await parse(message)).outcome).toBe('handled');
    const state = await fx.state(message);
    expect(state.parses[0]).toMatchObject({ status: 'parse_failed', failureReason: 'eml_missing' });
    expect(state.outbox).toEqual([]);
    expect(await lifecycle(message)).toMatchObject({
      status: 'journaled',
      statusReason: 'intake_parse_failed',
    });
    expect(await outboxTypes(org, message.messageId)).not.toContain(EventTypes.MessageParseFailed);
  });

  it('scan requested: parsed.v1 for the scan stage, the message stays persisted', async () => {
    const message = await fx.message(org, { eml: multipartMessage() });
    await asIntake(fx.prisma, message, true);
    const { metrics: text } = await parse(message);
    const state = await fx.state(message);
    expect(state.outbox.map((o) => o.eventType)).toEqual([EventTypes.MessageParsed]);
    expect(await lifecycle(message)).toMatchObject({ status: 'persisted', history: [] });
    expect(text).toMatch(/mime_intake_messages_total\{[^}]*result="scan_requested"[^}]*\} 1/);
  });

  it('scan requested and the parse fails: E30 intake_parse_failed, never parse_failed.v1', async () => {
    const message = await fx.message(org, { eml: 'x', upload: false });
    await asIntake(fx.prisma, message, true);
    await parse(message);
    expect((await fx.state(message)).outbox).toEqual([]);
    expect(await lifecycle(message)).toMatchObject({
      status: 'journaled',
      statusReason: 'intake_parse_failed',
    });
  });

  it('a missing journal_intake_messages row counts as not requested (fail safe)', async () => {
    const message = await fx.message(org, { eml: multipartMessage() });
    await fx.prisma.emailMessage.update({
      where: { id_receivedAt: { id: message.messageId, receivedAt: message.receivedAt } },
      data: { ingestSource: 'journal_intake', status: 'persisted' },
    });
    await parse(message);
    expect((await fx.state(message)).outbox).toEqual([]);
    expect(await lifecycle(message)).toMatchObject({ status: 'journaled' });
  });

  it('a redelivery of the received event changes nothing (idempotent)', async () => {
    const message = await fx.message(org, { eml: multipartMessage() });
    await asIntake(fx.prisma, message, false);
    const ingestion = fx.ingestion();
    const event = fx.received(message);
    expect(await ingestion.service.handle(event)).toBe('handled');
    expect(await ingestion.service.handle(event)).toBe('duplicate');
    expect((await lifecycle(message)).history).toHaveLength(1);
  });

  it('a gateway message keeps the 3.1 behaviour (parsed.v1, status untouched)', async () => {
    const message = await fx.message(org, { eml: multipartMessage() });
    await parse(message);
    const state = await fx.state(message);
    expect(state.outbox.map((o) => o.eventType)).toEqual([EventTypes.MessageParsed]);
    expect(state.message.status).toBe('received');
  });
});

const passAuth = (): AuthResults => ({
  spf: { result: 'pass', domain: null },
  dkim: { result: 'pass', signatures: [] },
  dmarc: { result: 'pass', policy: 'reject', domain: null },
  arc: { result: 'none' },
});

const rspamdFinal = (outcome: 'clean' | 'spam'): FinalRowInput => ({
  engine: 'rspamd',
  attempt: 1,
  outcome,
  errorCode: null,
  engineVersion: 'rspamd/3.12.1',
  score: outcome === 'spam' ? 11.25 : 0.4,
  requiredScore: 15,
  action: 'no action',
  reasonCodes: [outcome === 'spam' ? 'spam.score_high' : 'clean.below_threshold'],
  evidence: null,
  durationMs: 5,
  settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
  auth: passAuth(),
});

async function openRound(message: ScanMessage, deadlineSeconds = 1_800) {
  const record = await repo.loadMessage(
    message.messageId,
    message.receivedAt,
    message.organizationId,
  );
  if (!record) throw new Error('fixture message not found');
  const opened = await repo.openRound({
    message: record,
    round: 0,
    scanKind: 'initial',
    trigger: 'parsed',
    engine: 'rspamd',
    eventId: uuidv7(),
    correlationId: `it-intake-${sfx.suffix}`,
    requiredEngines: ['rspamd'],
    deadlineSeconds,
    now: new Date(),
  });
  if (opened.kind !== 'open') throw new Error(`round not opened: ${opened.reason}`);
  return opened.round;
}

describe('scan finalization of journal intake messages (D4)', () => {
  it('a completed round applies E31 in its transaction; no scanned.v1; risk score recorded', async () => {
    const message = await sfx.message(scanOrg, { eml: Buffer.from('x'), upload: false });
    await asIntake(sfx.prisma, message, true);
    const scan = await openRound(message);
    const eventId = uuidv7();
    const result = await repo.finalize({
      consumer: sfx.consumer('rspamd'),
      eventId,
      round: scan,
      final: rspamdFinal('spam'),
      completion: { causationEventId: eventId, correlationId: 'it-intake', now: new Date() },
    });
    expect(result).toMatchObject({
      kind: 'handled',
      completion: {
        kind: 'completed',
        transition: 'applied',
        scannedEventId: null,
        intake: 'journaled',
      },
    });
    const state = await sfx.state(message);
    expect(state.message.status).toBe('journaled');
    expect(state.history.map((h) => [h.fromStatus, h.toStatus, h.reasonCode])).toEqual([
      ['persisted', 'scanning', 'scan_started'],
      ['scanning', 'scanned', 'scan_complete'],
      ['scanned', 'journaled', 'intake_scan_complete'],
    ]);
    expect(state.scanned).toEqual([]);
    expect(state.scans[0]).toMatchObject({ status: 'completed' });
    const risk = await sfx.prisma.messageRiskScore.findMany({
      where: { scanId: scan.scanId, receivedAt: scan.receivedAt },
    });
    expect(risk.map((r) => r.revision)).toEqual([0]);
    const types = await outboxTypes(scanOrg, message.messageId);
    expect(types).not.toContain(EventTypes.MessageScanned);
  });

  it('a timed-out round swept by the deadline sweeper applies E32 (scan_failed → journaled)', async () => {
    const message = await sfx.message(scanOrg, { eml: Buffer.from('x'), upload: false });
    await asIntake(sfx.prisma, message, true);
    await openRound(message, 1);
    await new Promise((r) => setTimeout(r, 1_100));
    const locks = testLocks();
    try {
      const sweeper = new DeadlineSweeper({
        store: repo,
        locks,
        metrics,
        logger: silentLogger,
        intervalMs: 60_000,
        lookbackHours: 48,
        batchSize: 50,
        lockName: `it-intake:deadline:${sfx.suffix}`,
        organizationIds: [scanOrg],
      });
      expect(await sweeper.sweepOnce()).toMatchObject({ outcome: 'swept', completed: 1 });
    } finally {
      await locks.close();
    }
    const state = await sfx.state(message);
    expect(state.message.status).toBe('journaled');
    expect(state.history.map((h) => [h.toStatus, h.reasonCode])).toEqual([
      ['scanning', 'scan_started'],
      ['scan_failed', 'scan_timeout'],
      ['journaled', 'intake_scan_failed'],
    ]);
    expect(state.scanned).toEqual([]);
  });

  it('a gateway round still writes scanned.v1 (unchanged)', async () => {
    const message = await sfx.message(scanOrg, { eml: Buffer.from('x'), upload: false });
    const scan = await openRound(message);
    const eventId = uuidv7();
    await repo.finalize({
      consumer: sfx.consumer('rspamd'),
      eventId,
      round: scan,
      final: rspamdFinal('clean'),
      completion: { causationEventId: eventId, correlationId: 'it-intake', now: new Date() },
    });
    const state = await sfx.state(message);
    expect(state.message.status).toBe('scanned');
    expect(state.scanned).toHaveLength(1);
  });
});
