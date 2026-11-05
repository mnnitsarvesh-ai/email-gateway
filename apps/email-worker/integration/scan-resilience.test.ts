import { messageScannedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eventually, TcpProxy } from './support/broker';
import { workerConfig } from './support/fixtures';
import {
  corpusEml,
  HangingServer,
  loadCorpus,
  ScanBroker,
  ScanFixtures,
  type ScanMessage,
  sweeper,
  withScanPipeline,
} from './support/scan';
import { ScanMetrics } from '../src/scanning/scan-metrics';
import { MetricsService, uuidv7 } from '@email-gateway/common';

/**
 * Failure behaviour of the scan stage (step 4.1 S10, §9): Rspamd unreachable, hanging, the
 * circuit breaker, recovery within the attempt budget and the round deadline sweeper. A failure
 * is never `clean`: every round ends `scan_failed` unless a real Rspamd result was recorded.
 */
let fx: ScanFixtures;
let broker: ScanBroker;
let org: bigint;
const clean = loadCorpus().find((f) => f.class === 'clean')!;

beforeAll(async () => {
  fx = new ScanFixtures();
  org = await fx.organization('resilience');
  broker = await ScanBroker.start();
});

afterAll(async () => {
  await broker?.close();
  await fx?.cleanup();
});

const cleanMessage = (): Promise<ScanMessage> =>
  fx.message(org, { eml: corpusEml(clean), envelope: clean.envelope });

/** Fast retries; the breaker stays closed unless a test lowers its threshold. */
const fast = (overrides: Record<string, string>) => ({
  SCAN_RETRY_BASE_MS: '100',
  SCAN_RETRY_MAX_MS: '200',
  SCAN_BREAKER_FAILURE_THRESHOLD: '100',
  SCAN_BREAKER_FAILURE_RATIO: '1',
  SCAN_ROUND_DEADLINE_SECONDS: '600',
  ...overrides,
});

async function expectFailedRound(message: ScanMessage, reason: string, verdict: string) {
  const state = await fx.state(message);
  expect(state.message.status).toBe('scan_failed');
  expect(state.history.at(-1)).toMatchObject({ toStatus: 'scan_failed', reasonCode: reason });
  expect(state.scans[0]!.scanVerdict).toBe(verdict);
  expect(state.results.some((r) => r.outcome === 'clean')).toBe(false);
  expect(state.scanned).toHaveLength(1);
  const payload = messageScannedV1.parse(state.scanned[0]!.payload);
  expect(payload).toMatchObject({ outcome: 'scan_failed', verdict });
  return state;
}

describe('Rspamd unreachable (closed port)', () => {
  it('records error attempts, then a final error, and the round fails (never clean)', async () => {
    const message = await cleanMessage();
    const event = fx.parsed(message);
    await withScanPipeline(
      fx,
      broker,
      { overrides: fast({ SCAN_RSPAMD_URL: 'http://127.0.0.1:9', SCAN_RSPAMD_MAX_ATTEMPTS: '3' }) },
      async (pipeline) => {
        expect(await pipeline.deliver(broker, event)).toBe('handled');
        expect(pipeline.failuresOf(event.eventId)).toHaveLength(2);
        const state = await expectFailedRound(message, 'scan_error', 'error');
        expect(state.results.map((r) => [r.attempt, r.isFinal, r.outcome, r.errorCode])).toEqual([
          [1, false, 'error', 'unavailable'],
          [2, false, 'error', 'unavailable'],
          [3, true, 'error', 'unavailable'],
        ]);
        expect(state.scans[0]!.status).toBe('failed');
        expect(state.auth).toEqual([]);
        expect(await pipeline.text()).toMatch(
          /scan_engine_results_total\{engine="rspamd",outcome="error",final="false"[^}]*\} 2/,
        );
      },
    );
  });
});

describe('Rspamd hanging (accepts, never answers)', () => {
  it('records timeout attempts and the round ends scan_timeout', async () => {
    const hanging = await HangingServer.start();
    const message = await cleanMessage();
    const event = fx.parsed(message);
    try {
      await withScanPipeline(
        fx,
        broker,
        {
          overrides: fast({
            SCAN_RSPAMD_URL: `http://127.0.0.1:${String(hanging.port)}`,
            SCAN_RSPAMD_TIMEOUT_MS: '400',
            SCAN_RSPAMD_MAX_ATTEMPTS: '2',
          }),
        },
        async (pipeline) => {
          expect(await pipeline.deliver(broker, event)).toBe('handled');
          const state = await expectFailedRound(message, 'scan_timeout', 'timeout');
          expect(state.results.map((r) => [r.attempt, r.isFinal, r.outcome, r.errorCode])).toEqual([
            [1, false, 'timeout', 'timeout'],
            [2, true, 'timeout', 'timeout'],
          ]);
          expect(state.scans[0]!.status).toBe('timed_out');
          for (const r of state.results) expect(r.durationMs).toBeGreaterThanOrEqual(350);
        },
      );
      expect(hanging.requests).toBe(2);
    } finally {
      await hanging.close();
    }
  });
});

describe('circuit breaker', () => {
  it('opens after consecutive failures and then fails fast without calling Rspamd', async () => {
    const hanging = await HangingServer.start();
    const message = await cleanMessage();
    const event = fx.parsed(message);
    try {
      await withScanPipeline(
        fx,
        broker,
        {
          overrides: fast({
            SCAN_RSPAMD_URL: `http://127.0.0.1:${String(hanging.port)}`,
            SCAN_RSPAMD_TIMEOUT_MS: '300',
            SCAN_RSPAMD_MAX_ATTEMPTS: '5',
            SCAN_BREAKER_FAILURE_THRESHOLD: '2',
            SCAN_BREAKER_OPEN_MS: '60000',
          }),
        },
        async (pipeline) => {
          expect(await pipeline.deliver(broker, event)).toBe('handled');
          const state = await expectFailedRound(message, 'scan_error', 'error');
          expect(state.results.map((r) => [r.attempt, r.isFinal, r.errorCode])).toEqual([
            [1, false, 'timeout'],
            [2, false, 'timeout'],
            [3, false, 'circuit_open'],
            [4, false, 'circuit_open'],
            [5, true, 'circuit_open'],
          ]);
          // Fail fast: the open breaker never waits for the per-call timeout.
          for (const r of state.results.slice(2)) expect(r.durationMs).toBeLessThan(100);
          expect(state.results[4]!.reasonCodes).toEqual(['engine.circuit_open']);
          expect(pipeline.breaker.state).toBe('open');
          const text = await pipeline.text();
          expect(text).toMatch(/scan_engine_circuit_state\{engine="rspamd"[^}]*\} 2/);
          expect(text).toMatch(
            /scan_engine_circuit_transitions_total\{engine="rspamd",to="open"[^}]*\} 1/,
          );
          expect(text).toMatch(
            /scan_engine_failures_total\{engine="rspamd",reason="circuit_open"[^}]*\} 3/,
          );
        },
      );
      expect(hanging.requests).toBe(2);
    } finally {
      await hanging.close();
    }
  });
});

describe('recovery within the attempt budget', () => {
  it('Rspamd comes back before the budget is spent: the round ends scanned with a real result', async () => {
    const target = new URL(process.env.SCAN_RSPAMD_URL!);
    const proxy = await TcpProxy.start(target.hostname, Number(target.port));
    proxy.cut();
    const message = await cleanMessage();
    const event = fx.parsed(message);
    try {
      await withScanPipeline(
        fx,
        broker,
        {
          overrides: fast({
            SCAN_RSPAMD_URL: `http://127.0.0.1:${String(proxy.port)}`,
            SCAN_RSPAMD_MAX_ATTEMPTS: '6',
            SCAN_RETRY_BASE_MS: '300',
            SCAN_RETRY_MAX_MS: '600',
          }),
        },
        async (pipeline) => {
          await broker.publish([event]);
          await eventually(
            async () => (await fx.state(message)).results.length >= 1,
            30_000,
            'a failed attempt row',
          );
          proxy.restore();
          expect(await pipeline.outcome(event.eventId, 1, 60_000)).toBe('handled');
          const state = await fx.state(message);
          expect(state.message.status).toBe('scanned');
          const final = state.results.find((r) => r.isFinal)!;
          expect(final).toMatchObject({ outcome: 'clean', errorCode: null });
          expect(final.attempt).toBeGreaterThan(1);
          expect(state.results.filter((r) => !r.isFinal).every((r) => r.outcome === 'error')).toBe(
            true,
          );
          expect(state.auth).toHaveLength(1);
          expect(messageScannedV1.parse(state.scanned[0]!.payload)).toMatchObject({
            outcome: 'scanned',
            verdict: 'clean',
            engines: [{ engine: 'rspamd', attempts: final.attempt }],
          });
        },
      );
    } finally {
      await proxy.close();
    }
  });
});

describe('missing EML', () => {
  it('a missing object ends the round eml_unavailable at once (not retried)', async () => {
    const message = await fx.message(org, {
      eml: corpusEml(clean),
      envelope: clean.envelope,
      upload: false,
    });
    const event = fx.parsed(message);
    await withScanPipeline(fx, broker, { overrides: fast({}) }, async (pipeline) => {
      expect(await pipeline.deliver(broker, event)).toBe('handled');
      expect(pipeline.failuresOf(event.eventId)).toEqual([]);
      const state = await expectFailedRound(message, 'eml_unavailable', 'error');
      expect(state.results).toEqual([
        expect.objectContaining({ attempt: 1, isFinal: true, errorCode: 'eml_unavailable' }),
      ]);
    });
  });
});

describe('round deadline sweeper', () => {
  it('finalizes a round whose engine never reports: timeout rows, scan_failed', async () => {
    const config = workerConfig({});
    const registry = new MetricsService({ service: 'email-worker-it-sweeper' });
    const metrics = new ScanMetrics(registry);
    const { sweeper: sweep, store, locks } = sweeper(fx, metrics, config);
    const message = await cleanMessage();
    const row = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: message.messageId, receivedAt: message.receivedAt },
    });
    // The round opens (E3) as an engine delivery opens it, then the engine never reports.
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
      correlationId: 'it-scan-sweeper',
      requiredEngines: ['rspamd'],
      deadlineSeconds: 1,
      now: new Date(),
    });
    expect(opened).toMatchObject({ kind: 'open', opened: true });
    try {
      expect((await sweep.sweepOnce()).found).toBe(0);
      await new Promise((r) => setTimeout(r, 1_200));
      const report = await sweep.sweepOnce();
      expect(report).toMatchObject({
        outcome: 'swept',
        found: 1,
        completed: 1,
        finalizedEngines: 1,
      });
      const state = await fx.state(message);
      expect(state.message.status).toBe('scan_failed');
      expect(state.history.map((h) => [h.toStatus, h.reasonCode, h.eventId])).toEqual([
        ['scanning', 'scan_started', expect.any(String)],
        ['scan_failed', 'scan_timeout', null],
      ]);
      expect(state.results).toEqual([
        expect.objectContaining({
          isFinal: true,
          outcome: 'timeout',
          errorCode: 'deadline_exceeded',
          reasonCodes: ['engine.deadline_exceeded'],
        }),
      ]);
      expect(state.scans[0]).toMatchObject({ status: 'timed_out', scanVerdict: 'timeout' });
      expect(messageScannedV1.parse(state.scanned[0]!.payload)).toMatchObject({
        outcome: 'scan_failed',
        verdict: 'timeout',
      });
      expect(state.scanned[0]!.correlationId).toBe(`message:${message.messageId.toString()}`);
      expect(await registry.metrics()).toMatch(
        /scan_deadline_finalized_total\{engine="rspamd"[^}]*\} 1/,
      );
      // Idempotent: nothing left.
      expect((await sweep.sweepOnce()).found).toBe(0);
    } finally {
      await sweep.stop();
      await locks.close();
    }
  });

  it('finalizes initial and rescan rounds of a message received before the lookback window', async () => {
    // The sweep is bounded by the round's deadline, not by the message's received_at: a rescan
    // of mail received 72 h ago (lookback 48 h) whose engine never reports must still end.
    const config = workerConfig({});
    const registry = new MetricsService({ service: 'email-worker-it-sweeper-old' });
    const metrics = new ScanMetrics(registry);
    const { sweeper: sweep, store, locks } = sweeper(fx, metrics, config);
    const message = await fx.message(org, {
      eml: corpusEml(clean),
      envelope: clean.envelope,
      receivedAt: new Date(Date.now() - 72 * 3_600_000),
    });
    const row = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: message.messageId, receivedAt: message.receivedAt },
    });
    const record = {
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
    };
    const open = (round: number, scanKind: 'initial' | 'rescan') =>
      store.openRound({
        message: record,
        round,
        scanKind,
        trigger: round === 0 ? 'parsed' : 'rescan',
        engine: 'rspamd',
        eventId: uuidv7(),
        correlationId: 'it-scan-sweeper-old',
        requiredEngines: ['rspamd'],
        deadlineSeconds: 1,
        now: new Date(),
      });
    try {
      expect(await open(0, 'initial')).toMatchObject({ kind: 'open', opened: true });
      await new Promise((r) => setTimeout(r, 1_200));
      expect(await sweep.sweepOnce()).toMatchObject({ outcome: 'swept', found: 1, completed: 1 });
      expect((await fx.state(message)).message.status).toBe('scan_failed');

      // The administrative rescan (E19) opens round 1; its engine never reports either.
      await fx.rescan(message);
      expect(await open(1, 'rescan')).toMatchObject({ kind: 'open' });
      await new Promise((r) => setTimeout(r, 1_200));
      expect(await sweep.sweepOnce()).toMatchObject({
        outcome: 'swept',
        found: 1,
        completed: 1,
        finalizedEngines: 1,
      });
      const state = await fx.state(message);
      expect(state.message).toMatchObject({ status: 'scan_failed', lifecycleRound: 1 });
      expect(
        state.scans.map((s) => [s.lifecycleRound, s.scanKind, s.status, s.scanVerdict]),
      ).toEqual([
        [0, 'initial', 'timed_out', 'timeout'],
        [1, 'rescan', 'timed_out', 'timeout'],
      ]);
      expect(state.history.at(-1)).toMatchObject({
        toStatus: 'scan_failed',
        reasonCode: 'scan_timeout',
      });
      expect(state.scanned).toHaveLength(2);
      expect((await sweep.sweepOnce()).found).toBe(0);
    } finally {
      await sweep.stop();
      await locks.close();
    }
  });
});
