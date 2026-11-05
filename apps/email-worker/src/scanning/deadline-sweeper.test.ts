import { NonRetryableError } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { DeadlineSweeper, SCAN_DEADLINE_LOCK } from './deadline-sweeper';
import { FakeScanStore, newMetrics } from './fakes.test-support';

const logger = createLogger({ service: 'test', level: 'silent' });

function setup(leader = true) {
  const store = new FakeScanStore();
  const { metrics, registry } = newMetrics();
  const ensured: string[] = [];
  let now = new Date('2026-11-05T12:00:00Z');
  const sweeper = new DeadlineSweeper({
    store,
    locks: {
      ensure: (name) => {
        ensured.push(name);
        return Promise.resolve(leader);
      },
      release: () => Promise.resolve(),
    },
    metrics,
    logger,
    intervalMs: 10,
    lookbackHours: 48,
    batchSize: 10,
    now: () => now,
  });
  return { store, sweeper, registry, ensured, setNow: (d: Date) => (now = d) };
}

async function openRound(store: FakeScanStore, id: bigint, at: Date) {
  store.addMessage({
    id,
    receivedAt: at,
    organizationId: 1n,
    direction: 'inbound',
    emlObjectKey: 'org/1/eml/x',
    sizeBytes: 1,
    clientIp: null,
    clientHelo: null,
    clientName: null,
    envelopeFrom: '',
    mtaQueueId: null,
    recipients: [],
  });
  await store.openRound({
    message: store.messages.get(id.toString())!,
    round: 0,
    scanKind: 'initial',
    trigger: 'parsed',
    engine: 'rspamd',
    eventId: 'e',
    correlationId: 'c',
    requiredEngines: ['rspamd'],
    deadlineSeconds: 60,
    now: at,
  });
}

describe('DeadlineSweeper (S10)', () => {
  it('finalizes overdue rounds as timeout and fails them (never clean)', async () => {
    const { store, sweeper, registry, ensured } = setup();
    await openRound(store, 1n, new Date('2026-11-05T11:00:00Z'));
    await openRound(store, 2n, new Date('2026-11-05T11:59:30Z')); // not yet overdue
    const report = await sweeper.sweepOnce();
    expect(ensured).toEqual([SCAN_DEADLINE_LOCK]);
    expect(report).toEqual({
      outcome: 'swept',
      found: 1,
      completed: 1,
      finalizedEngines: 1,
      failed: 0,
    });
    expect(store.state(1n)).toEqual({ state: 'scan_failed', round: 0 });
    expect(store.state(2n)).toEqual({ state: 'scanning', round: 0 });
    expect(store.scans[0]).toMatchObject({ status: 'timed_out', verdict: 'timeout' });
    expect(store.rowsOf(store.scans[0]!.scanId)[0]).toMatchObject({
      isFinal: true,
      outcome: 'timeout',
      errorCode: 'deadline_exceeded',
    });
    const text = await registry.metrics();
    expect(text).toMatch(/scan_deadline_finalized_total\{engine="rspamd"[^}]*\} 1/);
    expect(text).toMatch(
      /scan_engine_failures_total\{engine="rspamd",reason="deadline_exceeded"[^}]*\} 1/,
    );
    // Idempotent: a second pass finds nothing.
    expect((await sweeper.sweepOnce()).found).toBe(0);
  });

  it('does nothing without the leader lock', async () => {
    const { store, sweeper } = setup(false);
    await openRound(store, 1n, new Date('2026-11-05T11:00:00Z'));
    expect((await sweeper.sweepOnce()).outcome).toBe('not_leader');
    expect(store.state(1n)!.state).toBe('scanning');
  });

  it('passes over a round that fails non-transiently so the others are still finalized', async () => {
    const { store, sweeper, registry } = setup();
    await openRound(store, 1n, new Date('2026-11-05T10:00:00Z')); // oldest deadline: first
    await openRound(store, 2n, new Date('2026-11-05T11:00:00Z'));
    const sweepRound = store.sweepRound.bind(store);
    store.sweepRound = (candidate, now) =>
      candidate.messageId === 1n
        ? Promise.reject(new NonRetryableError('scanned_payload_invalid'))
        : sweepRound(candidate, now);
    const report = await sweeper.sweepOnce();
    expect(report).toMatchObject({ outcome: 'swept', found: 2, completed: 1, failed: 1 });
    expect(store.state(1n)!.state).toBe('scanning');
    expect(store.state(2n)).toEqual({ state: 'scan_failed', round: 0 });
    expect(await registry.metrics()).toMatch(/scan_deadline_sweeper_errors_total\{[^}]*\} 1/);
  });

  it('stops the pass on a transient (database) error of one round', async () => {
    const { store, sweeper } = setup();
    await openRound(store, 1n, new Date('2026-11-05T10:00:00Z'));
    await openRound(store, 2n, new Date('2026-11-05T11:00:00Z'));
    store.sweepRound = () =>
      Promise.reject(Object.assign(new Error('connection lost'), { code: 'ECONNRESET' }));
    expect((await sweeper.sweepOnce()).outcome).toBe('database_error');
    expect(store.state(2n)!.state).toBe('scanning');
  });

  it('reports a database error and keeps running', async () => {
    const { store, sweeper, registry } = setup();
    store.sweepCandidates = () => Promise.reject(new Error('db down'));
    expect((await sweeper.sweepOnce()).outcome).toBe('database_error');
    expect(await registry.metrics()).toMatch(/scan_deadline_sweeper_errors_total\{[^}]*\} 1/);
    sweeper.start();
    expect(sweeper.running).toBe(true);
    await sweeper.stop();
    expect(sweeper.running).toBe(false);
  });
});
