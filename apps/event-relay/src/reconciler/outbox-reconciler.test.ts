import { describe, expect, it } from 'vitest';
import { FakeLocks, metricValue, newMetrics, silentLogger, T0 } from '../testing/fakes';
import {
  OutboxReconciler,
  settlesAsDeadLettered,
  type OutboxReconcilerOptions,
  trackedQueues,
  UNPUBLISHED_COUNT_CAP,
} from './outbox-reconciler';
import type {
  ConsumerProgress,
  OutboxHealth,
  ReconcilerStore,
  Scope,
  SweepRow,
} from './reconciler-store';

const RECEIVED = 'mail.message.received.v1';
const APPROVED = 'mail.delivery.approved.v1';
const PARSED = 'mail.message.parsed.v1';
const MIME = 'email-worker.mime-parser';
const PLANNER = 'delivery-worker.planner';

interface Row extends SweepRow {
  organizationId: bigint;
}

/** In-memory outbox + ledger + cursors with the store's semantics (`NOW(3)` = `clock()`). */
class FakeReconcilerStore implements ReconcilerStore {
  rows: Row[] = [];
  readonly ledger = new Set<string>();
  /** `message_consumer_progress` by `<consumer>|<eventId>`. */
  readonly progressRows = new Map<string, ConsumerProgress>();
  readonly cursors = new Map<string, bigint | null>();
  readonly ledgerQueries: { consumer: string; ids: string[] }[] = [];
  clock: () => Date = () => T0;
  private nextId = 1n;

  add(overrides: Partial<Row> = {}): Row {
    const id = overrides.id ?? this.nextId++;
    const row: Row = {
      id,
      createdAt: new Date(T0.getTime() - 3_600_000),
      eventId: `ev-${id.toString()}`,
      eventType: RECEIVED,
      publishedAt: new Date(T0.getTime() - 3_500_000),
      attempts: 0,
      redriveCount: 0,
      lastRedrivenAt: null,
      organizationId: 42n,
      ...overrides,
    };
    this.rows.push(row);
    this.rows.sort((a, b) => (a.id < b.id ? -1 : 1));
    return row;
  }

  consumed(consumer: string, row: Row): void {
    this.ledger.add(`${consumer}|${row.eventId}`);
  }

  recordProgress(
    consumer: string,
    row: Row,
    state: ConsumerProgress['state'],
    at: Date,
    reason: string | null = state === 'dead_lettered' ? 'max_attempts_exceeded' : null,
  ): void {
    this.progressRows.set(`${consumer}|${row.eventId}`, { state, reason, updatedAt: at });
  }

  get(id: bigint): Row {
    return this.rows.find((r) => r.id === id)!;
  }

  private inScope(row: Row, scope: Scope): boolean {
    return (
      scope.organizationIds === undefined || scope.organizationIds.includes(row.organizationId)
    );
  }

  health(maxAttempts: number, cap: number, scope: Scope): Promise<OutboxHealth> {
    const unpublished = this.rows.filter(
      (r) => this.inScope(r, scope) && r.publishedAt === null && r.attempts < maxAttempts,
    );
    const poison = this.rows.filter(
      (r) => this.inScope(r, scope) && r.publishedAt === null && r.attempts >= maxAttempts,
    );
    return Promise.resolve({
      unpublished: Math.min(cap, unpublished.length),
      oldestUnpublished:
        unpublished.length === 0
          ? null
          : new Date(Math.min(...unpublished.map((r) => r.createdAt.getTime()))),
      poison: poison.length,
      oldestPoisonId: poison[0]?.id ?? null,
    });
  }

  loadCursor(name: string): Promise<bigint | null | undefined> {
    return Promise.resolve(this.cursors.has(name) ? this.cursors.get(name) : undefined);
  }

  initCursor(name: string, position: bigint): Promise<bigint> {
    if (this.cursors.get(name) == null) this.cursors.set(name, position);
    return Promise.resolve(this.cursors.get(name)!);
  }

  saveCursor(name: string, position: bigint): Promise<void> {
    this.cursors.set(name, position);
    return Promise.resolve();
  }

  oldestPosition(since: Date, scope: Scope): Promise<bigint> {
    const ids = this.rows
      .filter((r) => this.inScope(r, scope) && r.createdAt >= since)
      .map((r) => r.id);
    if (ids.length > 0) return Promise.resolve(ids[0]! - 1n);
    return this.latestPosition(scope);
  }

  latestPosition(scope: Scope): Promise<bigint> {
    const ids = this.rows.filter((r) => this.inScope(r, scope)).map((r) => r.id);
    return Promise.resolve(ids.length === 0 ? 0n : ids[ids.length - 1]!);
  }

  readAfter(after: bigint, since: Date, limit: number, scope: Scope): Promise<SweepRow[]> {
    return Promise.resolve(
      this.rows
        .filter((r) => this.inScope(r, scope) && r.id > after && r.createdAt >= since)
        .slice(0, limit)
        .map((r) => ({ ...r })),
    );
  }

  ledgerPresent(consumer: string, eventIds: readonly string[]): Promise<Set<string>> {
    this.ledgerQueries.push({ consumer, ids: [...eventIds] });
    return Promise.resolve(new Set(eventIds.filter((id) => this.ledger.has(`${consumer}|${id}`))));
  }

  progress(consumer: string, eventIds: readonly string[]): Promise<Map<string, ConsumerProgress>> {
    const found = new Map<string, ConsumerProgress>();
    for (const id of eventIds) {
      const entry = this.progressRows.get(`${consumer}|${id}`);
      if (entry) found.set(id, entry);
    }
    return Promise.resolve(found);
  }

  watch(key: Pick<SweepRow, 'id' | 'createdAt'>): Promise<boolean> {
    const row = this.get(key.id);
    if (row.publishedAt === null) return Promise.resolve(false);
    row.lastRedrivenAt = this.clock();
    return Promise.resolve(true);
  }

  redrive(key: Pick<SweepRow, 'id' | 'createdAt'>, maxRedrives: number): Promise<boolean> {
    const row = this.get(key.id);
    if (row.publishedAt === null || row.redriveCount >= maxRedrives) return Promise.resolve(false);
    row.publishedAt = null;
    row.redriveCount += 1;
    row.lastRedrivenAt = this.clock();
    return Promise.resolve(true);
  }

  clearRedrive(key: Pick<SweepRow, 'id' | 'createdAt'>): Promise<void> {
    this.get(key.id).lastRedrivenAt = null;
    return Promise.resolve();
  }

  dueRechecks(before: Date, limit: number, scope: Scope): Promise<SweepRow[]> {
    return Promise.resolve(
      this.rows
        .filter(
          (r) =>
            this.inScope(r, scope) &&
            r.lastRedrivenAt !== null &&
            r.lastRedrivenAt < before &&
            r.publishedAt !== null &&
            r.publishedAt < before,
        )
        .slice(0, limit)
        .map((r) => ({ ...r })),
    );
  }

  /** The relay republishing a re-driven row at `at`. */
  republish(row: Row, at: Date): void {
    row.publishedAt = at;
  }
}

function setup(overrides: Partial<OutboxReconcilerOptions> = {}) {
  const store = new FakeReconcilerStore();
  const locks = new FakeLocks();
  const { metrics, service } = newMetrics();
  let now = T0;
  const options: OutboxReconcilerOptions = {
    store,
    locks,
    metrics,
    logger: silentLogger,
    queues: ['email.received', 'email.delivery.pending'],
    intervalMs: 60_000,
    unconsumedAfterSeconds: 900,
    maxRedrives: 3,
    lookbackHours: 72,
    batchSize: 1000,
    startPosition: 'oldest',
    maxAttempts: 10,
    now: () => now,
    ...overrides,
  };
  const reconciler = new OutboxReconciler(options);
  return {
    store,
    locks,
    service,
    reconciler,
    advance: (ms: number) => {
      now = new Date(now.getTime() + ms);
      store.clock = () => now;
    },
    now: () => now,
  };
}

describe('trackedQueues', () => {
  it('resolves the bound event types and ledger consumers from the topology', () => {
    expect(trackedQueues(['email.received', 'email.delivery.pending'])).toEqual([
      { queue: 'email.received', ledgerName: MIME, eventTypes: [RECEIVED], maxHopGapMs: 120_000 },
      {
        queue: 'email.delivery.pending',
        ledgerName: PLANNER,
        eventTypes: [APPROVED],
        maxHopGapMs: 1_800_000,
      },
    ]);
  });

  it('refuses a dormant queue', () => {
    expect(() => trackedQueues(['scan.auth'])).toThrow(/ledger consumer/);
  });
});

describe('OutboxReconciler.runOnce', () => {
  it('runs only while holding er:reconciler', async () => {
    const t = setup();
    t.locks.elsewhere.add('er:reconciler');
    expect((await t.reconciler.runOnce()).active).toBe(false);
    expect(t.store.cursors.size).toBe(0);
  });

  it('settles consumed rows and re-drives a published row without a ledger row', async () => {
    const t = setup();
    const consumed = t.store.add();
    const missing = t.store.add();
    const approved = t.store.add({ eventType: APPROVED });
    t.store.consumed(MIME, consumed);
    t.store.consumed(PLANNER, approved);
    const report = await t.reconciler.runOnce();
    expect(report).toMatchObject({ active: true, settled: 2, redriven: 1, exhausted: 0 });
    expect(report.unconsumed).toEqual({ 'email.received': 1, 'email.delivery.pending': 0 });
    expect(t.store.get(missing.id)).toMatchObject({
      publishedAt: null,
      redriveCount: 1,
      lastRedrivenAt: T0,
    });
    expect(t.store.get(consumed.id).publishedAt).not.toBeNull();
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(approved.id);
    expect(
      await metricValue(t.service, 'reconcile_redriven_total', { queue: 'email.received' }),
    ).toBe(1);
    expect(
      await metricValue(t.service, 'reconcile_unconsumed_rows', { queue: 'email.received' }),
    ).toBe(1);
    // Ledger lookups are batched per consumer.
    expect(t.store.ledgerQueries).toEqual([
      { consumer: MIME, ids: [consumed.eventId, missing.eventId] },
      { consumer: PLANNER, ids: [approved.eventId] },
    ]);
  });

  it('treats untracked types and poison rows as settled', async () => {
    const t = setup();
    const parsed = t.store.add({ eventType: PARSED });
    const poison = t.store.add({ publishedAt: null, attempts: 10 });
    const report = await t.reconciler.runOnce();
    expect(report).toMatchObject({ redriven: 0, settled: 0, stoppedBy: 'end' });
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(poison.id);
    expect(t.store.get(parsed.id).redriveCount).toBe(0);
  });

  it('stops at the first row that is not due', async () => {
    const t = setup();
    const due = t.store.add();
    t.store.add({ createdAt: new Date(T0.getTime() - 899_000), publishedAt: T0 });
    t.store.add(); // older id order does not matter: the sweep stops at the first not-due row
    const report = await t.reconciler.runOnce();
    expect(report.stoppedBy).toBe('not_due');
    expect(report.redriven).toBe(1);
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(due.id);
  });

  it('stops at an unpublished, non-poison row (the relay owns it)', async () => {
    const t = setup();
    const first = t.store.add();
    t.store.consumed(MIME, first);
    t.store.add({ publishedAt: null });
    const after = t.store.add();
    const report = await t.reconciler.runOnce();
    expect(report.stoppedBy).toBe('unpublished');
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(first.id);
    expect(t.store.get(after.id).redriveCount).toBe(0);
  });

  it('stops at a row published less than the threshold ago', async () => {
    const t = setup();
    t.store.add({ publishedAt: new Date(T0.getTime() - 60_000) });
    const report = await t.reconciler.runOnce();
    expect(report.stoppedBy).toBe('published_recently');
    expect(report.redriven).toBe(0);
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(0n);
  });

  it('re-checks a re-driven row: settled once the ledger row exists', async () => {
    const t = setup();
    const row = t.store.add();
    await t.reconciler.runOnce();
    expect(t.store.get(row.id).redriveCount).toBe(1);
    // The relay republishes it; the consumer handles it.
    t.advance(1000);
    t.store.republish(t.store.get(row.id), t.now());
    t.store.consumed(MIME, row);
    t.advance(901_000);
    const report = await t.reconciler.runOnce();
    expect(report).toMatchObject({ rechecked: 1, settled: 1, redriven: 0 });
    expect(t.store.get(row.id)).toMatchObject({ lastRedrivenAt: null, redriveCount: 1 });
    expect(t.store.get(row.id).publishedAt).not.toBeNull();
    // Nothing left to re-check.
    t.advance(900_000);
    expect((await t.reconciler.runOnce()).rechecked).toBe(0);
  });

  it('does not re-check before the republished copy had the full threshold', async () => {
    const t = setup();
    const row = t.store.add();
    await t.reconciler.runOnce();
    t.advance(900_001);
    t.store.republish(t.store.get(row.id), t.now()); // the relay was slow
    expect((await t.reconciler.runOnce()).rechecked).toBe(0);
  });

  it('re-drives up to RECONCILE_MAX_REDRIVES, then reports exhausted', async () => {
    const t = setup({ maxRedrives: 2 });
    const row = t.store.add();
    await t.reconciler.runOnce(); // re-drive 1 (sweep)
    for (let i = 0; i < 2; i += 1) {
      t.advance(1000);
      t.store.republish(t.store.get(row.id), t.now());
      t.advance(901_000);
      await t.reconciler.runOnce(); // re-check: re-drive 2, then exhausted
    }
    expect(t.store.get(row.id)).toMatchObject({ redriveCount: 2, lastRedrivenAt: null });
    expect(t.store.get(row.id).publishedAt).not.toBeNull();
    expect(
      await metricValue(t.service, 'reconcile_redriven_total', { queue: 'email.received' }),
    ).toBe(2);
    expect(
      await metricValue(t.service, 'reconcile_exhausted_total', { queue: 'email.received' }),
    ).toBe(1);
    t.advance(900_000);
    expect((await t.reconciler.runOnce()).rechecked).toBe(0);
  });

  it('detects only with RECONCILE_MAX_REDRIVES=0', async () => {
    const t = setup({ maxRedrives: 0 });
    const row = t.store.add();
    const report = await t.reconciler.runOnce();
    expect(report).toMatchObject({ redriven: 0, exhausted: 1 });
    expect(t.store.get(row.id).publishedAt).not.toBeNull();
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(row.id);
  });

  it('skips rows older than the lookback', async () => {
    const t = setup({ lookbackHours: 1 });
    const old = t.store.add({ createdAt: new Date(T0.getTime() - 3_700_000) });
    const recent = t.store.add({ createdAt: new Date(T0.getTime() - 3_000_000) });
    const report = await t.reconciler.runOnce();
    expect(report.redriven).toBe(1);
    expect(t.store.get(old.id).redriveCount).toBe(0);
    expect(t.store.get(recent.id).redriveCount).toBe(1);
  });

  it('starts at the oldest row within the lookback (oldest) or after MAX(id) (latest)', async () => {
    const oldest = setup({ lookbackHours: 2 });
    oldest.store.add({ createdAt: new Date(T0.getTime() - 3 * 3_600_000) });
    const inside = oldest.store.add();
    await oldest.reconciler.runOnce();
    expect(oldest.store.get(inside.id).redriveCount).toBe(1);

    const latest = setup({ startPosition: 'latest' });
    latest.store.add();
    const last = latest.store.add();
    await latest.reconciler.runOnce();
    expect(latest.store.cursors.get('reconcile:unconsumed')).toBe(last.id);
    expect(latest.store.rows.every((r) => r.redriveCount === 0)).toBe(true);
    const later = latest.store.add();
    await latest.reconciler.runOnce();
    expect(latest.store.get(later.id).redriveCount).toBe(1);
  });

  it('keeps an existing cursor across restarts', async () => {
    const t = setup();
    t.store.cursors.set('reconcile:unconsumed', 5n);
    for (let i = 0; i < 6; i += 1) t.store.add();
    const report = await t.reconciler.runOnce();
    expect(report.redriven).toBe(1);
    expect(t.store.get(6n).redriveCount).toBe(1);
  });

  it('reads at most RECONCILE_BATCH_SIZE rows per run', async () => {
    const t = setup({ batchSize: 2 });
    for (let i = 0; i < 5; i += 1) t.store.add();
    expect((await t.reconciler.runOnce()).redriven).toBe(2);
    expect((await t.reconciler.runOnce()).redriven).toBe(2);
    expect((await t.reconciler.runOnce()).redriven).toBe(1);
  });

  it('reports unpublished and poison rows in the health gauges', async () => {
    const t = setup();
    t.store.add({ publishedAt: null, createdAt: new Date(T0.getTime() - 120_000) });
    t.store.add({ publishedAt: null, attempts: 10 });
    t.store.add({ publishedAt: null, attempts: 12 });
    const report = await t.reconciler.runOnce();
    expect(report).toMatchObject({ unpublished: 1, poison: 2 });
    expect(await metricValue(t.service, 'outbox_unpublished_rows')).toBe(1);
    expect(await metricValue(t.service, 'outbox_unpublished_oldest_seconds')).toBe(120);
    expect(await metricValue(t.service, 'outbox_poison_rows')).toBe(2);
    expect(UNPUBLISHED_COUNT_CAP).toBe(100_000);
  });

  it('applies the organization scope', async () => {
    const t = setup({ organizationIds: [7n] });
    t.store.add({ organizationId: 8n });
    const mine = t.store.add({ organizationId: 7n });
    const report = await t.reconciler.runOnce();
    expect(report.redriven).toBe(1);
    expect(t.store.get(mine.id).redriveCount).toBe(1);
  });

  it('uses its own lock and cursor names when given', async () => {
    const t = setup({ lockName: 'it:rec', cursorName: 'it:cursor' });
    t.store.add();
    await t.reconciler.runOnce();
    expect(t.locks.ensured).toEqual(['it:rec']);
    expect(t.store.cursors.has('it:cursor')).toBe(true);
  });

  it('refuses a threshold below 300 s', () => {
    expect(() => setup({ unconsumedAfterSeconds: 299 })).toThrow(/300/);
  });
});

describe('OutboxReconciler: dead letters, retries and backlogs are not lost events (review round 1)', () => {
  it('never re-drives an event its consumer dead-lettered (settled; replay recovers it)', async () => {
    const t = setup();
    const poison = t.store.add({ eventType: APPROVED });
    t.store.recordProgress(PLANNER, poison, 'dead_lettered', new Date(T0.getTime() - 3_000_000));
    const report = await t.reconciler.runOnce();
    expect(report).toMatchObject({ redriven: 0, exhausted: 0, deadLettered: 1, deferred: 0 });
    expect(report.unconsumed['email.delivery.pending']).toBe(0);
    expect(t.store.get(poison.id)).toMatchObject({ redriveCount: 0, lastRedrivenAt: null });
    expect(t.store.get(poison.id).publishedAt).not.toBeNull();
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(poison.id);
    expect(
      await metricValue(t.service, 'reconcile_skipped_total', {
        queue: 'email.delivery.pending',
        reason: 'dead_lettered',
      }),
    ).toBe(1);
    expect(
      await metricValue(t.service, 'reconcile_exhausted_total', {
        queue: 'email.delivery.pending',
      }),
    ).toBe(0);
  });

  it.each(['approval_mismatch', 'approval_not_issued', 'contract_invalid', 'tenant_mismatch'])(
    'does not let a %s dead letter (not a relay copy: forged or altered) settle the row',
    async (reason) => {
      const t = setup({ maxRedrives: 1 });
      const row = t.store.add({ eventType: APPROVED });
      t.store.recordProgress(PLANNER, row, 'dead_lettered', T0, reason);
      expect(await t.reconciler.runOnce()).toMatchObject({ deadLettered: 0, redriven: 1 });
      expect(t.store.get(row.id)).toMatchObject({ redriveCount: 1, publishedAt: null });
      expect(
        await metricValue(t.service, 'reconcile_skipped_total', {
          queue: 'email.delivery.pending',
          reason: 'dead_lettered',
        }),
      ).toBe(0);
    },
  );

  it('settles on a trusted dead-letter reason, and on a record without a reason', () => {
    const at = T0;
    expect(
      settlesAsDeadLettered({
        state: 'dead_lettered',
        reason: 'retry_age_exceeded',
        updatedAt: at,
      }),
    ).toBe(true);
    expect(
      settlesAsDeadLettered({ state: 'dead_lettered', reason: 'message_purged', updatedAt: at }),
    ).toBe(true);
    expect(settlesAsDeadLettered({ state: 'dead_lettered', reason: null, updatedAt: at })).toBe(
      true,
    );
    expect(
      settlesAsDeadLettered({ state: 'dead_lettered', reason: 'approval_mismatch', updatedAt: at }),
    ).toBe(false);
    expect(settlesAsDeadLettered({ state: 'retrying', reason: null, updatedAt: at })).toBe(false);
    expect(settlesAsDeadLettered(undefined)).toBe(false);
  });

  it('defers an event that is still retrying, then re-drives it once its retries went quiet', async () => {
    const t = setup();
    const row = t.store.add({ eventType: APPROVED });
    // The planner's last delay hop was 20 min ago: within 15 min threshold + 30 min hop gap.
    t.store.recordProgress(PLANNER, row, 'retrying', new Date(T0.getTime() - 20 * 60_000));
    const first = await t.reconciler.runOnce();
    expect(first).toMatchObject({ redriven: 0, deferred: 1 });
    expect(t.store.get(row.id)).toMatchObject({ redriveCount: 0, lastRedrivenAt: T0 });
    expect(t.store.get(row.id).publishedAt).not.toBeNull();
    expect(t.store.cursors.get('reconcile:unconsumed')).toBe(row.id);
    expect(
      await metricValue(t.service, 'reconcile_skipped_total', {
        queue: 'email.delivery.pending',
        reason: 'retrying',
      }),
    ).toBe(1);

    // Re-check after the threshold: still retrying (a newer hop) → deferred again.
    t.advance(901_000);
    t.store.recordProgress(PLANNER, row, 'retrying', t.now());
    expect(await t.reconciler.runOnce()).toMatchObject({ rechecked: 1, deferred: 1, redriven: 0 });

    // The retries stopped without a ledger row or a dead letter for longer than the window.
    t.advance(46 * 60_000);
    const later = await t.reconciler.runOnce();
    expect(later).toMatchObject({ rechecked: 1, deferred: 0, redriven: 1 });
    expect(t.store.get(row.id)).toMatchObject({ redriveCount: 1, publishedAt: null });
  });

  it("applies each queue's own hop gap (hold: 2 min, delay-queue: 30 min)", async () => {
    const t = setup();
    const at = new Date(T0.getTime() - 20 * 60_000);
    const received = t.store.add();
    const approved = t.store.add({ eventType: APPROVED });
    t.store.recordProgress(MIME, received, 'retrying', at);
    t.store.recordProgress(PLANNER, approved, 'retrying', at);
    const report = await t.reconciler.runOnce();
    expect(report).toMatchObject({ redriven: 1, deferred: 1 });
    expect(t.store.get(received.id).redriveCount).toBe(1);
    expect(t.store.get(approved.id).redriveCount).toBe(0);
  });

  it('settles a row once the consumer handled the event, whatever its progress row says', async () => {
    const t = setup();
    const row = t.store.add();
    t.store.recordProgress(MIME, row, 'dead_lettered', T0);
    t.store.consumed(MIME, row); // replayed and handled
    expect(await t.reconciler.runOnce()).toMatchObject({ settled: 1, deadLettered: 0 });
  });

  it('defers while the queue has ready messages (a backlog), asking the broker once per queue per run', async () => {
    const asked: string[] = [];
    let depth = 250;
    const t = setup({
      queueDepth: {
        readyMessages: (queue) => {
          asked.push(queue);
          return Promise.resolve(depth);
        },
      },
    });
    const rows = [t.store.add(), t.store.add(), t.store.add()];
    const first = await t.reconciler.runOnce();
    expect(first).toMatchObject({ redriven: 0, deferred: 3 });
    expect(asked).toEqual(['email.received']);
    for (const row of rows) expect(t.store.get(row.id).redriveCount).toBe(0);
    expect(
      await metricValue(t.service, 'reconcile_skipped_total', {
        queue: 'email.received',
        reason: 'queue_backlog',
      }),
    ).toBe(3);
    // The consumer caught up but never recorded these: lost, re-driven by the re-check.
    depth = 0;
    t.advance(901_000);
    expect(await t.reconciler.runOnce()).toMatchObject({ rechecked: 3, redriven: 3 });
  });

  it('defers when the queue depth cannot be read (never re-drives blind)', async () => {
    const t = setup({
      queueDepth: { readyMessages: () => Promise.reject(new Error('broker down')) },
    });
    const row = t.store.add();
    expect(await t.reconciler.runOnce()).toMatchObject({ redriven: 0, deferred: 1 });
    expect(t.store.get(row.id).redriveCount).toBe(0);
    expect(
      await metricValue(t.service, 'reconcile_skipped_total', {
        queue: 'email.received',
        reason: 'queue_unknown',
      }),
    ).toBe(1);
  });
});
