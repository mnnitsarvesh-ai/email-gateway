import { describe, expect, it } from 'vitest';
import { type SeenSql, silentLogger, sqlOf, testMetrics } from '../worker.test-support';
import { ReplayProcessor } from './replay';

const NOW = new Date('2026-11-13T12:00:00.000Z');

const replayRow = (overrides: Record<string, unknown> = {}) => ({
  id: 9n,
  organization_id: 42n,
  subscription_id: 501n,
  status: 'queued',
  range_from: new Date('2026-11-12T00:00:00.000Z'),
  range_to: new Date('2026-11-13T00:00:00.000Z'),
  statuses: ['failed', 'dead'],
  event_types: null,
  cursor_occurred_at: null,
  cursor_id: null,
  matched_count: 0,
  ...overrides,
});

const original = (i: number, org = 42n) => ({
  id: BigInt(i),
  event_occurred_at: new Date(Date.UTC(2026, 10, 12, 0, 0, i)),
  organization_id: org,
  event_id: `0193a1b2-0000-8000-8000-${String(i).padStart(12, '0')}`,
  event_type: 'email.received',
});

function harness(options: {
  replay?: ReturnType<typeof replayRow> | null;
  rows?: ReturnType<typeof original>[];
  subscription?: { id: bigint; organizationId: bigint; status: string } | null;
  maxSeq?: Record<string, number>;
  /** Existing replays (seq ≥ 1) per event id. */
  replays?: Record<string, number>;
  batchSize?: number;
  maxEvents?: number;
  maxPerDelivery?: number;
  organization?: { id: bigint; status: string } | null;
  feature?: { organizationId: bigint; featureKey: string; enabled: boolean } | null;
}) {
  const statements: SeenSql[] = [];
  const tx = {
    $queryRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.includes('FROM webhook_replays')) {
        return Promise.resolve(options.replay === null ? [] : [options.replay ?? replayRow()]);
      }
      if (s.text.includes('FROM webhook_subscriptions')) {
        const sub =
          options.subscription === undefined
            ? { id: 501n, organizationId: 42n, status: 'active' }
            : options.subscription;
        return Promise.resolve(
          sub === null
            ? []
            : [{ id: sub.id, organization_id: sub.organizationId, status: sub.status }],
        );
      }
      if (s.text.includes('MAX(delivery_seq)')) {
        return Promise.resolve(
          Object.entries(options.maxSeq ?? {}).map(([eventId, seq]) => ({
            event_id: eventId,
            event_occurred_at: (options.rows ?? []).find((r) => r.event_id === eventId)!
              .event_occurred_at,
            seq,
            replays: options.replays?.[eventId] ?? 0,
          })),
        );
      }
      if (s.text.includes('FROM webhook_deliveries d')) {
        const limit = s.values.at(-1) as number;
        return Promise.resolve((options.rows ?? []).slice(0, limit));
      }
      return Promise.resolve([]);
    },
    $executeRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.startsWith('INSERT INTO webhook_deliveries')) {
        return Promise.resolve((s.text.match(/'replay'/g) ?? []).length);
      }
      return Promise.resolve(1);
    },
    organization: {
      findUnique: () =>
        Promise.resolve(
          options.organization === undefined ? { id: 42n, status: 'active' } : options.organization,
        ),
    },
    organizationFeature: {
      findUnique: () =>
        Promise.resolve(
          options.feature === undefined
            ? { organizationId: 42n, featureKey: 'webhooks', enabled: true }
            : options.feature,
        ),
    },
  };
  const prisma = { $transaction: (fn: (t: typeof tx) => Promise<unknown>) => fn(tx) };
  const { metrics, registry } = testMetrics();
  const processor = new ReplayProcessor(prisma as never, {
    maxEvents: options.maxEvents ?? 10_000,
    maxPerDelivery: options.maxPerDelivery ?? 10,
    metrics,
    sink: () => undefined,
    logger: silentLogger,
    batchSize: options.batchSize ?? 3,
    now: () => NOW,
  });
  const update = () =>
    statements.filter((s) => s.text.startsWith('UPDATE webhook_replays')).at(-1)!;
  return { processor, statements, registry, update };
}

describe('ReplayProcessor (W12)', () => {
  it('a full batch inserts replay deliveries (max + 1) and advances the cursor', async () => {
    const rows = [original(1), original(2), original(3), original(4)];
    const h = harness({ rows, maxSeq: { [rows[0]!.event_id]: 0, [rows[1]!.event_id]: 2 } });
    expect(await h.processor.step(9n)).toBe('continued');
    const lock = h.statements.find((s) => s.text.includes('FROM webhook_replays'))!;
    expect(lock.text).toContain('FOR UPDATE SKIP LOCKED');
    // The subscription lock the api's single replay also takes, and a current read of the seqs.
    const subLock = h.statements.find((s) => s.text.includes('FROM webhook_subscriptions'))!;
    expect(subLock.text).toContain('FOR UPDATE');
    const seq = h.statements.find((s) => s.text.includes('MAX(delivery_seq)'))!;
    expect(seq.text).toContain('SUM(delivery_seq > 0) AS replays');
    expect(seq.text).toContain('FOR UPDATE');
    expect(h.statements.indexOf(subLock)).toBeLessThan(h.statements.indexOf(seq));
    const select = h.statements.find((s) => s.text.includes('FROM webhook_deliveries d'))!;
    expect(select.text).toContain('JOIN webhook_events e');
    expect(select.text).toContain('d.delivery_seq = 0');
    expect(select.text).toContain('ORDER BY d.event_occurred_at, d.id');
    const insert = h.statements.find((s) => s.text.startsWith('INSERT INTO webhook_deliveries'))!;
    expect(insert.text).toContain('ON DUPLICATE KEY UPDATE id = id');
    // delivery_seq: 0 + 1, 2 + 1, none yet → 1
    const seqs = insert.values.filter((v) => typeof v === 'number');
    expect(seqs).toEqual([1, 3, 1]);
    expect(insert.values.filter((v) => v === 9n)).toHaveLength(3); // replay_id
    const update = h.update();
    expect(update.text).toContain('matched_count = matched_count + ?');
    expect(update.values).toEqual(
      expect.arrayContaining(['running', rows[2]!.event_occurred_at, 3n, 3]),
    );
  });

  it('a short batch completes the replay', async () => {
    const h = harness({ rows: [original(1)] });
    expect(await h.processor.step(9n)).toBe('completed');
    expect(h.update().values).toContain('completed');
    expect(await h.registry.metrics()).toMatch(
      /webhook_replays_total\{[^}]*result="completed"[^}]*\} 1/,
    );
  });

  it('resumes after the stored cursor (keyset)', async () => {
    const h = harness({
      replay: replayRow({
        status: 'running',
        cursor_occurred_at: new Date('2026-11-12T00:00:02.000Z'),
        cursor_id: 2n,
      }),
      rows: [],
    });
    expect(await h.processor.step(9n)).toBe('completed');
    const select = h.statements.find((s) => s.text.includes('FROM webhook_deliveries d'))!;
    expect(select.text).toContain(
      'd.event_occurred_at > ? OR (d.event_occurred_at = ? AND d.id > ?)',
    );
  });

  it('stops at WEBHOOK_REPLAY_MAX_EVENTS: truncated when more matches exist', async () => {
    const atBound = harness({
      replay: replayRow({ status: 'running', matched_count: 5 }),
      rows: [original(9)],
      maxEvents: 5,
    });
    expect(await atBound.processor.step(9n)).toBe('truncated');
    expect(
      atBound.statements.some((s) => s.text.startsWith('INSERT INTO webhook_deliveries')),
    ).toBe(false);
    expect(atBound.update().values).toEqual(expect.arrayContaining(['completed', true]));
    const exact = harness({
      replay: replayRow({ status: 'running', matched_count: 5 }),
      rows: [],
      maxEvents: 5,
    });
    expect(await exact.processor.step(9n)).toBe('completed');
  });

  it('limits the batch to the remaining bound', async () => {
    const h = harness({
      replay: replayRow({ matched_count: 8 }),
      rows: [original(1), original(2), original(3)],
      maxEvents: 10,
    });
    expect(await h.processor.step(9n)).toBe('continued');
    const select = h.statements.find((s) => s.text.includes('FROM webhook_deliveries d'))!;
    expect(select.values.at(-1)).toBe(2);
  });

  it('fails when the subscription is no longer active, or the stored filter is invalid', async () => {
    const paused = harness({ subscription: { id: 501n, organizationId: 42n, status: 'paused' } });
    expect(await paused.processor.step(9n)).toBe('failed');
    expect(paused.update().values).toEqual(
      expect.arrayContaining(['failed', 'webhook_not_active']),
    );
    const invalid = harness({ replay: replayRow({ statuses: ['pending'] }) });
    expect(await invalid.processor.step(9n)).toBe('failed');
    expect(invalid.update().values).toContain('replay_invalid');
  });

  it('skips events that already have WEBHOOK_REPLAY_MAX_PER_DELIVERY replays (counted apart)', async () => {
    const rows = [original(1), original(2)];
    const h = harness({
      rows,
      maxSeq: { [rows[0]!.event_id]: 3, [rows[1]!.event_id]: 2 },
      replays: { [rows[0]!.event_id]: 3, [rows[1]!.event_id]: 2 },
      maxPerDelivery: 3,
    });
    expect(await h.processor.step(9n)).toBe('completed');
    const insert = h.statements.find((s) => s.text.startsWith('INSERT INTO webhook_deliveries'))!;
    expect(insert.values.filter((v) => typeof v === 'number')).toEqual([3]); // only event 2
    // matched 2, created 1
    expect(h.update().values).toEqual(expect.arrayContaining([2, 1]));
    expect(await h.registry.metrics()).toMatch(
      /webhook_replay_events_skipped_total\{[^}]*reason="replay_limit"[^}]*\} 1/,
    );
  });

  it.each([
    ['suspended', { id: 42n, status: 'suspended' }, undefined, 'organization_inactive'],
    ['deleted', { id: 42n, status: 'deleted' }, undefined, 'organization_inactive'],
    [
      'without the webhooks feature',
      undefined,
      { organizationId: 42n, featureKey: 'webhooks', enabled: false },
      'webhooks_not_enabled',
    ],
    ['with no feature row', undefined, null, 'webhooks_not_enabled'],
  ] as const)(
    'fails a replay of an organization %s without inserting anything',
    async (_label, organization, feature, code) => {
      const h = harness({
        rows: [original(1)],
        ...(organization !== undefined && { organization }),
        ...(feature !== undefined && { feature }),
      });
      expect(await h.processor.step(9n)).toBe('failed');
      expect(h.update().values).toEqual(expect.arrayContaining(['failed', code]));
      expect(h.statements.some((s) => s.text.startsWith('INSERT INTO webhook_deliveries'))).toBe(
        false,
      );
    },
  );

  it('skips a replay locked by another replica or already finished', async () => {
    expect(await harness({ replay: null }).processor.step(9n)).toBe('skipped');
    expect(await harness({ replay: replayRow({ status: 'completed' }) }).processor.step(9n)).toBe(
      'skipped',
    );
  });

  it('refuses original deliveries of another organization (echo check)', async () => {
    const h = harness({ rows: [original(1, 7n)] });
    await expect(h.processor.step(9n)).rejects.toThrow(/inconsistent/);
  });
});
