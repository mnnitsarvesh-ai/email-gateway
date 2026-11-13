import { describe, expect, it } from 'vitest';
import { InconsistentReadError } from '../shared/errors';
import { type SeenSql, sqlOf } from '../worker.test-support';
import { DeliveryClaimer, shuffle } from './claimer';
import { FakeCounterRedis } from './delivery.test-support';
import { InflightCounters, orgKey, subKey } from './inflight';

const NOW = new Date('2026-11-13T12:00:00.000Z');
const ORG = 42n;

const row = (id: number, sub: number, attempts = 0, org = ORG) => ({
  id: BigInt(id),
  event_occurred_at: new Date('2026-11-13T11:00:00.000Z'),
  public_id: `0193a1b2-0000-7000-8000-${String(id).padStart(12, '0')}`,
  subscription_id: BigInt(sub),
  organization_id: org,
  event_id: '0193a1b2-0000-8000-8000-000000000001',
  event_type: 'email.received',
  attempt_count: attempts,
  first_attempt_at: attempts > 0 ? new Date('2026-11-13T11:30:00.000Z') : null,
});

const sub = (id: number, status = 'active', maxConcurrency: number | null = null) => ({
  id: BigInt(id),
  organizationId: ORG,
  publicId: `01890a5d-ac96-774b-bcce-${String(id).padStart(12, '0')}`,
  url: 'https://hooks.receiver.test/a',
  status,
  maxConcurrency,
  secretVersion: 1,
  secretCiphertext: 'v1.k1.a.b.c',
  previousSecretCiphertext: null,
  previousSecretExpiresAt: null,
});

function harness(options: {
  rows: ReturnType<typeof row>[];
  subs: ReturnType<typeof sub>[];
  cas?: (id: bigint) => number;
  failAfterClaim?: boolean;
  maxPerOrganization?: number;
  ratePerMinute?: number;
  organization?: { id: bigint; status: string } | null;
  feature?: { organizationId: bigint; featureKey: string; enabled: boolean } | null;
  dueOrganizations?: (sql: SeenSql) => bigint[];
}) {
  const statements: SeenSql[] = [];
  const redis = new FakeCounterRedis();
  /** Rows that left the due range (claimed, cancelled or parked): a tiny stateful table. */
  const gone = new Set<bigint>();
  const tx = {
    $queryRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      const limit = s.values.at(-1) as number;
      return Promise.resolve(options.rows.filter((r) => !gone.has(r.id)).slice(0, limit));
    },
    $executeRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      const ids = s.values.filter((v): v is bigint => typeof v === 'bigint');
      if (s.text.includes('attempt_count = attempt_count + 1')) {
        const n = options.cas ? options.cas(ids[0]!) : 1;
        if (n === 1) gone.add(ids[0]!);
        return Promise.resolve(n);
      }
      for (const id of ids) gone.add(id);
      return Promise.resolve(Math.max(1, ids.length));
    },
    webhookSubscription: {
      findMany: ({ where }: { where: { id: { in: bigint[] } } }) =>
        Promise.resolve(options.subs.filter((x) => where.id.in.includes(x.id))),
    },
    organization: {
      findUnique: () =>
        Promise.resolve(
          options.organization === undefined ? { id: ORG, status: 'active' } : options.organization,
        ),
    },
    organizationFeature: {
      findUnique: () =>
        Promise.resolve(
          options.feature === undefined
            ? { organizationId: ORG, featureKey: 'webhooks', enabled: true }
            : options.feature,
        ),
    },
  };
  const prisma = {
    $transaction: async (fn: (t: typeof tx) => Promise<unknown>) => {
      const result = await fn(tx);
      if (options.failAfterClaim)
        throw Object.assign(new Error('commit failed'), { code: 'P2034' });
      return result;
    },
    $queryRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      const ids = options.dueOrganizations ? options.dueOrganizations(s) : [7n, 42n];
      return Promise.resolve(ids.map((organization_id) => ({ organization_id })));
    },
  };
  const sinks: string[] = [];
  const counters = new InflightCounters(
    redis,
    {
      leaseMs: 70_000,
      maxPerOrganization: options.maxPerOrganization ?? 16,
      ratePerMinute: options.ratePerMinute ?? 600,
    },
    () => NOW.getTime(),
  );
  const claimer = new DeliveryClaimer(prisma as never, counters, {
    totalTimeoutMs: 10_000,
    maxPerSubscription: 4,
    sink: (read) => void sinks.push(read),
  });
  return { claimer, statements, redis, sinks, gone };
}

describe('DeliveryClaimer (W8 steps 1–2)', () => {
  it('finds the organizations with due work through the status/org/next index', async () => {
    const h = harness({ rows: [], subs: [] });
    expect(await h.claimer.dueOrganizations(NOW)).toEqual([7n, 42n]);
    const sql = h.statements[0]!.text;
    expect(sql).toContain("WHERE status = 'pending'");
    expect(sql).toContain('GROUP BY organization_id HAVING MIN(next_attempt_at) <= ?');
    expect(sql).toContain('ORDER BY organization_id');
    expect(sql).toContain('LIMIT ?');
  });

  it('rotates through more than 200 due organizations (cursor, wrap-around)', async () => {
    const all = Array.from({ length: 450 }, (_, i) => BigInt(i + 1));
    const h = harness({
      rows: [],
      subs: [],
      dueOrganizations: (s) => {
        const limit = s.values.at(-1) as number;
        const bounds = s.values.filter((v): v is bigint => typeof v === 'bigint');
        let list = all;
        if (s.text.includes('organization_id > ?')) list = list.filter((id) => id > bounds[0]!);
        if (s.text.includes('organization_id <= ?')) list = list.filter((id) => id <= bounds[0]!);
        return list.slice(0, limit);
      },
    });
    const seen = new Set<bigint>();
    const ticks: bigint[][] = [];
    for (let i = 0; i < 3; i += 1) {
      const due = await h.claimer.dueOrganizations(NOW);
      expect(due.length).toBeLessThanOrEqual(200);
      ticks.push(due);
      for (const id of due) seen.add(id);
    }
    expect(seen.size).toBe(450); // every organization within ⌈450 / 200⌉ ticks
    expect(ticks[0]![0]).toBe(1n);
    expect(ticks[1]![0]).toBe(201n);
    // Third tick: 401–450, then wraps around to the start.
    expect(ticks[2]!.slice(0, 50)).toEqual(all.slice(400));
    expect(ticks[2]![50]).toBe(1n);
    expect(ticks[2]).toHaveLength(200);
  });

  it('claims due rows with a lease and counts the attempt (FOR UPDATE SKIP LOCKED)', async () => {
    const h = harness({ rows: [row(1, 10), row(2, 10, 2)], subs: [sub(10)] });
    const report = await h.claimer.claim(ORG, 8, NOW);
    expect(report.claimed.map((c) => [c.id, c.attemptNo])).toEqual([
      [1n, 1],
      [2n, 3],
    ]);
    expect(report.claimed[0]!.firstAttemptAt).toEqual(NOW);
    expect(report.claimed[1]!.firstAttemptAt).toEqual(new Date('2026-11-13T11:30:00.000Z'));
    const select = h.statements.find((s) => s.text.startsWith('SELECT id, event_occurred_at'))!;
    expect(select.text).toContain('FOR UPDATE SKIP LOCKED');
    expect(select.text).toContain('ORDER BY next_attempt_at');
    const lease = h.statements.find((s) => s.text.includes('attempt_count = attempt_count + 1'))!;
    expect(lease.values[2]).toEqual(new Date(NOW.getTime() + 70_000));
    expect(h.redis.size(orgKey(ORG))).toBe(2);
    expect(h.redis.size(subKey(10n))).toBe(2);
  });

  it('parks paused subscriptions and cancels disabled, deleted and missing ones', async () => {
    const h = harness({
      rows: [row(1, 10), row(2, 11), row(3, 12), row(4, 13)],
      subs: [sub(10, 'paused'), sub(11, 'disabled'), sub(12, 'deleted')],
    });
    const report = await h.claimer.claim(ORG, 8, NOW);
    expect(report.claimed).toEqual([]);
    expect(report.paused).toBe(1);
    const park = h.statements.find((s) =>
      s.text.startsWith('UPDATE webhook_deliveries SET next_attempt_at = NULL'),
    )!;
    expect(park.text).toContain("WHERE status = 'pending'");
    // MySQL rejects DATETIME parameters in a multi-tuple row constructor (error 1292).
    expect(park.text).toContain('(id = ? AND event_occurred_at = ?)');
    expect(park.values).toContain(1n);
    expect(report.cancelled.map((c) => c.reason)).toEqual([
      'subscription_disabled',
      'subscription_deleted',
      'subscription_missing',
    ]);
    const cancels = h.statements.filter((s) => s.text.includes("SET status = 'cancelled'"));
    expect(cancels).toHaveLength(3);
    expect(cancels.every((s) => s.text.includes("AND status = 'pending'"))).toBe(true);
  });

  it("a paused subscription's backlog of more than 200 due rows never blocks an active one", async () => {
    const paused = Array.from({ length: 450 }, (_, i) => row(i + 1, 10));
    const h = harness({ rows: [...paused, row(1000, 11)], subs: [sub(10, 'paused'), sub(11)] });
    const claimed: bigint[] = [];
    let ticks = 0;
    while (claimed.length === 0 && ticks < 100) {
      ticks += 1;
      claimed.push(...(await h.claimer.claim(ORG, 8, NOW)).claimed.map((c) => c.id));
    }
    expect(claimed).toEqual([1000n]);
    // Each claim parks the rows it read (2 × 8): the backlog leaves the due range for good (the
    // api parks it at pause time; this covers rows that were in flight then).
    expect(ticks).toBe(Math.ceil(451 / 16)); // the last window holds the active row
    expect(paused.every((r) => h.gone.has(r.id))).toBe(true);
  });

  it.each([
    ['suspended', { id: ORG, status: 'suspended' }, undefined, 'organization_inactive'],
    [
      'pending deletion',
      { id: ORG, status: 'pending_deletion' },
      undefined,
      'organization_inactive',
    ],
    ['missing', null, undefined, 'organization_inactive'],
    [
      'feature revoked',
      undefined,
      { organizationId: ORG, featureKey: 'webhooks', enabled: false },
      'webhooks_not_enabled',
    ],
    ['feature absent', undefined, null, 'webhooks_not_enabled'],
  ] as const)(
    'sends nothing for an organization that is %s: its due rows are cancelled',
    async (_label, organization, feature, reason) => {
      const h = harness({
        rows: [row(1, 10), row(2, 10, 3)],
        subs: [sub(10)],
        ...(organization !== undefined && { organization }),
        ...(feature !== undefined && { feature }),
      });
      const report = await h.claimer.claim(ORG, 8, NOW);
      expect(report.claimed).toEqual([]);
      expect(report.cancelled).toEqual([{ reason }, { reason }]);
      const cancel = h.statements.find((s) => s.text.includes("SET status = 'cancelled'"))!;
      expect(cancel.values).toContain(reason);
      expect(cancel.text).toContain("WHERE status = 'pending'");
      expect(h.redis.size(orgKey(ORG))).toBe(0); // no reservation taken
    },
  );

  it('respects the per-subscription cap (max_concurrency overrides the default)', async () => {
    const h = harness({
      rows: [row(1, 10), row(2, 10), row(3, 11), row(4, 11)],
      subs: [sub(10, 'active', 1), sub(11)],
    });
    const report = await h.claimer.claim(ORG, 8, NOW);
    expect(report.claimed.map((c) => c.id)).toEqual([1n, 3n, 4n]);
    expect(report.limited).toEqual(['subscription']);
  });

  it('stops at the organization cap and the per-minute rate', async () => {
    const org = harness({
      rows: [row(1, 10), row(2, 11), row(3, 12)],
      subs: [sub(10), sub(11), sub(12)],
      maxPerOrganization: 2,
    });
    const r1 = await org.claimer.claim(ORG, 8, NOW);
    expect(r1.claimed).toHaveLength(2);
    expect(r1.limited).toEqual(['organization']);
    const rate = harness({ rows: [row(1, 10), row(2, 10)], subs: [sub(10)], ratePerMinute: 1 });
    const r2 = await rate.claimer.claim(ORG, 8, NOW);
    expect(r2.claimed).toHaveLength(1);
    expect(r2.limited).toEqual(['subscription_rate']);
  });

  it('claims at most `limit` rows', async () => {
    const h = harness({
      rows: [row(1, 10), row(2, 11), row(3, 12)],
      subs: [sub(10), sub(11), sub(12)],
    });
    expect((await h.claimer.claim(ORG, 2, NOW)).claimed).toHaveLength(2);
  });

  it('a lost lease CAS gives the reservation back and is counted', async () => {
    const h = harness({
      rows: [row(1, 10), row(2, 10)],
      subs: [sub(10)],
      cas: (id) => (id === 1n ? 0 : 1),
    });
    const report = await h.claimer.claim(ORG, 8, NOW);
    expect(report.claimed.map((c) => c.id)).toEqual([2n]);
    expect(report.lost).toBe(1);
    expect(h.sinks).toEqual(['claim']);
    expect(h.redis.size(subKey(10n))).toBe(1);
  });

  it('a rolled-back claim gives every reservation back', async () => {
    const h = harness({
      rows: [row(1, 10), row(2, 11)],
      subs: [sub(10), sub(11)],
      failAfterClaim: true,
    });
    await expect(h.claimer.claim(ORG, 8, NOW)).rejects.toThrow('commit failed');
    expect(h.redis.size(orgKey(ORG))).toBe(0);
    expect(h.redis.size(subKey(10n))).toBe(0);
  });

  it('refuses rows of another organization (echo check)', async () => {
    const h = harness({ rows: [row(1, 10, 0, 7n)], subs: [sub(10)] });
    await expect(h.claimer.claim(ORG, 8, NOW)).rejects.toBeInstanceOf(InconsistentReadError);
  });
});

describe('shuffle (fairness)', () => {
  it('is a permutation and puts every organization first sometimes', () => {
    const firsts = new Set<number>();
    for (let i = 0; i < 200; i += 1) {
      const out = shuffle([1, 2, 3, 4]);
      expect([...out].sort()).toEqual([1, 2, 3, 4]);
      firsts.add(out[0]!);
    }
    expect(firsts.size).toBe(4);
  });
});
