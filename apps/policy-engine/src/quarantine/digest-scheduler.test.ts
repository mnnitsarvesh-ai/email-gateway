import { createLogger } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { DigestScheduler } from './digest-scheduler';

const NOW = new Date('2026-11-12T12:00:00.000Z');

/**
 * `run()` fairness (step 5.3 Q20): the organizations a sweep examines come from a keyset cursor
 * over the organizations with open entries; `organization()` (one organization's admin alert
 * and digests) is replaced by a stub that records the calls and consumes a set budget.
 */
function setup(options: {
  orgs: bigint[];
  batchSize: number;
  maxUsersPerSweep: number;
  /** Digests each organization writes when it gets budget (default 0). */
  users?: Map<bigint, number>;
}) {
  const remaining = new Map(options.users ?? []);
  const groupBy = vi.fn(
    (args: {
      where: { AND?: Array<{ organizationId: { gt?: bigint; lte?: bigint } }> };
      take: number;
    }) => {
      let ids = [...options.orgs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      for (const c of args.where.AND ?? []) {
        const { gt, lte } = c.organizationId;
        if (gt !== undefined) ids = ids.filter((id) => id > gt);
        if (lte !== undefined) ids = ids.filter((id) => id <= lte);
      }
      return Promise.resolve(ids.slice(0, args.take).map((organizationId) => ({ organizationId })));
    },
  );
  const scheduler = new DigestScheduler({
    prisma: { quarantineMessage: { groupBy } } as never,
    settings: { resolve: vi.fn() },
    sink: vi.fn(),
    logger: createLogger({ service: 't', level: 'silent' }),
    maxUsersPerSweep: options.maxUsersPerSweep,
    batchSize: options.batchSize,
  });
  const calls: Array<{ org: bigint; budget: number }> = [];
  (scheduler as unknown as { organization: unknown }).organization = (
    org: bigint,
    _now: Date,
    budget: number,
  ) => {
    calls.push({ org, budget });
    const left = remaining.get(org) ?? 0;
    const done = Math.min(left, budget);
    remaining.set(org, left - done);
    return Promise.resolve(done);
  };
  const sweep = async () => {
    calls.length = 0;
    await scheduler.run(NOW);
    return calls.map((c) => [Number(c.org), c.budget]);
  };
  return { scheduler, sweep, remaining };
}

describe('DigestScheduler.run fairness (Q20)', () => {
  it('pages through more organizations than batchSize and wraps around to the lowest id', async () => {
    const s = setup({ orgs: [1n, 2n, 3n, 4n, 5n], batchSize: 2, maxUsersPerSweep: 100 });
    const seen: number[][] = [];
    for (let i = 0; i < 4; i += 1) seen.push((await s.sweep()).map(([org]) => org!));
    expect(seen).toEqual([
      [1, 2],
      [3, 4],
      [5, 1],
      [2, 3],
    ]);
  });

  it('every organization is examined at least once per ⌈n / batchSize⌉ sweeps', async () => {
    const orgs = Array.from({ length: 450 }, (_, i) => BigInt(i + 1));
    const s = setup({ orgs, batchSize: 200, maxUsersPerSweep: 5_000 });
    const seen = new Set<number>();
    for (let i = 0; i < 3; i += 1) for (const [org] of await s.sweep()) seen.add(org!);
    expect(seen.size).toBe(450);
  });

  it('a spent budget resumes at the cut-short organization; admin alerts still run for the rest', async () => {
    const s = setup({
      orgs: [1n, 2n, 3n, 4n],
      batchSize: 4,
      maxUsersPerSweep: 10,
      users: new Map([
        [1n, 4],
        [2n, 15],
        [3n, 3],
      ]),
    });
    // Sweep 1: org 1 writes 4, org 2 spends the rest (6) → orgs 3 and 4 get budget 0 (alerts only).
    expect(await s.sweep()).toEqual([
      [1, 10],
      [2, 6],
      [3, 0],
      [4, 0],
    ]);
    // Sweep 2 starts at org 2 (not at org 1): it finishes (9), org 3 gets the remainder.
    expect(await s.sweep()).toEqual([
      [2, 10],
      [3, 1],
      [4, 0],
      [1, 0],
    ]);
    // Sweep 3 resumes at org 3.
    expect((await s.sweep())[0]).toEqual([3, 10]);
    expect(s.remaining.get(3n)).toBe(0);
  });

  it('an empty page leaves the cursor at the start', async () => {
    const s = setup({ orgs: [], batchSize: 2, maxUsersPerSweep: 10 });
    expect(await s.sweep()).toEqual([]);
    expect(s.scheduler.nextCursor).toBeNull();
  });
});
