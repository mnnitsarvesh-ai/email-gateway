import { Writable } from 'node:stream';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import type { AdvisoryLocks } from './advisory-locks';
import { type EventHandler, processOnceHandler } from './event-feed';
import { OutboxPoller, type OutboxPollerOptions, type PayloadSchema } from './outbox-poller';

interface Row {
  id: bigint;
  created_at: Date;
  event_id: string;
  organization_id: bigint;
  event_type: string;
  correlation_id: string;
  payload: unknown;
}

type Payload = { n: number };

/** A minimal zod-compatible schema of `{ n: number }` (common does not depend on zod). */
const schema = {
  parse(value: unknown): Payload {
    const n = (value as { n?: unknown } | null)?.n;
    if (typeof n !== 'number') {
      throw Object.assign(new Error('invalid'), {
        issues: [{ path: ['n'], message: 'Expected number' }],
      });
    }
    return { n };
  },
} as unknown as PayloadSchema<Payload>;

const NOW = new Date('2026-11-03T12:00:00Z');
const old = new Date(NOW.getTime() - 300_000);
const fresh = new Date(NOW.getTime() - 10_000);
const uuid = (n: number) => `0190f0f0-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const row = (
  id: number,
  createdAt: Date,
  payload: unknown = { n: id },
  type = 'test.event.v1',
): Row => ({
  id: BigInt(id),
  created_at: createdAt,
  event_id: uuid(id),
  organization_id: 7n,
  event_type: type,
  correlation_id: `corr-${id}-xxxxxx`,
  payload,
});

/** A fake writer: message_outbox rows, stream_cursors and the processOnce ledger. */
function fakePrisma(rows: Row[], initialCursors: [string, bigint | null][] = []) {
  const cursors = new Map<string, bigint | null>(initialCursors);
  const ledger = new Set<string>();
  const queries: { sql: string; values: unknown[] }[] = [];
  const prisma = {
    $queryRaw(strings: TemplateStringsArray, ...values: unknown[]) {
      const sql = strings.join('?');
      if (sql.includes('MAX(id)')) {
        const max = rows.reduce<bigint | null>((m, r) => (m === null || r.id > m ? r.id : m), null);
        return Promise.resolve([{ position: max }]);
      }
      if (sql.includes('MIN(id)')) {
        const min = rows.reduce<bigint | null>((m, r) => (m === null || r.id < m ? r.id : m), null);
        return Promise.resolve([{ position: min }]);
      }
      queries.push({ sql, values });
      if (sql.includes('created_at <= ?')) {
        // The lag probe of a shard this process does not hold.
        const [after, type, count, index, horizon] = values as [
          bigint,
          string,
          number,
          number,
          Date,
        ];
        const first = rows
          .filter((r) => r.id > after && r.event_type === type)
          .filter((r) => Number(r.id % BigInt(count)) === index && r.created_at <= horizon)
          .sort((x, y) => (x.id < y.id ? -1 : 1))[0];
        return Promise.resolve(first ? [{ created_at: first.created_at }] : []);
      }
      const sharded = sql.includes('MOD(id, ?) = ?');
      const [after, type] = values as [bigint, string];
      const [count, index, limit] = sharded
        ? (values.slice(2) as [number, number, number])
        : [1, 0, values[2] as number];
      return Promise.resolve(
        rows
          .filter((r) => r.id > after && r.event_type === type)
          .filter((r) => Number(r.id % BigInt(count)) === index)
          .sort((a, b) => (a.id < b.id ? -1 : 1))
          .slice(0, limit),
      );
    },
    streamCursor: {
      findUnique: ({ where }: { where: { name: string } }) =>
        Promise.resolve(cursors.has(where.name) ? { positionId: cursors.get(where.name) } : null),
      findUniqueOrThrow: ({ where }: { where: { name: string } }) =>
        Promise.resolve({ positionId: cursors.get(where.name) ?? null }),
      findMany: ({ where }: { where: { name: { startsWith: string } } }) =>
        Promise.resolve(
          [...cursors]
            .filter(([name, p]) => name.startsWith(where.name.startsWith) && p !== null)
            .map(([name, positionId]) => ({ name, positionId })),
        ),
      create: ({ data }: { data: { name: string; positionId: bigint } }) => {
        cursors.set(data.name, data.positionId);
        return Promise.resolve(data);
      },
      updateMany: () => Promise.resolve({ count: 0 }),
      update: ({ where, data }: { where: { name: string }; data: { positionId: bigint } }) => {
        cursors.set(where.name, data.positionId);
        return Promise.resolve(data);
      },
    },
    transactions: [] as unknown[],
    $transaction<T>(fn: (tx: unknown) => Promise<T>, opts?: unknown) {
      prisma.transactions.push(opts);
      const pending: string[] = [];
      const tx = {
        messageIdempotency: {
          create: ({ data }: { data: { consumer: string; eventId: string } }) => {
            const key = `${data.consumer}|${data.eventId}`;
            if (ledger.has(key)) {
              return Promise.reject(
                new Prisma.PrismaClientKnownRequestError('duplicate', {
                  code: 'P2002',
                  clientVersion: 'test',
                }),
              );
            }
            pending.push(key);
            return Promise.resolve(data);
          },
        },
      };
      return fn(tx).then((result) => {
        for (const key of pending) ledger.add(key);
        return result;
      });
    },
  };
  return { prisma: prisma as unknown as PrismaClient, cursors, ledger, queries, raw: prisma };
}

const locks = (held = true) =>
  ({
    ensure: () => Promise.resolve(held),
    release: () => Promise.resolve(),
  }) as unknown as AdvisoryLocks;

/** Fake lock set shared by several pollers of one process (another holder per name optional). */
function lockSet(heldElsewhere: Set<string> = new Set()) {
  const held = new Set<string>();
  const ensured: string[] = [];
  const set = {
    ensured,
    held,
    ensure: (name: string) => {
      ensured.push(name);
      if (heldElsewhere.has(name)) return Promise.resolve(false);
      held.add(name);
      return Promise.resolve(true);
    },
    release: (name: string) => (held.delete(name), Promise.resolve()),
    isHeld: (name: string) => held.has(name),
    heldCount: (prefix: string) => [...held].filter((n) => n.startsWith(prefix)).length,
  };
  return set;
}

const silent = createLogger({ service: 'test', level: 'silent' });

function fakeMetrics() {
  const lag = new Map<string, number>();
  const invalid = new Map<string, number>();
  return {
    lag,
    invalid,
    pollLag: (consumer: string, seconds: number) => void lag.set(consumer, seconds),
    invalidRow: (consumer: string) => void invalid.set(consumer, (invalid.get(consumer) ?? 0) + 1),
  };
}

function poller(
  prisma: PrismaClient,
  options: Partial<OutboxPollerOptions<Payload>> & { held?: boolean } = {},
) {
  const m = fakeMetrics();
  const { held, ...rest } = options;
  return {
    metrics: m,
    poller: new OutboxPoller<Payload>({
      prisma,
      locks: locks(held ?? true),
      logger: silent,
      metrics: { pollLag: m.pollLag, invalid: m.invalidRow },
      consumer: 'delivery-worker.test',
      eventType: 'test.event.v1',
      schema,
      initialPosition: 'oldest',
      pollIntervalMs: 1000,
      safetyLagMs: 120_000,
      batchSize: 500,
      lockPrefix: 'dw',
      now: () => NOW,
      ...rest,
    }),
  };
}

const recorder = () => {
  const seen: number[] = [];
  const handler: EventHandler<Payload> = (event) => {
    seen.push(event.payload.n);
    return Promise.resolve('handled');
  };
  return { seen, handler };
};

/** A handler over the fake ledger (the step 2.3 shape). */
const ledgerHandler = (prisma: PrismaClient, seen: number[]) =>
  processOnceHandler<Payload>(
    prisma,
    'delivery-worker.test',
    (event) => (seen.push(event.payload.n), Promise.resolve()),
    { txTimeoutMs: 5000 },
  );

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('OutboxPoller (step 2.3 R6 semantics)', () => {
  it('starts an approvals consumer at the oldest retained row and handles rows in id order', async () => {
    const db = fakePrisma([row(5, old), row(6, old), row(7, old, { n: 7 }, 'other.event.v1')]);
    const { poller: p } = poller(db.prisma);
    const { seen, handler } = recorder();
    const report = await p.pollOnce(handler);
    expect(seen).toEqual([5, 6]);
    expect(report).toMatchObject({ active: true, handled: 2, cursor: 6n });
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(6n);
    expect(p.lockName).toBe('dw:outbox:delivery-worker.test');
    expect(db.queries[0]?.sql).not.toContain('MOD(');
  });

  it('starts a pass-through consumer at MAX(id) (never replays old mail)', async () => {
    const db = fakePrisma([row(5, old), row(6, old)]);
    const { poller: p } = poller(db.prisma, { initialPosition: 'latest' });
    const { seen, handler } = recorder();
    await p.pollOnce(handler);
    expect(seen).toEqual([]);
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(6n);
  });

  it('keeps the cursor below rows newer than the safety lag and still handles an out-of-order commit', async () => {
    const rows = [row(1, old), row(3, fresh)];
    const db = fakePrisma(rows);
    const { poller: p } = poller(db.prisma);
    const { seen, handler } = recorder();
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 3]);
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(1n);
    // id 2 commits late (allocated before 3, visible after it): still inside the lag window.
    rows.push(row(2, fresh));
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 3, 2]); // 3 is not handled twice (recent set), 2 is not lost
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(1n);
  });

  it('skips a duplicate through the processOnce ledger after a restart', async () => {
    const db = fakePrisma([row(1, fresh)]);
    const first: number[] = [];
    await poller(db.prisma).poller.pollOnce(ledgerHandler(db.prisma, first));
    const second: number[] = [];
    const report = await poller(db.prisma).poller.pollOnce(ledgerHandler(db.prisma, second));
    expect(first).toEqual([1]);
    expect(second).toEqual([]);
    expect(report.duplicates).toBe(1);
  });

  it('logs, counts and skips invalid rows (they can never become valid)', async () => {
    const db = fakePrisma([
      row(1, old, { n: 'not a number' }),
      row(2, old, '{"n":2}'),
      row(3, old, 'not json'),
    ]);
    const { poller: p, metrics } = poller(db.prisma);
    const { seen, handler } = recorder();
    const report = await p.pollOnce(handler);
    expect(seen).toEqual([2]);
    expect(report).toMatchObject({ invalid: 2, handled: 1, cursor: 3n });
    expect(metrics.invalid.get('delivery-worker.test')).toBe(2);
  });

  it('a failing handler holds the cursor (never skipped) without blocking later rows', async () => {
    const db = fakePrisma([row(1, old), row(2, old), row(3, old)]);
    const { poller: p, metrics } = poller(db.prisma);
    const seen: number[] = [];
    let fail = true;
    const handler: EventHandler<Payload> = (event) => {
      if (event.payload.n === 2 && fail) return Promise.reject(new Error('db down'));
      seen.push(event.payload.n);
      return Promise.resolve('handled');
    };
    const report = await p.pollOnce(handler);
    expect(report).toMatchObject({ failed: 1, handled: 2, cursor: 1n });
    expect(seen).toEqual([1, 3]);
    expect(metrics.lag.get('delivery-worker.test')).toBe(300);
    fail = false;
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 3, 2]);
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(3n);
    expect(metrics.lag.get('delivery-worker.test')).toBe(0);
  });

  it('pages through more rows than one batch inside the lag window', async () => {
    const db = fakePrisma(Array.from({ length: 7 }, (_, i) => row(i + 1, fresh)));
    const { poller: p } = poller(db.prisma, { batchSize: 3 });
    const { seen, handler } = recorder();
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 2, 3]);
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 2, 3, 4, 5, 6]);
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('never starts more than batchSize new rows in one poll', async () => {
    // 2 rows already handled (recent), then 4 new ones: a page of 3 holds 1 recent + 2 new.
    const rows = [row(1, fresh), row(2, fresh)];
    const db = fakePrisma(rows);
    const { poller: p } = poller(db.prisma, { batchSize: 3 });
    const { seen, handler } = recorder();
    await p.pollOnce(handler);
    rows.push(row(3, fresh), row(4, fresh), row(5, fresh), row(6, fresh));
    const report = await p.pollOnce(handler);
    expect(report.handled).toBe(3);
    expect(seen).toEqual([1, 2, 3, 4, 5]);
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('idles without the consumer lock', async () => {
    const db = fakePrisma([row(1, old)]);
    const { poller: p } = poller(db.prisma, { held: false });
    const { seen, handler } = recorder();
    expect((await p.pollOnce(handler)).active).toBe(false);
    expect(seen).toEqual([]);
    expect(db.queries).toEqual([]);
  });

  it('logs a handler failure with ids, class and code only (no message, no error object)', async () => {
    const lines: string[] = [];
    const destination = new Writable({
      write(chunk: Buffer, _enc, done) {
        lines.push(chunk.toString());
        done();
      },
    });
    const logger = createLogger({ service: 'test', level: 'info', destination });
    const db = fakePrisma([row(1, old)]);
    const { poller: p } = poller(db.prisma, { logger });
    const secret = 'Subject: MARKER-7f3a quoted by a parser';
    await p.pollOnce(() =>
      Promise.reject(Object.assign(new TypeError(secret), { code: 'EPARSE', stack: secret })),
    );
    const failure = lines
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .find((l) => {
        return l.message === 'outbox event handler failed; retried on a later poll';
      });
    expect(failure).toMatchObject({
      outboxId: '1',
      eventId: uuid(1),
      errName: 'TypeError',
      errCode: 'EPARSE',
    });
    expect(failure).not.toHaveProperty('err');
    expect(lines.join('\n')).not.toContain('MARKER-7f3a');
  });

  it('validates the lock name length and the options', () => {
    const db = fakePrisma([]);
    expect(() => poller(db.prisma, { consumer: 'c'.repeat(54) })).not.toThrow(); // 10 + 54 = 64
    expect(() => poller(db.prisma, { consumer: 'c'.repeat(55) })).toThrow('at most 64');
    expect(() =>
      poller(db.prisma, { consumer: 'c'.repeat(50), shard: { index: 0, count: 16 } }),
    ).toThrow('at most 64');
    expect(() => poller(db.prisma, { concurrency: 0 })).toThrow('concurrency');
    expect(() => poller(db.prisma, { shard: { index: 2, count: 2 } })).toThrow('shard');
    expect(() => poller(db.prisma, { failureBackoff: { baseMs: 10, maxMs: 5 } })).toThrow(
      'failureBackoff',
    );
    expect(() => poller(db.prisma, { consumer: 'a#b' })).toThrow('"#"');
  });
});

describe('OutboxPoller concurrency (step 3.1 M2)', () => {
  /** Completes rows in reverse order of start: the slowest is the first row. */
  const outOfOrder = (seen: number[], fail: Set<number> = new Set()): EventHandler<Payload> => {
    let inFlight = 0;
    return async (event) => {
      inFlight += 1;
      const maxInFlight = inFlight;
      await delay(5 * (10 - event.payload.n));
      inFlight -= 1;
      if (fail.has(event.payload.n)) throw new Error(`fail ${maxInFlight}`);
      seen.push(event.payload.n);
      return 'handled';
    };
  };

  it('completing out of order yields the same cursor and report as sequential handling', async () => {
    const make = () => [
      row(1, old),
      row(2, old),
      row(3, old, { n: 'bad' }),
      row(4, old),
      row(5, fresh),
      row(6, old),
    ];
    const sequentialDb = fakePrisma(make());
    const sequential = await poller(sequentialDb.prisma).poller.pollOnce(outOfOrder([]));
    const concurrentDb = fakePrisma(make());
    const seen: number[] = [];
    const concurrent = await poller(concurrentDb.prisma, { concurrency: 4 }).poller.pollOnce(
      outOfOrder(seen),
    );
    expect(seen).not.toEqual([1, 2, 4, 5, 6]); // really completed out of order
    expect(seen.sort()).toEqual([1, 2, 4, 5, 6]);
    expect(concurrent).toEqual(sequential);
    expect(concurrent).toMatchObject({ handled: 5, invalid: 1, cursor: 4n });
  });

  it('runs at most `concurrency` handlers at a time', async () => {
    const db = fakePrisma(Array.from({ length: 9 }, (_, i) => row(i + 1, old)));
    let inFlight = 0;
    let peak = 0;
    const handler: EventHandler<Payload> = async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await delay(5);
      inFlight -= 1;
      return 'handled';
    };
    const report = await poller(db.prisma, { concurrency: 3 }).poller.pollOnce(handler);
    expect(peak).toBe(3);
    expect(report).toMatchObject({ handled: 9, cursor: 9n });
  });

  it('a failing row in a concurrent page freezes the cursor, later rows are still handled', async () => {
    const db = fakePrisma([row(1, old), row(2, old), row(3, old), row(4, old)]);
    const { poller: p, metrics } = poller(db.prisma, { concurrency: 4 });
    const seen: number[] = [];
    const report = await p.pollOnce(outOfOrder(seen, new Set([2])));
    expect(report).toMatchObject({ handled: 3, failed: 1, cursor: 1n });
    expect(seen.sort()).toEqual([1, 3, 4]);
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(1n);
    expect(metrics.lag.get('delivery-worker.test')).toBe(300);
    // Only the failed row is redelivered; then the cursor passes all four.
    const again: number[] = [];
    const next = await p.pollOnce(outOfOrder(again));
    expect(again).toEqual([2]);
    expect(next).toMatchObject({ handled: 1, cursor: 4n });
  });
});

describe('OutboxPoller sharding (step 3.1 M2)', () => {
  it('adds the MOD filter and names cursor and lock per shard', async () => {
    const db = fakePrisma(Array.from({ length: 6 }, (_, i) => row(i + 1, old)));
    const { poller: p } = poller(db.prisma, {
      consumer: 'email-worker.mime-parser',
      lockPrefix: 'ew',
      shard: { index: 1, count: 3 },
    });
    const { seen, handler } = recorder();
    const report = await p.pollOnce(handler);
    expect(seen).toEqual([1, 4]);
    expect(report.cursor).toBe(4n);
    expect(db.queries[0]?.sql).toContain('AND MOD(id, ?) = ?');
    expect(db.queries[0]?.values.slice(2, 4)).toEqual([3, 1]);
    expect(p.cursorName).toBe('outbox:email-worker.mime-parser#1/3');
    expect(p.lockName).toBe('ew:outbox:email-worker.mime-parser#1/3');
    expect(db.cursors.get('outbox:email-worker.mime-parser#1/3')).toBe(4n);
  });

  it('starts a new shard cursor at the minimum of the consumer’s cursors of other shard counts', async () => {
    const db = fakePrisma(
      [row(10, old)],
      [
        ['outbox:c', 40n],
        ['outbox:c#0/2', 25n],
        ['outbox:c#1/2', 31n],
        ['outbox:c#1/2-stale', null],
        ['outbox:c#0/4', 2n], // a sibling of the same count: other residues, not a lower bound
        ['outbox:c.other', 3n], // another consumer
        ['outbox:cc#0/2', 1n], // another consumer
      ],
    );
    const { poller: p } = poller(db.prisma, {
      consumer: 'c',
      initialPosition: 'latest',
      shard: { index: 3, count: 4 },
    });
    await p.pollOnce(recorder().handler);
    expect(db.cursors.get('outbox:c#3/4')).toBe(25n);
  });

  it('uses the initial position when the consumer has no cursor yet', async () => {
    const db = fakePrisma([row(10, old), row(11, old)], [['outbox:other#0/2', 1n]]);
    const { poller: p } = poller(db.prisma, {
      consumer: 'c',
      initialPosition: 'latest',
      shard: { index: 0, count: 2 },
    });
    await p.pollOnce(recorder().handler);
    expect(db.cursors.get('outbox:c#0/2')).toBe(11n);
  });

  it('an unsharded cursor created after sharding starts at the minimum shard cursor', async () => {
    const db = fakePrisma(
      [row(50, old)],
      [
        ['outbox:c#0/2', 20n],
        ['outbox:c#1/2', 30n],
      ],
    );
    const { poller: p } = poller(db.prisma, { consumer: 'c', initialPosition: 'latest' });
    const { seen, handler } = recorder();
    await p.pollOnce(handler);
    expect(seen).toEqual([50]); // re-read, never skipped
    expect(db.cursors.get('outbox:c')).toBe(50n);
  });

  it('shard pollers cover every row once and maxHeldLocks spreads shards over replicas', async () => {
    const db = fakePrisma(Array.from({ length: 8 }, (_, i) => row(i + 1, old)));
    const replicaA = lockSet();
    const m = fakeMetrics();
    const shards = 4;
    // One poller per MOD(id, n) residue, all with the same lock connection of the replica.
    const replica = (locksOfReplica: ReturnType<typeof lockSet>) =>
      Array.from(
        { length: shards },
        (_, index) =>
          new OutboxPoller<Payload>({
            prisma: db.prisma,
            locks: locksOfReplica as unknown as AdvisoryLocks,
            logger: silent,
            metrics: { pollLag: m.pollLag, invalid: m.invalidRow },
            consumer: 'c',
            eventType: 'test.event.v1',
            schema,
            initialPosition: 'oldest',
            pollIntervalMs: 1000,
            safetyLagMs: 0,
            batchSize: 100,
            lockPrefix: 'ew',
            maxHeldLocks: 2,
            shard: { index, count: shards },
            now: () => NOW,
          }),
      );
    const a = replica(replicaA);
    const seenA: number[] = [];
    const handlerA = ledgerHandler(db.prisma, seenA);
    const reportsA = await Promise.all(a.map((p) => p.pollOnce(handlerA)));
    // Pollers race for locks; exactly two shards are active on replica A.
    expect(reportsA.filter((r) => r.active)).toHaveLength(2);
    expect(replicaA.heldCount('ew:outbox:c#')).toBe(2);

    const replicaB = lockSet(new Set(replicaA.held));
    const b = replica(replicaB);
    const seenB: number[] = [];
    const reportsB = await Promise.all(b.map((p) => p.pollOnce(ledgerHandler(db.prisma, seenB))));
    expect(reportsB.filter((r) => r.active)).toHaveLength(2);
    expect([...seenA, ...seenB].sort()).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(new Set([...replicaA.held, ...replicaB.held]).size).toBe(4);
    // A third poll on A does not try to take another shard while it holds two.
    replicaA.ensured.length = 0;
    await Promise.all(a.map((p) => p.pollOnce(handlerA)));
    expect(replicaA.ensured.sort()).toEqual([...replicaA.held].sort());
    expect(db.ledger.size).toBe(8);
  });
});

describe('OutboxPoller lag of a shard this process does not hold', () => {
  const shardPoller = (
    db: ReturnType<typeof fakePrisma>,
    lockState: ReturnType<typeof lockSet>,
    now: () => Date = () => NOW,
  ) => {
    const m = fakeMetrics();
    const p = new OutboxPoller<Payload>({
      prisma: db.prisma,
      locks: lockState as unknown as AdvisoryLocks,
      logger: silent,
      metrics: { pollLag: m.pollLag, invalid: m.invalidRow },
      consumer: 'c',
      eventType: 'test.event.v1',
      schema,
      initialPosition: 'oldest',
      pollIntervalMs: 1000,
      safetyLagMs: 120_000,
      batchSize: 100,
      lockPrefix: 'ew',
      shard: { index: 1, count: 4 },
      maxHeldLocks: 1,
      now,
    });
    return { p, m };
  };

  it('reports the backlog of a shard nobody runs (maxHeldLocks reached), never 0', async () => {
    // Shard 1/4 holds rows 1 and 5 (300 s old), past its cursor at 0.
    const db = fakePrisma([row(1, old), row(5, old), row(2, old)], [['outbox:c#1/4', 0n]]);
    const lockState = lockSet();
    lockState.held.add('ew:outbox:c#0/4'); // this process already runs another shard
    const { p, m } = shardPoller(db, lockState);

    const report = await p.pollOnce(recorder().handler);
    expect(report.active).toBe(false);
    // 300 s old, minus the 120 s safety lag the cursor always trails by.
    expect(m.lag.get('c')).toBe(180);
    expect(db.cursors.get('outbox:c#1/4')).toBe(0n);
  });

  it('reports ~0 for a shard another replica keeps up with, and probes at most every 10 s', async () => {
    let now = NOW.getTime();
    const db = fakePrisma([row(1, old), row(5, fresh)], [['outbox:c#1/4', 1n]]);
    const { p, m } = shardPoller(db, lockSet(new Set(['ew:outbox:c#1/4'])), () => new Date(now));

    await p.pollOnce(recorder().handler);
    expect(m.lag.get('c')).toBe(0);
    const probes = () => db.queries.filter((q) => q.sql.includes('created_at <= ?')).length;
    expect(probes()).toBe(1);
    now += 5_000;
    await p.pollOnce(recorder().handler);
    expect(probes()).toBe(1);
    now += 5_000;
    await p.pollOnce(recorder().handler);
    expect(probes()).toBe(2);
  });

  it('measures a shard without a cursor from the start of the stream', async () => {
    const db = fakePrisma([row(1, old)]);
    const { m, p } = shardPoller(db, lockSet(new Set(['ew:outbox:c#1/4'])));
    await p.pollOnce(recorder().handler);
    expect(m.lag.get('c')).toBe(180);
  });
});

describe('OutboxPoller failure backoff (step 3.1 M2)', () => {
  it('does not retry a failed row before min(maxMs, baseMs * 2^(failures-1))', async () => {
    let now = NOW.getTime();
    const db = fakePrisma([row(1, old), row(2, old)]);
    const { poller: p } = poller(db.prisma, {
      failureBackoff: { baseMs: 1000, maxMs: 3000 },
      now: () => new Date(now),
    });
    const attempts: number[] = [];
    let fail = true;
    const handler: EventHandler<Payload> = (event) => {
      if (event.payload.n === 1) {
        attempts.push(now - NOW.getTime());
        if (fail) return Promise.reject(new Error('s3 down'));
      }
      return Promise.resolve('handled');
    };
    const first = await p.pollOnce(handler); // failure 1 → wait 1000
    expect(first).toMatchObject({ failed: 1, handled: 1, cursor: 0n });
    now += 999;
    const waiting = await p.pollOnce(handler);
    expect(waiting).toMatchObject({ failed: 0, backedOff: 1, handled: 0, cursor: 0n });
    now += 1; // 1000: failure 2 → wait 2000
    await p.pollOnce(handler);
    now += 1999;
    await p.pollOnce(handler);
    now += 1; // 3000: failure 3 → wait min(3000, 4000)
    await p.pollOnce(handler);
    now += 2999;
    await p.pollOnce(handler);
    fail = false;
    now += 1;
    const recovered = await p.pollOnce(handler);
    expect(attempts).toEqual([0, 1000, 3000, 6000]);
    expect(recovered).toMatchObject({ handled: 1, cursor: 2n });
  });

  it('retries on every poll without a backoff (step 2.3 behaviour)', async () => {
    const db = fakePrisma([row(1, old)]);
    const { poller: p } = poller(db.prisma);
    let attempts = 0;
    const handler: EventHandler<Payload> = () => {
      attempts += 1;
      return Promise.reject(new Error('down'));
    };
    await p.pollOnce(handler);
    await p.pollOnce(handler);
    expect(attempts).toBe(2);
  });
});

describe('processOnceHandler', () => {
  const event = {
    eventId: uuid(1),
    eventType: 'test.event.v1',
    occurredAt: NOW.toISOString(),
    correlationId: 'corr-1-xxxxxx',
    organizationId: '7',
    payload: { n: 1 },
  };

  it('runs the handler in the ledger transaction with the budget, then reports duplicates', async () => {
    const db = fakePrisma([]);
    const seen: unknown[] = [];
    const handle = processOnceHandler<Payload>(
      db.prisma,
      'consumer-a',
      (e, tx) => (seen.push([e.payload.n, typeof tx]), Promise.resolve()),
      { txTimeoutMs: 60_000 },
    );
    expect(await handle(event)).toBe('handled');
    expect(await handle(event)).toBe('duplicate');
    expect(seen).toEqual([[1, 'object']]);
    expect(db.ledger.has(`consumer-a|${uuid(1)}`)).toBe(true);
    expect(db.raw.transactions[0]).toEqual({ timeout: 60_000, maxWait: 60_000 });
  });

  it('rolls the ledger row back when the handler throws (retried later)', async () => {
    const db = fakePrisma([]);
    let fail = true;
    const handle = processOnceHandler<Payload>(
      db.prisma,
      'consumer-a',
      () => (fail ? Promise.reject(new Error('boom')) : Promise.resolve()),
      { txTimeoutMs: 1000 },
    );
    await expect(handle(event)).rejects.toThrow('boom');
    expect(db.ledger.size).toBe(0);
    fail = false;
    expect(await handle(event)).toBe('handled');
  });
});
