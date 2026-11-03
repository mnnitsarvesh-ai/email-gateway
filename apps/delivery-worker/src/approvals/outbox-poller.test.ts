import { MetricsService } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { DeliveryMetrics } from '../metrics/delivery-metrics';
import type { AdvisoryLocks } from '../shared/advisory-locks';
import type { FeedHandler } from './approval-feed';
import { OutboxPoller } from './outbox-poller';

interface Row {
  id: bigint;
  created_at: Date;
  event_id: string;
  organization_id: bigint;
  event_type: string;
  correlation_id: string;
  payload: unknown;
}

const schema = z.object({ n: z.number() });
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
function fakePrisma(rows: Row[]) {
  const cursors = new Map<string, bigint | null>();
  const ledger = new Set<string>();
  const queries: { after: bigint; limit: number }[] = [];
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
      const [after, type, limit] = values as [bigint, string, number];
      queries.push({ after, limit });
      return Promise.resolve(
        rows
          .filter((r) => r.id > after && r.event_type === type)
          .sort((a, b) => (a.id < b.id ? -1 : 1))
          .slice(0, limit),
      );
    },
    streamCursor: {
      findUnique: ({ where }: { where: { name: string } }) =>
        Promise.resolve(cursors.has(where.name) ? { positionId: cursors.get(where.name) } : null),
      findUniqueOrThrow: ({ where }: { where: { name: string } }) =>
        Promise.resolve({ positionId: cursors.get(where.name) ?? null }),
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
    $transaction<T>(fn: (tx: unknown) => Promise<T>) {
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
  return { prisma: prisma as unknown as PrismaClient, cursors, ledger, queries };
}

const locks = (held = true) =>
  ({
    ensure: () => Promise.resolve(held),
    release: () => Promise.resolve(),
  }) as unknown as AdvisoryLocks;

const logger = createLogger({ service: 'test', level: 'silent' });

function poller(
  prisma: PrismaClient,
  options: Partial<{ initialPosition: 'oldest' | 'latest'; batchSize: number; held: boolean }> = {},
) {
  const metrics = new DeliveryMetrics(new MetricsService({ service: 'test' }));
  return {
    metrics,
    poller: new OutboxPoller({
      prisma,
      locks: locks(options.held ?? true),
      logger,
      metrics,
      consumer: 'delivery-worker.test',
      eventType: 'test.event.v1',
      schema,
      initialPosition: options.initialPosition ?? 'oldest',
      pollIntervalMs: 1000,
      safetyLagMs: 120_000,
      batchSize: options.batchSize ?? 500,
      txTimeoutMs: 5000,
      now: () => NOW,
    }),
  };
}

const recorder = () => {
  const seen: number[] = [];
  const handler: FeedHandler<{ n: number }> = (event) => {
    seen.push(event.payload.n);
    return Promise.resolve();
  };
  return { seen, handler };
};

describe('OutboxPoller (R6)', () => {
  it('starts an approvals consumer at the oldest retained row and handles rows in id order', async () => {
    const db = fakePrisma([row(5, old), row(6, old), row(7, old, { n: 7 }, 'other.event.v1')]);
    const { poller: p } = poller(db.prisma);
    const { seen, handler } = recorder();
    const report = await p.pollOnce(handler);
    expect(seen).toEqual([5, 6]);
    expect(report).toMatchObject({ active: true, handled: 2, cursor: 6n });
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(6n);
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
    const first = recorder();
    await poller(db.prisma).poller.pollOnce(first.handler);
    const second = recorder();
    const report = await poller(db.prisma).poller.pollOnce(second.handler);
    expect(first.seen).toEqual([1]);
    expect(second.seen).toEqual([]);
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
    const text = await metrics.outboxInvalid.get();
    expect(text.values[0]?.value).toBe(2);
  });

  it('a failing handler holds the cursor (never skipped) without blocking later rows', async () => {
    const db = fakePrisma([row(1, old), row(2, old), row(3, old)]);
    const { poller: p } = poller(db.prisma);
    const seen: number[] = [];
    let fail = true;
    const handler: FeedHandler<{ n: number }> = (event) => {
      if (event.payload.n === 2 && fail) return Promise.reject(new Error('db down'));
      seen.push(event.payload.n);
      return Promise.resolve();
    };
    const report = await p.pollOnce(handler);
    expect(report).toMatchObject({ failed: 1, handled: 2, cursor: 1n });
    expect(seen).toEqual([1, 3]);
    fail = false;
    await p.pollOnce(handler);
    expect(seen).toEqual([1, 3, 2]);
    expect(db.cursors.get('outbox:delivery-worker.test')).toBe(3n);
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

  it('idles without the consumer lock', async () => {
    const db = fakePrisma([row(1, old)]);
    const { poller: p } = poller(db.prisma, { held: false });
    const { seen, handler } = recorder();
    expect((await p.pollOnce(handler)).active).toBe(false);
    expect(seen).toEqual([]);
    expect(db.queries).toEqual([]);
  });
});
