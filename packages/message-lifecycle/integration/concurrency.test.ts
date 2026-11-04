import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  transitionMessage,
  transitionMessageWithRetry,
  type LifecycleMetrics,
  type MessageState,
  type TransitionOutcome,
  type TransitionRequest,
} from '../src';
import { Fixtures, requireEnv, type MessageFixture } from './support/fixtures';

/** §9 item 8: parallel writers on the real MySQL writer (row lock + CAS, no lost update). */

const fx = new Fixtures();
// A pool large enough for 64 concurrent interactive transactions.
const prisma = new PrismaClient({
  datasourceUrl: (() => {
    const url = new URL(requireEnv('DATABASE_URL'));
    url.searchParams.set('connection_limit', '32');
    url.searchParams.set('pool_timeout', '60');
    return url.toString();
  })(),
});
const TX = { timeoutMs: 30_000, maxAttempts: 10 };
let org: bigint;

beforeAll(async () => {
  org = await fx.organization('cc');
});
afterAll(async () => {
  await prisma.$disconnect();
  await fx.cleanup();
});

const delivery = { role: 'delivery', service: 'delivery-worker', type: 'system' } as const;

function approve(m: MessageFixture, key: string): TransitionRequest {
  return {
    message: m,
    to: 'approved',
    reason: 'dev_passthrough',
    actor: { role: 'dev_passthrough', service: 'delivery-worker', type: 'system' },
    transitionKey: key,
    expectedRound: 0,
    expectedFrom: ['persisted'],
  };
}

const tally = (outcomes: TransitionOutcome[]) => {
  const counts: Record<string, number> = {};
  for (const o of outcomes) counts[o.result] = (counts[o.result] ?? 0) + 1;
  return counts;
};

async function assertContiguous(m: MessageFixture): Promise<number> {
  const row = await fx.row(m);
  const history = await fx.history(m);
  expect(history.map((h) => h.version)).toEqual(history.map((_, i) => i));
  expect(history.at(-1)!.version).toBe(row.version);
  expect(history.at(-1)!.toStatus).toBe(row.status);
  for (let i = 1; i < history.length; i += 1) {
    expect(history[i]!.fromStatus).toBe(history[i - 1]!.toStatus);
  }
  return row.version;
}

describe('concurrent transitions (§9 item 8)', () => {
  it('(a) 64 parallel persisted → approved with distinct keys: 1 applied, 63 duplicate', async () => {
    const m = await fx.message(org);
    const outcomes = await Promise.all(
      Array.from({ length: 64 }, (_, i) =>
        transitionMessageWithRetry(prisma, approve(m, `evt:${randomUUID()}:approved:${i}`), TX),
      ),
    );
    expect(tally(outcomes)).toEqual({ applied: 1, duplicate: 63 });
    for (const o of outcomes) if (o.result === 'duplicate') expect(o.why).toBe('same_state');
    expect((await fx.history(m)).filter((h) => h.toStatus === 'approved')).toHaveLength(1);
    expect(await fx.outbox(m)).toHaveLength(1);
    expect(await fx.events(m)).toHaveLength(1);
    expect(await assertContiguous(m)).toBe(2);
  });

  it('(b) 64 parallel requests with the same key: 1 applied', async () => {
    const m = await fx.message(org);
    const key = `evt:${randomUUID()}:approved`;
    const outcomes = await Promise.all(
      Array.from({ length: 64 }, () => transitionMessageWithRetry(prisma, approve(m, key), TX)),
    );
    expect(tally(outcomes)).toEqual({ applied: 1, duplicate: 63 });
    expect(await fx.outbox(m)).toHaveLength(1);
    expect(await assertContiguous(m)).toBe(2);
  });

  it('(c) 16 workers race through a delivery chain: every step once, contiguous versions', async () => {
    const m = await fx.message(org, { state: 'approved' });
    const base = 2;
    const chain: { to: MessageState; reason: TransitionRequest['reason'] }[] = [
      { to: 'delivery_pending', reason: 'delivery_planned' },
      { to: 'delivery_retry', reason: 'delivery_deferred' },
      { to: 'delivery_pending', reason: 'delivery_requeued' },
      { to: 'delivered', reason: 'delivery_complete' },
    ];
    let applied = 0;
    const worker = async () => {
      for (let guard = 0; guard < 200; guard += 1) {
        // The worker's view: an unlocked read (may be stale by the time it transitions).
        const view = await fx.row(m);
        const step = view.version - base;
        if (step >= chain.length) return;
        const next = chain[step]!;
        const outcome = await transitionMessageWithRetry(
          prisma,
          {
            message: m,
            ...next,
            actor: delivery,
            transitionKey: `chain:${m.id.toString()}:${step}`,
            ...(step === 0 ? { expectedRound: 0, expectedFrom: ['approved'] as const } : {}),
          },
          TX,
        );
        if (outcome.result === 'applied') applied += 1;
        else expect(['duplicate', 'stale', 'invalid']).toContain(outcome.result);
      }
      throw new Error('worker did not finish');
    };
    await Promise.all(Array.from({ length: 16 }, worker));
    expect(applied).toBe(chain.length);
    const history = await fx.history(m);
    expect(history.slice(base + 1).map((h) => h.toStatus)).toEqual(chain.map((c) => c.to));
    expect(await assertContiguous(m)).toBe(base + chain.length);
    // Final version = 1 + applied rows after creation (version 0 is the received row).
    expect(history.length - 1).toBe(base + chain.length);
    expect(await fx.outbox(m)).toHaveLength(chain.length);
  });

  it('(d) two transactions with the same expectedVersion: one applied, one stale/version_mismatch', async () => {
    const m = await fx.message(org, { state: 'delivery_pending' });
    const expire = (suffix: string): TransitionRequest => ({
      message: m,
      to: 'expired',
      reason: 'deadline_exceeded',
      actor: { role: 'sweeper', service: 'event-relay', type: 'system' },
      transitionKey: `expire:${m.id.toString()}:2:${suffix}`,
      expectedVersion: 2,
      expectedFrom: ['delivery_pending'],
    });
    const retry: TransitionRequest = {
      message: m,
      to: 'delivery_retry',
      reason: 'delivery_deferred',
      actor: delivery,
      transitionKey: `signal:x:${randomUUID()}:delivery_retry`,
      expectedVersion: 2,
    };
    // Both transactions open first, then race for the lock.
    let ready = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const run = (request: TransitionRequest) =>
      prisma.$transaction(
        async (tx) => {
          await tx.$queryRaw`SELECT 1`;
          ready += 1;
          if (ready === 2) release();
          await gate;
          return transitionMessage(tx, request);
        },
        { timeout: 30_000, maxWait: 30_000 },
      );
    const outcomes = await Promise.all([run(expire('a')), run(retry)]);
    expect(tally(outcomes)).toEqual({ applied: 1, stale: 1 });
    const stale = outcomes.find((o) => o.result === 'stale');
    expect(stale).toMatchObject({ why: 'version_mismatch' });
    expect(await assertContiguous(m)).toBe(3);
  });

  it('(e) 200 messages × 8 writers mixed: no deadlock escapes, every message consistent', async () => {
    const messages: MessageFixture[] = [];
    for (let i = 0; i < 200; i += 1) messages.push(await fx.message(org));
    const steps: { to: MessageState; reason: TransitionRequest['reason']; role: string }[] = [
      { to: 'approved', reason: 'dev_passthrough', role: 'dev_passthrough' },
      { to: 'delivery_pending', reason: 'delivery_planned', role: 'delivery' },
      { to: 'delivery_retry', reason: 'delivery_deferred', role: 'delivery' },
      { to: 'delivered', reason: 'delivery_partial', role: 'delivery' },
    ];
    let conflicts = 0;
    const metrics: LifecycleMetrics = {
      transition: () => undefined,
      ignored: () => undefined,
      versionConflict: () => void (conflicts += 1),
      derivedSkipped: () => undefined,
    };
    const writer = async (w: number) => {
      const order = [...messages].sort(() => Math.random() - 0.5);
      for (const m of order) {
        // Writers walk the steps from different starting points (out-of-order arrivals).
        for (let k = 0; k < steps.length; k += 1) {
          const index = (k + w) % steps.length;
          const step = steps[index]!;
          await transitionMessageWithRetry(
            prisma,
            {
              message: m,
              to: step.to,
              reason: step.reason,
              actor: { role: step.role as 'delivery', service: 'delivery-worker', type: 'system' },
              transitionKey: `mix:${m.id.toString()}:${index}`,
            },
            TX,
            { metrics },
          );
        }
      }
    };
    // Repeat until every message reached the end (an early step may be refused before its cause).
    for (let pass = 0; pass < 6; pass += 1) {
      await Promise.all(Array.from({ length: 8 }, (_, w) => writer(w)));
      const states = await prisma.emailMessage.findMany({
        where: { organizationId: org, id: { in: messages.map((m) => m.id) } },
        select: { status: true },
      });
      if (states.every((s) => s.status === 'delivered')) break;
    }
    // `delivered` may follow `delivery_pending` directly (E23), so a message has 3 or 4 applied
    // transitions after creation; each has its history, event and outbox row.
    let applied = 0;
    for (const m of messages) {
      expect((await fx.row(m)).status).toBe('delivered');
      const version = await assertContiguous(m);
      expect([4, 5]).toContain(version);
      applied += version - 1;
    }
    const outbox = await prisma.messageOutbox.count({
      where: { organizationId: org, aggregateId: { in: messages.map((m) => m.id.toString()) } },
    });
    expect(outbox).toBe(applied);
    expect(conflicts).toBeGreaterThanOrEqual(0);
  });
});
