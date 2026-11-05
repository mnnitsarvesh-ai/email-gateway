import { randomUUID } from 'node:crypto';
import { processOnceHandler } from '@email-gateway/common';
import { Prisma, PrismaClient } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  isTransitionKeyViolation,
  transitionKeyHash,
  transitionMessage,
  transitionMessageWithRetry,
  type TransitionRequest,
} from '../src';
import {
  Fixtures,
  requireEnv,
  writerTarget,
  writerUrlVia,
  type MessageFixture,
} from './support/fixtures';
import { TcpProxy } from './support/tcp-proxy';

/** §9 item 9: failure recovery against the real MySQL writer. */

const fx = new Fixtures();
const prisma = fx.prisma;
const TX = { timeoutMs: 15_000 };
let org: bigint;
const proxies: TcpProxy[] = [];
const clients: PrismaClient[] = [];

beforeAll(async () => {
  org = await fx.organization('rc');
});
afterAll(async () => {
  for (const c of clients) await c.$disconnect().catch(() => undefined);
  for (const p of proxies) await p.close();
  await fx.cleanup();
});

function approve(m: MessageFixture, eventId: string): TransitionRequest {
  return {
    message: m,
    to: 'approved',
    reason: 'dev_passthrough',
    actor: { role: 'dev_passthrough', service: 'delivery-worker', type: 'system' },
    transitionKey: `evt:${eventId}:approved`,
    causationEventId: eventId,
    expectedRound: 0,
    // E27 (step 4.1): the dev pass-through approves a scanned message (E4 is retired).
    expectedFrom: ['scanned'],
  };
}

async function keyRows(m: MessageFixture, key: string): Promise<number> {
  return prisma.emailMessageStatusHistory.count({
    where: { messageId: m.id, receivedAt: m.receivedAt, transitionKey: transitionKeyHash(key) },
  });
}

describe('failure recovery (§9 item 9)', () => {
  it('(a) a consumer crash between transition and commit leaves nothing; the re-run applies once', async () => {
    const m = await fx.message(org, { state: 'scanned' });
    const consumer = fx.consumer('crash');
    const eventId = randomUUID();
    const event: EventEnvelope<{ messageId: string }> = {
      eventId,
      eventType: 'mail.message.received.v1',
      occurredAt: new Date().toISOString(),
      correlationId: `it-crash-${eventId.slice(0, 8)}`,
      organizationId: org.toString(),
      payload: { messageId: m.id.toString() },
    };
    let crash = true;
    const handler = processOnceHandler<{ messageId: string }>(
      prisma,
      consumer,
      async (_event, tx) => {
        const outcome = await transitionMessage(tx, approve(m, eventId));
        expect(outcome.result).toBe('applied');
        if (crash) throw new Error('crash after the transition, before the commit');
      },
      { txTimeoutMs: 15_000 },
    );

    await expect(handler(event)).rejects.toThrow('crash after the transition');
    expect(await fx.row(m)).toMatchObject({ status: 'scanned', version: 2 });
    expect(await fx.history(m)).toHaveLength(3);
    expect(await fx.outbox(m)).toHaveLength(0);
    expect(await fx.events(m)).toHaveLength(0);
    expect(await prisma.messageIdempotency.count({ where: { consumer, eventId } })).toBe(0);

    crash = false;
    expect(await handler(event)).toBe('handled');
    expect(await fx.row(m)).toMatchObject({ status: 'approved', version: 3 });
    expect(await keyRows(m, `evt:${eventId}:approved`)).toBe(1);
    expect(await fx.outbox(m)).toHaveLength(1);

    expect(await handler(event)).toBe('duplicate');
    expect(await fx.history(m)).toHaveLength(4);
    expect(await fx.outbox(m)).toHaveLength(1);
  });

  it('(b) a writer outage after SELECT … FOR UPDATE fails the call, releases the lock, and the retry applies once', async () => {
    const m = await fx.message(org, { state: 'scanned' });
    const target = writerTarget();
    const proxy = await TcpProxy.start(target.host, target.port);
    proxies.push(proxy);
    const proxied = new PrismaClient({
      datasourceUrl: writerUrlVia(proxy.port, {
        connection_limit: '2',
        connect_timeout: '2',
        pool_timeout: '5',
      }),
    });
    clients.push(proxied);
    const eventId = randomUUID();
    const request = approve(m, eventId);

    // The transaction client cuts the network right after its first raw query (the row lock).
    const failed = await proxied
      .$transaction(
        (tx) => {
          let cut = false;
          const cutting = new Proxy(tx, {
            get(t, prop, receiver) {
              if (prop === '$queryRaw') {
                return async (...args: unknown[]) => {
                  const rows: unknown = await (
                    Reflect.get(t, prop, receiver) as (...a: unknown[]) => Promise<unknown>
                  ).apply(t, args);
                  if (!cut) {
                    cut = true;
                    proxy.cut();
                  }
                  return rows;
                };
              }
              return Reflect.get(t, prop, receiver) as unknown;
            },
          });
          return transitionMessage(cutting, request);
        },
        { timeout: 10_000, maxWait: 10_000 },
      )
      .then(
        () => null,
        (error: unknown) => error,
      );
    expect(failed).toBeInstanceOf(Error);
    expect(proxy.cutActive).toBe(true);

    // Nothing committed, and the row is not left locked: another session locks it in time.
    expect(await fx.row(m)).toMatchObject({ status: 'scanned', version: 2 });
    const direct = new PrismaClient({
      datasourceUrl: (() => {
        const url = new URL(requireEnv('DATABASE_URL'));
        url.searchParams.set('connection_limit', '1');
        return url.toString();
      })(),
    });
    clients.push(direct);
    const waitedMs = await direct.$transaction(
      async (tx) => {
        await tx.$executeRawUnsafe('SET SESSION innodb_lock_wait_timeout = 10');
        const started = Date.now();
        await tx.$queryRaw`
          SELECT id FROM email_messages WHERE id = ${m.id} AND received_at = ${m.receivedAt}
          FOR UPDATE`;
        return Date.now() - started;
      },
      { timeout: 20_000, maxWait: 20_000 },
    );
    expect(waitedMs).toBeLessThan(10_000);
    await direct.$disconnect();

    proxy.restore();
    const outcome = await transitionMessageWithRetry(proxied, request, TX);
    expect(outcome).toMatchObject({ result: 'applied', version: 3 });
    expect(await keyRows(m, request.transitionKey)).toBe(1);
    expect(await fx.outbox(m)).toHaveLength(1);
    expect(await transitionMessageWithRetry(proxied, request, TX)).toMatchObject({
      result: 'duplicate',
      why: 'transition_key',
    });
  });

  it('(c) a P2002 on the transition key rolls the attempt back; the retry answers duplicate', async () => {
    // A caller in REPEATABLE READ whose snapshot predates a concurrent commit of the same key: the
    // key check (a consistent read) misses it, the re-entry edge E19 applies from `scanning`, and
    // the history unique key is the backstop.
    const m = await fx.message(org, { state: 'quarantined' });
    const request: TransitionRequest = {
      message: m,
      to: 'scanning',
      reason: 'admin_rescan',
      actor: { role: 'operator', service: 'api', type: 'api_key', id: randomUUID() },
      transitionKey: `api:${org.toString()}:rescan:${randomUUID()}`,
      recordIgnored: false,
    };
    const errors: unknown[] = [];
    let first = true;
    const racing = {
      $transaction: <T>(
        fn: (tx: Prisma.TransactionClient) => Promise<T>,
        options: { timeout: number; maxWait: number },
      ) =>
        prisma.$transaction(
          async (tx) => {
            if (first) {
              first = false;
              // Snapshot first, then the concurrent writer commits the same request.
              await tx.$queryRaw`
                SELECT COUNT(*) AS n FROM email_message_status_history
                WHERE message_id = ${m.id} AND received_at = ${m.receivedAt}`;
              const other = await transitionMessageWithRetry(prisma, request, TX);
              expect(other).toMatchObject({ result: 'applied', version: 3, round: 1 });
            }
            try {
              return await fn(tx);
            } catch (error) {
              errors.push(error);
              throw error;
            }
          },
          { ...options, isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead },
        ),
    } as unknown as PrismaClient;

    const outcome = await transitionMessageWithRetry(racing, request, TX);
    expect(errors).toHaveLength(1);
    expect(isTransitionKeyViolation(errors[0])).toBe(true);
    expect(outcome).toMatchObject({ result: 'duplicate', why: 'transition_key' });
    expect(await keyRows(m, request.transitionKey)).toBe(1);
    expect(await fx.row(m)).toMatchObject({ status: 'scanning', version: 3, lifecycleRound: 1 });
    expect(await fx.outbox(m)).toHaveLength(1);
  });
});
