import { PrismaService } from '@email-gateway/common';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type ClaimedReinjection, ReinjectionStore } from '../src/reinjection/reinjection-store';
import { FreezeProxy, proxiedUrl } from './support/freeze-proxy';
import { Fixtures, type MessageFixture, requireEnv, workerConfig } from './support/fixtures';
import { buildWorker, FAST, type TestWorker } from './support/worker';

/**
 * Deterministic reproduction of the step 4.1 carry-over defect (step 4.2 §6, recorded in §12
 * WP4): after a writer stall the delivery-worker's pool returned results of other queries. A
 * test-only TCP proxy freezes the writer connection in both directions while keeping the
 * sockets open (what `docker compose pause mysql` does to a client); a statement is in flight
 * when the client gives up on it; after the unfreeze, distinct queries on the same client and
 * the store's reads on fixture rows must each return their own result.
 *
 * Root cause (H1, measured here): the Prisma 6.19.3 library engine returns a connection to the
 * pool while a reply is still unread when an interactive transaction expires or `socket_timeout`
 * fires; the next request on that connection reads the previous reply (an off-by-one result
 * stream). The engine sections pin that behaviour (`it.fails`: they turn red once the engine or
 * the driver is replaced, F3); the delivery-worker section is the regression test of the fix:
 * its transactions never expire before the writer answers.
 */

const fx = new Fixtures();
let worker: TestWorker;
let message: MessageFixture;
let reinjection: ClaimedReinjection;
let approvalAt: Date;
let org: bigint;

const ENVELOPE_FROM = 'stall@sender.example';
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

beforeAll(async () => {
  worker = buildWorker(fx, workerConfig({ ...FAST }));
  org = await fx.organization('stall');
  message = await fx.message(org, {
    direction: 'outbound',
    envelopeFrom: ENVELOPE_FROM,
    recipients: [{ address: 'a@ext-stall.test' }, { address: 'b@ext-stall.test' }],
    upload: false,
  });
  const planned = await worker.plan(fx.approval(message));
  expect(planned).toMatchObject({ status: 'planned' });
  const rows = await fx.reinjections(message);
  expect(rows).toHaveLength(1);
  reinjection = rows[0]!;
  approvalAt = rows[0]!.createdAt;
});

afterAll(async () => {
  await worker?.close();
  await fx.cleanup();
});

/** The fixture row back to `pending` and due (each claim scenario claims it once). */
async function resetReinjection(): Promise<void> {
  await fx.prisma.deliveryReinjection.update({
    where: { id_receivedAt: { id: reinjection.id, receivedAt: reinjection.receivedAt } },
    data: { status: 'pending', nextAttemptAt: new Date(Date.now() - 1000), leaseExpiresAt: null },
  });
}

function upstream(): { host: string; port: number } {
  const url = new URL(requireEnv('DATABASE_URL'));
  return {
    host: url.hostname === 'localhost' ? '127.0.0.1' : url.hostname,
    port: Number(url.port),
  };
}

interface Harness {
  proxy: FreezeProxy;
  client: PrismaService;
  store: ReinjectionStore;
}

/**
 * The writer client as the services build it (`PrismaService`), connected through the proxy.
 * `params` adds URL parameters (the engine sections set `socket_timeout` themselves).
 */
async function harness(connectionLimit: number, params: Record<string, string> = {}) {
  const { host, port } = upstream();
  const proxy = new FreezeProxy(host, port);
  const proxyPort = await proxy.start();
  const url = proxiedUrl(requireEnv('DATABASE_URL'), proxyPort, {
    connection_limit: String(connectionLimit),
    ...params,
  });
  const client = new PrismaService({ url });
  await client.$connect();
  return { proxy, client, store: new ReinjectionStore(client) } satisfies Harness;
}

async function close(h: Harness | undefined): Promise<void> {
  await h?.client.$disconnect();
  await h?.proxy.stop();
}

/** A raw result as a short comparable string (`n=1001`, `[]`). */
const shown = (rows: Record<string, unknown>[]): string =>
  rows.length === 0
    ? '[]'
    : rows
        .map((row) =>
          Object.entries(row)
            .map(([k, v]) => `${k}=${v instanceof Date ? v.toISOString() : String(v)}`)
            .join(','),
        )
        .join(';');

const settle = async (run: () => Promise<string>): Promise<string> => {
  try {
    return await run();
  } catch (error) {
    return `error: ${(error as Error).name}: ${(error as Error).message.split('\n').at(-1)}`;
  }
};

/**
 * Distinct queries in sequence, then concurrently, then the store's two reads on the fixture
 * row; every observation must be its own result. Collected first and compared at once, so a
 * failure shows the whole sequence (which query received which result).
 */
async function expectOwnResults(h: Harness, label: string): Promise<void> {
  const select = (value: number) =>
    settle(async () =>
      shown(
        await h.client.$queryRaw<Record<string, unknown>[]>`SELECT CAST(${value} AS SIGNED) AS n`,
      ),
    );
  const sequential = [1001, 1002, 1003, 1004, 1005, 1006];
  const concurrent = [2001, 2002, 2003, 2004];
  const observed: string[] = [];
  for (const value of sequential) observed.push(`SELECT ${value} -> ${await select(value)}`);
  const parallel = await Promise.all(concurrent.map((value) => select(value)));
  concurrent.forEach((value, i) => observed.push(`SELECT ${value} -> ${parallel[i]}`));
  observed.push(
    `context() -> ${await settle(async () => {
      const context = await h.store.context(reinjection);
      if (context === null) return 'null';
      const ids = context.deliveries.map((d) => d.recipientId.toString()).sort();
      return `from=${context.envelopeFrom} deliveries=${ids.join(',')}`;
    })}`,
  );
  observed.push(
    `approvalTime() -> ${await settle(async () =>
      (await h.store.approvalTime(reinjection)).toISOString(),
    )}`,
  );
  const ids = message.recipients.map((r) => r.id.toString()).sort();
  expect(observed, label).toEqual([
    ...sequential.map((value) => `SELECT ${value} -> n=${value}`),
    ...concurrent.map((value) => `SELECT ${value} -> n=${value}`),
    `context() -> from=${ENVELOPE_FROM} deliveries=${ids.join(',')}`,
    `approvalTime() -> ${approvalAt.toISOString()}`,
  ]);
}

/**
 * An interactive transaction with `timeout: 1000` runs a statement, then sends a second one of
 * the same shape as the probes (a cached prepared statement, as the services' recurring
 * queries are) that the frozen proxy holds; the transaction expires client-side while it is in
 * flight; after 3 s the proxy delivers everything it held.
 */
async function expiredTransaction(h: Harness): Promise<unknown> {
  const outcome = h.client
    .$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT 1 AS warm`;
        h.proxy.freeze();
        await tx.$queryRaw`SELECT CAST(${9999} AS SIGNED) AS n`;
        return 'committed';
      },
      { timeout: 1000, maxWait: 1000 },
    )
    .then(
      (value) => value,
      (error: unknown) => error,
    );
  await sleep(3000);
  h.proxy.unfreeze();
  return outcome;
}

/** A plain statement stalled for 3 s on a client with `socket_timeout=1`. */
async function socketTimeout(h: Harness): Promise<unknown> {
  await h.client.$queryRaw`SELECT 1 AS warm`;
  h.proxy.freeze();
  const outcome = h.client.$queryRaw`SELECT CAST(${9999} AS SIGNED) AS n`.then(
    (value) => value,
    (error: unknown) => error,
  );
  await sleep(3000);
  h.proxy.unfreeze();
  return outcome;
}

describe.each([1, 2])('engine defect, connection_limit=%i (pinned until F3)', (limit) => {
  describe('interactive transaction expiry', () => {
    let h: Harness | undefined;
    beforeAll(async () => {
      h = await harness(limit);
    });
    afterAll(() => close(h));

    it('reads correctly before the stall', async () => {
      await expectOwnResults(h!, 'baseline');
    });

    // Fails on Prisma 6.19.3 (library engine): the expired transaction's connection goes back
    // to the pool with the held reply unread, and every later query reads the previous reply.
    it.fails(
      'after an expiry with a statement in flight, every query gets its own result',
      async () => {
        const outcome = await expiredTransaction(h!);
        expect(String((outcome as Error).message)).toMatch(/expired transaction/);
        await expectOwnResults(h!, 'after the expired transaction');
      },
    );
  });

  describe('socket_timeout', () => {
    let h: Harness | undefined;
    beforeAll(async () => {
      h = await harness(limit, { socket_timeout: '1' });
    });
    afterAll(() => close(h));

    // Fails on Prisma 6.19.3: `socket_timeout` fails the statement ("Timed out during query
    // execution") but neither closes nor discards the connection (the proxy sees no close).
    it.fails(
      'after a socket timeout, the stalled connection is closed and not reused',
      async () => {
        const opened = h!.proxy.opened;
        const outcome = await socketTimeout(h!);
        expect(String((outcome as Error).message)).toMatch(/Timed out during query execution/);
        expect(h!.proxy.closedByClient, 'the client closed the stalled connection').toBeGreaterThan(
          0,
        );
        expect(h!.proxy.opened, 'a new connection replaced it').toBeGreaterThan(opened);
        await expectOwnResults(h!, 'after the socket timeout');
      },
    );
  });
});

describe.each([1, 2])(
  'delivery-worker claim during a writer stall, connection_limit=%i',
  (limit) => {
    let h: Harness | undefined;
    beforeAll(async () => {
      h = await harness(limit);
    });
    afterAll(() => close(h));
    beforeEach(resetReinjection);

    it('a 7 s stall inside ReinjectionStore.claim() leaves every later read correct', async () => {
      await expectOwnResults(h!, 'baseline');
      // Freeze on the claim's `SELECT … FOR UPDATE SKIP LOCKED` (sent while the transaction is
      // open), for longer than Prisma's default interactive-transaction timeout (5 s).
      h!.proxy.freezeOn('FOR UPDATE SKIP LOCKED');
      const claimed = h!.store.claim(10, new Date(), 60, { organizationIds: [org] }).then(
        (rows) => rows.map((row) => row.id.toString()),
        (error: unknown) => error,
      );
      await sleep(500);
      expect(h!.proxy.isFrozen, 'the claim statement reached the proxy').toBe(true);
      await sleep(6500);
      h!.proxy.unfreeze();
      const outcome = await claimed;
      await expectOwnResults(h!, 'after the stalled claim');
      expect(outcome, 'the claim completed after the stall').toEqual([reinjection.id.toString()]);
    });
  },
);
