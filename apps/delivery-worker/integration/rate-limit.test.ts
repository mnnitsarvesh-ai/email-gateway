import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { rateLimitKeys } from '../src/rate-limit/outbound-rate-limiter';
import { FakePostfix } from './support/fake-postfix';
import { Fixtures, type MessageFixture, workerConfig } from './support/fixtures';
import { buildWorker, FAST, makeDue, type TestWorker } from './support/worker';

const fx = new Fixtures();
const postfix = new FakePostfix();
let worker: TestWorker;

beforeAll(async () => {
  await postfix.start();
  worker = buildWorker(fx, workerConfig({ ...FAST, ...postfix.configOverrides }));
});
afterEach(() => postfix.reset());
afterAll(async () => {
  await worker.close();
  await postfix.stop();
  await fx.cleanup();
});

/** Keep the whole test inside one UTC minute window. */
async function freshMinute(): Promise<void> {
  const second = new Date().getUTCSeconds();
  if (second > 45) await new Promise((r) => setTimeout(r, (61 - second) * 1000));
}

async function planned(org: bigint, addresses: string[]): Promise<MessageFixture> {
  const message = await fx.message(org, { recipients: addresses.map((address) => ({ address })) });
  expect(await worker.plan(fx.approval(message))).toMatchObject({ status: 'planned' });
  return message;
}

describe('outbound rate limits (R11) in Redis', () => {
  it('splits a group larger than the limit into chunks that fit, admits one chunk per window, defers the rest once per window', async () => {
    await freshMinute();
    const org = await fx.organization('rl');
    await fx.limit(org, 'outbound_recipients_per_minute', 2);
    const domain = `rl-${fx.suffix}.test`;
    fx.trackDomain(domain);
    const message = await planned(
      org,
      ['a', 'b', 'c', 'd', 'e'].map((l) => `${l}@${domain}`),
    );
    expect(await fx.reinjections(message)).toHaveLength(1);

    await worker.reinjectOnce();
    let rows = await fx.reinjections(message);
    expect(rows.map((r) => [r.status, r.recipientCount])).toEqual([
      ['queued', 2],
      ['pending', 2],
      ['pending', 1],
    ]);
    expect(postfix.transactions).toHaveLength(1);
    expect(postfix.transactions[0]!.rcpts).toHaveLength(2);
    const keys = rateLimitKeys(org, domain, new Date());
    expect(await fx.redis.client.get(keys[0])).toBe('2');
    expect(await fx.redis.client.get(keys[1])).toBe('2');

    // The new chunks are due now but the tenant window is full: deferred, attempts refunded.
    await worker.reinjectOnce();
    rows = await fx.reinjections(message);
    expect(rows.slice(1).map((r) => [r.status, r.lastErrorClass, r.attempts])).toEqual([
      ['pending', 'gateway_rate_limited', 0],
      ['pending', 'gateway_rate_limited', 0],
    ]);
    for (const row of rows.slice(1)) {
      expect(row.nextAttemptAt.getTime()).toBeGreaterThanOrEqual(
        Math.ceil(Date.now() / 60_000) * 60_000,
      );
    }
    expect(postfix.transactions).toHaveLength(1);
    expect(await fx.redis.client.get(keys[0])).toBe('2'); // a deferred group consumes nothing
    const deliveries = await fx.deliveries(message);
    expect(deliveries.map((d) => d.status).sort()).toEqual([
      'deferred',
      'deferred',
      'deferred',
      'queued',
      'queued',
    ]);
    expect(
      deliveries
        .filter((d) => d.status === 'deferred')
        .every((d) => d.lastErrorClass === 'gateway_rate_limited'),
    ).toBe(true);

    // Polling again in the same window writes no second audit row.
    const before = await fx.counts(message);
    await makeDue(fx, rows.slice(1));
    await worker.reinjectOnce();
    expect(await fx.counts(message)).toEqual(before);
  });

  it('a limit of 0 holds every outbound delivery of the tenant; inbound is never limited', async () => {
    const org = await fx.organization('rl-zero');
    await fx.limit(org, 'outbound_recipients_per_minute', 0);
    const tenant = fx.name('rl-in');
    await fx.domain(org, tenant, { destination: 'mail.customer.example' });
    const domain = `rl0-${fx.suffix}.test`;
    fx.trackDomain(domain);
    const outbound = await planned(org, [`x@${domain}`]);
    const inbound = await fx.message(org, {
      direction: 'inbound',
      recipients: [{ address: `u@${tenant}` }],
    });
    await worker.plan(fx.approval(inbound));
    await worker.reinjectOnce();
    expect((await fx.deliveries(outbound))[0]).toMatchObject({
      status: 'deferred',
      lastErrorClass: 'gateway_rate_limited',
    });
    expect((await fx.deliveries(inbound))[0]).toMatchObject({ status: 'queued' });
    expect(postfix.transactions.map((t) => t.listener)).toEqual(['inbound']);
  });

  it('fails closed when Redis is unreachable: deferred (gateway_rate_limit_unavailable), never sent, never dropped', async () => {
    const org = await fx.organization('rl-down');
    const domain = `rld-${fx.suffix}.test`;
    const message = await planned(org, [`x@${domain}`]);
    const down = buildWorker(fx, workerConfig({ ...FAST, ...postfix.configOverrides }), {
      redisUrl: 'redis://127.0.0.1:1/0',
    });
    try {
      await down.reinjectOnce();
    } finally {
      await down.close();
    }
    expect(postfix.transactions).toHaveLength(0);
    const [row] = await fx.reinjections(message);
    expect(row).toMatchObject({
      status: 'pending',
      lastErrorClass: 'gateway_rate_limit_unavailable',
    });
    expect((await fx.deliveries(message))[0]).toMatchObject({
      status: 'deferred',
      lastErrorClass: 'gateway_rate_limit_unavailable',
    });

    // Redis back: delivered.
    await makeDue(fx, [row!]);
    await worker.reinjectOnce();
    expect((await fx.deliveries(message))[0]).toMatchObject({ status: 'queued' });
  });
});
