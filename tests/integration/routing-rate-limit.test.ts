import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { composeOk, waitFor } from './support/compose';
import {
  deliveriesOf,
  reinjectionsOf,
  statusEventsOf,
  waitForAllDeliveries,
  waitForDeliveries,
  waitForMessage,
} from './support/deliveries';
import { startWorker, stopWorker, workerHealth } from './support/delivery-worker';
import { clearSinkDomain, sinkFiles } from './support/mail-sink';
import { involving, listQueue } from './support/postfix';
import { MAIL_SINK_HOST, sendingDomain, sleep, submit } from './support/routing';
import { routingStackGate } from './support/routing-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Outbound rate limits of the delivery-worker (docs/plan/steps/05-routing.md §9 item 8, R11):
 * tenant limit 1 recipient per UTC minute, three external recipients in three domains (three
 * groups) → one reinjected now, the others `deferred` (`gateway_rate_limited`) and delivered in
 * later windows. Redis stopped → fail closed: nothing reinjected, nothing lost
 * (`gateway_rate_limit_unavailable`), delivered after Redis is back.
 *
 * The limit key `outbound_recipients_per_minute` is shared with the step 2.2 submission limit
 * (same organization limit, separate counters), so the worker is stopped while the message is
 * submitted and the limit of 1 is set before the worker starts (a fresh worker has no cached
 * limits).
 */
const gate = await routingStackGate();
const fx = new SmtpFixtures();
let orgLimited = 0n;
let orgRedis = 0n;
let limited: FixtureDomain;
let redisOut: FixtureDomain;
let limitedSasl: { username: string; password: string };
let redisSasl: { username: string; password: string };
let redisStopped = false;
const extDomains = () => [1, 2, 3].map((n) => fx.sinkDomain(`rl-ext${n}`));
const redisExt = () => fx.sinkDomain('rl-redis-ext');

async function startRedis() {
  await composeOk(['up', '-d', '--wait', '--no-deps', 'redis'], { timeoutMs: 120_000 });
  redisStopped = false;
}

beforeAll(async () => {
  assertStackReady(gate);
  orgLimited = await fx.organization('rl');
  orgRedis = await fx.organization('rl-redis');
  limited = await sendingDomain(fx, orgLimited, 'rl-out');
  redisOut = await sendingDomain(fx, orgRedis, 'rl-redis-out');
  for (const d of [limited, redisOut]) {
    await fx.destinations(d, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  }
  limitedSasl = await fx.saslConnector(orgLimited, 'rl');
  redisSasl = await fx.saslConnector(orgRedis, 'rl-redis');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  if (redisStopped) await startRedis();
  if (!(await workerHealth('ready'))) {
    if (!(await workerHealth('live'))) await startWorker();
    await waitFor('the delivery-worker ready again', () => workerHealth('ready'), {
      timeoutMs: 90_000,
    });
  }
  for (const d of [...extDomains(), redisExt()]) await clearSinkDomain(d);
  await fx.cleanup();
}, 240_000);

describe.skipIf(gate.skip)('routing stack: outbound rate limits (§9 item 8)', () => {
  it(
    'reinjects one recipient per window under a tenant limit of 1/min and delivers the rest later',
    { timeout: 420_000 },
    async () => {
      const to = extDomains().map((d, i) => `r${i}@${d}`);
      await stopWorker();
      let messageId = 0n;
      try {
        const sent = await submit({
          credentials: limitedSasl,
          from: `rita@${limited.name}`,
          to,
          subject: 'Routing rate limit',
        });
        messageId = (await waitForMessage(fx.prisma, orgLimited, { mtaQueueId: sent.queueId! })).id;
        await fx.limit(orgLimited, 'outbound_recipients_per_minute', 1);
        // Start early in a UTC minute, so "one now, the others deferred" is observed in one window.
        const second = new Date().getUTCSeconds();
        if (second > 30) await sleep((61 - second) * 1_000);
      } finally {
        await startWorker();
      }
      const first = await waitForDeliveries(
        fx.prisma,
        orgLimited,
        messageId,
        'one recipient reinjected, two deferred by the gateway rate limit',
        (rows) =>
          rows.length === 3 &&
          rows.filter((d) => ['queued', 'delivered'].includes(d.status)).length === 1 &&
          rows.filter((d) => d.status === 'deferred' && d.lastErrorClass === 'gateway_rate_limited')
            .length === 2,
        90_000,
      );
      expect(first.filter((d) => d.status === 'deferred').every((d) => d.attemptCount === 0)).toBe(
        true,
      );
      // Deferred groups are still pending reinjections (never dropped), scheduled for a later window.
      const groups = await reinjectionsOf(fx.prisma, orgLimited, messageId);
      expect(groups).toHaveLength(3);
      expect(
        groups.filter((g) => g.status === 'pending' && g.lastErrorClass === 'gateway_rate_limited'),
      ).toHaveLength(2);

      const delivered = await waitForAllDeliveries(
        fx.prisma,
        orgLimited,
        messageId,
        ['delivered'],
        3,
        300_000,
      );
      // At most one recipient per UTC minute.
      const minutes = delivered.map((d) => Math.floor(d.deliveredAt!.getTime() / 60_000));
      expect(new Set(minutes).size).toBe(3);
      for (const address of to) expect(await sinkFiles(address)).toHaveLength(1);
      const audit = await statusEventsOf(fx.prisma, orgLimited, messageId);
      expect(audit.some((e) => e.errorClass === 'gateway_rate_limited' && e.applied)).toBe(true);
    },
  );

  it(
    'fails closed with Redis stopped (nothing reinjected, nothing lost) and delivers after recovery',
    { timeout: 420_000 },
    async () => {
      const rcpt = `sam@${redisExt()}`;
      await stopWorker();
      let messageId = 0n;
      try {
        const sent = await submit({
          credentials: redisSasl,
          from: `rex@${redisOut.name}`,
          to: [rcpt],
          subject: 'Routing rate limit Redis down',
        });
        messageId = (await waitForMessage(fx.prisma, orgRedis, { mtaQueueId: sent.queueId! })).id;
        redisStopped = true;
        await composeOk(['stop', 'redis'], { timeoutMs: 60_000 });
      } finally {
        // The worker runs without Redis (readiness reports it); its rate check fails closed.
        await startWorker('live');
      }
      try {
        const [deferred] = await waitForDeliveries(
          fx.prisma,
          orgRedis,
          messageId,
          'delivery deferred: rate limit unavailable',
          (rows) =>
            rows[0]?.status === 'deferred' &&
            rows[0].lastErrorClass === 'gateway_rate_limit_unavailable',
          120_000,
        );
        expect(deferred!.outboundQueueId).toBeNull();
        await sleep(10_000);
        expect(involving(await listQueue('postfix-outbound'), [redisExt()])).toEqual([]);
        expect(await sinkFiles(rcpt)).toEqual([]);
        const [group] = await reinjectionsOf(fx.prisma, orgRedis, messageId);
        expect(group).toMatchObject({ status: 'pending', queueId: null });
        expect((await deliveriesOf(fx.prisma, orgRedis, messageId))[0]!.status).toBe('deferred');
      } finally {
        await startRedis();
      }
      await waitFor(
        'the delivery-worker ready after Redis recovered',
        () => workerHealth('ready'),
        {
          timeoutMs: 90_000,
        },
      );
      await waitForAllDeliveries(fx.prisma, orgRedis, messageId, ['delivered'], 1, 180_000);
      expect(await sinkFiles(rcpt)).toHaveLength(1);
    },
  );
});
