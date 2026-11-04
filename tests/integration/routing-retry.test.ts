import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  DELIVERED_PATH,
  expectConsistentHistory,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { purgeDormantQueues } from './support/broker';
import { composeOk } from './support/compose';
import {
  statusEventsOf,
  waitForAllDeliveries,
  waitForDeliveries,
  waitForMessage,
} from './support/deliveries';
import { clearSinkDomain, sinkFiles, type SinkService } from './support/mail-sink';
import { maillogForQueueId, maillogOffset } from './support/maillog';
import { involving, listQueue } from './support/postfix';
import { googleServers, m365Servers, sendInbound } from './support/routing';
import { routingStackGate } from './support/routing-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Destination outage, Postfix's own retry and failover (docs/plan/steps/05-routing.md §9 item 5,
 * R4, ADR-0006): the destination server is stopped, postfix-outbound defers (status from the
 * delivery log: `deferred`, attempts, error class), the server comes back and Postfix's retry
 * delivers it — with the TEST-PROFILE backoff from the environment (local .env / CI:
 * POSTFIX_MINIMAL_BACKOFF_TIME=10s, POSTFIX_MAXIMAL_BACKOFF_TIME=60s, POSTFIX_QUEUE_RUN_DELAY=10s,
 * POSTFIX_OUTBOUND_SMTP_CONNECT_TIMEOUT=5s), never `postqueue -f`. Then failover along the
 * Google Workspace next-hop list when the primary host is down.
 */
const gate = await routingStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let m365: FixtureDomain;
let google: FixtureDomain;
const stopped = new Set<SinkService>();
const externalSender = () => `ext@${fx.sinkDomain('retry-ext')}`;

async function stopSink(service: SinkService) {
  stopped.add(service);
  await composeOk(['stop', '--timeout', '5', service], { timeoutMs: 60_000 });
}

async function startSink(service: SinkService) {
  await composeOk(['--profile', 'smtp-test', 'up', '-d', '--wait', '--no-deps', service], {
    timeoutMs: 120_000,
  });
  stopped.delete(service);
}

beforeAll(async () => {
  assertStackReady(gate);
  for (const p of ['POSTFIX_MINIMAL_BACKOFF_TIME', 'POSTFIX_MAXIMAL_BACKOFF_TIME']) {
    // The recovery below waits for Postfix's own retry; production values (300s/4000s) would
    // make it take minutes. Configuration only — nothing in code depends on these values.
    if (!/^(\d+)s$/.test(process.env[p] ?? '') || Number(process.env[p]!.slice(0, -1)) > 60) {
      throw new Error(`${p} must be the test-profile value (≤ 60s) in .env / CI`);
    }
  }
  org = await fx.organization('retry');
  m365 = await fx.domain(org, 'retry-m365');
  google = await fx.domain(org, 'retry-google');
  await fx.destinations(m365, m365Servers(`it-${fx.suffix}-retry`));
  await fx.destinations(google, googleServers());
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const service of [...stopped]) await startSink(service);
  for (const domain of [m365, google].filter(Boolean)) await clearSinkDomain(domain.name, 'all');
  await fx.cleanup();
  await purgeDormantQueues();
}, 240_000);

describe.skipIf(gate.skip)('routing stack: outage, retry and failover (§9 item 5)', () => {
  it(
    'defers while the destination is down and delivers after it recovers, by Postfix retry alone',
    { timeout: 420_000 },
    async () => {
      const offset = await maillogOffset();
      const rcpt = `henry@${m365.name}`;
      await stopSink('sink-m365');
      let messageId = 0n;
      try {
        const sent = await sendInbound({
          from: externalSender(),
          to: [rcpt],
          subject: 'Routing outage',
        });
        const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
        messageId = message.id;
        const [deferred] = await waitForDeliveries(
          fx.prisma,
          org,
          message.id,
          'delivery deferred by postfix-outbound (destination down)',
          (rows) => rows[0]?.status === 'deferred' && rows[0].attemptCount >= 1,
          120_000,
        );
        expect(['connect', 'timeout']).toContain(deferred!.lastErrorClass);
        expect(deferred!.deliveredAt).toBeNull();
        const lines = await maillogForQueueId(offset, deferred!.outboundQueueId!);
        expect(lines.some((l) => /status=deferred \((connect to|conversation with)/.test(l))).toBe(
          true,
        );
        // Postfix holds it in its deferred queue (it owns the retry, ADR-0006).
        const queued = involving(await listQueue('postfix-outbound'), [m365.name]);
        expect(queued.map((m) => m.queue_name)).toContain('deferred');
        // Step 3.3 (L9, E21): a deferred recipient → delivery_retry/delivery_deferred.
        await waitForLifecycle(fx.prisma, message, 'delivery_retry', 'delivery_deferred', 30_000);
      } finally {
        await startSink('sink-m365');
      }
      const recoveredAt = Date.now();
      const [delivered] = await waitForAllDeliveries(
        fx.prisma,
        org,
        messageId,
        ['delivered'],
        1,
        240_000,
      );
      expect(delivered!.attemptCount).toBeGreaterThanOrEqual(2);
      expect(delivered!.remoteHost).toContain('.mail.protection.outlook.com');
      expect(await sinkFiles(rcpt, 'sink-m365')).toHaveLength(1);
      // Within the shortened backoff (≤ maximal backoff + queue run delay + delivery), well
      // below the production schedule.
      expect(Date.now() - recoveredAt).toBeLessThan(150_000);
      const audit = await statusEventsOf(fx.prisma, org, messageId);
      const applied = audit.filter((e) => e.applied).map((e) => e.toStatus);
      expect(applied).toContain('deferred');
      expect(applied.at(-1)).toBe('delivered');
      expect(
        audit.filter((e) => e.toStatus === 'deferred' && e.source === 'postfix_log').length,
      ).toBeGreaterThanOrEqual(1);
      expect(involving(await listQueue('postfix-outbound'), [m365.name])).toEqual([]);
      // … and the retry's success → delivered/delivery_complete, from delivery_retry (E23).
      const key = { id: messageId, receivedAt: delivered!.receivedAt };
      await waitForLifecycle(fx.prisma, key, 'delivered', 'delivery_complete');
      const path = await pathOf(fx.prisma, key);
      expect(path.slice(0, 4)).toEqual(DELIVERED_PATH('delivery_retry', '').slice(0, 4));
      expect(path).toContainEqual(['delivery_pending', 'delivery_retry', 'delivery_deferred']);
      // From delivery_retry (E23), or from delivery_pending if a requeue signal came first (E22).
      expect(path.at(-1)?.slice(1)).toEqual(['delivered', 'delivery_complete']);
      await expectConsistentHistory(fx.prisma, key);
    },
  );

  it(
    'fails over to the next Google Workspace host when the primary is down',
    { timeout: 300_000 },
    async () => {
      const offset = await maillogOffset();
      const rcpt = `iris@${google.name}`;
      await stopSink('sink-google'); // aspmx.l, alt2–alt4 (172.31.250.27); alt1 (.28) stays up
      try {
        const sent = await sendInbound({
          from: externalSender(),
          to: [rcpt],
          subject: 'Routing failover',
        });
        const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
        const [delivered] = await waitForAllDeliveries(
          fx.prisma,
          org,
          message.id,
          ['delivered'],
          1,
          180_000,
        );
        expect(delivered!.remoteHost).toContain('alt1.aspmx.l.google.com');
        expect(await sinkFiles(rcpt, 'sink-google-alt')).toHaveLength(1);
        const lines = await maillogForQueueId(offset, delivered!.outboundQueueId!);
        expect(
          lines.some((l) =>
            /relay=alt1\.aspmx\.l\.google\.com\[172\.31\.250\.28\]:25.*status=sent/.test(l),
          ),
        ).toBe(true);
      } finally {
        await startSink('sink-google');
      }
      // `up --wait` returned: sink-google is healthy again for the suites that follow.
      expect(stopped.has('sink-google')).toBe(false);
    },
  );
});
