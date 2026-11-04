import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DELIVERED_PATH, expectConsistentHistory, pathOf } from './support/lifecycle';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import {
  deliveriesOf,
  signalSideEffects,
  statusEventsOf,
  waitForAllDeliveries,
  waitForMessage,
} from './support/deliveries';
import { startWorker, stopWorker, workerHealth } from './support/delivery-worker';
import { rawLmtp } from './support/lmtp-raw';
import { clearSinkDomain, sinkFiles, sinkMessage } from './support/mail-sink';
import { maillogOffset } from './support/maillog';
import { metricValue } from './support/metrics';
import { MAIL_SINK_HOST, sendingDomain, sleep, submit } from './support/routing';
import { routingStackGate } from './support/routing-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Duplicate and out-of-order status signals (docs/plan/steps/05-routing.md §9 item 7, R9.1):
 * with the worker STOPPED, the status tailer's cursor (`stream_cursors`) is rewound to the byte
 * offset the delivery log had before this test's mail was sent (file identity kept), so the
 * restarted worker re-reads every line of this run a second time, long after the deliveries
 * became terminal; then a captured bounce notice of the same failure is redelivered over LMTP
 * 10052 with the step 2.2 raw-LMTP client. Neither may produce a transition, an `email_events`
 * row, an outbox row, an attempt, a bounce event or a status-history row; the audit trail stays
 * deduplicated. (Step 3.3 L16: rewinding instead of deleting the cursor keeps the re-read
 * independent of the accumulated maillog size.)
 */
const gate = await routingStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let out: FixtureDomain;
let sasl: { username: string; password: string };
const extDomain = () => fx.sinkDomain('signals-ext');
const cursorName = () =>
  `postfix-log:${process.env.DELIVERY_STATUS_LOG_SOURCE_ID ?? 'out.gateway.local'}`;

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('signals');
  out = await sendingDomain(fx, org, 'signals-out');
  await fx.destinations(out, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  sasl = await fx.saslConnector(org, 'signals');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  if (!(await workerHealth('live'))) await startWorker();
  await clearSinkDomain(out.name);
  await clearSinkDomain(extDomain());
  await fx.cleanup();
  await purgeDormantQueues();
}, 180_000);

describe.skipIf(gate.skip)(
  'routing stack: duplicate signals (§9 item 7)',
  { timeout: 300_000 },
  () => {
    it('re-reading the whole delivery log and redelivering a bounce notice change nothing', async () => {
      const sender = `alice@${out.name}`;
      const ok = `ok@${extDomain()}`;
      const bad = `hard-bounce@${extDomain()}`;
      // Every line of this test's mail is written after this offset (the re-read start point).
      const rewindTo = await maillogOffset();
      const sent = await submit({
        credentials: sasl,
        from: sender,
        to: [ok, bad],
        subject: 'Routing duplicate signals',
      });
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered', 'bounced'], 2);
      // Wait for every signal of this message: the DSN binding, the bounce notice, the aggregate.
      await waitFor('the bounce notice signal and the DSN record', async () => {
        const rows = await deliveriesOf(fx.prisma, org, message.id);
        const bounced = rows.find((d) => d.address === bad);
        if (!bounced?.dsnQueueId) return false;
        const notices = await fx.prisma.deliveryStatusEvent.count({
          where: { deliveryId: bounced.id, source: 'bounce_notice' },
        });
        const msg = await fx.prisma.emailMessage.findFirstOrThrow({ where: { id: message.id } });
        return notices > 0 && msg.status === 'delivered' && msg.statusReason === 'delivery_partial';
      });
      // Step 3.3 (L9, E23): one delivered, one bounced → delivered/delivery_partial.
      expect(await pathOf(fx.prisma, message)).toEqual(
        DELIVERED_PATH('delivered', 'delivery_partial'),
      );
      await expectConsistentHistory(fx.prisma, message);
      const dsnFile = await waitFor(
        'the DSN at the sender domain',
        async () => (await sinkFiles(sender))[0],
        {
          timeoutMs: 90_000,
        },
      );
      const capturedNotice = await sinkMessage(dsnFile);
      await sleep(3_000); // the tailer is past every line of this message

      const before = await signalSideEffects(fx.prisma, [org]);
      const deliveriesBefore = await deliveriesOf(fx.prisma, org, message.id);
      const messageBefore = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.id },
      });
      const logSize = await maillogOffset();

      // 1. Re-read this run's lines: worker stopped, cursor rewound (same file identity), worker
      //    started; it must pass the check-point offset again.
      await stopWorker();
      try {
        const cursor = await fx.prisma.streamCursor.findUniqueOrThrow({
          where: { name: cursorName() },
        });
        expect(cursor.fileId).not.toBeNull();
        const rewound = await fx.prisma.streamCursor.updateMany({
          where: { name: cursorName(), fileId: cursor.fileId },
          data: { fileOffset: BigInt(rewindTo) },
        });
        expect(rewound.count).toBe(1);
      } finally {
        await startWorker();
      }
      const reReadStarted = Date.now();
      await waitFor(
        "the status tailer to re-read this run's part of the delivery log",
        async () => {
          const cursor = await fx.prisma.streamCursor.findUnique({ where: { name: cursorName() } });
          return cursor !== null && Number(cursor.fileOffset ?? 0) >= logSize;
        },
        { timeoutMs: 60_000, intervalMs: 500 },
      );
      // Bounded by this run's lines, not by the size of the accumulated log.
      expect(Date.now() - reReadStarted).toBeLessThan(30_000);
      // The restarted worker saw this run's lines again and found them all known.
      expect(
        await metricValue('delivery-worker', 'delivery_status_signals_total', {
          source: 'postfix_log',
          result: 'duplicate',
        }),
      ).toBeGreaterThan(0);

      // 2. Redeliver the captured notice of the same failure (same X-Postfix-Queue-ID,
      //    Original-Envelope-Id, recipient, status and arrival date) over LMTP 10052.
      const duplicatesBefore = await metricValue('smtp-adapter', 'smtp_bounce_notices_total', {
        outcome: 'duplicate',
      });
      const replies = await rawLmtp({
        host: gate.adapterHost,
        port: 10052,
        lhlo: process.env.POSTFIX_OUTBOUND_MYHOSTNAME ?? 'out.gateway.local',
        xforward: [],
        from: '',
        to: [`bounce-notices@${process.env.POSTFIX_BOUNCE_DOMAIN ?? 'bounces.gateway.internal'}`],
        message: capturedNotice,
      });
      expect(replies.get('DATA-END#0')).toMatch(/^250 /);
      await waitFor(
        'the adapter to count the duplicate notice',
        async () =>
          (await metricValue('smtp-adapter', 'smtp_bounce_notices_total', {
            outcome: 'duplicate',
          })) > duplicatesBefore,
      );
      await sleep(5_000);

      // Nothing changed: no transition, no email_events/outbox/attempt/bounce/history row.
      expect(await signalSideEffects(fx.prisma, [org])).toEqual(before);
      const deliveriesAfter = await deliveriesOf(fx.prisma, org, message.id);
      expect(
        deliveriesAfter.map((d) => [
          d.address,
          d.status,
          d.attemptCount,
          d.lastSignalAt?.getTime(),
        ]),
      ).toEqual(
        deliveriesBefore.map((d) => [
          d.address,
          d.status,
          d.attemptCount,
          d.lastSignalAt?.getTime(),
        ]),
      );
      const messageAfter = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.id },
      });
      expect([messageAfter.status, messageAfter.statusReason, messageAfter.version]).toEqual([
        messageBefore.status,
        messageBefore.statusReason,
        messageBefore.version,
      ]);
      expect(await pathOf(fx.prisma, message)).toEqual(
        DELIVERED_PATH('delivered', 'delivery_partial'),
      );
      // The audit trail has one row per distinct signal key (deduplicated by the unique key).
      const audit = await statusEventsOf(fx.prisma, org, message.id);
      const keys = audit.map((e) => `${e.deliveryId.toString()}|${e.signalKey}`);
      expect(new Set(keys).size).toBe(keys.length);
      expect(audit.filter((e) => e.toStatus === 'delivered' && e.applied)).toHaveLength(1);
      expect(audit.filter((e) => e.toStatus === 'bounced' && e.applied)).toHaveLength(1);
    });
  },
);
