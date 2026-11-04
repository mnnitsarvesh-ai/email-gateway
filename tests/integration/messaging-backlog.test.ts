import { EventTypes } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compose, composeOk, waitFor } from './support/compose';
import { MessagingScenario } from './support/messaging-scenario';
import {
  containerHealth,
  messagingStackGate,
  MIME_LEDGER,
  QUEUES,
  record,
  waitForHealthy,
} from './support/messaging-stack';
import { stack } from './support/env';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Queue backlog and consumer backpressure through the live stack (docs/plan/steps/07-rabbitmq.md
 * §10 "Queue backlog / backpressure", Q16, WP5): the email-worker container is paused
 * (`docker compose pause email-worker`), 500 messages go through postfix:25 and the relay
 * publishes every received event into `email.received` (the backlog builds in the broker, not in
 * the worker); then the worker is unpaused. While it drains, the queue's unacknowledged count
 * (management API, sampled every 250 ms) never exceeds MIME_CONCURRENCY (= the consumer's
 * prefetch) times its consumers, and every message is parsed, planned and delivered exactly once.
 * The per-channel counter of the worker's consumer channel is the exact measure and must stay
 * ≤ prefetch; the queue-level counter is sampled too (WP2 measured it one above the prefetch
 * while acks were in flight, docs/architecture/messaging-topology.md "Client behaviour").
 */
const N = Number(process.env.MESSAGING_BACKLOG_MESSAGES ?? 500);
const PREFETCH = Number(process.env.MIME_CONCURRENCY ?? 4);
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('messaging-backlog', fx);
let paused = false;

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('mq-backlog');
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  if (paused || (await containerHealth('email-worker')).startsWith('paused')) {
    await compose(['unpause', 'email-worker'], { timeoutMs: 60_000 });
  }
  await waitForHealthy('email-worker').catch(() => undefined);
  await scenario.teardown();
}, 300_000);

describe.skipIf(gate.skip)(
  'messaging stack: queue backlog and backpressure',
  { timeout: 1_500_000 },
  () => {
    it(`drains a ${N}-message backlog with at most ${PREFETCH} unacked deliveries`, async () => {
      const vhost = stack.rabbitmqVhost();
      await composeOk(['pause', 'email-worker'], { timeoutMs: 60_000 });
      paused = true;
      const samples: { unacked: number; consumers: number; channelUnacked: number }[] = [];
      const workerUser = process.env.RABBITMQ_EMAIL_WORKER_USER || 'eg-email-worker';
      let backlogReady = 0;
      let drainMs = 0;

      await scenario.run({
        n: N,
        sessions: 20,
        chaos: async (progress) => {
          // Every received event of the run is published (confirmed) while the worker is paused.
          await waitFor(
            `${N} received events published into email.received`,
            async () =>
              (await fx.prisma.messageOutbox.count({
                where: {
                  organizationId: scenario.org,
                  eventType: EventTypes.MessageReceived,
                  publishedAt: { not: null },
                },
              })) === N,
            { timeoutMs: 600_000, intervalMs: 1_000 },
          );
          backlogReady = await scenario.broker.depth(QUEUES.received);
          // At most the paused consumer's prefetch was pushed to it before the pause took effect.
          expect(backlogReady).toBeGreaterThanOrEqual(N - PREFETCH);
          expect((await progress.counts()).mimeLedger).toBe(0);

          await composeOk(['unpause', 'email-worker'], { timeoutMs: 60_000 });
          paused = false;
          const started = Date.now();
          const parsed = async () => {
            const events = await fx.prisma.messageOutbox.findMany({
              where: { organizationId: scenario.org, eventType: EventTypes.MessageReceived },
              select: { eventId: true },
            });
            return fx.prisma.messageIdempotency.count({
              where: { consumer: MIME_LEDGER, eventId: { in: events.map((e) => e.eventId) } },
            });
          };
          for (;;) {
            const q = await scenario.broker.mgmt.queue(vhost, QUEUES.received);
            const channels = (await scenario.broker.mgmt.channels(vhost)).filter(
              (c) => c.user === workerUser && c.consumers > 0,
            );
            samples.push({
              unacked: q.messagesUnacknowledged,
              consumers: q.consumers,
              channelUnacked: Math.max(0, ...channels.map((c) => c.unacked)),
            });
            if ((await parsed()) >= N) break;
            if (Date.now() - started > 600_000) throw new Error('backlog not drained in 600 s');
            await new Promise((r) => setTimeout(r, 250));
          }
          drainMs = Date.now() - started;
        },
      });

      const maxUnacked = Math.max(...samples.map((s) => s.unacked));
      const maxConsumers = Math.max(...samples.map((s) => s.consumers));
      const maxChannelUnacked = Math.max(...samples.map((s) => s.channelUnacked));
      record('messaging-backlog', {
        backlog_ready: backlogReady,
        drain_s: (drainMs / 1000).toFixed(1),
        drain_rate_msg_s: (N / (drainMs / 1000)).toFixed(1),
        samples: samples.length,
        max_queue_unacked: maxUnacked,
        max_channel_unacked: maxChannelUnacked,
        max_consumers: maxConsumers,
        prefetch: PREFETCH,
      });
      expect(samples.length).toBeGreaterThan(0);
      expect(maxConsumers).toBeLessThanOrEqual(1);
      expect(maxChannelUnacked).toBeLessThanOrEqual(PREFETCH);
      expect(maxUnacked).toBeLessThanOrEqual(PREFETCH * Math.max(1, maxConsumers));
    });
  },
);
