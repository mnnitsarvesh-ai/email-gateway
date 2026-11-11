import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { composeOk } from './support/compose';
import { MessagingScenario } from './support/messaging-scenario';
import { messagingStackGate, record, waitForHealthy } from './support/messaging-stack';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * RabbitMQ restart mid-stream through the live stack (docs/plan/steps/07-rabbitmq.md §10
 * "RabbitMQ restart mid-stream", WP5): 300 messages through postfix:25 while
 * `docker compose restart rabbitmq` runs twice — once while received events flow (relay →
 * `email.received` → email-worker), once while approvals flow (policy-engine, step 5.2 → relay →
 * `email.delivery.pending` → planner). Every client reconnects by itself (no process exits);
 * unconfirmed relay publishes stay unpublished and are republished; unacked deliveries return to
 * their queue. Asserted: every message parsed exactly once (one parse row, one
 * `email-worker.mime-parser` ledger row, one parse event), approved and planned exactly once (one
 * planner ledger row, one delivery, one reinjection group), delivered once to the sink, no dead
 * letter, every outbox row of the run published.
 */
const N = Number(process.env.MESSAGING_CHAOS_MESSAGES ?? 300);
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('messaging-restart', fx);

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('mq-restart');
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await waitForHealthy('rabbitmq').catch(() => undefined);
  await scenario.teardown();
}, 300_000);

async function restartBroker(phase: string): Promise<void> {
  const started = Date.now();
  await composeOk(['restart', 'rabbitmq'], { timeoutMs: 180_000 });
  await waitForHealthy('rabbitmq', 180_000);
  record('messaging-restart', {
    phase,
    broker_restart_s: ((Date.now() - started) / 1000).toFixed(1),
  });
}

describe.skipIf(gate.skip)(
  'messaging stack: RabbitMQ restart mid-stream',
  { timeout: 1_500_000 },
  () => {
    it(`delivers ${N} messages exactly once across two broker restarts`, async () => {
      const counts = await scenario.run({
        n: N,
        chaos: async (progress) => {
          // While received events are being published and consumed.
          await progress.stored(Math.floor(N / 3));
          await restartBroker('ingestion');
          // While approvals are being published and planned.
          await progress.planned(Math.floor(N / 4));
          expect((await progress.counts()).plannerLedger).toBeLessThan(N);
          await restartBroker('delivery');
        },
      });
      expect(counts.delivered).toBe(N);
    });
  },
);
