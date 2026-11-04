import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  containerHealth,
  containerId,
  messagingStackGate,
  record,
  waitForHealthy,
} from './support/messaging-stack';
import { run } from './support/compose';
import { MessagingScenario } from './support/messaging-scenario';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Consumer crash mid-stream through the live stack (docs/plan/steps/07-rabbitmq.md §10
 * "Consumer crash", WP5): 300 messages through postfix:25 while the email-worker container is
 * SIGKILLed (`docker kill`) with deliveries in flight, then started again. The broker returns
 * the unacked deliveries of the dead connection to `email.received`; handlers that had committed
 * before the kill find their ledger row (duplicate, acked), the others run again. Asserted:
 * exactly-once effects of every stage, no dead letter, every outbox row published.
 */
const N = Number(process.env.MESSAGING_CHAOS_MESSAGES ?? 300);
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('messaging-consumer-crash', fx);
let killedId: string | undefined;

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('mq-crash');
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  if (killedId && !(await containerHealth('email-worker')).startsWith('running')) {
    await run('docker', ['start', killedId], { timeoutMs: 60_000 });
    await waitForHealthy('email-worker').catch(() => undefined);
  }
  await scenario.teardown();
}, 300_000);

describe.skipIf(gate.skip)(
  'messaging stack: email-worker killed mid-stream',
  { timeout: 1_500_000 },
  () => {
    it(`parses ${N} messages exactly once across a SIGKILL of the consumer`, async () => {
      await scenario.run({
        n: N,
        chaos: async (progress) => {
          await progress.parsed(Math.floor(N / 4));
          killedId = await containerId('email-worker');
          const before = await progress.counts();
          const killed = await run('docker', ['kill', '--signal', 'KILL', killedId], {
            timeoutMs: 60_000,
          });
          expect(killed.exitCode, killed.stderr).toBe(0);
          const killedAt = Date.now();
          expect(before.mimeLedger).toBeLessThan(N);
          // Down for a few seconds while the relay keeps publishing into email.received.
          await new Promise((r) => setTimeout(r, 5_000));
          // The restart policy does not apply to a manual kill: start it like an operator would.
          if (!(await containerHealth('email-worker')).startsWith('running')) {
            const started = await run('docker', ['start', killedId], { timeoutMs: 60_000 });
            expect(started.exitCode, started.stderr).toBe(0);
          }
          await waitForHealthy('email-worker', 180_000);
          record('messaging-consumer-crash', {
            parsed_before_kill: before.mimeLedger,
            worker_back_after_s: ((Date.now() - killedAt) / 1000).toFixed(1),
          });
        },
      });
    });
  },
);
