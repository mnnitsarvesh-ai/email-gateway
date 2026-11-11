import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { run } from './support/compose';
import { workerHealth } from './support/delivery-worker';
import { MessagingScenario } from './support/messaging-scenario';
import {
  containerHealth,
  containerId,
  messagingStackGate,
  record,
  waitForHealthy,
} from './support/messaging-stack';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Crash between consume and transition (docs/plan/steps/08-message-lifecycle.md L14 row 1, §9
 * "Stack"), as `messaging-consumer-crash` does for the email-worker: messages through
 * postfix:25 while the DELIVERY-WORKER container — the process that applies E20 (planner,
 * `email.delivery.pending` consumer) and derives the delivery states (recorder); until step 5.2
 * also E27 (the dev pass-through, removed: the policy-engine approves since then) — is
 * SIGKILLed with approvals in flight, then started again. A transition commits in the handler's
 * transaction with its ledger row, so a kill rolls both back; the broker redelivers the unacked
 * approvals. `MessagingScenario.run` asserts the exactly-once effects of every stage and, for step
 * 3.3, that every message is `delivered`/`delivery_complete` with exactly one history row per
 * transition (versions 0..7 since the step 4.1 scan hop and the step 5.2 policy hop, distinct transition keys) and one `state_changed` row per applied
 * transition after creation.
 */
const N = Number(process.env.LIFECYCLE_CHAOS_MESSAGES ?? 200);
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('lifecycle-consumer-crash', fx);
let killedId: string | undefined;

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('lc-crash');
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  if (killedId && !(await containerHealth('delivery-worker')).startsWith('running')) {
    await run('docker', ['start', killedId], { timeoutMs: 60_000 });
    await waitForHealthy('delivery-worker').catch(() => undefined);
  }
  await scenario.teardown();
}, 300_000);

describe.skipIf(gate.skip)(
  'lifecycle stack: delivery-worker killed mid-handling',
  { timeout: 1_500_000 },
  () => {
    it(`applies every transition of ${N} messages exactly once across a SIGKILL`, async () => {
      await scenario.run({
        n: N,
        chaos: async (progress) => {
          await progress.planned(Math.floor(N / 4));
          killedId = await containerId('delivery-worker');
          const before = await progress.counts();
          const killed = await run('docker', ['kill', '--signal', 'KILL', killedId], {
            timeoutMs: 60_000,
          });
          expect(killed.exitCode, killed.stderr).toBe(0);
          const killedAt = Date.now();
          expect(before.plannerLedger).toBeLessThan(N);
          await new Promise((r) => setTimeout(r, 5_000));
          if (!(await containerHealth('delivery-worker')).startsWith('running')) {
            const started = await run('docker', ['start', killedId], { timeoutMs: 60_000 });
            expect(started.exitCode, started.stderr).toBe(0);
          }
          await waitForHealthy('delivery-worker', 180_000);
          expect(await workerHealth('ready')).toBe(true);
          record('lifecycle-consumer-crash', {
            planned_before_kill: before.plannerLedger,
            worker_back_after_s: ((Date.now() - killedAt) / 1000).toFixed(1),
          });
        },
      });
    });
  },
);
