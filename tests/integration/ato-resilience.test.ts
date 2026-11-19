import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import {
  atoOrganization,
  deleteAtoRows,
  purgeAtoQueues,
  saveAtoSettings,
  settleSettingsCache,
  waitForMailboxAccount,
} from './support/ato';
import { ManagementApi, purgeDormantQueues } from './support/broker';
import { compose, composeOk, waitFor } from './support/compose';
import { stack } from './support/env';
import { buildMessage } from './support/messages';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { swaks } from './support/smtp-tools';

/**
 * Step 8.4 resilience (§10.5 `ato-resilience`, D3, D8, invariant 9): a burst of outbound
 * messages of one ATO-enabled mailbox while the ato-worker container is SIGKILLed and started
 * again. The mail path never waits for ATO (every submission is accepted while the worker is
 * down); afterwards every message is counted exactly once in the account's daily activity
 * (`processOnce` ledger: redelivered and catch-up events have one effect), no signal is
 * duplicated, and the worker is healthy again.
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();
const BURST = 30;
let org: { id: bigint; slug: string };
let out: FixtureDomain;
let sasl: { username: string; password: string };
let admin: ApiSession | undefined;
let sink = '';

/**
 * postfix-outbound limits AUTH per client to `POSTFIX_CLIENT_AUTH_RATE_LIMIT` (30, shipped
 * default) per `anvil_rate_time_unit` (60 s). The burst alone uses the whole budget of the
 * smtp-tools address, and suites running in parallel authenticate from the same address, so a
 * submission may get the temporary `450 4.7.1 … too many AUTH commands`. A real client retries a
 * 4xx later; the burst does the same after the anvil window (the limit itself is not changed).
 * Stack suites run one after another and the next one may authenticate from the same address at
 * once (`smtp-fail-closed` expects its first AUTH answer to be the SASL one), so `afterAll` waits
 * until the window of the last AUTH has passed: the suite returns the budget it used.
 */
const AUTH_RATE_REPLY = /\b450 4\.7\.1 [^\n]*too many AUTH commands/;
const AUTH_RATE_WINDOW_MS = 65_000;
let lastAuthAt = 0;
async function submitWithinAuthRate(options: Parameters<typeof swaks>[0]) {
  let sent = await swaks(options);
  lastAuthAt = Date.now();
  for (
    let retry = 0;
    retry < 3 && !sent.queueId && AUTH_RATE_REPLY.test(sent.transcript);
    retry++
  ) {
    await new Promise((r) => setTimeout(r, AUTH_RATE_WINDOW_MS));
    sent = await swaks(options);
    lastAuthAt = Date.now();
  }
  return sent;
}

async function ensureWorkerRunning(): Promise<void> {
  await composeOk(['--profile', 'apps', 'up', '-d', '--no-deps', '--wait', 'ato-worker']);
}

beforeAll(async () => {
  assertStackReady(gate);
  org = await atoOrganization(fx, 'ato-res');
  out = await fx.domain(org.id, 'ato-res', { outboundEnabled: true });
  await fx.dkimKey(out);
  await fx.dkimSync();
  sasl = await fx.saslConnector(org.id, 'ato-res');
  sink = fx.sinkDomain('ato-res');
  admin = await apiSession(fx.prisma, org, 'organization_admin');
  await saveAtoSettings(admin, { mode: 'monitor', learningDays: 0 });
  await settleSettingsCache();
  await ensureWorkerRunning();
}, 300_000);

afterAll(async () => {
  if (gate.skip) return;
  await ensureWorkerRunning();
  await admin?.remove();
  const queue = await listQueue('postfix-outbound');
  await deleteQueued(
    'postfix-outbound',
    involving(queue, [out?.name, sink].filter(Boolean)).map((m) => m.queue_id),
  );
  await deleteAtoRows(fx.prisma, org ? [org.id] : []);
  await fx.cleanup();
  await purgeAtoQueues(mgmt, vhost);
  await purgeDormantQueues(mgmt, vhost);
  await fx.prisma.$disconnect();
  // Return the shared AUTH budget of the smtp-tools address before the next suite runs.
  const authWindowLeft = lastAuthAt + AUTH_RATE_WINDOW_MS - Date.now();
  if (lastAuthAt > 0 && authWindowLeft > 0) {
    await new Promise((r) => setTimeout(r, authWindowLeft));
  }
}, 300_000);

describe.skipIf(gate.skip)('ato stack: worker killed during a burst', { timeout: 900_000 }, () => {
  it('SIGKILL mid-burst, restart: every message counted once, no duplicate signal', async () => {
    const from = `burst@${out.name}`;
    const accepted: string[] = [];
    for (let i = 0; i < BURST; i += 1) {
      if (i === 10) {
        // The worker dies with events in flight; the mail path must not notice.
        const killed = await compose(['kill', '-s', 'SIGKILL', 'ato-worker']);
        expect(killed.exitCode).toBe(0);
      }
      const to = [`rcpt${i}@${sink}`];
      const sent = await submitWithinAuthRate({
        server: 'postfix-outbound',
        port: 587,
        tls: true,
        auth: sasl,
        from,
        to,
        data: buildMessage({ from, to, subject: `ATO burst ${i}` }).text,
      });
      expect(sent.queueId, sent.transcript.slice(-300)).toBeTruthy();
      accepted.push(sent.queueId!);
    }
    expect(accepted).toHaveLength(BURST);
    await ensureWorkerRunning();

    const account = await waitForMailboxAccount(fx.prisma, org.id, from, 300_000);
    const counted = await waitFor(
      `${BURST} messages counted for the account`,
      async () => {
        const days = await fx.prisma.atoAccountActivityDaily.findMany({
          where: { organizationId: org.id, accountId: account.id },
          select: { messages: true },
        });
        const total = days.reduce((n, d) => n + Number(d.messages), 0);
        return total >= BURST ? total : undefined;
      },
      { timeoutMs: 600_000, intervalMs: 2_000 },
    );
    // Exactly once: a redelivered or caught-up event never counts twice.
    expect(counted).toBe(BURST);
    await new Promise((r) => setTimeout(r, 10_000));
    const again = await fx.prisma.atoAccountActivityDaily.findMany({
      where: { organizationId: org.id, accountId: account.id },
      select: { messages: true },
    });
    expect(again.reduce((n, d) => n + Number(d.messages), 0)).toBe(BURST);
    // No duplicated signal (one row per rule code and dedupe window).
    const signals = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org.id, accountId: account.id },
      select: { ruleCode: true, dedupeKey: true },
    });
    const keys = signals.map((s) => `${s.ruleCode}|${s.dedupeKey}`);
    expect(new Set(keys).size).toBe(keys.length);
    // The worker is healthy again.
    const health = await fetch(
      `http://${stack.host}:${process.env.ATO_WORKER_HOST_PORT ?? 3085}/health/ready`,
    );
    expect(health.ok).toBe(true);
  });
});
