import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import {
  atoOrganization,
  deleteAtoRows,
  purgeAtoQueues,
  saveAtoSettings,
  settleSettingsCache,
  waitForMailboxAccount,
} from './support/ato';
import { ManagementApi, purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { stack } from './support/env';
import { buildMessage } from './support/messages';
import {
  createAndPublishPolicy,
  expectPolicyHeld,
  waitForEvaluation,
  type EvaluationRow,
} from './support/policy';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { waitForEntries, waitForReleaseOutcome } from './support/quarantine';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { swaks } from './support/smtp-tools';

/**
 * Step 8.4 ATO risk fields in the policy language through the real stack (§10.5 `ato-policy`,
 * D23, ADR-0073): a tenant policy `ato.risk_level gte high → QUARANTINE` published through the
 * api; an analyst override `compromised` on a synthetic mailbox account; its next outbound
 * message is quarantined by that rule with the `ato-policy-facts/1` block stored on the
 * evaluation; another mailbox of the tenant is delivered (facts: low); an organization without
 * ATO delivers with no facts; the held message is released through the step 5.3 workflow.
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();
let orgP: { id: bigint; slug: string };
let orgN: { id: bigint; slug: string };
let outP: FixtureDomain;
let outN: FixtureDomain;
let saslP: { username: string; password: string };
let saslN: { username: string; password: string };
let analyst: ApiSession | undefined;
let admin: ApiSession | undefined;
let sink = '';
const RULE = 'ato-hold-high';

async function sendOutbound(
  credentials: { username: string; password: string },
  organizationId: bigint,
  from: string,
  subject: string,
) {
  const to = [`rcpt@${sink}`];
  const result = await swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: credentials,
    from,
    to,
    data: buildMessage({ from, to, subject }).text,
  });
  expect(result.queueId, result.transcript.slice(-400)).toBeTruthy();
  const row = await waitFor(
    `email_messages row for ${result.queueId!}`,
    () =>
      fx.prisma.emailMessage
        .findFirst({ where: { organizationId, mtaQueueId: result.queueId! } })
        .then((r) => r ?? undefined),
    { timeoutMs: 60_000 },
  );
  return { id: row.id, receivedAt: row.receivedAt, publicId: '' };
}

const factsOf = (row: EvaluationRow) => row.atoFacts as Record<string, unknown> | null;

beforeAll(async () => {
  assertStackReady(gate);
  orgP = await atoOrganization(fx, 'atop');
  orgN = await atoOrganization(fx, 'aton', false);
  outP = await fx.domain(orgP.id, 'atop', { outboundEnabled: true });
  outN = await fx.domain(orgN.id, 'aton', { outboundEnabled: true });
  await fx.dkimKey(outP);
  await fx.dkimKey(outN);
  await fx.dkimSync();
  saslP = await fx.saslConnector(orgP.id, 'atop');
  saslN = await fx.saslConnector(orgN.id, 'aton');
  sink = fx.sinkDomain('atop');
  analyst = await apiSession(fx.prisma, orgP, 'security_analyst');
  admin = await apiSession(fx.prisma, orgP, 'organization_admin');
  await saveAtoSettings(admin, { mode: 'monitor', learningDays: 0 });
  await settleSettingsCache();
  const published = await createAndPublishPolicy(admin, admin, 'ATO hold (stack test)', {
    dslVersion: 'policy-dsl/1',
    direction: 'outbound',
    priority: 10,
    rules: [
      {
        id: RULE,
        priority: 0,
        when: { all: [{ field: 'ato.risk_level', op: 'gte', value: 'high' }] },
        actions: [{ type: 'QUARANTINE' }],
      },
    ],
  });
  expect(published.policyId).toBeTruthy();
}, 300_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const s of [analyst, admin]) await s?.remove();
  const queue = await listQueue('postfix-outbound');
  await deleteQueued(
    'postfix-outbound',
    involving(queue, [outP?.name, outN?.name, sink].filter(Boolean)).map((m) => m.queue_id),
  );
  await deleteAtoRows(
    fx.prisma,
    [orgP?.id, orgN?.id].filter((x): x is bigint => Boolean(x)),
  );
  await fx.cleanup();
  await purgeAtoQueues(mgmt, vhost);
  await purgeDormantQueues(mgmt, vhost);
  await fx.prisma.$disconnect();
}, 300_000);

describe.skipIf(gate.skip)(
  'ato stack: policy facts at the delivery gate',
  { timeout: 900_000 },
  () => {
    it('a compromised mailbox is quarantined by the tenant rule with the facts stored; others deliver; release works', async () => {
      // First messages create the two mailbox accounts (the ato-worker's outbound handler).
      const riskyFrom = `ceo@${outP.name}`;
      const otherFrom = `staff@${outP.name}`;
      const first = await sendOutbound(saslP, orgP.id, riskyFrom, 'ATO policy warm-up 1');
      await sendOutbound(saslP, orgP.id, otherFrom, 'ATO policy warm-up 2');
      const warm = await waitForEvaluation(fx.prisma, first);
      expect(warm.disposition).toBe('allow');
      expect(factsOf(warm)).toMatchObject({ version: 'ato-policy-facts/1', riskLevel: 'low' });
      const risky = await waitForMailboxAccount(fx.prisma, orgP.id, riskyFrom);
      await waitForMailboxAccount(fx.prisma, orgP.id, otherFrom);

      // The analyst marks the account compromised (rescored at once: score ≥ 90, critical).
      const override = await analyst!.put(
        `/ato/accounts/${risky.publicId}/override`,
        {
          verdict: 'compromised',
          reason: 'stack test: confirmed phishing kit on the laptop',
          expiresInHours: 24,
        },
        idempotencyKey(),
      );
      expect(override.status, JSON.stringify(override.body)).toBe(200);
      expect(override.body).toMatchObject({ riskLevel: 'critical' });

      const held = await sendOutbound(saslP, orgP.id, riskyFrom, 'ATO policy held');
      const row = await expectPolicyHeld(fx.prisma, held, { min: 'quarantine' });
      expect(row).toMatchObject({
        disposition: 'quarantine',
        decisionSource: 'tenant_rule',
        decisiveRuleId: RULE,
      });
      expect(factsOf(row)).toMatchObject({
        version: 'ato-policy-facts/1',
        accountKnown: true,
        riskLevel: 'critical',
      });
      expect(Number(factsOf(row)!.riskScore)).toBeGreaterThanOrEqual(90);
      // No address in the stored facts.
      expect(JSON.stringify(factsOf(row))).not.toContain('@');

      const delivered = await sendOutbound(saslP, orgP.id, otherFrom, 'ATO policy delivered');
      const ok = await waitForEvaluation(fx.prisma, delivered);
      expect(ok.disposition).toBe('allow');
      expect(factsOf(ok)).toMatchObject({ riskLevel: 'low', accountKnown: true });

      const plain = await sendOutbound(saslN, orgN.id, `user@${outN.name}`, 'No ATO tenant');
      const none = await waitForEvaluation(fx.prisma, plain);
      expect(none.disposition).toBe('allow');
      expect(factsOf(none)).toBeNull();

      // Release through the 5.3 workflow (the operator release of a held entry).
      const [entry] = await waitForEntries(fx.prisma, held, 1);
      const release = await admin!.post(
        `/quarantine/entries/${entry!.publicId}/release`,
        { reason: 'stack test: released after the account was cleaned' },
        idempotencyKey(),
      );
      expect(release.status, JSON.stringify(release.body)).toBe(202);
      const releaseId = (release.body as { releaseId: string }).releaseId;
      const logs = await waitForReleaseOutcome(fx.prisma, releaseId);
      expect(logs.length).toBeGreaterThan(0);
    });

    it('the per-round dry-run reproduces the stored evaluation with atoFactsSource "stored"', async () => {
      const message = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { organizationId: orgP.id, subject: 'ATO policy held' },
        select: { id: true, receivedAt: true },
      });
      const identity = await fx.prisma.messageIdentity.findFirstOrThrow({
        where: { id: message.id, organizationId: orgP.id },
        select: { publicId: true },
      });
      const scan = await fx.prisma.emailScan.findFirstOrThrow({
        where: { messageId: message.id, receivedAt: message.receivedAt },
        select: { id: true },
      });
      const dry = await admin!.post(
        `/messages/${identity.publicId}/scans/${scan.id.toString()}/policy/dry-run`,
        { target: 'active' },
        idempotencyKey(),
      );
      expect(dry.status, JSON.stringify(dry.body)).toBe(200);
      expect(dry.body).toMatchObject({ atoFactsSource: 'stored', reproducible: true });
    });
  },
);
