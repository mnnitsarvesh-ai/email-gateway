import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import {
  atoOrganization,
  deleteAtoRows,
  purgeAtoQueues,
  requestAndApprove,
  rollback,
  saveAtoSettings,
  settleSettingsCache,
  waitForConnectorAccount,
  waitForIncident,
  waitForMailboxAccount,
  waitForSignals,
} from './support/ato';
import { ManagementApi, purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { stack } from './support/env';
import { buildMessage } from './support/messages';
import { platformAdminSession, type PlatformAdminSession } from './support/platform-admin';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { swaks, toolsAddresses, type SwaksOptions } from './support/smtp-tools';

/**
 * Step 8.4 account takeover through the real stack (docs/plan/steps/24-account-takeover-core.md
 * §10.5 `ato-smtp`, D4, D13, D14): SASL telemetry from the smtp-adapter (after the reply) through
 * the outbox, the event-relay and `ato.events` to the ato-worker; outbound rounds through
 * `ato.mail`; the incident policy, approvals by a second MFA analyst through the api, and the two
 * enforcement points of the smtp-adapter (sending restriction at RCPT, authentication block in the
 * SASL service), lifted by roll-back.
 *
 * Organizations S (ATO on, tenant thresholds lowered so the short test traffic is enough: A1 at 3
 * failures, A2 after 2, O1 at 10 messages an hour, incident threshold 35, learning off) and T
 * (another tenant). Recipients are dns-sink domains (mail-sink).
 *
 * Deviation (§13 WP6): the client of `postfix-outbound` is the `smtp-tools` container on the
 * Compose network (a private address). The ato-worker looks up and counts only routable client
 * addresses (WP4 deviation 3, D7), so a platform `ip` indicator for that address cannot raise T1
 * here; the suite asserts that the private address is not looked up (no reputation stored) and
 * T1 is covered by the worker integration suite with the documentation-range test seam.
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();
const orgs: Array<{ id: bigint; slug: string }> = [];
let orgS: { id: bigint; slug: string };
let orgT: { id: bigint; slug: string };
let outS: FixtureDomain;
let outT: FixtureDomain;
let saslS: { username: string; password: string };
let saslT: { username: string; password: string };
let analyst: ApiSession | undefined;
let approver: ApiSession | undefined;
let admin: ApiSession | undefined;
let platform: PlatformAdminSession | undefined;
let sink = '';
const indicatorIds: string[] = [];
let toolsIps: string[] = [];

function submit(
  credentials: { username: string; password: string },
  options: Omit<SwaksOptions, 'server' | 'port' | 'auth' | 'tls'>,
) {
  return swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: { username: credentials.username, password: credentials.password },
    ...options,
  });
}

function send(
  credentials: { username: string; password: string },
  from: string,
  subject: string,
  body?: string,
) {
  const to = [`rcpt@${sink}`];
  return submit(credentials, { from, to, data: buildMessage({ from, to, subject, body }).text });
}

const rcptCode = (result: Awaited<ReturnType<typeof swaks>>) => result.replies.get('RCPT#0')?.code;
const authCode = (result: Awaited<ReturnType<typeof swaks>>) => result.replies.get('AUTH')?.code;

/** Retries until the SMTP answer matches (restriction caches expire within 15 s, D14). */
async function untilRcpt(
  credentials: { username: string; password: string },
  from: string,
  code: number,
): Promise<Awaited<ReturnType<typeof swaks>>> {
  let last: Awaited<ReturnType<typeof swaks>> | undefined;
  for (let i = 0; i < 20; i += 1) {
    last = await submit(credentials, { from, to: [`rcpt@${sink}`], quitAfter: 'RCPT' });
    if (rcptCode(last) === code) return last;
    await new Promise((r) => setTimeout(r, 2_000));
  }
  throw new Error(`RCPT of ${from} answered ${rcptCode(last!)}; expected ${code}`);
}

async function untilAuth(code: number): Promise<void> {
  let last = 0;
  for (let i = 0; i < 20; i += 1) {
    last = authCode(await submit(saslS, { quitAfter: 'AUTH' })) ?? 0;
    if (last === code) return;
    await new Promise((r) => setTimeout(r, 2_000));
  }
  throw new Error(`AUTH answered ${last}; expected ${code}`);
}

beforeAll(async () => {
  assertStackReady(gate);
  toolsIps = await toolsAddresses();
  for (const ip of toolsIps) fx.trackClientIp(ip);
  await fx.forgetConnectorCache(toolsIps);
  orgS = await atoOrganization(fx, 'ato-s');
  orgT = await atoOrganization(fx, 'ato-t');
  orgs.push(orgS, orgT);
  outS = await fx.domain(orgS.id, 'ato-s', { outboundEnabled: true });
  outT = await fx.domain(orgT.id, 'ato-t', { outboundEnabled: true });
  await fx.dkimKey(outS);
  await fx.dkimKey(outT);
  await fx.dkimSync();
  saslS = await fx.saslConnector(orgS.id, 'ato-s');
  saslT = await fx.saslConnector(orgT.id, 'ato-t');
  sink = fx.sinkDomain('ato');
  analyst = await apiSession(fx.prisma, orgS, 'security_analyst');
  approver = await apiSession(fx.prisma, orgS, 'security_analyst', { mfa: true });
  admin = await apiSession(fx.prisma, orgS, 'organization_admin');
  platform = await platformAdminSession(fx.prisma);
  await saveAtoSettings(admin, {
    mode: 'monitor',
    learningDays: 0,
    scoring: { incidentThreshold: 35, weakOnlyCap: 30 },
    rules: {
      'ato.auth.bruteforce': { params: { failures: 3, windowMinutes: 15 } },
      'ato.auth.success_after_failures': { params: { failures: 2, windowMinutes: 30 } },
      'ato.outbound.volume_spike': { params: { immaturePerHour: 10 } },
    },
  });
  await settleSettingsCache();
}, 300_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const id of indicatorIds) {
    await platform?.call(
      'DELETE',
      `/platform/threat-indicators/${id}?reason=stack%20test%20cleanup`,
    );
  }
  for (const s of [analyst, approver, admin]) await s?.remove();
  await platform?.remove();
  const queue = await listQueue('postfix-outbound');
  await deleteQueued(
    'postfix-outbound',
    involving(queue, [outS?.name, outT?.name, sink].filter(Boolean)).map((m) => m.queue_id),
  );
  await deleteAtoRows(
    fx.prisma,
    orgs.map((o) => o.id),
  );
  await fx.cleanup();
  await purgeAtoQueues(mgmt, vhost);
  await purgeDormantQueues(mgmt, vhost);
  await fx.prisma.$disconnect();
}, 300_000);

describe.skipIf(gate.skip)(
  'ato stack: SMTP telemetry, incidents, enforcement',
  { timeout: 900_000 },
  () => {
    let connectorAccountId = 0n;
    let connectorIncident = '';

    it('(1) wrong SASL passwords (535) then a success: A1 + A2 on the connector account open an incident', async () => {
      for (let i = 0; i < 3; i += 1) {
        const failed = await submit(
          { username: saslS.username, password: `${saslS.password}x` },
          { quitAfter: 'AUTH' },
        );
        expect(authCode(failed)).toBe(535);
      }
      const ok = await send(saslS, `mailbox1@${outS.name}`, 'ATO stack 1');
      expect(authCode(ok)).toBe(235);
      expect(rcptCode(ok)).toBe(250);
      expect(ok.queueId).toBeTruthy();
      const { account } = await waitForConnectorAccount(fx.prisma, orgS.id, saslS.username);
      connectorAccountId = account.id;
      const signals = await waitForSignals(fx.prisma, orgS.id, account.id, [
        'ato.auth.bruteforce',
        'ato.auth.success_after_failures',
      ]);
      expect(signals.every((s) => s.status === 'active')).toBe(true);
      const incident = await waitForIncident(fx.prisma, orgS.id, account.id);
      expect(incident).toMatchObject({ category: 'account_takeover', subjectType: 'ato_account' });
      connectorIncident = incident.publicId;
      // Auth events: the failures and the success, with the private client address and no lookup.
      const events = await fx.prisma.atoAuthEvent.findMany({
        where: { organizationId: orgS.id, accountId: account.id },
        select: { outcome: true, ipAddress: true, reputation: true, source: true },
      });
      expect(events.filter((e) => e.outcome === 'failure').length).toBeGreaterThanOrEqual(3);
      expect(events.some((e) => e.outcome === 'success')).toBe(true);
      expect(events.every((e) => e.source === 'smtp_auth')).toBe(true);
      expect(events.every((e) => e.reputation === null)).toBe(true);
      // The api shows the incident with the connector as subject.
      const read = await analyst!.get(`/incidents/${connectorIncident}`);
      expect(read.status).toBe(200);
      expect(read.body).toMatchObject({ category: 'account_takeover', status: 'open' });
    });

    it('(2) a platform ip indicator for the private client address is not looked up (D7, deviation)', async () => {
      const added = await platform!.call(
        'POST',
        '/platform/threat-indicators',
        {
          type: 'ip',
          value: toolsIps[0]!,
          severity: 'high',
          category: 'malware',
          reason: 'stack test ATO',
        },
        idempotencyKey(),
      );
      expect([201, 400]).toContain(added.status);
      if (added.status === 201) indicatorIds.push(added.body.id as string);
      const ok = await send(saslS, `mailbox1@${outS.name}`, 'ATO stack 2');
      expect(authCode(ok)).toBe(235);
      await new Promise((r) => setTimeout(r, 5_000));
      const t1 = await fx.prisma.atoRiskSignal.count({
        where: { organizationId: orgS.id, ruleCode: 'ato.ti.malicious_ip_success' },
      });
      expect(t1).toBe(0);
    });

    it('(3) a mailbox restriction approved by a second MFA analyst: 550 5.7.1 at RCPT, others unaffected, roll back → 250', async () => {
      const mailbox = await waitForMailboxAccount(fx.prisma, orgS.id, `mailbox1@${outS.name}`);
      const opened = await analyst!.post(
        '/incidents',
        {
          category: 'account_takeover',
          subject: { type: 'ato_account', id: mailbox.publicId },
          severity: 'high',
          reason: 'stack test: the user reported phishing sent from the mailbox',
        },
        idempotencyKey(),
      );
      expect(opened.status, JSON.stringify(opened.body)).toBe(201);
      const incidentId = (opened.body as { id: string }).id;
      const action = await requestAndApprove(analyst!, approver!, incidentId, {
        actionType: 'restrict_smtp_sending',
        durationMinutes: 60,
        mode: 'reject',
        reason: 'stack test: stop the mailbox sending',
      });
      expect(action.status).toBe('succeeded');
      const restriction = await waitFor(
        'the active send_block',
        () =>
          fx.prisma.atoSmtpRestriction
            .findFirst({ where: { organizationId: orgS.id, kind: 'send_block', status: 'active' } })
            .then((r) => r ?? undefined),
        { timeoutMs: 30_000 },
      );
      expect(restriction.scope).toBe('mailbox');
      const blocked = await untilRcpt(saslS, `mailbox1@${outS.name}`, 550);
      expect(blocked.replies.get('RCPT#0')?.text).toMatch(
        /^550 5\.7\.1 .*Sending temporarily restricted by security policy/,
      );
      expect(
        rcptCode(
          await submit(saslS, {
            from: `mailbox2@${outS.name}`,
            to: [`rcpt@${sink}`],
            quitAfter: 'RCPT',
          }),
        ),
      ).toBe(250);
      expect(
        rcptCode(
          await submit(saslT, {
            from: `mailbox1@${outT.name}`,
            to: [`rcpt@${sink}`],
            quitAfter: 'RCPT',
          }),
        ),
      ).toBe(250);
      await rollback(approver!, action.id);
      await untilRcpt(saslS, `mailbox1@${outS.name}`, 250);
      const lifted = await fx.prisma.atoSmtpRestriction.findUniqueOrThrow({
        where: { id: restriction.id },
      });
      expect(lifted.status).toBe('lifted');
    });

    it('(4) an authentication block on the connector: 535 with the right password; lifted → 235', async () => {
      expect(connectorAccountId).not.toBe(0n);
      const action = await requestAndApprove(analyst!, approver!, connectorIncident, {
        actionType: 'block_smtp_auth',
        durationMinutes: 60,
        reason: 'stack test: block the relay credential',
      });
      expect(action.status).toBe('succeeded');
      await untilAuth(535);
      // Recorded as `blocked` telemetry (not a wrong password), indistinguishable to the client.
      await waitFor('a blocked auth event', async () =>
        (await fx.prisma.atoAuthEvent.count({
          where: { organizationId: orgS.id, accountId: connectorAccountId, outcome: 'blocked' },
        })) > 0
          ? true
          : undefined,
      );
      await rollback(approver!, action.id);
      await untilAuth(235);
    });

    it('(5) outbound volume above the tenant threshold raises O1 on the mailbox', async () => {
      const from = `bulk@${outS.name}`;
      for (let i = 0; i < 11; i += 1) {
        const sent = await send(saslS, from, `ATO volume ${i}`);
        expect(rcptCode(sent)).toBe(250);
      }
      const account = await waitForMailboxAccount(fx.prisma, orgS.id, from);
      await waitForSignals(fx.prisma, orgS.id, account.id, ['ato.outbound.volume_spike'], 180_000);
    });

    it('(6) an outbound message with a known phishing URL through the pipeline raises P1', async () => {
      const host = `login.it-${fx.suffix}-phish.example`;
      const added = await platform!.call(
        'POST',
        '/platform/threat-indicators',
        {
          type: 'domain',
          value: host,
          severity: 'high',
          category: 'phishing',
          reason: 'stack test ATO P1',
        },
        idempotencyKey(),
      );
      expect(added.status, JSON.stringify(added.body)).toBe(201);
      indicatorIds.push(added.body.id as string);
      const from = `phisher@${outS.name}`;
      const sent = await send(
        saslS,
        from,
        'Verify your account',
        `Please sign in at https://${host}/verify today.`,
      );
      expect(rcptCode(sent)).toBe(250);
      const account = await waitForMailboxAccount(fx.prisma, orgS.id, from);
      const [p1] = await waitForSignals(
        fx.prisma,
        orgS.id,
        account.id,
        ['ato.content.phishing_sent'],
        180_000,
      );
      expect(p1!.strength).toBe('strong');
      const incident = await waitForIncident(fx.prisma, orgS.id, account.id);
      expect(incident.severity).toMatch(/high|critical/);
    });
  },
);
