import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { atoMailKey } from '@email-gateway/ato-detection';
import { LEDGERS } from '../src/shared/db';
import { Fixtures, ips, type MessageSpec } from './support/fixtures';
import { Clock, harness, type Harness } from './support/harness';
import {
  accountOf,
  codes,
  configure,
  deliver,
  deliverMail,
  matureAccount,
} from './support/scenario';

/**
 * Step 8.4 §10.3 outbound scenarios (D6): (7) abnormal volume (immature absolute and mature
 * robust thresholds), (8) unusual recipients (fan-out, new domains, attachment spread, mass
 * subject), phishing and malware sent from an authenticated account, BEC outbound observations,
 * replies without a parent, connector attribution (D4), login → outbound correlation (X1),
 * inbound/null-sender fast paths and (17) live + catch-up of the same message (one effect).
 */
const fx = new Fixtures();
const MIN = 60_000;
const clock = new Clock();
let h: Harness;

const ago = (ms: number) => new Date(clock.now().getTime() - ms);
const hex64 = () => randomBytes(32).toString('hex');

beforeAll(async () => {
  h = await harness(fx, { clock });
});

afterAll(async () => {
  await h?.close();
  await fx.cleanup();
});

async function send(specs: MessageSpec[], organizationId: bigint) {
  const seeded = await fx.messages(organizationId, specs);
  for (const m of seeded) await deliverMail(h, fx.scanned(m));
  return seeded;
}

describe('outbound volume (scenario 7)', () => {
  it('immature account: O1 above 200 messages per hour (absolute threshold)', async () => {
    const org = await fx.organization('vol');
    await configure(h, org.id);
    const sender = `bulk@${org.domain}`;
    const specs = Array.from({ length: 201 }, (_, i) => ({
      sender,
      receivedAt: ago(40 * MIN - i * 5000),
      recipients: [`r${i}@partner.example`],
      domainId: org.domainId,
    }));
    await send(specs, org.id);
    const account = await accountOf(fx, org.id, 'mailbox', sender);
    const signals = await fx.prisma.atoRiskSignal.findMany({
      where: {
        organizationId: org.id,
        accountId: account!.id,
        ruleCode: 'ato.outbound.volume_spike',
      },
    });
    expect(signals).toHaveLength(1);
    expect(signals[0]!.evidence).toMatchObject({ threshold: 200, windowMinutes: 60 });
    expect(signals[0]!.strength).toBe('moderate');
    const day = await fx.prisma.atoAccountActivityDaily.findMany({
      where: { organizationId: org.id, accountId: account!.id },
    });
    expect(day.reduce((s, d) => s + d.messages, 0)).toBe(201);
    // Recipient addresses are never stored: registrable domains and counts only.
    const text = JSON.stringify(day, (_k, v: unknown) =>
      typeof v === 'bigint' ? v.toString() : v,
    );
    expect(text).not.toContain('r1@partner.example');
    expect(text).toContain('partner.example');
  });

  it('mature account: O1 relative, O2 fan-out, O3 new domains, O4 attachment spread, O5 mass subject', async () => {
    const org = await fx.organization('fan');
    await configure(h, org.id);
    const sender = `cfo@${org.domain}`;
    await matureAccount(
      h,
      fx,
      org.id,
      { kind: 'mailbox', address: sender },
      {
        messagesPerDay: 16,
        externalDomains: ['usual-1.example', 'usual-2.example', 'usual-3.example'],
      },
    );
    const attachment = { sha256: hex64(), type: 'application/x-msdownload' };
    const specs = Array.from({ length: 30 }, (_, i) => ({
      sender,
      receivedAt: ago(30 * MIN - i * 30_000),
      recipients: [`victim@target-${i}-${fx.suffix}.example`],
      attachments: [attachment],
      subject: 'Invoice overdue',
      domainId: org.domainId,
    }));
    await send(specs, org.id);
    const account = await accountOf(fx, org.id, 'mailbox', sender);
    const c = await codes(fx, org.id, account!.id);
    for (const code of [
      'ato.outbound.volume_spike',
      'ato.outbound.recipient_fanout',
      'ato.outbound.new_recipient_domains',
      'ato.outbound.attachment_spread',
      'ato.outbound.mass_subject',
    ]) {
      expect(c, code).toContain(code);
    }
    // Deduplicated per UTC clock hour (dedupe bucket `hour`): each fires once per hour however
    // many messages crossed its threshold. The 30 messages span 14.5 minutes ending 15.5 minutes
    // ago, so a run near the top of the hour legitimately spreads them over two buckets.
    const hours = new Set(specs.map((s) => Math.floor(s.receivedAt.getTime() / 3_600_000))).size;
    const fanout = c.filter((x) => x === 'ato.outbound.recipient_fanout').length;
    expect(fanout).toBeGreaterThanOrEqual(1);
    expect(fanout).toBeLessThanOrEqual(hours);
    const o4 = await fx.prisma.atoRiskSignal.findFirst({
      where: {
        organizationId: org.id,
        accountId: account!.id,
        ruleCode: 'ato.outbound.attachment_spread',
      },
    });
    expect(JSON.stringify(o4!.evidence)).not.toContain(attachment.sha256);
  });
});

describe('content sent from an account (P1, P2, P4) and correlation (X1)', () => {
  it('phishing sent → P1 strong → incident with the message linked; X1 after a listed-IP login', async () => {
    const org = await fx.organization('phish');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'sales', org.domain);
    // A success from a platform-feed IP (T1, threat intelligence) on the linked portal account.
    const ip = ips.saoPaulo();
    await fx.indicator('ip', ip, 'high');
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip,
        at: ago(19 * MIN),
      }),
    );
    const [msg] = await send(
      [
        {
          sender: user.email,
          receivedAt: ago(10 * MIN),
          recipients: ['someone@victim.example'],
          verdict: 'malicious',
          reasonCodes: ['url.phishing_high_confidence'],
          domainId: org.domainId,
        },
      ],
      org.id,
    );
    const mailbox = await accountOf(fx, org.id, 'mailbox', user.email);
    const c = await codes(fx, org.id, mailbox!.id);
    expect(c).toContain('ato.content.phishing_sent');
    expect(c).toContain('ato.correlation.login_then_outbound');
    const fresh = await fx.prisma.atoAccount.findUniqueOrThrow({ where: { id: mailbox!.id } });
    expect(fresh.riskScore).toBeGreaterThanOrEqual(60);
    const links = await fx.prisma.securityIncidentLink.findMany({
      where: { organizationId: org.id, incidentId: fresh.activeIncidentId!, linkType: 'message' },
    });
    expect(links.map((l) => l.refId)).toContain(msg!.id);
    // Recommendations include the policy hint (no active ato.* tenant rule) and the restriction.
    const detail = await fx.prisma.atoIncidentDetail.findUniqueOrThrow({
      where: { incidentId: fresh.activeIncidentId! },
    });
    const recs = detail.recommendedActions as Array<{ actionType: string; availability: string }>;
    expect(recs.map((r) => r.actionType)).toEqual(
      expect.arrayContaining([
        'restrict_smtp_sending',
        'alert_tenant_admins',
        'policy_hold_outbound',
      ]),
    );
    expect(recs.find((r) => r.actionType === 'revoke_sessions')?.availability).toBe(
      'requires_provider',
    );
  });

  it('malware sent → P2; BEC observations (bank change) on a mature mailbox → P4', async () => {
    const org = await fx.organization('mal');
    await configure(h, org.id);
    const sender = `ap@${org.domain}`;
    await matureAccount(h, fx, org.id, { kind: 'mailbox', address: sender }, { messagesPerDay: 5 });
    await send(
      [
        {
          sender,
          receivedAt: ago(5 * MIN),
          recipients: ['x@partner.example'],
          verdict: 'malicious',
          reasonCodes: ['attachment.malware'],
          domainId: org.domainId,
        },
      ],
      org.id,
    );
    const account = await accountOf(fx, org.id, 'mailbox', sender);
    expect(await codes(fx, org.id, account!.id)).toContain('ato.content.malware_sent');
    const second = await fx.messages(org.id, [
      {
        sender,
        receivedAt: ago(3 * MIN),
        recipients: ['z@partner.example'],
        domainId: org.domainId,
      },
    ]);
    // The BEC observation row of the round (written by the email-worker in production, D6).
    await fx.prisma.becScanResult.create({
      data: {
        receivedAt: second[0]!.receivedAt,
        messageId: second[0]!.id,
        organizationId: org.id,
        scanId: second[0]!.scanId,
        lifecycleRound: 0,
        engineVersion: 'it',
        rulesVersion: 'it',
        settingsVersion: 'it',
        lexiconVersion: 'it',
        textVersion: 'it',
        deterministicScore: 0,
        score: 0,
        deterministicVerdict: 'skipped',
        verdict: 'skipped',
        inputs: {},
        rules: [],
        durationMs: 1,
        outboundObservations: {
          version: 'bec-outbound-obs/1',
          status: 'complete',
          reason: null,
          categories: { bank_change: 1 },
          financialIdentifiers: { iban: 1, swift: 0, ifsc_account: 0, amount: 0 },
          links: {
            credentialHarvesting: false,
            credentialForm: false,
            lookalike: false,
            malicious: false,
          },
        },
      },
    });
    await deliverMail(h, fx.scanned(second[0]!));
    const c = await codes(fx, org.id, account!.id);
    expect(c).toContain('ato.content.bec_language');
    expect(c).toContain('ato.content.financial_identifiers');
  });

  it('replies whose parent is unknown (O9) after five in an hour', async () => {
    const org = await fx.organization('reply');
    await configure(h, org.id);
    const sender = `re@${org.domain}`;
    await send(
      Array.from({ length: 5 }, (_, i) => ({
        sender,
        receivedAt: ago(10 * MIN - i * 1000),
        recipients: [`p${i}@partner.example`],
        inReplyTo: `<never-seen-${i}-${fx.suffix}@partner.example>`,
        domainId: org.domainId,
      })),
      org.id,
    );
    const account = await accountOf(fx, org.id, 'mailbox', sender);
    expect(await codes(fx, org.id, account!.id)).toContain('ato.outbound.reply_without_parent');
  });
});

describe('connector attribution (D4) and fast paths', () => {
  it('a submission attributes the message to its connector: connector P1 and the mailbox peer', async () => {
    const org = await fx.organization('attr');
    await configure(h, org.id);
    const connector = await fx.connector(org.id, 'app');
    const sender = `noreply@${org.domain}`;
    const queueId = fx.queueId();
    await deliver(
      h,
      fx.smtpSubmission(org.id, [
        { at: ago(6 * MIN), connectorId: connector.id, queueId, clientIp: ips.pune(), sender },
      ]),
    );
    const attribution = await h.comps.windows.submissionAttribution(org.id, queueId);
    expect(attribution?.connectorId).toBe(connector.id.toString());
    await send(
      [
        {
          sender,
          receivedAt: ago(5 * MIN),
          recipients: ['c@victim.example'],
          queueId,
          verdict: 'malicious',
          reasonCodes: ['phishing.known_bad_url'],
          domainId: org.domainId,
        },
      ],
      org.id,
    );
    const conn = await accountOf(fx, org.id, 'smtp_connector', connector.id);
    const mailbox = await accountOf(fx, org.id, 'mailbox', sender);
    expect(await codes(fx, org.id, conn!.id)).toContain('ato.content.phishing_sent');
    expect(await codes(fx, org.id, mailbox!.id)).toContain('ato.content.phishing_sent');
    const day = await fx.prisma.atoAccountActivityDaily.findFirst({
      where: { organizationId: org.id, accountId: mailbox!.id },
    });
    expect(day!.peers).toEqual([{ k: connector.id.toString(), n: 1 }]);
  });

  it('inbound rounds and organizations without ATO are no-op acks (no ledger row); null senders unattributed', async () => {
    const org = await fx.organization('fast');
    await configure(h, org.id);
    const off = await fx.organization('fast-off', { ato: false });
    const [inbound] = await fx.messages(org.id, [
      { sender: 'x@partner.example', direction: 'inbound', receivedAt: ago(MIN), recipients: [] },
    ]);
    await deliverMail(h, fx.scanned(inbound!));
    const [disabled] = await fx.messages(off.id, [
      { sender: `a@${off.domain}`, receivedAt: ago(MIN), recipients: ['b@partner.example'] },
    ]);
    await deliverMail(h, fx.scanned(disabled!));
    for (const m of [inbound!, disabled!]) {
      expect(await h.comps.db.processed(LEDGERS.mail, atoMailKey(m.id, m.scanId))).toBe(false);
    }
    const [bounce] = await fx.messages(org.id, [
      { sender: '', receivedAt: ago(MIN), recipients: ['b@partner.example'] },
    ]);
    await deliverMail(h, fx.scanned(bounce!));
    expect(
      await fx.prisma.atoAccount.count({ where: { organizationId: { in: [org.id, off.id] } } }),
    ).toBe(0);
    expect(
      await h.metric('ato_events_total', {
        source: 'outbound_message',
        result: 'skipped_direction',
      }),
    ).toBeGreaterThan(0);
    expect(
      await h.metric('ato_events_total', { source: 'outbound_message', result: 'skipped_feature' }),
    ).toBeGreaterThan(0);
    expect(
      await h.metric('ato_events_total', { source: 'outbound_message', result: 'unattributed' }),
    ).toBeGreaterThan(0);
  });

  it('live + catch-up of the same message: one effect (scenario 17); catch-up processes missed ones', async () => {
    const org = await fx.organization('catch');
    await configure(h, org.id);
    const sender = `ops@${org.domain}`;
    const seeded = await fx.messages(
      org.id,
      Array.from({ length: 6 }, (_, i) => ({
        sender,
        receivedAt: ago(30 * MIN - i * 1000),
        recipients: [`r${i}@partner.example`],
        domainId: org.domainId,
      })),
    );
    // Three were seen live; three were dropped by the lossy queue.
    for (const m of seeded.slice(0, 3)) await deliverMail(h, fx.scanned(m));
    // The operator enabled the feature an hour ago (catch-up start bound).
    await fx.prisma.organizationFeature.updateMany({
      where: { organizationId: org.id, featureKey: 'ato_detection' },
      data: { updatedAt: ago(60 * MIN) },
    });
    h.comps.orgs.invalidate(org.id);
    const before = await h.metric('ato_mail_catchup_processed_total');
    await h.comps.maintenance.mailCatchup();
    expect(await h.metric('ato_mail_catchup_processed_total')).toBe(before + 3);
    for (const m of seeded) {
      expect(await h.comps.db.processed(LEDGERS.mail, atoMailKey(m.id, m.scanId))).toBe(true);
    }
    // A redelivery after the catch-up is a duplicate; a second catch-up pass does nothing.
    await expect(deliverMail(h, fx.scanned(seeded[4]!))).resolves.toBe('duplicate');
    await h.comps.maintenance.mailCatchup();
    expect(await h.metric('ato_mail_catchup_processed_total')).toBe(before + 3);
    const account = await accountOf(fx, org.id, 'mailbox', sender);
    const days = await fx.prisma.atoAccountActivityDaily.findMany({
      where: { organizationId: org.id, accountId: account!.id },
    });
    expect(days.reduce((s, d) => s + d.messages, 0)).toBe(6);
    const cursor = await fx.prisma.streamCursor.findUnique({
      where: { name: `ato-mail-catchup:${org.id}` },
    });
    expect(cursor?.positionId).toBe(seeded[5]!.id);
  });
});
