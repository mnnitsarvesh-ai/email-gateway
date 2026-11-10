import { messageScannedV1 } from '@email-gateway/event-contracts';
import { PrismaClient } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { ManagementApi, purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForAllDeliveries, waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import {
  expectConsistentHistory,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles, SINK_SERVICES } from './support/mail-sink';
import { buildMessage } from './support/messages';
import { metricValue } from './support/metrics';
import { record, sleep } from './support/messaging-stack';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import {
  BEC_LEDGER,
  becResultsOf,
  becRuleCodes,
  engineResultsOf,
  messagePublicId,
  PASSTHROUGH_CONSUMER,
  REQUIRED_ENGINES,
  roundFinalEngines,
  scannedEventsOf,
  scanStackGate,
  sendToMx,
  stageReadyEventsOf,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';

/**
 * The step 4.4 phishing/BEC engine end to end through the inbound Postfix (docs/plan/steps/
 * 12-phishing-bec.md §9 "Stack", B1, B2, B6, B15, B17, B18): smtp-tools → postfix:25 →
 * smtp-adapter → email-worker MIME role → `parsed.v1` → stage 1 (`scan.spam` Rspamd,
 * `scan.attachment`, `scan.url`) → the transaction that inserts the last of the rspamd/url finals
 * writes `mail.message.scan_stage_ready.v1` → event-relay → `scan.bec` → the bec engine (real
 * auth row of the round, url results, stored text parts, the tenant's executive profile created
 * through the api) → round completion → dev pass-through → postfix-outbound → mail-sink.
 *
 * - A fixture organization with an executive profile ("Anita Sharma", known address on the
 *   tenant's domain) created through `POST /api/v1/bec/executives`.
 * - CEO fraud, pretext stage (the executive's display name from a free-mail address: "quick
 *   favour, urgent, keep this confidential"): bec `suspicious` (X1, X2, C7, C8: score over the
 *   malicious threshold but no intent-evidence rule, so B6 caps it at suspicious); the read API
 *   explains it (rules with evidence, the profile's public id); the dev pass-through does NOT
 *   approve it (B17: `delivery_approvals_skipped_total{reason="bec_verdict"}` +1, the message
 *   stays `scanned`, nothing in any sink during the observation window).
 * - CEO fraud, gift-card stage (adds "buy gift cards, send me the codes"): bec `malicious` (X1
 *   identity + C3 intent evidence); the round verdict is then `malicious`, so the pass-through
 *   holds it under the earlier `malicious_verdict` rule (B17 keeps that reason); never delivered.
 * - A legitimate message (no profile match, no cue, authenticated as From): bec `clean`,
 *   approved and delivered.
 * - A Hinglish payment-urgency message ("turant paise transfer karo, kisi ko mat batana"): the
 *   C-codes of the romanized-Hindi lexicon are recorded (C4/C1, C7, C8), never clean.
 * - ≥ 1 consumer on `scan.bec`; one stage trigger and one bec ledger row per round.
 *
 * Every bec row, the profile and the fixture organization are removed in `afterAll` and the
 * removal is verified.
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let session: ApiSession | undefined;
let executiveId = '';
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();

/** The envelope sender: SPF pass from the mailtest network (scan.test zone, step 4.1 S12). */
const ENVELOPE_FROM = 'alice@clean.scan.test';
const EXECUTIVE = 'Anita Sharma';
const FREEMAIL_IMPOSTOR = 'anita.sharma.office@gmail.com';
/** Body sentences the read API must never echo (B15: offsets only, never text). */
const PRETEXT_BODY =
  'Hi, are you at your desk? I need a quick favour from you. It is urgent. ' +
  'Keep this confidential, I am in a meeting and cannot talk now. Reply as soon as possible.';
const GIFT_CARD_BODY =
  'Hi, I need you to buy gift cards for a client presentation today. Keep this confidential, ' +
  'I am in a meeting. It is urgent, send me the codes as soon as possible.';
const HINGLISH_BODY = 'boss ne bola hai turant paise transfer karo, kisi ko mat batana';

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('bec-smtp');
  domain = await fx.domain(org, 'bec-smtp');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  // security_analyst holds bec:read, bec:manage, bec:feedback and message:read (B18).
  session = await apiSession(fx.prisma, await organizationRef(fx, org), 'security_analyst');
  // The profile exists before the first message of the organization, so the worker's tenant
  // data cache (B4 step 3, TTL BEC_TENANT_DATA_CACHE_TTL_MS) never holds a state without it.
  const res = await session.post('/bec/executives', {
    displayName: EXECUTIVE,
    aliases: [],
    knownAddresses: [`anita.sharma@${domain.name}`],
    title: 'Chief Executive Officer',
    enabled: true,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  executiveId = (res.body as { id: string }).id;
  expect(executiveId).toMatch(/^[0-9a-f-]{36}$/);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await session?.remove();
  if (domain) await clearSinkDomain(domain.name, 'all').catch(() => undefined);
  const removed = org;
  await fx.cleanup();
  await purgeDormantQueues();
  if (removed === 0n) return;
  // Verify the cleanup: no bec row, profile or fixture organization is left.
  const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  try {
    const where = { organizationId: removed };
    const left = {
      becScanResults: await prisma.becScanResult.count({ where }),
      becExecutiveProfiles: await prisma.becExecutiveProfile.count({ where }),
      becVendorProfiles: await prisma.becVendorProfile.count({ where }),
      becTrustedSenders: await prisma.becTrustedSender.count({ where }),
      becFeedback: await prisma.becFeedback.count({ where }),
      becSuppressionRules: await prisma.becSuppressionRule.count({ where }),
      becContactHistory: await prisma.becContactHistory.count({ where }),
      organizations: await prisma.organization.count({ where: { id: removed } }),
    };
    expect(left).toEqual({
      becScanResults: 0,
      becExecutiveProfiles: 0,
      becVendorProfiles: 0,
      becTrustedSenders: 0,
      becFeedback: 0,
      becSuppressionRules: 0,
      becContactHistory: 0,
      organizations: 0,
    });
  } finally {
    await prisma.$disconnect();
  }
}, 180_000);

/** Sends a plain-text message through the MX with the trusted envelope of `ENVELOPE_FROM`. */
async function send(local: string, from: string, subject: string, body: string) {
  const rcpt = `${local}@${domain.name}`;
  const built = buildMessage({ from, to: [rcpt], subject, body });
  const started = Date.now();
  const sent = await sendToMx({
    from: ENVELOPE_FROM,
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: built.text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
  const round = await waitForRoundComplete(fx.prisma, message, 0, 180_000);
  const scannedAfterMs = Date.now() - started;
  const finals = (await engineResultsOf(fx.prisma, message)).filter((r) => r.isFinal);
  const becFinal = finals.find((r) => r.engine === 'bec');
  const [becRow, ...moreBec] = await becResultsOf(fx.prisma, message);
  expect(moreBec).toEqual([]);
  return { rcpt, message, round, finals, becFinal, becRow, started, scannedAfterMs };
}

/** Exactly one stage trigger for round 0, consumed once by the bec consumer (B2). */
async function expectOneStageTrigger(message: { id: bigint; receivedAt: Date }, scanId: bigint) {
  const stage = await stageReadyEventsOf(fx.prisma, org, message);
  expect(stage).toHaveLength(1);
  expect(stage[0]!.payload).toMatchObject({
    lifecycleRound: 0,
    scanId: scanId.toString(),
    scanKind: 'initial',
    engine: 'bec',
  });
  expect(
    await fx.prisma.messageIdempotency.count({
      where: { consumer: BEC_LEDGER, eventId: stage[0]!.eventId },
    }),
  ).toBe(1);
}

interface BecRuleView {
  id: string;
  code: string;
  category: string;
  severity: string;
  weight: number;
  suppressed: string | null;
  evidence: Record<string, unknown>[];
}
interface BecEngineView {
  engine: string;
  final: boolean;
  outcome: string | null;
  reasonCodes: string[];
  bec?: {
    verdict: string;
    deterministicVerdict: string;
    score: number;
    deterministicScore: number;
    thresholds: { suspicious: number | null; malicious: number | null };
    inputs: Record<string, string> | null;
    rules: BecRuleView[];
    ai: unknown[];
    aiShadow: unknown[];
  } | null;
}

/** The scans read API (replica) once round 0 is completed: the bec engine entry. */
async function becEngineView(publicId: string): Promise<{ raw: string; engine: BecEngineView }> {
  return waitFor(
    `GET /messages/${publicId}/scans with a completed round and a bec section`,
    async () => {
      const res = await session!.get(`/messages/${publicId}/scans`);
      if (res.status !== 200) return undefined;
      const body = res.body as { data: { status: string; engines: BecEngineView[] }[] };
      const round = body.data[0];
      if (!round || round.status === 'running') return undefined;
      const engine = round.engines.find((e) => e.engine === 'bec');
      return engine?.bec ? { raw: JSON.stringify(res.body), engine } : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 500 },
  );
}

const skippedCounter = (reason: string) =>
  metricValue('delivery-worker', 'delivery_approvals_skipped_total', { reason });

/** The pass-through handled the scanned event (ledger row) and did not approve it. */
async function expectHeld(
  message: { id: bigint; receivedAt: Date },
  rcpt: string,
  reason: string,
  before: number,
): Promise<void> {
  const [scanned] = await scannedEventsOf(fx.prisma, org, message);
  await waitFor(
    `the dev pass-through to hold the message (${reason})`,
    async () => {
      const ledger = await fx.prisma.messageIdempotency.count({
        where: { consumer: PASSTHROUGH_CONSUMER, eventId: scanned!.eventId },
      });
      return ledger === 1 && (await skippedCounter(reason)) >= before + 1;
    },
    { timeoutMs: 60_000, intervalMs: 1_000 },
  );
  // Observation window: nothing is approved or delivered later.
  await sleep(10_000);
  expect(await skippedCounter(reason)).toBe(before + 1);
  expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
    status: 'scanned',
    statusReason: 'scan_complete',
    lifecycleRound: 0,
  });
  expect((await pathOf(fx.prisma, message)).at(-1)).toEqual([
    'scanning',
    'scanned',
    'scan_complete',
  ]);
  const approvals = await fx.prisma.messageOutbox.findMany({
    where: { organizationId: org, eventType: 'mail.delivery.approved.v1' },
    select: { payload: true },
  });
  expect(
    approvals.filter(
      (a) => (a.payload as { messageId?: string }).messageId === message.id.toString(),
    ),
  ).toEqual([]);
  expect(
    await fx.prisma.emailDelivery.count({ where: { organizationId: org, messageId: message.id } }),
  ).toBe(0);
  for (const service of SINK_SERVICES) expect(await sinkFiles(rcpt, service), service).toEqual([]);
  await expectConsistentHistory(fx.prisma, message);
}

describe.skipIf(gate.skip)(
  'bec stack: phishing and BEC engine through Postfix',
  { timeout: 300_000 },
  () => {
    it('scan.bec has a consumer (the stage-2 engine of topology v6)', async () => {
      const details = await mgmt.get<{
        consumers?: number;
        consumer_details?: { channel_details?: { user?: string } }[];
      }>(`/queues/${encodeURIComponent(vhost)}/scan.bec`);
      expect(details.consumers).toBeGreaterThanOrEqual(1);
      const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
      expect(new Set((details.consumer_details ?? []).map((c) => c.channel_details?.user))).toEqual(
        new Set([scanner]),
      );
    });

    it('CEO fraud pretext from a free-mail address: bec suspicious, explained, held by the dev pass-through (bec_verdict)', async () => {
      const before = await skippedCounter('bec_verdict');
      const { rcpt, message, round, finals, becFinal, becRow, scannedAfterMs } = await send(
        'ceo-pretext',
        `"${EXECUTIVE}" <${FREEMAIL_IMPOSTOR}>`,
        'Quick favour',
        PRETEXT_BODY,
      );
      expect(round).toMatchObject({
        status: 'completed',
        requiredEngines: [...REQUIRED_ENGINES],
      });
      expect(roundFinalEngines(finals)).toEqual(['attachment', 'bec', 'dlp', 'rspamd', 'url']);
      expect(round.scanVerdict).not.toBe('malicious');
      expect(becFinal).toMatchObject({ outcome: 'suspicious', errorCode: null, attempt: 1 });
      expect(becFinal!.engineVersion).toMatch(
        /^bec\/1;lex=[0-9a-f]{8};fm=[0-9a-f]{8};br=[0-9a-f]{8}$/,
      );
      expect(becFinal!.reasonCodes as string[]).toEqual(
        expect.arrayContaining([
          'bec.impersonation.executive_name',
          'bec.impersonation.executive_freemail',
          'bec.content.urgency',
          'bec.content.secrecy',
        ]),
      );
      expect(becFinal!.evidence).toMatchObject({ thresholds: { suspicious: 40, malicious: 80 } });
      await expectOneStageTrigger(message, round.id);

      // bec_scan_results: X1 and intent codes, every input available, verdict and versions.
      expect(becRow).toMatchObject({
        organizationId: org,
        scanId: round.id,
        lifecycleRound: 0,
        rulesVersion: 'bec-map/1',
        textVersion: 'bec-text/1',
        verdict: 'suspicious',
        deterministicVerdict: 'suspicious',
        inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
      });
      const fired = becRuleCodes(becRow!.rules);
      expect(fired).toEqual(
        expect.arrayContaining([
          'bec.impersonation.executive_name',
          'bec.impersonation.executive_freemail',
          'bec.content.urgency',
          'bec.content.secrecy',
        ]),
      );
      // No intent-evidence rule (C1–C6, C9, K1, V4) fired: B6 keeps it below malicious.
      expect(becRow!.deterministicScore).toBeGreaterThanOrEqual(40);
      // No body text in the row (spans are offsets).
      const rowJson = JSON.stringify(becRow, (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      );
      expect(rowJson).not.toContain('Keep this confidential');
      expect(rowJson).not.toContain('quick favour from you');

      // The read API explains the verdict: rules with evidence, the executive profile's public id.
      const view = await becEngineView(await messagePublicId(fx.prisma, message));
      expect(view.engine).toMatchObject({ final: true, outcome: 'suspicious' });
      const bec = view.engine.bec!;
      expect(bec).toMatchObject({
        verdict: 'suspicious',
        deterministicVerdict: 'suspicious',
        thresholds: { suspicious: 40, malicious: 80 },
        inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
      });
      const x1 = bec.rules.find((r) => r.id === 'X1');
      expect(x1).toMatchObject({
        code: 'bec.impersonation.executive_name',
        category: 'impersonation',
        severity: 'high',
        suppressed: null,
      });
      expect(x1!.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            header: 'From',
            address: FREEMAIL_IMPOSTOR,
            displayName: EXECUTIVE,
            profile: expect.objectContaining({ kind: 'executive', id: executiveId }),
          }),
        ]),
      );
      const secrecy = bec.rules.find((r) => r.code === 'bec.content.secrecy');
      expect(secrecy!.evidence[0]).toMatchObject({
        keywords: expect.objectContaining({ category: 'secrecy', language: 'en' }),
      });
      const spans = (
        secrecy!.evidence[0]!.keywords as {
          spans: { source: string; start: number; end: number }[];
        }
      ).spans;
      expect(spans.length).toBeGreaterThan(0);
      for (const span of spans) expect(span.end).toBeGreaterThan(span.start);
      expect(view.raw).not.toContain('Keep this confidential');
      expect(view.raw).not.toContain('responseSha256');

      // B17: held by the pass-through under reason bec_verdict; never delivered.
      await expectHeld(message, rcpt, 'bec_verdict', before);
      record('bec-smtp', {
        pretext_bec: `${becFinal!.outcome}:${becRow!.score}`,
        pretext_rules: fired.length,
        pretext_round_verdict: round.scanVerdict,
        pretext_smtp_to_scanned_ms: scannedAfterMs,
      });
    });

    it('CEO fraud asking for gift cards: bec malicious (identity + intent evidence), round malicious, never delivered', async () => {
      const before = await skippedCounter('malicious_verdict');
      const { rcpt, message, round, becFinal, becRow } = await send(
        'ceo-giftcards',
        `"${EXECUTIVE}" <${FREEMAIL_IMPOSTOR}>`,
        'Quick favour',
        GIFT_CARD_BODY,
      );
      expect(becFinal).toMatchObject({ outcome: 'malicious', errorCode: null });
      expect(round).toMatchObject({ status: 'completed', scanVerdict: 'malicious' });
      expect(becRow).toMatchObject({ verdict: 'malicious', deterministicVerdict: 'malicious' });
      expect(becRuleCodes(becRow!.rules)).toEqual(
        expect.arrayContaining([
          'bec.impersonation.executive_name',
          'bec.impersonation.executive_freemail',
          'bec.content.gift_card',
          'bec.content.secrecy',
        ]),
      );
      const [scanned] = await scannedEventsOf(fx.prisma, org, message);
      expect(messageScannedV1.parse(scanned!.payload)).toMatchObject({
        outcome: 'scanned',
        verdict: 'malicious',
      });
      expect(messageScannedV1.parse(scanned!.payload).engines).toEqual(
        expect.arrayContaining([
          { engine: 'bec', required: true, outcome: 'malicious', attempts: 1 },
        ]),
      );
      // A malicious round is held under the earlier malicious_verdict rule (B17 keeps its reason).
      await expectHeld(message, rcpt, 'malicious_verdict', before);
      record('bec-smtp', { giftcard_bec: `${becFinal!.outcome}:${becRow!.score}` });
    });

    it('a legitimate message: bec clean (no profile match, no cue, authenticated as From), approved and delivered', async () => {
      const { rcpt, message, round, becFinal, becRow, started } = await send(
        'legit',
        'Alice Martin <alice@clean.scan.test>',
        'Warehouse inventory: next steps',
        'Hi team, the inventory count for the north warehouse is attached to the shared folder. ' +
          'Let us review the numbers at the weekly meeting on Thursday. Thanks, Alice',
      );
      expect(round).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
      expect(becFinal).toMatchObject({ outcome: 'clean', reasonCodes: ['clean.below_threshold'] });
      expect(becRow).toMatchObject({
        verdict: 'clean',
        deterministicVerdict: 'clean',
        inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
      });
      expect(becRuleCodes(becRow!.rules)).toEqual([]);
      await expectOneStageTrigger(message, round.id);
      const [delivery] = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 1);
      expect(delivery!.address).toBe(rcpt.toLowerCase());
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
      expect(await sinkFiles(rcpt)).toHaveLength(1);
      record('bec-smtp', {
        legit_bec: becFinal!.outcome,
        legit_round_verdict: round.scanVerdict,
        legit_smtp_to_delivered_ms: Date.now() - started,
      });
    });

    it('a Hinglish payment-urgency message records the romanized-Hindi C-codes and is never clean', async () => {
      const { becFinal, becRow } = await send(
        'hinglish',
        'Accounts <accounts.desk.2024@gmail.com>',
        'urgent',
        HINGLISH_BODY,
      );
      expect(becFinal!.outcome).not.toBe('clean');
      expect(['suspicious', 'malicious']).toContain(becFinal!.outcome);
      const fired = becRuleCodes(becRow!.rules);
      expect(fired).toEqual(expect.arrayContaining(['bec.content.urgency', 'bec.content.secrecy']));
      expect(
        fired.some((c) => c === 'bec.content.wire_transfer' || c === 'bec.content.payment_request'),
      ).toBe(true);
      // The keyword evidence names the romanized-Hindi lexicon (language hi-Latn), never text.
      const rules = becRow!.rules as {
        code: string;
        evidence: { keywords?: { language?: string; lexiconIds?: string[] } }[];
      }[];
      const urgency = rules.find((r) => r.code === 'bec.content.urgency')!;
      expect(urgency.evidence.map((e) => e.keywords?.language)).toContain('hi-Latn');
      expect(
        urgency.evidence
          .flatMap((e) => e.keywords?.lexiconIds ?? [])
          .some((id) => id.startsWith('hi-Latn.')),
      ).toBe(true);
      expect(JSON.stringify(becRow!.rules)).not.toContain('kisi ko mat batana');
      record('bec-smtp', {
        hinglish_bec: `${becFinal!.outcome}:${becRow!.score}`,
        hinglish_codes: fired.filter((c) => c.startsWith('bec.content.')).join(','),
      });
    });
  },
);
