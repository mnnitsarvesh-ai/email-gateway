import { randomInt } from 'node:crypto';
import { eicar } from '@email-gateway/attachment-corpus';
import { Prng, Synthetic } from '@email-gateway/dlp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession, idempotencyKey } from './support/api-client';
import { attachmentMessage, type MessageAttachment } from './support/attachment-stack';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { expectConsistentHistory, lifecycleOf, waitForLifecycle } from './support/lifecycle';
import { clearSinkDomain, sinkFiles, SINK_SERVICES } from './support/mail-sink';
import { metricValue } from './support/metrics';
import { record, sleep } from './support/messaging-stack';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { MAIL_SINK_HOST, organizationRef, sendingDomain } from './support/routing';
import {
  activeGroupsOf,
  contentProblems,
  hardBlocksOf,
  levelAtLeast,
  riskRowsOf,
  riskStateChecksums,
  scanRiskColumns,
  signalsOf,
  waitForRiskRow,
  type RiskRow,
} from './support/risk';
import {
  corpusEml,
  ensureRspamdRunning,
  messagePublicId,
  REQUIRED_ENGINES,
  scanStackGate,
  sendToMx,
  stopRspamd,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';
import {
  approvalsOf as policyApprovalsOf,
  expectPolicyHeld,
  floorOf,
  policyEvaluations,
  policyFloorRaises,
  waitForEvaluation,
} from './support/policy';

/**
 * Step 5.1 risk scoring end to end through Postfix and the live containers (docs/plan/steps/
 * 15-risk-scoring.md §9.5, R4–R8, R13, R15, R17; ADR-0041, ADR-0042). The email-worker scores
 * every completed round in the completion transaction (revision 0, `message_risk_scores`, and
 * the `email_scans` snapshot columns `verdict`, `risk_score`, `scoring_version`,
 * `risk_profile_version_id`). Since step 5.2 the policy-engine decides every round from that
 * row (docs/plan/steps/16-policy-engine.md P9: the platform default follows the recommendation,
 * the floor holds hard blocks, failures and the DLP binding); the 5.1 development pass-through
 * (R17) was removed with ADR-0044, so the holds below are policy holds (`quarantined`,
 * `rejected`), asserted through the evaluation rows and `policy_evaluations_total`.
 *
 * 1. A clean, DKIM-signed and aligned inbound message → one revision-0 row, `none`, `clean`,
 *    `deliver`; approved and delivered; the scans read API lists the row.
 * 2. GTUBE through the OUTBOUND path (SASL on postfix-outbound:587, no in-session milter there;
 *    the inbound milter rejects GTUBE, ADR-0027) → `spam.gtube`, `high`, `spam`, `quarantine`,
 *    quarantined by the platform default (`policy.default.risk_quarantine`).
 * 3. EICAR attachment (inbound) → `hb.malware_attachment`, `critical`, `malware`, `block`
 *    (rejected by policy: floor `hard_block`; the risk row agrees).
 * 4. A card number outbound under the platform default DLP policy (`alert`) → `dlp` group,
 *    `low`, `dlp_violation`, `tag` (approved and delivered); and in a second organization with a
 *    tenant DLP `block` rule → `hb.dlp_block`, `block`, rejected by policy.
 * 5. Rspamd stopped past its attempt budget (the scan-resilience mechanism) → `scan_failed`
 *    round with a revision-0 row: `risk.engine.rspamd.<error|timeout>`, level ≥ `medium`,
 *    `quarantine`.
 * 6. Administrative rescan of (5) once Rspamd is back → round 1 with its own row; round 0's row
 *    unchanged.
 * 7. Profile change applies to the next round only: a tenant version (`actions.medium =
 *    quarantine`) published through the api; a new message B and a rescan of the GTUBE message
 *    A (quarantined; the EICAR message is `rejected` since step 5.2, a terminal state E19 does
 *    not leave) use it (`profile_source = tenant`, `profile_id_text` with the version), A's
 *    first row and its NULL snapshot are unchanged.
 * 8. Dry-run changes nothing (checksums of the organization's risk rows, rounds, profile,
 *    versions, audit rows and the outbox count); `active` reproduces the stored result; a draft
 *    gives another `profileSha256` with the same `inputSha256`.
 *
 * Every row is checked for content: no `@`, no `://`, no fixture domain or local part in the
 * explanation or the JSON columns (§2.0-6).
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
const synthetic = new Synthetic(new Prng(randomInt(1, 2 ** 31 - 1)));
const maxRspamdAttempts = Number(process.env.SCAN_RSPAMD_MAX_ATTEMPTS ?? 6);

let org = 0n;
let blockOrg = 0n;
let inbound: FixtureDomain;
let out: FixtureDomain;
let blockOut: FixtureDomain;
let analyst: ApiSession | undefined;
let admin: ApiSession | undefined;
let blockAnalyst: ApiSession | undefined;
let sasl: { username: string; password: string };
let blockSasl: { username: string; password: string };
const extDomain = () => fx.sinkDomain('risk-ext');

type Msg = { id: bigint; receivedAt: Date; direction: string; publicId: string };
/** Messages shared between cases. */
const shared: {
  clean?: Msg;
  eicar?: Msg;
  outage?: Msg;
  eicarRow0?: RiskRow;
  gtube?: Msg;
  gtubeRow0?: RiskRow;
  b?: Msg;
  version?: { id: string; internalId: bigint; versionNo: number; profileSha256: string };
} = {};

/** Names that must never appear in a risk row (fixture domains and local parts). */
const forbidden = () =>
  [inbound?.name, out?.name, blockOut?.name, extDomain(), 'clean.scan.test', 'alice'].filter(
    (n): n is string => Boolean(n),
  );

/** JSON of a Prisma row (BigInt ids as strings). */
const rowJson = (value: unknown) =>
  JSON.stringify(value, (_key, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

function expectNoContent(row: RiskRow): void {
  expect(contentProblems(row, forbidden())).toEqual([]);
}

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('risk');
  inbound = await fx.domain(org, 'risk-in');
  out = await sendingDomain(fx, org, 'risk-out');
  await fx.destinations(inbound, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(out, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  sasl = await fx.saslConnector(org, 'risk');

  // A second organization whose tenant DLP policy blocks card numbers (case 4b), created
  // before its first message so the worker's tenant cache never holds a state without it.
  blockOrg = await fx.organization('risk-dlp');
  blockOut = await sendingDomain(fx, blockOrg, 'risk-blk');
  await fx.destinations(blockOut, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  blockSasl = await fx.saslConnector(blockOrg, 'risk-blk');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);

  analyst = await apiSession(fx.prisma, await organizationRef(fx, org), 'security_analyst');
  admin = await apiSession(fx.prisma, await organizationRef(fx, org), 'organization_admin');
  blockAnalyst = await apiSession(
    fx.prisma,
    await organizationRef(fx, blockOrg),
    'security_analyst',
  );
  const policy = await blockAnalyst.post('/dlp/policies', {
    name: 'Block card numbers',
    priority: 10,
    directions: ['outbound', 'internal'],
  });
  expect(policy.status, JSON.stringify(policy.body)).toBe(201);
  const rule = await blockAnalyst.post(
    `/dlp/policies/${(policy.body as { id: string }).id}/rules`,
    {
      name: 'Cards → block',
      priority: 10,
      conditions: { selectors: { categories: ['payment_card'] } },
      action: 'block',
    },
  );
  expect(rule.status, JSON.stringify(rule.body)).toBe(201);
}, 180_000);

afterAll(async () => {
  if (gate.skip) return;
  await ensureRspamdRunning().catch(() => undefined);
  await analyst?.remove();
  await admin?.remove();
  await blockAnalyst?.remove();
  const names = [inbound, out, blockOut].filter(Boolean).map((d) => d.name);
  const queued = involving(await listQueue('postfix-outbound'), [...names, extDomain()]);
  await deleteQueued(
    'postfix-outbound',
    queued.map((m) => m.queue_id),
  );
  for (const domain of [extDomain(), ...names]) {
    await clearSinkDomain(domain, 'all').catch(() => undefined);
  }
  const removed = [org, blockOrg].filter((id) => id !== 0n);
  await fx.cleanup();
  await purgeDormantQueues();
  if (removed.length === 0) return;
  // The cleanup leaves no risk row, profile or version of the fixture organizations.
  const { PrismaClient } = await import('@email-gateway/database');
  const { stack } = await import('./support/env');
  const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  try {
    const where = { organizationId: { in: removed } };
    expect({
      scores: await prisma.messageRiskScore.count({ where }),
      versions: await prisma.riskScoringProfileVersion.count({ where }),
      profiles: await prisma.riskScoringProfile.count({ where }),
    }).toEqual({ scores: 0, versions: 0, profiles: 0 });
  } finally {
    await prisma.$disconnect();
  }
}, 300_000);

// --- Sending ------------------------------------------------------------------------------------

async function inboundMessage(eml: string, local: string) {
  const rcpt = `${local}@${inbound.name}`;
  const sent = await sendToMx({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: eml,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  return { rcpt, ...(await keyOf(org, sent.queueId!)) };
}

async function outboundMessage(options: {
  organizationId: bigint;
  domain: FixtureDomain;
  auth: { username: string; password: string };
  rcpt: string;
  subject: string;
  body: string;
  attachments?: readonly MessageAttachment[];
}) {
  const from = `alice@${options.domain.name}`;
  const { text } = attachmentMessage({
    from: `Alice <${from}>`,
    to: [options.rcpt],
    subject: options.subject,
    body: options.body,
    attachments: options.attachments ?? [],
  });
  const sent = await swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: options.auth,
    from,
    to: [options.rcpt],
    data: text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  return { rcpt: options.rcpt, ...(await keyOf(options.organizationId, sent.queueId!)) };
}

async function keyOf(organizationId: bigint, queueId: string): Promise<{ message: Msg }> {
  const row = await waitForMessage(fx.prisma, organizationId, { mtaQueueId: queueId });
  return {
    message: {
      id: row.id,
      receivedAt: row.receivedAt,
      direction: row.direction,
      publicId: await messagePublicId(fx.prisma, row),
    },
  };
}

/** Round `round` completed; its revision-0 row and the round's snapshot columns. */
async function scoredRound(message: Msg, round = 0, timeoutMs = 180_000) {
  const scan = await waitForRoundComplete(fx.prisma, message, round, timeoutMs);
  const row = await waitForRiskRow(fx.prisma, message, scan.id, 0);
  const columns = await scanRiskColumns(fx.prisma, message, round);
  expect(row).toMatchObject({
    organizationId: scan.organizationId,
    messageId: message.id,
    scanId: scan.id,
    lifecycleRound: round,
    revision: 0,
    direction: message.direction,
    scorerVersion: 'risk-score/1',
    signalMapVersion: 'risk-signals/1',
    inputVersion: 'risk-input/1',
  });
  expect(row.inputSha256).toMatch(/^[0-9a-f]{64}$/);
  expect(row.profileSha256).toMatch(/^[0-9a-f]{64}$/);
  // R13: the round's columns mirror the revision-0 row.
  expect(columns).toMatchObject({
    verdict: row.verdict,
    riskScore: row.score,
    scoringVersion: 'risk-score/1',
  });
  expectNoContent(row);
  return { scan, row, columns };
}

// --- Policy (step 5.2) ----------------------------------------------------------------------------

/** The policy-engine evaluated round `round` (one `policy_execution_logs` row, P13). */
async function policyHandled(message: Msg, round: number) {
  return waitForEvaluation(fx.prisma, message, round, 120_000);
}

/** Held by policy: evaluated, not `allow`, in the disposition's state, never delivered. */
async function expectHeld(message: Msg, rcpt: string, round = 0) {
  const evaluation = await expectPolicyHeld(fx.prisma, message, { round });
  await sleep(5_000);
  expect(await policyApprovalsOf(fx.prisma, message)).toHaveLength(0);
  expect(
    await fx.prisma.emailDelivery.count({
      where: { messageId: message.id },
    }),
  ).toBe(0);
  for (const service of SINK_SERVICES) {
    expect(await sinkFiles(rcpt, service), `${rcpt} ${service}`).toEqual([]);
  }
  await expectConsistentHistory(fx.prisma, message);
  return evaluation;
}

/** The scans read API (replica): the `risk` section of round `round`. */
async function riskViewOf(session: ApiSession, message: Msg, round: number, revisions = 1) {
  return waitFor(
    `GET /messages/${message.publicId}/scans with ${revisions} risk score(s) on round ${round}`,
    async () => {
      const res = await session.get(`/messages/${message.publicId}/scans`);
      if (res.status !== 200) return undefined;
      const body = res.body as {
        data: { round: number; status: string; risk: Record<string, unknown>[] }[];
      };
      const entry = body.data.find((r) => r.round === round);
      return entry && entry.risk.length === revisions
        ? { raw: JSON.stringify(res.body), entry }
        : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 500 },
  );
}

// --- Cases --------------------------------------------------------------------------------------

describe.skipIf(gate.skip)(
  'risk scoring stack: scores through Postfix',
  { timeout: 600_000 },
  () => {
    it('(1) clean inbound: one revision-0 row, none / clean / deliver, approved and delivered', async () => {
      const { rcpt, message } = await inboundMessage(
        corpusEml('clean/clean-dkim-aligned.eml'),
        'clean',
      );
      const { scan, row, columns } = await scoredRound(message);
      expect(scan).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
      expect(row).toMatchObject({
        status: 'scored',
        level: 'none',
        verdict: 'clean',
        recommendedAction: 'deliver',
        profileSource: 'platform',
        profileIdText: 'rsk-default/1',
        profileVersionId: null,
      });
      expect(row.score).toBeLessThan(100);
      expect(hardBlocksOf(row)).toEqual([]);
      expect(columns.riskProfileVersionId).toBeNull();
      expect(await riskRowsOf(fx.prisma, message)).toHaveLength(1);
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 180_000);
      expect(await sinkFiles(rcpt)).toHaveLength(1);

      // The scans read API lists the stored score (public ids only).
      const { raw, entry } = await riskViewOf(analyst!, message, 0);
      expect(entry.risk[0]).toMatchObject({
        revision: 0,
        status: 'scored',
        score: row.score,
        level: 'none',
        verdict: 'clean',
        recommendedAction: 'deliver',
        inputSha256: row.inputSha256,
        versions: {
          profile: { source: 'platform', id: 'rsk-default/1', sha256: row.profileSha256 },
        },
      });
      expect(raw).not.toContain(`"profileVersionId"`);
      shared.clean = message;
      record('risk-smtp', { clean_score: row.score, clean_duration_us: row.durationUs });
    });

    it('(2) GTUBE through the outbound path: spam.gtube, high, spam, quarantine, held (risk_recommendation)', async () => {
      const quarantinedBefore = await policyEvaluations({
        trigger: 'scanned',
        disposition: 'quarantine',
        source: 'platform_default',
        direction: 'outbound',
      });
      const { rcpt, message } = await outboundMessage({
        organizationId: org,
        domain: out,
        auth: sasl,
        rcpt: `gtube@${extDomain()}`,
        subject: 'Risk stack: GTUBE',
        body: 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X',
      });
      expect(message.direction).toBe('outbound');
      const { scan, row } = await scoredRound(message);
      expect(scan).toMatchObject({ status: 'completed', scanVerdict: 'spam' });
      expect(signalsOf(row)).toContain('spam_gtube');
      expect((row.contributions as { codes: string[] }[]).flatMap((c) => c.codes)).toContain(
        'rspamd:spam.gtube',
      );
      expect(row).toMatchObject({
        status: 'scored',
        level: 'high',
        verdict: 'spam',
        recommendedAction: 'quarantine',
      });
      expect(hardBlocksOf(row)).toEqual([]);
      // Step 5.2: quarantined by the platform default following the recommendation (P9.4).
      const evaluation = await expectHeld(message, rcpt);
      expect(evaluation).toMatchObject({
        disposition: 'quarantine',
        decisionSource: 'platform_default',
      });
      expect(floorOf(evaluation).reasons).toEqual([]);
      expect(
        await policyEvaluations({
          trigger: 'scanned',
          disposition: 'quarantine',
          source: 'platform_default',
          direction: 'outbound',
        }),
      ).toBe(quarantinedBefore + 1);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
        status: 'quarantined',
        statusReason: 'policy_quarantine',
      });
      shared.gtube = message;
      shared.gtubeRow0 = row;
      record('risk-smtp', { gtube_score: row.score, gtube_level: row.level });
    });

    it('(3) EICAR attachment: hb.malware_attachment, critical, malware, block; held', async () => {
      const hardBlocks = await policyFloorRaises('hard_block');
      const built = attachmentMessage({
        from: 'alice@clean.scan.test',
        to: [`eicar@${inbound.name}`],
        subject: 'Risk stack: EICAR',
        attachments: [{ filename: 'readme.txt', contentType: 'text/plain', bytes: eicar() }],
      });
      const { rcpt, message } = await inboundMessage(built.text, 'eicar');
      const { scan, row } = await scoredRound(message);
      expect(scan).toMatchObject({ status: 'completed', scanVerdict: 'malicious' });
      expect(hardBlocksOf(row)).toEqual(['hb.malware_attachment']);
      expect(row.hardBlocks).toEqual([
        { id: 'hb.malware_attachment', verdict: 'malware', action: 'block' },
      ]);
      expect(row).toMatchObject({
        status: 'scored',
        level: 'critical',
        verdict: 'malware',
        recommendedAction: 'block',
      });
      expect(row.score).toBeGreaterThanOrEqual(800);
      expect(row.reasonCodes as string[]).toContain('risk.hard_block.malware_attachment');
      expect(signalsOf(row)).toContain('attachment_malware');
      // Step 5.2: rejected (inbound: discarded, no bounce) with the hard-block floor reason.
      const evaluation = await expectHeld(message, rcpt);
      expect(evaluation.disposition).toBe('reject');
      expect(floorOf(evaluation).reasons).toContain('policy.floor.hard_block');
      expect(await policyFloorRaises('hard_block')).toBeGreaterThanOrEqual(hardBlocks + 1);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
        status: 'rejected',
        statusReason: 'policy_discard',
      });
      shared.eicar = message;
      shared.eicarRow0 = row;
      record('risk-smtp', { eicar_score: row.score });
    });

    it('(4a) card number outbound under the default DLP policy (alert): dlp group, low, dlp_violation, tag; delivered', async () => {
      const card = synthetic.card('4532');
      const { rcpt, message } = await outboundMessage({
        organizationId: org,
        domain: out,
        auth: sasl,
        rcpt: `cards@${extDomain()}`,
        subject: 'Risk stack: card number',
        body: `Please charge card ${card.replace(/(\d{4})(?=\d)/g, '$1 ')} today.\r\nThanks`,
      });
      const { row } = await scoredRound(message);
      const dlp = await fx.prisma.dlpScanResult.findFirstOrThrow({
        where: { messageId: message.id, receivedAt: message.receivedAt },
      });
      expect(dlp).toMatchObject({ action: 'alert', actionSource: 'default_policy' });
      expect(activeGroupsOf(row)).toContain('dlp');
      expect(row).toMatchObject({
        status: 'scored',
        level: 'low',
        verdict: 'dlp_violation',
        recommendedAction: 'tag',
      });
      expect(hardBlocksOf(row)).toEqual([]);
      expect(rowJson(row)).not.toContain(card);
      // `tag` is approved by the pass-through (R17) and delivered.
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 180_000);
      expect(await sinkFiles(rcpt)).toHaveLength(1);
      record('risk-smtp', { dlp_alert_score: row.score });
    });

    it('(4b) card number under a tenant DLP block rule: hb.dlp_block, critical, block; held', async () => {
      const card = synthetic.card('4024');
      const { rcpt, message } = await outboundMessage({
        organizationId: blockOrg,
        domain: blockOut,
        auth: blockSasl,
        rcpt: `cards-block@${extDomain()}`,
        subject: 'Risk stack: card number (block)',
        body: `Card ${card.replace(/(\d{4})(?=\d)/g, '$1 ')} for the invoice.\r\nThanks`,
      });
      const { row } = await scoredRound(message);
      const dlp = await fx.prisma.dlpScanResult.findFirstOrThrow({
        where: { messageId: message.id, receivedAt: message.receivedAt },
      });
      expect(dlp).toMatchObject({ action: 'block', actionSource: 'tenant_policy' });
      expect(row.hardBlocks).toEqual([
        { id: 'hb.dlp_block', verdict: 'dlp_violation', action: 'block' },
      ]);
      expect(row).toMatchObject({
        status: 'scored',
        level: 'critical',
        verdict: 'dlp_violation',
        recommendedAction: 'block',
      });
      expect(rowJson(row)).not.toContain(card);
      // Step 5.2: the DLP binding (floor) rejects it.
      const evaluation = await expectHeld(message, rcpt);
      expect(evaluation.disposition).toBe('reject');
      expect(floorOf(evaluation).reasons).toContain('policy.floor.dlp_block');
      record('risk-smtp', { dlp_block_score: row.score });
    });

    it('(5) Rspamd down past its budget: scan_failed round with risk.engine.rspamd.*, level ≥ medium, quarantine', async () => {
      const scanFailedBefore = await policyFloorRaises('scan_failed');
      await stopRspamd();
      let message: Msg;
      let rcpt: string;
      try {
        const built = attachmentMessage({
          from: 'alice@clean.scan.test',
          to: [`outage@${inbound.name}`],
          subject: 'Risk stack: engine outage',
          attachments: [],
        });
        ({ rcpt, message } = await inboundMessage(built.text, 'outage'));
        const { scan, row } = await scoredRound(message, 0, 300_000);
        expect(scan).toMatchObject({ status: 'failed', scanVerdict: 'error' });
        const finals = await fx.prisma.scanEngineResult.findMany({
          where: {
            scanId: scan.id,
            receivedAt: message.receivedAt,
            isFinal: true,
            engine: 'rspamd',
          },
        });
        expect(finals).toHaveLength(1);
        expect(finals[0]!.attempt).toBe(maxRspamdAttempts);
        const failureCode = (row.reasonCodes as string[]).find((c) =>
          c.startsWith('risk.engine.rspamd.'),
        );
        expect(failureCode).toMatch(/^risk\.engine\.rspamd\.(error|timeout)$/);
        expect(row.failures).toEqual(
          expect.arrayContaining([expect.objectContaining({ engine: 'rspamd' })]),
        );
        expect(levelAtLeast(row.level, 'medium')).toBe(true);
        expect(row.recommendedAction).toBe('quarantine');
        expect(row.verdict).not.toBe('clean');
        expect(row.status).toBe('scored');
        // Step 5.2: E9 (scan_failed_fail_safe) then at least quarantine (floor scan_failed).
        const evaluation = await expectHeld(message, rcpt);
        expect(evaluation).toMatchObject({ trigger: 'scan_failed' });
        expect(['quarantine', 'reject']).toContain(evaluation.disposition);
        expect(floorOf(evaluation).reasons).toContain('policy.floor.scan_failed');
        expect(await policyFloorRaises('scan_failed')).toBeGreaterThanOrEqual(scanFailedBefore + 1);
        const path = await fx.prisma.emailMessageStatusHistory.findMany({
          where: { messageId: message.id, receivedAt: message.receivedAt },
          orderBy: { version: 'asc' },
          select: { toStatus: true, reasonCode: true },
        });
        expect(path.map((h) => [h.toStatus, h.reasonCode]).slice(3, 6)).toEqual([
          ['scan_failed', 'scan_error'],
          ['policy_evaluated', 'scan_failed_fail_safe'],
          [
            evaluation.disposition === 'reject' ? 'rejected' : 'quarantined',
            evaluation.disposition === 'reject' ? 'policy_discard' : 'policy_quarantine',
          ],
        ]);
        shared.outage = message;
        record('risk-smtp', {
          outage_score: row.score,
          outage_level: row.level,
          outage_code: failureCode,
        });
      } finally {
        await ensureRspamdRunning();
      }
    });

    it('(6) rescan of the scan_failed message: round 1 has its own row, round 0 row unchanged', async () => {
      expect(shared.outage, 'case 5 left a scan_failed message').toBeDefined();
      const message = shared.outage!;
      const before = await riskRowsOf(fx.prisma, message);
      expect(before).toHaveLength(1);
      const current = await lifecycleOf(fx.prisma, message);
      const res = await analyst!.post(
        `/messages/${message.publicId}/rescan`,
        { expectedVersion: current.version, reason: 'stack test: rspamd recovered' },
        { 'Idempotency-Key': `it-risk-rescan-outage-${fx.suffix}` },
      );
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      const { scan, row } = await scoredRound(message, 1);
      expect(scan).toMatchObject({ scanKind: 'rescan', status: 'completed' });
      expect(row.scanId).not.toBe(before[0]!.scanId);
      expect(row.reasonCodes as string[]).not.toEqual(
        expect.arrayContaining([expect.stringMatching(/^risk\.engine\.rspamd\./)]),
      );
      const after = await riskRowsOf(fx.prisma, message);
      expect(after.map((r) => [r.lifecycleRound, r.revision])).toEqual([
        [0, 0],
        [1, 0],
      ]);
      expect(after[0]).toEqual(before[0]);
      record('risk-smtp', { rescan_level: row.level, rescan_action: row.recommendedAction });
    });

    it('(7) a published tenant version applies to the next round only (message B and a rescan of A)', async () => {
      // Step 5.2: A is the GTUBE message (quarantined, E19 applies); the EICAR message is
      // `rejected` (terminal) and can no longer be rescanned.
      expect(shared.gtube && shared.gtubeRow0, 'case 2 left the GTUBE message').toBeTruthy();
      const a = shared.gtube!;
      const a0Before = (await riskRowsOf(fx.prisma, a))[0]!;
      expect(a0Before).toEqual(shared.gtubeRow0);
      const a0Columns = await scanRiskColumns(fx.prisma, a, 0);
      expect(a0Columns.riskProfileVersionId).toBeNull();

      const draft = await analyst!.post('/risk-scoring/profile/versions', {
        overrides: { actions: { medium: 'quarantine' } },
        changeNote: 'stack test: quarantine medium risk',
      });
      expect(draft.status, JSON.stringify(draft.body)).toBe(201);
      const created = draft.body as { id: string; rowVersion: number; versionNo: number };
      // security_analyst holds policy:manage but not policy:publish.
      const refused = await analyst!.post(
        `/risk-scoring/profile/versions/${created.id}/publish`,
        {
          activate: true,
          expectedRowVersion: created.rowVersion,
        },
        idempotencyKey(),
      );
      expect(refused.status).toBe(403);
      const published = await admin!.post(
        `/risk-scoring/profile/versions/${created.id}/publish`,
        {
          activate: true,
          expectedRowVersion: created.rowVersion,
        },
        idempotencyKey(),
      );
      expect(published.status, JSON.stringify(published.body)).toBe(200);
      const body = published.body as {
        version: { id: string; versionNo: number; status: string; profileSha256: string };
        profile: { active: { source: string; versionId: string; profileId: string } };
      };
      expect(body.version.status).toBe('published');
      expect(body.profile.active).toMatchObject({ source: 'tenant', versionId: created.id });
      const internal = await fx.prisma.riskScoringProfileVersion.findFirstOrThrow({
        where: { publicId: created.id, organizationId: org },
        select: { id: true },
      });
      const profileIdText = `rsk-default/1+t:${created.id}#${body.version.versionNo}`;
      expect(body.profile.active.profileId).toBe(profileIdText);
      shared.version = {
        id: created.id,
        internalId: internal.id,
        versionNo: body.version.versionNo,
        profileSha256: body.version.profileSha256,
      };
      const audit = await fx.prisma.auditLog.findMany({
        where: { organizationId: org, action: { startsWith: 'risk_profile.' } },
        select: { action: true },
      });
      expect(audit.map((r) => r.action).sort()).toEqual(
        ['risk_profile.activated', 'risk_profile.draft_created', 'risk_profile.published'].sort(),
      );

      // Message B, opened after the publish: scored with the tenant version.
      const { message: b } = await inboundMessage(corpusEml('clean/clean-dkim-aligned.eml'), 'b');
      const { row: bRow, columns: bColumns } = await scoredRound(b);
      expect(bColumns.riskProfileVersionId).toBe(internal.id);
      expect(bRow).toMatchObject({
        profileSource: 'tenant',
        profileVersionId: internal.id,
        profileIdText,
        profileSha256: shared.version.profileSha256,
      });
      expect((bRow.explanation as { code: string }[]).map((l) => l.code)).toContain('profile');
      shared.b = b;

      // A rescan of A: round 1 with the tenant version; A's round 0 row and snapshot unchanged.
      const current = await lifecycleOf(fx.prisma, a);
      const res = await analyst!.post(
        `/messages/${a.publicId}/rescan`,
        { expectedVersion: current.version, reason: 'stack test: profile changed' },
        { 'Idempotency-Key': `it-risk-rescan-a-${fx.suffix}` },
      );
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      const { row: a1, columns: a1Columns } = await scoredRound(a, 1);
      expect(a1Columns.riskProfileVersionId).toBe(internal.id);
      expect(a1).toMatchObject({
        profileSource: 'tenant',
        profileVersionId: internal.id,
        profileIdText,
        profileSha256: shared.version.profileSha256,
        level: 'high',
        recommendedAction: 'quarantine',
      });
      // Both messages settle before the next case takes its checksums: B is delivered, A's
      // round 1 is evaluated (quarantined again) by the policy-engine.
      await waitForLifecycle(fx.prisma, b, 'delivered', 'delivery_complete', 180_000);
      expect((await policyHandled(a, 1)).disposition).toBe('quarantine');
      const rows = await riskRowsOf(fx.prisma, a);
      expect(rows.filter((r) => r.lifecycleRound === 0)).toEqual([a0Before]);
      expect(a0Before).toMatchObject({ profileSource: 'platform', profileIdText: 'rsk-default/1' });
      expect((await scanRiskColumns(fx.prisma, a, 0)).riskProfileVersionId).toBeNull();
      expect(a0Before.profileSha256).not.toBe(shared.version.profileSha256);
    });

    it('(8) dry-run writes nothing; active reproduces the stored result; a draft changes only the profile hash', async () => {
      expect(shared.b && shared.eicar && shared.version, 'cases 3 and 7 ran').toBeTruthy();
      // A draft (created before the "before" checksums: creating it is a write).
      const draftRes = await analyst!.post('/risk-scoring/profile/versions', {
        overrides: { thresholds: { low: 150 } },
        changeNote: 'stack test: dry-run draft',
      });
      expect(draftRes.status, JSON.stringify(draftRes.body)).toBe(201);
      const draftId = (draftRes.body as { id: string }).id;

      const targets = [
        { message: shared.b!, round: 0 },
        { message: shared.eicar!, round: 0 },
      ];
      const scans = await Promise.all(
        targets.map(async (t) => ({
          ...t,
          scanId: (await scanRiskColumns(fx.prisma, t.message, t.round)).id,
          row: (await riskRowsOf(fx.prisma, t.message)).find(
            (r) => r.lifecycleRound === t.round && r.revision === 0,
          )!,
        })),
      );
      const dryRun = (message: Msg, scanId: bigint, profile: unknown) =>
        waitFor(
          `dry-run of scan ${scanId} (replicated)`,
          async () => {
            const res = await analyst!.post(
              `/messages/${message.publicId}/scans/${scanId.toString()}/risk/dry-run`,
              { profile },
            );
            if (res.status === 409) return undefined;
            return res;
          },
          { timeoutMs: 30_000, intervalMs: 500 },
        );

      // A quiet organization first: no outbox row written for 5 s (late lifecycle or delivery
      // events of earlier cases are not the dry-run's).
      let quiet = await riskStateChecksums(fx.prisma, org);
      await waitFor(
        'no new row in the organization for 5 s',
        async () => {
          await sleep(5_000);
          const now = await riskStateChecksums(fx.prisma, org);
          const same = JSON.stringify(now) === JSON.stringify(quiet);
          quiet = now;
          return same;
        },
        { timeoutMs: 120_000, intervalMs: 0 },
      );
      const before = quiet;
      const dryRunsBefore = await metricValue('api', 'risk_dry_runs_total', { result: 'ok' });
      for (const { message, scanId, row } of scans) {
        const active = await dryRun(message, scanId, 'active');
        expect(active.status, JSON.stringify(active.body)).toBe(200);
        const body = active.body as {
          result: {
            score: number;
            level: string;
            verdict: string;
            recommendedAction: string;
            inputSha256: string;
            reasonCodes: string[];
            explanation: { text: string };
            versions: { profile: { source: string; id: string; sha256: string } };
          };
          stored: { inputSha256: string; profileSha256: string } | null;
          reproducible: boolean;
        };
        expect(body.reproducible).toBe(true);
        expect(body.stored).toMatchObject({
          inputSha256: row.inputSha256,
          profileSha256: row.profileSha256,
        });
        expect(body.result).toMatchObject({
          score: row.score,
          level: row.level,
          verdict: row.verdict,
          recommendedAction: row.recommendedAction,
          inputSha256: row.inputSha256,
          reasonCodes: row.reasonCodes,
          versions: {
            profile: {
              source: row.profileSource,
              id: row.profileIdText,
              sha256: row.profileSha256,
            },
          },
        });
        expect(body.result.explanation.text).toBe(row.explanationText);

        const draft = await dryRun(message, scanId, { versionId: draftId });
        expect(draft.status, JSON.stringify(draft.body)).toBe(200);
        const draftBody = draft.body as typeof body;
        expect(draftBody.result.inputSha256).toBe(row.inputSha256);
        expect(draftBody.result.versions.profile.sha256).not.toBe(row.profileSha256);
        expect(draftBody.result.versions.profile.source).toBe('tenant');
        expect(draftBody.reproducible).toBe(true);
      }
      // `platform` on B (scored with the tenant version) gives A's platform hash.
      const platform = await dryRun(shared.b!, scans[0]!.scanId, 'platform');
      expect(platform.status).toBe(200);
      expect(
        (platform.body as { result: { versions: { profile: { sha256: string } } } }).result.versions
          .profile.sha256,
      ).toBe(scans[1]!.row.profileSha256);

      // Nothing changed: rows, rounds, profile, versions, audit rows, outbox.
      await sleep(2_000);
      expect(await riskStateChecksums(fx.prisma, org)).toEqual(before);
      expect(await metricValue('api', 'risk_dry_runs_total', { result: 'ok' })).toBe(
        dryRunsBefore + 5,
      );
      record('risk-smtp', { dry_run_reproducible: true });
    });
  },
);
