import { randomInt } from 'node:crypto';
import { ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { PrismaClient } from '@email-gateway/database';
import { buildDocx, buildZip, markZipEncrypted, Prng, Synthetic } from '@email-gateway/dlp';
import { messageDlpIncidentV1, messageScannedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { attachmentMessage, type MessageAttachment } from './support/attachment-stack';
import { ManagementApi, purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForAllDeliveries, waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import { expectConsistentHistory, lifecycleOf, pathOf } from './support/lifecycle';
import { clearSinkDomain, sinkFiles, SINK_SERVICES } from './support/mail-sink';
import { record, sleep } from './support/messaging-stack';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { MAIL_SINK_HOST, organizationRef, sendingDomain } from './support/routing';
import {
  DLP_LEDGER,
  dlpEvidenceOf,
  dlpFindingCodes,
  dlpIncidentEventsOf,
  dlpResultsOf,
  engineResultsOf,
  messagePublicId,
  REQUIRED_ENGINES,
  roundFinalEngines,
  scannedEventsOf,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import {
  actionsOf,
  DISPOSITION_STATE,
  expectPolicyHeld,
  floorOf,
  policyFloorRaises,
  waitForEvaluation,
} from './support/policy';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';

/**
 * The step 4.5 DLP engine end to end through the authenticated outbound path (docs/plan/steps/
 * 13-dlp.md §9 "Stack", D1, D3, D4, D11–D16, D20, D21): smtp-tools → postfix-outbound:587
 * (STARTTLS + SASL, the path of smtp-outbound / routing-*) → smtp-adapter (EML in MinIO) →
 * email-worker MIME role → `parsed.v1` → stage 1 (`scan.spam`, `scan.attachment`, `scan.url`
 * and `scan.dlp`: the DLP engine reads the stored text parts and extracts the attachments in its
 * isolated extractor child, detects, classifies and evaluates the tenant's policy, seals the
 * evidence into MinIO and writes `dlp_scan_results`, `dlp_evidence` and the
 * `mail.message.dlp_incident.v1` outbox row with its final) → round completion → policy-engine
 * (D13, since step 5.2 the DLP binding of the policy floor, P9.5: `allow`/`alert` approved,
 * `alert` with the mandatory `dlp-alert` TAG; `require_approval` → `held_for_review`,
 * `quarantine` → `quarantined`, `block` → `rejected` with a sender notice requested) →
 * planner → postfix-outbound → mail-sink.
 *
 * Fixture organization, policies and rules created through the api with a `security_analyst`
 * token (D21) before the organization's first message (so the worker's tenant cache, D3 step 3,
 * never holds a state without them): one enforce policy for outbound and internal mail with
 * rule A payment_card ≥ 1 to an external recipient → quarantine; B credential → block;
 * C confidential → alert; D national_id → require_approval; E payment_card, internal only →
 * alert; and a recipient-domain exception for a partner domain. Then:
 *
 * 1. card numbers in the body and in a DOCX → `suspicious`, `quarantine` (rule A), one incident,
 *    evidence stored, NOT approved (policy quarantine with floor reason `policy.floor.dlp_quarantine`,
 *    nothing in any sink during a 10 s window);
 * 2. a PEM private key inside a ZIP → `block` (rule B), rejected by policy;
 * 3. a CONFIDENTIAL board memo → `alert` (rule C), approved and delivered, incident;
 * 4. a card message to the partner domain → `allow` with the exception applied, delivered;
 * 5. an encrypted ZIP → `unknown` with `dlp.not_extracted.encrypted`, never clean;
 * 6. the evidence of (1) read through the api with MFA by a security_analyst (the decrypted
 *    values match the synthetic fixture; `dlp_evidence.read` audit row) and refused with 403
 *    for a read_only_user;
 * 7. the scans read API shows masked values only (no 13–19 digit run, no private key text);
 *    a read_only_user gets no dlp section;
 * 8. a PAN in prose → `require_approval` (rule D), held for review by policy;
 * 9. internal mail (sender and recipient on the tenant's domains) with a card number → dlp runs
 *    with direction `internal` and rule E's `alert`, delivered;
 * 10. an inbound message with a card number → dlp `skipped` / `dlp.not_inbound`.
 *
 * Only synthetic values of the `@email-gateway/dlp` corpus generators are used (seeded PRNG,
 * test IIN ranges with a valid Luhn digit, invented PAN/IBAN; the PEM block has a random
 * non-key base64 body). `afterAll` runs the fixtures' cleanup and asserts that no DLP row,
 * evidence object or fixture organization is left.
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();
const synthetic = new Synthetic(new Prng(randomInt(1, 2 ** 31 - 1)));

let org = 0n;
let out: FixtureDomain;
let internal: FixtureDomain;
let analyst: ApiSession | undefined;
let readOnly: ApiSession | undefined;
let sasl: { username: string; password: string };
let policyId = '';
const ruleIds: Record<'A' | 'B' | 'C' | 'D' | 'E', string> = { A: '', B: '', C: '', D: '', E: '' };
let exceptionId = '';
const extDomain = () => fx.sinkDomain('dlp-ext');
const partnerDomain = () => fx.sinkDomain('dlp-partner');

/** The quarantined card message of case 1 (evidence and read API cases 6 and 7). */
let cardMessage:
  | {
      message: { id: bigint; receivedAt: Date };
      scanId: bigint;
      cards: [string, string];
      iban: string;
    }
  | undefined;
let keyMessage: { message: { id: bigint; receivedAt: Date }; pem: string } | undefined;

const group4 = (digits: string) => digits.replace(/(\d{4})(?=\d)/g, '$1 ');
/** D16: card numbers are kept in evidence as first 6 + last 4 only. */
const evidenceCard = (digits: string) =>
  `${digits.slice(0, 6)}${'*'.repeat(digits.length - 10)}${digits.slice(-4)}`;
/** D15: masked samples keep the last 4 digits only. */
const maskedCard = (digits: string) => `${'*'.repeat(digits.length - 4)}${digits.slice(-4)}`;
/** No full card-like number in a text (13–19 digits, contiguous). */
const LONG_DIGIT_RUN = /\d{13,19}/;
/**
 * The text with hex digests (SHA-256 of an attachment, object hashes: 32+ hex characters with at
 * least one letter) blanked: a random digest can hold 13+ consecutive decimal digits by chance,
 * which is not a leaked number. A plain digit run is never blanked.
 */
const withoutHexDigests = (text: string) =>
  text.replace(/[0-9a-f]{32,}/gi, (hex) => (/[a-f]/i.test(hex) ? '<hex>' : hex));
/** JSON of a Prisma row (BigInt ids as strings). */
const json = (value: unknown) =>
  JSON.stringify(value, (_key, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('dlp-smtp');
  out = await sendingDomain(fx, org, 'dlp-out');
  internal = await fx.domain(org, 'dlp-int', { inboundEnabled: false });
  // The sending domain also receives the inbound case; the internal domain is reached on 10026.
  await fx.destinations(out, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(internal, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  sasl = await fx.saslConnector(org, 'dlp');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);

  // security_analyst holds dlp:read, dlp:manage, dlp:evidence_read and message:read (D21).
  analyst = await apiSession(fx.prisma, await organizationRef(fx, org), 'security_analyst', {
    mfa: true,
  });
  readOnly = await apiSession(fx.prisma, await organizationRef(fx, org), 'read_only_user');

  const policy = await analyst.post('/dlp/policies', {
    name: 'Outbound data protection',
    priority: 10,
    directions: ['outbound', 'internal'],
  });
  expect(policy.status, JSON.stringify(policy.body)).toBe(201);
  policyId = (policy.body as { id: string }).id;
  const rules: [keyof typeof ruleIds, Record<string, unknown>, string][] = [
    [
      'A',
      {
        selectors: { categories: ['payment_card'] },
        minCount: 1,
        recipients: { externalOnly: true },
      },
      'quarantine',
    ],
    ['B', { selectors: { categories: ['credential'] } }, 'block'],
    ['C', { selectors: { categories: ['confidential'] } }, 'alert'],
    ['D', { selectors: { categories: ['national_id'] } }, 'require_approval'],
    ['E', { selectors: { categories: ['payment_card'] }, directions: ['internal'] }, 'alert'],
  ];
  for (const [key, conditions, action] of rules) {
    const res = await analyst.post(`/dlp/policies/${policyId}/rules`, {
      name: `Rule ${key}`,
      priority: 10 + Object.keys(ruleIds).indexOf(key),
      conditions,
      action,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    ruleIds[key] = (res.body as { id: string }).id;
  }
  const exception = await analyst.post('/dlp/exceptions', {
    scope: 'recipient_domain',
    value: partnerDomain(),
    reason: 'Card processing partner (stack test)',
    expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
  });
  expect(exception.status, JSON.stringify(exception.body)).toBe(201);
  exceptionId = (exception.body as { id: string }).id;
}, 180_000);

afterAll(async () => {
  if (gate.skip) return;
  await analyst?.remove();
  await readOnly?.remove();
  const names = [out, internal].filter(Boolean).map((d) => d.name);
  const queued = involving(await listQueue('postfix-outbound'), [
    ...names,
    extDomain(),
    partnerDomain(),
  ]);
  await deleteQueued(
    'postfix-outbound',
    queued.map((m) => m.queue_id),
  );
  for (const domain of [extDomain(), partnerDomain(), ...names]) {
    await clearSinkDomain(domain, 'all').catch(() => undefined);
  }
  const removed = org;
  await fx.cleanup();
  await purgeDormantQueues();
  if (removed === 0n) return;
  // Verify the cleanup: no DLP row, evidence object or fixture organization is left.
  const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  const s3cfg = stack.s3();
  const s3 = new S3Client({
    region: s3cfg.region,
    endpoint: s3cfg.endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId: s3cfg.accessKeyId, secretAccessKey: s3cfg.secretAccessKey },
  });
  try {
    const where = { organizationId: removed };
    const left = {
      dlpScanResults: await prisma.dlpScanResult.count({ where }),
      dlpEvidence: await prisma.dlpEvidence.count({ where }),
      dlpPolicies: await prisma.dlpPolicy.count({ where }),
      dlpPolicyRules: await prisma.dlpPolicyRule.count({ where }),
      dlpExceptions: await prisma.dlpException.count({ where }),
      dlpCustomPatterns: await prisma.dlpCustomPattern.count({ where }),
      dlpKeywordDictionaries: await prisma.dlpKeywordDictionary.count({ where }),
      dlpComplianceSettings: await prisma.dlpComplianceSettings.count({ where }),
      organizations: await prisma.organization.count({ where: { id: removed } }),
    };
    expect(left).toEqual({
      dlpScanResults: 0,
      dlpEvidence: 0,
      dlpPolicies: 0,
      dlpPolicyRules: 0,
      dlpExceptions: 0,
      dlpCustomPatterns: 0,
      dlpKeywordDictionaries: 0,
      dlpComplianceSettings: 0,
      organizations: 0,
    });
    const objects = await s3.send(
      new ListObjectsV2Command({
        Bucket: s3cfg.mailBucket,
        Prefix: `org/${removed.toString()}/`,
      }),
    );
    expect((objects.Contents ?? []).map((o) => o.Key)).toEqual([]);
  } finally {
    await prisma.$disconnect();
    s3.destroy();
  }
}, 240_000);

/** One authenticated submission (postfix-outbound:587) of a prepared RFC 5322 text. */
async function submit(to: readonly string[], text: string, from = `alice@${out.name}`) {
  const sent = await swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: sasl,
    from,
    to,
    data: text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  return sent;
}

/** Submits, waits for round 0 and returns its finals and the round's dlp rows. */
async function scanned(
  to: readonly string[],
  subject: string,
  body: string,
  attachments: readonly MessageAttachment[] = [],
) {
  const { text } = attachmentMessage({
    from: `Alice <alice@${out.name}>`,
    to,
    subject,
    body,
    attachments,
  });
  const started = Date.now();
  const sent = await submit(to, text);
  const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
  const round = await waitForRoundComplete(fx.prisma, message, 0, 180_000);
  const scannedAfterMs = Date.now() - started;
  expect(round).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
  const finals = (await engineResultsOf(fx.prisma, message)).filter((r) => r.isFinal);
  expect(roundFinalEngines(finals)).toEqual(['attachment', 'bec', 'dlp', 'rspamd', 'url']);
  const dlpFinal = finals.find((f) => f.engine === 'dlp')!;
  const [dlpRow, ...moreDlp] = await dlpResultsOf(fx.prisma, message);
  expect(moreDlp).toEqual([]);
  expect(dlpRow).toMatchObject({ scanId: round.id, lifecycleRound: 0, rulesVersion: 'dlp-map/1' });
  // One ledger row of the dlp consumer for the parsed event (stage 1, D1).
  const parsed = await fx.prisma.messageOutbox.findFirstOrThrow({
    where: {
      organizationId: org,
      aggregateId: message.id.toString(),
      eventType: 'mail.message.parsed.v1',
    },
  });
  expect(
    await fx.prisma.messageIdempotency.count({
      where: { consumer: DLP_LEDGER, eventId: parsed.eventId },
    }),
  ).toBe(1);
  // §2.0-2: no full value in any stored column of the result row or the final.
  expect(
    withoutHexDigests(
      json({
        ...dlpRow,
        id: 0,
        messageId: 0,
        scanId: 0,
        organizationId: 0,
        matchedPolicyId: 0,
        matchedRuleId: 0,
      }),
    ),
  ).not.toMatch(LONG_DIGIT_RUN);
  expect(withoutHexDigests(json(dlpFinal.evidence ?? null))).not.toMatch(LONG_DIGIT_RUN);
  return { message, round, dlpFinal, dlpRow: dlpRow!, scannedAfterMs, started };
}

/** The incident events of a message, parsed with the strict contract (D14). */
async function incidentsOf(message: { id: bigint; receivedAt: Date }) {
  const rows = await dlpIncidentEventsOf(fx.prisma, org, message);
  for (const row of rows)
    expect(withoutHexDigests(JSON.stringify(row.payload))).not.toMatch(LONG_DIGIT_RUN);
  return rows.map((row) => messageDlpIncidentV1.parse(row.payload));
}

/** The disposition the DLP binding of the policy floor gives each held DLP action (P9.5). */
const DLP_DISPOSITION = {
  require_approval: 'require_approval',
  quarantine: 'quarantine',
  block: 'reject',
} as const;

/**
 * Held by policy (D13; since step 5.2 the DLP binding of the policy floor, before it the dev
 * pass-through): evaluated with the DLP floor reason, in the disposition's state, never approved.
 */
async function expectHeld(
  message: { id: bigint; receivedAt: Date },
  rcpts: readonly string[],
  action: keyof typeof DLP_DISPOSITION,
  before: { floor: number },
): Promise<void> {
  const [scannedEvent] = await scannedEventsOf(fx.prisma, org, message);
  expect(messageScannedV1.parse(scannedEvent!.payload)).toMatchObject({ outcome: 'scanned' });
  const evaluation = await expectPolicyHeld(fx.prisma, message, {
    min: DLP_DISPOSITION[action],
  });
  expect(floorOf(evaluation).reasons).toContain(`policy.floor.dlp_${action}`);
  // Observation window: nothing is approved or delivered later.
  await sleep(10_000);
  expect(await policyFloorRaises(`dlp_${action}`)).toBeGreaterThanOrEqual(before.floor + 1);
  const state = DISPOSITION_STATE[evaluation.disposition];
  const reason = {
    require_approval: 'policy_hold',
    quarantine: 'policy_quarantine',
    reject: 'policy_reject',
    allow: 'policy_deliver',
  }[evaluation.disposition];
  expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
    status: state,
    statusReason: reason,
    lifecycleRound: 0,
  });
  expect((await pathOf(fx.prisma, message)).slice(-3)).toEqual([
    ['scanning', 'scanned', 'scan_complete'],
    ['scanned', 'policy_evaluated', 'policy_decided'],
    ['policy_evaluated', state, reason],
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
  for (const rcpt of rcpts) {
    for (const service of SINK_SERVICES) {
      expect(await sinkFiles(rcpt, service), `${rcpt} ${service}`).toEqual([]);
    }
  }
  await expectConsistentHistory(fx.prisma, message);
}

async function heldCounters(action: string) {
  return { floor: await policyFloorRaises(`dlp_${action}`) };
}

interface DlpEngineView {
  engine: string;
  final: boolean;
  outcome: string | null;
  reasonCodes: string[];
  dlp?: {
    verdict: string;
    action: string;
    actionSource: string;
    coverage: string;
    findings: { detector: string; count: number; masked: string[] }[];
    policy: {
      winner: { policyId: string; ruleId: string } | null;
      exceptionsApplied: string[];
    };
    evidence: { status: string; purged: boolean };
  } | null;
}

/** The scans read API (replica) once round 0 is completed: the raw body and the dlp entry. */
async function dlpEngineView(session: ApiSession, publicId: string) {
  return waitFor(
    `GET /messages/${publicId}/scans with a completed round and a dlp engine entry`,
    async () => {
      const res = await session.get(`/messages/${publicId}/scans`);
      if (res.status !== 200) return undefined;
      const body = res.body as { data: { status: string; engines: DlpEngineView[] }[] };
      const round = body.data[0];
      if (!round || round.status === 'running') return undefined;
      const engine = round.engines.find((e) => e.engine === 'dlp');
      return engine?.final ? { raw: JSON.stringify(res.body), engine } : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 500 },
  );
}

describe.skipIf(gate.skip)(
  'dlp stack: data loss prevention through the outbound path',
  { timeout: 300_000 },
  () => {
    it('scan.dlp has a consumer (the stage-1 engine of topology v7), all eg-scanner', async () => {
      const details = await mgmt.get<{
        consumers?: number;
        consumer_details?: { channel_details?: { user?: string } }[];
      }>(`/queues/${encodeURIComponent(vhost)}/scan.dlp`);
      expect(details.consumers).toBeGreaterThanOrEqual(1);
      const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
      expect(new Set((details.consumer_details ?? []).map((c) => c.channel_details?.user))).toEqual(
        new Set([scanner]),
      );
    });

    it('(1) card numbers in the body and in a DOCX: suspicious, quarantine, one incident, evidence stored, not approved', async () => {
      const before = await heldCounters('quarantine');
      const cards: [string, string] = [synthetic.card('4532'), synthetic.card('4024')];
      const iban = synthetic.iban('GB');
      const docx = await buildDocx({ body: [`Debit card ${group4(cards[1])}`, 'Kind regards'] });
      const rcpt = `payments@${extDomain()}`;
      const { message, round, dlpFinal, dlpRow, scannedAfterMs } = await scanned(
        [rcpt],
        'Customer payment details',
        [
          'Hello,',
          `Please charge the customer card: ${group4(cards[0])} exp 09/29.`,
          `Beneficiary IBAN ${iban}`,
          'Thanks',
        ].join('\r\n'),
        [
          {
            filename: 'card-details.docx',
            contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            bytes: docx,
          },
        ],
      );
      expect(message.direction).toBe('outbound');
      // D10: a finding never makes the engine outcome malicious; the action holds the mail.
      expect(dlpFinal).toMatchObject({ outcome: 'suspicious', errorCode: null, attempt: 1 });
      expect(dlpFinal.engineVersion).toMatch(
        /^dlp\/1;dict=[0-9a-f]{8};data=[0-9a-f]{8};ext=dlp-extract\/1$/,
      );
      const codes = dlpFinal.reasonCodes as string[];
      expect(codes[0]).toBe('dlp.action.quarantine');
      expect(codes).toEqual(
        expect.arrayContaining(['dlp.payment_card.number', 'dlp.bank_account.iban']),
      );
      expect(round.scanVerdict).not.toBe('malicious');
      expect(dlpRow).toMatchObject({
        organizationId: org,
        direction: 'outbound',
        verdict: 'suspicious',
        action: 'quarantine',
        actionSource: 'tenant_policy',
        coverage: 'complete',
        extractorVersion: 'dlp-extract/1',
        evidenceStatus: 'stored',
      });
      expect(dlpRow.policyVersion).toMatch(/^pol\/1;h=[0-9a-f]{12}$/);
      expect(dlpRow.matchedPolicyId).not.toBeNull();
      expect(dlpRow.matchedRuleId).not.toBeNull();
      expect(dlpRow.policy).toMatchObject({
        winner: { policyId, ruleId: ruleIds.A },
        exceptionsApplied: [],
      });
      const pc1 = (dlpRow.findings as { detector: string; count: number; masked: string[] }[]).find(
        (f) => f.detector === 'PC1',
      );
      expect(pc1).toMatchObject({ count: 2 });
      expect([...pc1!.masked].sort()).toEqual(cards.map(maskedCard).sort());
      // Both sources: the body and the DOCX attachment.
      expect(
        (dlpRow.coverageDetail as { sources: { source: string; status: string }[] }).sources,
      ).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ source: 'body_text', status: 'scanned' }),
          expect.objectContaining({ source: 'attachment', status: 'scanned' }),
        ]),
      );
      const stored = json(dlpRow);
      for (const value of [...cards, iban]) expect(stored).not.toContain(value);

      // D16: one evidence row, its object encrypted at rest under the organization's prefix.
      const [evidence, ...moreEvidence] = await dlpEvidenceOf(fx.prisma, message);
      expect(moreEvidence).toEqual([]);
      expect(evidence).toMatchObject({
        organizationId: org,
        scanId: round.id,
        algorithm: 'dlp-evidence/1',
        purgedAt: null,
      });
      expect(evidence!.wrappedKey).toMatch(/^v1\./);
      expect(evidence!.matchCount).toBeGreaterThanOrEqual(3);
      expect(evidence!.objectKey!.startsWith(`org/${org.toString()}/dlp-evidence/`)).toBe(true);
      const object = await fx.object(evidence!.objectKey!);
      expect(object.subarray(0, 6).toString('latin1')).toBe('EGDLP1');
      expect(object.length).toBe(evidence!.objectSizeBytes);
      const latin = object.toString('latin1');
      for (const value of [...cards, iban, evidenceCard(cards[0])]) {
        expect(latin).not.toContain(value);
      }

      // D14: exactly one incident (ids, codes and counts only).
      const incidents = await incidentsOf(message);
      expect(incidents).toHaveLength(1);
      expect(incidents[0]).toMatchObject({
        messageId: message.id.toString(),
        lifecycleRound: 0,
        scanId: round.id.toString(),
        direction: 'outbound',
        action: 'quarantine',
        actionSource: 'tenant_policy',
        policyId,
        ruleId: ruleIds.A,
        exceptionApplied: false,
        coverage: 'complete',
        evidenceAvailable: true,
      });
      expect(incidents[0]!.categories).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ category: 'payment_card', count: 2, maxSeverity: 'high' }),
        ]),
      );
      expect(incidents[0]!.detectorCodes).toContain('dlp.payment_card.number');

      await expectHeld(message, [rcpt], 'quarantine', before);
      cardMessage = { message, scanId: round.id, cards, iban };
      record('dlp-smtp', { card_quarantine_smtp_to_scanned_ms: scannedAfterMs });
    });

    it('(2) a PEM private key inside a ZIP: block, held', async () => {
      const before = await heldCounters('block');
      const pem = synthetic.pemPrivateKey();
      const zip = await buildZip([
        { name: 'deploy/README.txt', data: 'Deployment notes for the staging cluster.' },
        { name: 'deploy/id_rsa.pem', data: pem },
      ]);
      const rcpt = `contractor@${extDomain()}`;
      const { message, dlpFinal, dlpRow } = await scanned(
        [rcpt],
        'Deployment files',
        'Here are the deployment files you asked for.',
        [{ filename: 'deploy.zip', contentType: 'application/zip', bytes: zip }],
      );
      expect(dlpFinal).toMatchObject({ outcome: 'suspicious', errorCode: null });
      expect((dlpFinal.reasonCodes as string[])[0]).toBe('dlp.action.block');
      expect(dlpFindingCodes(dlpRow.findings)).toContain('dlp.credential.private_key');
      expect(dlpRow).toMatchObject({
        verdict: 'suspicious',
        action: 'block',
        actionSource: 'tenant_policy',
        policy: expect.objectContaining({ winner: { policyId, ruleId: ruleIds.B } }),
      });
      const cr1 = (dlpRow.findings as { detector: string; masked: string[] }[]).find(
        (f) => f.detector === 'CR1',
      );
      // D15: credentials are type-only masks; the finding's source is the ZIP entry.
      expect(cr1!.masked).toEqual(['[private key: RSA]']);
      const stored = json(dlpRow);
      expect(stored).not.toContain('PRIVATE KEY-----');
      for (const line of pem.split('\n').slice(1, -1)) expect(stored).not.toContain(line);
      const incidents = await incidentsOf(message);
      expect(incidents.map((i) => [i.action, i.ruleId])).toEqual([['block', ruleIds.B]]);
      await expectHeld(message, [rcpt], 'block', before);
      keyMessage = { message, pem };
    });

    it('(3) a CONFIDENTIAL board memo: alert, approved and delivered, incident', async () => {
      const rcpt = `director@${extDomain()}`;
      const { message, dlpFinal, dlpRow, started } = await scanned(
        [rcpt],
        'Board memo',
        [
          'CONFIDENTIAL',
          '',
          'Board minutes of the March meeting: the merger agreement draft and the term sheet',
          'are attached for the directors. Please review before Friday.',
        ].join('\r\n'),
      );
      expect(dlpFinal).toMatchObject({ outcome: 'suspicious', errorCode: null });
      expect((dlpFinal.reasonCodes as string[])[0]).toBe('dlp.action.alert');
      expect(dlpFindingCodes(dlpRow.findings)).toContain('dlp.confidential.classification_label');
      expect(dlpRow).toMatchObject({
        verdict: 'suspicious',
        action: 'alert',
        actionSource: 'tenant_policy',
        policy: expect.objectContaining({ winner: { policyId, ruleId: ruleIds.C } }),
      });
      const incidents = await incidentsOf(message);
      expect(incidents.map((i) => [i.action, i.ruleId])).toEqual([['alert', ruleIds.C]]);
      expect(incidents[0]!.categories.map((c) => c.category)).toContain('confidential');
      // D13, since step 5.2: alert is allowed by policy with the mandatory `dlp-alert` TAG
      // (P9.5; outbound platform tag headers are suppressed by default: status `recorded`, P9.11)
      // and delivered.
      const evaluation = await waitForEvaluation(fx.prisma, message, 0);
      expect(evaluation.disposition).toBe('allow');
      expect(floorOf(evaluation)).toMatchObject({ tag: true });
      // A round may carry one TAG per origin (the platform risk TAG of a `tag` recommendation and
      // the floor's mandatory `dlp-alert` TAG, P10): select the DLP one; every TAG is `recorded`
      // (outbound headers suppressed).
      const tags = actionsOf(evaluation).filter((a) => a.type === 'TAG');
      const dlpTag = tags.find((a) =>
        ((a.params as { labels?: string[] }).labels ?? []).includes('dlp-alert'),
      );
      expect(dlpTag, JSON.stringify(tags)).toMatchObject({
        origin: 'floor',
        applicability: 'applies',
        status: 'recorded',
      });
      for (const t of tags) expect(t.status).toBe('recorded');
      record('dlp-smtp', {
        alert_policy: `${evaluation.disposition}:${evaluation.decisionSource}:${evaluation.action}`,
        alert_tags: tags.map((t) => `${t.origin}/${t.status}`).join(','),
      });
      const [delivery] = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 1);
      expect(delivery!.address).toBe(rcpt);
      expect(await sinkFiles(rcpt)).toHaveLength(1);
      record('dlp-smtp', { alert_smtp_to_delivered_ms: Date.now() - started });
    });

    it('(4) a recipient-domain exception: the card message passes (allow, exception applied) and is delivered', async () => {
      const card = synthetic.card('4556');
      const rcpt = `billing@${partnerDomain()}`;
      const { message, dlpFinal, dlpRow } = await scanned(
        [rcpt],
        'Card for the partner',
        `Please process the card: ${group4(card)} exp 11/28.`,
      );
      // The finding stays (suspicious); the exception removed the partner recipient from every
      // rule, so no rule matched and the action is allow (D12: recorded, so an investigator sees
      // why the message passed).
      expect(dlpFinal).toMatchObject({ outcome: 'suspicious', errorCode: null });
      expect(dlpFinal.reasonCodes as string[]).toEqual(
        expect.arrayContaining(['dlp.exception.applied', 'dlp.payment_card.number']),
      );
      expect(dlpRow).toMatchObject({ verdict: 'suspicious', action: 'allow' });
      expect(dlpRow.policy).toMatchObject({ winner: null, exceptionsApplied: [exceptionId] });
      expect(await incidentsOf(message)).toEqual([]);
      const [delivery] = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 1);
      expect(delivery!.address).toBe(rcpt);
      expect(await sinkFiles(rcpt)).toHaveLength(1);
    });

    it('(5) an encrypted ZIP: unknown with dlp.not_extracted.encrypted, never clean', async () => {
      const zip = markZipEncrypted(
        await buildZip([{ name: 'cards.txt', data: `Card ${group4(synthetic.card('4716'))}` }]),
      );
      const { dlpFinal, dlpRow } = await scanned(
        [`archive@${extDomain()}`],
        'Archive',
        'The archive is attached; the password follows by phone.',
        [{ filename: 'archive.zip', contentType: 'application/zip', bytes: zip }],
      );
      expect(dlpFinal).toMatchObject({ outcome: 'unknown', errorCode: null });
      expect(dlpFinal.reasonCodes as string[]).toEqual(
        expect.arrayContaining(['dlp.coverage.partial', 'dlp.not_extracted.encrypted']),
      );
      expect(dlpFinal.reasonCodes as string[]).not.toContain('dlp.no_findings');
      expect(dlpRow).toMatchObject({
        verdict: 'unknown',
        coverage: 'partial',
        findingCount: 0,
        action: 'allow',
      });
      const sources = (
        dlpRow.coverageDetail as { sources: { source: string; reasons: string[] }[] }
      ).sources;
      expect(sources.find((s) => s.source === 'attachment')!.reasons).toContain(
        'dlp.not_extracted.encrypted',
      );
    });

    it('(6) evidence through the api: decrypted with MFA by a security_analyst (audited), 403 for a read_only_user', async () => {
      expect(cardMessage, 'case (1) must run first').toBeDefined();
      const { message, scanId, cards, iban } = cardMessage!;
      const publicId = await messagePublicId(fx.prisma, message);
      const path = `/messages/${publicId}/scans/${scanId.toString()}/dlp-evidence`;
      const auditsBefore = await fx.prisma.auditLog.count({
        where: { organizationId: org, action: 'dlp_evidence.read', resourceId: publicId },
      });

      const refused = await readOnly!.get(path);
      expect(refused.status).toBe(403);
      expect(withoutHexDigests(JSON.stringify(refused.body))).not.toMatch(LONG_DIGIT_RUN);

      const res = await analyst!.get(path);
      expect(res.status, JSON.stringify(res.body).slice(0, 200)).toBe(200);
      expect(res.headers.get('cache-control')).toBe('no-store');
      const body = res.body as {
        messageId: string;
        scanId: string;
        matchCount: number;
        evidence: {
          format: string;
          matches: { detector: string; value: string; source: { kind: string } }[];
        };
      };
      expect(body).toMatchObject({ messageId: publicId, scanId: scanId.toString() });
      expect(body.evidence.format).toBe('dlp-evidence/1');
      const values = (detector: string) =>
        body.evidence.matches
          .filter((m) => m.detector === detector)
          .map((m) => m.value)
          .sort();
      // PC1 as first 6 + last 4 of the synthetic cards (never the full PAN, D16); the IBAN raw.
      expect(values('PC1')).toEqual(cards.map(evidenceCard).sort());
      expect(values('BA1')).toEqual([iban]);
      expect(
        new Set(
          body.evidence.matches.filter((m) => m.detector === 'PC1').map((m) => m.source.kind),
        ),
      ).toEqual(new Set(['body_text', 'attachment']));
      for (const card of cards) expect(JSON.stringify(body)).not.toContain(card);

      // The audit row (committed before decryption): ids and the match count only.
      const audits = await fx.prisma.auditLog.findMany({
        where: { organizationId: org, action: 'dlp_evidence.read', resourceId: publicId },
        orderBy: { id: 'asc' },
      });
      expect(audits).toHaveLength(auditsBefore + 1);
      expect(audits.at(-1)!.metadata).toEqual({
        messageId: publicId,
        scanId: scanId.toString(),
        matchCount: body.matchCount,
        // Step 6.1: every audit row carries the request id of the HTTP request.
        requestId: expect.any(String),
      });
      expect(withoutHexDigests(json(audits))).not.toMatch(LONG_DIGIT_RUN);
      expect(json(audits)).not.toContain(iban);
      // Nothing was audited for the refused read.
      expect(
        await fx.prisma.auditLog.count({
          where: { organizationId: org, action: 'dlp_evidence.read_failed', resourceId: publicId },
        }),
      ).toBe(0);
    });

    it('(7) the scans read API shows masked values only; a read_only_user gets no dlp section', async () => {
      expect(cardMessage && keyMessage, 'cases (1) and (2) must run first').toBeTruthy();
      const cardId = await messagePublicId(fx.prisma, cardMessage!.message);
      const { raw, engine } = await dlpEngineView(analyst!, cardId);
      expect(withoutHexDigests(raw)).not.toMatch(LONG_DIGIT_RUN);
      for (const value of [...cardMessage!.cards, cardMessage!.iban]) {
        expect(raw).not.toContain(value);
      }
      expect(engine).toMatchObject({
        outcome: 'suspicious',
        dlp: {
          verdict: 'suspicious',
          action: 'quarantine',
          actionSource: 'tenant_policy',
          policy: { winner: { policyId, ruleId: ruleIds.A }, exceptionsApplied: [] },
          evidence: { status: 'stored', purged: false },
        },
      });
      const pc1 = engine.dlp!.findings.find((f) => f.detector === 'PC1')!;
      expect([...pc1.masked].sort()).toEqual(cardMessage!.cards.map(maskedCard).sort());

      const keyId = await messagePublicId(fx.prisma, keyMessage!.message);
      const key = await dlpEngineView(analyst!, keyId);
      expect(key.raw).not.toContain('PRIVATE KEY-----');
      for (const line of keyMessage!.pem.split('\n').slice(1, -1)) {
        expect(key.raw).not.toContain(line);
      }
      expect(key.engine.dlp!.findings.find((f) => f.detector === 'CR1')!.masked).toEqual([
        '[private key: RSA]',
      ]);

      // D20: message:read alone (read_only_user) shows the standard engine fields only.
      const plain = await dlpEngineView(readOnly!, cardId);
      expect(plain.engine).toMatchObject({ engine: 'dlp', outcome: 'suspicious', dlp: null });
      expect(withoutHexDigests(plain.raw)).not.toMatch(LONG_DIGIT_RUN);
      expect(plain.raw).not.toContain(policyId);
      expect(plain.raw).not.toContain(maskedCard(cardMessage!.cards[0]));
    });

    it('(8) a PAN in prose: require_approval, held', async () => {
      const before = await heldCounters('require_approval');
      const rcpt = `tax@${extDomain()}`;
      const { message, dlpFinal, dlpRow } = await scanned(
        [rcpt],
        'Tax filing',
        `For the tax filing, my PAN: ${synthetic.pan()} (permanent account number).`,
      );
      expect((dlpFinal.reasonCodes as string[])[0]).toBe('dlp.action.require_approval');
      expect(dlpFindingCodes(dlpRow.findings)).toContain('dlp.national_id.india_pan');
      expect(dlpRow).toMatchObject({
        action: 'require_approval',
        policy: expect.objectContaining({ winner: { policyId, ruleId: ruleIds.D } }),
      });
      const incidents = await incidentsOf(message);
      expect(incidents.map((i) => [i.action, i.ruleId])).toEqual([['require_approval', ruleIds.D]]);
      await expectHeld(message, [rcpt], 'require_approval', before);
    });

    it('(9) internal mail with a card number: dlp runs with direction internal and the internal rule (alert), delivered', async () => {
      const card = synthetic.card('4916');
      const rcpt = `finance@${internal.name}`;
      const { message, dlpFinal, dlpRow } = await scanned(
        [rcpt],
        'Corporate card',
        `The corporate card for the offsite: ${group4(card)} exp 03/28.`,
      );
      expect(message.direction).toBe('internal');
      expect(dlpRow).toMatchObject({
        direction: 'internal',
        verdict: 'suspicious',
        action: 'alert',
      });
      // Rule A needs an external recipient; rule E (internal only) matched.
      expect(dlpRow.policy).toMatchObject({ winner: { policyId, ruleId: ruleIds.E } });
      expect((dlpFinal.reasonCodes as string[])[0]).toBe('dlp.action.alert');
      const incidents = await incidentsOf(message);
      expect(incidents.map((i) => [i.direction, i.action, i.ruleId])).toEqual([
        ['internal', 'alert', ruleIds.E],
      ]);
      const deliveries = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 1);
      expect(deliveries.map((d) => [d.address, d.direction])).toEqual([[rcpt, 'internal']]);
      expect(await sinkFiles(rcpt)).toHaveLength(1);
    });

    it('(10) an inbound message: dlp skipped with dlp.not_inbound (the tenant does not scan inbound mail)', async () => {
      const rcpt = `inbox@${out.name}`;
      const sent = await sendToMx({
        from: 'alice@clean.scan.test',
        to: [rcpt],
        helo: 'mx.clean.scan.test',
        data: attachmentMessage({
          from: 'alice@clean.scan.test',
          to: [rcpt],
          subject: 'Inbound card',
          body: `Card: ${group4(synthetic.card('5412'))} exp 09/27`,
          attachments: [],
        }).text,
      });
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      expect(message.direction).toBe('inbound');
      const round = await waitForRoundComplete(fx.prisma, message, 0, 180_000);
      const dlpFinal = (await engineResultsOf(fx.prisma, message)).find(
        (r) => r.isFinal && r.engine === 'dlp',
      );
      expect(dlpFinal).toMatchObject({
        scanId: round.id,
        outcome: 'skipped',
        reasonCodes: ['dlp.not_inbound'],
      });
      const [dlpRow] = await dlpResultsOf(fx.prisma, message);
      expect(dlpRow).toMatchObject({
        direction: 'inbound',
        verdict: 'skipped',
        action: 'allow',
        actionSource: 'none',
        findingCount: 0,
        evidenceStatus: 'none',
      });
      expect(await dlpEvidenceOf(fx.prisma, message)).toEqual([]);
      expect(await incidentsOf(message)).toEqual([]);
    });
  },
);
