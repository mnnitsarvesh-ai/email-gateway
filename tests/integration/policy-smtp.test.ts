import { randomInt } from 'node:crypto';
import { eicar } from '@email-gateway/attachment-corpus';
import { Prng, Synthetic } from '@email-gateway/dlp';
import {
  EventTypes,
  messageArchiveRequestedV1,
  policyDecidedV1,
  policyNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { attachmentMessage, type MessageAttachment } from './support/attachment-stack';
import { copiesOfEvent, ManagementApi, purgeDormantQueues } from './support/broker';
import { composeExec, waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import {
  expectConsistentHistory,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles, sinkMessage, SINK_SERVICES } from './support/mail-sink';
import { metricValue } from './support/metrics';
import { envelopeOfRow, LiveBroker, record, sleep } from './support/messaging-stack';
import {
  actionOf,
  actionsOf,
  approvalsOf,
  createAndPublishPolicy,
  evaluationContentProblems,
  evaluationsOf,
  expectPolicyHeld,
  floorOf,
  messageOutboxOf,
  pointNotificationWorkerAtSink,
  POLICY_LEDGER,
  policyEvaluations,
  policyPathOf,
  policyStateChecksums,
  publishVersion,
  recommendationOf,
  restoreNotificationWorker,
  rowJson,
  startPolicyEngine,
  stopPolicyEngine,
  waitForEvaluation,
  type EvaluationRow,
} from './support/policy';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { MAIL_SINK_HOST, organizationRef, sendingDomain } from './support/routing';
import {
  corpusEml,
  messagePublicId,
  scannedEventsOf,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';

/**
 * Step 5.2 policy engine end to end through Postfix and the live containers (docs/plan/steps/
 * 16-policy-engine.md §9.3, P9, P12, P13, P15, P18–P22, P25; ADR-0043/0044/0045). Since 5.2 the
 * policy-engine is the only automatic producer of delivery approvals: it consumes
 * `mail.message.scanned.v1` from `email.policy.evaluate`, writes one `policy_execution_logs` row
 * per message and round, moves the message through E8 and the disposition edge (E10 approved,
 * E11 quarantined, E12 held_for_review, E13 rejected) and writes the outbox rows (decided,
 * approvals `source = policy`, archive and notification requests) in one transaction.
 *
 * Three fixture organizations: A (platform default only until cases 8b and 13), B (a tenant DLP
 * `block` rule, before its first message) and C (tenant policies and a Finance department,
 * published through the api before its first message). The notification-worker is recreated for
 * the run with `NOTIFICATION_SMTP_HOST=mail-sink` on the `mailtest` network (restored from .env
 * in afterAll).
 *
 * 1. Clean inbound → `allow` from the platform default, E8/E10, approval `source = policy`,
 *    delivered.
 * 2. GTUBE outbound → `quarantine` from the recommendation; EICAR inbound → `reject` with the
 *    hard-block floor (`policy_discard`, no notice, no bounce); a card number outbound under the
 *    default DLP policy → `allow` + mandatory TAG `dlp-alert` `recorded` (outbound platform tag
 *    header suppressed), delivered; org B's DLP block → `reject` (`policy_reject`) + sender
 *    non-delivery notice requested and sent to the tenant sender (mail-sink).
 * 3. Tenant rules (org C): QUARANTINE by sender domain; TAG → delivered policy copy with
 *    `X-EG-Policy-Tag` and the subject prefix, approval key `org/<org>/policy/…`, planner
 *    `object="policy_copy"`.
 * 4. Department exception (`unless recipient.department in [finance]`, quantifier `all`): to a
 *    Finance member → delivered; to Finance + another recipient → quarantined.
 * 5. REJECT stops delivery; REQUIRE_APPROVAL → `held_for_review`, operator release (E15) →
 *    delivered.
 * 6. ARCHIVE → `mail.message.archive_requested.v1` in the dormant `email.archive` (peeked
 *    without losing other messages).
 * 7. ALERT → `mail.policy.notification_requested.v1` → notification-worker → mail-sink.
 * 8. A published change applies to the next evaluation only.
 * 9. Rescan of a quarantined message → a new evaluation row; round 0's row unchanged.
 * 10. Policy-engine outage → the message stays `scanned` without approval; after the start it is
 *     evaluated and delivered.
 * 11. An exact copy of a real `scanned.v1` → one evaluation and one approval.
 * 12. Test and message dry-run write nothing (scoped checksums after quiescence) and the dry-run
 *     reproduces the stored decision (`reproducible: true`).
 * 13. Override: a level-only `quarantine` (GTUBE) allowed by an `override` rule only after
 *     `allowRecommendationOverrides` is enabled; EICAR with the same rule stays rejected.
 *
 * Every evaluation row read is checked for content (no `@`, `://`, fixture domain, local part or
 * file name in the explanation, trace, actions, delivery block or any other JSON column).
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
const synthetic = new Synthetic(new Prng(randomInt(1, 2 ** 31 - 1)));
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();

let orgA = 0n;
let orgB = 0n;
let orgC = 0n;
let inA: FixtureDomain;
let outA: FixtureDomain;
let outB: FixtureDomain;
let inC: FixtureDomain;
let saslA: { username: string; password: string };
let saslB: { username: string; password: string };
let analystA: ApiSession | undefined;
let adminA: ApiSession | undefined;
let analystB: ApiSession | undefined;
let analystC: ApiSession | undefined;
let adminC: ApiSession | undefined;
let adminCEmail = '';
let financeId = '';
let rulesPolicyId = '';
let notificationWorkerRedirected = false;
let policyEngineStopped = false;
const extDomain = () => fx.sinkDomain('pol-ext');
/** Local parts of org C that select a tenant rule (never used as rule ids or labels). */
const LP = {
  tag: 'p5tg',
  reject: 'p5rj',
  hold: 'p5hd',
  archive: 'p5ar',
  alert: 'p5al',
  finance: 'p5fn',
  other: 'p5ot',
  quarantine: 'p5qd',
  nextA: 'p5na',
  nextB: 'p5nb',
} as const;
const TAG_LABEL = 'stack-label';
const SUBJECT_PREFIX = '[P5 TAG]';

type Msg = { id: bigint; receivedAt: Date; direction: string; publicId: string };
const shared: {
  clean?: Msg;
  gtube?: Msg;
  eicar?: Msg;
  dept?: Msg;
  nextA?: { message: Msg; row: EvaluationRow };
} = {};

/** Names that must never appear in an evaluation row. */
const forbidden = () =>
  [
    inA?.name,
    outA?.name,
    outB?.name,
    inC?.name,
    extDomain(),
    'clean.scan.test',
    'quarantine.scan.test',
    'alice',
    'readme.txt',
    ...Object.values(LP),
  ].filter((n): n is string => Boolean(n));

function expectNoContent(row: EvaluationRow): void {
  expect(evaluationContentProblems(row, forbidden())).toEqual([]);
}

/** An evaluation row, checked for content and its common columns. */
async function evaluated(message: Msg, round = 0, timeoutMs = 180_000): Promise<EvaluationRow> {
  const row = await waitForEvaluation(fx.prisma, message, round, timeoutMs);
  expect(row).toMatchObject({
    evaluationSeq: round,
    direction: message.direction,
    platformDefaultId: 'pol-default/1',
    dslVersion: 'policy-dsl/1',
    evaluatorVersion: 'policy-eval/1',
    inputVersion: 'policy-input/1',
  });
  expect(row.inputSha256).toMatch(/^[0-9a-f]{64}$/);
  expect(row.snapshotSha256).toMatch(/^[0-9a-f]{64}$/);
  expect(row.explanationText.length).toBeGreaterThan(0);
  expectNoContent(row);
  // One decided event per evaluation (P15), parsed with its strict contract.
  const decided = (
    await messageOutboxOf(fx.prisma, await orgOf(message), message, EventTypes.PolicyDecided)
  )
    .map((r) => policyDecidedV1.parse(r.payload))
    .filter((p) => p.lifecycleRound === round);
  expect(decided).toHaveLength(1);
  expect(decided[0]).toMatchObject({
    disposition: row.disposition,
    inputSha256: row.inputSha256,
    snapshotSha256: row.snapshotSha256,
    policyGeneration: row.policyGeneration.toString(),
  });
  return row;
}

async function orgOf(message: Msg): Promise<bigint> {
  const row = await fx.prisma.emailMessage.findFirstOrThrow({
    where: { id: message.id, receivedAt: message.receivedAt },
    select: { organizationId: true },
  });
  return row.organizationId;
}

beforeAll(async () => {
  assertStackReady(gate);
  // A: platform default only (cases 1, 2, 10–13).
  orgA = await fx.organization('pol');
  inA = await fx.domain(orgA, 'pol-in');
  outA = await sendingDomain(fx, orgA, 'pol-out');
  await fx.destinations(inA, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(outA, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  saslA = await fx.saslConnector(orgA, 'pol');
  // B: a tenant DLP rule blocking card numbers (case 2d), before its first message.
  orgB = await fx.organization('pol-dlp');
  outB = await sendingDomain(fx, orgB, 'pol-blk');
  await fx.destinations(outB, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  saslB = await fx.saslConnector(orgB, 'pol-blk');
  // C: tenant policies (cases 3–8).
  orgC = await fx.organization('pol-rules');
  inC = await fx.domain(orgC, 'pol-rin');
  await fx.destinations(inC, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  expect(await fx.dkimSync()).toMatch(/published=\d+/);

  analystA = await apiSession(fx.prisma, await organizationRef(fx, orgA), 'security_analyst');
  adminA = await apiSession(fx.prisma, await organizationRef(fx, orgA), 'organization_admin');
  analystB = await apiSession(fx.prisma, await organizationRef(fx, orgB), 'security_analyst');
  analystC = await apiSession(fx.prisma, await organizationRef(fx, orgC), 'security_analyst');
  adminC = await apiSession(fx.prisma, await organizationRef(fx, orgC), 'organization_admin');
  adminCEmail = (
    await fx.prisma.user.findUniqueOrThrow({
      where: { id: adminC.userId },
      select: { email: true },
    })
  ).email;

  const dlp = await analystB.post('/dlp/policies', {
    name: 'Block card numbers',
    priority: 10,
    directions: ['outbound', 'internal'],
  });
  expect(dlp.status, JSON.stringify(dlp.body)).toBe(201);
  const dlpRule = await analystB.post(`/dlp/policies/${(dlp.body as { id: string }).id}/rules`, {
    name: 'Cards → block',
    priority: 10,
    conditions: { selectors: { categories: ['payment_card'] } },
    action: 'block',
  });
  expect(dlpRule.status, JSON.stringify(dlpRule.body)).toBe(201);

  // Org C: the Finance department with one member, then the policies (P5, P17, P22).
  const dept = await adminC.post('/departments', { name: 'Finance' });
  expect(dept.status, JSON.stringify(dept.body)).toBe(201);
  financeId = (dept.body as { id: string }).id;
  const member = await adminC.post(`/departments/${financeId}/members`, {
    address: `${LP.finance}@${inC.name}`,
  });
  expect(member.status, JSON.stringify(member.body)).toBe(201);
  const rules = await createAndPublishPolicy(analystC, adminC, 'Stack rules', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'quarantine-sender-domain',
        priority: 10,
        when: { field: 'sender.envelope.domain', op: 'equals', value: 'quarantine.scan.test' },
        actions: [{ type: 'QUARANTINE' }],
      },
      {
        id: 'reject-recipient',
        priority: 20,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.reject },
        actions: [{ type: 'REJECT' }],
      },
      {
        id: 'hold-recipient',
        priority: 30,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.hold },
        actions: [{ type: 'REQUIRE_APPROVAL' }],
      },
      {
        id: 'tag-recipient',
        priority: 40,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.tag },
        actions: [{ type: 'TAG', label: TAG_LABEL, subjectPrefix: SUBJECT_PREFIX }],
      },
      {
        id: 'archive-recipient',
        priority: 50,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.archive },
        actions: [{ type: 'ARCHIVE' }],
      },
      {
        id: 'alert-recipient',
        priority: 60,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.alert },
        actions: [{ type: 'ALERT', severity: 'warning' }],
      },
    ],
  });
  rulesPolicyId = rules.policyId;
  await createAndPublishPolicy(analystC, adminC, 'Finance only', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 50,
    rules: [
      {
        id: 'quarantine-unless-finance',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'in', value: [LP.finance, LP.other] },
        unless: [
          { field: 'recipient.department', op: 'in', value: [financeId], quantifier: 'all' },
        ],
        actions: [{ type: 'QUARANTINE' }],
      },
    ],
  });

  // The notification-worker relays to the test mail-sink for this run (restored in afterAll).
  await pointNotificationWorkerAtSink();
  notificationWorkerRedirected = true;
}, 600_000);

afterAll(async () => {
  if (gate.skip) return;
  if (policyEngineStopped) await startPolicyEngine().catch(() => undefined);
  if (notificationWorkerRedirected) await restoreNotificationWorker();
  for (const session of [analystA, adminA, analystB, analystC, adminC]) await session?.remove();
  const names = [inA, outA, outB, inC].filter(Boolean).map((d) => d.name);
  for (const service of ['postfix-outbound', 'postfix'] as const) {
    const queued = involving(await listQueue(service), [...names, extDomain()]);
    await deleteQueued(
      service,
      queued.map((m) => m.queue_id),
    );
  }
  for (const domain of [extDomain(), ...names]) {
    await clearSinkDomain(domain, 'all').catch(() => undefined);
  }
  if (adminCEmail) {
    const [local, domain] = adminCEmail.split('@');
    await composeExec('mail-sink', ['rm', '-rf', `/var/mail/sink/${domain}/${local}`]).catch(
      () => undefined,
    );
  }
  const removed = [orgA, orgB, orgC].filter((id) => id !== 0n);
  await fx.cleanup();
  await purgeDormantQueues();
  if (removed.length === 0) return;
  // No policy row of the fixture organizations is left (P22 purge order in the fixtures).
  const { PrismaClient } = await import('@email-gateway/database');
  const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  try {
    const where = { organizationId: { in: removed } };
    expect({
      evaluations: await prisma.policyExecutionLog.count({ where }),
      policies: await prisma.emailPolicy.count({ where }),
      versions: await prisma.policyVersion.count({ where }),
      settings: await prisma.policySettings.count({ where }),
      departments: await prisma.tenantDepartment.count({ where }),
      members: await prisma.tenantDepartmentMember.count({ where }),
      messages: await prisma.emailMessage.count({ where }),
    }).toEqual({
      evaluations: 0,
      policies: 0,
      versions: 0,
      settings: 0,
      departments: 0,
      members: 0,
      messages: 0,
    });
  } finally {
    await prisma.$disconnect();
  }
}, 600_000);

// --- Sending ------------------------------------------------------------------------------------

async function keyOf(organizationId: bigint, queueId: string): Promise<Msg> {
  const row = await waitForMessage(fx.prisma, organizationId, { mtaQueueId: queueId });
  return {
    id: row.id,
    receivedAt: row.receivedAt,
    direction: row.direction,
    publicId: await messagePublicId(fx.prisma, row),
  };
}

async function inbound(
  organizationId: bigint,
  rcpts: readonly string[],
  eml: string,
  from = 'alice@clean.scan.test',
) {
  const sent = await sendToMx({ from, to: rcpts, helo: 'mx.clean.scan.test', data: eml });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  return keyOf(organizationId, sent.queueId!);
}

const cleanEml = () => corpusEml('clean/clean-dkim-aligned.eml');

async function outbound(options: {
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
  return keyOf(options.organizationId, sent.queueId!);
}

const GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';

const gtubeOutbound = (local: string) =>
  outbound({
    organizationId: orgA,
    domain: outA,
    auth: saslA,
    rcpt: `${local}@${extDomain()}`,
    subject: 'Policy stack: GTUBE',
    body: GTUBE,
  });

/** Allowed and delivered: approval `source = policy` of the round, the message `delivered`. */
async function expectDelivered(message: Msg, rcpts: readonly string[], round = 0) {
  await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 240_000);
  const approvals = (await approvalsOf(fx.prisma, message)).filter(
    (a) => (a.payload as { lifecycleRound?: number }).lifecycleRound === round,
  );
  expect(approvals.length).toBeGreaterThanOrEqual(1);
  for (const a of approvals) expect(a.payload).toMatchObject({ source: 'policy' });
  for (const rcpt of rcpts) expect(await sinkFiles(rcpt), rcpt).toHaveLength(1);
  await expectConsistentHistory(fx.prisma, message);
  return approvals;
}

/** Held: never approved or delivered (5 s window), nothing in any sink. */
async function expectNotDelivered(message: Msg, rcpts: readonly string[]) {
  await sleep(5_000);
  expect(await approvalsOf(fx.prisma, message)).toHaveLength(0);
  expect(await fx.prisma.emailDelivery.count({ where: { messageId: message.id } })).toBe(0);
  for (const rcpt of rcpts) {
    for (const service of SINK_SERVICES) {
      expect(await sinkFiles(rcpt, service), `${rcpt} ${service}`).toEqual([]);
    }
  }
  await expectConsistentHistory(fx.prisma, message);
}

/** The policy decision path of round 0 after the scan (E8 + disposition edge). */
async function expectDecisionPath(message: Msg, row: EvaluationRow) {
  const path = await pathOf(fx.prisma, message);
  const at = path.findIndex(([, to]) => to === 'policy_evaluated');
  expect(at).toBeGreaterThan(0);
  expect(path.slice(at, at + 2)).toEqual(policyPathOf(row));
  const history = await fx.prisma.emailMessageStatusHistory.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { version: 'asc' },
  });
  expect(history.slice(at, at + 2).map((h) => [h.actorRole, h.actorService])).toEqual([
    ['policy', 'policy-engine'],
    ['policy', 'policy-engine'],
  ]);
}

/** Notification requests of a message (P15), parsed with the strict contract. */
async function notificationsOf(message: Msg) {
  return (
    await messageOutboxOf(
      fx.prisma,
      await orgOf(message),
      message,
      EventTypes.PolicyNotificationRequested,
    )
  ).map((r) => ({ eventId: r.eventId, payload: policyNotificationRequestedV1.parse(r.payload) }));
}

const notificationsSent = (kind: string) =>
  metricValue('notification-worker', 'notification_policy_messages_total', {
    kind,
    result: 'sent',
  });

// --- Cases --------------------------------------------------------------------------------------

describe.skipIf(gate.skip)(
  'policy engine stack: decisions through Postfix',
  { timeout: 900_000 },
  () => {
    it('(1) clean inbound: platform default allow, E8/E10, approval source policy, delivered', async () => {
      const before = await policyEvaluations({
        trigger: 'scanned',
        disposition: 'allow',
        source: 'platform_default',
        direction: 'inbound',
      });
      const rcpt = `clean@${inA.name}`;
      const message = await inbound(orgA, [rcpt], cleanEml());
      const row = await evaluated(message);
      expect(row).toMatchObject({
        trigger: 'scanned',
        disposition: 'allow',
        decisionSource: 'platform_default',
        action: 'deliver',
        overrideApplied: false,
        decisivePolicyPublicId: null,
        decisiveRuleId: null,
        policyGeneration: 0n,
      });
      expect(['original', 'rewritten']).toContain(row.deliveredObject);
      expect(row.objectKey).toBeNull();
      expect(floorOf(row).disposition).toBeNull();
      expect(recommendationOf(row)).toMatchObject({ disposition: 'allow', revisions: [0] });
      const scan = await waitForRoundComplete(fx.prisma, message, 0);
      expect(row.scanId).toBe(scan.id);
      const [approval] = await expectDelivered(message, [rcpt]);
      expect(approval!.payload).toMatchObject({
        source: 'policy',
        deliverySeq: 0,
        lifecycleRound: 0,
      });
      await expectDecisionPath(message, row);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({ status: 'delivered' });
      const final = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.id, receivedAt: message.receivedAt },
        select: { finalAction: true, finalVerdict: true, riskScore: true },
      });
      expect(final).toMatchObject({ finalAction: 'deliver', finalVerdict: row.finalVerdict });
      expect(final.riskScore).toBe(row.riskScore);
      expect(
        await policyEvaluations({
          trigger: 'scanned',
          disposition: 'allow',
          source: 'platform_default',
          direction: 'inbound',
        }),
      ).toBeGreaterThanOrEqual(before + 1);
      // The read APIs (replica): the scans `policy` section and the evaluations list (no address).
      const view = await waitFor(
        'the policy section of the scans read API',
        async () => {
          const res = await analystA!.get(`/messages/${message.publicId}/scans`);
          const body = res.body as { data?: { round: number; policy: unknown }[] };
          const entry = body.data?.find((r) => r.round === 0);
          return entry?.policy
            ? { raw: JSON.stringify(entry.policy), policy: entry.policy }
            : undefined;
        },
        { timeoutMs: 30_000, intervalMs: 500 },
      );
      expect(view.policy).toMatchObject({ disposition: 'allow', lifecycleRound: 0 });
      // The policy section carries no address (§2.0-8).
      expect(view.raw).not.toContain('@');
      const list = await analystA!.get(`/messages/${message.publicId}/policy-evaluations`);
      expect(list.status).toBe(200);
      expect((list.body as { data: unknown[] }).data).toHaveLength(1);
      shared.clean = message;
      record('policy-smtp', {
        clean: `${row.disposition}:${row.decisionSource}`,
        us: row.durationUs,
      });
    });

    it('(2a) GTUBE outbound: quarantine from the recommendation, quarantined, not delivered', async () => {
      const message = await gtubeOutbound('gtube');
      const row = await evaluated(message);
      expect(row).toMatchObject({
        disposition: 'quarantine',
        decisionSource: 'platform_default',
        action: 'quarantine',
        deliveredObject: 'none',
        delivery: null,
      });
      expect(recommendationOf(row)).toMatchObject({
        disposition: 'quarantine',
        riskAction: 'quarantine',
      });
      expect(row.reasonCodes as string[]).toContain('policy.default.risk_quarantine');
      await expectPolicyHeld(fx.prisma, message);
      await expectNotDelivered(message, [`gtube@${extDomain()}`]);
      await expectDecisionPath(message, row);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
        status: 'quarantined',
        statusReason: 'policy_quarantine',
      });
      shared.gtube = message;
      record('policy-smtp', {
        gtube: `${row.disposition}:${row.decisionSource}`,
        gtube_level_only: recommendationOf(row).levelOnly,
      });
    });

    it('(2b) EICAR inbound: reject through the hard-block floor, policy_discard, no notice, no bounce', async () => {
      const built = attachmentMessage({
        from: 'alice@clean.scan.test',
        to: [`eicar@${inA.name}`],
        subject: 'Policy stack: EICAR',
        attachments: [{ filename: 'readme.txt', contentType: 'text/plain', bytes: eicar() }],
      });
      const message = await inbound(orgA, [`eicar@${inA.name}`], built.text);
      const row = await evaluated(message);
      expect(row).toMatchObject({
        disposition: 'reject',
        action: 'discard',
        deliveredObject: 'none',
      });
      expect(['floor', 'platform_default']).toContain(row.decisionSource);
      expect(floorOf(row)).toMatchObject({ disposition: 'reject' });
      expect(floorOf(row).reasons).toContain('policy.floor.hard_block');
      await expectPolicyHeld(fx.prisma, message, { min: 'reject' });
      await expectNotDelivered(message, [`eicar@${inA.name}`]);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
        status: 'rejected',
        statusReason: 'policy_discard',
      });
      // Inbound: never a sender notice (P9.10) and never a bounce from the outbound MTA.
      expect(await notificationsOf(message)).toEqual([]);
      // No bounce: nothing queued for the (external) sender.
      expect(
        (await listQueue('postfix-outbound')).filter((m) =>
          m.recipients.some((r) => r.address.toLowerCase() === 'alice@clean.scan.test'),
        ),
      ).toEqual([]);
      expect(await sinkFiles('alice@clean.scan.test')).toEqual([]);
      shared.eicar = message;
      record('policy-smtp', { eicar: `${row.disposition}:${row.decisionSource}` });
    });

    it('(2c) card number outbound under the default DLP policy: allow + dlp-alert TAG recorded, delivered', async () => {
      const card = synthetic.card('4532');
      const rcpt = `cards@${extDomain()}`;
      const message = await outbound({
        organizationId: orgA,
        domain: outA,
        auth: saslA,
        rcpt,
        subject: 'Policy stack: card number',
        body: `Please charge card ${card.replace(/(\d{4})(?=\d)/g, '$1 ')} today.\r\nThanks`,
      });
      const row = await evaluated(message);
      const dlp = await fx.prisma.dlpScanResult.findFirstOrThrow({
        where: { messageId: message.id, receivedAt: message.receivedAt },
      });
      expect(dlp).toMatchObject({ action: 'alert', actionSource: 'default_policy' });
      expect(row.disposition).toBe('allow');
      expect(floorOf(row)).toMatchObject({ tag: true });
      // The mandatory TAG of the DLP binding (origin floor) next to any platform risk TAG.
      const tags = actionsOf(row).filter((a) => a.type === 'TAG');
      const tag = tags.find((a) => (a.params as { labels: string[] }).labels.includes('dlp-alert'));
      expect(tag, JSON.stringify(tags)).toMatchObject({
        origin: 'floor',
        status: 'recorded',
        applicability: 'applies',
      });
      for (const t of tags) expect(t.status).toBe('recorded');
      // Outbound platform/floor tag headers are suppressed by default (P9.11): no copy.
      expect(row.deliveredObject).not.toBe('policy_copy');
      expect(rowJson(row)).not.toContain(card);
      await expectDelivered(message, [rcpt]);
      const delivered = await sinkMessage((await sinkFiles(rcpt))[0]!);
      expect(delivered.toString('latin1')).not.toMatch(/^X-EG-Policy-Tag:/im);
      record('policy-smtp', { dlp_alert: `${row.disposition}:${row.action}:${tag!.status}` });
    });

    it('(2d) org B DLP block: reject (policy_reject), sender non-delivery notice requested and sent', async () => {
      const sentBefore = await notificationsSent('sender_non_delivery');
      const card = synthetic.card('4024');
      const rcpt = `cards-block@${extDomain()}`;
      const message = await outbound({
        organizationId: orgB,
        domain: outB,
        auth: saslB,
        rcpt,
        subject: 'Policy stack: card number (block)',
        body: `Card ${card.replace(/(\d{4})(?=\d)/g, '$1 ')} for the invoice.\r\nThanks`,
      });
      const row = await evaluated(message);
      expect(row).toMatchObject({ disposition: 'reject', action: 'reject' });
      expect(floorOf(row).reasons).toContain('policy.floor.dlp_block');
      await expectPolicyHeld(fx.prisma, message, { min: 'reject' });
      await expectNotDelivered(message, [rcpt]);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
        status: 'rejected',
        statusReason: 'policy_reject',
      });
      const notices = await notificationsOf(message);
      expect(notices.map((n) => n.payload.kind)).toEqual(['sender_non_delivery']);
      expect(notices[0]!.payload).toMatchObject({ direction: 'outbound', disposition: 'reject' });
      // The notification-worker sent it to the tenant's own sender (mail-sink), at least once.
      const sender = `alice@${outB.name}`;
      const path = await waitFor(
        'the sender notice in mail-sink',
        async () => (await sinkFiles(sender))[0],
        {
          timeoutMs: 120_000,
          intervalMs: 1_000,
        },
      );
      const notice = (await sinkMessage(path)).toString('utf8');
      expect(notice).toMatch(
        new RegExp(`^Message-ID:\\s+<policy-notice\\.${notices[0]!.eventId}@`, 'im'),
      );
      expect(notice).not.toContain('Policy stack: card number');
      expect(notice).not.toContain(rcpt);
      expect(notice).not.toMatch(/\d{4} \d{4} \d{4}/);
      expect(await notificationsSent('sender_non_delivery')).toBeGreaterThanOrEqual(sentBefore + 1);
      record('policy-smtp', { dlp_block: `${row.disposition}:${row.decisionSource}` });
    });

    it('(3a) tenant QUARANTINE by sender domain', async () => {
      const rcpt = `${LP.quarantine}@${inC.name}`;
      const message = await inbound(orgC, [rcpt], cleanEml(), 'billing@quarantine.scan.test');
      const row = await evaluated(message);
      expect(row.disposition === 'quarantine' || row.disposition === 'reject').toBe(true);
      if (row.disposition === 'quarantine') {
        expect(row).toMatchObject({
          decisionSource: 'tenant_rule',
          decisiveRuleId: 'quarantine-sender-domain',
          decisivePolicyPublicId: rulesPolicyId,
        });
      }
      expect(row.matchedRules as { ruleId: string }[]).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: 'quarantine-sender-domain' })]),
      );
      await expectPolicyHeld(fx.prisma, message, { min: 'quarantine' });
      await expectNotDelivered(message, [rcpt]);
      record('policy-smtp', { sender_domain: `${row.disposition}:${row.decisionSource}` });
    });

    it('(3b) tenant TAG: delivered policy copy with X-EG-Policy-Tag and the subject prefix', async () => {
      const copiesBefore = await metricValue('delivery-worker', 'delivery_approvals_total', {
        source: 'policy',
        object: 'policy_copy',
      });
      const rcpt = `${LP.tag}@${inC.name}`;
      const message = await inbound(orgC, [rcpt], cleanEml());
      const row = await evaluated(message);
      expect(row).toMatchObject({
        disposition: 'allow',
        action: 'tag',
        deliveredObject: 'policy_copy',
      });
      const tag = actionOf(row, 'TAG');
      expect(tag).toMatchObject({ origin: 'tenant_rule', status: 'enforced' });
      expect(row.delivery).toMatchObject({
        headers: [{ name: 'X-EG-Policy-Tag', value: TAG_LABEL }],
        subjectPrefix: SUBJECT_PREFIX,
      });
      const prefix = `org/${orgC.toString()}/policy/`;
      expect(row.objectKey).toMatch(
        new RegExp(
          `^${prefix}\\d{4}/\\d{2}/\\d{2}/${message.id.toString()}/r0-[0-9a-f]{32}\\.eml$`,
        ),
      );
      const [approval] = await expectDelivered(message, [rcpt]);
      expect((approval!.payload as { emlS3Key: string }).emlS3Key).toBe(row.objectKey);
      await expectDecisionPath(message, row);
      expect((await pathOf(fx.prisma, message)).find(([, to]) => to === 'approved')?.[2]).toBe(
        'policy_tag',
      );
      const delivered = (await sinkMessage((await sinkFiles(rcpt))[0]!)).toString('latin1');
      const headerBlock = delivered.split(/\r?\n\r?\n/)[0]!;
      expect(headerBlock).toMatch(new RegExp(`^X-EG-Policy-Tag: ${TAG_LABEL}\\r?$`, 'm'));
      expect(headerBlock).toMatch(/^Subject: \[P5 TAG\] /m);
      expect(await fx.objectKeys(orgC)).toContain(row.objectKey);
      await waitFor(
        'delivery_approvals_total{object="policy_copy"} +1',
        async () =>
          (await metricValue('delivery-worker', 'delivery_approvals_total', {
            source: 'policy',
            object: 'policy_copy',
          })) >=
          copiesBefore + 1,
        { timeoutMs: 30_000, intervalMs: 1_000 },
      );
      record('policy-smtp', { tag_copy: row.deliveredObject });
    });

    it('(4) department exception (all): to Finance only delivered, Finance + another quarantined', async () => {
      const finance = `${LP.finance}@${inC.name}`;
      const other = `${LP.other}@${inC.name}`;
      const only = await inbound(orgC, [finance], cleanEml());
      const onlyRow = await evaluated(only);
      expect(onlyRow.disposition).toBe('allow');
      expect((onlyRow.trace as { entries: { result: string; ref: string }[] }).entries).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            result: 'excepted',
            ref: expect.stringMatching(/\/quarantine-unless-finance$/),
          }),
        ]),
      );
      await expectDelivered(only, [finance]);

      const mixed = await inbound(orgC, [finance, other], cleanEml());
      const mixedRow = await evaluated(mixed);
      expect(mixedRow).toMatchObject({
        disposition: 'quarantine',
        decisionSource: 'tenant_rule',
        decisiveRuleId: 'quarantine-unless-finance',
      });
      await expectPolicyHeld(fx.prisma, mixed);
      shared.dept = mixed;
      // The Finance mailbox holds only the first message (checked below).
      await expectNotDelivered(mixed, [other]);
      expect(await sinkFiles(finance)).toHaveLength(1); // only the first message
      record('policy-smtp', { dept_only: onlyRow.disposition, dept_mixed: mixedRow.disposition });
    });

    it('(5) REJECT stops delivery; REQUIRE_APPROVAL → held_for_review, then operator release → delivered', async () => {
      const rejectRcpt = `${LP.reject}@${inC.name}`;
      const rejected = await inbound(orgC, [rejectRcpt], cleanEml());
      const rejectRow = await evaluated(rejected);
      expect(rejectRow).toMatchObject({
        disposition: 'reject',
        action: 'discard',
        decisionSource: 'tenant_rule',
        decisiveRuleId: 'reject-recipient',
      });
      await expectPolicyHeld(fx.prisma, rejected, { min: 'reject' });
      await expectNotDelivered(rejected, [rejectRcpt]);
      expect(await notificationsOf(rejected)).toEqual([]);

      const holdRcpt = `${LP.hold}@${inC.name}`;
      const held = await inbound(orgC, [holdRcpt], cleanEml());
      const holdRow = await evaluated(held);
      expect(holdRow).toMatchObject({
        disposition: 'require_approval',
        action: 'require_approval',
        decisiveRuleId: 'hold-recipient',
      });
      await expectPolicyHeld(fx.prisma, held);
      await expectNotDelivered(held, [holdRcpt]);
      expect(await lifecycleOf(fx.prisma, held)).toMatchObject({
        status: 'held_for_review',
        statusReason: 'policy_hold',
      });
      const current = await lifecycleOf(fx.prisma, held);
      const res = await adminC!.post(
        `/messages/${held.publicId}/release`,
        { expectedVersion: current.version, reason: 'stack test: reviewed and released' },
        { 'Idempotency-Key': `it-policy-release-${fx.suffix}` },
      );
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      await waitForLifecycle(fx.prisma, held, 'delivered', 'delivery_complete', 240_000);
      expect(await sinkFiles(holdRcpt)).toHaveLength(1);
      const path = await pathOf(fx.prisma, held);
      expect(path.find(([from]) => from === 'held_for_review')).toEqual([
        'held_for_review',
        'approved',
        'review_release',
      ]);
      const approvals = await approvalsOf(fx.prisma, held);
      expect(approvals.map((a) => (a.payload as { source: string }).source)).toEqual([
        'quarantine_release',
      ]);
      // The release is a new round; the policy evaluation of round 0 is unchanged and the only one.
      expect((await evaluationsOf(fx.prisma, held)).map((r) => rowJson(r))).toEqual([
        rowJson(holdRow),
      ]);
    });

    it('(6) ARCHIVE → archive_requested in the dormant email.archive (peeked, nothing lost)', async () => {
      const rcpt = `${LP.archive}@${inC.name}`;
      const message = await inbound(orgC, [rcpt], cleanEml());
      const row = await evaluated(message);
      expect(row.disposition).toBe('allow');
      expect(actionOf(row, 'ARCHIVE')).toMatchObject({
        status: 'requested',
        applicability: 'applies',
      });
      const [request] = await messageOutboxOf(
        fx.prisma,
        orgC,
        message,
        EventTypes.MessageArchiveRequested,
      );
      expect(request).toBeDefined();
      const payload = messageArchiveRequestedV1.parse(request!.payload);
      const stored = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.id, receivedAt: message.receivedAt },
        select: { emlObjectKey: true },
      });
      expect(payload).toMatchObject({
        source: 'policy',
        emlS3Key: stored.emlObjectKey,
        ruleRef: expect.stringMatching(/\/archive-recipient$/),
      });
      await waitFor(
        'the archive request in email.archive',
        async () => (await copiesOfEvent(mgmt, vhost, 'email.archive', request!.eventId)) === 1,
        { timeoutMs: 60_000, intervalMs: 1_000 },
      );
      expect((await mgmt.queue(vhost, 'email.archive')).consumers).toBe(0);
      await expectDelivered(message, [rcpt]);
      record('policy-smtp', { archive: actionOf(row, 'ARCHIVE')!.status });
    });

    it('(7) ALERT → notification-worker → the alert mail in mail-sink', async () => {
      const sentBefore = await notificationsSent('policy_alert');
      const rcpt = `${LP.alert}@${inC.name}`;
      const message = await inbound(orgC, [rcpt], cleanEml());
      const row = await evaluated(message);
      expect(actionOf(row, 'ALERT')).toMatchObject({ status: 'requested' });
      const [request] = await notificationsOf(message);
      expect(request?.payload).toMatchObject({ kind: 'policy_alert', severity: 'warning' });
      const path = await waitFor(
        'the policy alert in mail-sink',
        async () => (await sinkFiles(adminCEmail))[0],
        { timeoutMs: 120_000, intervalMs: 1_000 },
      );
      const mail = (await sinkMessage(path)).toString('utf8');
      expect(mail).toMatch(
        new RegExp(`^Message-ID:\\s+<policy-notice\\.${request!.eventId}@`, 'im'),
      );
      expect(mail).toContain(message.publicId);
      expect(mail).not.toContain('clean.scan.test');
      expect(mail).not.toContain(rcpt);
      expect(await sinkFiles(adminCEmail)).toHaveLength(1);
      expect(await notificationsSent('policy_alert')).toBeGreaterThanOrEqual(sentBefore + 1);
      await expectDelivered(message, [rcpt]);
    });

    it('(10) policy-engine outage: the message stays scanned without approval; after the start it is evaluated and delivered', async () => {
      const rcpt = `outage@${inA.name}`;
      await stopPolicyEngine();
      policyEngineStopped = true;
      let message: Msg;
      try {
        message = await inbound(orgA, [rcpt], cleanEml());
        await waitForRoundComplete(fx.prisma, message, 0, 180_000);
        await waitForLifecycle(fx.prisma, message, 'scanned', 'scan_complete');
        await sleep(15_000);
        expect(await lifecycleOf(fx.prisma, message)).toMatchObject({ status: 'scanned' });
        expect(await evaluationsOf(fx.prisma, message)).toEqual([]);
        expect(await approvalsOf(fx.prisma, message)).toHaveLength(0);
        expect((await mgmt.queue(vhost, 'email.policy.evaluate')).consumers).toBe(0);
      } finally {
        await startPolicyEngine();
        policyEngineStopped = false;
      }
      const row = await evaluated(message, 0, 240_000);
      expect(row.disposition).toBe('allow');
      await expectDelivered(message, [rcpt]);
    });

    it('(11) an exact copy of a real scanned.v1: one evaluation, one approval', async () => {
      expect(shared.clean, 'case 1 left a delivered message').toBeDefined();
      const message = shared.clean!;
      const [scanned] = await scannedEventsOf(fx.prisma, orgA, message);
      expect(scanned!.publishedAt).not.toBeNull();
      const before = rowJson(await evaluationsOf(fx.prisma, message));
      const ledger = () =>
        fx.prisma.messageIdempotency.count({
          where: { consumer: POLICY_LEDGER, eventId: scanned!.eventId },
        });
      expect(await ledger()).toBe(1);
      const duplicates = () =>
        metricValue('policy-engine', 'amqp_consumer_messages_total', {
          queue: 'email.policy.evaluate',
          outcome: 'duplicate',
        });
      const duplicatesBefore = await duplicates();
      const broker = await LiveBroker.connect();
      try {
        await broker.publish([envelopeOfRow(scanned!)]);
        await broker.publish([envelopeOfRow(scanned!)]);
      } finally {
        await broker.close();
      }
      await waitFor(
        'two ledger duplicates in the policy-engine',
        async () => (await duplicates()) >= duplicatesBefore + 2,
        {
          timeoutMs: 60_000,
          intervalMs: 500,
        },
      );
      await sleep(3_000);
      expect(await ledger()).toBe(1);
      expect(rowJson(await evaluationsOf(fx.prisma, message))).toBe(before);
      expect(await approvalsOf(fx.prisma, message)).toHaveLength(1);
      expect(
        await messageOutboxOf(fx.prisma, orgA, message, EventTypes.PolicyDecided),
      ).toHaveLength(1);
    });

    it('(9) rescan of a quarantined message: a new evaluation row for round 1, round 0 unchanged', async () => {
      expect(shared.gtube, 'case 2a left a quarantined message').toBeDefined();
      const message = shared.gtube!;
      const [round0] = await evaluationsOf(fx.prisma, message);
      const current = await lifecycleOf(fx.prisma, message);
      expect(current.status).toBe('quarantined');
      const res = await analystA!.post(
        `/messages/${message.publicId}/rescan`,
        { expectedVersion: current.version, reason: 'stack test: re-evaluate' },
        { 'Idempotency-Key': `it-policy-rescan-${fx.suffix}` },
      );
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      const row1 = await evaluated(message, 1);
      expect(row1.scanId).not.toBe(round0!.scanId);
      expect(row1.disposition).toBe('quarantine');
      const rows = await evaluationsOf(fx.prisma, message);
      expect(rows.map((r) => r.evaluationSeq)).toEqual([0, 1]);
      expect(rowJson(rows[0])).toBe(rowJson(round0));
      await expectPolicyHeld(fx.prisma, message, { round: 1 });
    });

    it('(12) test and message dry-run write nothing; the dry-run reproduces the stored decision', async () => {
      expect(shared.dept && shared.clean, 'cases 1 and 4 ran').toBeTruthy();
      const targets = [
        { session: analystC!, org: orgC, message: shared.dept! },
        { session: analystA!, org: orgA, message: shared.clean! },
      ];
      for (const { session, org, message } of targets) {
        const [stored] = await evaluationsOf(fx.prisma, message);
        // Quiet organization: nothing changes for 5 s (late delivery rows of earlier cases).
        let quiet = await policyStateChecksums(fx.prisma, org);
        await waitFor(
          'no new row in the organization for 5 s',
          async () => {
            await sleep(5_000);
            const now = await policyStateChecksums(fx.prisma, org);
            const same = JSON.stringify(now) === JSON.stringify(quiet);
            quiet = now;
            return same;
          },
          { timeoutMs: 180_000, intervalMs: 0 },
        );
        const before = quiet;
        const okBefore = await metricValue('api', 'policy_dry_runs_total', {
          kind: 'message',
          result: 'ok',
        });
        const dry = await waitFor(
          `dry-run of scan ${stored!.scanId} (replicated)`,
          async () => {
            const r = await session.post(
              `/messages/${message.publicId}/scans/${stored!.scanId!.toString()}/policy/dry-run`,
              {},
            );
            return r.status === 409 ? undefined : r;
          },
          { timeoutMs: 30_000, intervalMs: 500 },
        );
        expect(dry.status, JSON.stringify(dry.body)).toBe(200);
        const body = dry.body as {
          result: { disposition: string; inputSha256: string; explanation: { text: string } };
          stored: { disposition: string; inputSha256: string } | null;
          reproducible: boolean;
        };
        expect(body.reproducible).toBe(true);
        expect(body.result).toMatchObject({
          disposition: stored!.disposition,
          inputSha256: stored!.inputSha256,
        });
        expect(body.result.explanation.text).toBe(stored!.explanationText);
        expect(body.stored).toMatchObject({ disposition: stored!.disposition });
        const platform = await session.post(
          `/messages/${message.publicId}/scans/${stored!.scanId!.toString()}/policy/dry-run`,
          { target: 'platform' },
        );
        expect(platform.status).toBe(200);
        const test = await session.post('/policies/test', {
          facts: { recipients: [{ address: `${LP.finance}@${inC.name}` }] },
        });
        expect(test.status, JSON.stringify(test.body)).toBe(200);
        await sleep(2_000);
        expect(await policyStateChecksums(fx.prisma, org)).toEqual(before);
        expect(
          await metricValue('api', 'policy_dry_runs_total', { kind: 'message', result: 'ok' }),
        ).toBeGreaterThanOrEqual(okBefore + 2);
      }
      record('policy-smtp', { dry_run_reproducible: true });
    });

    it('(8) a published change applies to the next evaluation only', async () => {
      const rcptA = `${LP.nextA}@${inC.name}`;
      const rcptB = `${LP.nextB}@${inC.name}`;
      const a = await inbound(orgC, [rcptA], cleanEml());
      const rowA = await evaluated(a);
      expect(rowA.disposition).toBe('allow');
      await expectDelivered(a, [rcptA]);
      const generationA = rowA.policyGeneration;

      // A new version of the rules policy quarantining both recipients, published and activated.
      const v1 = await analystC!.get(`/policies/${rulesPolicyId}/versions/1`);
      expect(v1.status).toBe(200);
      const definition = (v1.body as { definition: { rules: unknown[] } }).definition;
      const draft = await analystC!.post(`/policies/${rulesPolicyId}/versions`, {
        definition: {
          ...definition,
          rules: [
            ...definition.rules,
            {
              id: 'quarantine-next',
              priority: 5,
              when: { field: 'recipient.local_part', op: 'in', value: [LP.nextA, LP.nextB] },
              actions: [{ type: 'QUARANTINE' }],
            },
          ],
        },
        changeNote: 'stack test: next evaluation only',
      });
      expect(draft.status, JSON.stringify(draft.body)).toBe(201);
      const versionNo = (draft.body as { versionNo: number }).versionNo;
      expect(versionNo).toBe(2);
      const generation = await publishVersion(adminC!, rulesPolicyId, versionNo);
      expect(BigInt(generation)).toBe(generationA + 1n);

      const b = await inbound(orgC, [rcptB], cleanEml());
      const rowB = await evaluated(b);
      expect(rowB).toMatchObject({
        disposition: 'quarantine',
        decisiveRuleId: 'quarantine-next',
        policyGeneration: generationA + 1n,
      });
      expect(rowB.snapshotSha256).not.toBe(rowA.snapshotSha256);
      await expectPolicyHeld(fx.prisma, b);
      // A was evaluated before the change and is never re-evaluated by it.
      expect(rowJson(await evaluationsOf(fx.prisma, a))).toBe(rowJson([rowA]));
      expect(await lifecycleOf(fx.prisma, a)).toMatchObject({ status: 'delivered' });
    });

    it('(13) override: a level-only quarantine allowed only with allowRecommendationOverrides; EICAR stays rejected', async () => {
      await createAndPublishPolicy(analystA!, adminA!, 'Trusted outbound', {
        dslVersion: 'policy-dsl/1',
        direction: 'outbound',
        priority: 10,
        rules: [
          {
            id: 'trusted-sender-override',
            priority: 1,
            when: { field: 'sender.authenticated.domain', op: 'equals', value: outA.name },
            actions: [{ type: 'ALLOW' }],
            override: true,
          },
        ],
      });
      // Without the setting: the override is clamped (P9.6), the recommendation decides.
      const clamped = await gtubeOutbound('gtube-clamped');
      const clampedRow = await evaluated(clamped);
      expect(recommendationOf(clampedRow).levelOnly).toBe(true);
      expect(clampedRow).toMatchObject({
        disposition: 'quarantine',
        decisionSource: 'platform_default',
        overrideApplied: false,
      });
      expect(clampedRow.clamps).toEqual([
        expect.objectContaining({ from: 'allow', to: 'quarantine', reason: 'override_disabled' }),
      ]);
      await expectPolicyHeld(fx.prisma, clamped);

      // Enabled (audited): the same kind of message is allowed by the override.
      const settings = await adminA!.get('/policy-settings');
      const put = await adminA!.put('/policy-settings', {
        settings: { allowRecommendationOverrides: true },
        expectedRowVersion: (settings.body as { rowVersion: number }).rowVersion,
      });
      expect(put.status, JSON.stringify(put.body)).toBe(200);
      expect(
        await fx.prisma.auditLog.count({
          where: { organizationId: orgA, action: 'policy.settings_overrides_enabled' },
        }),
      ).toBe(1);
      const allowed = await gtubeOutbound('gtube-override');
      const allowedRow = await evaluated(allowed);
      expect(allowedRow).toMatchObject({
        disposition: 'allow',
        decisionSource: 'tenant_rule',
        decisiveRuleId: 'trusted-sender-override',
        overrideApplied: true,
      });
      expect(allowedRow.reasonCodes as string[]).toContain('policy.override.applied');
      // Approved by policy and planned. The reinjection through postfix-outbound:10027 then meets
      // the outbound Rspamd milter, which refuses GTUBE itself (`5.7.1 Gtube pattern`): the
      // delivery fails downstream of policy (observed `rejected/delivery_failed`), the outbound
      // MTA's own protection, not a policy decision.
      const [overrideApproval] = await approvalsOf(fx.prisma, allowed);
      expect(overrideApproval?.payload).toMatchObject({ source: 'policy', lifecycleRound: 0 });
      const settled = await waitFor(
        'the override message planned and settled',
        async () => {
          const state = await lifecycleOf(fx.prisma, allowed);
          return ['delivered', 'rejected'].includes(state.status) ? state : undefined;
        },
        { timeoutMs: 240_000, intervalMs: 1_000 },
      );
      expect(await pathOf(fx.prisma, allowed)).toEqual(
        expect.arrayContaining([
          ['policy_evaluated', 'approved', 'policy_deliver'],
          ['approved', 'delivery_pending', 'delivery_planned'],
        ]),
      );

      // EICAR with the same rule and setting: the hard-block floor still rejects it.
      const eicarOut = await outbound({
        organizationId: orgA,
        domain: outA,
        auth: saslA,
        rcpt: `eicar-out@${extDomain()}`,
        subject: 'Policy stack: EICAR outbound',
        body: 'See attachment.',
        attachments: [{ filename: 'readme.txt', contentType: 'text/plain', bytes: eicar() }],
      });
      const eicarRow = await evaluated(eicarOut);
      expect(eicarRow).toMatchObject({ disposition: 'reject', overrideApplied: false });
      expect(floorOf(eicarRow).reasons).toContain('policy.floor.hard_block');
      await expectPolicyHeld(fx.prisma, eicarOut, { min: 'reject' });
      await expectNotDelivered(eicarOut, [`eicar-out@${extDomain()}`]);
      record('policy-smtp', {
        override_clamped: clampedRow.disposition,
        override_applied: allowedRow.disposition,
        override_delivery: `${settled.status}/${settled.statusReason}`,
        override_eicar: eicarRow.disposition,
      });
    });
  },
);
