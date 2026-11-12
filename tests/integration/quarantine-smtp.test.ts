import { HeadObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { eicar } from '@email-gateway/attachment-corpus';
import { Prng, Synthetic } from '@email-gateway/dlp';
import {
  EventTypes,
  quarantineNotificationRequestedV1,
  quarantineReleaseRequestedV1,
} from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiResponse, type ApiSession } from './support/api-client';
import { attachmentMessage } from './support/attachment-stack';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import {
  expectConsistentHistory,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles, sinkMessage } from './support/mail-sink';
import { record, sleep } from './support/messaging-stack';
import {
  actionOf,
  approvalsOf,
  createAndPublishPolicy,
  evaluationContentProblems,
  evaluationsOf,
  pointNotificationWorkerAtSink,
  restoreNotificationWorker,
  waitForEvaluation,
  type EvaluationRow,
} from './support/policy';
import { deleteQueued, involving, listQueue } from './support/postfix';
import {
  actionsOfEntry,
  entriesOf,
  entryByPublicId,
  entryContentProblems,
  postIdem,
  quarantineContentProblems,
  quarantineMetric,
  noticeText,
  quarantineNoticesSent,
  untilNextMinute,
  waitForEntries,
  waitForEntryState,
  waitForReleaseOutcome,
  windowQuery,
  type EntryRow,
} from './support/quarantine';
import { MAIL_SINK_HOST, organizationRef, sendingDomain } from './support/routing';
import {
  corpusEml,
  messagePublicId,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';
import {
  bodyOf,
  click,
  clickBaseUrl,
  clickTokensIn,
  linkMessage,
  smimeSignedMessage,
  urlRewritesOf,
} from './support/url-stack';

/**
 * Step 5.3 quarantine end to end through Postfix and the live containers (docs/plan/steps/
 * 17-quarantine.md §9.3, Q2–Q24, Q30; ADR-0046–0049). The policy-engine's evaluation
 * transaction writes one entry per held recipient (Q2, Q6), evaluates per recipient when tenant
 * rules are recipient-scoped (Q4, Q5), builds the delivered policy copy with WARN banners and URL
 * rewriting after the scan (Q22, Q23), executes releases from `email.quarantine` with an
 * authoritative re-validation (Q13) and runs the sweeper (expiry, purge, digests; Q17, Q19,
 * Q20). The api serves every user action (Q7–Q18). The notification-worker sends digests and
 * sender notices; it is recreated for the run with `NOTIFICATION_SMTP_HOST=mail-sink` on the
 * `mailtest` network (restored from .env in afterAll).
 *
 * Four fixture organizations: Q (inbound + outbound; tenant rules keyed on recipients, the
 * mailbox users M1/M2, two MFA administrators, a security analyst), D (the digest), W (WARN and
 * URL_REWRITE with the tenant's scan-time rewriting off) and L (the bulk per-minute item limit,
 * an organization of its own so the fixed window counts only this case).
 *
 * Fixture-only writes (each named where it happens): an `archive_legal_holds` row (8.1 has no
 * api yet), one entry's `expires_at` moved into the past (the hold period is ≥ 1 day), and the
 * digest organization's `digest_enabled`/schedule through the organizations api.
 *
 * Every quarantine and evaluation row read is checked for content: no subject (the retired
 * column stays NULL), no `@`/`://`, no fixture domain, local part, subject token, body phrase,
 * file name or card digits in the JSON/text columns written by this step.
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
const synthetic = new Synthetic(new Prng(randomInt(1, 2 ** 31 - 1)));
const run = randomBytes(3).toString('hex');

let orgQ = 0n;
let orgD = 0n;
let orgW = 0n;
let orgL = 0n;
let inQ: FixtureDomain;
let outQ: FixtureDomain;
let inD: FixtureDomain;
let inW: FixtureDomain;
let saslQ: { username: string; password: string };
let analystQ: ApiSession | undefined;
let adminQ: ApiSession | undefined;
let admin2Q: ApiSession | undefined;
let m1: ApiSession | undefined;
let m2: ApiSession | undefined;
let analystD: ApiSession | undefined;
let adminD: ApiSession | undefined;
let mD: ApiSession | undefined;
let analystW: ApiSession | undefined;
let adminW: ApiSession | undefined;
let analystL: ApiSession | undefined;
let notificationWorkerRedirected = false;
let legalHoldId: bigint | undefined;
let holdPolicyId = '';

const extDomain = () => fx.sinkDomain('q5-ext');
/** Local parts selecting the tenant rules (never rule ids, labels or policy names). */
const LP = {
  qa: 'q5qa',
  qb: 'q5qb',
  sa: 'q5sa',
  sb: 'q5sb',
  ev: 'q5ev',
  m1: 'q5m1',
  g1: 'q5g1',
  g2: 'q5g2',
  dl: 'q5dl',
  ex: 'q5ex',
  dg: 'q5dg',
  pv: 'q5pv',
  dw: 'q5dw',
  wn: 'q5wn',
  ur: 'q5ur',
  bk: 'q5bk',
  rs: 'q5rs',
} as const;
const HELD = [LP.qa, LP.qb, LP.dl, LP.ex, LP.pv, LP.dw, LP.bk, LP.rs, LP.m1];
const TAG_LABEL = 'q5-held';
const SUBJECT_TOKEN = `Q5S${run}`;
const BODY_MARKER = `Q5B${run}`;
const BANNER_TEXT = 'Quarantine stack banner';
const CLEAN_HOST = `r${run}.clean-site.test`;
const CLEAN_URL = `http://${CLEAN_HOST}/landing`;
const EICAR_FILE = 'q5-invoice.txt';
let card = '';

type Msg = { id: bigint; receivedAt: Date; direction: string; publicId: string };
const shared: {
  gtube?: Msg;
  gtubeEntries?: EntryRow[];
  held?: Msg;
  heldEntries?: EntryRow[];
  eicar?: Msg;
  eicarEntries?: EntryRow[];
  rejected?: EntryRow;
} = {};

/** Names that must never appear in a content-free column. */
const forbidden = () =>
  [
    inQ?.name,
    outQ?.name,
    inD?.name,
    inW?.name,
    extDomain(),
    'clean.scan.test',
    'alice',
    'Warehouse inventory',
    'reconciliation sheet',
    SUBJECT_TOKEN,
    BODY_MARKER,
    EICAR_FILE,
    CLEAN_HOST,
    card,
    ...Object.values(LP),
  ].filter((n): n is string => Boolean(n));

function expectContentFree(entries: readonly EntryRow[]): void {
  for (const e of entries) expect(entryContentProblems(e, forbidden())).toEqual([]);
}

/** An evaluation row of `round`, content-checked (5.2 helper + the step's names). */
async function evaluated(message: Msg, round = 0): Promise<EvaluationRow> {
  const row = await waitForEvaluation(fx.prisma, message, round, 180_000);
  expect(row.evaluatorVersion).toBe('policy-eval/2');
  expect(evaluationContentProblems(row, forbidden())).toEqual([]);
  return row;
}

beforeAll(async () => {
  assertStackReady(gate);
  card = synthetic.card('4532');
  // Q: inbound (tenant rules) and outbound (GTUBE).
  orgQ = await fx.organization('q5');
  inQ = await fx.domain(orgQ, 'q5-in');
  outQ = await sendingDomain(fx, orgQ, 'q5-out');
  await fx.destinations(inQ, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(outQ, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  saslQ = await fx.saslConnector(orgQ, 'q5');
  // D: the digest (case 8).
  orgD = await fx.organization('q5-dig');
  inD = await fx.domain(orgD, 'q5-din');
  await fx.destinations(inD, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  // W: WARN banners and URL_REWRITE after the scan (case 11).
  orgW = await fx.organization('q5-warn');
  inW = await fx.domain(orgW, 'q5-win');
  await fx.destinations(inW, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  // L: the bulk per-minute limit (case 12).
  orgL = await fx.organization('q5-bulk');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);

  const refQ = await organizationRef(fx, orgQ);
  analystQ = await apiSession(fx.prisma, refQ, 'security_analyst');
  adminQ = await apiSession(fx.prisma, refQ, 'organization_admin', { mfa: true });
  admin2Q = await apiSession(fx.prisma, refQ, 'organization_admin', { mfa: true });
  m1 = await apiSession(fx.prisma, refQ, 'mailbox_user', { email: `${LP.m1}@${inQ.name}` });
  m2 = await apiSession(fx.prisma, refQ, 'mailbox_user', { email: `${LP.g2}@${extDomain()}` });
  const refD = await organizationRef(fx, orgD);
  analystD = await apiSession(fx.prisma, refD, 'security_analyst');
  adminD = await apiSession(fx.prisma, refD, 'organization_admin');
  mD = await apiSession(fx.prisma, refD, 'mailbox_user', { email: `${LP.dg}@${inD.name}` });
  const refW = await organizationRef(fx, orgW);
  analystW = await apiSession(fx.prisma, refW, 'security_analyst');
  adminW = await apiSession(fx.prisma, refW, 'organization_admin');
  analystL = await apiSession(fx.prisma, await organizationRef(fx, orgL), 'security_analyst');

  // Q: a TAG rule and a QUARANTINE rule on the same recipients (the TAG rule first: a rule with
  // a disposition stops evaluation, policy-dsl §7; the release copy carries the TAG, Q13.6), and
  // a recipient-address rule (per-recipient split, Q4).
  const held = HELD.map((l) => l);
  const policy = await createAndPublishPolicy(analystQ, adminQ, 'Q5 rules', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'tag-listed',
        priority: 5,
        when: { field: 'recipient.local_part', op: 'in', value: held },
        actions: [{ type: 'TAG', label: TAG_LABEL }],
      },
      {
        id: 'hold-listed',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'in', value: held },
        actions: [{ type: 'QUARANTINE' }],
      },
      {
        id: 'hold-one-address',
        priority: 30,
        when: { field: 'recipient.address', op: 'in', value: [`${LP.sa}@${inQ.name}`] },
        actions: [{ type: 'QUARANTINE' }],
      },
    ],
  });
  holdPolicyId = policy.policyId;
  // D: one QUARANTINE rule; digests off until case 8 switches them on (no earlier run).
  await createAndPublishPolicy(analystD, adminD, 'Q5 digest', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'hold-digest',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.dg },
        actions: [{ type: 'QUARANTINE' }],
      },
    ],
  });
  await orgSettings(adminD, orgD, { digestEnabled: false });
  // W: WARN and URL_REWRITE, scan-time rewriting off for the tenant (skip reason `disabled`).
  const url = await adminW.put('/scan-settings/url', {
    expectedVersion: 0,
    settings: { rewrite: { enabled: false } },
  });
  expect(url.status, JSON.stringify(url.body)).toBe(200);
  await createAndPublishPolicy(analystW, adminW, 'Q5 delivery edits', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'warn-recipient',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.wn },
        actions: [{ type: 'WARN', level: 'warning', text: BANNER_TEXT }],
      },
      {
        id: 'rewrite-recipient',
        priority: 20,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.ur },
        actions: [{ type: 'URL_REWRITE', ifNotRewritten: 'quarantine' }],
      },
    ],
  });

  await pointNotificationWorkerAtSink();
  notificationWorkerRedirected = true;
}, 900_000);

afterAll(async () => {
  if (gate.skip) return;
  if (notificationWorkerRedirected) await restoreNotificationWorker();
  if (legalHoldId !== undefined) {
    await fx.prisma.archiveLegalHold.deleteMany({ where: { id: legalHoldId } });
  }
  for (const session of [
    analystQ,
    adminQ,
    admin2Q,
    m1,
    m2,
    analystD,
    adminD,
    mD,
    analystW,
    adminW,
    analystL,
  ]) {
    await session?.remove();
  }
  const names = [inQ, outQ, inD, inW].filter(Boolean).map((d) => d.name);
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
  const removed = [orgQ, orgD, orgW, orgL].filter((id) => id !== 0n);
  await fx.cleanup();
  await purgeDormantQueues();
  if (removed.length === 0) return;
  const { PrismaClient } = await import('@email-gateway/database');
  const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  try {
    const where = { organizationId: { in: removed } };
    expect({
      entries: await prisma.quarantineMessage.count({ where }),
      actions: await prisma.quarantineAction.count({ where }),
      releaseLogs: await prisma.quarantineReleaseLog.count({ where }),
      approvals: await prisma.quarantineApprovalRequest.count({ where }),
      grants: await prisma.quarantineDownloadGrant.count({ where }),
      purges: await prisma.quarantineObjectPurge.count({ where }),
      digests: await prisma.quarantineDigest.count({ where }),
      digestRuns: await prisma.quarantineDigestRun.count({ where }),
      settings: await prisma.quarantineSettings.count({ where }),
      legalHolds: await prisma.archiveLegalHold.count({ where }),
      evaluations: await prisma.policyExecutionLog.count({ where }),
      messages: await prisma.emailMessage.count({ where }),
      organizations: await prisma.organization.count({ where: { id: { in: removed } } }),
    }).toEqual({
      entries: 0,
      actions: 0,
      releaseLogs: 0,
      approvals: 0,
      grants: 0,
      purges: 0,
      digests: 0,
      digestRuns: 0,
      settings: 0,
      legalHolds: 0,
      evaluations: 0,
      messages: 0,
      organizations: 0,
    });
  } finally {
    await prisma.$disconnect();
  }
}, 900_000);

// --- Helpers -------------------------------------------------------------------------------------

async function orgSettings(admin: ApiSession, org: bigint, body: Record<string, unknown>) {
  const { publicId } = await fx.prisma.organization.findUniqueOrThrow({
    where: { id: org },
    select: { publicId: true },
  });
  const res = await admin.put(`/organizations/${publicId}/settings`, body);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
}

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
): Promise<Msg> {
  const sent = await sendToMx({ from, to: rcpts, helo: 'mx.clean.scan.test', data: eml });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  return keyOf(organizationId, sent.queueId!);
}

const cleanEml = () => corpusEml('clean/clean-dkim-aligned.eml');
const qa = (local: string) => `${local}@${inQ.name}`;

const GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';

async function gtubeOutbound(rcpts: readonly string[]): Promise<Msg> {
  const from = `alice@${outQ.name}`;
  const { text } = attachmentMessage({
    from: `Alice <${from}>`,
    to: [...rcpts],
    subject: `${SUBJECT_TOKEN} GTUBE`,
    body: GTUBE,
    attachments: [],
  });
  const sent = await swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: saslQ,
    from,
    to: [...rcpts],
    data: text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  return keyOf(orgQ, sent.queueId!);
}

/** An inbound clean (DKIM-aligned) message to Q's held recipients → entries of round 0. */
async function heldInbound(
  locals: readonly string[],
): Promise<{ message: Msg; entries: EntryRow[] }> {
  const message = await inbound(orgQ, locals.map(qa), cleanEml());
  const row = await evaluated(message);
  expect(row).toMatchObject({
    disposition: 'quarantine',
    decisionSource: 'tenant_rule',
    decisiveRuleId: 'hold-listed',
    decisivePolicyPublicId: holdPolicyId,
  });
  const entries = await waitForEntries(fx.prisma, message, locals.length);
  expectContentFree(entries);
  return { message, entries };
}

/** The executor's outcome of a queued release (writer). */
async function executed(releaseId: string) {
  const logs = await waitForReleaseOutcome(fx.prisma, releaseId);
  for (const l of logs) {
    expect(JSON.stringify({ p: l.precheck, r: l.revalidation }), 'release log content').not.toMatch(
      /@|:\/\//,
    );
  }
  return logs;
}

/** No message of `rcpt` in any sink after a 5 s window, and no approval of the message. */
async function expectNothingDelivered(message: Msg, rcpts: readonly string[]) {
  await sleep(5_000);
  expect(await approvalsOf(fx.prisma, message)).toHaveLength(0);
  for (const rcpt of rcpts) expect(await sinkFiles(rcpt), rcpt).toEqual([]);
}

async function objectExists(key: string): Promise<boolean> {
  try {
    await fx.s3.send(new HeadObjectCommand({ Bucket: fx.bucket, Key: key }));
    return true;
  } catch (error) {
    const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
    if (status === 404) return false;
    throw error;
  }
}

async function objectBytes(key: string): Promise<Buffer> {
  const res = await fx.s3.send(new GetObjectCommand({ Bucket: fx.bucket, Key: key }));
  return Buffer.from(await res.Body!.transformToByteArray());
}

const code = (res: ApiResponse) => (res.body as { code?: string }).code;

/** The quarantine settings document of Q merged with `patch` (PUT with its row version). */
async function patchQuarantineSettings(admin: ApiSession, patch: Record<string, unknown>) {
  const current = await admin.get('/quarantine/settings');
  expect(current.status, JSON.stringify(current.body)).toBe(200);
  const body = current.body as { raw: Record<string, unknown> | null; rowVersion: number };
  const raw = body.raw ?? {};
  const merged: Record<string, unknown> = { ...raw };
  for (const [key, value] of Object.entries(patch)) {
    merged[key] = {
      ...(raw[key] ?? {}),
      ...(value as object),
    };
  }
  const put = await admin.put('/quarantine/settings', {
    settings: merged,
    expectedRowVersion: body.rowVersion,
  });
  expect(put.status, JSON.stringify(put.body)).toBe(200);
}

/** A held entry released by the operator path: pre-check `release` → queued (Q13.1). */
async function releaseQueued(session: ApiSession, entry: EntryRow, label: string) {
  const res = await postIdem(
    session,
    `/quarantine/entries/${entry.publicId}/release`,
    { reason: `stack test release ${label}` },
    label,
  );
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  expect(res.body).toMatchObject({ outcome: 'queued', releaseId: expect.any(String) });
  return (res.body as { releaseId: string }).releaseId;
}

// --- Cases ---------------------------------------------------------------------------------------

describe.skipIf(gate.skip)(
  'quarantine stack: store, release, controls',
  { timeout: 900_000 },
  () => {
    it('(1) GTUBE outbound and a tenant QUARANTINE rule inbound: one held entry per recipient, nothing delivered', async () => {
      const createdBefore = await quarantineMetric('quarantine_entries_created_total', {
        origin: 'policy',
        kind: 'quarantine',
      });
      // GTUBE through the submission port (platform default from the recommendation).
      const ext = [`${LP.g1}@${extDomain()}`, `${LP.g2}@${extDomain()}`];
      const gtube = await gtubeOutbound(ext);
      const gRow = await evaluated(gtube);
      expect(gRow).toMatchObject({ disposition: 'quarantine', decisionSource: 'platform_default' });
      const gEntries = await waitForEntries(fx.prisma, gtube, 2);
      expect(gEntries.map((e) => [e.rcptSeq, e.recipientAddress, e.status])).toEqual([
        [0, ext[0], 'held'],
        [1, ext[1], 'held'],
      ]);
      for (const e of gEntries) {
        expect(e).toMatchObject({
          kind: 'quarantine',
          origin: 'policy',
          direction: 'outbound',
          lifecycleRound: 0,
          evaluationSeq: 0,
          decisionSource: 'platform_default',
          decisiveRuleId: null,
          envelopeFrom: `alice@${outQ.name}`,
          rowVersion: 1,
        });
        expect(['spam', 'bulk', 'suspicious']).toContain(e.reason);
        expect(e.riskLevel).not.toBeNull();
        expect(e.expiresAt.getTime()).toBeGreaterThan(Date.now() + 24 * 3_600_000);
      }
      expectContentFree(gEntries);
      await waitForLifecycle(fx.prisma, gtube, 'quarantined', 'policy_quarantine');
      const gRcpts = await fx.prisma.emailRecipient.findMany({
        where: { messageId: gtube.id, receivedAt: gtube.receivedAt },
        orderBy: { rcptSeq: 'asc' },
      });
      expect(gRcpts.map((r) => [r.status, r.finalAction])).toEqual([
        ['quarantined', 'quarantine'],
        ['quarantined', 'quarantine'],
      ]);
      await expectNothingDelivered(gtube, ext);

      // A tenant rule inbound (two listed recipients): reason `policy`, the rule decisive.
      const { message: held, entries } = await heldInbound([LP.qa, LP.qb]);
      for (const e of entries) {
        expect(e).toMatchObject({
          status: 'held',
          kind: 'quarantine',
          origin: 'policy',
          reason: 'policy',
          primaryEngine: 'policy',
          direction: 'inbound',
          decisionSource: 'tenant_rule',
          decisiveRuleId: 'hold-listed',
          decisivePolicyPublicId: holdPolicyId,
          decisivePolicyVersionNo: 1,
          subject: null,
        });
        expect(e.emlObjectKey).toMatch(new RegExp(`^org/${orgQ.toString()}/`));
        const [created] = await actionsOfEntry(fx.prisma, e.id);
        expect(created).toMatchObject({ action: 'quarantine', actorType: 'system' });
      }
      await waitForLifecycle(fx.prisma, held, 'quarantined', 'policy_quarantine');
      await expectNothingDelivered(held, [qa(LP.qa), qa(LP.qb)]);
      expect(
        await fx.prisma.emailEvent.count({
          where: { messageId: held.id, eventType: 'quarantine.created' },
        }),
      ).toBeGreaterThanOrEqual(1);
      expect(
        await quarantineMetric('quarantine_entries_created_total', {
          origin: 'policy',
          kind: 'quarantine',
        }),
      ).toBeGreaterThanOrEqual(createdBefore + 4);

      // Tenant-scoped search (replica): Q finds the message's entries, D finds nothing.
      const search = await waitFor(
        'the entries in the search api (replica)',
        async () => {
          const res = await analystQ!.get(
            `/quarantine/entries?${windowQuery()}&messageId=${held.publicId}`,
          );
          return res.status === 200 && (res.body as { items: unknown[] }).items.length === 2
            ? res
            : undefined;
        },
        { timeoutMs: 30_000, intervalMs: 500 },
      );
      const items = (search.body as { items: { id: string; state: string; recipient: string }[] })
        .items;
      expect(items.map((i) => i.id).sort()).toEqual(entries.map((e) => e.publicId).sort());
      const foreign = await analystD!.get(
        `/quarantine/entries?${windowQuery()}&messageId=${held.publicId}`,
      );
      expect(foreign.status).toBe(200);
      expect((foreign.body as { items: unknown[] }).items).toEqual([]);
      expect((await analystD!.get(`/quarantine/entries/${entries[0]!.publicId}`)).status).toBe(404);

      shared.gtube = gtube;
      shared.gtubeEntries = gEntries;
      shared.held = held;
      shared.heldEntries = entries;
      record('quarantine-smtp', {
        gtube: `${gRow.disposition}:${gEntries[0]!.reason}:${gEntries[0]!.riskLevel}`,
        tenant_rule: `${entries[0]!.reason}:${entries[0]!.riskLevel}`,
      });
    });

    it('(2) per-recipient rule: one recipient held, the other delivered (delivery_partial); a later release of the held one is delivered once (E28)', async () => {
      const a = qa(LP.sa);
      const b = qa(LP.sb);
      const message = await inbound(orgQ, [a, b], cleanEml());
      const row = await evaluated(message);
      expect(row).toMatchObject({ recipientSplit: true, action: 'partial' });
      const decisions = row.recipientDecisions as { rcptSeq: number; disposition: string }[];
      expect(decisions.map((d) => [d.rcptSeq, d.disposition])).toEqual([
        [0, 'quarantine'],
        [1, 'allow'],
      ]);
      const [entry, ...more] = await waitForEntries(fx.prisma, message, 1);
      expect(more).toEqual([]);
      expect(entry).toMatchObject({ recipientAddress: a, rcptSeq: 0, status: 'held' });
      expectContentFree([entry!]);
      // b delivered alone: E10 policy_partial, the message ends delivered/delivery_partial.
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_partial', 240_000);
      expect((await pathOf(fx.prisma, message)).find(([, to]) => to === 'approved')).toEqual([
        'policy_evaluated',
        'approved',
        'policy_partial',
      ]);
      expect(await sinkFiles(b)).toHaveLength(1);
      expect(await sinkFiles(a)).toEqual([]);
      const final = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.id, receivedAt: message.receivedAt },
        select: { finalAction: true },
      });
      expect(final.finalAction).toBe('partial');

      // The held recipient released later: E28 delivered → approved (new round), a only.
      const releaseId = await releaseQueued(analystQ!, entry!, 'split');
      const [log] = await executed(releaseId);
      expect(log).toMatchObject({ status: 'dispatched', lifecycleRoundAfter: 1, deliverySeq: 1 });
      await waitFor(
        'the released recipient delivered',
        async () => (await sinkFiles(a)).length === 1,
        {
          timeoutMs: 240_000,
          intervalMs: 1_000,
        },
      );
      await waitForLifecycle(fx.prisma, message, 'delivered', undefined, 240_000);
      const path = await pathOf(fx.prisma, message);
      expect(path).toEqual(
        expect.arrayContaining([['delivered', 'approved', 'quarantine_partial_release']]),
      );
      await sleep(3_000);
      expect(await sinkFiles(a)).toHaveLength(1);
      expect(await sinkFiles(b)).toHaveLength(1);
      const approvals = await approvalsOf(fx.prisma, message);
      expect(
        approvals.map((x) => [
          (x.payload as { source: string }).source,
          (x.payload as { lifecycleRound: number }).lifecycleRound,
        ]),
      ).toEqual([
        ['policy', 0],
        ['quarantine_release', 1],
      ]);
      expect((await entryByPublicId(fx.prisma, entry!.publicId)).status).toBe('released');
      await expectConsistentHistory(fx.prisma, message);
      record('quarantine-smtp', { split: path.map(([, to, r]) => `${to}/${r}`).join(' > ') });
    });

    it('(3) operator release re-validates: dispatched, the delivered copy carries X-EG-Quarantine-Release and the policy TAG, the log holds the re-validation summary', async () => {
      expect(shared.heldEntries, 'case 1 left held entries').toBeDefined();
      const message = shared.held!;
      const entry = shared.heldEntries!.find((e) => e.recipientAddress === qa(LP.qa))!;
      const releaseId = await releaseQueued(analystQ!, entry, 'revalidate');
      const outbox = await fx.prisma.messageOutbox.findMany({
        where: { organizationId: orgQ, eventType: EventTypes.QuarantineReleaseRequested },
      });
      const event = outbox
        .map((r) => quarantineReleaseRequestedV1.parse(r.payload))
        .find((p) => p.releaseId === releaseId);
      expect(event).toMatchObject({ mode: 'operator', entryIds: [entry.publicId] });
      const [log] = await executed(releaseId);
      expect(log).toMatchObject({
        status: 'dispatched',
        mode: 'operator',
        deliveredObject: 'policy_copy',
        lifecycleRoundAfter: 1,
      });
      expect(log!.objectKey).toMatch(
        new RegExp(
          `^org/${orgQ.toString()}/policy/\\d{4}/\\d{2}/\\d{2}/${message.id.toString()}/r1-[0-9a-f]{32}\\.eml$`,
        ),
      );
      expect(log!.revalidation).toMatchObject({
        outcome: 'release',
        summary: { disposition: 'quarantine', source: 'tenant_rule' },
      });
      expect(log!.precheck).toMatchObject({ outcome: 'release' });
      const rcpt = qa(LP.qa);
      const path = await waitFor(
        'the released copy in mail-sink',
        async () => (await sinkFiles(rcpt))[0],
        {
          timeoutMs: 240_000,
          intervalMs: 1_000,
        },
      );
      const delivered = (await sinkMessage(path)).toString('latin1');
      const headers = delivered.split(/\r?\n\r?\n/)[0]!;
      expect(headers).toMatch(new RegExp(`^X-EG-Quarantine-Release: ${releaseId}\\r?$`, 'm'));
      expect(headers).toMatch(new RegExp(`^X-EG-Policy-Tag: ${TAG_LABEL}\\r?$`, 'm'));
      expect(await sinkFiles(qa(LP.qb))).toEqual([]);
      expect((await pathOf(fx.prisma, message)).find(([from]) => from === 'quarantined')).toEqual([
        'quarantined',
        'approved',
        'quarantine_release',
      ]);
      const approvals = await approvalsOf(fx.prisma, message);
      expect(approvals).toHaveLength(1);
      expect(approvals[0]!.payload).toMatchObject({
        source: 'quarantine_release',
        lifecycleRound: 1,
        emlS3Key: log!.objectKey,
      });
      const released = await entryByPublicId(fx.prisma, entry.publicId);
      expect(released).toMatchObject({ status: 'released', decidedByType: 'user' });
      expectContentFree([released]);
      // The release view (replica).
      const view = await waitFor(
        'the release view',
        async () => {
          const res = await analystQ!.get(`/quarantine/releases/${releaseId}`);
          return res.status === 200 && (res.body as { status: string }).status === 'dispatched'
            ? res
            : undefined;
        },
        { timeoutMs: 30_000, intervalMs: 500 },
      );
      expect(view.body).toMatchObject({ mode: 'operator', deliveredObject: 'policy_copy' });
      record('quarantine-smtp', {
        release_copy: log!.deliveredObject,
        round_after: log!.lifecycleRoundAfter,
      });
    });

    it('(4) EICAR: manual quarantine of the policy rejection, release needs approval (hard_block), the requester is refused, a second admin approves and the release is dispatched', async () => {
      const built = attachmentMessage({
        from: 'alice@clean.scan.test',
        to: [qa(LP.ev), qa(LP.m1)],
        subject: `${SUBJECT_TOKEN} EICAR`,
        attachments: [{ filename: EICAR_FILE, contentType: 'text/plain', bytes: eicar() }],
      });
      const message = await inbound(orgQ, [qa(LP.ev), qa(LP.m1)], built.text);
      const row = await evaluated(message);
      expect(row).toMatchObject({ disposition: 'reject', action: 'discard' });
      await waitForLifecycle(fx.prisma, message, 'rejected', 'policy_discard');
      // 5.3: rejected recipients are `discarded`, no entry.
      expect(
        (
          await fx.prisma.emailRecipient.findMany({
            where: { messageId: message.id, receivedAt: message.receivedAt },
          })
        ).map((r) => r.status),
      ).toEqual(['discarded', 'discarded']);
      expect(await entriesOf(fx.prisma, message)).toEqual([]);

      // Manual quarantine (Q7, E29), every eligible recipient.
      const manual = await postIdem(
        analystQ!,
        '/quarantine/entries',
        { messageId: message.publicId, reason: 'stack test: keep for review' },
        'manual',
      );
      expect(manual.status, JSON.stringify(manual.body)).toBe(201);
      expect(manual.body).toMatchObject({ messageTransition: 'E29' });
      await waitForLifecycle(fx.prisma, message, 'quarantined', 'manual_quarantine');
      const entries = await waitForEntries(fx.prisma, message, 2);
      for (const e of entries) {
        expect({
          origin: e.origin,
          reason: e.reason,
          status: e.status,
          kind: e.kind,
          hasHardBlock: e.hasHardBlock,
          hardBlocks: e.hardBlocks,
        }).toMatchObject({
          origin: 'manual',
          reason: 'manual',
          status: 'held',
          kind: 'quarantine',
          hasHardBlock: true,
        });
      }
      expectContentFree(entries);
      const ev = entries.find((e) => e.recipientAddress === qa(LP.ev))!;

      // Release by the first admin → approval requested with hard_block.
      const requested = await postIdem(
        adminQ!,
        `/quarantine/entries/${ev.publicId}/release`,
        { reason: 'stack test: requested' },
        'eicar-release',
      );
      expect(requested.status, JSON.stringify(requested.body)).toBe(202);
      expect(requested.body).toMatchObject({
        outcome: 'approval_requested',
        state: 'pending_approval',
      });
      const reasons = (requested.body as { approvalReasons: string[] }).approvalReasons;
      expect(reasons).toContain('hard_block');
      const approvalId = (requested.body as { approvalRequestId: string }).approvalRequestId;
      const approval = await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({
        where: { publicId: approvalId },
      });
      expect(approval).toMatchObject({
        kind: 'release_approval',
        status: 'pending',
        requestedByUserId: adminQ!.userId,
      });
      // The requester cannot approve (separation of duties).
      const self = await postIdem(
        adminQ!,
        `/quarantine/approvals/${approvalId}/approve`,
        { reason: 'stack test: self approve' },
        'self-approve',
      );
      expect(self.status, JSON.stringify(self.body)).toBe(403);
      expect(self.body).toMatchObject({ code: 'quarantine_approval_forbidden' });
      // A second administrator approves.
      const approved = await postIdem(
        admin2Q!,
        `/quarantine/approvals/${approvalId}/approve`,
        { reason: 'stack test: second person approves' },
        'approve',
      );
      expect(approved.status, JSON.stringify(approved.body)).toBe(202);
      expect(approved.body).toMatchObject({ status: 'approved', entryState: 'releasing' });
      const releaseId = (approved.body as { releaseId: string }).releaseId;
      const [log] = await executed(releaseId);
      expect(log).toMatchObject({ status: 'dispatched', mode: 'approved' });
      expect(
        await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({
          where: { publicId: approvalId },
        }),
      ).toMatchObject({
        status: 'approved',
        decidedByUserId: admin2Q!.userId,
      });
      expect(await pathOf(fx.prisma, message)).toEqual(
        expect.arrayContaining([
          ['rejected', 'quarantined', 'manual_quarantine'],
          ['quarantined', 'approved', 'quarantine_release'],
        ]),
      );
      // Planned and settled (the outbound MTA may still refuse the reinjected EICAR itself).
      const settled = await waitFor(
        'the released EICAR message planned and settled',
        async () => {
          const s = await lifecycleOf(fx.prisma, message);
          return s.lifecycleRound === 1 && ['delivered', 'rejected'].includes(s.status)
            ? s
            : undefined;
        },
        { timeoutMs: 240_000, intervalMs: 1_000 },
      );
      const evSink = await sinkFiles(qa(LP.ev));
      expect(await sinkFiles(qa(LP.m1))).toEqual([]);
      shared.eicar = message;
      shared.eicarEntries = entries;
      record('quarantine-smtp', {
        eicar_approval_reasons: reasons.join(','),
        eicar_release: `${log!.status}:${settled.status}/${settled.statusReason}:sink=${evSink.length}`,
      });
    });

    it('(5) reject: an outbound entry → rejected with a sender notice in mail-sink; an inbound entry → rejected, no notice', async () => {
      expect(shared.gtubeEntries && shared.heldEntries, 'case 1 ran').toBeTruthy();
      const sentBefore = await quarantineNoticesSent('sender_rejected');
      const g1 = shared.gtubeEntries!.find((e) => e.recipientAddress.startsWith(`${LP.g1}@`))!;
      const res = await postIdem(
        analystQ!,
        `/quarantine/entries/${g1.publicId}/reject`,
        { reason: 'stack test: confirmed spam' },
        'reject-out',
      );
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({ state: 'rejected', messageTransition: null });
      const rejected = await entryByPublicId(fx.prisma, g1.publicId);
      expect(rejected.status).toBe('rejected');
      expectContentFree([rejected]);
      const recipient = await fx.prisma.emailRecipient.findFirstOrThrow({
        where: { id: g1.recipientId },
      });
      expect(recipient.status).toBe('discarded');
      const notices = (
        await fx.prisma.messageOutbox.findMany({
          where: { organizationId: orgQ, eventType: EventTypes.QuarantineNotificationRequested },
        })
      )
        .map((r) => ({
          eventId: r.eventId,
          payload: quarantineNotificationRequestedV1.parse(r.payload),
        }))
        .filter((n) => n.payload.kind === 'sender_rejected');
      expect(notices.map((n) => n.payload.refs.entryId)).toEqual([g1.publicId]);
      const sender = `alice@${outQ.name}`;
      const path = await waitFor(
        'the sender notice in mail-sink',
        async () => (await sinkFiles(sender))[0],
        {
          timeoutMs: 180_000,
          intervalMs: 1_000,
        },
      );
      const notice = (await sinkMessage(path)).toString('utf8');
      expect(notice).toMatch(
        new RegExp(`^Message-ID:\\s+<quarantine-notice\\.${notices[0]!.eventId}@`, 'im'),
      );
      expect(notice).not.toContain(GTUBE);
      expect(notice).not.toContain(g1.recipientAddress);
      expect(await quarantineNoticesSent('sender_rejected')).toBeGreaterThanOrEqual(sentBefore + 1);

      // Inbound: never a sender notice (no backscatter).
      const qb = shared.heldEntries!.find((e) => e.recipientAddress === qa(LP.qb))!;
      const inboundRes = await postIdem(
        analystQ!,
        `/quarantine/entries/${qb.publicId}/reject`,
        { reason: 'stack test: inbound reject' },
        'reject-in',
      );
      expect(inboundRes.status, JSON.stringify(inboundRes.body)).toBe(200);
      expect(inboundRes.body).toMatchObject({ state: 'rejected' });
      await sleep(3_000);
      const after = (
        await fx.prisma.messageOutbox.findMany({
          where: { organizationId: orgQ, eventType: EventTypes.QuarantineNotificationRequested },
        })
      )
        .map((r) => quarantineNotificationRequestedV1.parse(r.payload))
        .filter((n) => n.kind === 'sender_rejected');
      expect(after).toHaveLength(1);
      expect(await sinkFiles('alice@clean.scan.test')).toEqual([]);
      expect(
        await fx.prisma.auditLog.count({
          where: { organizationId: orgQ, action: 'quarantine.rejected' },
        }),
      ).toBe(2);
      shared.rejected = rejected;
    });

    it('(6) delete: refused under an active legal hold (object kept), then deleted and the EML purged by the sweeper', async () => {
      const { message, entries } = await heldInbound([LP.dl]);
      const entry = entries[0]!;
      expect(await objectExists(entry.emlObjectKey)).toBe(true);
      // Fixture: an active legal hold (8.1 owns the management api); criteria {} match everything.
      const hold = await fx.prisma.archiveLegalHold.create({
        data: {
          organizationId: orgQ,
          name: 'Q5 stack hold',
          reason: 'stack test',
          criteria: {},
          status: 'active',
        },
      });
      legalHoldId = hold.id;
      const refused = await postIdem(
        analystQ!,
        `/quarantine/entries/${entry.publicId}/delete`,
        { reason: 'stack test: delete under hold' },
        'delete-hold',
      );
      expect(refused.status, JSON.stringify(refused.body)).toBe(409);
      expect(refused.body).toMatchObject({ code: 'quarantine_legal_hold' });
      expect((await entryByPublicId(fx.prisma, entry.publicId)).status).toBe('held');
      expect(await objectExists(entry.emlObjectKey)).toBe(true);
      expect(
        await fx.prisma.auditLog.count({
          where: { organizationId: orgQ, action: 'quarantine.delete_refused' },
        }),
      ).toBe(1);
      await fx.prisma.archiveLegalHold.update({
        where: { id: hold.id },
        data: { status: 'released', releasedAt: new Date() },
      });

      const deleted = await postIdem(
        analystQ!,
        `/quarantine/entries/${entry.publicId}/delete`,
        { reason: 'stack test: delete' },
        'delete',
      );
      expect(deleted.status, JSON.stringify(deleted.body)).toBe(200);
      expect(deleted.body).toMatchObject({ state: 'deleted', purge: 'pending' });
      await waitForLifecycle(fx.prisma, message, 'rejected', 'quarantine_deleted');
      const purge = await waitFor(
        'the sweeper purge of the EML',
        async () => {
          const row = await fx.prisma.quarantineObjectPurge.findUnique({
            where: {
              messageId_messageReceivedAt: {
                messageId: message.id,
                messageReceivedAt: message.receivedAt,
              },
            },
          });
          return row?.status === 'purged' ? row : undefined;
        },
        { timeoutMs: 240_000, intervalMs: 2_000 },
      );
      expect(purge.purgedAt).not.toBeNull();
      expect(await objectExists(entry.emlObjectKey)).toBe(false);
      const after = await entryByPublicId(fx.prisma, entry.publicId);
      expect(after.status).toBe('deleted');
      expect(after.objectPurgedAt).not.toBeNull();
      expectContentFree([after]);
      expect((await actionsOfEntry(fx.prisma, entry.id)).map((a) => a.action)).toEqual(
        expect.arrayContaining(['quarantine', 'delete', 'object_purged']),
      );
      // The preview of a purged entry: content gone.
      const preview = await analystQ!.get(`/quarantine/entries/${entry.publicId}/preview`);
      expect([410, 200]).toContain(preview.status);
      if (preview.status === 410) expect(code(preview)).toBe('quarantine_content_purged');
      await expectNothingDelivered(message, [qa(LP.dl)]);
    });

    it('(7) expiry: an entry past expires_at expires, is never released, and the message expires (E26 quarantine_expired)', async () => {
      const expiredBefore = await quarantineMetric('quarantine_expired_total', {
        kind: 'quarantine',
      });
      const { message, entries } = await heldInbound([LP.ex]);
      // Fixture: the hold period is at least one day; the entry's deadline moves into the past.
      await fx.prisma.quarantineMessage.update({
        where: { id: entries[0]!.id },
        data: { expiresAt: new Date(Date.now() - 1_000) },
      });
      const expired = await waitForEntryState(fx.prisma, entries[0]!.publicId, 'expired', 240_000);
      expect(expired.releasedAt).toBeNull();
      expectContentFree([expired]);
      await waitForLifecycle(fx.prisma, message, 'expired', 'quarantine_expired');
      const history = await fx.prisma.emailMessageStatusHistory.findMany({
        where: { messageId: message.id, receivedAt: message.receivedAt },
        orderBy: { version: 'asc' },
      });
      expect(history.at(-1)).toMatchObject({
        fromStatus: 'quarantined',
        toStatus: 'expired',
        reasonCode: 'quarantine_expired',
        actorRole: 'quarantine',
      });
      const recipient = await fx.prisma.emailRecipient.findFirstOrThrow({
        where: { id: entries[0]!.recipientId },
      });
      expect(recipient.status).toBe('discarded');
      await expectNothingDelivered(message, [qa(LP.ex)]);
      expect(
        await quarantineMetric('quarantine_expired_total', { kind: 'quarantine' }),
      ).toBeGreaterThanOrEqual(expiredBefore + 1);
    });

    it('(8) digest: a mailbox_user with a held entry receives a digest in mail-sink (sender, subject, portal link; no body)', async () => {
      const rcpt = `${LP.dg}@${inD.name}`;
      const eml = [
        'From: Alice Martin <alice@clean.scan.test>',
        `To: ${rcpt}`,
        `Subject: ${SUBJECT_TOKEN} digest`,
        `Message-ID: <${randomUUID()}@clean.scan.test>`,
        `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: 7bit',
        '',
        `Hello, ${BODY_MARKER} for the digest.`,
        '',
      ].join('\r\n');
      const message = await inbound(orgD, [rcpt], eml);
      const row = await evaluated(message);
      expect(row.disposition === 'quarantine' || row.disposition === 'reject').toBe(true);
      const [entry] = await waitForEntries(fx.prisma, message, 1);
      expectContentFree([entry!]);
      // The digest instant must come after the entry: next minute, then every-minute schedule.
      await untilNextMinute();
      const sentBefore = await quarantineNoticesSent('user_digest');
      await orgSettings(adminD!, orgD, {
        digestEnabled: true,
        digestSchedule: '* * * * *',
        timezone: 'UTC',
      });
      const path = await waitFor(
        'the digest in mail-sink',
        async () => (await sinkFiles(rcpt))[0],
        {
          timeoutMs: 300_000,
          intervalMs: 2_000,
        },
      );
      await orgSettings(adminD!, orgD, { digestEnabled: false });
      const digest = noticeText(await sinkMessage(path));
      expect(digest).toMatch(/^Message-ID:\s+<quarantine-notice\./im);
      expect(digest).toContain('alice@clean.scan.test');
      expect(digest).toContain(SUBJECT_TOKEN);
      expect(digest).toContain(`/quarantine/me/${entry!.publicId}`);
      expect(digest).not.toContain(BODY_MARKER);
      const digests = await fx.prisma.quarantineDigest.findMany({
        where: { organizationId: orgD },
      });
      expect(digests.map((d) => d.userId)).toEqual([mD!.userId]);
      expect(await quarantineNoticesSent('user_digest')).toBeGreaterThanOrEqual(sentBefore + 1);
      record('quarantine-smtp', { digest_entries: digests[0]!.entryCount });
    });

    it('(9) preview: sanitized JSON text without active content, the card number masked, audited', async () => {
      const rcpt = qa(LP.pv);
      const spaced = card.replace(/(\d{4})(?=\d)/g, '$1 ');
      const html = [
        '<!doctype html><html><head><style>body{background:url(http://tracker.clean-site.test/bg.png)}</style>',
        '<script>alert("q5")</script></head><body onload="steal()">',
        `<p>Invoice ${BODY_MARKER}. Card ${spaced} please.</p>`,
        '<img src="http://tracker.clean-site.test/pixel.png" width="1" height="1">',
        '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==">',
        `<p><a href="${CLEAN_URL}">Open the portal</a> <a href="javascript:alert(1)">x</a></p>`,
        '<iframe src="http://tracker.clean-site.test/frame"></iframe>',
        '</body></html>',
      ].join('\r\n');
      const eml = [
        'From: Alice Martin <alice@clean.scan.test>',
        `To: ${rcpt}`,
        `Subject: ${SUBJECT_TOKEN} preview`,
        `Message-ID: <${randomUUID()}@clean.scan.test>`,
        `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=utf-8',
        'Content-Transfer-Encoding: 7bit',
        '',
        html,
        '',
      ].join('\r\n');
      const message = await inbound(orgQ, [rcpt], eml);
      const row = await evaluated(message);
      expect(['quarantine', 'reject']).toContain(row.disposition);
      let entry: EntryRow;
      if (row.disposition === 'quarantine') {
        [entry] = (await waitForEntries(fx.prisma, message, 1)) as [EntryRow];
      } else {
        // A stricter platform outcome: the entry comes from a manual quarantine (Q7).
        const manual = await postIdem(
          analystQ!,
          '/quarantine/entries',
          { messageId: message.publicId, reason: 'stack test: preview' },
          'manual-preview',
        );
        expect(manual.status, JSON.stringify(manual.body)).toBe(201);
        [entry] = (await waitForEntries(fx.prisma, message, 1)) as [EntryRow];
      }
      expectContentFree([entry]);
      await waitForRoundComplete(fx.prisma, message, 0);
      const res = await waitFor(
        'the preview (replica)',
        async () => {
          const r = await analystQ!.get(`/quarantine/entries/${entry.publicId}/preview`);
          return r.status === 200 ? r : undefined;
        },
        { timeoutMs: 30_000, intervalMs: 1_000 },
      );
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(res.headers.get('content-type')).toMatch(/application\/json/);
      const preview = res.body as {
        version: string;
        subject: string | null;
        body: { source: string; text: string; truncated: boolean };
        links: { n: number; displayUrl: string; host: string }[];
        dlp: { masked: number; categories: string[] };
      };
      expect(preview.version).toBe('preview/1');
      expect(preview.body.source).toBe('html');
      expect(preview.body.text).toContain(BODY_MARKER);
      expect(preview.body.text).toContain('[image]');
      const json = JSON.stringify(preview);
      for (const active of [
        '<script',
        '<img',
        '<iframe',
        'onload',
        'src=',
        'data:image',
        'javascript:alert', // listed as `javascript:[removed]` (defangUrl): text, no payload
        'steal()',
        'alert(',
      ]) {
        expect(json, active).not.toContain(active);
      }
      expect(json).not.toContain('http://');
      expect(json).not.toContain(card);
      expect(json).not.toContain(spaced);
      expect(preview.dlp.masked).toBeGreaterThanOrEqual(1);
      expect(preview.dlp.categories).toContain('payment_card');
      expect(preview.links.length).toBeGreaterThanOrEqual(1);
      expect(preview.links[0]!.displayUrl).toMatch(/^hxxp:\/\//);
      expect(preview.links[0]!.displayUrl).toContain('[.]');
      const audits = await fx.prisma.auditLog.findMany({
        where: { organizationId: orgQ, action: 'quarantine.previewed', resourceId: entry.publicId },
      });
      expect(audits).toHaveLength(1);
      expect(JSON.stringify(audits[0]!.metadata)).not.toMatch(/@|:\/\//);
      expect((await actionsOfEntry(fx.prisma, entry.id)).map((a) => a.action)).toContain('preview');
      // Without quarantine:preview (a mailbox user of another address): 403/404, never content.
      expect((await m2!.get(`/quarantine/me/entries/${entry.publicId}/preview`)).status).toBe(404);
      record('quarantine-smtp', {
        preview_masked: preview.dlp.masked,
        preview_links: preview.links.length,
      });
    });

    it('(10) download door: no permission 403, disabled 403, wrong password 401, a grant serves once (410 after), EICAR attachment refused 409', async () => {
      expect(shared.eicarEntries, 'case 4 ran').toBeDefined();
      const { entries } = await heldInbound([LP.dw]);
      const entry = entries[0]!;
      const grantPath = `/quarantine/entries/${entry.publicId}/download-grants`;
      // The analyst holds no quarantine:download.
      const noPermission = await analystQ!.post(grantPath, { object: 'eml', password: 'x' });
      expect(noPermission.status).toBe(403);
      // Allowed role, but the tenant switch is off (default).
      const disabled = await adminQ!.post(grantPath, {
        object: 'eml',
        ...(await adminQ!.reauth()),
      });
      expect(disabled.status, JSON.stringify(disabled.body)).toBe(403);
      expect(code(disabled)).toBe('quarantine_download_disabled');
      await patchQuarantineSettings(adminQ!, { download: { enabled: true } });
      // Wrong password: 401, counted toward the login lockout.
      const wrong = await adminQ!.post(grantPath, {
        object: 'eml',
        password: `wrong-${randomUUID()}`,
        totpCode: (await adminQ!.reauth()).totpCode,
      });
      expect(wrong.status, JSON.stringify(wrong.body)).toBe(401);
      expect(code(wrong)).toBe('quarantine_reauth_failed');
      // A grant, one download, then the token is used.
      const grant = await adminQ!.post(grantPath, { object: 'eml', ...(await adminQ!.reauth()) });
      expect(grant.status, JSON.stringify(grant.body)).toBe(201);
      const token = (grant.body as { token: string }).token;
      expect(grant.body).toMatchObject({ filename: `message-${entry.publicId}.eml.bin` });
      const file = await adminQ!.getRaw(`/quarantine/downloads/${token}`);
      expect(file.status).toBe(200);
      expect(file.headers.get('content-type')).toBe('application/octet-stream');
      expect(file.headers.get('x-content-type-options')).toBe('nosniff');
      expect(file.headers.get('cache-control')).toBe('no-store');
      expect(file.headers.get('content-security-policy')).toBe("sandbox; default-src 'none'");
      expect(Buffer.compare(file.bytes, await objectBytes(entry.emlObjectKey))).toBe(0);
      const reused = await adminQ!.getRaw(`/quarantine/downloads/${token}`);
      expect(reused.status).toBe(410);
      // Another administrator of the same organization cannot use a grant (binding) — new grant.
      const second = await adminQ!.post(grantPath, { object: 'eml', ...(await adminQ!.reauth()) });
      expect(second.status).toBe(201);
      const foreign = await admin2Q!.getRaw(
        `/quarantine/downloads/${(second.body as { token: string }).token}`,
      );
      expect(foreign.status).toBe(404);
      // EICAR: the attachment and the EML are never served.
      const eicarEntry = shared.eicarEntries!.find((e) => e.recipientAddress === qa(LP.m1))!;
      const attachment = await fx.prisma.emailAttachment.findFirstOrThrow({
        where: { messageId: eicarEntry.messageId, filename: EICAR_FILE },
      });
      const blocked = await adminQ!.post(
        `/quarantine/entries/${eicarEntry.publicId}/download-grants`,
        {
          object: 'attachment',
          partIndex: attachment.partIndex,
          ...(await adminQ!.reauth()),
        },
      );
      expect(blocked.status, JSON.stringify(blocked.body)).toBe(409);
      expect(code(blocked)).toBe('quarantine_download_blocked');
      for (const action of [
        'quarantine.download_granted',
        'quarantine.downloaded',
        'quarantine.download_refused',
      ]) {
        expect(
          await fx.prisma.auditLog.count({ where: { organizationId: orgQ, action } }),
          action,
        ).toBeGreaterThanOrEqual(1);
      }
      record('quarantine-smtp', { download: 'once', eicar_download: code(blocked) });
    });

    it('(11) WARN banner (text + HTML) in the delivered copy, skipped_signed for a signed message; URL_REWRITE with tenant rewriting off → click-service links that resolve', async () => {
      // WARN, multipart/alternative.
      const wn = `${LP.wn}@${inW.name}`;
      const boundary = `alt-${randomUUID()}`;
      const alt = [
        'From: Alice Martin <alice@clean.scan.test>',
        `To: ${wn}`,
        `Subject: ${SUBJECT_TOKEN} banner`,
        `Message-ID: <${randomUUID()}@clean.scan.test>`,
        `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
        'MIME-Version: 1.0',
        `Content-Type: multipart/alternative; boundary="${boundary}"`,
        '',
        `--${boundary}`,
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: 7bit',
        '',
        `Plain ${BODY_MARKER}.`,
        `--${boundary}`,
        'Content-Type: text/html; charset=utf-8',
        'Content-Transfer-Encoding: 7bit',
        '',
        `<html><body><p>Html ${BODY_MARKER}.</p></body></html>`,
        `--${boundary}--`,
        '',
      ].join('\r\n');
      const warned = await inbound(orgW, [wn], alt);
      const wRow = await evaluated(warned);
      expect(wRow).toMatchObject({ disposition: 'allow', deliveredObject: 'policy_copy' });
      expect(wRow.delivery).toMatchObject({ bodyBanner: 'applied' });
      expect(actionOf(wRow, 'WARN')).toMatchObject({ status: 'enforced' });
      await waitForLifecycle(fx.prisma, warned, 'delivered', 'delivery_complete', 240_000);
      const warnedMail = (await sinkMessage((await sinkFiles(wn))[0]!)).toString('utf8');
      expect(warnedMail).toMatch(/^X-EG-Policy-Warning: warning; Quarantine stack banner\r?$/m);
      expect(warnedMail).toContain(`[WARNING] ${BANNER_TEXT}`);
      expect(warnedMail).toContain('role="alert"');
      expect(warnedMail).toContain(`Plain ${BODY_MARKER}.`);
      expect(warnedMail).toContain(`Html ${BODY_MARKER}.`);
      expect(warnedMail.indexOf('role="alert"')).toBeGreaterThan(warnedMail.indexOf('<body>'));

      // Signed: nothing edited in the body, recorded skipped_signed.
      await clearSinkDomain(inW.name);
      const signed = smimeSignedMessage({
        from: 'Alice Martin <alice@clean.scan.test>',
        to: [wn],
        subject: `${SUBJECT_TOKEN} signed`,
        link: CLEAN_URL,
      });
      const signedMsg = await inbound(orgW, [wn], signed.text);
      const sRow = await evaluated(signedMsg);
      expect(sRow.disposition).toBe('allow');
      expect(sRow.delivery).toMatchObject({ bodyBanner: 'skipped_signed' });
      await waitForLifecycle(fx.prisma, signedMsg, 'delivered', 'delivery_complete', 240_000);
      const signedMail = (await sinkMessage((await sinkFiles(wn))[0]!)).toString('utf8');
      expect(signedMail).not.toContain('[WARNING]');
      // The signed part is byte-for-byte the sent one (line endings aside).
      expect(bodyOf(signedMail)).toContain(signed.signedBody.replace(/\r\n/g, '\n'));

      // URL_REWRITE with the tenant's scan-time rewriting off: the policy-engine rewrites.
      const ur = `${LP.ur}@${inW.name}`;
      const links = linkMessage({
        from: 'Alice Martin <alice@clean.scan.test>',
        to: [ur],
        subject: `${SUBJECT_TOKEN} links`,
        textLinks: [CLEAN_URL],
        htmlLinks: [CLEAN_URL],
      });
      const linked = await inbound(orgW, [ur], links.text);
      const uRow = await evaluated(linked);
      const [rewrite] = await urlRewritesOf(fx.prisma, linked);
      expect(rewrite).toMatchObject({ status: 'skipped', skipReason: 'disabled' });
      expect(uRow).toMatchObject({ disposition: 'allow', deliveredObject: 'policy_copy' });
      expect(uRow.delivery).toMatchObject({
        urlRewrite: { policyRewritable: true, policyAttempt: { status: 'rewritten' } },
      });
      expect(actionOf(uRow, 'URL_REWRITE')).toMatchObject({ status: 'enforced' });
      await waitForLifecycle(fx.prisma, linked, 'delivered', 'delivery_complete', 240_000);
      const linkedMail = (await sinkMessage((await sinkFiles(ur))[0]!)).toString('utf8');
      const tokens = clickTokensIn(linkedMail);
      expect(tokens.length).toBeGreaterThanOrEqual(2);
      expect(linkedMail).toContain(`href="${clickBaseUrl()}/c/`);
      const clicked = await click(`/c/${tokens[0]!}`);
      expect(clicked.status).toBe(302);
      expect(clicked.location).toBe(CLEAN_URL);
      record('quarantine-smtp', {
        banner: (wRow.delivery as { bodyBanner: string }).bodyBanner,
        signed: (sRow.delivery as { bodyBanner: string }).bodyBanner,
        policy_rewrite: tokens.length,
      });
    });

    it('(12) bulk: over the per-request limit 400, per-item results, the per-minute item limit 429', async () => {
      const { entries } = await heldInbound([LP.bk]);
      const tooMany = await postIdem(
        analystQ!,
        '/quarantine/bulk',
        {
          action: 'reject',
          ids: Array.from({ length: 101 }, () => randomUUID()),
          reason: 'stack test',
        },
        'bulk-over',
      );
      expect(tooMany.status, JSON.stringify(tooMany.body)).toBe(400);
      expect(code(tooMany)).toBe('quarantine_bulk_limit');

      expect(shared.rejected, 'case 5 rejected an entry').toBeDefined();
      const unknown = randomUUID();
      const mixed = await postIdem(
        analystQ!,
        '/quarantine/bulk',
        {
          action: 'reject',
          ids: [entries[0]!.publicId, unknown, shared.rejected!.publicId],
          reason: 'stack test: bulk reject',
        },
        'bulk-mixed',
      );
      expect(mixed.status, JSON.stringify(mixed.body)).toBe(200);
      const results = (mixed.body as { results: { id: string; status: string; code?: string }[] })
        .results;
      expect(results.map((r) => [r.id, r.status])).toEqual([
        [entries[0]!.publicId, 'done'],
        [unknown, 'not_found'],
        [shared.rejected!.publicId, 'refused'],
      ]);
      expect(results[2]!.code).toBe('quarantine_state_conflict');
      expect((await entryByPublicId(fx.prisma, entries[0]!.publicId)).status).toBe('rejected');
      expect(
        await fx.prisma.auditLog.count({
          where: { organizationId: orgQ, action: 'quarantine.bulk' },
        }),
      ).toBe(1);

      // Per organization and minute (default 1 000 items): eleven requests of 100 in one window.
      await untilNextMinute(500);
      const minute = Math.floor(Date.now() / 60_000);
      const statuses: number[] = [];
      let limited: ApiResponse | undefined;
      for (let i = 0; i < 11 && !limited; i += 1) {
        const res = await postIdem(
          analystL!,
          '/quarantine/bulk',
          {
            action: 'reject',
            ids: Array.from({ length: 100 }, () => randomUUID()),
            reason: 'stack test',
          },
          `bulk-flood-${i}`,
        );
        statuses.push(res.status);
        if (res.status === 429) limited = res;
      }
      expect(Math.floor(Date.now() / 60_000), 'all requests in one minute window').toBe(minute);
      expect(statuses).toEqual([200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 429]);
      expect(code(limited!)).toBe('quarantine_bulk_rate_limited');
      expect(Number(limited!.headers.get('retry-after'))).toBeGreaterThan(0);
    });

    it('(13) self-service: a mailbox_user sees only its own entries; self-release of a low-risk policy entry is delivered; GTUBE and a hard block are refused', async () => {
      expect(shared.gtubeEntries && shared.eicarEntries, 'cases 1 and 4 ran').toBeTruthy();
      await patchQuarantineSettings(adminQ!, {
        endUser: {
          selfRelease: true,
          selfReleaseReasons: ['spam', 'policy'],
          selfReleaseMaxLevel: 'medium',
        },
      });
      const { message, entries } = await heldInbound([LP.m1]);
      const own = entries[0]!;
      const eicarOwn = shared.eicarEntries!.find((e) => e.recipientAddress === qa(LP.m1))!;
      const list = await waitFor(
        "M1's entries (replica)",
        async () => {
          const res = await m1!.get(`/quarantine/me/entries?${windowQuery()}`);
          const items = (res.body as { items?: { id: string; recipient: string }[] }).items ?? [];
          return res.status === 200 && items.some((i) => i.id === own.publicId) ? items : undefined;
        },
        { timeoutMs: 30_000, intervalMs: 500 },
      );
      expect(new Set(list.map((i) => i.recipient))).toEqual(new Set([qa(LP.m1)]));
      expect(list.map((i) => i.id)).toEqual(
        expect.arrayContaining([own.publicId, eicarOwn.publicId]),
      );
      // Another address's entry is 404, operator routes are 403.
      expect(
        (await m1!.get(`/quarantine/me/entries/${shared.heldEntries![0]!.publicId}`)).status,
      ).toBe(404);
      expect((await m1!.get(`/quarantine/entries?${windowQuery()}`)).status).toBe(403);
      // The hard-blocked (manual EICAR) entry: no preview, no self-release.
      const noPreview = await m1!.get(`/quarantine/me/entries/${eicarOwn.publicId}/preview`);
      expect(noPreview.status).toBe(403);
      expect(code(noPreview)).toBe('quarantine_preview_not_allowed');
      const hardBlock = await postIdem(
        m1!,
        `/quarantine/me/entries/${eicarOwn.publicId}/release`,
        { reason: 'mine' },
        'self-eicar',
      );
      expect(hardBlock.status, JSON.stringify(hardBlock.body)).toBe(403);
      expect(code(hardBlock)).toBe('quarantine_self_release_not_allowed');
      // GTUBE (M2's address): refused (level above the bound).
      const g2 = shared.gtubeEntries!.find((e) => e.recipientAddress.startsWith(`${LP.g2}@`))!;
      const m2List = await m2!.get(`/quarantine/me/entries?${windowQuery()}`);
      expect(m2List.status).toBe(200);
      expect(
        new Set((m2List.body as { items: { recipient: string }[] }).items.map((i) => i.recipient)),
      ).toEqual(new Set([g2.recipientAddress]));
      const gtube = await postIdem(
        m2!,
        `/quarantine/me/entries/${g2.publicId}/release`,
        { reason: 'mine' },
        'self-gtube',
      );
      expect(gtube.status, JSON.stringify(gtube.body)).toBe(403);
      expect(code(gtube)).toBe('quarantine_self_release_not_allowed');
      // The own low-risk policy entry: self-release queued, executed (mode self), delivered.
      const released = await postIdem(
        m1!,
        `/quarantine/me/entries/${own.publicId}/release`,
        { reason: 'mine' },
        'self',
      );
      expect(released.status, JSON.stringify(released.body)).toBe(202);
      expect(released.body).toMatchObject({ outcome: 'queued' });
      const [log] = await executed((released.body as { releaseId: string }).releaseId);
      expect(log).toMatchObject({ status: 'dispatched', mode: 'self' });
      await waitFor(
        'the self-released message in mail-sink',
        async () => (await sinkFiles(qa(LP.m1))).length === 1,
        {
          timeoutMs: 240_000,
          intervalMs: 1_000,
        },
      );
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 240_000);
      expect(
        await fx.prisma.auditLog.count({
          where: {
            organizationId: orgQ,
            action: 'quarantine.self_released',
            resourceId: own.publicId,
          },
        }),
      ).toBe(1);
      record('quarantine-smtp', {
        self_gtube: (gtube.body as { cause?: string }).cause ?? '',
        self_hard_block: (hardBlock.body as { cause?: string }).cause ?? '',
      });
    });

    it('(14) rescan of a quarantined message supersedes its entries; the new round creates new entries', async () => {
      const { message, entries } = await heldInbound([LP.rs]);
      const current = await lifecycleOf(fx.prisma, message);
      const res = await postIdem(
        analystQ!,
        `/messages/${message.publicId}/rescan`,
        { expectedVersion: current.version, reason: 'stack test: re-evaluate' },
        'rescan',
      );
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      const row1 = await evaluated(message, 1);
      expect(row1.disposition).toBe('quarantine');
      const round1 = await waitForEntries(fx.prisma, message, 1, { round: 1 });
      const old = await entryByPublicId(fx.prisma, entries[0]!.publicId);
      expect(old).toMatchObject({ status: 'superseded', terminalReason: 'superseded' });
      expect(round1[0]).toMatchObject({
        status: 'held',
        lifecycleRound: 1,
        rcptSeq: 0,
        evaluationSeq: 1,
      });
      expect(round1[0]!.publicId).not.toBe(old.publicId);
      expectContentFree([old, ...round1]);
      expect((await evaluationsOf(fx.prisma, message)).map((r) => r.evaluationSeq)).toEqual([0, 1]);
      await waitForLifecycle(fx.prisma, message, 'quarantined', 'policy_quarantine');
    });

    it('every quarantine row of the fixture organizations is content-free; the old operator release answers 409 quarantine_workflow_required', async () => {
      const { problems, counts } = await quarantineContentProblems(
        fx.prisma,
        [orgQ, orgD, orgW, orgL],
        forbidden(),
      );
      expect(problems).toEqual([]);
      expect(counts.entries).toBeGreaterThanOrEqual(15);
      // Q30: a quarantined message is never released through the step 3.3 route.
      const message = shared.gtube!;
      const state = await lifecycleOf(fx.prisma, message);
      expect(state.status).toBe('quarantined');
      const old = await postIdem(
        adminQ!,
        `/messages/${message.publicId}/release`,
        { expectedVersion: state.version, reason: 'stack test: old route' },
        'old-release',
      );
      expect(old.status, JSON.stringify(old.body)).toBe(409);
      expect(old.body).toMatchObject({ code: 'quarantine_workflow_required' });
      record('quarantine-smtp', counts);
    });
  },
);
