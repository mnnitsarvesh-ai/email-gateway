/* eslint-disable @typescript-eslint/no-unsafe-return -- predicates over the api's loose JSON */
import { randomInt } from 'node:crypto';
import { eicar } from '@email-gateway/attachment-corpus';
import { Prng, Synthetic } from '@email-gateway/dlp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import {
  ADAPTER_SUITE_ENV,
  apiModeRowCounts,
  apiModeStackGate,
  decodedMailText,
  mailboxByAddress,
  purgeApiModeRows,
  recreateService,
  restoreService,
  sim,
  simMicrosoftDirectory,
} from './support/api-mode';
import { purgeClawbackRows, syntheticEml, clawbackRowCounts } from './support/api-mode-clawback';
import {
  COPY_DETECTED,
  POLICY_DECIDED,
  POLICY_NOTIFICATION_REQUESTED,
  PARITY_WORKER_SUITE_ENV,
  alertRequestsFor,
  detectRowsOf,
  outboxRowsOf,
  parityPayloadProblems,
  parityRowCounts,
  purgeParityRows,
  resetAlertWindows,
  simCallMark,
  simCallsNaming,
  waitForDetectRow,
} from './support/api-mode-parity';
import {
  actionsOfCopy,
  mailboxEntriesOfCopy,
  purgeRemediationRows,
  remediationRowCounts,
  simLocation,
} from './support/api-mode-remediation';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import {
  M365_SENDER,
  createSource,
  expectAccepted,
  intakeDomain,
  journalReport,
  queuedBouncesTo,
  sendIntake,
  waitForIntakeMessage,
} from './support/journal-intake';
import { clearSinkDomain, sinkFiles, sinkMessages } from './support/mail-sink';
import { record } from './support/messaging-stack';
import { createAndPublishPolicy } from './support/policy';
import { deleteQueued, involving, listQueue } from './support/postfix';
import {
  M365_PERMISSIONS,
  expectStatus,
  fake,
  guid,
  purgeProviderRows,
  runtimeSecret,
  waitForConnection,
  type Json,
} from './support/providers';
import { MAIL_SINK_HOST, organizationRef, sleep } from './support/routing';
import { sendToMx } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import {
  createWebhook,
  pointPostfixNotifyAtRelaySink,
  putAlertSettings,
  receivedRequests,
  restorePostfixNotify,
  waitForRequests,
  webhookRowCounts,
  type CreatedWebhook,
  type ReceivedRequest,
} from './support/webhooks';

/**
 * Step API-4 — API-mode parity and onboarding on the live containers
 * (docs/plan/steps/38-api-mode-parity-onboarding.md §10.6 cases (1)–(10), ADR-0105–0107):
 * journal reports sent with swaks from `provider-sender-m365` to the inbound Postfix and the
 * smtp-adapter's journal listener; inline mail through `postfix:25`; copies scanned by the
 * email-worker (DLP with a tenant DLP policy, EICAR); the mailbox-worker's `copies` role
 * evaluating the tenant policies in detect mode (`@email-gateway/policy-runtime`) and deciding the
 * policy lane, its `remediate` role acting on the TEST-ONLY idp-simulator's Graph mailboxes and
 * its health leader evaluating mailbox scopes and expiring detect-only periods;
 * `mail.message.copy_detected.v1` relayed by the rebuilt event-relay (topology v19) to the
 * webhook-worker (`mailbox.threat.detected`, `mailbox.dlp.detected` at the TEST-ONLY
 * webhook-receiver; alerts `threat_detected`, `dlp_detected`) and the notification-worker
 * (alert, detect-mode policy-alert and detect-only e-mails relayed by postfix-notify to
 * notify-relay-sink); ownership through the bound provider tenant checked by the
 * integration-worker against 8.2's provider-fake and won by the api's `DomainCheckScheduler`.
 *
 * Postfix must reach the adapter CONTAINER (the stack switch of `journal-intake.test.ts`:
 * `SMTP_ADAPTER_HOST=smtp-adapter docker compose up -d --no-deps --force-recreate postfix
 * postfix-outbound`, restored from `.env` afterwards).
 *
 * Test seams (recorded in note 38 §15.7): the alert windows of `threat_detected` / `dlp_detected`
 * of the organization are cleared before cases (2) and (4) (an earlier detection of the run would
 * otherwise hold the 60-minute window); case (9) moves `detect_only_until` of policies created
 * through the api into the past (the api only accepts now + 1 h … now + 30 d); case (10)
 * back-dates the api domain's `activated_at` by 15 minutes before the first copy (hints are shown
 * after `API_MODE_FIRST_COPY_HINT_AFTER_MINUTES`, 10). Documented test card numbers are refused by
 * the DLP detector by design (`packages/dlp` `TEST_CARD_NUMBERS`), so card values come from the
 * `@email-gateway/dlp` synthetic corpus generator, as `dlp-smtp` and `policy-smtp` do; the card
 * bodies avoid the detector's negative context words (`example`, `test`, `sample`, `order`) and keep the
 * `card` keyword next to the value (the reportable confidence of PC1).
 *
 * Organization `it-apiparity-<suffix>-m` (Microsoft 365: an `api` domain bound to the
 * connection, a `hybrid` domain with inline delivery to mail-sink, two `api` domains for the
 * detect-only cases, two pending domains for the ownership case) only — never organizations 1,
 * 2, 16946 or user 21416. Synthetic EML, the EICAR test string and corpus card values only. Tenant
 * id and app secret are generated at run time; every row, Redis key, queue entry and sink file of
 * the run is removed at the end. Observed values are recorded as `[api-mode-parity] …` lines.
 */
const gate = await apiModeStackGate();
const fx = new SmtpFixtures();
const synthetic = new Synthetic(new Prng(randomInt(1, 2 ** 31 - 1)));
const tenantM = guid();
const appM = { clientId: guid(), secret: runtimeSecret() };
const MAILBOX_ROLES = ['Mail.ReadWrite', 'User.Read.All'];
const QUARANTINE_FOLDER = process.env.API_MODE_QUARANTINE_FOLDER_NAME ?? 'Email Gateway Quarantine';
const LOG = 'api-mode-parity';
const WEBHOOK_TYPES = [
  'mailbox.threat.detected',
  'mailbox.dlp.detected',
  'email.threat.detected',
  'email.received',
];

interface Org {
  id: bigint;
  publicId: string;
  slug: string;
}
let orgM: Org;
let apiDom: FixtureDomain;
let hybDom: FixtureDomain;
let remDom: FixtureDomain;
let enfDom: FixtureDomain;
let connM = '';
let sourceM: { id: string; address: string } | undefined;
let webhook: CreatedWebhook | undefined;
let analyst: ApiSession | undefined;
let policyId = '';
let overridden = false;
let notifyPointed = false;
const sessions: ApiSession[] = [];
const cachedSessions = new Map<string, { session: ApiSession; at: number }>();
const simUsers = new Map<string, string>();
const shared: { firstCopyPublicId?: string; firstMessage?: string } = {};
/** Strings that never appear in a webhook payload or alert e-mail (subjects, local parts, …). */
const forbidden: string[] = ['alex', 'blake', 'casey', 'dana', 'hana', 'EXAMPLE parity'];

const addr = (local: string, d: FixtureDomain) => `${local}@${d.name}`;
const alex = () => addr('alex', apiDom);
const blake = () => addr('blake', apiDom);
const casey = () => addr('casey', apiDom);
const dana = () => addr('dana', apiDom);
const hana = () => addr('hana', hybDom);
const EXTERNAL_SENDER = 'sender@sender.example.test';
const BLOCKED_DOMAIN = 'blocked.example.test';
const BLOCKED_SENDER = `offers@${BLOCKED_DOMAIN}`;
const PARTNER = 'partner@partner.example.test';
const INLINE_SENDER = 'alice@clean.scan.test';
const messageIdOf = (label: string) =>
  `it-apiparity-${label}-${guid().slice(0, 12)}@sender.example.test`;
const subjectOf = (label: string) => {
  const s = `APIPARITY ${fx.suffix} ${label}`;
  forbidden.push(s);
  return s;
};
const spaced = (card: string) => card.replace(/(\d{4})(?=\d)/g, '$1 ');

/** An organization admin (MFA); renewed before the 10-minute token ends. */
async function admin(o: Org = orgM): Promise<ApiSession> {
  const hit = cachedSessions.get(o.slug);
  if (hit && Date.now() - hit.at < 8 * 60_000) return hit.session;
  const session = await apiSession(fx.prisma, { id: o.id, slug: o.slug }, 'organization_admin', {
    mfa: true,
  });
  sessions.push(session);
  cachedSessions.set(o.slug, { session, at: Date.now() });
  return session;
}

/** Every alert recipient of the run (each admin session's address receives alert e-mails). */
async function alertMails(predicate: (text: string) => boolean, only?: string): Promise<string[]> {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const s of sessions) {
    if (seen.has(s.email) || (only !== undefined && s.email !== only)) continue;
    seen.add(s.email);
    for (const raw of await sinkMessages(s.email, 'notify-relay-sink')) {
      const text = decodedMailText(raw);
      if (predicate(text)) out.push(text);
    }
  }
  return out;
}

function waitForAlertMail(what: string, predicate: (text: string) => boolean, timeoutMs = 180_000) {
  return waitFor(`${what} at notify-relay-sink`, async () => (await alertMails(predicate))[0], {
    timeoutMs,
    intervalMs: 3_000,
  });
}

const mailboxIdOf = (address: string) =>
  mailboxByAddress(fx.prisma, orgM.id, address).then((m) => m?.id);

/** The copy row of `address`'s mailbox for registry message `messageId` once `predicate` holds. */
function copyOf(
  address: string,
  messageId: bigint,
  predicate: (c: Awaited<ReturnType<typeof fx.prisma.apiMessageCopy.findMany>>[number]) => boolean,
  timeoutMs = 300_000,
) {
  return waitFor(
    `API-mode copy of message ${messageId.toString()} for ${address.split('@')[0]}`,
    async () => {
      const mailboxId = await mailboxIdOf(address);
      if (mailboxId === undefined) return undefined;
      const rows = await fx.prisma.apiMessageCopy.findMany({
        where: { organizationId: orgM.id, mailboxId, messageId },
      });
      return rows.find(predicate);
    },
    { timeoutMs, intervalMs: 1_500 },
  );
}

const decided = (c: { status: string; policyState: string; remediationState: string }) =>
  c.status === 'scanned' && c.policyState !== 'none' && c.remediationState !== 'pending';

/** The registry message and its public id (`message_identities`, the id events carry). */
async function registryMessage(messageId: bigint) {
  const row = await fx.prisma.emailMessage.findFirstOrThrow({
    where: { organizationId: orgM.id, id: messageId },
    select: {
      id: true,
      status: true,
      finalVerdict: true,
      finalAction: true,
      ingestSource: true,
    },
  });
  const identity = await fx.prisma.messageIdentity.findUniqueOrThrow({
    where: { id: messageId },
    select: { publicId: true, organizationId: true },
  });
  expect(identity.organizationId).toBe(orgM.id);
  return { ...row, publicId: identity.publicId };
}

/** A journal report of `original` for the M365 intake source, sent from provider-sender-m365. */
async function sendJournal(o: {
  messageId: string;
  sender: string;
  to: readonly string[];
  original: string;
  what: string;
}) {
  const sent = await sendIntake({
    service: M365_SENDER,
    to: [sourceM!.address],
    data: journalReport({
      intakeAddress: sourceM!.address,
      original: o.original,
      sender: o.sender,
      to: o.to,
      messageId: `<${o.messageId}>`,
      tenantIds: [tenantM],
    }),
  });
  expectAccepted(sent, `journal report ${o.what}`);
  const msg = await waitForIntakeMessage(fx.prisma, orgM.id, `<${o.messageId}>`, 'journaled');
  return registryMessage(msg.id);
}

/** Received webhooks of the run's subscription for one message (each checked for content). */
async function webhooksOf(messagePublicId: string, type?: string): Promise<ReceivedRequest[]> {
  const all = await receivedRequests(webhook!.path);
  return all.filter(
    (r) => r.envelope.data.message?.id === messagePublicId && (!type || r.eventType === type),
  );
}

function waitForWebhook(messagePublicId: string, type: string): Promise<ReceivedRequest> {
  return waitForRequests(
    webhook!.path,
    `${type} for ${messagePublicId}`,
    (reqs) =>
      reqs.some((r) => r.eventType === type && r.envelope.data.message?.id === messagePublicId),
    240_000,
  ).then((reqs) =>
    reqs.find((r) => r.eventType === type && r.envelope.data.message?.id === messagePublicId)!,
  );
}

function decisionOf(action: { decision: unknown }) {
  return action.decision as {
    v: number;
    ruleId: string | null;
    lanes: {
      verdict: { ruleId: string; action: string } | null;
      policy: { key: string; action: string } | null;
      winner: 'verdict' | 'policy' | null;
      suppressedBy: string | null;
    };
    policyOutcome: Json;
    postDelivery: { type: string; status: string; reason: string | null }[];
  };
}

async function putProtectionMode(d: FixtureDomain, mode: 'api' | 'hybrid') {
  expectStatus(
    await (
      await admin()
    ).put(
      `/domains/${d.publicId}/protection-mode`,
      { mode, reason: `stack test: API-mode parity ${mode} domain` },
      idempotencyKey(),
    ),
    200,
    `PUT /domains/{id}/protection-mode ${mode}`,
  );
}

async function scopeOf(d: FixtureDomain): Promise<Json> {
  const res = await (await admin()).get(`/api-mode/domains/${d.publicId}/scope`);
  expectStatus(res, 200, 'GET /api-mode/domains/{id}/scope');
  return res.body as Json;
}

async function putScope(d: FixtureDomain, scope: Json, mailboxIds?: string[]): Promise<Json> {
  const current = await scopeOf(d);
  const res = await (
    await admin()
  ).put(
    `/api-mode/domains/${d.publicId}/scope`,
    {
      scope,
      ...(mailboxIds ? { mailboxIds } : {}),
      reason: `stack test: scope ${scope.kind as string}`,
      expectedRowVersion: current.rowVersion,
    },
    idempotencyKey(),
  );
  expectStatus(res, 200, 'PUT /api-mode/domains/{id}/scope');
  return res.body as Json;
}

async function onboardingOf(d: FixtureDomain): Promise<Json> {
  const res = await (await admin()).get(`/api-mode/domains/${d.publicId}/onboarding`);
  expectStatus(res, 200, 'GET /api-mode/domains/{id}/onboarding');
  return res.body as Json;
}

beforeAll(async () => {
  assertStackReady(gate);
  overridden = true;
  await recreateService('mailbox-worker', PARITY_WORKER_SUITE_ENV);
  await recreateService('smtp-adapter', ADAPTER_SUITE_ENV);
  await pointPostfixNotifyAtRelaySink();
  notifyPointed = true;

  const enterprise = await fx.prisma.organizationPlan.findFirstOrThrow({
    where: { code: 'enterprise' },
    select: { id: true },
  });
  const id = await fx.organization('apiparity-m');
  const slug = `it-apiparity-${fx.suffix}-m`;
  await fx.prisma.organization.update({
    where: { id },
    data: { planId: enterprise.id, slug, name: 'API parity M' },
  });
  orgM = { id, publicId: (await organizationRef(fx, id)).publicId, slug };
  await fx.feature(orgM.id, 'api_mode_protection', true);
  await fx.feature(orgM.id, 'journal_intake', true);
  await fx.feature(orgM.id, 'webhooks', true);
  apiDom = await fx.domain(orgM.id, 'apiparity-api', { inboundEnabled: false });
  hybDom = await fx.domain(orgM.id, 'apiparity-hyb');
  await fx.destinations(hybDom, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  remDom = await fx.domain(orgM.id, 'apiparity-rem', { inboundEnabled: false });
  enfDom = await fx.domain(orgM.id, 'apiparity-enf', { inboundEnabled: false });
  for (const d of [apiDom, remDom, enfDom]) await putProtectionMode(d, 'api');
  await putProtectionMode(hybDom, 'hybrid');

  // Provider side, generated now: the tenant lists the bound domains and the second domain of
  // case (7) as verified; the unlisted domain of case (7) is absent.
  await fake.addMicrosoftTenant({
    tenantId: tenantM,
    displayName: `API parity ${fx.suffix}`,
    domains: [apiDom.name, hybDom.name, fx.name('apiparity-own')].map((name, i) => ({
      name,
      isVerified: true,
      isDefault: i === 0,
      mxHost: null,
    })),
  });
  await fake.addMicrosoftApp({
    clientId: appM.clientId,
    secret: appM.secret,
    homeTenantId: tenantM,
    requiredRoles: [...M365_PERMISSIONS, ...MAILBOX_ROLES],
  });
  await fake.consent(tenantM, appM.clientId, [...M365_PERMISSIONS, ...MAILBOX_ROLES]);

  await sim.reset();
  const users = [alex(), blake(), casey(), dana(), hana()].map((address) => ({
    id: guid(),
    address,
  }));
  for (const u of users) simUsers.set(u.address, u.id);
  await sim.dataset({
    microsoft: {
      directories: [simMicrosoftDirectory(tenantM, [apiDom.name, hybDom.name], users)],
    },
  });

  // The Microsoft 365 connection: mail-flow grant → link and bind → mailbox grant → inventory.
  const m = await admin();
  const created = await m.post(
    '/provider-connections',
    { provider: 'microsoft_365', displayName: `EXAMPLE API parity ${fx.suffix}` },
    idempotencyKey(),
  );
  expectStatus(created, 201, 'POST /provider-connections');
  connM = (created.body as Json).id as string;
  for (const profile of ['m365.mail_flow', 'm365.mailbox_remediation']) {
    expectStatus(
      await m.post(
        `/provider-connections/${connM}/grants`,
        { profile, authMethod: 'customer_app_secret' },
        idempotencyKey(),
      ),
      201,
      `POST …/grants ${profile}`,
    );
    expectStatus(
      await m.put(
        `/provider-connections/${connM}/grants/${profile}/credentials`,
        { tenantId: tenantM, clientId: appM.clientId, clientSecret: appM.secret },
        idempotencyKey(),
      ),
      200,
      `PUT …/credentials ${profile}`,
    );
    await waitForConnection(m, connM, `${profile} grant active`, (c) =>
      c.grants.some((x: Json) => x.profile === profile && x.status === 'active'),
    );
    if (profile === 'm365.mail_flow') {
      expectStatus(
        await m.put(
          `/provider-connections/${connM}/domains`,
          { domainIds: [apiDom.publicId, hybDom.publicId] },
          idempotencyKey(),
        ),
        200,
        'PUT …/domains',
      );
      await waitForConnection(m, connM, 'status active (bound)', (c) => c.status === 'active');
    }
  }
  expectStatus(
    await m.post(`/api-mode/connections/${connM}/inventory-sync`, {}, idempotencyKey()),
    202,
    'inventory-sync',
  );
  await waitFor(
    'inventory ok (5 mailboxes)',
    async () => {
      const res = await (await admin()).get(`/api-mode/connections/${connM}`);
      const c = res.body as Json;
      return res.status === 200 && c.inventoryStatus === 'ok' && c.mailboxesTotal === 5
        ? c
        : undefined;
    },
    { timeoutMs: 300_000, intervalMs: 2_000 },
  );

  // Security alerts on for this organization (the fixture switches them off, see
  // FIXTURE_NOTIFICATION_SETTINGS): threat and DLP alerts, never the organization contact.
  await putAlertSettings(m, {
    threatDetected: { enabled: true },
    dlpDetected: { enabled: true },
    domainDnsFailed: { enabled: false },
    webhookDisabled: { enabled: false },
    includeOrganizationContact: false,
  });

  // The webhook subscription to the two new types (+ the inline types, to prove their absence).
  webhook = await createWebhook(m, {
    name: 'it-apiparity detections',
    path: `it-apiparity-${fx.suffix}`,
    eventTypes: WEBHOOK_TYPES,
  });

  // Tenant policies (5.2): a block-listed sender → REJECT; an ALERT for one recipient. The DLP
  // policy (4.5): payment cards in outbound and internal mail → quarantine.
  analyst = await apiSession(fx.prisma, { id: orgM.id, slug: orgM.slug }, 'security_analyst');
  sessions.push(analyst);
  const published = await createAndPublishPolicy(analyst, m, 'API parity rules', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'block-listed-sender',
        priority: 10,
        when: { field: 'sender.header_from.domain', op: 'equals', value: BLOCKED_DOMAIN },
        actions: [{ type: 'REJECT' }],
      },
      {
        id: 'alert-recipient',
        priority: 20,
        when: { field: 'recipient.local_part', op: 'equals', value: 'dana' },
        actions: [{ type: 'ALERT', severity: 'warning' }],
      },
    ],
  });
  policyId = published.policyId;
  const dlp = await analyst.post('/dlp/policies', {
    name: 'API parity cards',
    priority: 10,
    directions: ['outbound', 'internal'],
  });
  expect(dlp.status, JSON.stringify(dlp.body)).toBe(201);
  const dlpRule = await analyst.post(`/dlp/policies/${(dlp.body as Json).id as string}/rules`, {
    name: 'Cards → quarantine',
    priority: 10,
    conditions: { selectors: { categories: ['payment_card'] } },
    action: 'quarantine',
  });
  expect(dlpRule.status, JSON.stringify(dlpRule.body)).toBe(201);
  record(LOG, { organizations: 1, domains: 4, connections: 1, simulator_users: users.length });
}, 1_200_000);

afterAll(async () => {
  if (gate.skip) return;
  const ids = orgM ? [orgM.id] : [];
  await sim.reset().catch(() => undefined);
  // Stop the worker first (recreated from .env) so no claim or flush writes behind the purge.
  if (overridden) await restoreService('mailbox-worker').catch(() => undefined);
  await purgeParityRows(fx.prisma, fx.redis, ids);
  await purgeClawbackRows(fx.prisma, ids);
  await purgeRemediationRows(fx.prisma, ids);
  await purgeApiModeRows(fx.prisma, fx.redis, ids);
  const sources = await fx.prisma.journalIntakeSource.findMany({
    where: { organizationId: { in: ids } },
    select: { addressHash: true, previousAddressHash: true },
  });
  const where = { organizationId: { in: ids } };
  await fx.prisma.journalIntakeMessage.deleteMany({ where });
  await fx.prisma.journalIntakeCounter.deleteMany({ where });
  await fx.prisma.journalIntakeSource.deleteMany({ where });
  const keys = sources.flatMap((s) => [
    `sa:jintake:src:${s.addressHash}`,
    ...(s.previousAddressHash ? [`sa:jintake:src:${s.previousAddressHash}`] : []),
  ]);
  if (keys.length > 0) await fx.redis.del(...keys);
  await purgeProviderRows(fx.prisma, ids);
  await fx.prisma.auditLog.deleteMany({ where });
  for (const session of sessions) await session.remove().catch(() => undefined);
  const names = [apiDom, hybDom, remDom, enfDom].filter(Boolean).map((d) => d.name);
  for (const service of ['postfix', 'postfix-outbound'] as const) {
    const queued = involving(await listQueue(service), [...names, intakeDomain()]);
    await deleteQueued(
      service,
      queued.map((q) => q.queue_id),
    );
  }
  for (const d of names) await clearSinkDomain(d, 'all').catch(() => undefined);
  await clearSinkDomain('routing.integration.test', 'notify-relay-sink').catch(() => undefined);
  const { PrismaClient } = await import('@email-gateway/database');
  const check = new PrismaClient({ datasourceUrl: process.env.DATABASE_URL });
  await fx.cleanup();
  if (notifyPointed) await restorePostfixNotify();
  if (overridden) await restoreService('smtp-adapter');
  try {
    const counts = {
      ...(await apiModeRowCounts(check, ids)),
      ...(await remediationRowCounts(check, ids)),
      ...(await clawbackRowCounts(check, ids)),
      ...(await parityRowCounts(check, ids)),
      ...(await webhookRowCounts(check, ids)),
      quarantineEntries: await check.quarantineMessage.count({ where }),
      domains: await check.domain.count({ where }),
    };
    record(LOG, { cleanup: JSON.stringify(counts) });
    expect(
      Object.values(counts).every((n) => n === 0),
      JSON.stringify(counts),
    ).toBe(true);
    expect(await check.organization.count({ where: { id: { in: ids } } })).toBe(0);
    expect(await check.providerConnection.count({ where })).toBe(0);
    expect(
      await check.organization.count({ where: { slug: { startsWith: 'it-apiparity-' } } }),
    ).toBe(0);
  } finally {
    await check.$disconnect();
  }
}, 900_000);

describe.skipIf(gate.skip)(
  'API-mode parity and onboarding (step API-4 §10.6)',
  { timeout: 900_000 },
  () => {
    it('(10a) onboarding before the first copy: waiting with hints (journal source missing); the journal source then clears that hint', async () => {
      // Test seam: hints appear after API_MODE_FIRST_COPY_HINT_AFTER_MINUTES (10) of waiting.
      await fx.prisma.domain.update({
        where: { id: apiDom.id },
        data: { activatedAt: new Date(Date.now() - 15 * 60_000) },
      });
      const before = await onboardingOf(apiDom);
      expect(before).toMatchObject({
        domainId: apiDom.publicId,
        effectiveMode: 'api',
        ownership: { status: 'verified' },
        connection: { id: connM, bound: true, mailboxAccessGrant: 'active' },
        scope: { kind: 'all' },
        firstCopy: { status: 'waiting', copy: null },
      });
      expect(before.firstCopy.waitingSinceMinutes).toBeGreaterThanOrEqual(10);
      const codes = (before.firstCopy.hints as Json[]).map((h) => h.code);
      expect(codes).toEqual(
        expect.arrayContaining(['journal_source_missing', 'send_test_message']),
      );
      expect(codes).not.toContain('connection_missing');
      expect(codes).not.toContain('mailbox_access_missing');
      expect(JSON.stringify(before)).not.toContain('@');
      const steps = Object.fromEntries((before.steps as Json[]).map((s) => [s.key, s.status]));
      expect(Object.keys(steps)).toEqual([
        'ownership',
        'connect',
        'intake',
        'mailboxes',
        'action',
        'review',
      ]);
      expect(steps.ownership).toBe('done');
      expect(steps.intake).not.toBe('done');

      sourceM = await createSource(await admin(), {
        kind: 'microsoft_365_journal',
        displayName: 'it-apiparity M365 journal',
        providerConnectionId: connM,
      });
      const after = await onboardingOf(apiDom);
      const afterCodes = (after.firstCopy.hints as Json[]).map((h) => h.code);
      expect(afterCodes).not.toContain('journal_source_missing');
      expect(after.intake.journalSources).toHaveLength(1);
      record(LOG, {
        case: '10a',
        hints_before: codes.join(','),
        hints_after: afterCodes.join(','),
      });
    });

    it('(1) tenant REJECT of a block-listed sender on a journal copy → detect row, policy lane → hidden quarantine folder; no delivery, DSN, email.received or mail.policy.decided.v1', async () => {
      const messageId = messageIdOf('c1');
      const original = syntheticEml({
        messageId,
        from: BLOCKED_SENDER,
        to: [alex()],
        subject: subjectOf('c1'),
        body: 'EXAMPLE parity case 1: a newsletter from a block-listed sender.',
      });
      const delivered = await sim.deliver(alex(), original);
      const msg = await sendJournal({
        messageId,
        sender: BLOCKED_SENDER,
        to: [alex()],
        original,
        what: 'c1',
      });
      const copy = await copyOf(alex(), msg.id, (c) => c.remediationState === 'remediated');
      expect(copy).toMatchObject({
        direction: 'inbound',
        source: 'journal',
        verdictAuthority: 'copy',
        policyState: 'evaluated',
        policyDisposition: 'reject',
        policyTagged: false,
        remediationAction: 'move_quarantine',
      });
      const row = await waitForDetectRow(fx.prisma, orgM.id, msg.id);
      expect(row).toMatchObject({
        evaluationMode: 'detect',
        evaluationSeq: 0,
        disposition: 'reject',
        decisionSource: 'tenant_rule',
        decisiveRuleId: 'block-listed-sender',
        deliveredObject: 'none',
        delivery: null,
        objectKey: null,
      });
      expect(row.decisivePolicyPublicId).toBe(policyId);
      expect(await detectRowsOf(fx.prisma, orgM.id, msg.id)).toHaveLength(1);
      const action = (await actionsOfCopy(fx.prisma, orgM.id, copy.id)).find(
        (a) => a.action === 'move_quarantine',
      )!;
      expect(action).toMatchObject({ trigger: 'policy', status: 'succeeded' });
      const decision = decisionOf(action);
      expect(decision.v).toBe(2);
      expect(decision.lanes.policy).toEqual({ key: 'reject', action: 'move_quarantine' });
      expect(decision.policyOutcome).toMatchObject({
        disposition: 'reject',
        decisionSource: 'tenant_rule',
      });
      expect(decision.policyOutcome.decisiveRuleRef).toMatch(
        new RegExp(`^${policyId}#1/block-listed-sender$`),
      );
      // The verdict lane wins only on a tie (it chooses the same move): then the entry keeps the
      // verdict reason; otherwise the policy lane decided and the entry reason is `policy`.
      const verdictMove = decision.lanes.verdict?.action === 'move_quarantine';
      expect(decision.lanes.winner).toBe(verdictMove ? 'verdict' : 'policy');
      const location = await simLocation(alex(), delivered.messageId);
      expect(location.folder).toMatchObject({ displayName: QUARANTINE_FOLDER, isHidden: true });
      const [entry] = await mailboxEntriesOfCopy(fx.prisma, orgM.id, copy.id);
      expect(entry).toMatchObject({ location: 'mailbox', kind: 'quarantine', status: 'held' });
      if (!verdictMove) expect(entry!.reason).toBe('policy');
      // P-I1: nothing of the gateway lifecycle happened for the copy.
      expect(msg).toMatchObject({
        status: 'journaled',
        finalVerdict: null,
        finalAction: null,
        ingestSource: 'journal_intake',
      });
      expect(await fx.prisma.emailDelivery.count({ where: { messageId: msg.id } })).toBe(0);
      expect(
        (await outboxRowsOf(fx.prisma, orgM.id, POLICY_DECIDED)).filter((r) =>
          [msg.id.toString(), msg.publicId].includes(r.aggregateId),
        ),
      ).toEqual([]);
      expect(await queuedBouncesTo([BLOCKED_SENDER])).toBe(0);
      const [detected] = await outboxRowsOf(fx.prisma, orgM.id, COPY_DETECTED, msg.publicId);
      expect(detected!.payload).toMatchObject({
        protectionMode: 'api',
        direction: 'inbound',
        copySource: 'journal',
        policy: { state: 'evaluated', disposition: 'reject', decisionSource: 'tenant_rule' },
        detectionIds: [copy.publicId],
      });
      await sleep(5_000);
      expect(await webhooksOf(msg.publicId, 'email.received')).toEqual([]);
      shared.firstCopyPublicId = copy.publicId;
      shared.firstMessage = msg.publicId;
      record(LOG, {
        case: 1,
        verdict: copy.verdict,
        winner: decision.lanes.winner,
        entry_reason: entry?.reason,
        folder: location.folder?.displayName,
      });
    });

    it('(2) outbound journal message with card numbers → outbound detection copy on the sender mailbox, mailbox.dlp.detected, dlp_detected e-mail, no mailbox call', async () => {
      const cleared = await resetAlertWindows(fx.prisma, orgM.id, 'dlp_detected');
      const mark = await simCallMark();
      const sender = await mailboxByAddress(fx.prisma, orgM.id, alex());
      const card = synthetic.card('4532');
      forbidden.push(card, spaced(card));
      const messageId = messageIdOf('c2');
      const original = syntheticEml({
        messageId,
        from: alex(),
        to: [PARTNER],
        subject: subjectOf('c2 outbound'),
        body: `Payment note: card ${spaced(card)} for the invoice.\r\nThanks`,
      });
      const msg = await sendJournal({
        messageId,
        sender: alex(),
        to: [PARTNER],
        original,
        what: 'c2',
      });
      const copy = await copyOf(alex(), msg.id, (c) => c.direction === 'outbound' && decided(c));
      expect(copy).toMatchObject({
        direction: 'outbound',
        source: 'journal',
        seenJournal: true,
        lagMs: null,
        policyState: 'evaluated',
        dlpAction: 'quarantine',
      });
      const [action] = await actionsOfCopy(fx.prisma, orgM.id, copy.id);
      expect(action).toMatchObject({ status: 'skipped', reasonCode: 'outbound_not_remediable' });
      expect(await mailboxByAddress(fx.prisma, orgM.id, PARTNER)).toBeUndefined();
      // Not a coverage sighting (A6.2).
      const after = await mailboxByAddress(fx.prisma, orgM.id, alex());
      expect(after!.journalLastSeenAt).toEqual(sender!.journalLastSeenAt);
      const hook = await waitForWebhook(msg.publicId, 'mailbox.dlp.detected');
      expect(parityPayloadProblems(hook, orgM.publicId, forbidden)).toEqual([]);
      expect(hook.signatureValid).toBe(true);
      expect(hook.envelope.data.dlp).toMatchObject({
        action: 'quarantine',
        direction: 'outbound',
        protectionMode: 'api',
        remediation: null,
        mailboxCount: 1,
        detectionIds: [copy.publicId],
      });
      expect((hook.envelope.data.dlp as Json).categories).toContain('payment_card');
      const mail = await waitForAlertMail(
        'the dlp_detected alert',
        (t) => t.includes('Sensitive data detected') && t.includes(msg.publicId),
      );
      expect(mail).toContain(`/api-mode?tab=detections&message=${msg.publicId}`);
      for (const value of [card, spaced(card), alex(), PARTNER, 'APIPARITY']) {
        expect(mail).not.toContain(value);
      }
      // The message has left: nothing is located, read or moved in the sender's mailbox.
      await sleep(5_000);
      expect(await simCallsNaming([simUsers.get(alex())!, alex()], mark)).toEqual([]);
      record(LOG, {
        case: 2,
        verdict: copy.verdict,
        dlp: copy.dlpAction,
        disposition: copy.policyDisposition,
        windows_cleared: cleared,
      });
    });

    it('(3) internal copy with a DLP quarantine rule → policy lane → remediated (entry reason by the A5 rule)', async () => {
      const card = synthetic.card('4024');
      forbidden.push(card, spaced(card));
      const messageId = messageIdOf('c3');
      const original = syntheticEml({
        messageId,
        from: alex(),
        to: [blake()],
        subject: subjectOf('c3 internal'),
        body: `Parity internal note: card ${spaced(card)} for the invoice.\r\nThanks`,
      });
      const delivered = await sim.deliver(blake(), original);
      const msg = await sendJournal({
        messageId,
        sender: alex(),
        to: [blake()],
        original,
        what: 'c3',
      });
      const copy = await copyOf(blake(), msg.id, (c) => c.remediationState === 'remediated');
      expect(copy).toMatchObject({
        direction: 'internal',
        verdictAuthority: 'copy',
        policyState: 'evaluated',
        policyDisposition: 'quarantine',
        dlpAction: 'quarantine',
        remediationAction: 'move_quarantine',
      });
      const [row] = await detectRowsOf(fx.prisma, orgM.id, msg.id);
      expect(row).toMatchObject({ direction: 'internal', disposition: 'quarantine' });
      const action = (await actionsOfCopy(fx.prisma, orgM.id, copy.id)).find(
        (a) => a.action === 'move_quarantine',
      )!;
      const decision = decisionOf(action);
      expect(decision.lanes.policy).toEqual({ key: 'quarantine', action: 'move_quarantine' });
      const verdictMove = decision.lanes.verdict?.action === 'move_quarantine';
      const [entry] = await mailboxEntriesOfCopy(fx.prisma, orgM.id, copy.id);
      expect(entry).toMatchObject({ kind: 'quarantine', status: 'held' });
      // A5 (`policyEntryReason`): `dlp` when the DLP floor decided (decision source `floor` with a
      // `policy.floor.dlp_*` reason); a DLP quarantine the platform default already decides is
      // `policy` (recorded in note 38 §15.7 as a difference to the §10.6 (3) expectation).
      const outcome = decision.policyOutcome as { decisionSource: string; floorReasons: string[] };
      const dlpFloor =
        outcome.decisionSource === 'floor' &&
        outcome.floorReasons.some((r) => r.startsWith('policy.floor.dlp_'));
      expect(outcome.floorReasons).toContain('policy.floor.dlp_quarantine');
      if (!verdictMove) expect(entry!.reason).toBe(dlpFloor ? 'dlp' : 'policy');
      expect((await simLocation(blake(), delivered.messageId)).folder?.displayName).toBe(
        QUARANTINE_FOLDER,
      );
      // No outbound copy for the internal sender (A6.2 is for outbound-only messages).
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, messageId: msg.id },
        }),
      ).toBe(1);
      const hook = await waitForWebhook(msg.publicId, 'mailbox.dlp.detected');
      expect(parityPayloadProblems(hook, orgM.publicId, forbidden)).toEqual([]);
      expect(hook.envelope.data.dlp).toMatchObject({
        direction: 'internal',
        action: 'quarantine',
        mailboxCount: 1,
      });
      expect((hook.envelope.data.dlp as Json).remediation).not.toBeNull();
      record(LOG, {
        case: 3,
        verdict: copy.verdict,
        winner: decision.lanes.winner,
        entry_reason: entry?.reason,
        decision_source: outcome.decisionSource,
      });
    });

    it('(4) EICAR journal copy → mailbox.threat.detected (protectionMode api) and one threat_detected e-mail with the /api-mode link', async () => {
      const cleared = await resetAlertWindows(fx.prisma, orgM.id, 'threat_detected');
      const messageId = messageIdOf('c4');
      const original = syntheticEml({
        messageId,
        from: EXTERNAL_SENDER,
        to: [alex()],
        subject: subjectOf('c4 eicar'),
        attachment: { filename: 'eicar.com', content: eicar() },
      });
      forbidden.push('eicar.com');
      const delivered = await sim.deliver(alex(), original);
      const msg = await sendJournal({
        messageId,
        sender: EXTERNAL_SENDER,
        to: [alex()],
        original,
        what: 'c4',
      });
      const copy = await copyOf(alex(), msg.id, (c) => c.remediationState === 'remediated');
      expect(copy).toMatchObject({ verdict: 'malware', remediationAction: 'move_quarantine' });
      expect((await simLocation(alex(), delivered.messageId)).folder?.displayName).toBe(
        QUARANTINE_FOLDER,
      );
      const hook = await waitForWebhook(msg.publicId, 'mailbox.threat.detected');
      expect(parityPayloadProblems(hook, orgM.publicId, forbidden)).toEqual([]);
      expect(hook.signatureValid).toBe(true);
      expect(hook.envelope.data.detection).toMatchObject({
        stage: 'scan',
        verdict: 'malicious',
        protectionMode: 'api',
        direction: 'inbound',
        copySource: 'journal',
        mailboxCount: 1,
        attachment: null,
        detectionIds: [copy.publicId],
      });
      const mail = await waitForAlertMail(
        'the threat_detected alert (API mode)',
        (t) => t.includes('after delivery (API mode)') && t.includes(msg.publicId),
      );
      expect(mail).toContain(`/api-mode?tab=detections&message=${msg.publicId}`);
      expect(mail).not.toContain(`/messages/${msg.publicId}`);
      for (const value of [alex(), EXTERNAL_SENDER, 'APIPARITY', 'eicar.com']) {
        expect(mail).not.toContain(value);
      }
      await sleep(10_000);
      // One e-mail per recipient (the first organization admin of the run holds `quarantine:approve`).
      const adminEmail = sessions[0]!.email;
      expect(
        await alertMails(
          (t) => t.includes('after delivery (API mode)') && t.includes(msg.publicId),
          adminEmail,
        ),
      ).toHaveLength(1);
      // A copy never yields the inline type (N1, ADR-0106).
      expect(await webhooksOf(msg.publicId, 'email.threat.detected')).toEqual([]);
      record(LOG, { case: 4, verdict: copy.verdict, windows_cleared: cleared });
    });

    it('(5) hybrid: an inline-delivered message → its journal copy (inline authority) is not evaluated, no copy_detected, no second alert or webhook, no mailbox call', async () => {
      const mark = await simCallMark();
      const messageId = messageIdOf('c5');
      const original = syntheticEml({
        messageId,
        from: INLINE_SENDER,
        to: [hana()],
        subject: subjectOf('c5 hybrid'),
        body: 'EXAMPLE parity case 5: an ordinary inline message.',
      });
      const sent = await sendToMx({
        from: INLINE_SENDER,
        to: [hana()],
        helo: 'mx.clean.scan.test',
        data: original,
      });
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const inline = await waitForMessage(
        fx.prisma,
        orgM.id,
        { mtaQueueId: sent.queueId! },
        120_000,
      );
      await waitFor(
        'inline delivery to the hybrid mailbox',
        async () => ((await sinkFiles(hana())).length > 0 ? true : undefined),
        { timeoutMs: 120_000, intervalMs: 1_500 },
      );
      const msg = await sendJournal({
        messageId,
        sender: INLINE_SENDER,
        to: [hana()],
        original,
        what: 'c5',
      });
      const copy = await copyOf(
        hana(),
        msg.id,
        (c) => c.status === 'scanned' && c.policyState !== 'none',
      );
      expect(copy).toMatchObject({
        verdictAuthority: 'inline',
        inlineMessageId: inline.id,
        policyState: 'inline',
      });
      await sleep(15_000);
      expect(await detectRowsOf(fx.prisma, orgM.id, msg.id)).toEqual([]);
      expect(await outboxRowsOf(fx.prisma, orgM.id, COPY_DETECTED, msg.publicId)).toEqual([]);
      for (const kind of ['threat_detected', 'dlp_detected']) {
        expect(await alertRequestsFor(fx.prisma, orgM.id, kind, msg.publicId)).toEqual([]);
      }
      const hooks = await webhooksOf(msg.publicId);
      expect(hooks.filter((h) => h.eventType.startsWith('mailbox.'))).toEqual([]);
      expect(await simCallsNaming([simUsers.get(hana())!, hana()], mark)).toEqual([]);
      record(LOG, {
        case: 5,
        inline_verdict: inline.finalVerdict ?? null,
        copy_authority: copy.verdictAuthority,
        copy_policy_state: copy.policyState,
      });
    });

    it('(6) a tenant ALERT rule on a copy → one detect-mode policy_alert request → the detect-variant e-mail', async () => {
      const messageId = messageIdOf('c6');
      const original = syntheticEml({
        messageId,
        from: EXTERNAL_SENDER,
        to: [dana()],
        subject: subjectOf('c6 alert'),
        body: 'EXAMPLE parity case 6: a message for the watched recipient.',
      });
      await sim.deliver(dana(), original);
      const msg = await sendJournal({
        messageId,
        sender: EXTERNAL_SENDER,
        to: [dana()],
        original,
        what: 'c6',
      });
      await copyOf(dana(), msg.id, decided);
      const requests = await waitFor(
        'the detect-mode policy alert request',
        async () => {
          const rows = (
            await outboxRowsOf(fx.prisma, orgM.id, POLICY_NOTIFICATION_REQUESTED)
          ).filter((r) => (r.payload as { messageId?: string }).messageId === msg.id.toString());
          return rows.length > 0 ? rows : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 1_500 },
      );
      expect(requests).toHaveLength(1);
      expect(requests[0]!.payload).toMatchObject({
        kind: 'policy_alert',
        severity: 'warning',
        evaluationMode: 'detect',
      });
      const mail = await waitForAlertMail(
        'the detect-mode policy alert',
        (t) => t.includes('detected after delivery (API mode)') && t.includes(msg.publicId),
      );
      expect(mail).toContain(`/api-mode?tab=detections&message=${msg.publicId}`);
      expect(mail).toContain('Protection mode: API mode');
      for (const value of [dana(), EXTERNAL_SENDER, 'APIPARITY']) expect(mail).not.toContain(value);
      record(LOG, { case: 6, requests: requests.length });
    });

    it('(7) ownership through the bound provider tenant: a listed second domain → verified (provider_tenant) without TXT; an unlisted domain → failed check, still pending', async () => {
      const m = await admin();
      const create = async (label: string) => {
        const res = await m.post(
          '/domains',
          { name: fx.name(label), inboundEnabled: false, protectionMode: 'api' },
          idempotencyKey(),
        );
        expectStatus(res, 201, `POST /domains ${label}`);
        return (res.body as Json).id as string;
      };
      const own = await create('apiparity-own');
      const unlisted = await create('apiparity-unl');
      const detail = await m.get(`/domains/${own}`);
      expectStatus(detail, 200, 'GET /domains/{id}');
      expect(detail.body).toMatchObject({
        status: 'pending_verification',
        ownership: { method: null, providerCheckAvailable: true },
      });
      const requested: Record<string, Json> = {};
      for (const [label, id] of [
        ['own', own],
        ['unlisted', unlisted],
      ] as const) {
        const res = await m.post(`/domains/${id}/ownership/provider-check`, {}, idempotencyKey());
        expect(res.status, JSON.stringify(res.body)).toBe(202);
        expect(res.body).toMatchObject({ status: 'pending', connectionId: connM });
        requested[label] = res.body;
      }
      const verified = await waitFor(
        'the provider-proven domain verified',
        async () => {
          const res = await m.get(`/domains/${own}`);
          return res.status === 200 && (res.body as Json).status === 'verified'
            ? (res.body as Json)
            : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 2_000 },
      );
      expect(verified.ownership).toMatchObject({
        method: 'provider_tenant',
        providerCheck: { status: 'verified', result: 'verified', connectionId: connM },
      });
      const ownRow = await fx.prisma.domain.findFirstOrThrow({ where: { publicId: own } });
      expect(ownRow).toMatchObject({
        ownershipMethod: 'provider_tenant',
        verifiedName: ownRow.name,
      });
      const audit = await fx.prisma.auditLog.findFirstOrThrow({
        where: { organizationId: orgM.id, action: 'domain.verified', resourceId: own },
      });
      expect(audit.metadata).toMatchObject({ method: 'provider_tenant', connectionId: connM });
      // No TXT record was ever published for it: the only verification row that won is the
      // provider row.
      const rows = await fx.prisma.domainVerification.findMany({
        where: { organizationId: orgM.id, domainId: ownRow.id, status: 'verified' },
      });
      expect(rows.map((r) => r.method)).toEqual(['provider_tenant']);
      const failed = await waitFor(
        'the unlisted domain check failed',
        async () => {
          const row = await fx.prisma.domainVerification.findFirst({
            where: { id: BigInt(requested.unlisted.verificationId as string) },
          });
          return row && row.status === 'failed' ? row : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 2_000 },
      );
      expect(failed).toMatchObject({ providerResult: 'absent', lastError: 'absent' });
      expect(
        await fx.prisma.domain.findFirstOrThrow({ where: { publicId: unlisted } }),
      ).toMatchObject({ status: 'pending_verification', ownershipMethod: null });
      record(LOG, { case: 7, own: 'provider_tenant', unlisted: failed.providerResult });
    });

    it('(8) scope mailboxes excluding one mailbox → its copy recorded, not remediated (out_of_scope), not counted', async () => {
      const boxes = await Promise.all(
        [alex(), blake(), casey(), dana()].map((a) => mailboxByAddress(fx.prisma, orgM.id, a)),
      );
      const selected = boxes
        .filter((b) => b && b.primaryAddress !== casey())
        .map((b) => b!.publicId);
      const changed = await putScope(apiDom, { kind: 'mailboxes' }, selected);
      expect(changed).toMatchObject({ kind: 'mailboxes' });
      await waitFor(
        'scope evaluated (casey excluded)',
        async () => {
          const c = await mailboxByAddress(fx.prisma, orgM.id, casey());
          const a = await mailboxByAddress(fx.prisma, orgM.id, alex());
          return c?.scopeState === 'excluded' && a?.scopeState === 'in_scope' ? true : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 1_500 },
      );
      const view = await scopeOf(apiDom);
      expect(view).toMatchObject({ kind: 'mailboxes' });
      const messageId = messageIdOf('c8');
      const original = syntheticEml({
        messageId,
        from: BLOCKED_SENDER,
        to: [alex(), casey()],
        subject: subjectOf('c8 scope'),
        body: 'EXAMPLE parity case 8: a block-listed sender to two mailboxes.',
      });
      await sim.deliver(alex(), original);
      const caseyDelivered = await sim.deliver(casey(), original);
      const msg = await sendJournal({
        messageId,
        sender: BLOCKED_SENDER,
        to: [alex(), casey()],
        original,
        what: 'c8',
      });
      const inScope = await copyOf(alex(), msg.id, (c) => c.remediationState === 'remediated');
      const excluded = await copyOf(casey(), msg.id, decided);
      expect(inScope).toMatchObject({
        policyDisposition: 'reject',
        remediationAction: 'move_quarantine',
      });
      expect(excluded.remediationState).not.toBe('remediated');
      const [skip] = await actionsOfCopy(fx.prisma, orgM.id, excluded.id);
      expect(skip).toMatchObject({ status: 'skipped', reasonCode: 'out_of_scope' });
      expect((await simLocation(casey(), caseyDelivered.messageId)).folder?.wellKnownName).toBe(
        'inbox',
      );
      const [detected] = await outboxRowsOf(fx.prisma, orgM.id, COPY_DETECTED, msg.publicId);
      expect(detected!.payload).toMatchObject({
        copies: { counted: 1 },
        detectionIds: [inScope.publicId],
      });
      // Back to every mailbox (the remaining cases run with the default scope).
      await putScope(apiDom, { kind: 'all' });
      await waitFor(
        'scope evaluated (casey back in scope)',
        async () =>
          (await mailboxByAddress(fx.prisma, orgM.id, casey()))?.scopeState === 'in_scope'
            ? true
            : undefined,
        { timeoutMs: 120_000, intervalMs: 1_500 },
      );
      record(LOG, { case: 8, excluded: excluded.remediationState, counted: 1 });
    });

    it('(9) detect-only period ended: remind → one alert, mode kept; enforce → switched to enforce with audit and alert', async () => {
      const m = await admin();
      const view = await m.get('/api-mode/remediation-policy');
      expectStatus(view, 200, 'GET /api-mode/remediation-policy');
      const document = (view.body as Json).presets.p1.document;
      const until = new Date(Date.now() + 2 * 3_600_000).toISOString();
      const created: Record<'remind' | 'enforce', string> = { remind: '', enforce: '' };
      for (const [then, d] of [
        ['remind', remDom],
        ['enforce', enfDom],
      ] as const) {
        const res = await m.put(
          `/api-mode/remediation-policy/domains/${d.publicId}`,
          {
            mode: 'detect_only',
            document,
            detectOnly: { until, then },
            reason: `stack test: detect-only start (${then})`,
            expectedRowVersion: null,
          },
          idempotencyKey(),
        );
        expectStatus(res, 200, `PUT /api-mode/remediation-policy/domains/{id} (${then})`);
        const row = await fx.prisma.apiRemediationPolicy.findFirstOrThrow({
          where: { organizationId: orgM.id, domainId: d.id },
        });
        expect(row).toMatchObject({ mode: 'detect_only', detectOnlyThen: then });
        created[then] = row.publicId;
      }
      // Test seam: the period ends now (the api refuses an `until` earlier than now + 1 h).
      await fx.prisma.apiRemediationPolicy.updateMany({
        where: { organizationId: orgM.id, publicId: { in: Object.values(created) } },
        data: { detectOnlyUntil: new Date(Date.now() - 60_000) },
      });
      const done = await waitFor(
        'both detect-only periods handled by the health leader',
        async () => {
          const rows = await fx.prisma.apiRemediationPolicy.findMany({
            where: { organizationId: orgM.id, publicId: { in: Object.values(created) } },
          });
          return rows.length === 2 && rows.every((r) => r.detectOnlyNotifiedAt !== null)
            ? rows
            : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 1_500 },
      );
      const remind = done.find((r) => r.publicId === created.remind)!;
      const enforce = done.find((r) => r.publicId === created.enforce)!;
      expect(remind).toMatchObject({ mode: 'detect_only', detectOnlyThen: 'remind' });
      expect(enforce).toMatchObject({
        mode: 'enforce',
        detectOnlyUntil: null,
        detectOnlyThen: null,
      });
      expect(enforce.rowVersion).toBeGreaterThan(remind.rowVersion);
      const audits = await fx.prisma.auditLog.findMany({
        where: {
          organizationId: orgM.id,
          action: {
            in: ['api_mode.remediation_policy_auto_enforced', 'api_mode.detect_only_period_ended'],
          },
        },
      });
      expect(audits.map((a) => a.action).sort()).toEqual([
        'api_mode.detect_only_period_ended',
        'api_mode.remediation_policy_auto_enforced',
      ]);
      expect(
        audits.find((a) => a.action === 'api_mode.remediation_policy_auto_enforced')!.metadata,
      ).toMatchObject({ policyId: created.enforce, scope: 'domain' });
      const ended = (text: string, domain: FixtureDomain) =>
        text.includes('detect-only period ended') && text.includes(domain.name);
      await waitForAlertMail('the remind alert', (t) => ended(t, remDom));
      await waitForAlertMail('the enforce alert', (t) => ended(t, enfDom));
      // Further health ticks do not alert again (once per period, `detect_only_notified_at`).
      await sleep(12_000);
      // Exactly one e-mail per recipient (the first admin of the run holds `remediation:write`).
      const admins = (await alertMails((t) => ended(t, remDom))).length;
      expect(await alertMails((t) => ended(t, remDom), sessions[0]!.email)).toHaveLength(1);
      expect(
        await fx.prisma.apiRemediationPolicy.findFirstOrThrow({
          where: { publicId: created.remind },
        }),
      ).toMatchObject({ mode: 'detect_only', rowVersion: remind.rowVersion });
      record(LOG, { case: 9, remind: remind.mode, enforce: enforce.mode, recipients: admins });
    });

    it('(10b) onboarding after the first copy: received; protection-coverage totals and gaps', async () => {
      const after = await onboardingOf(apiDom);
      expect(after.firstCopy).toMatchObject({
        status: 'received',
        waitingSinceMinutes: null,
        hints: [],
        copy: {
          detectionId: shared.firstCopyPublicId,
          source: 'journal',
          policyState: 'evaluated',
        },
      });
      const res = await (await admin()).get('/api-mode/protection-coverage?limit=100');
      expectStatus(res, 200, 'GET /api-mode/protection-coverage');
      const cov = res.body as Json;
      expect(cov).toMatchObject({ entitled: true, nextCursor: null });
      const items = cov.items as Json[];
      const byId = new Map(items.map((i) => [i.domainId as string, i]));
      const count = (mode: string) => items.filter((i) => i.effectiveMode === mode).length;
      expect(cov.totals).toEqual({
        inline: count('inline'),
        api: count('api'),
        hybrid: count('hybrid'),
      });
      expect(cov.totals.hybrid).toBe(1);
      expect(cov.totals.api).toBeGreaterThanOrEqual(5);
      expect(byId.get(apiDom.publicId)).toMatchObject({
        effectiveMode: 'api',
        api: {
          applies: true,
          connection: { id: connM, mailboxAccess: 'active' },
          scope: 'all',
          policyEvaluation: true,
        },
      });
      expect(byId.get(hybDom.publicId)).toMatchObject({
        effectiveMode: 'hybrid',
        inline: { applies: true },
        api: { applies: true },
      });
      expect(byId.get(remDom.publicId)!.gaps).toContain('api_no_connection');
      expect(byId.get(remDom.publicId)!.gaps).toContain('api_detect_only');
      expect((cov.capabilities as Json[]).map((c) => c.code)).toEqual(
        expect.arrayContaining([
          'pre_delivery_blocking',
          'post_delivery_removal',
          'tenant_policies',
        ]),
      );
      expect(JSON.stringify(cov)).not.toContain('@');
      // Every webhook the run received passed the content assertion.
      const all = await receivedRequests(webhook!.path);
      const mailboxHooks = all.filter((r) => r.eventType.startsWith('mailbox.'));
      expect(mailboxHooks.length).toBeGreaterThanOrEqual(3);
      for (const r of all) {
        expect(parityPayloadProblems(r, orgM.publicId, forbidden), r.eventType).toEqual([]);
      }
      record(LOG, {
        case: '10b',
        totals: JSON.stringify(cov.totals),
        webhooks: all.length,
        mailbox_webhooks: mailboxHooks.length,
      });
    });
  },
);
