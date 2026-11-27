/* eslint-disable @typescript-eslint/no-unsafe-return -- predicates over the api's loose JSON */
import { eicar } from '@email-gateway/attachment-corpus';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import {
  ADAPTER_SUITE_ENV,
  MAILBOX_WORKER_SUITE_ENV,
  apiModeMessageId,
  apiModeRowCounts,
  apiModeStackGate,
  attachmentEml,
  copyEml,
  copyMessageIdHash,
  decodedMailText,
  mailboxByAddress,
  purgeApiModeRows,
  recreateService,
  restoreService,
  sim,
  simGoogleCustomer,
  simMicrosoftDirectory,
  waitForCopy,
} from './support/api-mode';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import {
  M365_SENDER,
  createSource,
  expectAccepted,
  intakeDomain,
  journalReport,
  mentions,
  originalMessage,
  queuedBouncesTo,
  sendIntake,
  waitForIntakeMessage,
} from './support/journal-intake';
import { clearSinkDomain, sinkFiles, sinkMessages, waitForSinkMessage } from './support/mail-sink';
import { record } from './support/messaging-stack';
import { deleteQueued, involving, listQueue } from './support/postfix';
import {
  GOOGLE_SCOPES,
  M365_PERMISSIONS,
  expectStatus,
  fake,
  guid,
  purgeProviderRows,
  runtimeSecret,
  serviceAccount,
  serviceEnv,
  waitForConnection,
  type Json,
} from './support/providers';
import { MAIL_SINK_HOST, organizationRef, sendInbound, sleep } from './support/routing';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import {
  createWebhook,
  pointPostfixNotifyAtRelaySink,
  receivedRequests,
  restorePostfixNotify,
  type CreatedWebhook,
} from './support/webhooks';

/**
 * Step API-1 API-mode protection end to end (docs/plan/steps/35-api-mode-protection.md §9.6,
 * ADR-0098–0100) on the live containers (Compose `apps` + `smtp-test` profiles): journal reports
 * sent with swaks from `provider-sender-m365` to the inbound Postfix (`postfix:25`) and the
 * smtp-adapter's journal LMTP listener; the email-worker scanning copies in detect mode; the
 * mailbox-worker (copies, feeds, inventory, health) against the TEST-ONLY idp-simulator (Graph
 * mail, Gmail and Directory endpoints, change notifications pushed to the api container's public
 * callback); tokens issued by 8.2's provider-fake through 8.2's token service; grants verified by
 * the integration-worker; alerts rendered by the notification-worker and relayed by
 * postfix-notify to notify-relay-sink.
 *
 * Postfix must reach the adapter CONTAINER (a stack switch, as for `journal-intake.test.ts`:
 * `SMTP_ADAPTER_HOST=smtp-adapter docker compose up -d --no-deps --force-recreate postfix
 * postfix-outbound`, restored from `.env` afterwards); the gate checks the reachability.
 *
 * Organizations `it-apimode-<suffix>-m` (Microsoft 365: an `api` domain, an `inline` domain
 * delivered to mail-sink and a domain whose MX points to the gateway) and `it-apimode-<suffix>-g`
 * (Google Workspace, organization mode `api` inherited by its domain) only — never organizations
 * 1, 2, 16946 or user 21416. Every tenant id, app secret and service-account key is generated at
 * run time; every row, object, Redis key, queue entry and sink file of the run is removed at the
 * end. Observed values are recorded as `[api-mode] …` lines for the verification record.
 */
const gate = await apiModeStackGate();
const fx = new SmtpFixtures();
const tenantM = guid();
const customerG = `C${fx.suffix}am`;
const appM = { clientId: guid(), secret: runtimeSecret() };
const saG = serviceAccount(`it-${fx.suffix}-apimode`);
const MAILBOX_ROLES = ['Mail.ReadWrite', 'User.Read.All'];
const GOOGLE_MAILBOX_SCOPES = [
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
];

interface Org {
  id: bigint;
  publicId: string;
  slug: string;
}
let orgM: Org;
let orgG: Org;
let apiDom: FixtureDomain;
let inlineDom: FixtureDomain;
let mxDom: FixtureDomain;
let gDom: FixtureDomain;
let connM = '';
let connG = '';
let sourceM: { id: string; address: string } | undefined;
let hook: CreatedWebhook | undefined;
let overridden = false;
let notifyPointed = false;
const sessions: ApiSession[] = [];
const cachedSessions = new Map<string, { session: ApiSession; at: number }>();
const evidence: Record<string, unknown> = {};

const addr = (local: string, d: FixtureDomain) => `${local}@${d.name}`;
const alex = () => addr('alex', apiDom);
const blake = () => addr('blake', apiDom);
const casey = () => addr('casey', apiDom);
const dana = () => addr('dana', apiDom);
const gina = () => addr('gina', gDom);
const gadmin = () => addr('admin', gDom);
const EXTERNAL_SENDER = 'sender@sender.example.test';
const partner = () => `partner@${fx.sinkDomain('apimode-ext')}`;

/** An organization admin (MFA) of a fixture organization; renewed before the 10-minute token ends. */
async function admin(o: Org): Promise<ApiSession> {
  const key = o.slug;
  const hit = cachedSessions.get(key);
  if (hit && Date.now() - hit.at < 8 * 60_000) return hit.session;
  const session = await apiSession(fx.prisma, { id: o.id, slug: o.slug }, 'organization_admin', {
    mfa: true,
  });
  sessions.push(session);
  cachedSessions.set(key, { session, at: Date.now() });
  return session;
}

async function fixtureOrganization(label: string, planId: bigint): Promise<Org> {
  const id = await fx.organization(`apimode-${label}`);
  const slug = `it-apimode-${fx.suffix}-${label}`;
  await fx.prisma.organization.update({
    where: { id },
    data: { planId, slug, name: `API mode ${label}` },
  });
  const ref = await organizationRef(fx, id);
  return { id, publicId: ref.publicId, slug };
}

const mailboxIdOf = (o: Org, address: string) => () =>
  mailboxByAddress(fx.prisma, o.id, address).then((m) => m?.id);

async function connection(o: Org, id: string): Promise<Json> {
  const res = await (await admin(o)).get(`/api-mode/connections/${id}`);
  expectStatus(res, 200, `GET /api-mode/connections/${id}`);
  return res.body as Json;
}

function waitForApiConnection(
  o: Org,
  id: string,
  what: string,
  predicate: (c: Json) => boolean,
  timeoutMs = 180_000,
): Promise<Json> {
  return waitFor(
    `API-mode connection ${what}`,
    async () => {
      const c = await connection(o, id);
      return predicate(c) ? c : undefined;
    },
    { timeoutMs, intervalMs: 2_000 },
  );
}

/** The `api_mode_connections` row of an 8.2 connection (writer). */
async function apiConnectionRow(providerConnectionPublicId: string) {
  const pc = await fx.prisma.providerConnection.findFirstOrThrow({
    where: { publicId: providerConnectionPublicId },
    select: { id: true },
  });
  return fx.prisma.apiModeConnection.findUnique({ where: { providerConnectionId: pc.id } });
}

/** A journal report of `original` for the M365 intake source, sent from provider-sender-m365. */
async function sendJournal(o: {
  messageId: string;
  to: readonly string[];
  subject: string;
  body?: string;
  original?: string;
}): Promise<void> {
  const original =
    o.original ??
    originalMessage({
      messageId: `<${o.messageId}>`,
      from: EXTERNAL_SENDER,
      to: o.to,
      subject: o.subject,
      body: o.body ?? 'EXAMPLE API-mode journal copy body.',
    });
  const sent = await sendIntake({
    service: M365_SENDER,
    to: [sourceM!.address],
    data: journalReport({
      intakeAddress: sourceM!.address,
      original,
      sender: EXTERNAL_SENDER,
      to: o.to,
      messageId: `<${o.messageId}>`,
      tenantIds: [tenantM],
    }),
  });
  expectAccepted(sent, `journal report ${o.subject}`);
}

async function linkAndBind(o: Org, id: string, domain: FixtureDomain): Promise<void> {
  const session = await admin(o);
  expectStatus(
    await session.put(
      `/provider-connections/${id}/domains`,
      { domainIds: [domain.publicId] },
      idempotencyKey(),
    ),
    200,
    'PUT …/domains',
  );
  await waitForConnection(session, id, 'status active (bound)', (c) => c.status === 'active');
}

async function grantStatus(o: Org, id: string, profile: string): Promise<string | undefined> {
  const res = await (await admin(o)).get(`/provider-connections/${id}`);
  expectStatus(res, 200, 'GET /provider-connections/{id}');
  return ((res.body as Json).grants as Json[]).find((g) => g.profile === profile)?.status;
}

async function putSettings(
  o: Org,
  id: string,
  change: { feedsEnabled: boolean; feedMode?: 'poll' | 'notify' },
): Promise<Json> {
  const current = await connection(o, id);
  const res = await (
    await admin(o)
  ).put(
    `/api-mode/connections/${id}/settings`,
    { ...change, expectedRowVersion: current.rowVersion },
    idempotencyKey(),
  );
  expectStatus(res, 200, 'PUT /api-mode/connections/{id}/settings');
  return res.body as Json;
}

async function counterSums(apiConnectionId: bigint) {
  const rows = await fx.prisma.apiModeCounter.findMany({ where: { apiConnectionId } });
  const sum = (k: 'journalCopies' | 'feedCopies' | 'duplicates' | 'throttled429' | 'lagCount') =>
    rows.reduce((n, r) => n + r[k], 0);
  return {
    journalCopies: sum('journalCopies'),
    feedCopies: sum('feedCopies'),
    duplicates: sum('duplicates'),
    throttled429: sum('throttled429'),
    lagCount: sum('lagCount'),
    providerRequests: rows.reduce((n, r) => n + r.providerRequests, 0),
  };
}

beforeAll(async () => {
  assertStackReady(gate);
  overridden = true;
  await recreateService('mailbox-worker', MAILBOX_WORKER_SUITE_ENV);
  await recreateService('smtp-adapter', ADAPTER_SUITE_ENV);
  await pointPostfixNotifyAtRelaySink();
  notifyPointed = true;

  const enterprise = await fx.prisma.organizationPlan.findFirstOrThrow({
    where: { code: 'enterprise' },
    select: { id: true },
  });
  orgM = await fixtureOrganization('m', enterprise.id);
  orgG = await fixtureOrganization('g', enterprise.id);
  // API mode, journal intake WITHOUT archiving enabled (D6: API mode alone entitles the source).
  for (const o of [orgM, orgG]) {
    await fx.feature(o.id, 'api_mode_protection', true);
    await fx.feature(o.id, 'journal_intake', true);
  }
  await fx.feature(orgM.id, 'webhooks', true);
  apiDom = await fx.domain(orgM.id, 'apimode-api', { inboundEnabled: false });
  inlineDom = await fx.domain(orgM.id, 'apimode-inline');
  await fx.destinations(inlineDom, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  mxDom = await fx.domain(orgM.id, 'apimode-mx');
  await fx.prisma.domainMxRecord.create({
    data: {
      organizationId: orgM.id,
      domainId: mxDom.id,
      priority: 10,
      host: 'mx1.gateway.example.test',
      pointsToGateway: true,
      lastSeenAt: new Date(),
    },
  });
  gDom = await fx.domain(orgG.id, 'apimode-goog', { inboundEnabled: false });

  // Modes through the api (audited; case 8 reads the rows): the M domain explicitly `api`, the
  // G organization `api` (its domain inherits).
  const m = await admin(orgM);
  const g = await admin(orgG);
  const domainMode = await m.put(
    `/domains/${apiDom.publicId}/protection-mode`,
    { mode: 'api', reason: 'stack test: API-mode domain without an MX change' },
    idempotencyKey(),
  );
  expectStatus(domainMode, 200, 'PUT /domains/{id}/protection-mode');
  expect((domainMode.body as Json).protectionMode).toMatchObject({
    configured: 'api',
    effective: 'api',
    inherited: false,
  });
  const orgMode = await g.put(
    `/organizations/${orgG.publicId}/protection-mode`,
    { mode: 'api', reason: 'stack test: organization default API mode' },
    idempotencyKey(),
  );
  expectStatus(orgMode, 200, 'PUT /organizations/{id}/protection-mode');
  expect((orgMode.body as Json).inheritingDomains).toBe(1);

  // The provider side, generated now: Microsoft tenant + customer app (mail flow and mailbox
  // permissions), Google customer + service account delegated for mail flow and mailbox access.
  await fake.addMicrosoftTenant({
    tenantId: tenantM,
    displayName: `API mode ${fx.suffix}`,
    domains: [{ name: apiDom.name, isVerified: true, isDefault: true, mxHost: null }],
  });
  await fake.addMicrosoftApp({
    clientId: appM.clientId,
    secret: appM.secret,
    homeTenantId: tenantM,
    requiredRoles: [...M365_PERMISSIONS, ...MAILBOX_ROLES],
  });
  await fake.consent(tenantM, appM.clientId, [...M365_PERMISSIONS, ...MAILBOX_ROLES]);
  await fake.addGoogleCustomer({
    customerId: customerG,
    primaryDomain: gDom.name,
    organizationName: `API mode G ${fx.suffix}`,
    domains: [{ domainName: gDom.name, verified: true, isPrimary: true }],
    admins: [gadmin()],
  });
  await fake.addGoogleServiceAccount({
    clientEmail: saG.clientEmail,
    clientId: saG.clientId,
    keyId: saG.keyId,
    publicKeyPem: saG.publicKeyPem,
  });
  await fake.delegate(customerG, saG.clientId, [...GOOGLE_SCOPES, ...GOOGLE_MAILBOX_SCOPES]);

  // The mailbox APIs (idp-simulator, stack mode): this run's directory and customer only.
  await sim.reset();
  await sim.dataset({
    microsoft: {
      directories: [
        simMicrosoftDirectory(
          tenantM,
          [apiDom.name],
          [
            { id: guid(), address: alex() },
            { id: guid(), address: blake() },
            { id: guid(), address: casey() },
            { id: guid(), address: dana(), enabled: false },
          ],
        ),
      ],
    },
    google: {
      customers: [
        simGoogleCustomer(
          customerG,
          [gDom.name],
          [
            { id: `1${fx.suffix}01`, address: gadmin(), admin: true },
            { id: `1${fx.suffix}02`, address: gina() },
          ],
        ),
      ],
    },
  });

  // 8.2 connections bound through provider-fake (mail-flow grants verified by the
  // integration-worker), then the M365 journal intake source (API mode entitles it, D6).
  const createdM = await m.post(
    '/provider-connections',
    { provider: 'microsoft_365', displayName: `EXAMPLE API mode ${fx.suffix}` },
    idempotencyKey(),
  );
  expectStatus(createdM, 201, 'POST /provider-connections (M)');
  connM = (createdM.body as Json).id as string;
  expectStatus(
    await m.post(
      `/provider-connections/${connM}/grants`,
      { profile: 'm365.mail_flow', authMethod: 'customer_app_secret' },
      idempotencyKey(),
    ),
    201,
    'POST …/grants m365.mail_flow',
  );
  expectStatus(
    await m.put(
      `/provider-connections/${connM}/grants/m365.mail_flow/credentials`,
      { tenantId: tenantM, clientId: appM.clientId, clientSecret: appM.secret },
      idempotencyKey(),
    ),
    200,
    'PUT …/credentials m365.mail_flow',
  );
  await waitForConnection(m, connM, 'mail-flow grant active', (c) =>
    c.grants.some((x: Json) => x.profile === 'm365.mail_flow' && x.status === 'active'),
  );
  await linkAndBind(orgM, connM, apiDom);

  const createdG = await g.post(
    '/provider-connections',
    { provider: 'google_workspace', displayName: `EXAMPLE API mode G ${fx.suffix}` },
    idempotencyKey(),
  );
  expectStatus(createdG, 201, 'POST /provider-connections (G)');
  connG = (createdG.body as Json).id as string;
  expectStatus(
    await g.post(
      `/provider-connections/${connG}/grants`,
      { profile: 'google.mail_flow', authMethod: 'customer_service_account' },
      idempotencyKey(),
    ),
    201,
    'POST …/grants google.mail_flow',
  );
  const tokenUri = await serviceEnv('api', 'PROVIDER_GOOGLE_TOKEN_URL');
  expectStatus(
    await g.put(
      `/provider-connections/${connG}/grants/google.mail_flow/credentials`,
      { serviceAccountKey: saG.key(tokenUri), subjectEmail: gadmin() },
      idempotencyKey(),
    ),
    200,
    'PUT …/credentials google.mail_flow',
  );
  await waitForConnection(g, connG, 'mail-flow grant active', (c) =>
    c.grants.some((x: Json) => x.profile === 'google.mail_flow' && x.status === 'active'),
  );
  await linkAndBind(orgG, connG, gDom);

  sourceM = await createSource(m, {
    kind: 'microsoft_365_journal',
    displayName: 'it-apimode M365 journal',
    providerConnectionId: connM,
  });
  expect(sourceM.address.endsWith(`@${intakeDomain()}`)).toBe(true);
  hook = await createWebhook(m, {
    name: `it-apimode ${fx.suffix}`,
    path: `it-apimode-${fx.suffix}`,
    eventTypes: ['email.received'],
  });
  record('api-mode', {
    organizations: 2,
    domains: 4,
    connections: 2,
    simulator_users: 6,
  });
}, 900_000);

afterAll(async () => {
  if (gate.skip) return;
  const ids = [orgM, orgG].filter(Boolean).map((o) => o.id);
  if (hook && orgM) {
    await (
      await admin(orgM)
    )
      .delete(`/webhooks/${hook.id}`, idempotencyKey())
      .catch(() => undefined);
  }
  await sim.reset().catch(() => undefined);
  // Stop the worker first so no claim or flush writes a row behind the purge.
  if (overridden) await restoreService('mailbox-worker').catch(() => undefined);
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
  await fx.prisma.domainMxRecord.deleteMany({ where });
  await fx.prisma.auditLog.deleteMany({ where });
  for (const session of sessions) await session.remove().catch(() => undefined);
  const names = [apiDom, inlineDom, mxDom, gDom].filter(Boolean).map((d) => d.name);
  for (const service of ['postfix', 'postfix-outbound'] as const) {
    const queued = involving(await listQueue(service), [
      ...names,
      intakeDomain(),
      fx.sinkDomain('apimode-ext'),
    ]);
    await deleteQueued(
      service,
      queued.map((q) => q.queue_id),
    );
  }
  for (const d of [...names, fx.sinkDomain('apimode-ext')]) {
    await clearSinkDomain(d, 'all').catch(() => undefined);
  }
  await clearSinkDomain('routing.integration.test', 'notify-relay-sink').catch(() => undefined);
  const { PrismaClient } = await import('@email-gateway/database');
  const check = new PrismaClient({ datasourceUrl: process.env.DATABASE_URL });
  await fx.cleanup();
  if (notifyPointed) await restorePostfixNotify();
  if (overridden) await restoreService('smtp-adapter');
  try {
    const counts = await apiModeRowCounts(check, ids);
    record('api-mode', { cleanup: JSON.stringify(counts) });
    expect(counts).toEqual({
      connections: 0,
      mailboxes: 0,
      addresses: 0,
      copies: 0,
      dedupeKeys: 0,
      counters: 0,
    });
    expect(await check.organization.count({ where: { id: { in: ids } } })).toBe(0);
    expect(await check.providerConnection.count({ where })).toBe(0);
  } finally {
    await check.$disconnect();
  }
}, 900_000);

describe.skipIf(gate.skip)(
  'API-mode protection stack (step API-1 §9.6)',
  { timeout: 900_000 },
  () => {
    it('(1) api domain + bound M365 connection + journal source: the journal copy is scanned in detect mode, one copy per api-mode recipient, never delivered', async () => {
      const messageId = apiModeMessageId('j1');
      const since = Date.now();
      await sendJournal({
        messageId,
        // Two api-mode mailboxes, an inline domain of the same organization, an external partner.
        to: [alex(), blake(), addr('ina', inlineDom), partner()],
        subject: `APIMODE ${fx.suffix} journal`,
      });
      const msg = await waitForIntakeMessage(fx.prisma, orgM.id, `<${messageId}>`, 'journaled');
      const intake = await fx.prisma.journalIntakeMessage.findFirstOrThrow({
        where: { messageId: msg.id, receivedAt: msg.receivedAt },
      });
      // Detect mode without archiving: scan_requested comes from API mode alone (D6).
      expect(intake.scanRequested).toBe(true);
      const copyAlex = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, alex()),
        messageId,
        (c) => c.status === 'scanned',
      );
      const copyBlake = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, blake()),
        messageId,
        (c) => c.status === 'scanned',
      );
      for (const copy of [copyAlex, copyBlake]) {
        expect(copy.source).toBe('journal');
        expect(copy.seenJournal).toBe(true);
        expect(copy.seenApi).toBe(false);
        expect(copy.direction).toBe('inbound');
        expect(copy.messageId).toBe(msg.id);
        expect(copy.verdict).not.toBeNull();
        expect(copy.riskScore).not.toBeNull();
        expect(copy.lagMs).not.toBeNull();
        expect(copy.messageIdHash).toBe(copyMessageIdHash(orgM.id, messageId));
      }
      // Only the api-mode recipients have rows (inline domain and external partner: none).
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, messageId: msg.id },
        }),
      ).toBe(2);
      const alexMailbox = await mailboxByAddress(fx.prisma, orgM.id, alex());
      expect(alexMailbox?.status).toBe('discovered');
      expect(alexMailbox?.journalLastSeenAt).not.toBeNull();
      // Never delivered, evaluated, bounced or announced (N1).
      expect(await fx.prisma.emailDelivery.count({ where: { messageId: msg.id } })).toBe(0);
      expect(await fx.prisma.policyExecutionLog.count({ where: { messageId: msg.id } })).toBe(0);
      expect(await sinkFiles(partner())).toEqual([]);
      expect(await sinkFiles(addr('ina', inlineDom))).toEqual([]);
      expect(await queuedBouncesTo(['journal-agent@journal-source.test'])).toBe(0);
      const identity = await fx.prisma.messageIdentity.findUniqueOrThrow({
        where: { id: msg.id },
        select: { publicId: true },
      });
      await sleep(5_000);
      expect(mentions(await receivedRequests(hook!.path), [identity.publicId])).toBe(0);
      // The detections list shows both copies (masked sender, subject withheld).
      const detections = await (await admin(orgM)).get('/api-mode/detections?limit=100');
      expectStatus(detections, 200, 'GET /api-mode/detections');
      const listed = ((detections.body as Json).data as Json[]).filter((d) =>
        [alex(), blake()].includes(d.mailboxAddress),
      );
      expect(listed.length).toBeGreaterThanOrEqual(2);
      expect(listed.every((d) => d.subject === null && d.source === 'journal')).toBe(true);
      evidence.case1 = {
        verdict: copyAlex.verdict,
        risk: copyAlex.riskScore,
        lag_ms: copyAlex.lagMs,
        basis: copyAlex.deliveredBasis,
      };
      record('api-mode', {
        case: 1,
        copies: 2,
        verdict: copyAlex.verdict,
        risk_score: copyAlex.riskScore,
        lag_ms: copyAlex.lagMs,
        delivered_basis: copyAlex.deliveredBasis,
        seconds: Math.round((Date.now() - since) / 1000),
      });
    });

    it('(1b) EICAR journal copy → malware verdict; deliveries and sinks stay empty', async () => {
      const messageId = apiModeMessageId('eicar');
      await sendJournal({
        messageId,
        to: [alex()],
        subject: `APIMODE ${fx.suffix} eicar`,
        original: attachmentEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [alex()],
          subject: `APIMODE ${fx.suffix} eicar`,
          filename: 'eicar.com',
          content: eicar(),
        }),
      });
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, alex()),
        messageId,
        (c) => c.status === 'scanned' || c.status === 'scan_failed',
      );
      record('api-mode', { case: '1b', eicar_status: copy.status, eicar_verdict: copy.verdict });
      expect(copy.status).toBe('scanned');
      expect(copy.verdict).toBe('malware');
      expect(await fx.prisma.emailDelivery.count({ where: { messageId: copy.messageId } })).toBe(0);
    });

    it('(2) mailbox-access grant (customer app via provider-fake) verified by the integration-worker; inventory from the simulator → coverage totals', async () => {
      const m = await admin(orgM);
      expectStatus(
        await m.post(
          `/provider-connections/${connM}/grants`,
          { profile: 'm365.mailbox_remediation', authMethod: 'customer_app_secret' },
          idempotencyKey(),
        ),
        201,
        'POST …/grants m365.mailbox_remediation',
      );
      const creds = await m.put(
        `/provider-connections/${connM}/grants/m365.mailbox_remediation/credentials`,
        { tenantId: tenantM, clientId: appM.clientId, clientSecret: appM.secret },
        idempotencyKey(),
      );
      expectStatus(creds, 200, 'PUT …/credentials m365.mailbox_remediation');
      expect(JSON.stringify(creds.body)).not.toContain(appM.secret);
      const verified = await waitForConnection(m, connM, 'mailbox grant active', (c) =>
        c.grants.some(
          (x: Json) => x.profile === 'm365.mailbox_remediation' && x.status === 'active',
        ),
      );
      const grant = (verified.grants as Json[]).find(
        (x) => x.profile === 'm365.mailbox_remediation',
      );
      expect(grant.observedPermissions).toEqual(expect.arrayContaining(MAILBOX_ROLES));
      // The mail-flow grant and the binding are unchanged (separate purpose, ADR-0099).
      expect(verified.status).toBe('active');
      const sync = await m.post(
        `/api-mode/connections/${connM}/inventory-sync`,
        {},
        idempotencyKey(),
      );
      expectStatus(sync, 202, 'POST /api-mode/connections/{id}/inventory-sync');
      const synced = await waitForApiConnection(
        orgM,
        connM,
        'inventory ok with coverage totals',
        (c) =>
          c.inventoryStatus === 'ok' &&
          c.mailboxesTotal === 3 &&
          c.coverage.total === 3 &&
          c.coverage.covered === 2 &&
          c.coverage.gap === 1,
      );
      expect(synced.grant).toMatchObject({ profile: 'm365.mailbox_remediation', status: 'active' });
      // The journal-discovered mailboxes were adopted (provider ids), the disabled user is out of scope.
      const alexMailbox = await mailboxByAddress(fx.prisma, orgM.id, alex());
      expect(alexMailbox).toMatchObject({ status: 'active', coverageState: 'covered' });
      expect(alexMailbox?.providerUserId).not.toBeNull();
      expect(await mailboxByAddress(fx.prisma, orgM.id, casey())).toMatchObject({
        status: 'active',
        coverageState: 'gap',
      });
      expect(await mailboxByAddress(fx.prisma, orgM.id, dana())).toMatchObject({
        status: 'disabled',
        coverageState: 'out_of_scope',
      });
      const usersCalls = await sim.calls({ simulator: 'graph', path: '/v1.0/users' });
      expect(usersCalls.some((c) => c.status === 200)).toBe(true);
      record('api-mode', {
        case: 2,
        mailboxes_total: synced.mailboxesTotal,
        covered: synced.coverage.covered,
        gap: synced.coverage.gap,
        percent: synced.coverage.percent,
        health: synced.health.status,
      });
    });

    it('(3) feeds notify: subscription with validation handshake through the api; a delivered message → notification → delta → MIME fetched → scanned → copy source graph', async () => {
      await putSettings(orgM, connM, { feedsEnabled: true, feedMode: 'notify' });
      const feedMailboxes = await waitFor(
        'every in-scope mailbox fed with a subscription',
        async () => {
          const rows = await fx.prisma.apiMailbox.findMany({
            where: { organizationId: orgM.id, status: 'active' },
          });
          return rows.length === 3 &&
            rows.every((r) => r.feedStatus === 'active' && r.subscriptionId !== null)
            ? rows
            : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 2_000 },
      );
      expect(feedMailboxes.every((r) => r.clientStateHash?.length === 64)).toBe(true);
      const subscriptions = await sim.subscriptions();
      expect(subscriptions.filter((s) => s.hasClientState)).toHaveLength(3);
      expect(subscriptions[0]!.notificationUrl).toBe(process.env.API_MODE_GRAPH_NOTIFICATION_URL);
      const validations = (await sim.notifications()).filter((n) => n.kind === 'validation');
      expect(validations.length).toBeGreaterThanOrEqual(3);
      expect(validations.every((n) => n.ok && n.status === 200)).toBe(true);
      // Initialization did not fetch existing content (no backfill, N6).
      expect(
        (await sim.calls({ simulator: 'graph' })).some((c) => c.path.endsWith('/$value')),
      ).toBe(false);

      const messageId = apiModeMessageId('feed');
      const since = Date.now();
      const delivered = await sim.deliver(
        casey(),
        copyEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [casey()],
          subject: `APIMODE ${fx.suffix} feed`,
        }),
      );
      expect(delivered.notifications).toHaveLength(1);
      expect(delivered.notifications[0]!.status).toBe(202);
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, casey()),
        messageId,
        (c) => c.status === 'scanned',
      );
      expect(copy).toMatchObject({
        source: 'graph',
        seenApi: true,
        seenJournal: false,
        providerMessageId: delivered.messageId,
        deliveredBasis: 'graph_received',
      });
      expect(copy.verdict).not.toBeNull();
      expect(copy.lagMs).not.toBeNull();
      const registry = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { id: copy.messageId, receivedAt: copy.receivedAt },
        select: { ingestSource: true, status: true, emlObjectKey: true },
      });
      expect(registry).toMatchObject({ ingestSource: 'mailbox_api', status: 'journaled' });
      expect(registry.emlObjectKey).toMatch(new RegExp(`^org/${orgM.id.toString()}/eml/`));
      expect(await fx.object(registry.emlObjectKey)).toBeTruthy();
      expect(await fx.prisma.emailDelivery.count({ where: { messageId: copy.messageId } })).toBe(0);
      const fetched = await sim.calls({ simulator: 'graph' });
      expect(
        fetched.some((c) => c.path.includes(delivered.messageId) && c.path.endsWith('/$value')),
      ).toBe(true);
      record('api-mode', {
        case: 3,
        subscriptions: subscriptions.length,
        notification_status: delivered.notifications[0]!.status,
        verdict: copy.verdict,
        lag_ms: copy.lagMs,
        seconds: Math.round((Date.now() - since) / 1000),
      });
    });

    it('(3b) GTUBE synthetic copy through the feed → spam verdict (Postfix refuses GTUBE in session, 8.6)', async () => {
      const messageId = apiModeMessageId('gtube');
      const gtube = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
      await sim.deliver(
        blake(),
        copyEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [blake()],
          subject: `APIMODE ${fx.suffix} gtube`,
          body: gtube,
        }),
      );
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, blake()),
        messageId,
        (c) => c.status === 'scanned',
      );
      record('api-mode', { case: '3b', gtube_verdict: copy.verdict, risk_score: copy.riskScore });
      expect(copy.source).toBe('graph');
      expect(copy.verdict).toBe('spam');
      expect(await fx.prisma.emailDelivery.count({ where: { messageId: copy.messageId } })).toBe(0);
    });

    it('(4) dedupe both orders: journal then feed → one copy and no MIME fetch; feed then journal → seen_journal', async () => {
      // Journal first (alex).
      const first = apiModeMessageId('dedupe-j');
      await sendJournal({
        messageId: first,
        to: [alex()],
        subject: `APIMODE ${fx.suffix} dedupe j`,
      });
      const journalCopy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, alex()),
        first,
        (c) => c.status === 'scanned',
      );
      const delivered = await sim.deliver(
        alex(),
        copyEml({ messageId: first, from: EXTERNAL_SENDER, to: [alex()], subject: 'dedupe j' }),
      );
      const marked = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, alex()),
        first,
        (c) => c.seenApi && c.providerMessageId === delivered.messageId,
      );
      expect(marked.id).toBe(journalCopy.id);
      expect(marked.source).toBe('journal');
      const hashFirst = copyMessageIdHash(orgM.id, first);
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, mailboxId: marked.mailboxId, messageIdHash: hashFirst },
        }),
      ).toBe(1);
      const calls = await sim.calls({ simulator: 'graph' });
      // No content fetch of the provider copy. (Since step API-2 the P1 policy may tag the
      // copy — the synthetic body scans `suspicious` — so remediation calls may name the id.)
      expect(
        calls.some((c) => c.path.includes(delivered.messageId) && c.path.endsWith('/$value')),
      ).toBe(false);
      expect(
        await fx.prisma.emailMessage.count({
          where: {
            organizationId: orgM.id,
            internetMessageId: `<${first}>`,
            ingestSource: 'mailbox_api',
          },
        }),
      ).toBe(0);

      // Feed first (blake), then the journal copy of the same Message-ID.
      const second = apiModeMessageId('dedupe-f');
      const fed = await sim.deliver(
        blake(),
        copyEml({ messageId: second, from: EXTERNAL_SENDER, to: [blake()], subject: 'dedupe f' }),
      );
      const feedCopy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, blake()),
        second,
        (c) => c.status === 'scanned' && c.source === 'graph',
      );
      expect(feedCopy.providerMessageId).toBe(fed.messageId);
      await sendJournal({
        messageId: second,
        to: [blake()],
        subject: `APIMODE ${fx.suffix} dedupe f`,
      });
      await waitForIntakeMessage(fx.prisma, orgM.id, `<${second}>`, 'journaled');
      const seen = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, blake()),
        second,
        (c) => c.seenJournal,
      );
      expect(seen.id).toBe(feedCopy.id);
      expect(seen.source).toBe('graph');
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: {
            organizationId: orgM.id,
            mailboxId: seen.mailboxId,
            messageIdHash: copyMessageIdHash(orgM.id, second),
          },
        }),
      ).toBe(1);
      record('api-mode', { case: 4, journal_first_fetches: 0, feed_first_rows: 1 });
    });

    it('(5) Gmail history path with a Google connection: delegated mailbox grant, inventory, history poll, raw fetch, copy source gmail', async () => {
      const g = await admin(orgG);
      expectStatus(
        await g.post(
          `/provider-connections/${connG}/grants`,
          { profile: 'google.mailbox_remediation', authMethod: 'customer_service_account' },
          idempotencyKey(),
        ),
        201,
        'POST …/grants google.mailbox_remediation',
      );
      const tokenUri = await serviceEnv('api', 'PROVIDER_GOOGLE_TOKEN_URL');
      expectStatus(
        await g.put(
          `/provider-connections/${connG}/grants/google.mailbox_remediation/credentials`,
          { serviceAccountKey: saG.key(tokenUri), subjectEmail: gadmin() },
          idempotencyKey(),
        ),
        200,
        'PUT …/credentials google.mailbox_remediation',
      );
      await waitForConnection(g, connG, 'Google mailbox grant active', (c) =>
        c.grants.some(
          (x: Json) => x.profile === 'google.mailbox_remediation' && x.status === 'active',
        ),
      );
      expectStatus(
        await g.post(`/api-mode/connections/${connG}/inventory-sync`, {}, idempotencyKey()),
        202,
        'inventory-sync (G)',
      );
      await waitForApiConnection(
        orgG,
        connG,
        'Google inventory ok',
        (c) => c.inventoryStatus === 'ok' && c.mailboxesTotal === 2,
      );
      const settings = await putSettings(orgG, connG, { feedsEnabled: true });
      expect(settings.feedMode).toBe('poll');
      await waitFor(
        'Gmail feeds initialized',
        async () => {
          const rows = await fx.prisma.apiMailbox.findMany({
            where: { organizationId: orgG.id, status: 'active' },
          });
          return rows.length === 2 && rows.every((r) => r.feedStatus === 'active')
            ? rows
            : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 2_000 },
      );
      const messageId = apiModeMessageId('gmail');
      const delivered = await sim.deliver(
        gina(),
        copyEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [gina()],
          subject: `APIMODE ${fx.suffix} gmail`,
        }),
      );
      const copy = await waitForCopy(
        fx.prisma,
        orgG.id,
        mailboxIdOf(orgG, gina()),
        messageId,
        (c) => c.status === 'scanned',
      );
      expect(copy).toMatchObject({
        source: 'gmail',
        seenApi: true,
        providerMessageId: delivered.messageId,
        deliveredBasis: 'gmail_internal',
      });
      const gmailCalls = await sim.calls({ simulator: 'gmail' });
      expect(gmailCalls.some((c) => c.path.endsWith('/history') && c.status === 200)).toBe(true);
      expect(
        gmailCalls.some(
          (c) => c.path.includes(delivered.messageId) && /format=raw/.test(c.query ?? ''),
        ),
      ).toBe(true);
      record('api-mode', { case: 5, verdict: copy.verdict, lag_ms: copy.lagMs });
    });

    it('(6) scripted 429 Retry-After: 2 → the connection pauses, the sync is retried after the pause; counters and throttled_until', async () => {
      const row = await apiConnectionRow(connM);
      await sim.inject({ family: 'graph', status: 429, retryAfter: '2', times: 1 });
      const messageId = apiModeMessageId('throttle');
      await sim.deliver(
        casey(),
        copyEml({ messageId, from: EXTERNAL_SENDER, to: [casey()], subject: 'throttled' }),
      );
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, casey()),
        messageId,
        (c) => c.status === 'scanned',
      );
      expect(copy.source).toBe('graph');
      const throttledCalls = (await sim.calls({ simulator: 'graph' })).filter(
        (c) => c.status === 429,
      );
      expect(throttledCalls.length).toBeGreaterThanOrEqual(1);
      const after = await fx.prisma.apiModeConnection.findUniqueOrThrow({ where: { id: row!.id } });
      expect(after.throttledUntil).not.toBeNull();
      const counted = await waitFor(
        'throttled_429 counted',
        async () => {
          const sums = await counterSums(row!.id);
          return sums.throttled429 >= 1 ? sums : undefined;
        },
        { timeoutMs: 60_000, intervalMs: 2_000 },
      );
      record('api-mode', {
        case: 6,
        throttled_429: counted.throttled429,
        throttled_until_set: after.throttledUntil !== null,
        provider_requests: counted.providerRequests,
      });
    });

    it('(7) grant revoked → feeds stop, health failing, alert email at notify-relay-sink; journal detection continues', async () => {
      const m = await admin(orgM);
      const row = await apiConnectionRow(connM);
      // The 24 h alert window may hold an earlier degraded alert of this connection (coverage gap
      // before the feeds): reset it so the failing transition is alerted again (test seam only).
      await fx.prisma.apiModeConnection.update({
        where: { id: row!.id },
        data: { healthAlertedAt: null },
      });
      await fx.prisma.notificationAlertWindow.deleteMany({ where: { organizationId: orgM.id } });
      const revoked = await m.delete(
        `/provider-connections/${connM}/grants/m365.mailbox_remediation`,
        idempotencyKey(),
      );
      expectStatus(revoked, 200, 'DELETE …/grants/m365.mailbox_remediation');
      expect(await grantStatus(orgM, connM, 'm365.mailbox_remediation')).toBe('revoked');
      // Mail flow is untouched: the mail-flow grant and the binding stay.
      expect(await grantStatus(orgM, connM, 'm365.mail_flow')).toBe('active');
      // The worker applies a revocation at the next claim of a mailbox of the connection (D4).
      // In `notify` mode that is the next change notification (or the 1 h safety poll): a new
      // message to alex wakes the feed; the worker re-checks the grant and makes no provider call.
      const graphCallsBefore = (await sim.calls({ simulator: 'graph' })).length;
      await sim.deliver(
        alex(),
        copyEml({
          messageId: apiModeMessageId('wake'),
          from: EXTERNAL_SENDER,
          to: [alex()],
          subject: 'wake after revoke',
        }),
      );
      await waitFor(
        'feeds revoked and subscriptions cleared',
        async () => {
          const rows = await fx.prisma.apiMailbox.findMany({
            where: { organizationId: orgM.id, status: 'active' },
          });
          return rows.length === 3 &&
            rows.every(
              (r) =>
                r.feedStatus === 'revoked' && r.subscriptionId === null && r.feedCursor === null,
            )
            ? rows
            : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 2_000 },
      );
      // No content was fetched after the revocation (the wake-up message stays unread).
      const graphCallsAfter = (await sim.calls({ simulator: 'graph' })).slice(graphCallsBefore);
      expect(graphCallsAfter.some((c) => c.path.endsWith('/$value'))).toBe(false);
      const failing = await waitForApiConnection(
        orgM,
        connM,
        'health failing',
        (c) => c.health.status === 'failing' && c.inventoryStatus === 'unavailable',
      );
      const grantCheck = (failing.healthChecks as Json[]).find(
        (c) => c.code === 'mailbox_access.grant',
      );
      expect(grantCheck?.status).toBe('fail');
      const alert = await waitFor(
        'the api_mode_unhealthy alert in notify-relay-sink',
        async () => {
          const messages = await sinkMessages(m.email, 'notify-relay-sink');
          return messages
            .map((b) => decodedMailText(b))
            .find(
              (t) =>
                t.includes('API-mode protection needs attention') && t.includes('Problem: failing'),
            );
        },
        { timeoutMs: 240_000, intervalMs: 3_000 },
      );
      expect(alert).toContain(`/api-mode?connection=${row!.publicId}`);
      expect(alert).not.toContain(alex());
      const audit = await fx.prisma.auditLog.findFirst({
        where: { organizationId: orgM.id, action: 'api_mode.health_changed' },
        orderBy: { createdAt: 'desc' },
      });
      expect((audit?.metadata as Json)?.to).toBe('failing');
      // Journal detection needs no grant (D4): a new journal copy is still recorded.
      const messageId = apiModeMessageId('after-revoke');
      await sendJournal({ messageId, to: [blake()], subject: `APIMODE ${fx.suffix} after revoke` });
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, blake()),
        messageId,
        (c) => c.status === 'scanned',
      );
      expect(copy.source).toBe('journal');
      evidence.health = failing.health.status;
      record('api-mode', {
        case: 7,
        health: failing.health.status,
        inventory: failing.inventoryStatus,
        alert_email: true,
        journal_after_revoke: copy.status,
      });
    });

    it('(8) mode-change audit rows and MX-conflict refusal; an inline domain of the same organization still delivers normally', async () => {
      const m = await admin(orgM);
      const domainAudit = await fx.prisma.auditLog.findFirstOrThrow({
        where: {
          organizationId: orgM.id,
          action: 'domain.protection_mode_changed',
          resourceId: apiDom.publicId,
        },
      });
      expect(domainAudit.metadata).toMatchObject({
        fromConfigured: null,
        toConfigured: 'api',
        fromEffective: 'inline',
        toEffective: 'api',
      });
      const orgAudit = await fx.prisma.auditLog.findFirstOrThrow({
        where: { organizationId: orgG.id, action: 'organization.protection_mode_changed' },
      });
      expect(orgAudit.metadata).toMatchObject({ from: 'inline', to: 'api', inheritingDomains: 1 });
      // The domain whose MX points to the gateway cannot become `api` (N2) …
      const refused = await m.put(
        `/domains/${mxDom.publicId}/protection-mode`,
        { mode: 'api', reason: 'stack test: MX still at the gateway' },
        idempotencyKey(),
      );
      expect(refused.status).toBe(409);
      expect((refused.body as Json).code).toBe('protection_mode_mx_points_to_gateway');
      // … but `hybrid` is allowed and changes nothing of the inline mail flow.
      const hybrid = await m.put(
        `/domains/${mxDom.publicId}/protection-mode`,
        { mode: 'hybrid', reason: 'stack test: hybrid keeps MX' },
        idempotencyKey(),
      );
      expectStatus(hybrid, 200, 'PUT hybrid');
      const after = await fx.prisma.domain.findUniqueOrThrow({
        where: { id: mxDom.id },
        select: { inboundEnabled: true, outboundEnabled: true, protectionMode: true },
      });
      expect(after).toEqual({
        inboundEnabled: true,
        outboundEnabled: false,
        protectionMode: 'hybrid',
      });
      expect(
        await fx.prisma.auditLog.count({
          where: { organizationId: orgM.id, action: 'domain.protection_mode_changed' },
        }),
      ).toBe(2);

      // A normal inbound message to the inline domain of the same organization is delivered.
      const rcpt = addr('ina', inlineDom);
      const sent = await sendInbound({
        from: EXTERNAL_SENDER,
        to: [rcpt],
        subject: `APIMODE ${fx.suffix} inline`,
      });
      const msg = await waitForMessage(fx.prisma, orgM.id, { mtaQueueId: sent.queueId! }, 120_000);
      const eml = await waitForSinkMessage(rcpt, 180_000);
      expect(eml.toString('utf8')).toContain(`APIMODE ${fx.suffix} inline`);
      const delivered = await waitFor(
        'delivered row',
        async () => {
          const rows = await fx.prisma.emailDelivery.findMany({ where: { messageId: msg.id } });
          return rows.some((r) => r.status === 'delivered') ? rows : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 2_000 },
      );
      expect(delivered.length).toBeGreaterThan(0);
      // Gateway mail still reaches the customer's email.received webhook (copies never did, case 1).
      const identity = await fx.prisma.messageIdentity.findUniqueOrThrow({
        where: { id: msg.id },
        select: { publicId: true },
      });
      await waitFor(
        'email.received webhook of the inline message',
        async () => mentions(await receivedRequests(hook!.path), [identity.publicId]) > 0,
        { timeoutMs: 120_000, intervalMs: 2_000 },
      );
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, messageId: msg.id },
        }),
      ).toBe(0);
      record('api-mode', { case: 8, mx_conflict: refused.status, inline_delivered: true });
    });

    it('(9) GET /api-mode/overview reflects (1)–(7)', async () => {
      const row = await apiConnectionRow(connM);
      // Wait until the counters of the run are flushed (journal copies, feed copies, throttling).
      await waitFor(
        'counters flushed',
        async () => {
          const s = await counterSums(row!.id);
          return s.journalCopies >= 3 && s.feedCopies >= 3 && s.duplicates >= 1 && s.lagCount >= 6
            ? s
            : undefined;
        },
        { timeoutMs: 90_000, intervalMs: 2_000 },
      );
      const res = await (await admin(orgM)).get('/api-mode/overview');
      expectStatus(res, 200, 'GET /api-mode/overview');
      const o = res.body as Json;
      expect(o).toMatchObject({ entitled: true, active: true, organizationMode: 'inline' });
      expect(o.domainsByEffectiveMode).toEqual({ inline: 1, api: 1, hybrid: 1 });
      expect(o.connectionsByHealth.failing).toBe(1);
      expect(o.copiesToday).toBeGreaterThanOrEqual(6);
      expect(o.throttling.events24h).toBeGreaterThanOrEqual(1);
      expect(o.lag.p95Seconds24h).not.toBeNull();
      const c = (o.connections as Json[]).find((x) => x.id === connM);
      expect(c).toMatchObject({
        provider: 'microsoft_365',
        health: 'failing',
        feedsEnabled: true,
        feedMode: 'notify',
        grantStatus: 'revoked',
        inventoryStatus: 'unavailable',
      });
      expect(c.failingChecks).toContain('mailbox_access.grant');
      expect(c.throttledUntil).not.toBeNull();
      const g = await (await admin(orgG)).get('/api-mode/overview');
      expectStatus(g, 200, 'GET /api-mode/overview (G)');
      const go = g.body as Json;
      expect(go).toMatchObject({ entitled: true, active: true, organizationMode: 'api' });
      expect(go.domainsByEffectiveMode).toEqual({ inline: 0, api: 1, hybrid: 0 });
      const gc = (go.connections as Json[]).find((x) => x.id === connG);
      expect(gc).toMatchObject({
        provider: 'google_workspace',
        grantStatus: 'active',
        feedsEnabled: true,
      });
      expect(gc.coverage.total).toBe(2);
      // Tenant isolation: the other organization never sees the connection.
      expect((await (await admin(orgG)).get(`/api-mode/connections/${connM}`)).status).toBe(404);
      record('api-mode', {
        case: 9,
        copies_today: o.copiesToday,
        lag_p50_24h: o.lag.p50Seconds24h,
        lag_p95_24h: o.lag.p95Seconds24h,
        throttling_24h: o.throttling.events24h,
        failing: o.connectionsByHealth.failing,
        google_copies_today: go.copiesToday,
      });
    });
  },
);
