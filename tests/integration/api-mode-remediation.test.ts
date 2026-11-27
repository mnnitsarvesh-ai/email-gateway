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
import {
  actionsOfCopy,
  mailboxEntriesOfCopy,
  purgeRemediationRows,
  remediationCounterSums,
  remediationRowCounts,
  simLocation,
  waitForAction,
  waitForEntryRow,
  waitForLocation,
} from './support/api-mode-remediation';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import {
  M365_SENDER,
  createSource,
  expectAccepted,
  intakeDomain,
  journalReport,
  originalMessage,
  sendIntake,
} from './support/journal-intake';
import { clearSinkDomain, sinkMessages } from './support/mail-sink';
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
import { windowQuery } from './support/quarantine';
import { MAIL_SINK_HOST, organizationRef, sleep } from './support/routing';
import { sendToMx } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import { pointPostfixNotifyAtRelaySink, restorePostfixNotify } from './support/webhooks';

/**
 * Step API-2 API-mode post-delivery remediation end to end
 * (docs/plan/steps/36-api-mode-remediation.md §9.6, ADR-0101/0102) on the live containers
 * (Compose `apps` + `smtp-test` profiles): journal reports sent with swaks from
 * `provider-sender-m365` to the inbound Postfix and the smtp-adapter's journal listener; copies
 * scanned by the email-worker; the mailbox-worker's `copies` role deciding and its `remediate`
 * role acting on the TEST-ONLY idp-simulator's Graph and Gmail mailboxes (hidden quarantine
 * folder, Junk / SPAM, categories, restore to the Inbox); mailbox-located quarantine entries
 * released through the api's quarantine routes (operator with a second approver, end-user
 * self-release); tokens from 8.2's provider-fake; the `api_mode_unhealthy` alert rendered by the
 * notification-worker and relayed by postfix-notify to notify-relay-sink.
 *
 * Postfix must reach the adapter CONTAINER (the stack switch of `journal-intake.test.ts` and
 * `api-mode.test.ts`: `SMTP_ADAPTER_HOST=smtp-adapter docker compose up -d --no-deps
 * --force-recreate postfix postfix-outbound`, restored from `.env` afterwards).
 *
 * Organizations `it-apirem-<suffix>-m` (Microsoft 365: an `api` domain bound to the connection
 * and a `hybrid` domain receiving inline mail) and `it-apirem-<suffix>-g` (Google Workspace,
 * organization mode `api`) only — never organizations 1, 2, 16946 or user 21416. Synthetic EICAR
 * and GTUBE strings only. Tenant ids, the app secret and the service-account key are generated at
 * run time; every row, Redis key, queue entry and sink file of the run is removed at the end.
 * Observed values are recorded as `[api-mode-remediation] …` lines for the verification record.
 */
const gate = await apiModeStackGate();
const fx = new SmtpFixtures();
const tenantM = guid();
const customerG = `C${fx.suffix}ar`;
const appM = { clientId: guid(), secret: runtimeSecret() };
const saG = serviceAccount(`it-${fx.suffix}-apirem`);
const MAILBOX_ROLES = ['Mail.ReadWrite', 'User.Read.All'];
const GOOGLE_MAILBOX_SCOPES = [
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
];
const GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
const QUARANTINE_FOLDER = process.env.API_MODE_QUARANTINE_FOLDER_NAME ?? 'Email Gateway Quarantine';
const TAG_NAME = process.env.API_MODE_TAG_NAME ?? 'Email Gateway: Suspicious';
const LOG = 'api-mode-remediation';
/** The mailbox-worker's policy cache (R2.6) plus a margin. */
const POLICY_CACHE_MS = 32_000;

interface Org {
  id: bigint;
  publicId: string;
  slug: string;
}
let orgM: Org;
let orgG: Org;
let apiDom: FixtureDomain;
let hybDom: FixtureDomain;
let gDom: FixtureDomain;
let connM = '';
let connG = '';
let sourceM: { id: string; address: string } | undefined;
let approver: ApiSession | undefined;
let ginaUser: ApiSession | undefined;
let overridden = false;
let notifyPointed = false;
const sessions: ApiSession[] = [];
const cachedSessions = new Map<string, { session: ApiSession; at: number }>();
const shared: {
  case1?: { copyId: bigint; copyPublicId: string; simId: string; entryPublicId: string };
  case4CopyPublicId?: string;
  case4CopyId?: bigint;
  case4SimId?: string;
} = {};

const addr = (local: string, d: FixtureDomain) => `${local}@${d.name}`;
const alex = () => addr('alex', apiDom);
const blake = () => addr('blake', apiDom);
const casey = () => addr('casey', apiDom);
const hana = () => addr('hana', hybDom);
const gina = () => addr('gina', gDom);
const gadmin = () => addr('admin', gDom);
const EXTERNAL_SENDER = 'sender@sender.example.test';
const INLINE_SENDER = 'alice@clean.scan.test';

/** An organization admin (MFA) of a fixture organization; renewed before the 10-minute token ends. */
async function admin(o: Org): Promise<ApiSession> {
  const hit = cachedSessions.get(o.slug);
  if (hit && Date.now() - hit.at < 8 * 60_000) return hit.session;
  const session = await apiSession(fx.prisma, { id: o.id, slug: o.slug }, 'organization_admin', {
    mfa: true,
  });
  sessions.push(session);
  cachedSessions.set(o.slug, { session, at: Date.now() });
  return session;
}

async function fixtureOrganization(label: string, planId: bigint): Promise<Org> {
  const id = await fx.organization(`apirem-${label}`);
  const slug = `it-apirem-${fx.suffix}-${label}`;
  await fx.prisma.organization.update({
    where: { id },
    data: { planId, slug, name: `API remediation ${label}` },
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

async function apiConnectionRow(providerConnectionPublicId: string) {
  const pc = await fx.prisma.providerConnection.findFirstOrThrow({
    where: { publicId: providerConnectionPublicId },
    select: { id: true },
  });
  return fx.prisma.apiModeConnection.findUniqueOrThrow({ where: { providerConnectionId: pc.id } });
}

/** A journal report of `original` for the M365 intake source, sent from provider-sender-m365. */
async function sendJournal(o: {
  messageId: string;
  to: readonly string[];
  subject: string;
  original?: string;
}): Promise<void> {
  const original =
    o.original ??
    originalMessage({
      messageId: `<${o.messageId}>`,
      from: EXTERNAL_SENDER,
      to: o.to,
      subject: o.subject,
      body: 'EXAMPLE API-mode remediation journal copy body.',
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

const eicarEml = (messageId: string, to: readonly string[], from = EXTERNAL_SENDER) =>
  attachmentEml({
    messageId,
    from,
    to,
    subject: `APIREM ${fx.suffix} eicar`,
    filename: 'eicar.com',
    content: eicar(),
  });

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

/** The organization's remediation policy view (R13 #1). */
async function policyView(o: Org): Promise<Json> {
  const res = await (await admin(o)).get('/api-mode/remediation-policy');
  expectStatus(res, 200, 'GET /api-mode/remediation-policy');
  return res.body as Json;
}

/** PUT of the organization policy with CAS on the row version just read (R13 #2). */
async function putPolicy(
  o: Org,
  mode: 'detect_only' | 'enforce',
  document: Json,
  reason: string,
): Promise<Json> {
  const view = await policyView(o);
  const res = await (
    await admin(o)
  ).put(
    '/api-mode/remediation-policy',
    { mode, document, reason, expectedRowVersion: view.organization.rowVersion },
    idempotencyKey(),
  );
  expectStatus(res, 200, 'PUT /api-mode/remediation-policy');
  // The copies role keeps an organization's effective policy for 30 s (R2.6,
  // POLICY_CACHE_TTL_MS): copies decided within that window still use the previous policy.
  await sleep(POLICY_CACHE_MS);
  return res.body as Json;
}

/** P1 plus a rule tagging spam (GTUBE) in the Inbox — the suite's way to a `tag` decision. */
async function p1WithSpamTag(o: Org): Promise<Json> {
  const p1 = (await policyView(o)).presets.p1.document;
  return {
    v: 1,
    rules: [
      ...(p1.rules as Json[]),
      { id: 'it-spam-tag', when: { verdicts: ['spam'] }, action: 'tag' },
    ],
  };
}

async function waitForCounters(
  apiConnectionId: bigint,
  what: string,
  predicate: (s: Awaited<ReturnType<typeof remediationCounterSums>>) => boolean,
) {
  return waitFor(
    `remediation counters ${what}`,
    async () => {
      const s = await remediationCounterSums(fx.prisma, apiConnectionId);
      return predicate(s) ? s : undefined;
    },
    { timeoutMs: 90_000, intervalMs: 2_000 },
  );
}

/** Write calls of the simulators on mailbox messages and folders/labels, after the first `from`. */
async function mailboxWriteCalls(from = 0) {
  const calls = [
    ...(await sim.calls({ simulator: 'graph' })),
    ...(await sim.calls({ simulator: 'gmail' })),
  ];
  return calls
    .filter(
      (c) =>
        ['POST', 'PATCH', 'DELETE'].includes(c.method) &&
        /\/users\/[^/]+\/(messages|mailFolders|labels)/.test(c.path),
    )
    .slice(from);
}

async function mailboxWriteCount(): Promise<number> {
  return (await mailboxWriteCalls()).length;
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
  for (const o of [orgM, orgG]) {
    await fx.feature(o.id, 'api_mode_protection', true);
    await fx.feature(o.id, 'journal_intake', true);
  }
  apiDom = await fx.domain(orgM.id, 'apirem-api', { inboundEnabled: false });
  hybDom = await fx.domain(orgM.id, 'apirem-hyb');
  await fx.destinations(hybDom, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  gDom = await fx.domain(orgG.id, 'apirem-goog', { inboundEnabled: false });

  const m = await admin(orgM);
  const g = await admin(orgG);
  expectStatus(
    await m.put(
      `/domains/${apiDom.publicId}/protection-mode`,
      { mode: 'api', reason: 'stack test: API-mode remediation domain' },
      idempotencyKey(),
    ),
    200,
    'PUT /domains/{id}/protection-mode api',
  );
  expectStatus(
    await m.put(
      `/domains/${hybDom.publicId}/protection-mode`,
      { mode: 'hybrid', reason: 'stack test: hybrid keeps the inline path' },
      idempotencyKey(),
    ),
    200,
    'PUT /domains/{id}/protection-mode hybrid',
  );
  expectStatus(
    await g.put(
      `/organizations/${orgG.publicId}/protection-mode`,
      { mode: 'api', reason: 'stack test: organization default API mode' },
      idempotencyKey(),
    ),
    200,
    'PUT /organizations/{id}/protection-mode',
  );

  // Provider side, generated now (mail flow + mailbox permissions; Google delegation).
  await fake.addMicrosoftTenant({
    tenantId: tenantM,
    displayName: `API remediation ${fx.suffix}`,
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
    organizationName: `API remediation G ${fx.suffix}`,
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

  // Microsoft 365: mail-flow grant, binding, mailbox grant (Mail.ReadWrite), inventory, source.
  const createdM = await m.post(
    '/provider-connections',
    { provider: 'microsoft_365', displayName: `EXAMPLE API remediation ${fx.suffix}` },
    idempotencyKey(),
  );
  expectStatus(createdM, 201, 'POST /provider-connections (M)');
  connM = (createdM.body as Json).id as string;
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
    if (profile === 'm365.mail_flow') await linkAndBind(orgM, connM, apiDom);
  }
  expectStatus(
    await m.post(`/api-mode/connections/${connM}/inventory-sync`, {}, idempotencyKey()),
    202,
    'inventory-sync (M)',
  );
  await waitForApiConnection(
    orgM,
    connM,
    'inventory ok',
    (c) => c.inventoryStatus === 'ok' && c.mailboxesTotal === 3,
  );
  sourceM = await createSource(m, {
    kind: 'microsoft_365_journal',
    displayName: 'it-apirem M365 journal',
    providerConnectionId: connM,
  });

  // Google Workspace: mail-flow and mailbox grants (gmail.modify), inventory, history-poll feeds.
  const createdG = await g.post(
    '/provider-connections',
    { provider: 'google_workspace', displayName: `EXAMPLE API remediation G ${fx.suffix}` },
    idempotencyKey(),
  );
  expectStatus(createdG, 201, 'POST /provider-connections (G)');
  connG = (createdG.body as Json).id as string;
  const tokenUri = await serviceEnv('api', 'PROVIDER_GOOGLE_TOKEN_URL');
  for (const profile of ['google.mail_flow', 'google.mailbox_remediation']) {
    expectStatus(
      await g.post(
        `/provider-connections/${connG}/grants`,
        { profile, authMethod: 'customer_service_account' },
        idempotencyKey(),
      ),
      201,
      `POST …/grants ${profile}`,
    );
    expectStatus(
      await g.put(
        `/provider-connections/${connG}/grants/${profile}/credentials`,
        { serviceAccountKey: saG.key(tokenUri), subjectEmail: gadmin() },
        idempotencyKey(),
      ),
      200,
      `PUT …/credentials ${profile}`,
    );
    await waitForConnection(g, connG, `${profile} grant active`, (c) =>
      c.grants.some((x: Json) => x.profile === profile && x.status === 'active'),
    );
    if (profile === 'google.mail_flow') await linkAndBind(orgG, connG, gDom);
  }
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
  await putSettings(orgG, connG, { feedsEnabled: true });
  await waitFor(
    'Gmail feeds initialized',
    async () => {
      const rows = await fx.prisma.apiMailbox.findMany({
        where: { organizationId: orgG.id, status: 'active' },
      });
      return rows.length === 2 && rows.every((r) => r.feedStatus === 'active') ? rows : undefined;
    },
    { timeoutMs: 180_000, intervalMs: 2_000 },
  );

  // A second administrator of M (separation of duties) and gina as a mailbox user of G.
  approver = await apiSession(fx.prisma, { id: orgM.id, slug: orgM.slug }, 'organization_admin', {
    mfa: true,
  });
  sessions.push(approver);
  ginaUser = await apiSession(fx.prisma, { id: orgG.id, slug: orgG.slug }, 'mailbox_user', {
    email: gina(),
  });
  sessions.push(ginaUser);
  record(LOG, { organizations: 2, domains: 3, connections: 2, simulator_users: 5 });
}, 900_000);

afterAll(async () => {
  if (gate.skip) return;
  const ids = [orgM, orgG].filter(Boolean).map((o) => o.id);
  await sim.reset().catch(() => undefined);
  // Stop the worker first (recreated from .env) so no claim or flush writes behind the purge.
  if (overridden) await restoreService('mailbox-worker').catch(() => undefined);
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
  const names = [apiDom, hybDom, gDom].filter(Boolean).map((d) => d.name);
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
      quarantineEntries: await check.quarantineMessage.count({ where }),
    };
    record(LOG, { cleanup: JSON.stringify(counts) });
    expect(counts).toEqual({
      connections: 0,
      mailboxes: 0,
      addresses: 0,
      copies: 0,
      dedupeKeys: 0,
      counters: 0,
      actions: 0,
      policies: 0,
      mailboxEntries: 0,
      quarantineEntries: 0,
    });
    expect(await check.organization.count({ where: { id: { in: ids } } })).toBe(0);
    expect(await check.providerConnection.count({ where })).toBe(0);
    expect(
      await check.organization.count({ where: { slug: { startsWith: `it-apirem-${fx.suffix}` } } }),
    ).toBe(0);
  } finally {
    await check.$disconnect();
  }
}, 900_000);

describe.skipIf(gate.skip)(
  'API-mode remediation stack (step API-2 §9.6)',
  { timeout: 900_000 },
  () => {
    it('(1) EICAR journal copy → P1 move_quarantine: the simulator message is in the hidden quarantine folder and a mailbox-located quarantine entry is listed', async () => {
      const messageId = apiModeMessageId('rem-eicar');
      // The message is in alex's Inbox (feeds off: no feed copy); the journal copy has no
      // provider id, so the worker locates it by Internet Message-ID (R5.3).
      const delivered = await sim.deliver(alex(), eicarEml(messageId, [alex()]));
      expect(delivered.notifications).toEqual([]);
      const since = Date.now();
      await sendJournal({
        messageId,
        to: [alex()],
        subject: `APIREM ${fx.suffix} eicar`,
        original: eicarEml(messageId, [alex()]),
      });
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, alex()),
        messageId,
        (c) => c.remediationState === 'remediated',
      );
      expect(copy).toMatchObject({
        source: 'journal',
        status: 'scanned',
        verdict: 'malware',
        verdictAuthority: 'copy',
        remediationAction: 'move_quarantine',
        remediationGeneration: 0,
      });
      const [action] = await actionsOfCopy(fx.prisma, orgM.id, copy.id);
      expect(action).toMatchObject({
        action: 'move_quarantine',
        trigger: 'policy',
        status: 'succeeded',
        requestedByType: 'system',
        generation: 0,
      });
      expect((action!.decision as Json).ruleId).toBe('p1-high-confidence-malware-phishing-hb');
      expect((action!.decision as Json).policy.scope).toBe('platform_default');
      expect((action!.providerRefs as Json).container).toBe('quarantine_folder');
      expect(action!.locateAttempts).toBe(0);
      // The simulator: the message left the Inbox for the hidden gateway folder.
      const location = await simLocation(alex(), delivered.messageId);
      expect(location.state).toBe('present');
      expect(location.folder).toMatchObject({ displayName: QUARANTINE_FOLDER, isHidden: true });
      // The located id is stored on the copy (it had none: journal copy).
      const after = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: copy.id } });
      expect(after.providerMessageId).not.toBeNull();
      // The mailbox-located entry (R9.1).
      const [entry] = await mailboxEntriesOfCopy(fx.prisma, orgM.id, copy.id);
      expect(entry).toMatchObject({
        location: 'mailbox',
        mailboxContainer: 'quarantine_folder',
        origin: 'api_remediation',
        kind: 'quarantine',
        status: 'held',
        reason: 'malware',
        hasHardBlock: true,
        recipientAddress: alex(),
        apiRemediationActionId: action!.id,
        lifecycleRound: 0,
      });
      expect(action!.quarantineEntryId).toBe(entry!.id);
      const qActions = await fx.prisma.quarantineAction.findMany({
        where: { quarantineMessageId: entry!.id },
      });
      expect(qActions.map((a) => a.action)).toContain('mailbox_remediated');
      // Executed actions are audited (system, ids and codes only).
      const audit = await fx.prisma.auditLog.findFirst({
        where: { organizationId: orgM.id, action: 'api_mode.remediation_executed' },
      });
      expect(audit).not.toBeNull();
      expect(JSON.stringify(audit!.metadata)).not.toContain('@');
      // Listed through the quarantine api with its location (filter location=mailbox).
      const listed = await waitFor(
        'the mailbox entry listed by GET /quarantine/entries?location=mailbox',
        async () => {
          const res = await (
            await admin(orgM)
          ).get(`/quarantine/entries?location=mailbox&${windowQuery()}`);
          expectStatus(res, 200, 'GET /quarantine/entries');
          return ((res.body as Json).items as Json[]).find((i) => i.id === entry!.publicId);
        },
        { timeoutMs: 60_000, intervalMs: 1_500 },
      );
      expect(listed.location).toMatchObject({
        kind: 'mailbox',
        container: 'quarantine_folder',
        provider: 'microsoft_365',
        connectionId: connM,
        detectionId: copy.publicId,
        remediationStatus: 'succeeded',
      });
      const gateway = await (
        await admin(orgM)
      ).get(`/quarantine/entries?location=gateway&${windowQuery()}`);
      expectStatus(gateway, 200, 'GET /quarantine/entries?location=gateway');
      expect(((gateway.body as Json).items as Json[]).some((i) => i.id === entry!.publicId)).toBe(
        false,
      );
      shared.case1 = {
        copyId: copy.id,
        copyPublicId: copy.publicId,
        simId: delivered.messageId,
        entryPublicId: entry!.publicId,
      };
      record(LOG, {
        case: 1,
        verdict: copy.verdict,
        risk: copy.riskScore,
        action: action!.action,
        folder_hidden: location.folder?.isHidden,
        entry: entry!.status,
        seconds_to_remediated: Math.round((Date.now() - since) / 1000),
        latency_ms:
          action!.completedAt && action!.verdictAt
            ? action!.completedAt.getTime() - action!.verdictAt.getTime()
            : null,
      });
    });

    it('(2) operator release → approval_required (hard block) → a second admin approves → restore: the message is back in the Inbox, entry released', async () => {
      expect(shared.case1, 'case 1 ran').toBeDefined();
      const c1 = shared.case1!;
      const m = await admin(orgM);
      const requested = await m.post(
        `/quarantine/entries/${c1.entryPublicId}/release`,
        { reason: 'stack test: restore the mailbox copy' },
        idempotencyKey(),
      );
      expect(requested.status, JSON.stringify(requested.body)).toBe(202);
      expect(requested.body).toMatchObject({
        outcome: 'approval_requested',
        state: 'pending_approval',
      });
      expect((requested.body as Json).approvalReasons).toContain('hard_block');
      const approvalId = (requested.body as Json).approvalRequestId as string;
      // No restore before the approval (nothing queued, the message stays in the folder).
      expect(
        (await actionsOfCopy(fx.prisma, orgM.id, c1.copyId)).some(
          (a) => a.action === 'restore_inbox',
        ),
      ).toBe(false);
      // The requester cannot approve (separation of duties, unchanged).
      const self = await m.post(
        `/quarantine/approvals/${approvalId}/approve`,
        { reason: 'stack test: self approve' },
        idempotencyKey(),
      );
      expect(self.status, JSON.stringify(self.body)).toBe(403);
      const approved = await approver!.post(
        `/quarantine/approvals/${approvalId}/approve`,
        { reason: 'stack test: second person approves the restore' },
        idempotencyKey(),
      );
      expect(approved.status, JSON.stringify(approved.body)).toBe(202);
      expect(approved.body).toMatchObject({ status: 'approved', entryState: 'releasing' });
      const releaseId = (approved.body as Json).releaseId as string;
      const entryRow = await fx.prisma.quarantineMessage.findUniqueOrThrow({
        where: { publicId: c1.entryPublicId },
      });
      const released = await waitForEntryRow(fx.prisma, entryRow.id, 'released', (e) =>
        ['released', 'held'].includes(e.status),
      );
      expect(released.status).toBe('released');
      const restore = await waitForAction(
        fx.prisma,
        orgM.id,
        c1.copyId,
        'restore_inbox succeeded',
        (a) => a.action === 'restore_inbox' && a.status === 'succeeded',
      );
      expect(restore).toMatchObject({ trigger: 'release', quarantineEntryId: entryRow.id });
      const logs = await fx.prisma.quarantineReleaseLog.findMany({
        where: { releasePublicId: releaseId },
      });
      expect(logs.map((l) => [l.status, l.mode])).toEqual([['restored', 'approved']]);
      // No gateway release event for a mailbox entry (R10.2).
      expect(
        await fx.prisma.messageOutbox.count({
          where: { organizationId: orgM.id, eventType: 'mail.quarantine.release_requested.v1' },
        }),
      ).toBe(0);
      const location = await simLocation(alex(), c1.simId);
      expect(location.folder?.wellKnownName).toBe('inbox');
      const copy = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: c1.copyId } });
      expect(copy).toMatchObject({ remediationState: 'restored', remediationGeneration: 1 });
      const original = (await actionsOfCopy(fx.prisma, orgM.id, c1.copyId)).find(
        (a) => a.action === 'move_quarantine',
      );
      expect(original!.reversedByActionId).toBe(restore.id);
      expect(
        (
          await fx.prisma.quarantineAction.findMany({ where: { quarantineMessageId: entryRow.id } })
        ).map((a) => a.action),
      ).toContain('mailbox_restored');
      record(LOG, {
        case: 2,
        approval_reasons: ((requested.body as Json).approvalReasons as string[]).join(','),
        release_log: logs[0]!.status,
        folder_after: location.folder?.wellKnownName,
        generation_after: copy.remediationGeneration,
      });
    });

    it('(3) suspicious-tier copy (spam → tag rule) through the Graph feed → category tag; restore via /api-mode/detections/{id}/restore → category removed', async () => {
      const policy = await putPolicy(
        orgM,
        'enforce',
        await p1WithSpamTag(orgM),
        'stack test: tag spam in the Inbox',
      );
      expect(policy).toMatchObject({ scope: 'organization', mode: 'enforce', created: true });
      // Feeds in notify mode (subscriptions through the api's validation handshake).
      await putSettings(orgM, connM, { feedsEnabled: true, feedMode: 'notify' });
      await waitFor(
        'every in-scope mailbox fed with a subscription',
        async () => {
          const rows = await fx.prisma.apiMailbox.findMany({
            where: { organizationId: orgM.id, status: 'active' },
          });
          return rows.length === 3 &&
            rows.every(
              (r) =>
                r.feedStatus === 'active' && r.subscriptionId !== null && r.feedCursor !== null,
            )
            ? rows
            : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 2_000 },
      );
      const messageId = apiModeMessageId('rem-tag');
      const delivered = await sim.deliver(
        casey(),
        copyEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [casey()],
          subject: `APIREM ${fx.suffix} tag`,
          body: GTUBE,
        }),
      );
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, casey()),
        messageId,
        (c) => c.remediationState !== 'none' && c.remediationState !== 'pending',
      );
      expect(copy).toMatchObject({
        source: 'graph',
        verdict: 'spam',
        remediationState: 'remediated',
        remediationAction: 'tag',
      });
      const tagged = await simLocation(casey(), delivered.messageId);
      expect(tagged.categories).toContain(TAG_NAME);
      expect(tagged.folder?.wellKnownName).toBe('inbox');
      // A tag creates no quarantine entry (R9.3).
      expect(await mailboxEntriesOfCopy(fx.prisma, orgM.id, copy.id)).toEqual([]);
      const detection = await (await admin(orgM)).get(`/api-mode/detections/${copy.publicId}`);
      expectStatus(detection, 200, 'GET /api-mode/detections/{id}');
      expect(detection.body).toMatchObject({
        remediationState: 'remediated',
        remediationAction: 'tag',
        quarantineEntryId: null,
      });
      const restore = await (
        await admin(orgM)
      ).post(
        `/api-mode/detections/${copy.publicId}/restore`,
        { reason: 'stack test: not spam' },
        idempotencyKey(),
      );
      expect(restore.status, JSON.stringify(restore.body)).toBe(202);
      expect(restore.body).toMatchObject({ via: 'mailbox_action', release: null });
      expect((restore.body as Json).remediation).toMatchObject({
        action: 'remove_tag',
        trigger: 'admin',
      });
      await waitForAction(
        fx.prisma,
        orgM.id,
        copy.id,
        'remove_tag succeeded',
        (a) => a.action === 'remove_tag' && a.status === 'succeeded',
      );
      const untagged = await waitForLocation(
        casey(),
        delivered.messageId,
        'without the gateway category',
        (l) => !l.categories.includes(TAG_NAME),
      );
      const restored = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: copy.id } });
      expect(restored).toMatchObject({ remediationState: 'restored', remediationGeneration: 1 });
      const audit = await fx.prisma.auditLog.findFirst({
        where: { organizationId: orgM.id, action: 'api_mode.restore_requested' },
      });
      expect(audit).not.toBeNull();
      record(LOG, {
        case: 3,
        verdict: copy.verdict,
        tagged: tagged.categories.includes(TAG_NAME),
        untagged: !untagged.categories.includes(TAG_NAME),
      });
    });

    it('(4) detect-only policy → the decision is recorded as simulated; no simulator write call', async () => {
      await putPolicy(
        orgM,
        'detect_only',
        await p1WithSpamTag(orgM),
        'stack test: detect-only start',
      );
      const writesBefore = await mailboxWriteCount();
      const messageId = apiModeMessageId('rem-detect');
      const delivered = await sim.deliver(
        casey(),
        copyEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [casey()],
          subject: `APIREM ${fx.suffix} detect`,
          body: GTUBE,
        }),
      );
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, casey()),
        messageId,
        (c) => c.remediationState !== 'none',
      );
      expect(copy).toMatchObject({ verdict: 'spam', remediationState: 'simulated' });
      const [action] = await actionsOfCopy(fx.prisma, orgM.id, copy.id);
      expect(action).toMatchObject({ action: 'tag', status: 'simulated', trigger: 'policy' });
      expect((action!.decision as Json).mode).toBe('detect_only');
      // Give a running remediate role two ticks: still nothing written to any mailbox.
      await sleep(6_000);
      expect(await mailboxWriteCalls(writesBefore)).toEqual([]);
      expect((await simLocation(casey(), delivered.messageId)).categories).toEqual([]);
      shared.case4CopyPublicId = copy.publicId;
      shared.case4CopyId = copy.id;
      shared.case4SimId = delivered.messageId;
      record(LOG, { case: 4, status: action!.status, writes: 0 });
    });

    it('(5) hybrid domain: the journal copy of an inline-processed message → skipped inline_authority (R-I3)', async () => {
      await putPolicy(
        orgM,
        'enforce',
        await p1WithSpamTag(orgM),
        'stack test: enforce again after detect-only',
      );
      const messageId = apiModeMessageId('rem-hybrid');
      // The inline path sees the message first (gateway MX of the hybrid domain).
      const sent = await sendToMx({
        from: INLINE_SENDER,
        to: [hana()],
        helo: 'mx.clean.scan.test',
        data: eicarEml(messageId, [hana()], INLINE_SENDER),
      });
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const inline = await waitForMessage(
        fx.prisma,
        orgM.id,
        { mtaQueueId: sent.queueId! },
        120_000,
      );
      // Then the journal copy of the same Message-ID for the hybrid mailbox.
      await sendJournal({
        messageId,
        to: [hana()],
        subject: `APIREM ${fx.suffix} hybrid`,
        original: eicarEml(messageId, [hana()], INLINE_SENDER),
      });
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, hana()),
        messageId,
        (c) => c.status === 'scanned' && c.remediationState !== 'none',
      );
      expect(copy).toMatchObject({
        verdictAuthority: 'inline',
        inlineMessageId: inline.id,
        remediationState: 'skipped',
      });
      const [action] = await actionsOfCopy(fx.prisma, orgM.id, copy.id);
      expect(action).toMatchObject({
        status: 'skipped',
        reasonCode: 'inline_authority',
        trigger: 'policy',
      });
      expect((action!.decision as Json).inputs.verdictAuthority).toBe('inline');
      expect(await mailboxEntriesOfCopy(fx.prisma, orgM.id, copy.id)).toEqual([]);
      record(LOG, {
        case: 5,
        verdict: copy.verdict,
        authority: copy.verdictAuthority,
        reason: action!.reasonCode,
      });
    });

    it('(6) scripted 429 Retry-After: 2 on the move → paused and retried after the pause; remediation_throttled counted, attempt not counted', async () => {
      const strict = (await policyView(orgM)).presets.strict;
      await putPolicy(orgM, strict.mode, strict.document, 'stack test: strict preset');
      const row = await apiConnectionRow(connM);
      await sim.inject({
        family: 'graph_messages',
        method: 'POST',
        status: 429,
        retryAfter: '2',
        times: 1,
      });
      const messageId = apiModeMessageId('rem-429');
      const delivered = await sim.deliver(
        blake(),
        copyEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [blake()],
          subject: `APIREM ${fx.suffix} throttled`,
          body: GTUBE,
        }),
      );
      const copy = await waitForCopy(
        fx.prisma,
        orgM.id,
        mailboxIdOf(orgM, blake()),
        messageId,
        (c) => c.remediationState !== 'none' && c.remediationState !== 'pending',
      );
      expect(copy).toMatchObject({
        remediationState: 'remediated',
        remediationAction: 'move_junk',
      });
      const [action] = await actionsOfCopy(fx.prisma, orgM.id, copy.id);
      // The throttled try is not counted (R5.6): the only counted attempt is the one that moved it.
      expect(action).toMatchObject({
        action: 'move_junk',
        status: 'succeeded',
        attempts: 1,
        lastErrorCode: null,
      });
      expect((action!.decision as Json).ruleId).toBe('strict-spam-junk');
      const throttled = (await sim.calls({ simulator: 'graph' })).filter(
        (c) => c.status === 429 && c.method === 'POST' && c.path.endsWith('/move'),
      );
      expect(throttled.length).toBeGreaterThanOrEqual(1);
      const location = await simLocation(blake(), delivered.messageId);
      expect(location.folder?.wellKnownName).toBe('junkemail');
      const [entry] = await mailboxEntriesOfCopy(fx.prisma, orgM.id, copy.id);
      expect(entry).toMatchObject({ mailboxContainer: 'junk', status: 'held', reason: 'spam' });
      const counters = await waitForCounters(row.id, 'throttled', (s) => s.throttled >= 1);
      record(LOG, {
        case: 6,
        throttled_calls: throttled.length,
        remediation_throttled: counters.throttled,
        attempts: action!.attempts,
        folder: location.folder?.wellKnownName,
      });
    });

    it('(7) Gmail connection: GTUBE copy with the STRICT preset → Junk (SPAM label); end-user self-release (spam allowed) → back in the Inbox', async () => {
      const g = await admin(orgG);
      const strict = (await policyView(orgG)).presets.strict;
      await putPolicy(orgG, strict.mode, strict.document, 'stack test: strict preset (Google)');
      // Quarantine settings: end users may self-release spam up to medium risk.
      const current = await g.get('/quarantine/settings');
      expectStatus(current, 200, 'GET /quarantine/settings');
      const settings = current.body as { raw: Record<string, unknown> | null; rowVersion: number };
      const put = await g.put('/quarantine/settings', {
        settings: {
          ...(settings.raw ?? {}),
          endUser: {
            ...((settings.raw?.endUser as object | undefined) ?? {}),
            enabled: true,
            selfRelease: true,
            selfReleaseReasons: ['spam'],
            selfReleaseMaxLevel: 'medium',
          },
        },
        expectedRowVersion: settings.rowVersion,
      });
      expect(put.status, JSON.stringify(put.body)).toBe(200);
      // A tenant risk profile under which GTUBE (risk ≈ 640) is `medium` (high from 700).
      const draft = await g.post('/risk-scoring/profile/versions', {
        overrides: { thresholds: { high: 700 } },
        changeNote: 'stack test: GTUBE is medium so the end user may self-release it',
      });
      expect(draft.status, JSON.stringify(draft.body)).toBe(201);
      const created = draft.body as { id: string; rowVersion: number };
      const published = await g.post(
        `/risk-scoring/profile/versions/${created.id}/publish`,
        { activate: true, expectedRowVersion: created.rowVersion },
        idempotencyKey(),
      );
      expect(published.status, JSON.stringify(published.body)).toBe(200);

      const messageId = apiModeMessageId('rem-gmail');
      const delivered = await sim.deliver(
        gina(),
        copyEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [gina()],
          subject: `APIREM ${fx.suffix} gmail`,
          body: GTUBE,
        }),
      );
      const copy = await waitForCopy(
        fx.prisma,
        orgG.id,
        mailboxIdOf(orgG, gina()),
        messageId,
        (c) => c.remediationState !== 'none' && c.remediationState !== 'pending',
      );
      expect(copy).toMatchObject({
        source: 'gmail',
        verdict: 'spam',
        remediationState: 'remediated',
        remediationAction: 'move_junk',
      });
      const junk = await simLocation(gina(), delivered.messageId);
      expect(junk.labelIds).toContain('SPAM');
      expect(junk.labelIds).not.toContain('INBOX');
      const [entry] = await mailboxEntriesOfCopy(fx.prisma, orgG.id, copy.id);
      expect(entry).toMatchObject({
        location: 'mailbox',
        mailboxContainer: 'junk',
        status: 'held',
        reason: 'spam',
        recipientAddress: gina(),
      });
      // The end user sees the entry with its location (no connection id on self routes).
      const own = await waitFor(
        "gina's mailbox entry in the self-service list",
        async () => {
          const res = await ginaUser!.get(`/quarantine/me/entries?${windowQuery()}`);
          expectStatus(res, 200, 'GET /quarantine/me/entries');
          return ((res.body as Json).items as Json[]).find((i) => i.id === entry!.publicId);
        },
        { timeoutMs: 60_000, intervalMs: 1_500 },
      );
      expect(own.location).toMatchObject({ kind: 'mailbox', container: 'junk' });
      expect(own.location.connectionId).toBeUndefined();
      const self = await ginaUser!.post(
        `/quarantine/me/entries/${entry!.publicId}/release`,
        { reason: 'stack test: mine, not spam' },
        idempotencyKey(),
      );
      expect(self.status, JSON.stringify(self.body)).toBe(202);
      expect(self.body).toMatchObject({ outcome: 'queued' });
      const releaseId = (self.body as Json).releaseId as string;
      const released = await waitForEntryRow(fx.prisma, entry!.id, 'released', (e) =>
        ['released', 'held'].includes(e.status),
      );
      expect(released.status).toBe('released');
      const restore = await waitForAction(
        fx.prisma,
        orgG.id,
        copy.id,
        'restore_inbox succeeded',
        (a) => a.action === 'restore_inbox' && a.status === 'succeeded',
      );
      expect(restore.trigger).toBe('end_user');
      const logs = await fx.prisma.quarantineReleaseLog.findMany({
        where: { releasePublicId: releaseId },
      });
      expect(logs.map((l) => [l.status, l.mode])).toEqual([['restored', 'self']]);
      const inbox = await simLocation(gina(), delivered.messageId);
      expect(inbox.labelIds).toContain('INBOX');
      expect(inbox.labelIds).not.toContain('SPAM');
      record(LOG, {
        case: 7,
        verdict: copy.verdict,
        risk: copy.riskScore,
        entry_level: entry!.riskLevel,
        junk_labels: junk.labelIds.join(','),
        restored_labels: inbox.labelIds.join(','),
      });
    });

    it('(8) grant revoked while an action waits for its retry → failed mailbox_access_revoked; health failing with remediation.access; alert e-mail at notify-relay-sink', async () => {
      expect(shared.case4CopyPublicId, 'case 4 ran').toBeDefined();
      const m = await admin(orgM);
      const row = await apiConnectionRow(connM);
      // A retryable provider failure keeps a manual action pending (back-off 30 s).
      await sim.inject({ family: 'graph_messages', method: 'POST', status: 503, times: 1 });
      const requested = await m.post(
        `/api-mode/detections/${shared.case4CopyPublicId}/remediate`,
        { action: 'move_quarantine', reason: 'stack test: manual quarantine' },
        idempotencyKey(),
      );
      expect(requested.status, JSON.stringify(requested.body)).toBe(202);
      expect((requested.body as Json).remediation).toMatchObject({
        action: 'move_quarantine',
        trigger: 'admin',
        status: 'pending',
      });
      const waiting = await waitForAction(
        fx.prisma,
        orgM.id,
        shared.case4CopyId!,
        'manual move pending after a 503',
        (a) =>
          a.action === 'move_quarantine' &&
          a.trigger === 'admin' &&
          a.status === 'pending' &&
          a.attempts >= 1,
        120_000,
      );
      expect(waiting.lastHttpStatus).toBe(503);
      // The 24 h alert window may hold an earlier transition of this connection: reset it so the
      // failing transition is alerted again (test seam only, as API-1 case 7).
      await fx.prisma.apiModeConnection.update({
        where: { id: row.id },
        data: { healthAlertedAt: null },
      });
      await fx.prisma.notificationAlertWindow.deleteMany({ where: { organizationId: orgM.id } });
      expectStatus(
        await m.delete(
          `/provider-connections/${connM}/grants/m365.mailbox_remediation`,
          idempotencyKey(),
        ),
        200,
        'DELETE …/grants/m365.mailbox_remediation',
      );
      const failed = await waitForAction(
        fx.prisma,
        orgM.id,
        shared.case4CopyId!,
        'failed mailbox_access_revoked',
        (a) => a.id === waiting.id && a.status === 'failed',
        180_000,
      );
      expect(failed.reasonCode).toBe('mailbox_access_revoked');
      const copy = await fx.prisma.apiMessageCopy.findFirstOrThrow({
        where: { id: shared.case4CopyId! },
      });
      expect(copy.remediationState).toBe('failed');
      // Nothing moved: the message is still in the Inbox.
      expect((await simLocation(casey(), shared.case4SimId!)).folder?.wellKnownName).toBe('inbox');
      const failing = await waitForApiConnection(
        orgM,
        connM,
        'health failing with the remediation access warning',
        (c) =>
          c.health.status === 'failing' &&
          (c.healthChecks as Json[]).some(
            (x) => x.code === 'remediation.access' && x.status === 'warn',
          ),
      );
      expect(
        (failing.healthChecks as Json[]).find((x) => x.code === 'mailbox_access.grant')?.status,
      ).toBe('fail');
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
      expect(alert).toContain(`/api-mode?connection=${row.publicId}`);
      expect(alert).not.toContain(casey());
      const retry = await m.post(
        `/api-mode/remediations/${failed.publicId}/retry`,
        {},
        idempotencyKey(),
      );
      // A retry without an active grant is queued and fails again at the pre-check (R5.1).
      expect(retry.status, JSON.stringify(retry.body)).toBe(202);
      const refailed = await waitForAction(
        fx.prisma,
        orgM.id,
        shared.case4CopyId!,
        'retried row failed again',
        (a) => a.id === waiting.id && a.status === 'failed' && a.updatedAt > failed.updatedAt,
        60_000,
      );
      expect(refailed.reasonCode).toBe('mailbox_access_revoked');
      record(LOG, {
        case: 8,
        reason: failed.reasonCode,
        health: failing.health.status,
        alert_email: true,
        retry_status: retry.status,
      });
    });

    it('(9) GET /api-mode/overview remediation block is consistent with (1)–(8)', async () => {
      const rowM = await apiConnectionRow(connM);
      const rowG = await apiConnectionRow(connG);
      const sums = await waitForCounters(
        rowM.id,
        'of the M365 connection flushed',
        (s) =>
          s.succeeded >= 3 &&
          s.restoresSucceeded >= 2 &&
          s.skipped >= 1 &&
          s.simulated >= 1 &&
          s.throttled >= 1 &&
          s.failed >= 1,
      );
      await waitForCounters(
        rowG.id,
        'of the Google connection flushed',
        (s) => s.succeeded >= 1 && s.restoresSucceeded >= 1,
      );
      const res = await (await admin(orgM)).get('/api-mode/overview');
      expectStatus(res, 200, 'GET /api-mode/overview');
      const r = (res.body as Json).remediation;
      expect(r).toMatchObject({
        policyMode: 'enforce',
        policySource: 'organization',
        paused: false,
      });
      expect(r.succeeded24h).toBeGreaterThanOrEqual(3);
      expect(r.restores24h).toBeGreaterThanOrEqual(2);
      expect(r.skipped24h).toBeGreaterThanOrEqual(1);
      expect(r.simulated24h).toBeGreaterThanOrEqual(1);
      expect(r.throttled24h).toBeGreaterThanOrEqual(1);
      expect(r.failed24h).toBeGreaterThanOrEqual(1);
      expect(r.backlog.pending).toBe(0);
      expect(r.latencyAvgSeconds24h).not.toBeNull();
      const c = ((res.body as Json).connections as Json[]).find((x) => x.id === connM);
      expect(c.remediation.succeeded24h).toBe(r.succeeded24h);
      const g = await (await admin(orgG)).get('/api-mode/overview');
      expectStatus(g, 200, 'GET /api-mode/overview (G)');
      const gr = (g.body as Json).remediation;
      expect(gr).toMatchObject({ policyMode: 'enforce', policySource: 'organization' });
      expect(gr.succeeded24h).toBeGreaterThanOrEqual(1);
      expect(gr.restores24h).toBeGreaterThanOrEqual(1);
      // The history lists M's actions only (tenant from the principal).
      const history = await (await admin(orgM)).get('/api-mode/remediations?limit=100');
      expectStatus(history, 200, 'GET /api-mode/remediations');
      const items = (history.body as Json).data as Json[];
      expect(items.length).toBeGreaterThanOrEqual(8);
      expect(items.every((i) => i.connectionId === connM)).toBe(true);
      expect(JSON.stringify(history.body)).not.toMatch(/providerRefs|AAMk/);
      // Cross-tenant: G cannot read M's remediation.
      expect((await (await admin(orgG)).get(`/api-mode/remediations/${items[0]!.id}`)).status).toBe(
        404,
      );
      record(LOG, {
        case: 9,
        succeeded24h: r.succeeded24h,
        failed24h: r.failed24h,
        restores24h: r.restores24h,
        skipped24h: r.skipped24h,
        simulated24h: r.simulated24h,
        throttled24h: r.throttled24h,
        latency_avg_s: r.latencyAvgSeconds24h,
        counters: JSON.stringify(sums),
        google_succeeded24h: gr.succeeded24h,
      });
    });
  },
);
