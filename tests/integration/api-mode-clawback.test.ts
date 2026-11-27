/* eslint-disable @typescript-eslint/no-unsafe-return -- predicates over the api's loose JSON */
import { eicar } from '@email-gateway/attachment-corpus';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import {
  ADAPTER_SUITE_ENV,
  apiModeRowCounts,
  apiModeStackGate,
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
import {
  CLAWBACK_WORKER_SUITE_ENV,
  FINAL_CLAWBACK_STATUSES,
  benignAttachment,
  clawbackCounterSums,
  clawbackRowCounts,
  clawbacksOf,
  forwardAsAttachmentEml,
  inlineForwardEml,
  purgeClawbackRows,
  sha256Hex,
  syntheticEml,
  targetsOf,
  waitForClawback,
  waitForClawbackState,
  waitForPublished,
  waitForReport,
  writeSandboxLateSignal,
  type ClawbackRow,
} from './support/api-mode-clawback';
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
  sendIntake,
  waitForIntakeMessage,
} from './support/journal-intake';
import { clearSinkDomain, sinkFiles, sinkMessages } from './support/mail-sink';
import { record } from './support/messaging-stack';
import { platformAdminSession, type PlatformAdminSession } from './support/platform-admin';
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
import { MAIL_SINK_HOST, organizationRef, sleep } from './support/routing';
import { sendToMx } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import { pointPostfixNotifyAtRelaySink, restorePostfixNotify } from './support/webhooks';

/**
 * Step API-3 — the program acceptance run of API-mode protection (API-1..API-3)
 * (docs/plan/steps/37-api-mode-clawback-reporting.md §9.6 and §13 A1–A10, ADR-0098–0104) on the
 * live containers (Compose `apps` + `smtp-test` profiles): journal reports sent with swaks from
 * `provider-sender-m365` to the inbound Postfix and the smtp-adapter's journal listener; inline
 * mail through `postfix:25`; copies scanned by the email-worker; the mailbox-worker's `copies`
 * role (internal mail, report intake, late signals), `clawback` role (materialization, planning,
 * queueing, reconcile, bulk restore, the threat-intelligence sweep), `reports` role and
 * `remediate` role acting on the TEST-ONLY idp-simulator's Graph and Gmail mailboxes; clawbacks,
 * reports and settings through the api; reporter feedback and alert e-mails rendered by the
 * notification-worker and relayed by postfix-notify to notify-relay-sink; tokens from 8.2's
 * provider-fake. A11 (assistant tools, step-up, hard delete portal-only) is covered by the api
 * integration suite `apps/api/integration/assistant-writes-api-mode.test.ts` and
 * `assistant-tools.test.ts` (C15).
 *
 * Postfix must reach the adapter CONTAINER (the stack switch of `journal-intake.test.ts`:
 * `SMTP_ADAPTER_HOST=smtp-adapter docker compose up -d --no-deps --force-recreate postfix
 * postfix-outbound`, restored from `.env` afterwards).
 *
 * A3 (§13 fallback, recorded in note 37 §15.7): the sandbox test backend of the stack is
 * `disabled` (the analysis ends `not_executed`, final `unknown`) and the `static` backend gives no
 * deterministic malicious verdict, so no raising risk revision 1 can be produced after a round
 * here. The suite lets the real email-worker scan the synthetic copies and then writes the exact
 * `mail.threat.late_signal.v1` outbox row of the sandbox finalizer (`writeLateSignalOutbox`,
 * strict contract) for that registry message; relay, topology v18 binding, mailbox-worker,
 * clawback, policy and remediation are the live path. The emission itself is covered by the
 * email-worker integration test `risk-scoring.test.ts`.
 *
 * Organizations `it-apiclaw-<suffix>-m` (Microsoft 365: an `api` domain, a `hybrid` domain with
 * inline delivery to mail-sink and an `inline` domain), `-g` (Google Workspace, organization mode
 * `api`) and `-x` (Microsoft 365, `api`, no matching mail: the A4 control) only — never
 * organizations 1, 2, 16946 or user 21416. Synthetic EICAR strings, benign generated attachments
 * and URLs under example.com only. Tenant ids, app secrets and the service-account key are
 * generated at run time; every row, Redis key, queue entry, indicator and sink file of the run is
 * removed at the end. Observed values are recorded as `[api-mode-clawback] …` lines.
 */
const gate = await apiModeStackGate();
const fx = new SmtpFixtures();
const tenantM = guid();
const tenantX = guid();
const customerG = `C${fx.suffix}ac`;
const appM = { clientId: guid(), secret: runtimeSecret() };
const appX = { clientId: guid(), secret: runtimeSecret() };
const saG = serviceAccount(`it-${fx.suffix}-apiclaw`);
const MAILBOX_ROLES = ['Mail.ReadWrite', 'User.Read.All'];
const GOOGLE_MAILBOX_SCOPES = [
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
];
const QUARANTINE_FOLDER = process.env.API_MODE_QUARANTINE_FOLDER_NAME ?? 'Email Gateway Quarantine';
const LOG = 'api-mode-clawback';
const BULK = 60;
const BULK_USERS = Array.from({ length: BULK }, (_, i) => `u${String(i + 1).padStart(2, '0')}`);

interface Org {
  id: bigint;
  publicId: string;
  slug: string;
}
let orgM: Org;
let orgG: Org;
let orgX: Org;
let apiDom: FixtureDomain;
let hybDom: FixtureDomain;
let inlDom: FixtureDomain;
let gDom: FixtureDomain;
let xDom: FixtureDomain;
let connM = '';
let connG = '';
let connX = '';
let sourceM: { id: string; address: string } | undefined;
let approver: ApiSession | undefined;
let platform: PlatformAdminSession | undefined;
let overridden = false;
let notifyPointed = false;
const indicatorIds = new Set<string>();
const sessions: ApiSession[] = [];
const cachedSessions = new Map<string, { session: ApiSession; at: number }>();
const shared: {
  a1?: { messageId: string; alexCopyId: bigint; alexSim: string; hanaSim: string };
  a5ApprovalClawback?: string;
} = {};

const addr = (local: string, d: FixtureDomain) => `${local}@${d.name}`;
const alex = () => addr('alex', apiDom);
const blake = () => addr('blake', apiDom);
const casey = () => addr('casey', apiDom);
const reportBox = () => addr('report', apiDom);
const hana = () => addr('hana', hybDom);
const ina = () => addr('ina', inlDom);
const gina = () => addr('gina', gDom);
const gadmin = () => addr('admin', gDom);
const bulk = (local: string) => addr(local, apiDom);
const EXTERNAL_SENDER = 'sender@sender.example.test';
const OUTSIDER = 'outsider@sender.example.test';
const PARTNER = 'partner@partner.example.test';
const INLINE_SENDER = 'alice@clean.scan.test';
const messageIdOf = (label: string) =>
  `it-apiclaw-${label}-${guid().slice(0, 12)}@sender.example.test`;
const subjectOf = (label: string) => `APICLAW ${fx.suffix} ${label}`;

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
  const id = await fx.organization(`apiclaw-${label}`);
  const slug = `it-apiclaw-${fx.suffix}-${label}`;
  await fx.prisma.organization.update({
    where: { id },
    data: { planId, slug, name: `API clawback ${label}` },
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
  sender?: string;
  to: readonly string[];
  original: string;
  what: string;
}): Promise<void> {
  const sent = await sendIntake({
    service: M365_SENDER,
    to: [sourceM!.address],
    data: journalReport({
      intakeAddress: sourceM!.address,
      original: o.original,
      sender: o.sender ?? EXTERNAL_SENDER,
      to: o.to,
      messageId: `<${o.messageId}>`,
      tenantIds: [tenantM],
    }),
  });
  expectAccepted(sent, `journal report ${o.what}`);
}

const eicarEml = (messageId: string, from: string, to: readonly string[], subject: string) =>
  syntheticEml({
    messageId,
    from,
    to,
    subject,
    attachment: { filename: 'eicar.com', content: eicar() },
  });

async function linkAndBind(o: Org, id: string, domains: readonly FixtureDomain[]): Promise<void> {
  const session = await admin(o);
  expectStatus(
    await session.put(
      `/provider-connections/${id}/domains`,
      { domainIds: domains.map((d) => d.publicId) },
      idempotencyKey(),
    ),
    200,
    'PUT …/domains',
  );
  await waitForConnection(session, id, 'status active (bound)', (c) => c.status === 'active');
}

async function putConnectionSettings(
  o: Org,
  id: string,
  change: { feedsEnabled: boolean; feedMode?: 'poll' | 'notify'; remediationPaused?: boolean },
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

/** A Microsoft 365 connection with mail-flow and mailbox grants, bound domains and inventory. */
async function microsoftConnection(
  o: Org,
  app: { clientId: string; secret: string },
  tenantId: string,
  domains: readonly FixtureDomain[],
  mailboxes: number,
): Promise<string> {
  const session = await admin(o);
  const created = await session.post(
    '/provider-connections',
    { provider: 'microsoft_365', displayName: `EXAMPLE API clawback ${o.slug}` },
    idempotencyKey(),
  );
  expectStatus(created, 201, `POST /provider-connections (${o.slug})`);
  const id = (created.body as Json).id as string;
  for (const profile of ['m365.mail_flow', 'm365.mailbox_remediation']) {
    expectStatus(
      await session.post(
        `/provider-connections/${id}/grants`,
        { profile, authMethod: 'customer_app_secret' },
        idempotencyKey(),
      ),
      201,
      `POST …/grants ${profile}`,
    );
    expectStatus(
      await session.put(
        `/provider-connections/${id}/grants/${profile}/credentials`,
        { tenantId, clientId: app.clientId, clientSecret: app.secret },
        idempotencyKey(),
      ),
      200,
      `PUT …/credentials ${profile}`,
    );
    await waitForConnection(session, id, `${profile} grant active`, (c) =>
      c.grants.some((x: Json) => x.profile === profile && x.status === 'active'),
    );
    if (profile === 'm365.mail_flow') await linkAndBind(o, id, domains);
  }
  expectStatus(
    await session.post(`/api-mode/connections/${id}/inventory-sync`, {}, idempotencyKey()),
    202,
    `inventory-sync (${o.slug})`,
  );
  await waitForApiConnection(
    o,
    id,
    `inventory ok (${o.slug})`,
    (c) => c.inventoryStatus === 'ok' && c.mailboxesTotal === mailboxes,
    300_000,
  );
  return id;
}

// --- clawback api ---------------------------------------------------------------------------------

async function clawbackDetail(o: Org, id: string, session?: ApiSession): Promise<Json> {
  const res = await (session ?? (await admin(o))).get(`/api-mode/clawbacks/${id}`);
  expectStatus(res, 200, 'GET /api-mode/clawbacks/{id}');
  return res.body as Json;
}

async function clawbackTargets(o: Org, id: string): Promise<Json[]> {
  const out: Json[] = [];
  let cursor: string | null = null;
  do {
    const res = await (
      await admin(o)
    ).get(
      `/api-mode/clawbacks/${id}/targets?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
    );
    expectStatus(res, 200, 'GET /api-mode/clawbacks/{id}/targets');
    out.push(...((res.body as Json).data as Json[]));
    cursor = (res.body as Json).nextCursor as string | null;
  } while (cursor);
  return out;
}

/** POST /api-mode/clawbacks (C14 #1) → the created public id (status `searching`). */
async function createClawback(o: Org, body: Json): Promise<string> {
  const res = await (await admin(o)).post('/api-mode/clawbacks', body, idempotencyKey());
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  expect(res.body).toMatchObject({ status: 'searching' });
  return (res.body as Json).id as string;
}

/** Waits until the api shows the clawback in one of `statuses`. */
function waitForClawbackView(
  o: Org,
  id: string,
  statuses: readonly string[],
  timeoutMs = 180_000,
): Promise<Json> {
  return waitFor(
    `clawback ${id} ${statuses.join('|')}`,
    async () => {
      const c = await clawbackDetail(o, id);
      return statuses.includes(c.status as string) ? c : undefined;
    },
    { timeoutMs, intervalMs: 1_500 },
  );
}

async function submitClawback(o: Org, id: string, body: Json): Promise<Json> {
  const detail = await clawbackDetail(o, id);
  const res = await (
    await admin(o)
  ).post(
    `/api-mode/clawbacks/${id}/submit`,
    { ...body, expectedRowVersion: detail.rowVersion },
    idempotencyKey(),
  );
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  return res.body as Json;
}

const finalStatuses: readonly string[] = FINAL_CLAWBACK_STATUSES;

/** The copy row of `address`'s mailbox for a Message-ID once `predicate` holds. */
const copyIn = (
  o: Org,
  address: string,
  messageId: string,
  predicate: Parameters<typeof waitForCopy>[4],
  timeoutMs?: number,
) => waitForCopy(fx.prisma, o.id, mailboxIdOf(o, address), messageId, predicate, timeoutMs);

const scanned = (c: { status: string; remediationState: string }) =>
  c.status === 'scanned' && c.remediationState !== 'pending';

async function registryMessage(organizationId: bigint, messageId: bigint) {
  return fx.prisma.emailMessage.findFirstOrThrow({
    where: { organizationId, id: messageId },
    select: { id: true, receivedAt: true },
  });
}

beforeAll(async () => {
  assertStackReady(gate);
  overridden = true;
  await recreateService('mailbox-worker', CLAWBACK_WORKER_SUITE_ENV);
  await recreateService('smtp-adapter', ADAPTER_SUITE_ENV);
  await pointPostfixNotifyAtRelaySink();
  notifyPointed = true;

  const enterprise = await fx.prisma.organizationPlan.findFirstOrThrow({
    where: { code: 'enterprise' },
    select: { id: true },
  });
  orgM = await fixtureOrganization('m', enterprise.id);
  orgG = await fixtureOrganization('g', enterprise.id);
  orgX = await fixtureOrganization('x', enterprise.id);
  for (const o of [orgM, orgG, orgX]) {
    await fx.feature(o.id, 'api_mode_protection', true);
    await fx.feature(o.id, 'journal_intake', true);
  }
  apiDom = await fx.domain(orgM.id, 'apiclaw-api', { inboundEnabled: false });
  hybDom = await fx.domain(orgM.id, 'apiclaw-hyb');
  await fx.destinations(hybDom, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  inlDom = await fx.domain(orgM.id, 'apiclaw-inl');
  await fx.destinations(inlDom, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  gDom = await fx.domain(orgG.id, 'apiclaw-goog', { inboundEnabled: false });
  xDom = await fx.domain(orgX.id, 'apiclaw-x', { inboundEnabled: false });

  const m = await admin(orgM);
  const g = await admin(orgG);
  const x = await admin(orgX);
  for (const [session, dom, mode] of [
    [m, apiDom, 'api'],
    [m, hybDom, 'hybrid'],
    [x, xDom, 'api'],
  ] as const) {
    expectStatus(
      await session.put(
        `/domains/${dom.publicId}/protection-mode`,
        { mode, reason: `stack test: API-mode clawback ${mode} domain` },
        idempotencyKey(),
      ),
      200,
      `PUT /domains/{id}/protection-mode ${mode}`,
    );
  }
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
  for (const [tenantId, app, domains] of [
    [tenantM, appM, [apiDom, hybDom]],
    [tenantX, appX, [xDom]],
  ] as const) {
    await fake.addMicrosoftTenant({
      tenantId,
      displayName: `API clawback ${fx.suffix}`,
      domains: domains.map((d, i) => ({
        name: d.name,
        isVerified: true,
        isDefault: i === 0,
        mxHost: null,
      })),
    });
    await fake.addMicrosoftApp({
      clientId: app.clientId,
      secret: app.secret,
      homeTenantId: tenantId,
      requiredRoles: [...M365_PERMISSIONS, ...MAILBOX_ROLES],
    });
    await fake.consent(tenantId, app.clientId, [...M365_PERMISSIONS, ...MAILBOX_ROLES]);
  }
  await fake.addGoogleCustomer({
    customerId: customerG,
    primaryDomain: gDom.name,
    organizationName: `API clawback G ${fx.suffix}`,
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
  const usersM = [
    alex(),
    blake(),
    casey(),
    reportBox(),
    hana(),
    ...BULK_USERS.map((u) => bulk(u)),
  ].map((address) => ({ id: guid(), address }));
  await sim.dataset({
    microsoft: {
      directories: [
        // One Microsoft directory: the Graph simulator maps provider-fake tokens to its first
        // directory, so the control organization X has no mailbox (it is API-active through its
        // connection and its `api` domain, which is what the threat-intelligence fan-out uses).
        simMicrosoftDirectory(tenantM, [apiDom.name, hybDom.name], usersM),
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

  connM = await microsoftConnection(orgM, appM, tenantM, [apiDom, hybDom], usersM.length);
  sourceM = await createSource(m, {
    kind: 'microsoft_365_journal',
    displayName: 'it-apiclaw M365 journal',
    providerConnectionId: connM,
  });
  connX = await microsoftConnection(orgX, appX, tenantX, [xDom], 0);

  // Google Workspace: mail-flow and mailbox grants (gmail.modify), inventory, history-poll feeds.
  const createdG = await g.post(
    '/provider-connections',
    { provider: 'google_workspace', displayName: `EXAMPLE API clawback G ${fx.suffix}` },
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
      c.grants.some((y: Json) => y.profile === profile && y.status === 'active'),
    );
    if (profile === 'google.mail_flow') await linkAndBind(orgG, connG, [gDom]);
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
  await putConnectionSettings(orgG, connG, { feedsEnabled: true });
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

  // Organization settings of M through the api (C14 #19, CAS null = create): the P2 threshold
  // stays at 50 distinct mailboxes (the §13 A5 value), everything else at the defaults.
  const settings = await m.get('/api-mode/settings');
  expectStatus(settings, 200, 'GET /api-mode/settings');
  expect(settings.body).toMatchObject({ source: 'defaults', rowVersion: null });
  const put = await m.put(
    '/api-mode/settings',
    {
      ...(settings.body as Json).settings,
      purgeApprovalMailboxes: 50,
      reason: 'stack test: P2 threshold 50 mailboxes',
      expectedRowVersion: null,
    },
    idempotencyKey(),
  );
  expectStatus(put, 200, 'PUT /api-mode/settings');
  expect(put.body).toMatchObject({ created: true, source: 'row' });

  // The report mailbox (C9.1): an API-side mailbox of the inventory, designated through the api.
  const reportMailbox = await mailboxByAddress(fx.prisma, orgM.id, reportBox());
  const designated = await m.put(
    `/api-mode/mailboxes/${reportMailbox!.publicId}/report-mailbox`,
    { enabled: true, reason: 'stack test: phishing report mailbox' },
    idempotencyKey(),
  );
  expectStatus(designated, 200, 'PUT /api-mode/mailboxes/{id}/report-mailbox');
  expect(designated.body).toMatchObject({ changed: true, mailbox: { reportMailbox: true } });

  // A second administrator of M (separation of duties) and the platform analyst (A4).
  approver = await apiSession(fx.prisma, { id: orgM.id, slug: orgM.slug }, 'organization_admin', {
    mfa: true,
  });
  sessions.push(approver);
  platform = await platformAdminSession(fx.prisma);
  record(LOG, {
    organizations: 3,
    domains: 5,
    connections: 3,
    simulator_users: usersM.length + 2,
  });
}, 1_200_000);

afterAll(async () => {
  if (gate.skip) return;
  const ids = [orgM, orgG, orgX].filter(Boolean).map((o) => o.id);
  for (const id of indicatorIds) {
    await platform
      ?.call(
        'DELETE',
        `/platform/threat-indicators/${id}?reason=stack%20test%20cleanup`,
        undefined,
        idempotencyKey(),
      )
      .catch(() => undefined);
  }
  await platform?.remove().catch(() => undefined);
  await sim.reset().catch(() => undefined);
  // Stop the worker first (recreated from .env) so no claim or flush writes behind the purge.
  if (overridden) await restoreService('mailbox-worker').catch(() => undefined);
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
  const rateKeys = (
    await Promise.all(ids.map((id) => fx.redis.keys(`mbx:rpt:${id.toString()}:*`)))
  ).flat();
  if (rateKeys.length > 0) await fx.redis.del(...rateKeys);
  await purgeProviderRows(fx.prisma, ids);
  await fx.prisma.auditLog.deleteMany({ where });
  for (const session of sessions) await session.remove().catch(() => undefined);
  const names = [apiDom, hybDom, inlDom, gDom, xDom].filter(Boolean).map((d) => d.name);
  for (const service of ['postfix', 'postfix-outbound'] as const) {
    const queued = involving(await listQueue(service), [...names, intakeDomain()]);
    await deleteQueued(
      service,
      queued.map((q) => q.queue_id),
    );
  }
  for (const d of names) await clearSinkDomain(d, 'all').catch(() => undefined);
  await clearSinkDomain('routing.integration.test', 'notify-relay-sink').catch(() => undefined);
  await clearSinkDomain('sender.example.test', 'notify-relay-sink').catch(() => undefined);
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
      clawbacks: 0,
      targets: 0,
      reports: 0,
      orgSettings: 0,
      quarantineEntries: 0,
    });
    expect(await check.organization.count({ where: { id: { in: ids } } })).toBe(0);
    expect(await check.providerConnection.count({ where })).toBe(0);
    expect(
      await check.organization.count({
        where: { slug: { startsWith: `it-apiclaw-${fx.suffix}` } },
      }),
    ).toBe(0);
    if (indicatorIds.size > 0) {
      expect(
        await check.threatIndicator.count({
          where: { id: { in: [...indicatorIds].map((i) => BigInt(i)) } },
        }),
      ).toBe(0);
    }
  } finally {
    await check.$disconnect();
  }
}, 900_000);

describe.skipIf(gate.skip)(
  'API-mode program acceptance: clawback, purge, internal mail, reports (step API-3 §13)',
  { timeout: 900_000 },
  () => {
    it('A1 intake → verdict: inline mailbox delivered without a copy, api mailbox journal copy never delivered, hybrid copy linked with inline authority', async () => {
      const messageId = messageIdOf('a1');
      const subject = subjectOf('a1');
      const original = syntheticEml({
        messageId,
        from: INLINE_SENDER,
        to: [ina(), hana(), alex()],
        subject,
        body: 'EXAMPLE quarterly newsletter: nothing to act on.',
      });
      // The mailboxes hold the message (feeds off for M: no feed copy; A10 acts on them later).
      const alexSim = await sim.deliver(alex(), original);
      const hanaSim = await sim.deliver(hana(), original);
      // The inline path: the gateway MX of the inline and hybrid domains delivers to mail-sink.
      const sent = await sendToMx({
        from: INLINE_SENDER,
        to: [ina(), hana()],
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
        'inline delivery to the inline and hybrid mailboxes',
        async () =>
          (await sinkFiles(ina())).length > 0 && (await sinkFiles(hana())).length > 0
            ? true
            : undefined,
        { timeoutMs: 120_000, intervalMs: 1_500 },
      );
      // The journal copy of the same message (the provider journals every recipient).
      await sendJournal({ messageId, to: [ina(), hana(), alex()], original, what: 'A1' });
      const msg = await waitForIntakeMessage(fx.prisma, orgM.id, `<${messageId}>`, 'journaled');
      const alexCopy = await copyIn(orgM, alex(), messageId, scanned);
      const hanaCopy = await copyIn(orgM, hana(), messageId, scanned);
      expect(alexCopy).toMatchObject({
        source: 'journal',
        direction: 'inbound',
        verdictAuthority: 'copy',
        messageId: msg.id,
        messageIdHash: copyMessageIdHash(orgM.id, messageId),
      });
      expect(alexCopy.verdict).not.toBeNull();
      expect(alexCopy.lagMs).not.toBeNull();
      expect(hanaCopy).toMatchObject({
        source: 'journal',
        verdictAuthority: 'inline',
        inlineMessageId: inline.id,
      });
      expect(hanaCopy.lagMs).not.toBeNull();
      // Only the API-side recipients have copies; the inline mailbox has none.
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, messageId: msg.id },
        }),
      ).toBe(2);
      expect(await mailboxByAddress(fx.prisma, orgM.id, ina())).toBeUndefined();
      // The journal copy is never delivered (N1): no delivery row, nothing for the api mailbox.
      expect(await fx.prisma.emailDelivery.count({ where: { messageId: msg.id } })).toBe(0);
      expect(await sinkFiles(alex())).toEqual([]);
      shared.a1 = {
        messageId,
        alexCopyId: alexCopy.id,
        alexSim: alexSim.messageId,
        hanaSim: hanaSim.messageId,
      };
      record(LOG, {
        case: 'A1',
        api_verdict: alexCopy.verdict,
        api_lag_ms: alexCopy.lagMs,
        hybrid_authority: hanaCopy.verdictAuthority,
        hybrid_verdict: hanaCopy.verdict,
        inline_delivered: true,
      });
    });

    it('A2 verdict → remediation → restore: EICAR journal copy → P1 hidden quarantine folder → mailbox entry → operator restore with a second approver → Inbox', async () => {
      const messageId = messageIdOf('a2');
      const original = eicarEml(messageId, EXTERNAL_SENDER, [alex()], subjectOf('a2'));
      const delivered = await sim.deliver(alex(), original);
      await sendJournal({ messageId, to: [alex()], original, what: 'A2' });
      const copy = await copyIn(
        orgM,
        alex(),
        messageId,
        (c) => c.remediationState === 'remediated',
      );
      expect(copy).toMatchObject({ verdict: 'malware', remediationAction: 'move_quarantine' });
      const location = await simLocation(alex(), delivered.messageId);
      expect(location.folder).toMatchObject({ displayName: QUARANTINE_FOLDER, isHidden: true });
      const [entry] = await mailboxEntriesOfCopy(fx.prisma, orgM.id, copy.id);
      expect(entry).toMatchObject({ location: 'mailbox', status: 'held', hasHardBlock: true });
      const m = await admin(orgM);
      const requested = await m.post(
        `/quarantine/entries/${entry!.publicId}/release`,
        { reason: 'stack test: restore the mailbox copy' },
        idempotencyKey(),
      );
      expect(requested.status, JSON.stringify(requested.body)).toBe(202);
      expect(requested.body).toMatchObject({ outcome: 'approval_requested' });
      const approved = await approver!.post(
        `/quarantine/approvals/${(requested.body as Json).approvalRequestId as string}/approve`,
        { reason: 'stack test: second person approves the restore' },
        idempotencyKey(),
      );
      expect(approved.status, JSON.stringify(approved.body)).toBe(202);
      await waitForEntryRow(fx.prisma, entry!.id, 'released', (e) => e.status === 'released');
      await waitForAction(
        fx.prisma,
        orgM.id,
        copy.id,
        'restore_inbox succeeded',
        (a) => a.action === 'restore_inbox' && a.status === 'succeeded',
      );
      const inbox = await simLocation(alex(), delivered.messageId);
      expect(inbox.folder?.wellKnownName).toBe('inbox');
      record(LOG, { case: 'A2', verdict: copy.verdict, folder_after: inbox.folder?.wellKnownName });
    });

    it('A3 late sandbox verdict → clawback (fallback: the finalizer outbox row) → policy → the copy in every recipient mailbox (api and hybrid) moved; detections show verdictRevision 1', async () => {
      const messageId = messageIdOf('a3');
      const otherMessageId = messageIdOf('a3b');
      const content = benignAttachment('a3');
      const attachment = { filename: 'statement.txt', contentType: 'text/plain', content };
      const original = syntheticEml({
        messageId,
        from: INLINE_SENDER,
        to: [blake(), hana()],
        subject: subjectOf('a3'),
        attachment,
      });
      // A second message carrying the same attachment (matched by the attachment key only).
      const other = syntheticEml({
        messageId: otherMessageId,
        from: EXTERNAL_SENDER,
        to: [casey()],
        subject: subjectOf('a3b'),
        attachment,
      });
      const blakeSim = await sim.deliver(blake(), original);
      const hanaSim = await sim.deliver(hana(), original);
      const caseySim = await sim.deliver(casey(), other);
      // Hybrid: the gateway sees the message inline first.
      const sent = await sendToMx({
        from: INLINE_SENDER,
        to: [hana()],
        helo: 'mx.clean.scan.test',
        data: original,
      });
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      await waitForMessage(fx.prisma, orgM.id, { mtaQueueId: sent.queueId! }, 120_000);
      await sendJournal({
        messageId,
        sender: INLINE_SENDER,
        to: [blake(), hana()],
        original,
        what: 'A3',
      });
      await sendJournal({ messageId: otherMessageId, to: [casey()], original: other, what: 'A3b' });
      const blakeCopy = await copyIn(orgM, blake(), messageId, scanned);
      const hanaCopy = await copyIn(orgM, hana(), messageId, scanned);
      const caseyCopy = await copyIn(orgM, casey(), otherMessageId, scanned);
      expect(hanaCopy.verdictAuthority).toBe('inline');
      // Before the signal: nothing stronger than P1's tag of a synthetic `suspicious` body (the
      // clawback escalates a tag, C5.3).
      for (const c of [blakeCopy, hanaCopy, caseyCopy]) {
        expect([null, 'tag']).toContain(c.remediationAction);
      }
      const message = await registryMessage(orgM.id, blakeCopy.messageId);
      const attachmentSha = sha256Hex(content);
      expect(
        await fx.prisma.emailAttachment.count({
          where: { organizationId: orgM.id, sha256: attachmentSha },
        }),
      ).toBeGreaterThanOrEqual(2);
      // The sandbox finalizer's late-signal row for a raising revision 1 (C2.1).
      const signal = await writeSandboxLateSignal(fx.prisma, {
        organizationId: orgM.id,
        message,
        verdict: 'malware',
        level: 'critical',
        hardBlocks: ['hb.sandbox.malicious'],
        attachmentSha256: [attachmentSha],
      });
      await waitForPublished(fx.prisma, signal.eventId);
      const clawback = await waitForClawback(
        fx.prisma,
        orgM.id,
        'late_verdict completed',
        (c) => c.trigger === 'late_verdict' && finalStatuses.includes(c.status),
        240_000,
      );
      expect(clawback).toMatchObject({
        status: 'completed',
        decisionMode: 'policy',
        signalVerdict: 'malware',
        signalLevel: 'critical',
        requestedByType: 'system',
        targetsSucceeded: 3,
        targetsFailed: 0,
      });
      expect(clawback.signalKey).toMatch(/^[0-9a-f]{64}$/);
      const targets = await targetsOf(fx.prisma, clawback.id);
      expect(targets.map((t) => t.status)).toEqual(['succeeded', 'succeeded', 'succeeded']);
      expect(new Set(targets.map((t) => t.plannedAction))).toEqual(new Set(['move_quarantine']));
      const byCopy = new Map(targets.map((t) => [t.copyId.toString(), t]));
      expect(byCopy.get(blakeCopy.id.toString())!.matchKeys).toEqual(
        expect.arrayContaining(['message_id', 'attachment']),
      );
      expect(byCopy.get(caseyCopy.id.toString())!.matchKeys).toEqual(['attachment']);
      for (const c of [blakeCopy, hanaCopy, caseyCopy]) {
        const actions = await actionsOfCopy(fx.prisma, orgM.id, c.id);
        const act = actions.find((a) => a.trigger === 'clawback');
        expect(act).toMatchObject({
          action: 'move_quarantine',
          status: 'succeeded',
          clawbackId: clawback.id,
        });
        expect((act!.decision as Json).inputs.verdictAuthority).toBe('copy');
        expect((act!.decision as Json).notes).toEqual(expect.arrayContaining(['source:clawback']));
      }
      for (const [user, simId] of [
        [blake(), blakeSim.messageId],
        [hana(), hanaSim.messageId],
        [casey(), caseySim.messageId],
      ] as const) {
        const l = await simLocation(user, simId);
        expect(l.folder?.displayName, user).toBe(QUARANTINE_FOLDER);
      }
      // C3.3: the copies of the signal's own message carry the raised verdict (revision 1).
      for (const c of [blakeCopy, hanaCopy]) {
        const res = await (await admin(orgM)).get(`/api-mode/detections/${c.publicId}`);
        expectStatus(res, 200, 'GET /api-mode/detections/{id}');
        expect(res.body).toMatchObject({ verdictRevision: 1, verdict: 'malware' });
        expect((res.body as Json).clawbacks as string[]).toContain(clawback.publicId);
      }
      const otherView = await (await admin(orgM)).get(`/api-mode/detections/${caseyCopy.publicId}`);
      expect((otherView.body as Json).verdictRevision).toBe(0);
      // A redelivered / repeated signal creates nothing new (one clawback per signal key, C2.5).
      const again = await writeSandboxLateSignal(fx.prisma, {
        organizationId: orgM.id,
        message,
        verdict: 'malware',
        level: 'critical',
        hardBlocks: ['hb.sandbox.malicious'],
        attachmentSha256: [attachmentSha],
        signalAt: new Date(signal.payload.signalAt),
      });
      await waitForPublished(fx.prisma, again.eventId);
      await sleep(5_000);
      expect(
        (await clawbacksOf(fx.prisma, orgM.id)).filter((c) => c.trigger === 'late_verdict'),
      ).toHaveLength(1);
      const detail = await clawbackDetail(orgM, clawback.publicId);
      expect(detail).toMatchObject({ trigger: 'late_verdict', signalKind: 'sandbox_revision' });
      record(LOG, {
        case: 'A3',
        path: 'fallback_outbox_row',
        clawback: clawback.status,
        targets: targets.length,
        hybrid_authority_decided: 'copy',
        verdict_revision: 1,
      });
    });

    it('A4 threat intel → clawback: a platform url indicator (severity high) for a URL in earlier clean copies of two organizations → only those get clawbacks and the copies move; the control organization gets none', async () => {
      const url = `https://login-${fx.suffix}.clawback-phish.example.com/verify?session=it`;
      const body = `EXAMPLE account notice. Review it at ${url} today.`;
      const mId = messageIdOf('a4m');
      const gId = messageIdOf('a4g');
      const originalM = syntheticEml({
        messageId: mId,
        from: EXTERNAL_SENDER,
        to: [casey()],
        subject: subjectOf('a4'),
        body,
      });
      const caseySim = await sim.deliver(casey(), originalM);
      await sendJournal({ messageId: mId, to: [casey()], original: originalM, what: 'A4' });
      const ginaSim = await sim.deliver(
        gina(),
        syntheticEml({
          messageId: gId,
          from: EXTERNAL_SENDER,
          to: [gina()],
          subject: subjectOf('a4'),
          body,
        }),
      );
      const caseyCopy = await copyIn(orgM, casey(), mId, scanned);
      const ginaCopy = await copyIn(orgG, gina(), gId, scanned);
      for (const c of [caseyCopy, ginaCopy]) {
        expect(['malware', 'phishing']).not.toContain(c.verdict);
      }
      // The control organization is API-active (connection synced, `api` domain; no mailbox).
      expect(await connection(orgX, connX)).toMatchObject({
        inventoryStatus: 'ok',
        mailboxesTotal: 0,
      });
      const clawbacksXBefore = await fx.prisma.apiClawback.count({
        where: { organizationId: orgX.id },
      });
      const added = await platform!.call(
        'POST',
        '/platform/threat-indicators',
        {
          type: 'url',
          value: url,
          severity: 'high',
          category: 'phishing',
          reason: 'stack test: API-mode threat-intelligence clawback',
        },
        idempotencyKey(),
      );
      expect(added.status, JSON.stringify(added.body)).toBe(201);
      const indicatorId = added.body.id as string;
      indicatorIds.add(indicatorId);
      // The indicator's identity hash is the hash the URL extractor stored for both copies.
      for (const [o, c] of [
        [orgM, caseyCopy],
        [orgG, ginaCopy],
      ] as const) {
        const urls = await fx.prisma.messageUrl.findMany({
          where: { organizationId: o.id, messageId: c.messageId },
          select: { urlSha256: true },
        });
        expect(urls.map((u) => u.urlSha256)).toContain(added.body.valueSha256);
      }
      const done = (o: Org) =>
        waitForClawback(
          fx.prisma,
          o.id,
          `threat_intel completed (${o.slug})`,
          (c) => c.trigger === 'threat_intel' && finalStatuses.includes(c.status),
          240_000,
        );
      const [cm, cg] = [await done(orgM), await done(orgG)];
      for (const c of [cm, cg]) {
        expect(c).toMatchObject({
          status: 'completed',
          decisionMode: 'policy',
          signalVerdict: 'phishing',
          signalLevel: 'high',
          targetsSucceeded: 1,
        });
        expect(c.signalHardBlocks).toEqual(['hb.clawback.threat_intel']);
      }
      const [tm] = await targetsOf(fx.prisma, cm.id);
      expect(tm).toMatchObject({ copyId: caseyCopy.id, plannedAction: 'move_quarantine' });
      expect(tm!.matchKeys).toEqual(['url']);
      const moved = await simLocation(casey(), caseySim.messageId);
      expect(moved.folder?.displayName).toBe(QUARANTINE_FOLDER);
      const movedG = await simLocation(gina(), ginaSim.messageId);
      expect(movedG.labelIds).not.toContain('INBOX');
      // Two more sweeps: the control organization (API-active, no copy with the URL) gets none.
      await sleep(12_000);
      expect(await fx.prisma.apiClawback.count({ where: { organizationId: orgX.id } })).toBe(
        clawbacksXBefore,
      );
      // The platform indicator is removed again (it would also block the URL at scan time).
      const removed = await platform!.call(
        'DELETE',
        `/platform/threat-indicators/${indicatorId}?reason=stack%20test`,
        undefined,
        idempotencyKey(),
      );
      expect([200, 204]).toContain(removed.status);
      indicatorIds.delete(indicatorId);
      record(LOG, {
        case: 'A4',
        m_clawback: cm.status,
        g_clawback: cg.status,
        x_clawbacks: 0,
        facts: `${cm.signalVerdict}/${cm.signalLevel}`,
        gmail_labels: movedG.labelIds.join(','),
      });
    });

    it('A5 admin search and purge: by Message-ID over 3 mailboxes → preview → submit move_junk; by sender + subject over 60 mailboxes → pending_approval → requester refused → second admin approves → per-mailbox results → bulk restore → Inbox', async () => {
      // (a) Message-ID across alex, blake, casey; below the threshold.
      const messageId = messageIdOf('a5');
      const recipients = [alex(), blake(), casey()];
      const original = syntheticEml({
        messageId,
        from: EXTERNAL_SENDER,
        to: recipients,
        subject: subjectOf('a5'),
        body: 'EXAMPLE invoice reminder for the stack test.',
      });
      const sims = new Map<string, string>();
      for (const r of recipients) sims.set(r, (await sim.deliver(r, original)).messageId);
      await sendJournal({ messageId, to: recipients, original, what: 'A5a' });
      for (const r of recipients) await copyIn(orgM, r, messageId, scanned);
      const now = Date.now();
      const id = await createClawback(orgM, {
        criteria: {
          messageId: `<${messageId}>`,
          from: new Date(now - 3_600_000).toISOString(),
          to: new Date(now + 60_000).toISOString(),
        },
        reason: 'stack test: purge by Message-ID',
      });
      const ready = await waitForClawbackView(orgM, id, ['ready', 'no_match', 'failed']);
      expect(ready).toMatchObject({
        status: 'ready',
        trigger: 'admin',
        counts: { targetsEligible: 3, mailboxesEligible: 3 },
        hints: { canSubmit: true },
      });
      const preview = await clawbackTargets(orgM, id);
      expect(preview.map((t) => t.mailbox.address).sort()).toEqual([...recipients].sort());
      expect(
        preview.every((t) => t.status === 'matched' && t.matchKeys.includes('message_id')),
      ).toBe(true);
      const submitted = await submitClawback(orgM, id, {
        mode: 'explicit',
        action: 'move_junk',
        reason: 'stack test: junk it',
      });
      expect(submitted).toMatchObject({ status: 'queued', requiresApproval: false });
      const doneA = await waitForClawbackView(orgM, id, finalStatuses, 240_000);
      expect(doneA).toMatchObject({ status: 'completed', counts: { succeeded: 3, failed: 0 } });
      for (const r of recipients) {
        expect((await simLocation(r, sims.get(r)!)).folder?.wellKnownName, r).toBe('junkemail');
      }

      // (b) sender + subject over 60 mailboxes (P2 threshold 50 → second approver).
      const bulkId = messageIdOf('a5bulk');
      const bulkSubject = subjectOf('a5 bulk newsletter');
      const bulkRecipients = BULK_USERS.map((u) => bulk(u));
      const bulkOriginal = syntheticEml({
        messageId: bulkId,
        from: EXTERNAL_SENDER,
        to: bulkRecipients,
        subject: bulkSubject,
        body: 'EXAMPLE bulk announcement for the stack test.',
      });
      const bulkSims = new Map<string, string>();
      for (const r of bulkRecipients)
        bulkSims.set(r, (await sim.deliver(r, bulkOriginal)).messageId);
      await sendJournal({
        messageId: bulkId,
        to: bulkRecipients,
        original: bulkOriginal,
        what: 'A5b',
      });
      const hash = copyMessageIdHash(orgM.id, bulkId);
      await waitFor(
        '60 scanned copies of the bulk message',
        async () => {
          const n = await fx.prisma.apiMessageCopy.count({
            // Scanned and decided (P1 tags a synthetic `suspicious` body; a search materialized
            // while a copy's action is pending skips it as remediation_in_progress, C5.2).
            where: {
              organizationId: orgM.id,
              messageIdHash: hash,
              status: 'scanned',
              remediationState: { not: 'pending' },
            },
          });
          return n === BULK ? n : undefined;
        },
        { timeoutMs: 300_000, intervalMs: 2_000 },
      );
      const t = Date.now();
      const bulkClawback = await createClawback(orgM, {
        criteria: {
          sender: EXTERNAL_SENDER.toUpperCase(),
          subject: `RE: ${bulkSubject}`,
          from: new Date(t - 3_600_000).toISOString(),
          to: new Date(t + 60_000).toISOString(),
        },
        reason: 'stack test: purge a campaign by sender and subject',
      });
      const bulkReady = await waitForClawbackView(orgM, bulkClawback, [
        'ready',
        'no_match',
        'failed',
      ]);
      expect(bulkReady).toMatchObject({
        status: 'ready',
        counts: { targetsEligible: BULK, mailboxesEligible: BULK },
      });
      expect(bulkReady.criteria.keys.senderSubject).toMatchObject({ sender: EXTERNAL_SENDER });
      const pending = await submitClawback(orgM, bulkClawback, {
        mode: 'explicit',
        action: 'move_junk',
        reason: 'stack test: junk the campaign',
      });
      expect(pending).toMatchObject({
        status: 'pending_approval',
        requiresApproval: true,
        approvalReasons: ['mailbox_threshold'],
      });
      shared.a5ApprovalClawback = bulkClawback;
      // The requester cannot approve (C6: separation by user id).
      const self = await (
        await admin(orgM)
      ).post(
        `/api-mode/clawbacks/${bulkClawback}/approve`,
        { reason: 'stack test: self approve', expectedRowVersion: pending.rowVersion },
        idempotencyKey(),
      );
      expect(self.status, JSON.stringify(self.body)).toBe(403);
      expect(JSON.stringify(self.body)).toContain('api_mode_purge_approval_forbidden');
      expect(JSON.stringify(self.body)).toContain('requester');
      const asApprover = await clawbackDetail(orgM, bulkClawback, approver);
      expect(asApprover.hints.canApprove).toBe(true);
      const approved = await approver!.post(
        `/api-mode/clawbacks/${bulkClawback}/approve`,
        {
          reason: 'stack test: second admin approves the purge',
          expectedRowVersion: asApprover.rowVersion,
        },
        idempotencyKey(),
      );
      expect(approved.status, JSON.stringify(approved.body)).toBe(200);
      const bulkDone = await waitForClawbackView(orgM, bulkClawback, finalStatuses, 420_000);
      expect(bulkDone).toMatchObject({
        status: 'completed',
        counts: { succeeded: BULK, failed: 0 },
        approval: { status: 'approved' },
      });
      const row = await fx.prisma.apiClawback.findUniqueOrThrow({
        where: { publicId: bulkClawback },
      });
      expect(row.approvedByUserId).toBe(approver!.userId);
      expect(row.approverPermissionsHash).toMatch(/^[0-9a-f]{64}$/);
      // Per-mailbox results: one succeeded target per distinct mailbox.
      const results = await clawbackTargets(orgM, bulkClawback);
      expect(new Set(results.map((r) => r.mailbox.id)).size).toBe(BULK);
      expect(results.every((r) => r.status === 'succeeded' && r.remediationId !== null)).toBe(true);
      for (const r of bulkRecipients.slice(0, 5)) {
        expect((await simLocation(r, bulkSims.get(r)!)).folder?.wellKnownName, r).toBe('junkemail');
      }
      // Bulk restore (C7): every entry released → restore_inbox → back in the Inbox.
      const restore = await (
        await admin(orgM)
      ).post(
        `/api-mode/clawbacks/${bulkClawback}/restore`,
        { reason: 'stack test: it was a legitimate newsletter' },
        idempotencyKey(),
      );
      expect(restore.status, JSON.stringify(restore.body)).toBe(202);
      const restored = await waitForClawbackState(
        fx.prisma,
        bulkClawback,
        'restore completed',
        (c) => c.restoreStatus === 'completed' || c.restoreStatus === 'completed_with_errors',
        420_000,
      );
      expect(restored).toMatchObject({
        restoreStatus: 'completed',
        restoresSucceeded: BULK,
        restoresFailed: 0,
      });
      for (const r of bulkRecipients) {
        expect((await simLocation(r, bulkSims.get(r)!)).folder?.wellKnownName, r).toBe('inbox');
      }
      expect(
        await fx.prisma.auditLog.count({
          where: {
            organizationId: orgM.id,
            action: { in: ['api_mode.clawback_approved', 'api_mode.clawback_restore_requested'] },
          },
        }),
      ).toBeGreaterThanOrEqual(2);
      record(LOG, {
        case: 'A5',
        message_id_purge: doneA.status,
        bulk_targets: BULK,
        approval_reasons: (pending.approvalReasons as string[]).join(','),
        self_approve: self.status,
        bulk: bulkDone.status,
        restored: restored.restoresSucceeded,
      });
    });

    it('A6 throttling: a scripted 429 Retry-After: 2 during a purge → paused and resumed, the attempt not counted, remediation_throttled counted', async () => {
      const row = await apiConnectionRow(connM);
      const before = await remediationCounterSums(fx.prisma, row.id);
      const messageId = messageIdOf('a6');
      const original = syntheticEml({
        messageId,
        from: EXTERNAL_SENDER,
        to: [blake()],
        subject: subjectOf('a6'),
      });
      const delivered = await sim.deliver(blake(), original);
      await sendJournal({ messageId, to: [blake()], original, what: 'A6' });
      const copy = await copyIn(orgM, blake(), messageId, scanned);
      const now = Date.now();
      const id = await createClawback(orgM, {
        criteria: {
          messageId,
          from: new Date(now - 3_600_000).toISOString(),
          to: new Date(now + 60_000).toISOString(),
        },
        reason: 'stack test: purge under throttling',
      });
      await waitForClawbackView(orgM, id, ['ready']);
      await sim.inject({
        family: 'graph_messages',
        method: 'POST',
        status: 429,
        retryAfter: '2',
        times: 1,
      });
      const submitted = await submitClawback(orgM, id, {
        mode: 'explicit',
        action: 'move_quarantine',
        reason: 'stack test: quarantine it',
      });
      expect(submitted.status).toBe('queued');
      const done = await waitForClawbackView(orgM, id, finalStatuses, 240_000);
      expect(done).toMatchObject({ status: 'completed', counts: { succeeded: 1 } });
      const action = (await actionsOfCopy(fx.prisma, orgM.id, copy.id)).find(
        (a) => a.trigger === 'purge',
      );
      expect(action).toMatchObject({ status: 'succeeded', attempts: 1, lastErrorCode: null });
      const throttled = (await sim.calls({ simulator: 'graph' })).filter(
        (c) => c.status === 429 && c.method === 'POST' && c.path.endsWith('/move'),
      );
      expect(throttled.length).toBeGreaterThanOrEqual(1);
      const after = await waitFor(
        'remediation_throttled counted',
        async () => {
          const s = await remediationCounterSums(fx.prisma, row.id);
          return s.throttled > before.throttled ? s : undefined;
        },
        { timeoutMs: 90_000, intervalMs: 2_000 },
      );
      expect((await simLocation(blake(), delivered.messageId)).folder?.displayName).toBe(
        QUARANTINE_FOLDER,
      );
      record(LOG, {
        case: 'A6',
        throttled_calls: throttled.length,
        remediation_throttled: after.throttled - before.throttled,
        attempts: action!.attempts,
      });
    });

    it('A7 internal mail: internal EICAR (org sender → api and hybrid recipients) journaled → two internal copies → P1 → moved; a second journal report → duplicates; an outbound-only message → no copy; no delivery attempt', async () => {
      const messageId = messageIdOf('a7');
      const original = eicarEml(messageId, alex(), [blake(), hana()], subjectOf('a7 internal'));
      const blakeSim = await sim.deliver(blake(), original);
      const hanaSim = await sim.deliver(hana(), original);
      await sendJournal({ messageId, sender: alex(), to: [blake(), hana()], original, what: 'A7' });
      const msg = await waitForIntakeMessage(fx.prisma, orgM.id, `<${messageId}>`, 'journaled');
      const copies = [
        await copyIn(orgM, blake(), messageId, (c) => c.remediationState === 'remediated'),
        await copyIn(orgM, hana(), messageId, (c) => c.remediationState === 'remediated'),
      ];
      for (const c of copies) {
        expect(c).toMatchObject({
          direction: 'internal',
          verdict: 'malware',
          verdictAuthority: 'copy',
          remediationAction: 'move_quarantine',
        });
      }
      expect((await simLocation(blake(), blakeSim.messageId)).folder?.displayName).toBe(
        QUARANTINE_FOLDER,
      );
      expect((await simLocation(hana(), hanaSim.messageId)).folder?.displayName).toBe(
        QUARANTINE_FOLDER,
      );
      // The sender is never a copy (journal recipients only).
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, messageId: msg.id },
        }),
      ).toBe(2);
      // A second journal report of the same message: duplicates, no new copy.
      await sendJournal({
        messageId,
        sender: alex(),
        to: [blake(), hana()],
        original,
        what: 'A7 dup',
      });
      await waitFor(
        'the second journal report processed',
        async () => {
          const n = await fx.prisma.emailMessage.count({
            where: { organizationId: orgM.id, internetMessageId: `<${messageId}>` },
          });
          return n >= 2 ? n : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 1_500 },
      ).catch(() => undefined);
      await sleep(8_000);
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, messageIdHash: copyMessageIdHash(orgM.id, messageId) },
        }),
      ).toBe(2);
      // Outbound-only: org sender, external recipient only → no copy, no mailbox discovered.
      const outId = messageIdOf('a7out');
      const outbound = syntheticEml({
        messageId: outId,
        from: alex(),
        to: [PARTNER],
        subject: subjectOf('a7 outbound'),
      });
      await sendJournal({
        messageId: outId,
        sender: alex(),
        to: [PARTNER],
        original: outbound,
        what: 'A7 out',
      });
      const outMsg = await waitForIntakeMessage(
        fx.prisma,
        orgM.id,
        `<${outId}>`,
        'journaled',
      ).catch(() => undefined);
      await sleep(8_000);
      expect(
        await fx.prisma.apiMessageCopy.count({
          where: { organizationId: orgM.id, messageIdHash: copyMessageIdHash(orgM.id, outId) },
        }),
      ).toBe(0);
      expect(await mailboxByAddress(fx.prisma, orgM.id, PARTNER)).toBeUndefined();
      // Never delivered (N1).
      for (const id of [msg.id, ...(outMsg ? [outMsg.id] : [])]) {
        expect(await fx.prisma.emailDelivery.count({ where: { messageId: id } })).toBe(0);
        expect(
          await fx.prisma.messageOutbox.count({
            where: { aggregateId: id.toString(), eventType: { startsWith: 'mail.delivery.' } },
          }),
        ).toBe(0);
      }
      record(LOG, {
        case: 'A7',
        internal_copies: copies.length,
        action: copies[0]!.remediationAction,
        duplicate_copies: 0,
        outbound_only_copies: 0,
      });
    });

    it('A8 report: a forward-as-attachment report → original found by Message-ID → pending_triage (malicious) → ack e-mail → resolved malicious → result e-mail → clawback from the report → every copy removed; inline forward matched by sender + subject; external reporter rejected without e-mail', async () => {
      const m = await admin(orgM);
      // The original's copies stay in the mailboxes: remediation paused for M while it arrives
      // (copies `skipped remediation_paused`); an admin purge is not stopped by the pause (C3.4).
      await putConnectionSettings(orgM, connM, { feedsEnabled: false, remediationPaused: true });
      const messageId = messageIdOf('a8');
      const subject = subjectOf('a8 urgent payroll');
      const recipients = [alex(), blake(), casey()];
      const date = new Date();
      const original = syntheticEml({
        messageId,
        from: EXTERNAL_SENDER,
        to: recipients,
        subject,
        date,
        attachment: { filename: 'eicar.com', content: eicar() },
      });
      const sims = new Map<string, string>();
      for (const r of recipients) sims.set(r, (await sim.deliver(r, original)).messageId);
      await sendJournal({ messageId, to: recipients, original, what: 'A8 original' });
      for (const r of recipients) {
        const c = await copyIn(
          orgM,
          r,
          messageId,
          (x) => x.status === 'scanned' && x.remediationState === 'skipped',
        );
        expect(c.verdict).toBe('malware');
      }
      await putConnectionSettings(orgM, connM, { feedsEnabled: false, remediationPaused: false });

      // (1) alex forwards it as an attachment to the report mailbox (internal journal copy).
      const fwdId = messageIdOf('a8fwd');
      await sendJournal({
        messageId: fwdId,
        sender: alex(),
        to: [reportBox()],
        original: forwardAsAttachmentEml({
          messageId: fwdId,
          reporter: alex(),
          reportMailbox: reportBox(),
          original,
        }),
        what: 'A8 report',
      });
      const report = await waitForReport(
        fx.prisma,
        orgM.id,
        alex(),
        'pending_triage',
        (r) => r.status === 'pending_triage' || r.status === 'rejected',
        240_000,
      );
      const alexCopy = await copyIn(orgM, alex(), messageId, () => true);
      expect(report).toMatchObject({
        status: 'pending_triage',
        identification: 'attachment',
        assessment: 'malicious',
        originalCopyId: alexCopy.id,
        originalMessageIdHash: copyMessageIdHash(orgM.id, messageId),
        ackFeedback: 'queued',
      });
      // The report copy gets no remediation (C-I5).
      const reportCopy = await copyIn(orgM, reportBox(), fwdId, (c) => c.status === 'scanned');
      expect(await actionsOfCopy(fx.prisma, orgM.id, reportCopy.id)).toEqual([]);
      const ack = await waitFor(
        'the acknowledgement e-mail at notify-relay-sink',
        async () =>
          (await sinkMessages(alex(), 'notify-relay-sink'))
            .map((b) => decodedMailText(b))
            .find((t) => t.includes('We received your report')),
        { timeoutMs: 180_000, intervalMs: 3_000 },
      );
      expect(ack).toContain(report.publicId);
      expect(ack).not.toContain(subject);

      // (2) blake forwards it inline (no Message-ID): matched by sender + subject.
      const inlineId = messageIdOf('a8inl');
      await sendJournal({
        messageId: inlineId,
        sender: blake(),
        to: [reportBox()],
        original: inlineForwardEml({
          messageId: inlineId,
          reporter: blake(),
          reportMailbox: reportBox(),
          originalFrom: `EXAMPLE Sender <${EXTERNAL_SENDER}>`,
          originalTo: blake(),
          originalSubject: subject,
          originalDate: date,
        }),
        what: 'A8 inline report',
      });
      const blakeCopy = await copyIn(orgM, blake(), messageId, () => true);
      const inlineReport = await waitForReport(
        fx.prisma,
        orgM.id,
        blake(),
        'inline pending_triage',
        (r) => r.status === 'pending_triage' || r.status === 'rejected',
        240_000,
      );
      expect(inlineReport).toMatchObject({
        status: 'pending_triage',
        identification: 'inline',
        originalCopyId: blakeCopy.id,
      });

      // (3) an external reporter: rejected, no e-mail.
      const extId = messageIdOf('a8ext');
      await sendJournal({
        messageId: extId,
        sender: OUTSIDER,
        to: [reportBox()],
        original: forwardAsAttachmentEml({
          messageId: extId,
          reporter: OUTSIDER,
          reportMailbox: reportBox(),
          original,
        }),
        what: 'A8 external report',
      });
      const rejected = await waitForReport(
        fx.prisma,
        orgM.id,
        OUTSIDER,
        'rejected external_reporter',
        (r) => r.status === 'rejected',
        240_000,
      );
      expect(rejected.rejectReason).toBe('external_reporter');
      // No acknowledgement for a rejected report (C10.6): `skipped`, never `queued`.
      expect(rejected.ackFeedback).not.toBe('queued');

      // The analyst resolves the report as malicious and notifies the reporter.
      const view = await m.get(`/api-mode/reports/${report.publicId}`);
      expectStatus(view, 200, 'GET /api-mode/reports/{id}');
      expect(view.body).toMatchObject({
        assessment: 'malicious',
        originalDetectionId: alexCopy.publicId,
      });
      const triaged = await m.post(
        `/api-mode/reports/${report.publicId}/triage`,
        {
          status: 'resolved',
          verdict: 'malicious',
          notifyReporter: true,
          expectedRowVersion: (view.body as Json).rowVersion,
        },
        idempotencyKey(),
      );
      expect(triaged.status, JSON.stringify(triaged.body)).toBe(200);
      expect(triaged.body).toMatchObject({
        report: { status: 'resolved', analystVerdict: 'malicious' },
      });
      const result = await waitFor(
        'the result e-mail at notify-relay-sink',
        async () =>
          (await sinkMessages(alex(), 'notify-relay-sink'))
            .map((b) => decodedMailText(b))
            .find((t) => t.includes('the message was dangerous')),
        { timeoutMs: 180_000, intervalMs: 3_000 },
      );
      expect(result).not.toContain(subject);
      expect(await sinkFiles(OUTSIDER, 'notify-relay-sink')).toEqual([]);

      // Clawback from the report → preview → submit → every copy removed.
      const fromReport = await m.post(
        `/api-mode/reports/${report.publicId}/clawback`,
        { reason: 'stack test: remove the reported phishing everywhere' },
        idempotencyKey(),
      );
      expect(fromReport.status, JSON.stringify(fromReport.body)).toBe(202);
      expect(fromReport.body).toMatchObject({ trigger: 'report', status: 'searching' });
      const clawbackId = (fromReport.body as Json).clawbackId as string;
      const ready = await waitForClawbackView(orgM, clawbackId, ['ready', 'no_match', 'failed']);
      expect(ready.status).toBe('ready');
      expect(ready.reportId).toBe(report.publicId);
      const preview = await clawbackTargets(orgM, clawbackId);
      expect(preview.map((t) => t.mailbox.address).sort()).toEqual([...recipients].sort());
      const submitted = await submitClawback(orgM, clawbackId, {
        mode: 'explicit',
        action: 'move_quarantine',
        reason: 'stack test: quarantine the reported message',
      });
      expect(submitted.status).toBe('queued');
      const done = await waitForClawbackView(orgM, clawbackId, finalStatuses, 240_000);
      expect(done).toMatchObject({ status: 'completed', counts: { succeeded: 3 } });
      for (const r of recipients) {
        expect((await simLocation(r, sims.get(r)!)).folder?.displayName, r).toBe(QUARANTINE_FOLDER);
      }
      const linked = await fx.prisma.apiUserReport.findUniqueOrThrow({ where: { id: report.id } });
      expect(linked.clawbackId).not.toBeNull();
      record(LOG, {
        case: 'A8',
        identification: report.identification,
        assessment: report.assessment,
        inline: inlineReport.identification,
        external: rejected.rejectReason,
        ack_email: true,
        result_email: true,
        clawback: done.status,
      });
    });

    it('A9 Gmail: a purge with soft_delete → Trash; restore → Inbox', async () => {
      const messageId = messageIdOf('a9');
      const delivered = await sim.deliver(
        gina(),
        syntheticEml({
          messageId,
          from: EXTERNAL_SENDER,
          to: [gina()],
          subject: subjectOf('a9'),
        }),
      );
      await copyIn(orgG, gina(), messageId, scanned);
      const now = Date.now();
      const id = await createClawback(orgG, {
        criteria: {
          messageId,
          from: new Date(now - 3_600_000).toISOString(),
          to: new Date(now + 60_000).toISOString(),
        },
        reason: 'stack test: Gmail purge',
      });
      await waitForClawbackView(orgG, id, ['ready']);
      const submitted = await submitClawback(orgG, id, {
        mode: 'explicit',
        action: 'soft_delete',
        reason: 'stack test: delete it',
      });
      expect(submitted.status).toBe('queued');
      const done = await waitForClawbackView(orgG, id, finalStatuses, 240_000);
      expect(done).toMatchObject({ status: 'completed', counts: { succeeded: 1 } });
      const trashed = await simLocation(gina(), delivered.messageId);
      expect(trashed.labelIds).toContain('TRASH');
      expect(trashed.labelIds).not.toContain('INBOX');
      const restore = await (
        await admin(orgG)
      ).post(`/api-mode/clawbacks/${id}/restore`, { reason: 'stack test: undo' }, idempotencyKey());
      expect(restore.status, JSON.stringify(restore.body)).toBe(202);
      const restored = await waitForClawbackState(
        fx.prisma,
        id,
        'restore completed',
        (c) => c.restoreStatus === 'completed' || c.restoreStatus === 'completed_with_errors',
        240_000,
      );
      expect(restored).toMatchObject({ restoreStatus: 'completed', restoresSucceeded: 1 });
      const inbox = await waitForLocation(gina(), delivered.messageId, 'back in the Inbox', (l) =>
        l.labelIds.includes('INBOX'),
      );
      expect(inbox.labelIds).not.toContain('TRASH');
      record(LOG, {
        case: 'A9',
        trashed: trashed.labelIds.join(','),
        restored: inbox.labelIds.join(','),
      });
    });

    it('A10 coverage and health: clawback.stalled warns while a paused connection holds an automatic clawback; the purge-approval alert e-mail; overview internal/clawback/reports blocks consistent with A3–A9', async () => {
      expect(shared.a1, 'A1 ran').toBeDefined();
      const m = await admin(orgM);
      // The purge-approval alert of A5 (recipients holding remediation:purge).
      const alert = await waitFor(
        'the api_mode_purge_approval alert at notify-relay-sink',
        async () =>
          (await sinkMessages(m.email, 'notify-relay-sink'))
            .map((b) => decodedMailText(b))
            .find((t) => t.includes('API-mode clawback needs a second approver')),
        { timeoutMs: 180_000, intervalMs: 3_000 },
      );
      expect(alert).toContain(shared.a5ApprovalClawback!);

      // Pause M, then a late signal for the clean A1 message: the automatic clawback is queued and
      // its actions wait (trigger `clawback` honours the pause, C5.7).
      await putConnectionSettings(orgM, connM, { feedsEnabled: false, remediationPaused: true });
      const copy = await fx.prisma.apiMessageCopy.findFirstOrThrow({
        where: { id: shared.a1!.alexCopyId },
      });
      const message = await registryMessage(orgM.id, copy.messageId);
      const before = new Set((await clawbacksOf(fx.prisma, orgM.id)).map((c) => c.publicId));
      const signal = await writeSandboxLateSignal(fx.prisma, {
        organizationId: orgM.id,
        message,
        verdict: 'malware',
        level: 'critical',
        hardBlocks: ['hb.sandbox.malicious'],
        attachmentSha256: [],
      });
      await waitForPublished(fx.prisma, signal.eventId);
      const waiting: ClawbackRow = await waitForClawback(
        fx.prisma,
        orgM.id,
        'automatic clawback running while paused',
        (c) => !before.has(c.publicId) && ['queued', 'running'].includes(c.status),
        120_000,
      );
      const pendingAction = await waitForAction(
        fx.prisma,
        orgM.id,
        copy.id,
        'clawback action pending while paused',
        (a) => a.trigger === 'clawback' && a.clawbackId === waiting.id,
        60_000,
      );
      expect(pendingAction).toMatchObject({ status: 'pending', attempts: 0 });
      const stalled = await waitForApiConnection(
        orgM,
        connM,
        'clawback.stalled warn',
        (c) =>
          (c.healthChecks as Json[]).some(
            (x) => x.code === 'clawback.stalled' && x.status === 'warn',
          ),
        240_000,
      );
      const stalledCheck = (stalled.healthChecks as Json[]).find(
        (x) => x.code === 'clawback.stalled',
      );
      await putConnectionSettings(orgM, connM, { feedsEnabled: false, remediationPaused: false });
      const resumed = await waitForClawbackState(
        fx.prisma,
        waiting.publicId,
        'completed after the pause',
        (c) => finalStatuses.includes(c.status),
        // Paused automatic actions are deferred by PAUSED_RECHECK_MS (300 s, R5.1); a resume does
        // not re-arm them, so they run at their next look.
        420_000,
      );
      expect(resumed.status).toBe('completed');
      expect(resumed.targetsSucceeded).toBe(2);
      expect((await simLocation(alex(), shared.a1!.alexSim)).folder?.displayName).toBe(
        QUARANTINE_FOLDER,
      );
      expect((await simLocation(hana(), shared.a1!.hanaSim)).folder?.displayName).toBe(
        QUARANTINE_FOLDER,
      );
      await waitForApiConnection(orgM, connM, 'clawback.stalled back to pass', (c) =>
        (c.healthChecks as Json[]).some(
          (x) => x.code === 'clawback.stalled' && x.status === 'pass',
        ),
      );

      // Overview: counters flushed, live counts.
      const rowM = await apiConnectionRow(connM);
      const sums = await waitFor(
        'API-3 counters of M flushed',
        async () => {
          const s = await clawbackCounterSums(fx.prisma, rowM.id);
          return s.internalCopies >= 2 &&
            s.targetsSucceeded >= 3 + 1 + 3 + BULK + 1 + 3 + 2 &&
            s.reportsReceived >= 3 &&
            s.reportsResolved >= 1
            ? s
            : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 2_000 },
      );
      // A fresh session: A10 outlives a 10-minute access token taken at its start.
      const res = await (await admin(orgM)).get('/api-mode/overview');
      expectStatus(res, 200, 'GET /api-mode/overview');
      const o = res.body as Json;
      expect(o.internal.enabled).toBe(true);
      expect(o.internal.copies24h).toBeGreaterThanOrEqual(2);
      expect(o.clawback).toMatchObject({ active: 0, reviewRequired: 0, pendingApproval: 0 });
      expect(o.clawback.completed24h).toBeGreaterThanOrEqual(7);
      expect(o.clawback.targetsSucceeded24h).toBeGreaterThanOrEqual(3 + 1 + 3 + BULK + 1 + 3 + 2);
      expect(o.clawback.targetsFailed24h).toBe(0);
      expect(o.reports.reportMailboxes).toBe(1);
      expect(o.reports.received24h).toBeGreaterThanOrEqual(3);
      expect(o.reports.resolved24h).toBeGreaterThanOrEqual(1);
      const c = ((o.connections as Json[]) ?? []).find((x) => x.id === connM);
      expect(c.clawback.targetsSucceeded24h).toBe(sums.targetsSucceeded);
      const g = await (await admin(orgG)).get('/api-mode/overview');
      expectStatus(g, 200, 'GET /api-mode/overview (G)');
      expect((g.body as Json).clawback.completed24h).toBeGreaterThanOrEqual(2);
      // Tenant isolation: G cannot read M's clawbacks.
      expect(
        (await (await admin(orgG)).get(`/api-mode/clawbacks/${waiting.publicId}`)).status,
      ).toBe(404);
      record(LOG, {
        case: 'A10',
        stalled: stalledCheck?.status,
        alert_email: true,
        internal24h: o.internal.copies24h,
        clawbacks_completed24h: o.clawback.completed24h,
        targets_succeeded24h: o.clawback.targetsSucceeded24h,
        reports_received24h: o.reports.received24h,
        reports_resolved24h: o.reports.resolved24h,
        counters: JSON.stringify(sums),
      });
    });
  },
);
