/**
 * Identity providers (step 8.5 §7, §11.6) against the real api, ato-worker and integration-worker
 * with the Compose `provider-fake` (tokens) and the TEST-ONLY `idp-simulator` (ATO data
 * endpoints; never Microsoft or Google). This Node process prepares a Microsoft 365 connection of
 * alpha through 8.2's api (its own run domain, a customer app generated now, the mail-flow and ATO
 * grants verified by the integration-worker) and loads a synthetic directory into the simulator;
 * the browser then connects it as an ATO identity provider (MFA administrator), sees the streams
 * with their lag, requests a backfill, pauses and resumes; an analyst removes an external
 * forwarding rule from the account's "Mailbox changes" tab and a second MFA administrator
 * approves it; RBAC (read without connect; no navigation item without `ato:read`), isolation
 * (beta), axe and responsive widths. Every row the spec created is removed afterwards (alpha's
 * ATO figures are asserted by ato.spec, which runs after this file).
 */
import type { PrismaClient } from '@email-gateway/database';
import { defaultBindingSettings } from '@email-gateway/idp-adapters';
import { MS_DOMAIN, MS_TENANT_ID, microsoftDirectory } from '@email-gateway/idp-adapters/testing';
import type { Page } from '@playwright/test';
import { randomBytes, randomUUID } from 'node:crypto';
import { apiSession, type ApiSession } from '../seed/api';
import { writer } from '../seed/db';
import { signIn, user } from '../support/auth';
import { requireEnv } from '../support/env';
import { expect, test } from '../support/fixtures';
import { expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { readState } from '../support/state';

// The steps build on one connection and one integration (directories are unique platform-wide).
test.describe.configure({ mode: 'serial', timeout: 300_000, retries: 0 });

const FAKE = () => `http://127.0.0.1:${process.env.PROVIDER_FAKE_HOST_PORT || '18093'}`;
const SIM = () => `http://127.0.0.1:${process.env.IDP_SIMULATOR_ADMIN_HOST_PORT || '18097'}`;

async function fakePost(path: string, body: unknown): Promise<void> {
  const response = await fetch(`${FAKE()}${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${requireEnv('PROVIDER_FAKE_ADMIN_TOKEN')}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (response.status !== 204) throw new Error(`provider-fake ${path}: ${response.status}`);
}

async function simPost(path: string, body: unknown): Promise<void> {
  const response = await fetch(`${SIM()}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (response.status !== 204) throw new Error(`idp-simulator ${path}: ${response.status}`);
}

/**
 * Polls `check` until it returns a value. On a timeout the error names `what` and, when given,
 * the output of `diagnose` (state read at that moment, never secrets), so the cause is visible.
 */
async function until<T>(
  what: string,
  check: () => Promise<T | undefined>,
  ms = 180_000,
  diagnose?: () => Promise<string>,
) {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await check().catch(() => undefined);
    if (value !== undefined) return value;
    if (Date.now() > deadline) {
      const detail = diagnose
        ? await diagnose().catch((error: unknown) => `diagnostics unavailable: ${String(error)}`)
        : '';
      throw new Error(`timed out waiting for ${what}${detail ? `\n${detail}` : ''}`);
    }
    await new Promise((r) => setTimeout(r, 2_000));
  }
}

/**
 * Scheduling state of this run's integration and its streams (step AI-4 D14): status, health and
 * the next probe; per stream the status, next poll, consecutive failures and last error code. No
 * secrets, no provider payloads.
 */
async function integrationDiagnostics(): Promise<string> {
  const row = await prisma.atoProviderIntegration.findFirst({
    where: { organizationId: alphaId, publicId: integrationId },
    select: {
      id: true,
      status: true,
      healthStatus: true,
      healthCheckedAt: true,
      nextHealthAt: true,
    },
  });
  if (!row) return `integration ${integrationId || '(unset)'}: not found`;
  const streams = await prisma.atoProviderStream.findMany({
    where: { organizationId: alphaId, integrationId: row.id },
    orderBy: { id: 'asc' },
    select: {
      stream: true,
      status: true,
      nextPollAt: true,
      consecutiveFailures: true,
      lastErrorCode: true,
    },
  });
  const iso = (d: Date | null) => d?.toISOString() ?? 'null';
  return [
    `now=${new Date().toISOString()} integration status=${row.status} health_status=${row.healthStatus} health_checked_at=${iso(row.healthCheckedAt)} next_health_at=${iso(row.nextHealthAt)}`,
    ...streams.map(
      (s) =>
        `  stream=${s.stream} status=${s.status} next_poll_at=${iso(s.nextPollAt)} consecutive_failures=${s.consecutiveFailures} last_error_code=${s.lastErrorCode ?? 'null'}`,
    ),
  ].join('\n');
}

const ROLES = [
  'Organization.Read.All',
  'Domain.Read.All',
  'AuditLog.Read.All',
  'Directory.Read.All',
  'IdentityRiskEvent.Read.All',
  'User.Read.All',
  'MailboxSettings.Read',
  'User.RevokeSessions.All',
  'User.EnableDisableAccount.All',
  'User-PasswordProfile.ReadWrite.All',
  'MailboxSettings.ReadWrite',
];

const run = randomBytes(3).toString('hex');
const domainName = `idp-${run}.alpha.e2e-portal.test`;
const tenantId = randomUUID();
const app = { clientId: randomUUID(), secret: randomBytes(24).toString('base64url') };
const connectionName = `E2E IdP ${run}`;
let prisma: PrismaClient;
let admin: ApiSession;
let domainId = 0n;
let alphaId = 0n;
let connectionId = '';
let integrationId = '';

/** The synthetic directory of `@email-gateway/idp-adapters/testing`, rewritten to this run. */
function directory() {
  const json = JSON.stringify(microsoftDirectory(new Date()))
    .split(MS_TENANT_ID)
    .join(tenantId)
    .split(MS_DOMAIN)
    .join(domainName);
  return JSON.parse(json) as unknown;
}

async function connection(): Promise<Record<string, unknown>> {
  const res = await admin.call('GET', `/provider-connections/${connectionId}`);
  return res.body;
}

async function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => {
    const root = document.documentElement;
    return Math.max(root.scrollWidth, document.body.scrollWidth) - root.clientWidth;
  });
}

test.beforeAll(async () => {
  const state = readState();
  prisma = writer();
  alphaId = (
    await prisma.organization.findFirstOrThrow({
      where: { slug: state.orgs.alpha.slug },
      select: { id: true },
    })
  ).id;
  domainId = (
    await prisma.domain.create({
      data: {
        organizationId: alphaId,
        name: domainName,
        status: 'active',
        verifiedAt: new Date(),
        activatedAt: new Date(),
      },
      select: { id: true },
    })
  ).id;
  const domainPublicId = (
    await prisma.domain.findUniqueOrThrow({ where: { id: domainId }, select: { publicId: true } })
  ).publicId;
  await fakePost('/_fake/m365/tenants', {
    tenantId,
    displayName: 'E2E IdP tenant',
    domains: [{ name: domainName, isVerified: true, isDefault: true, mxHost: null }],
  });
  await fakePost('/_fake/m365/apps', {
    clientId: app.clientId,
    secret: app.secret,
    homeTenantId: tenantId,
    requiredRoles: ROLES,
  });
  await fakePost('/_fake/m365/consents', { tenantId, clientId: app.clientId, roles: ROLES });
  await fakePost('/_fake/m365/consents', {
    tenantId,
    clientId: app.clientId,
    roles: ['ActivityFeed.Read'],
    resource: 'https://manage.office.com',
  });
  await simPost('/admin/reset', {});
  await simPost('/admin/dataset', { microsoft: { directories: [directory()] } });

  const alphaAdmin = user('alphaAdmin');
  admin = await apiSession(alphaAdmin.email, alphaAdmin.password);
  const created = await admin.call(
    'POST',
    '/provider-connections',
    { provider: 'microsoft_365', displayName: connectionName },
    { idempotent: true, expect: 201 },
  );
  connectionId = created.body.id as string;
  const credentials = { tenantId, clientId: app.clientId, clientSecret: app.secret };
  for (const profile of ['m365.mail_flow', 'm365.ato_telemetry', 'm365.ato_response']) {
    await admin.call(
      'POST',
      `/provider-connections/${connectionId}/grants`,
      { profile, authMethod: 'customer_app_secret' },
      { idempotent: true, expect: 201 },
    );
  }
  await admin.call(
    'PUT',
    `/provider-connections/${connectionId}/grants/m365.mail_flow/credentials`,
    credentials,
    { idempotent: true, expect: 200 },
  );
  await until('mail-flow grant active', async () => {
    const c = await connection();
    return (c.grants as Array<{ profile: string; status: string }>).some(
      (g) => g.profile === 'm365.mail_flow' && g.status === 'active',
    )
      ? true
      : undefined;
  });
  await admin.call(
    'PUT',
    `/provider-connections/${connectionId}/domains`,
    { domainIds: [domainPublicId] },
    { idempotent: true, expect: 200 },
  );
  await until('connection active', async () =>
    (await connection()).status === 'active' ? true : undefined,
  );
  for (const profile of ['m365.ato_telemetry', 'm365.ato_response']) {
    await admin.call(
      'PUT',
      `/provider-connections/${connectionId}/grants/${profile}/credentials`,
      credentials,
      { idempotent: true, expect: 200 },
    );
  }
  await until('ATO grants active', async () => {
    const grants = (await connection()).grants as Array<{ profile: string; status: string }>;
    return ['m365.ato_telemetry', 'm365.ato_response'].every((p) =>
      grants.some((g) => g.profile === p && g.status === 'active'),
    )
      ? true
      : undefined;
  });
});

test.afterAll(async () => {
  // E2E_KEEP_DATA=1 keeps the run's rows for debugging (like the global teardown).
  if (process.env.E2E_KEEP_DATA === '1') return;
  await simPost('/admin/reset', {}).catch(() => undefined);
  if (!prisma || alphaId === 0n) return;
  const where = { organizationId: alphaId };
  // Every ATO row of the run domain's accounts (the integration's identities), then the
  // integration, the 8.2 connection and the run domain.
  const accounts = await prisma.atoAccount.findMany({
    where: { ...where, address: { endsWith: `@${domainName}` } },
    select: { id: true },
  });
  const accountIds = accounts.map((a) => a.id);
  const incidents = await prisma.securityIncident.findMany({
    where: { ...where, category: 'account_takeover', subjectRefId: { in: accountIds } },
    select: { id: true },
  });
  const incidentIds = incidents.map((i) => i.id);
  const actions = await prisma.atoResponseAction.findMany({
    where: { ...where, accountId: { in: accountIds } },
    select: { id: true },
  });
  await prisma.atoResponseActionLog.deleteMany({
    where: { ...where, actionId: { in: actions.map((a) => a.id) } },
  });
  await prisma.atoResponseAction.deleteMany({ where: { ...where, accountId: { in: accountIds } } });
  await prisma.atoIncidentDetail.deleteMany({
    where: { ...where, incidentId: { in: incidentIds } },
  });
  await prisma.securityIncidentLink.deleteMany({
    where: { ...where, incidentId: { in: incidentIds } },
  });
  await prisma.securityIncidentEvent.deleteMany({
    where: { ...where, incidentId: { in: incidentIds } },
  });
  await prisma.securityIncident.deleteMany({ where: { ...where, id: { in: incidentIds } } });
  const byAccount = { ...where, accountId: { in: accountIds } };
  await prisma.atoTrustedContext.deleteMany({ where: byAccount });
  await prisma.atoRiskOverride.deleteMany({ where: byAccount });
  await prisma.atoRiskSignal.deleteMany({ where: byAccount });
  await prisma.atoRiskScore.deleteMany({ where: byAccount });
  await prisma.atoAuthEvent.deleteMany({ where: byAccount });
  await prisma.atoAccountActivityDaily.deleteMany({ where: byAccount });
  await prisma.atoAccountBaseline.deleteMany({ where: byAccount });
  await prisma.atoAccountIdentity.deleteMany({ where: byAccount });
  const integrations = await prisma.atoProviderIntegration.findMany({
    where: { ...where, connectorRef: connectionId },
    select: { id: true },
  });
  const integrationIds = integrations.map((i) => i.id);
  await prisma.atoProviderMailboxItem.deleteMany({
    where: { ...where, integrationId: { in: integrationIds } },
  });
  await prisma.atoProviderStream.deleteMany({
    where: { ...where, integrationId: { in: integrationIds } },
  });
  await prisma.atoProviderIntegration.deleteMany({
    where: { ...where, id: { in: integrationIds } },
  });
  await prisma.atoAccount.deleteMany({ where: { ...where, id: { in: accountIds } } });
  if (connectionId) {
    const conn = await prisma.providerConnection.findFirst({
      where: { ...where, publicId: connectionId },
      select: { id: true },
    });
    if (conn) {
      const byConnection = { ...where, connectionId: conn.id };
      await prisma.providerHealthEvent.deleteMany({ where: byConnection });
      await prisma.providerHealthCheck.deleteMany({ where: byConnection });
      await prisma.providerValidationRun.deleteMany({ where: byConnection });
      await prisma.providerConsentState.deleteMany({ where: byConnection });
      await prisma.providerConnectionDomain.deleteMany({ where: byConnection });
      await prisma.providerConnectionGrant.deleteMany({ where: byConnection });
      await prisma.providerConnection.deleteMany({ where: { ...where, id: conn.id } });
    }
  }
  if (domainId) await prisma.domain.deleteMany({ where: { ...where, id: domainId } });
  await admin?.logout();
  await prisma.$disconnect();
});

test('connect: eligible connection, permissions, streams and backfill; streams with lag; axe', async ({
  page,
}) => {
  await signIn(page, 'alphaApprover', { next: '/ato/providers' });
  await expect(page.getByRole('heading', { level: 1, name: 'Identity providers' })).toBeVisible();
  await expectSettled(page, '/ato/providers');
  await expectNoSeriousA11yViolations(page, '/ato/providers');
  await page.getByRole('button', { name: 'Connect identity provider' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Connect an identity provider' });
  await dialog.getByRole('radio', { name: new RegExp(connectionName) }).click();
  await expect(
    dialog.getByRole('group', { name: 'Required and granted permissions of the connection' }),
  ).toContainText('ActivityFeed.Read');
  await dialog.getByRole('spinbutton', { name: 'Backfill days' }).fill('0');
  await expectNoSeriousA11yViolations(page, '/ato/providers connect dialog');
  await dialog.getByRole('button', { name: 'Connect' }).click();
  await page.waitForURL(/\/ato\/providers\/[0-9a-f-]{36}$/);
  integrationId = /providers\/([0-9a-f-]{36})/.exec(page.url())![1]!;
  // The worker probes the provider, then polls every primary stream (page refetches each 30 s).
  await expect(page.getByText('Healthy').first()).toBeVisible({ timeout: 180_000 });
  await page.getByRole('tab', { name: 'Streams' }).click();
  const streams = page.getByRole('table', { name: 'Streams of the identity provider' });
  const signIns = streams.getByRole('row', { name: /^Sign-ins/ });
  await expect(signIns).not.toContainText('Never', { timeout: 120_000 });
  await expect(signIns).toContainText(/\d+ (s|min)/);
  await expectSettled(page, '/ato/providers/[id]?tab=streams');
  await expectNoSeriousA11yViolations(page, '/ato/providers/[id]?tab=streams');
  for (const tab of ['Actions', 'Permissions', 'Settings', 'Overview']) {
    await page.getByRole('tab', { name: tab }).click();
    await expectNoSeriousA11yViolations(page, `/ato/providers/[id] ${tab}`);
  }
  // The api stored the chosen settings (no historical backfill on binding).
  const stored = await prisma.atoProviderIntegration.findFirstOrThrow({
    where: { publicId: integrationId },
    select: { settings: true },
  });
  expect((stored.settings as { backfillDays: number }).backfillDays).toBe(0);
  expect(defaultBindingSettings().backfillDays).toBe(7);
});

test('backfill request, pause and resume', async ({ page }) => {
  await signIn(page, 'alphaApprover', { next: `/ato/providers/${integrationId}?tab=streams` });
  await page.getByRole('button', { name: 'Backfill' }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Backfill history' });
  await dialog.getByRole('spinbutton', { name: 'Days back' }).fill('1');
  await dialog.getByRole('checkbox', { name: 'Sign-ins' }).click();
  await dialog.getByRole('button', { name: 'Start backfill' }).click();
  await expect(page.getByText('Backfill requested')).toBeVisible();
  const row = await prisma.atoProviderStream.findFirstOrThrow({
    where: { integration: { publicId: integrationId }, stream: 'sign_ins' },
    select: { backfillRequestedAt: true },
  });
  expect(row.backfillRequestedAt).not.toBeNull();
  await page.getByRole('tab', { name: 'Overview' }).click();
  await page.getByRole('button', { name: 'Pause', exact: true }).click();
  const pause = page.getByRole('alertdialog', { name: 'Pause the identity provider?' });
  await pause.getByRole('textbox').fill('E2E maintenance window');
  await pause.getByRole('button', { name: 'Pause' }).click();
  await expect(page.getByText('By a user')).toBeVisible();
  await page.getByRole('button', { name: 'Resume' }).click();
  await expect(page.getByRole('button', { name: 'Pause', exact: true })).toBeVisible();
});

test('mailbox changes: remove an external forwarding rule through approval', async ({ page }) => {
  // Longer than the 300 s wait below, so a timeout reports the integration diagnostics instead of
  // being cut off by the test timeout (AI-4 gate, 2026-11-25).
  test.setTimeout(480_000);
  const alex = await until(
    'the alex mailbox account and its incident',
    async () => {
      const account = await prisma.atoAccount.findFirst({
        where: { organizationId: alphaId, kind: 'mailbox', address: `alex@${domainName}` },
        select: { id: true, publicId: true },
      });
      if (!account) return undefined;
      const incident = await prisma.securityIncident.findFirst({
        where: { organizationId: alphaId, subjectRefId: account.id, activeMarker: 1 },
      });
      const item = await prisma.atoProviderMailboxItem.findFirst({
        where: { organizationId: alphaId, accountId: account.id, itemKind: 'inbox_rule' },
      });
      return incident && item ? account : undefined;
    },
    300_000,
    integrationDiagnostics,
  );
  await signIn(page, 'alphaAnalyst', { next: `/ato/accounts/${alex.publicId}?tab=mailbox` });
  const items = page.getByRole('table', { name: 'Mailbox items' });
  const rule = items.getByRole('row', { name: /Inbox rule or filter/ }).filter({
    hasText: 'evil-mail.example',
  });
  await expect(rule).toBeVisible({ timeout: 60_000 });
  await expectSettled(page, '/ato/accounts/[id]?tab=mailbox');
  await expectNoSeriousA11yViolations(page, '/ato/accounts/[id]?tab=mailbox');
  await rule.getByRole('button', { name: 'Remove forwarding' }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Request a response' });
  await expect(dialog).toContainText('evil-mail.example');
  await dialog
    .getByRole('textbox', { name: /Reason/ })
    .fill('E2E: forwarding to an unknown domain');
  await dialog.getByRole('button', { name: 'Request' }).click();
  await expect(page.getByText('Response requested')).toBeVisible();

  await signIn(page, 'alphaApprover', { next: '/ato/responses' });
  const pending = page.getByRole('table', { name: 'Responses waiting for approval' });
  await pending.getByRole('button', { name: 'Approve: Remove a forwarding rule' }).first().click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Approve' }).click();
  const action = await until('the provider-confirmed removal', async () => {
    const row = await prisma.atoResponseAction.findFirst({
      where: { organizationId: alphaId, accountId: alex.id, actionType: 'remove_forwarding_rule' },
      select: { publicId: true, status: true, providerStatus: true },
    });
    return row && ['succeeded', 'failed', 'unsupported'].includes(row.status) ? row : undefined;
  });
  expect(action).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
  await page.goto('/ato/responses?tab=all');
  await expect(page.getByText('Confirmed by the provider').first()).toBeVisible({
    timeout: 60_000,
  });
});

test('RBAC and isolation: read without connect, no item without ato:read, beta sees nothing', async ({
  page,
}) => {
  await signIn(page, 'alphaAuditor', { next: '/ato/providers' });
  await expect(page.getByRole('link', { name: connectionName })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Connect identity provider' })).toHaveCount(0);
  await page.goto(`/ato/providers/${integrationId}`);
  await expect(page.getByRole('button', { name: 'Pause', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Remove' })).toHaveCount(0);

  await signIn(page, 'alphaMailbox', { next: '/quarantine/me' });
  await expect(page.getByRole('link', { name: 'Identity providers' })).toHaveCount(0);
  await page.goto('/ato/providers');
  await expect(
    page.getByRole('heading', { name: 'You do not have access to this page' }),
  ).toBeVisible();

  await signIn(page, 'betaAdmin', { next: `/ato/providers/${integrationId}` });
  await expect(page.getByText(/Page not found/i)).toBeVisible();
  await page.goto('/ato/providers');
  await expect(page.getByRole('link', { name: connectionName })).toHaveCount(0);
});

test('responsive: list and details fit 390 px and 834 px without horizontal page scroll', async ({
  page,
}) => {
  await signIn(page, 'alphaApprover', { next: '/ato/providers' });
  for (const width of [390, 834]) {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ['/ato/providers', `/ato/providers/${integrationId}?tab=streams`]) {
      await page.goto(path);
      await expectSettled(page, path);
      expect(await horizontalOverflow(page), `${path} at ${width}px`).toBeLessThanOrEqual(1);
    }
  }
});
