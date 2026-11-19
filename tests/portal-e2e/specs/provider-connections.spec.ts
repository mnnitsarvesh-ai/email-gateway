/**
 * Microsoft 365 and Google Workspace connection pages (step 8.2 §6, §10.6) against the real api,
 * integration-worker and the Compose `provider-fake` (smtp-test profile; never Microsoft or
 * Google): an organization admin connects a Microsoft 365 tenant with a customer app secret
 * generated at run time (registered at the fake from this Node process, never by the browser),
 * the server-computed wizard advances as the worker verifies the grant and binds the tenant,
 * the inbound preview dialog shows the change set and is cancelled (alpha's destinations are not
 * changed: other specs read them), health, validations, the setup guide with its Markdown
 * download, settings, the consent callback's URL scrubbing, RBAC and tenant isolation, axe on
 * every page; the connection is disconnected through the typed confirmation at the end.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { signIn } from '../support/auth';
import { requireEnv } from '../support/env';
import { expect, test } from '../support/fixtures';
import { expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { readState } from '../support/state';

// No retries: the steps build on one connection whose tenant and domain link are unique
// platform-wide (I10, D4), so a rerun from the first step would meet its own earlier binding.
test.describe.configure({ mode: 'serial', timeout: 240_000, retries: 0 });

const FAKE = () => `http://127.0.0.1:${process.env.PROVIDER_FAKE_HOST_PORT || '18093'}`;

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

const tenantId = randomUUID();
const app = { clientId: randomUUID(), secret: randomBytes(24).toString('base64url') };
const name = `E2E Contoso ${randomBytes(3).toString('hex')}`;
let connectionId = '';

test.beforeAll(async () => {
  const domain = readState().alpha.domainName;
  await fakePost('/_fake/m365/tenants', {
    tenantId,
    displayName: 'E2E tenant',
    domains: [
      {
        name: domain,
        isVerified: true,
        isDefault: true,
        mxHost: `${domain.replace(/\./g, '-')}.mail.protection.outlook.com`,
      },
    ],
  });
  await fakePost('/_fake/m365/apps', {
    clientId: app.clientId,
    secret: app.secret,
    homeTenantId: tenantId,
    requiredRoles: ['Organization.Read.All', 'Domain.Read.All'],
  });
  await fakePost('/_fake/m365/consents', {
    tenantId,
    clientId: app.clientId,
    roles: ['Organization.Read.All', 'Domain.Read.All'],
  });
});

test('connect a Microsoft 365 tenant with a customer app secret; the wizard follows the worker', async ({
  page,
}) => {
  const state = readState();
  await signIn(page, 'alphaAdmin', { next: '/integrations' });
  await expect(
    page.getByRole('heading', { name: 'Microsoft 365 and Google Workspace' }),
  ).toBeVisible();
  await expectSettled(page, '/integrations');
  await expectNoSeriousA11yViolations(page, '/integrations');
  await page.getByRole('link', { name: 'Connect', exact: true }).click();
  await expect(page).toHaveURL(/\/integrations\/providers\/new$/);
  await expect(page.getByLabel('Connection name (required)')).toBeVisible();
  await expectSettled(page, '/integrations/providers/new');
  await expectNoSeriousA11yViolations(page, '/integrations/providers/new');
  await page.getByLabel('Connection name (required)').fill(name);
  await page.getByRole('button', { name: 'Create and continue' }).click();
  await page.waitForURL(/\/integrations\/providers\/[0-9a-f-]{36}\?tab=setup$/);
  connectionId = /providers\/([0-9a-f-]{36})/.exec(page.url())![1]!;
  await expect(page.getByRole('navigation', { name: 'Setup steps' })).toBeVisible();

  await page.getByRole('button', { name: 'Use your own app registration' }).click();
  const secret = page.getByLabel('Client secret value');
  await expect(secret).toHaveAttribute('type', 'password');
  await page.getByLabel('Directory (tenant) ID').fill(tenantId);
  await page.getByLabel('Application (client) ID').fill(app.clientId);
  await secret.fill(app.secret);
  await page.getByRole('button', { name: 'Upload and verify' }).click();
  // The worker verifies the grant against the fake (the page polls every 5 s): Connect is done,
  // but the tenant stays a claim until a linked domain proves control of it (D4).
  await expect(page.getByRole('button', { name: /Step 1 Connect.*Done/ })).toBeVisible({
    timeout: 120_000,
  });
  await expect(page.getByText('E2E tenant', { exact: false })).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText(app.secret);
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).not.toContain(app.secret);

  await page.getByRole('button', { name: /Step 2 Domains/ }).click();
  await page.getByRole('checkbox', { name: state.alpha.domainName }).click();
  await page.getByRole('button', { name: 'Save linked domains' }).click();
  // The worker checks the domain in the tenant and binds the connection (I10): Domains is done.
  await expect(page.getByRole('button', { name: /Domains.*Done/ })).toBeVisible({
    timeout: 120_000,
  });
  await expect(page.getByText('E2E tenant', { exact: false }).first()).toBeVisible({
    timeout: 60_000,
  });
  await expectNoSeriousA11yViolations(page, '/integrations/providers/[id]?tab=setup');

  // Inbound: the preview shows the server's change set; cancelled (alpha's routing unchanged).
  await page.getByRole('button', { name: /Step 3 Inbound/ }).click();
  await page.getByRole('button', { name: 'Preview inbound change' }).click();
  const dialog = page.getByRole('dialog', { name: 'Apply inbound routing' });
  await expect(dialog.getByTestId('change-set')).toContainText('mail.protection.outlook.com');
  await expect(dialog.getByRole('button', { name: 'Apply inbound routing' })).toBeDisabled();
  await expectNoSeriousA11yViolations(page, 'inbound preview dialog');
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
});

test('health, validations, setup guide download and rename', async ({ page }) => {
  expect(connectionId, 'the first test created the connection').not.toBe('');
  await signIn(page, 'alphaAdmin', { next: `/integrations/providers/${connectionId}?tab=health` });
  await expect(page.getByRole('heading', { name: 'Health' })).toBeVisible();
  await page.getByRole('button', { name: 'Check now' }).click();
  await expectNoSeriousA11yViolations(page, 'health tab');
  await page.getByRole('tab', { name: 'Setup guide' }).click();
  await expect(page.getByRole('heading', { name: /Inbound mail/ })).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download Markdown' }).click();
  expect((await download).suggestedFilename()).toMatch(/^setup-microsoft-365-.+\.md$/);
  await expectNoSeriousA11yViolations(page, 'setup guide tab');
  await page.getByRole('tab', { name: 'Validations' }).click();
  await expect(page.getByText('No validation has run yet.')).toBeVisible();
  await page.getByRole('tab', { name: 'Settings' }).click();
  await page.getByLabel('Connection name').fill(`${name} renamed`);
  await page.getByRole('button', { name: 'Save name' }).click();
  await expect(page.getByRole('heading', { level: 1, name: `${name} renamed` })).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'settings tab');
});

test('read-only users see the connection without actions; another organization gets 404', async ({
  page,
}) => {
  await signIn(page, 'alphaReadOnly', { next: '/integrations' });
  await expect(page.getByRole('link', { name: `${name} renamed` })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Connect', exact: true })).toHaveCount(0);
  await page.goto(`/integrations/providers/${connectionId}?tab=settings`);
  await expect(page.getByRole('button', { name: 'Disconnect…' })).toHaveCount(0);
  await page.goto('/integrations/providers/new');
  await expect(page.getByText('You do not have access to this page')).toBeVisible();
  await page.context().clearCookies();
  await signIn(page, 'betaAdmin', { next: `/integrations/providers/${connectionId}` });
  await expect(page.getByText(/Page not found/i)).toBeVisible();
});

test('the consent callback scrubs its query string and explains an invalid state', async ({
  page,
}) => {
  await signIn(page, 'alphaAdmin', { next: '/integrations' });
  await page.goto(
    `/integrations/providers/consent-callback?admin_consent=True&tenant=${tenantId}&state=${'x'.repeat(43)}`,
  );
  await expect(
    page.getByRole('heading', { name: 'The consent could not be completed' }),
  ).toBeVisible();
  expect(new URL(page.url()).search).toBe('');
  await expectNoSeriousA11yViolations(page, 'consent callback');
});

test('disconnect needs the typed connection name and lists the provider cleanup steps', async ({
  page,
}) => {
  await signIn(page, 'alphaAdmin', {
    next: `/integrations/providers/${connectionId}?tab=settings`,
  });
  await page.getByRole('button', { name: 'Disconnect…' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByTestId('change-set')).toContainText('Connection status');
  await dialog.getByRole('checkbox').click();
  await dialog.getByLabel(/to confirm/).fill('wrong');
  await expect(dialog.getByRole('button', { name: 'Disconnect' })).toBeDisabled();
  await dialog.getByLabel(/to confirm/).fill(`${name} renamed`);
  await dialog.getByRole('button', { name: 'Disconnect' }).click();
  await expect(page.getByRole('heading', { name: 'Finish in your provider' })).toBeVisible();
  await expect(page.getByText('This connection is disconnected.')).toBeVisible();
});
