/**
 * Create / update / delete through the UI against the real api (design §9):
 * users (invite → edit roles → disable → delete), domains (onboarding wizard to the DNS step,
 * verify shows pending, delete), webhooks (create with the secret shown once, edit, send a
 * test event and read the recorded delivery, delete). Names are unique per run.
 */
import { randomBytes } from 'node:crypto';
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { readState } from '../support/state';

const suffix = () => randomBytes(3).toString('hex');

async function confirm(page: Page, label: string | RegExp): Promise<void> {
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toBeVisible();
  const reason = dialog.getByRole('textbox');
  if ((await reason.count()) > 0 && (await reason.first().isEditable())) {
    await reason.first().fill('E2E lifecycle check (synthetic user)');
  }
  await dialog.getByRole('button', { name: label }).click();
  await expect(dialog).toHaveCount(0);
}

test('users: invite → edit roles → disable → delete', async ({ page }) => {
  const s = readState();
  const email = `invitee-${suffix()}@${s.alpha.domainName}`;
  await signIn(page, 'alphaAdmin', { next: '/users' });
  await page.getByRole('button', { name: 'Invite user' }).first().click();
  const invite = page.getByRole('dialog', { name: 'Invite a user' });
  await invite.getByLabel('Email (required)').fill(email);
  await invite.getByLabel('Name (required)').fill('E2E Invitee');
  await invite.getByRole('checkbox', { name: /Read-only User/ }).check();
  await invite
    .getByRole('button', { name: /invite|send/i })
    .last()
    .click();
  await expect(invite).toHaveCount(0);

  // The portal opens the new user, status Invited.
  await expect(page.getByRole('heading', { level: 1, name: 'E2E Invitee' })).toBeVisible();
  await expect(page.locator('main')).toContainText(email);
  await expect(page.locator('main').getByText('Invited', { exact: true }).first()).toBeVisible();

  // Edit roles: add Security Analyst, remove Read-only User.
  const roles = page.getByRole('form', { name: 'Change roles' });
  await roles.getByRole('checkbox', { name: /Security Analyst/ }).check();
  await roles.getByRole('checkbox', { name: /Read-only User/ }).uncheck();
  await roles.getByRole('button', { name: 'Save roles' }).click();
  const current = page.getByRole('list', { name: 'Current roles' });
  await expect(current).toContainText('Security Analyst');
  await expect(current).not.toContainText('Read-only User');

  // Disable.
  await page.getByRole('button', { name: 'Disable', exact: true }).click();
  await confirm(page, 'Disable');
  await expect(page.locator('main')).toContainText(/disabled/i);

  // Delete (typed confirmation when asked).
  await page
    .getByRole('button', { name: /^Delete/ })
    .first()
    .click();
  const dialog = page.getByRole('alertdialog');
  const typed = dialog.getByRole('textbox');
  if ((await typed.count()) > 0) await typed.first().fill(email);
  await dialog.getByRole('button', { name: 'Delete user' }).click();
  await expect(page).toHaveURL(/\/users(\?|$)/);
  await expect(page.locator('main table tbody tr').filter({ hasText: email })).toHaveCount(0);
});

test('domains: onboarding wizard to the DNS step, verify pending, delete', async ({ page }) => {
  const name = `onboard-${suffix()}.alpha.e2e-portal.test`;
  await signIn(page, 'alphaDomainAdmin', { next: '/domains/onboarding' });
  const add = page.getByRole('form', { name: 'Add domain' });
  await add.getByLabel('Domain name (required)').fill(name);
  await add.getByRole('button', { name: 'Add domain' }).click();

  // DNS step: the records to publish (ownership TXT, MX, SPF, DKIM, DMARC).
  await expect(page).toHaveURL(/domainId=/);
  const main = page.locator('main');
  await expect(main).toContainText(/TXT/);
  await expect(main).toContainText(/MX/);
  await page.getByRole('button', { name: 'I have published the records' }).click();

  // Verify: the records do not exist (dns-sink), so ownership stays pending.
  await page.getByRole('button', { name: /verify now/i }).click();
  await expect(main).toContainText(/pending|not found|not yet/i);
  const domainId = new URL(page.url()).searchParams.get('domainId');
  expect(domainId).toBeTruthy();

  // Delete from the domain page (a pending domain may be deleted).
  await page.goto(`/domains/${domainId}`);
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
  await page
    .getByRole('button', { name: /^Delete/ })
    .first()
    .click();
  const dialog = page.getByRole('alertdialog');
  const typed = dialog.getByRole('textbox');
  if ((await typed.count()) > 0) await typed.first().fill(name);
  await dialog
    .getByRole('button', { name: /delete/i })
    .last()
    .click();
  await page.goto('/domains');
  await expect(page.locator('main table')).not.toContainText(name);
});

test('webhooks: create (secret once) → edit → send test → delete', async ({ page }) => {
  const name = `E2E hook ${suffix()}`;
  await signIn(page, 'alphaAdmin', { next: '/integrations' });
  await page.getByRole('button', { name: 'New webhook' }).first().click();
  const form = page.getByRole('dialog', { name: 'New webhook' });
  await form.getByLabel('Name (required)').fill(name);
  // Accepted by the api's create-time SSRF rules (https, port 443, a name, no IP literal); it
  // resolves only through dns-sink and never answers (docs/deployment/webhooks.md).
  await form.getByLabel('Endpoint URL (required)').fill('https://hooks.e2e-portal.test/in');
  await form
    .getByRole('group', { name: /Event types/ })
    .getByRole('checkbox')
    .first()
    .check();
  await form.getByRole('button', { name: 'Create webhook' }).click();

  // The signing secret is shown once.
  const secretDialog = page.getByRole('dialog').filter({ has: page.locator('code[data-secret]') });
  await expect(secretDialog).toBeVisible();
  const secret = ((await secretDialog.locator('code[data-secret]').textContent()) ?? '').trim();
  expect(secret.length).toBeGreaterThanOrEqual(24);
  const done = secretDialog.getByRole('button', { name: 'Done' });
  await expect(done).toBeDisabled();
  await secretDialog.getByRole('checkbox').check();
  await done.click();
  await expect(secretDialog).toHaveCount(0);
  // Not anywhere in the page afterwards.
  expect(await page.content()).not.toContain(secret);

  // The portal opens the new webhook: edit, test, delete.
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
  expect(await page.content()).not.toContain(secret);
  await page.getByRole('button', { name: 'Edit settings' }).click();
  const edit = page.getByRole('dialog', { name: 'Edit webhook' });
  await edit.getByLabel('Description (optional)').fill('Edited by the e2e suite');
  await edit.getByRole('button', { name: /save/i }).click();
  await expect(edit).toHaveCount(0);
  await expect(page.locator('main')).toContainText('Edited by the e2e suite');

  await page.getByRole('button', { name: 'Send test event' }).click();
  await expect(
    page.getByRole('status').filter({ hasText: 'test delivery was queued' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'View the test delivery' }).click();
  const test = page.getByRole('dialog', { name: 'Test delivery' });
  // The receiver does not exist locally: assert the recorded delivery, not its success.
  await expect(test).toContainText('webhook.ping');
  await expect(test).toContainText(/pending|scheduled|retrying|failed|delivered|in progress/i);
  await test.getByRole('button', { name: /close/i }).first().click();

  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  const dialog = page.getByRole('alertdialog');
  const typed = dialog.getByRole('textbox');
  if ((await typed.count()) > 0) await typed.first().fill(name);
  await dialog.getByRole('button', { name: 'Delete webhook' }).click();
  await expect(page).toHaveURL(/\/integrations/);
  await expect(page.locator('main')).not.toContainText(name);
});
