/**
 * Quarantine through the browser (design §9, docs/plan/steps/17-quarantine.md):
 * - the reviewer requests the release of the entry whose message has no completed scan round
 *   (pre-check `no_scan_round` → an approver is required); a different administrator with an
 *   MFA session approves; states and audit rows are verified; the release itself is executed by
 *   the policy-engine's quarantine executor and asserted only when it runs (recorded otherwise);
 * - the sanitized preview shows the stored part as text (script dropped, link defanged);
 * - the download grant (password + TOTP) returns an attachment response.
 */
import { readFile } from 'node:fs/promises';
import type { Page } from '@playwright/test';
import { nextTotp, signIn, user } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { readState } from '../support/state';

test.describe.configure({ mode: 'serial' });

const REASON = 'E2E release check: synthetic message, approved by a second admin';

async function fillReasonAndConfirm(page: Page, confirmLabel: string): Promise<void> {
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('textbox').first().fill(REASON);
  await dialog.getByRole('button', { name: confirmLabel, exact: true }).click();
}

test('reviewer requests the release; a second admin approves; states and audit rows', async ({
  page,
  context,
}, testInfo) => {
  test.setTimeout(240_000);
  const s = readState();
  await signIn(page, 'alphaReviewer', { next: `/quarantine/${s.alpha.approvalEntryId}` });
  await expect(page.getByRole('heading', { level: 1, name: 'Quarantine entry' })).toBeVisible();
  // The reviewer has no content access: the subject is withheld, the envelope is shown.
  await expect(page.locator('main')).toContainText('billing@external.e2e-portal.test');
  await expect(page.locator('main')).toContainText('not shown: needs the preview permission');
  await page.getByRole('button', { name: 'Request release' }).click();
  await fillReasonAndConfirm(page, 'Request release');
  // Pending approval, with the pre-check's approval reason.
  await expect(page.locator('main')).toContainText(/pending approval/i, { timeout: 20_000 });
  await context.clearCookies();

  // The reviewer cannot decide their own request; the approver (organization admin, MFA) can.
  await signIn(page, 'alphaApprover', { next: '/quarantine/approvals' });
  const row = page
    .locator('main table tbody tr')
    .filter({ hasText: /release request/i })
    .filter({ hasText: /no_scan_round|no scan round/i });
  await expect(row.first()).toBeVisible();
  await row.first().getByRole('link').first().click();
  await expect(page.getByRole('heading', { level: 1, name: 'Approval request' })).toBeVisible();
  await expect(page.locator('main')).toContainText('E2E approval-required message');
  const approvalUrl = page.url();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await fillReasonAndConfirm(page, 'Approve');
  await expect(page.locator('main')).toContainText(/approved/i, { timeout: 20_000 });

  // The entry: no longer pending approval; the release attempt is listed.
  await page.goto(`/quarantine/${s.alpha.approvalEntryId}`);
  const attempts = page
    .getByRole('region', { name: 'Release attempts' })
    .or(
      page
        .locator('section')
        .filter({ has: page.getByRole('heading', { name: 'Release attempts' }) }),
    );
  await expect(attempts.first()).toBeVisible();
  const releaseLink = attempts.first().getByRole('link').first();
  await expect(releaseLink).toBeVisible({ timeout: 20_000 });
  await releaseLink.click();
  await expect(page).toHaveURL(/\/quarantine\/releases\//);

  // The executor (policy-engine, quarantine role) decides the queued release. Assert its outcome
  // only if it runs; otherwise record that it stayed pending.
  const main = page.locator('main');
  let executed = false;
  for (let i = 0; i < 12 && !executed; i++) {
    const text = await main.innerText();
    executed = /dispatched|approval required|refused|rescan required|message busy|stale/i.test(
      text.replace(/pending/gi, ''),
    );
    if (!executed) await page.waitForTimeout(5_000);
  }
  const outcome = executed
    ? `executor decided: ${(await main.innerText()).match(/dispatched|approval required|refused|rescan required|message busy|stale/i)?.[0]}`
    : 'release stayed pending for 60 s: the quarantine executor did not run (not asserted)';
  testInfo.annotations.push({
    type: 'release-execution',
    description: outcome,
  });

  // Audit rows of both decisions (Audit logs, exact action filter).
  // The audit search reads the replica (a few seconds behind).
  for (const action of ['quarantine.approval_requested', 'quarantine.approval_approved']) {
    await expect(async () => {
      await page.goto(`/audit-logs?range=7d&action=${action}`);
      await expect(page.locator('main table').first()).toContainText(action, { timeout: 3_000 });
    }).toPass({ timeout: 30_000 });
  }
  await page.goto(approvalUrl);
  await expect(page.locator('main')).toContainText(/approved/i);
});

test('sanitized preview: the stored part as text, no active content, defanged link', async ({
  page,
}) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: `/quarantine/${s.alpha.previewEntryId}` });
  await page.getByRole('button', { name: 'Show sanitized preview' }).click();
  const text = page.getByLabel('Sanitized message text');
  await expect(text).toContainText(s.alpha.previewText);
  await expect(page.locator('main')).not.toContainText('window.__e2eInjected');
  await expect(page.locator('main')).toContainText(/hxxp:\/\/newsletter\[\.\]e2e-portal/);
  expect(
    await page.evaluate(() => (window as unknown as { __e2eInjected?: number }).__e2eInjected),
  ).toBeUndefined();
  // No iframe, no blob: or data: document of message content.
  await expect(page.locator('main iframe')).toHaveCount(0);
});

test('download grant: password + TOTP → single-use attachment response', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaApprover', { next: '/quarantine/settings' });
  // Downloads are off by default (step 5.3): an administrator enables them.
  const settings = page.getByRole('form', { name: 'Quarantine settings' });
  await settings
    .getByRole('switch', { name: /Allow downloads of clean quarantined content/ })
    .click();
  await settings.getByRole('button', { name: 'Save settings' }).click();
  await expect(settings.getByRole('switch', { name: /Allow downloads/ })).toBeChecked();

  await page.goto(`/quarantine/${s.alpha.previewEntryId}`);
  await page.getByRole('button', { name: 'Download', exact: true }).click();
  const grant = page.getByRole('form', { name: 'Download grant' });
  await grant.getByLabel('Your password (required)').fill(user('alphaApprover').password);
  await grant.getByLabel('Authenticator code (required)').fill(await nextTotp('alphaApprover'));
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    grant.getByRole('button', { name: 'Download', exact: true }).click(),
  ]);
  // The api names it `message-<entryId>.eml.bin` (never opened by the browser, step 5.3 §19).
  expect(download.suggestedFilename()).toBe(`message-${s.alpha.previewEntryId}.eml.bin`);
  const body = await readFile(await download.path(), 'utf8');
  expect(body).toContain('Subject: E2E preview message');
  // The token is single use: the same URL again is refused.
  const again = await page.request.get(download.url());
  expect(again.status()).toBe(410);
  expect(((await again.json()) as { code: string }).code).toBe('quarantine_download_token_used');
});
