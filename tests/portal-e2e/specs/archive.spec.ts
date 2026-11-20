/**
 * Step 8.1 (docs/plan/steps/23-journaling-archiving.md §9.5, A17–A22, A28): journaling and the
 * compliance archive through the browser, against the real api, the real archive-worker
 * (capture, encryption, index sync), MinIO and OpenSearch.
 *
 * - organization admin (MFA) holding the migrated compliance_officer grant (step 8.6): enables
 *   journaling in Settings → Journaling; messages received afterwards are captured by the worker
 *   and appear in the archive search;
 * - search (masked), details, the audited reveal (row checked through the audit API), the
 *   sanitized preview requested explicitly, and the original downloaded through
 *   re-authentication (single use);
 * - read-only user: no archive search, no record detail (step 8.6: `archive:search`) and no
 *   content;
 * - tenant isolation: beta's record never appears for alpha, ids of the other tenant look missing.
 */
import { readFileSync } from 'node:fs';
import { nextTotp, signIn, signOut } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { bff } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';
import {
  CAPTURE_TIMEOUT_MS,
  alphaArchivingEnabled,
  archiveAuditRows,
  ensureAlphaArchive,
  ensureBetaArchive,
} from '../support/archive';
import { ARCHIVE_BODY_MARKER, ARCHIVE_SENDER, ARCHIVE_SUBJECTS } from '../seed/archive';

test.describe.configure({ mode: 'serial', timeout: CAPTURE_TIMEOUT_MS + 180_000 });

test('organization admin enables archiving and sees the next messages captured', async ({
  page,
}) => {
  // Step 8.6: the old Settings link lands on Journaling (the capture half of the old tab).
  await signIn(page, 'alphaApprover', { next: '/settings?tab=archive' });
  await expect(page).toHaveURL(/\/settings\?tab=journaling/);
  await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible();
  const form = page.getByRole('form', { name: 'Journaling settings' });
  await expect(form).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole('heading', { name: 'Journaling and the archive' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'settings journaling tab');
  if (!(await alphaArchivingEnabled())) {
    const toggle = form.getByRole('switch', { name: 'Journal mail of this organization' });
    await expect(toggle).not.toBeChecked();
    await toggle.click();
    await form.getByRole('button', { name: 'Save journaling settings' }).click();
    await expect(page.getByText('Journaling settings saved')).toBeVisible();
    await expect(
      form.getByRole('switch', { name: 'Journal mail of this organization' }),
    ).toBeChecked();
    await expect.poll(alphaArchivingEnabled).toBe(true);
  }
  // Immutability and keys moved to Archive → Retention and lock.
  await page.goto('/archive/retention?tab=immutability');
  await expect(page.getByText(/Immutable storage \(S3 Object Lock\)/)).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'archive immutability tab');
  // Messages received after the enablement are journaled by the archive-worker.
  const ids = await ensureAlphaArchive();
  await page.goto(`/archive?range=24h&sender=${encodeURIComponent(ARCHIVE_SENDER)}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Archive' })).toBeVisible();
  await expect(page.locator(`a[href="/archive/${ids.invoice}"]`).first()).toBeVisible({
    timeout: 30_000,
  });
  await page.goto('/archive/retention?tab=immutability');
  await expect(page.getByText(/^[1-9]\d* active · /)).toBeVisible({ timeout: 20_000 });
});

test('search, details, audited reveal, preview and download through re-authentication', async ({
  page,
}) => {
  const ids = await ensureAlphaArchive();
  await signIn(page, 'alphaApprover', { next: '/archive?range=24h' });
  const main = page.locator('main');
  await expect(main.locator(`a[href="/archive/${ids.invoice}"]`).first()).toBeVisible({
    timeout: 30_000,
  });
  // Masked for everyone: no subject, recipients as f***@….
  await expect(main.getByText(ARCHIVE_SUBJECTS.invoice)).toHaveCount(0);
  await expect(main.getByText('a***@alpha.e2e-portal.test').first()).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/archive');

  // Filters live in the URL; a sender search narrows to the invoice.
  await main.getByLabel('Sender address').fill(ARCHIVE_SENDER);
  await main.getByLabel('Sender address').press('Enter');
  await expect(page).toHaveURL(/sender=billing%40vendor\.e2e-portal\.test/);
  await expect(main.getByRole('link', { name: /open archived message/ })).toHaveCount(1);

  // Details.
  await main.locator(`a[href="/archive/${ids.invoice}"]`).first().click();
  await expect(page.getByRole('heading', { level: 1, name: 'Archived message' })).toBeVisible();
  await expect(main.getByText('archive-object/1', { exact: false })).toBeVisible();
  await expect(main.getByText(readState().archive.policyName).first()).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/archive/[messageId]');

  // Reveal: audited before the response; the audit row is visible through the audit API.
  const since = new Date(Date.now() - 5_000);
  await main.getByRole('button', { name: 'Reveal' }).click();
  await expect(main.getByText(ARCHIVE_SUBJECTS.invoice).first()).toBeVisible();
  await expect(main.getByText('archive-custodian@alpha.e2e-portal.test').first()).toBeVisible();
  const audit = await bff(
    page,
    'GET',
    `/audit/logs?action=archive.revealed&resourceId=${ids.invoice}&from=${encodeURIComponent(since.toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 60_000).toISOString())}`,
  );
  expect(audit.status).toBe(200);
  const rows = (audit.body?.data ?? []) as Array<{
    action: string;
    resourceId: string;
    metadata: unknown;
  }>;
  expect(rows.length).toBeGreaterThanOrEqual(1);
  expect(JSON.stringify(rows)).not.toContain(ARCHIVE_SUBJECTS.invoice);
  // Hidden again: the values were only in component state.
  await main.getByRole('button', { name: 'Hide again' }).click();
  await expect(main.getByText(ARCHIVE_SUBJECTS.invoice)).toHaveCount(0);

  // The journal and the sanitized preview are loaded only on request.
  const previews: string[] = [];
  page.on('request', (r) => {
    if (r.url().includes(`/archive/messages/${ids.invoice}/preview`)) previews.push(r.url());
  });
  await main.getByRole('button', { name: 'Load the journal' }).click();
  await expect(main.getByText('mx.vendor.e2e-portal.test', { exact: false })).toBeVisible();
  expect(previews).toHaveLength(0);
  // The frozen security results: the real worker freezes the rspamd score as a decimal string
  // and the api restores it for the scans mapper (WP3 D2).
  const securityResponse = page.waitForResponse((r) =>
    r.url().includes(`/archive/messages/${ids.invoice}/security`),
  );
  await main.getByRole('button', { name: 'Load the security results' }).click();
  expect((await securityResponse).status()).toBe(200);
  await expect(main.getByText(/Snapshot of round \d+, revision \d+/).first()).toBeVisible();
  await expect(main.getByText('1.5 / 15', { exact: true }).first()).toBeVisible();
  await main.getByRole('button', { name: 'Show sanitized preview' }).click();
  await expect(main.getByTestId('preview-text')).toContainText(ARCHIVE_BODY_MARKER);
  expect(previews).toHaveLength(1);
  expect(
    (await archiveAuditRows('alpha', 'archive.previewed', since)).length,
  ).toBeGreaterThanOrEqual(1);

  // Download the original through re-authentication.
  await main.getByRole('button', { name: 'Download original' }).click();
  const dialog = page.getByRole('dialog');
  await dialog
    .getByLabel('Your password (required)')
    .fill(readState().users.alphaApprover.password);
  await dialog.getByLabel('Authenticator code (required)').fill(await nextTotp('alphaApprover'));
  const download = page.waitForEvent('download');
  await dialog.getByRole('button', { name: 'Download' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/\.eml$/);
  const path = await file.path();
  const eml = readFileSync(path, 'utf8');
  expect(eml).toContain(`Subject: ${ARCHIVE_SUBJECTS.invoice}`);
  expect(eml).toContain(ARCHIVE_BODY_MARKER);
  expect(
    (await archiveAuditRows('alpha', 'archive.downloaded', since)).length,
  ).toBeGreaterThanOrEqual(1);

  // The malicious record cannot be downloaded interactively.
  await page.goto(`/archive/${ids.phish}`);
  await expect(
    main.getByText(/classified as malicious: it cannot be downloaded interactively/),
  ).toBeVisible();
});

test('read-only user: no archive search, no record detail and no content', async ({ page }) => {
  const ids = await ensureAlphaArchive();
  await signIn(page, 'alphaReadOnly', { next: '/archive/retention' });
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(page.getByRole('heading', { level: 1, name: 'Retention and lock' })).toBeVisible();
  await expect(nav.getByRole('link', { name: 'Search', exact: true })).toHaveCount(0);
  await expect(nav.getByRole('link', { name: 'eDiscovery' })).toHaveCount(0);
  expect(
    (
      await bff(
        page,
        'GET',
        `/archive/messages?from=${encodeURIComponent(new Date(Date.now() - 86_400_000).toISOString())}&to=${encodeURIComponent(new Date().toISOString())}`,
      )
    ).status,
  ).toBe(403);
  await page.goto('/archive');
  await expect(
    page.getByText(/You do not have access|do not have permission/i).first(),
  ).toBeVisible();
  // Step 8.6 (ADR-0089, Q4): record detail needs archive:search; archive:read alone opens
  // configuration only.
  await page.goto(`/archive/${ids.invoice}`);
  await expect(
    page.getByRole('heading', { level: 1, name: 'You do not have access to this page' }),
  ).toBeVisible();
  expect((await bff(page, 'GET', `/archive/messages/${ids.invoice}`)).status).toBe(403);
  expect((await bff(page, 'GET', `/archive/messages/${ids.invoice}/journal`)).status).toBe(403);
  expect((await bff(page, 'GET', `/archive/messages/${ids.invoice}/preview`)).status).toBe(403);
  expect(
    (await bff(page, 'POST', `/archive/messages/${ids.invoice}/reveal`, { fields: ['subject'] }))
      .status,
  ).toBe(403);
});

test('tenant isolation: the other tenant’s archive is invisible both ways', async ({ page }) => {
  const ids = await ensureAlphaArchive();
  const betaId = await ensureBetaArchive();
  await signIn(page, 'alphaApprover', { next: `/archive/${betaId}` });
  await expect(
    page.getByText('It does not exist, or you do not have access to it.').first(),
  ).toBeVisible();
  const from = encodeURIComponent(new Date(Date.now() - 86_400_000).toISOString());
  const to = encodeURIComponent(new Date(Date.now() + 60_000).toISOString());
  const alphaList = await bff(page, 'GET', `/archive/messages?from=${from}&to=${to}&limit=100`);
  expect(alphaList.status).toBe(200);
  const alphaIds = ((alphaList.body?.data ?? []) as Array<{ messageId: string }>).map(
    (m) => m.messageId,
  );
  expect(alphaIds).toContain(ids.invoice);
  expect(alphaIds).not.toContain(betaId);
  expect((await bff(page, 'GET', `/archive/messages/${betaId}/journal`)).status).toBe(404);

  await signOut(page);
  await signIn(page, 'betaAdmin', { next: `/archive/${ids.invoice}` });
  await expect(
    page.getByText('It does not exist, or you do not have access to it.').first(),
  ).toBeVisible();
  const betaList = await bff(page, 'GET', `/archive/messages?from=${from}&to=${to}&limit=100`);
  expect(betaList.status).toBe(200);
  const betaIds = ((betaList.body?.data ?? []) as Array<{ messageId: string }>).map(
    (m) => m.messageId,
  );
  expect(betaIds).toContain(betaId);
  expect(betaIds).not.toContain(ids.invoice);
});
