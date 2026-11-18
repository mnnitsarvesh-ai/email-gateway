/**
 * Step 8.1 (docs/plan/steps/23-journaling-archiving.md §9.5, A12, A18, A28): an eDiscovery case
 * from opening to a downloaded export, against the real api and the real archive-worker
 * (`ediscovery` role: case searches verified against MySQL, signed ZIP exports).
 *
 * The compliance auditor opens the case and its custodians, runs the search, reviews the hits
 * and exports and downloads the package (manifest and signature present). Holds need
 * `archive:legal_hold`, which compliance auditors do not hold (A20, product owner decision 1):
 * the organization admin places the hold, and the auditor sees it without hold controls.
 */
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { nextTotp, signIn, signOut } from '../support/auth';
import { CAPTURE_TIMEOUT_MS, ensureAlphaArchive } from '../support/archive';
import { expect, test } from '../support/fixtures';
import { bff } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ mode: 'serial', timeout: CAPTURE_TIMEOUT_MS + 300_000 });

test('compliance auditor: case → custodians → hold (admin) → search → review → export → download', async ({
  page,
}) => {
  const ids = await ensureAlphaArchive();
  const custodian = readState().archive.custodian;
  const caseName = `E2E case ${randomUUID().slice(0, 8)}`;
  const main = page.locator('main');

  // 1. The auditor opens a case with the custodian.
  await signIn(page, 'alphaAuditorMfa', { next: '/ediscovery' });
  await expect(page.getByRole('heading', { level: 1, name: 'eDiscovery' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/ediscovery');
  await main.getByRole('button', { name: 'New case' }).click();
  const create = page.getByRole('dialog');
  await create.getByLabel('Case name (required)').fill(caseName);
  await create.getByLabel('Matter reference').fill('E2E-MATTER-1');
  await create.getByLabel(/Custodians/).fill(custodian);
  await create.getByRole('button', { name: 'Open case' }).click();
  await expect(page.getByRole('heading', { level: 1, name: caseName })).toBeVisible();
  const caseUrl = new URL(page.url());
  const caseId = caseUrl.pathname.split('/').pop()!;
  await page.getByRole('tab', { name: 'Custodians' }).click();
  await expect(main.getByLabel('Custodian addresses (one per line)')).toHaveValue(custodian);
  await expectNoSeriousA11yViolations(page, '/ediscovery/[caseId] custodians');
  // No hold controls without archive:legal_hold.
  await page.getByRole('tab', { name: 'Legal holds' }).click();
  await expect(main.getByText(/needs the archive:legal_hold permission/)).toBeVisible();
  await expect(main.getByRole('button', { name: 'Place a hold' })).toHaveCount(0);
  await signOut(page);

  // 2. The organization admin (MFA) places a hold on the case's custodians.
  await signIn(page, 'alphaApprover', { next: `/ediscovery/${caseId}?tab=holds` });
  await main.getByRole('button', { name: 'Place a hold' }).click();
  const hold = page.getByRole('dialog');
  await hold.getByLabel('Hold name (required)').fill(`${caseName} hold`);
  await hold.getByLabel('Reason (required)').fill('E2E litigation notice');
  await hold.getByRole('button', { name: 'Place hold' }).click();
  await expect(main.getByRole('link', { name: `${caseName} hold` })).toBeVisible();
  const holds = await bff(page, 'GET', `/legal-holds?caseId=${caseId}&status=active`);
  const holdId = (
    (holds.body?.data ?? []) as Array<{ id: string; criteria: { custodians?: string[] } }>
  )[0];
  expect(holdId?.criteria.custodians).toEqual([custodian]);
  await signOut(page);

  // 3. The auditor runs the case search over the custodians' mail.
  await signIn(page, 'alphaAuditorMfa', { next: `/ediscovery/${caseId}?tab=searches` });
  await main.getByRole('button', { name: 'New search' }).click();
  const form = main.getByRole('form', { name: 'New case search' });
  await expect(form.getByRole('checkbox', { name: /Mail of the case’s custodians/ })).toBeChecked();
  await form.getByRole('button', { name: 'Run search' }).click();
  const searchLink = main.getByRole('link', { name: /^Search of / }).first();
  await expect(searchLink).toBeVisible();
  // The ediscovery role completes it (polled by the page every 5 s).
  await expect(main.getByText('Completed').first()).toBeVisible({ timeout: 120_000 });
  await searchLink.click();
  await expect(page.getByRole('heading', { level: 1, name: 'Case search' })).toBeVisible();
  await expect(
    main
      .getByText(/^Complete:|may be incomplete|index was behind|not been verified|disagreed/)
      .first(),
  ).toBeVisible();
  for (const id of [ids.invoice, ids.outbound, ids.phish]) {
    await expect(main.locator(`a[href="/archive/${id}"]`).first()).toBeVisible();
  }
  await expect(main.getByText('E2E archive invoice 9031')).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, '/ediscovery/[caseId]/searches/[searchId]');

  // 4. Review: tag every hit as relevant (one audited request).
  await main
    .getByRole('checkbox', { name: /select all/i })
    .first()
    .check();
  await main.getByRole('combobox', { name: 'Tag as' }).click();
  await page.getByRole('option', { name: 'Relevant', exact: true }).click();
  await main.getByRole('button', { name: /^Tag 3 hits as relevant$/ }).click();
  await expect(main.getByText(/Tagged 3 hit\(s\) as relevant/)).toBeVisible();

  // 5. Export: the selection holds a malicious message → explicit acknowledgement.
  await page.goto(`/ediscovery/${caseId}?tab=exports`);
  await main.getByRole('button', { name: 'New export' }).click();
  const exportDialog = page.getByRole('dialog');
  await exportDialog.getByRole('button', { name: 'Create export' }).click();
  await expect(exportDialog.getByText(/contains 1 malicious message/)).toBeVisible();
  await exportDialog.getByRole('checkbox', { name: 'Include malicious messages' }).check();
  await exportDialog.getByRole('button', { name: 'Create export' }).click();
  await expect(exportDialog).toHaveCount(0);
  await expect(main.getByRole('button', { name: 'Download' }).first()).toBeVisible({
    timeout: 120_000,
  });
  await expect(main.getByText('3 (1 malicious, under malicious/)')).toBeVisible();

  // 6. Download through re-authentication: a ZIP with the manifest and its signature.
  await main.getByRole('button', { name: 'Download' }).first().click();
  const grant = page.getByRole('dialog');
  await grant
    .getByLabel('Your password (required)')
    .fill(readState().users.alphaAuditorMfa.password);
  await grant.getByLabel('Authenticator code (required)').fill(await nextTotp('alphaAuditorMfa'));
  const download = page.waitForEvent('download');
  await grant.getByRole('button', { name: 'Download' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/\.zip$/);
  const zip = readFileSync(await file.path());
  expect(zip.subarray(0, 2).toString('latin1')).toBe('PK');
  for (const name of ['manifest.json', 'manifest.sig', 'README.txt', 'malicious/']) {
    expect(zip.includes(Buffer.from(name)), name).toBe(true);
  }
});

test('roles and isolation: security analyst has no eDiscovery; beta never sees the alpha case', async ({
  page,
}) => {
  await signIn(page, 'alphaAnalyst', { next: '/ediscovery' });
  await expect(
    page.getByText(/You do not have access|do not have permission/i).first(),
  ).toBeVisible();
  await expect(
    page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'eDiscovery' }),
  ).toHaveCount(0);
  await signOut(page);
  await signIn(page, 'alphaAuditorMfa', { next: '/ediscovery' });
  const cases = await bff(page, 'GET', '/ediscovery/cases?limit=100');
  const alphaCase = ((cases.body?.data ?? []) as Array<{ id: string }>)[0];
  test.skip(!alphaCase, 'no alpha case (the case spec did not run)');
  await signOut(page);
  await signIn(page, 'betaAdmin', { next: `/ediscovery/${alphaCase!.id}` });
  await expect(
    page.getByText('It does not exist, or you do not have access to it.').first(),
  ).toBeVisible();
  const foreignHolds = await bff(page, 'GET', `/legal-holds?caseId=${alphaCase!.id}`);
  if (foreignHolds.status === 200) expect(foreignHolds.body?.data).toEqual([]);
  else expect(foreignHolds.status).toBe(404);
});
