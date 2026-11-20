/**
 * Step 8.6 (docs/plan/steps/27-journal-intake-and-archive-split.md D10, D11, D14, §9.5): Settings
 * → Journaling and the journal intake source pages through the browser, against the real api
 * (MySQL writer/replica, Redis, the intake address derivation with JOURNAL_INTAKE_ADDRESS_SECRET):
 *
 * - the two-layer explainer and the journaling form;
 * - a new SMTP BCC source through the wizard: networks → name → review → created, the address
 *   shown once with a copy button, then the guide (rendered and downloaded as Markdown);
 * - the masked address revealed on request (audited `journal_intake.address_revealed`) and rotated
 *   with MFA (one-time display, previous address kept for the overlap);
 * - pause and resume with confirmations, disable after the typed confirmation (terminal).
 *
 * The mail path of a source (Postfix → LMTP → archive) is the stack suite's job
 * (tests/integration/journal-intake.test.ts); no message is sent here.
 */
import { readFileSync } from 'node:fs';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { alphaIntakeSources, auditRows, ensureAlphaJournaling } from '../support/journaling';
import { expectNoSeriousA11yViolations } from '../support/pages';

test.describe.configure({ mode: 'serial', timeout: 240_000 });

const NAME = `E2E branch Postfix ${Date.now().toString(36)}`;
const ADDRESS = /^journal-[a-z2-7]{26}@[a-z0-9.-]+$/;

test('Settings → Journaling explains the two layers and offers the intake sources', async ({
  page,
}) => {
  await ensureAlphaJournaling();
  await signIn(page, 'alphaApprover', { next: '/settings?tab=journaling' });
  await expect(page.getByRole('heading', { name: 'Journaling and the archive' })).toBeVisible();
  await expect(page.getByText('1. Journaling (this page)')).toBeVisible();
  const form = page.getByRole('form', { name: 'Journaling settings' });
  await expect(
    form.getByRole('switch', { name: 'Journal mail of this organization' }),
  ).toBeChecked();
  await expect(form.getByRole('switch', { name: 'Scan journal intake copies' })).toBeVisible();
  await expect(
    page.getByRole('heading', { level: 2, name: 'Journal intake sources' }),
  ).toBeVisible();
  await expect(page.getByRole('link', { name: 'Add source' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'settings journaling tab');
});

test('a new SMTP BCC source: wizard, one-time address, guide and Markdown download', async ({
  page,
}) => {
  await ensureAlphaJournaling();
  await signIn(page, 'alphaApprover', { next: '/settings?tab=journaling' });
  await page.getByRole('link', { name: 'Add source' }).click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Add a journal intake source' }),
  ).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'intake wizard');
  await page.getByRole('radio', { name: /SMTP BCC copy/ }).click();
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByLabel(/Sending networks/).fill('203.0.113.32/28');
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByLabel('Name (required)').fill(NAME);
  await page.getByRole('button', { name: 'Next' }).click();
  await expect(page.getByText('203.0.113.32/28')).toBeVisible();
  await page.getByRole('button', { name: 'Create intake source' }).click();

  const dialog = page.getByRole('dialog', { name: 'Intake source created' });
  await expect(dialog).toBeVisible({ timeout: 20_000 });
  const address = (await dialog.locator('[data-secret]').first().textContent())?.trim() ?? '';
  expect(address).toMatch(ADDRESS);
  await expect(dialog.getByRole('button', { name: 'Copy Intake address' })).toBeVisible();
  await dialog.getByRole('checkbox').click();
  await dialog.getByRole('button', { name: 'Done' }).click();

  // The guide of the new source, written for its own values (the address is revealed to
  // journal:manage holders, audited).
  await expect(page).toHaveURL(/\/settings\/journaling\/intake\/[0-9a-f-]{36}\?tab=guide/);
  await expect(page.getByRole('heading', { level: 1, name: NAME })).toBeVisible();
  await expect(page.getByText('Waiting for the first message')).toBeVisible();
  await expect(page.getByRole('heading', { name: /^Setup guide/ })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByText(address).first()).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'intake source guide');
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download Markdown' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/\.md$/);
  expect(readFileSync(await file.path(), 'utf8')).toContain(address);

  // The created source exists on the writer, waiting for its first copy.
  const id = /intake\/([0-9a-f-]{36})/.exec(page.url())![1]!;
  expect((await alphaIntakeSources()).find((s) => s.publicId === id)?.status).toBe(
    'pending_verification',
  );
});

test('address: masked, revealed on request (audited) and rotated with a one-time display', async ({
  page,
}) => {
  const source = (await alphaIntakeSources()).find((s) => s.status !== 'disabled');
  test.skip(!source, 'needs the source of the previous test');
  await signIn(page, 'alphaApprover', {
    next: `/settings/journaling/intake/${source!.publicId}?tab=address`,
  });
  await expect(page.getByText(/journal-••••/).first()).toBeVisible();
  const since = new Date(Date.now() - 5_000);
  await page.getByRole('button', { name: 'Reveal' }).click();
  await expect(page.getByRole('button', { name: 'Copy the address' })).toBeVisible();
  const revealed = (await page.getByText(ADDRESS).first().textContent())?.trim() ?? '';
  expect(revealed).toMatch(ADDRESS);
  await expect
    .poll(async () => (await auditRows('alpha', 'journal_intake.address_revealed', since)).length)
    .toBeGreaterThanOrEqual(1);

  await page.getByRole('button', { name: 'Rotate address' }).click();
  const confirm = page.getByRole('alertdialog');
  await confirm.getByRole('button', { name: 'Rotate address' }).click();
  const dialog = page.getByRole('dialog', { name: 'New intake address' });
  await expect(dialog).toBeVisible({ timeout: 20_000 });
  const rotated = (await dialog.locator('[data-secret]').first().textContent())?.trim() ?? '';
  expect(rotated).toMatch(ADDRESS);
  expect(rotated).not.toBe(revealed);
  await dialog.getByRole('checkbox').click();
  await dialog.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByText('Address version')).toBeVisible();
  await expect(page.locator('main').getByText('2', { exact: true }).first()).toBeVisible();
  expect(
    (await auditRows('alpha', 'journal_intake.address_rotated', since)).length,
  ).toBeGreaterThanOrEqual(1);
});

test('pause and resume with confirmations; disable only after typing disable', async ({ page }) => {
  const source = (await alphaIntakeSources()).find((s) => s.status !== 'disabled');
  test.skip(!source, 'needs the source of the previous tests');
  await signIn(page, 'alphaApprover', {
    next: `/settings/journaling/intake/${source!.publicId}?tab=settings`,
  });
  await page.getByRole('button', { name: 'Pause intake' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Pause' }).click();
  await expect(page.getByRole('button', { name: 'Resume intake' })).toBeVisible({
    timeout: 20_000,
  });
  await expect
    .poll(
      async () => (await alphaIntakeSources()).find((s) => s.publicId === source!.publicId)?.status,
    )
    .toBe('paused');
  await page.getByRole('button', { name: 'Resume intake' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Resume' }).click();
  await expect(page.getByRole('button', { name: 'Pause intake' })).toBeVisible({ timeout: 20_000 });

  await page.getByRole('button', { name: 'Disable source' }).click();
  const dialog = page.getByRole('alertdialog');
  const confirm = dialog.getByRole('button', { name: 'Disable source' });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel(/Type disable to confirm/).fill('disable');
  await confirm.click();
  await expect(page.getByText(/This source is disabled/)).toBeVisible({ timeout: 20_000 });
  await expect
    .poll(
      async () => (await alphaIntakeSources()).find((s) => s.publicId === source!.publicId)?.status,
    )
    .toBe('disabled');
});
