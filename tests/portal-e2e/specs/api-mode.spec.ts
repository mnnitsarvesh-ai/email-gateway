/**
 * Step API-1 (docs/plan/steps/35-api-mode-protection.md D3, D14, §9.5): API-mode protection in the
 * browser against the real api (MySQL writer/replica, Redis), on the synthetic tenant zeta
 * (seed/api-mode.ts; enterprise plan, `api_mode_protection` on):
 *
 * - the onboarding wizard's first step "Protection mode" for each option (Inline, API, Hybrid):
 *   API creates the domain with inbound off (toggle hidden) and (step API-4 B1) lists only the
 *   API-mode steps (no DNS, destinations or recipients step); the stored mode is checked on the
 *   writer;
 * - a domain mode change and an organization mode change through their dialogs (reason
 *   required) with the audit entries visible on the audit page; the MX-conflict refusal names the
 *   domain and suggests Hybrid (domain and organization);
 * - /api-mode: coverage tiles, the connection table (check titles, grant link), the feeds toggle
 *   (settings route with CAS), the Mailboxes and Detections tables, the Setup tab and guide;
 * - the provider connection's "Mailbox access for API mode" card;
 * - a read-only user sees every page without any write control.
 *
 * No mail is sent and no provider is contacted: the mailbox-worker's rows are seeded in a state the
 * running worker evaluates again and keeps (seed/api-mode.ts).
 */
import { randomBytes } from 'node:crypto';
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { writerDb } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ mode: 'serial', timeout: 240_000 });

const suffix = () => randomBytes(3).toString('hex');
const literal = (text: string) => new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

async function zetaId(): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.zeta.id },
    select: { id: true },
  });
  return org.id;
}

async function storedDomain(name: string) {
  return writerDb().domain.findFirst({
    where: { organizationId: await zetaId(), name },
    select: { protectionMode: true, inboundEnabled: true },
  });
}

/** The audit page lists the action (the audit search reads the replica: retried). */
async function expectAuditRow(page: Page, action: string, text: string) {
  await expect(async () => {
    await page.goto(`/audit-logs?range=7d&action=${action}`);
    await expect(page.locator('main table').first()).toContainText(action, { timeout: 3_000 });
    await expect(page.locator('main table').first()).toContainText(text, { timeout: 3_000 });
  }).toPass({ timeout: 45_000 });
}

test('wizard: the protection-mode step for Inline, API and Hybrid', async ({ page }) => {
  await signIn(page, 'zetaAdmin', { next: '/domains/onboarding' });
  await expect(page.getByRole('heading', { name: '1. Protection mode' })).toBeVisible();
  await expect(page.getByRole('radio', { name: /^Inline \(MX\)/ })).toBeChecked();
  await expect(page.getByText(/mail flow is never changed, delayed or bounced/)).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/domains/onboarding (mode)');

  const created: Record<'inline' | 'api' | 'hybrid', string> = {
    inline: `in-${suffix()}.zeta.e2e-portal.test`,
    api: `api-${suffix()}.zeta.e2e-portal.test`,
    hybrid: `hy-${suffix()}.zeta.e2e-portal.test`,
  };
  for (const mode of ['api', 'hybrid', 'inline'] as const) {
    await page.goto('/domains/onboarding');
    const label =
      mode === 'api' ? /^API \(no MX change\)/ : mode === 'hybrid' ? /^Hybrid/ : /^Inline \(MX\)/;
    await page.getByRole('radio', { name: label }).click();
    await page.getByRole('button', { name: 'Continue' }).click();
    const add = page.getByRole('form', { name: 'Add domain' });
    await expect(add.getByLabel('Domain name (required)')).toBeVisible();
    if (mode === 'api') {
      await expect(add.getByText('Receive inbound mail for this domain')).toHaveCount(0);
      await expect(add.getByRole('note')).toContainText('stays off in API mode');
      await expectNoSeriousA11yViolations(page, '/domains/onboarding (add, API)');
    } else {
      await expect(add.getByText('Receive inbound mail for this domain')).toBeVisible();
    }
    await add.getByLabel('Domain name (required)').fill(created[mode]);
    await add.getByRole('button', { name: 'Add domain' }).click();
    const steps = page.getByRole('navigation', { name: 'Onboarding steps' });
    if (mode === 'api') {
      // Step API-4 (B1): API lists only what applies — the TXT ownership record, no DNS step,
      // destinations, recipients or MX/SPF/DKIM/DMARC records.
      await expect(page).toHaveURL(/domainId=.*step=ownership/);
      await expect(page.getByRole('heading', { name: '3. Verify ownership' })).toBeVisible();
      await expect(steps.getByRole('button', { name: /Destination mail server/ })).toHaveCount(0);
      await expect(steps.getByRole('button', { name: /Recipient validation/ })).toHaveCount(0);
      await expect(steps.getByRole('button', { name: /Publish DNS records/ })).toHaveCount(0);
      await expectNoSeriousA11yViolations(page, '/domains/onboarding (ownership, API)');
      await steps.getByRole('button', { name: /Connect mailboxes/ }).click();
      await expect(page.getByRole('heading', { name: '4. Connect mailboxes' })).toBeVisible();
      await expect(
        page.getByText(/No Microsoft 365 or Google Workspace connection is linked/),
      ).toBeVisible();
    } else if (mode === 'inline') {
      await expect(page).toHaveURL(/domainId=.*step=dns/);
      await expect(page.getByRole('heading', { name: '3. Publish DNS records' })).toBeVisible();
      await expect(steps.getByRole('button', { name: /Mailbox protection/ })).toBeDisabled();
      await expect(page.getByText('Not required in API mode')).toHaveCount(0);
    } else {
      await expect(page).toHaveURL(/domainId=.*step=dns/);
      await expect(page.getByRole('heading', { name: '3. Publish DNS records' })).toBeVisible();
      await expect(steps.getByRole('button', { name: /Destination mail server/ })).toBeEnabled();
      await expect(steps.getByRole('button', { name: /Connect mailboxes/ })).toBeEnabled();
    }
  }
  expect(await storedDomain(created.api)).toEqual({ protectionMode: 'api', inboundEnabled: false });
  expect(await storedDomain(created.hybrid)).toEqual({
    protectionMode: 'hybrid',
    inboundEnabled: true,
  });
  expect(await storedDomain(created.inline)).toEqual({
    protectionMode: 'inline',
    inboundEnabled: true,
  });
});

test('domain mode: change with a reason (audited); MX conflict suggests Hybrid', async ({
  page,
}) => {
  const s = readState().apiMode;
  await signIn(page, 'zetaAdmin', { next: '/domains' });
  const table = page.locator('main table').first();
  await expect(table).toContainText(s.domainNames.api);
  await expect(table.getByRole('row', { name: literal(s.domainNames.hybrid) })).toContainText(
    'Hybrid',
  );
  await expect(table.getByRole('row', { name: literal(s.domainNames.switch) })).toContainText(
    'inherited',
  );

  // MX conflict: the inline domain's MX points to the gateway.
  await page.goto(`/domains/${s.domains.inline}`);
  const panel = page.locator('main').getByRole('heading', { name: 'Protection mode' });
  await expect(panel).toBeVisible();
  await page.getByRole('button', { name: 'Change mode' }).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByRole('radio', { name: /^API \(no MX change\)/ }).click();
  await dialog.getByLabel(/Reason/).fill('E2E: try API mode with the MX at the gateway');
  await dialog.getByRole('button', { name: 'Change mode' }).click();
  await expect(dialog.getByText(/the MX record still points to the gateway/)).toBeVisible({
    timeout: 20_000,
  });
  await expect(dialog.getByText(/Choose Hybrid/)).toBeVisible();
  await expect(dialog.getByText('protection_mode_mx_points_to_gateway')).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/domains/[id] mode dialog (MX conflict)');
  await dialog.getByRole('button', { name: 'Cancel' }).click();

  // A domain without an MX observation: API is accepted, then back to inherit.
  const reason = `E2E domain mode ${suffix()}`;
  await page.goto(`/domains/${s.domains.switch}`);
  await page.getByRole('button', { name: 'Change mode' }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByRole('radio', { name: /^API \(no MX change\)/ }).click();
  await dialog.getByRole('button', { name: 'Change mode' }).click();
  await expect(dialog.getByText('Enter a reason.')).toBeVisible();
  await dialog.getByLabel(/Reason/).fill(reason);
  await dialog.getByRole('button', { name: 'Change mode' }).click();
  await expect(dialog).toHaveCount(0, { timeout: 20_000 });
  await expect(page.getByText('This domain (API (no MX change))')).toBeVisible({ timeout: 20_000 });
  expect((await storedDomain(s.domainNames.switch))?.protectionMode).toBe('api');
  await expectAuditRow(page, 'domain.protection_mode_changed', 'domain.protection_mode_changed');

  await page.goto(`/domains/${s.domains.switch}`);
  await page.getByRole('button', { name: 'Change mode' }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByRole('radio', { name: /^Inherit from organization/ }).click();
  await dialog.getByLabel(/Reason/).fill(`${reason} (back)`);
  await dialog.getByRole('button', { name: 'Change mode' }).click();
  await expect(dialog).toHaveCount(0, { timeout: 20_000 });
  await expect(page.getByText('Inherited from the organization (no mode of its own)')).toBeVisible({
    timeout: 20_000,
  });
});

test('organization mode: counts, inheriting domains, change (audited) and MX conflict', async ({
  page,
}) => {
  const s = readState();
  await signIn(page, 'zetaAdmin', { next: `/organizations/${s.orgs.zeta.id}` });
  const counts = page.getByRole('list', { name: 'Domains per effective mode' });
  await expect(counts).toBeVisible({ timeout: 20_000 });
  await expectNoSeriousA11yViolations(page, '/organizations/[id] (protection mode)');

  // API for the whole organization: refused, the inline domain's MX points to the gateway.
  await page.getByRole('button', { name: 'Change organization mode' }).click();
  let dialog = page.getByRole('dialog');
  await expect(dialog.getByText(/without a mode of their own inherit/)).toBeVisible();
  await dialog.getByRole('radio', { name: /^API \(no MX change\)/ }).click();
  await dialog.getByLabel(/Reason/).fill('E2E: organization to API mode');
  await dialog.getByRole('button', { name: 'Change organization mode' }).click();
  await expect(dialog.getByText(s.apiMode.domainNames.inline).first()).toBeVisible({
    timeout: 20_000,
  });
  await expect(dialog.getByText(/Choose Hybrid/)).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();

  // Hybrid is accepted (the result names the inheriting domains), then back to Inline.
  for (const [mode, label] of [
    ['Hybrid', /^Hybrid/],
    ['Inline (MX)', /^Inline \(MX\)/],
  ] as const) {
    await page.getByRole('button', { name: 'Change organization mode' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByRole('radio', { name: label }).click();
    await dialog.getByLabel(/Reason/).fill(`E2E organization mode ${mode} ${suffix()}`);
    await dialog.getByRole('button', { name: 'Change organization mode' }).click();
    await expect(
      dialog.getByText(
        new RegExp(
          `Organization mode is now ${mode.replace(/[()]/g, '\\$&')}; \\d+ domains? inherit`,
        ),
      ),
    ).toBeVisible({ timeout: 20_000 });
    await dialog.getByRole('button', { name: 'Done' }).click();
  }
  await expectAuditRow(
    page,
    'organization.protection_mode_changed',
    'organization.protection_mode_changed',
  );
});

test('/api-mode: coverage tiles, connections, feeds toggle, mailboxes, detections, setup', async ({
  page,
}) => {
  const s = readState().apiMode;
  await signIn(page, 'zetaAdmin', { next: '/api-mode' });
  await expect(page.getByRole('heading', { level: 1, name: 'Mailbox protection' })).toBeVisible();
  const tiles = page.getByRole('list', { name: 'Mailbox protection summary' });
  await expect(tiles).toContainText('Mailboxes covered', { timeout: 20_000 });
  await expect(tiles).toContainText('3 / 4');
  await expect(tiles).toContainText('Detection lag, last hour');
  const table = page.getByRole('table').first();
  const m365 = table.getByRole('row', { name: literal(s.m365Name) });
  await expect(m365).toContainText('Degraded');
  // Only the non-passing checks are named: coverage warns (3 of 4), feeds are off.
  await expect(m365).toContainText('Mailbox coverage');
  await expect(m365).not.toContainText('Mailbox feed errors');
  const google = table.getByRole('row', { name: literal(s.googleName) });
  await expect(google).toContainText('Not granted');
  await expect(
    google.getByRole('link', { name: `Grant mailbox access for ${s.googleName}` }),
  ).toHaveAttribute(
    'href',
    `/integrations/providers/${s.googleConnectionId}?tab=settings#mailbox-access`,
  );
  await expectNoSeriousA11yViolations(page, '/api-mode (coverage)');

  // Feeds toggle through PUT …/settings (CAS on the row version), then off again.
  const feeds = page.getByRole('switch', { name: `Mailbox feeds for ${s.m365Name}` });
  await expect(feeds).not.toBeChecked();
  await feeds.click();
  await expect(feeds).toBeChecked({ timeout: 20_000 });
  await feeds.click();
  await expect(feeds).not.toBeChecked({ timeout: 20_000 });
  // Without mailbox access the api refuses feeds; the page explains it.
  await page.getByRole('switch', { name: `Mailbox feeds for ${s.googleName}` }).click();
  await expect(
    page.getByText(/Grant mailbox access for API mode on the connection first/),
  ).toBeVisible({
    timeout: 20_000,
  });

  await page.getByRole('tab', { name: 'Mailboxes' }).click();
  const mailboxes = page.getByRole('table').first();
  for (const address of s.mailboxes) await expect(mailboxes).toContainText(address);
  await expect(mailboxes.getByRole('row', { name: /cy@/ })).toContainText('Gap');
  await expectNoSeriousA11yViolations(page, '/api-mode (mailboxes)');

  await page.getByRole('tab', { name: 'Detections' }).click();
  const detections = page.getByRole('table').first();
  await expect(detections).toContainText('Phishing', { timeout: 20_000 });
  await expect(detections).toContainText('Hidden (masked)');
  await expect(detections).toContainText(s.mailboxes[0]!);
  await expectNoSeriousA11yViolations(page, '/api-mode (detections)');

  await page.getByRole('tab', { name: 'Setup' }).click();
  await expect(page.getByRole('list', { name: 'API-mode setup steps' })).toContainText(
    'Mailbox access granted',
    { timeout: 20_000 },
  );
  await expect(page.getByRole('button', { name: 'Download Markdown' })).toBeVisible({
    timeout: 20_000,
  });
  await expectNoSeriousA11yViolations(page, '/api-mode (setup)');
});

test('the connection page lists "Mailbox access for API mode" with its permissions', async ({
  page,
}) => {
  const s = readState().apiMode;
  await signIn(page, 'zetaAdmin', {
    next: `/integrations/providers/${s.m365ConnectionId}?tab=settings`,
  });
  await expect(page.getByRole('heading', { name: 'Mailbox access for API mode' })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByText(/Mail.ReadWrite \(read new messages/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Revoke mailbox access' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/integrations/providers/[id]?tab=settings');
});

test('read-only user: every API-mode page without write controls', async ({ page }) => {
  const s = readState();
  await signIn(page, 'zetaReadOnly', { next: '/api-mode' });
  await expect(page.getByRole('link', { name: 'Mailbox protection' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Mailbox protection summary' })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByRole('switch')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Sync inventory/ })).toHaveCount(0);
  await page.getByRole('tab', { name: 'Mailboxes' }).click();
  await expect(page.getByRole('table').first()).toContainText(s.apiMode.mailboxes[0]!);
  await expect(page.getByRole('button', { name: /^Actions for / })).toHaveCount(0);
  await page.goto(`/domains/${s.apiMode.domains.api}`);
  await expect(page.getByRole('heading', { name: 'Protection mode' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Change mode' })).toHaveCount(0);
  await page.goto(`/organizations/${s.orgs.zeta.id}`);
  await expect(page.getByRole('list', { name: 'Domains per effective mode' })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByRole('button', { name: 'Change organization mode' })).toHaveCount(0);
});
