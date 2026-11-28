/**
 * Step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md B1–B9, A10, §10.5): the
 * mode-specific add-domain wizard, the domain page per mode, Protection by mode and the read-only
 * user, in the browser against the real api (MySQL writer/replica, Redis), on the synthetic
 * tenant eta (seed/onboarding.ts; enterprise plan, `api_mode_protection` and `journal_intake`):
 *
 * - inline regression: the full inline wizard (mode → add → DNS → verify → destinations →
 *   recipients → activate → done) exactly as before, and no `/api-mode/domains/*` request;
 * - api path: the ownership step lists only the TXT record; ownership through the bound
 *   Microsoft 365 tenant (provider check → the worker's answer → the api scheduler's win, method
 *   `provider_tenant`); connect (link the verified domain), intake (the seeded journal source),
 *   which mailboxes, threat action (detect only for 7 days, then remind: the default),
 *   review/activate and the live first-copy check;
 * - hybrid path: the inline steps plus the API steps and the provider option on the verify step;
 * - the domain page per mode, Protection by mode and a read-only user.
 *
 * Two test seams write what a worker would write, on the writer (documented in seed/onboarding.ts):
 * (1) the integration-worker's answer to the provider ownership check (`domain_verifications.
 * provider_result = verified`, `provider_checked_at`) — the api's own DomainCheckScheduler
 * (DOMAIN_BACKGROUND_JOBS_ENABLED, every DOMAIN_JOBS_INTERVAL_SECONDS) then applies the win;
 * the api offers no scheduler trigger, so the spec waits for its next tick; (2) the
 * mailbox-worker's rows of a mailbox and of the first copy. The inline domain's DNS ownership is
 * a third seam (no DNS record can be published to the dns-sink resolver): the spec marks the
 * domain verified the way the scheduler's TXT win does. Nothing is sent and no provider is
 * contacted.
 */
import { randomBytes } from 'node:crypto';
import type { Page, Request } from '@playwright/test';
import { seedEtaFirstCopy, seedEtaMailbox } from '../seed/onboarding';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { writerDb } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ mode: 'serial', timeout: 300_000 });

const suffix = () => randomBytes(3).toString('hex');
const newName = (label: string) => `${label}-${suffix()}.${readState().onboarding.newZone}`;

async function etaId(): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.eta.id },
    select: { id: true },
  });
  return org.id;
}

async function domainRow(name: string) {
  return writerDb().domain.findFirstOrThrow({
    where: { organizationId: await etaId(), name },
    select: { id: true, publicId: true, status: true, ownershipMethod: true, protectionMode: true },
  });
}

/** Records every request the page makes to an API-mode domain route. */
function trackApiModeDomainRequests(page: Page): string[] {
  const seen: string[] = [];
  page.on('request', (request: Request) => {
    const path = new URL(request.url()).pathname;
    if (/\/api-mode\/domains\//.test(path)) seen.push(`${request.method()} ${path}`);
  });
  return seen;
}

/** Creates a domain through the wizard's first two steps. */
async function addDomain(page: Page, mode: 'inline' | 'api' | 'hybrid', name: string) {
  await page.goto('/domains/onboarding');
  const label =
    mode === 'api' ? /^API \(no MX change\)/ : mode === 'hybrid' ? /^Hybrid/ : /^Inline \(MX\)/;
  await page.getByRole('radio', { name: label }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  const add = page.getByRole('form', { name: 'Add domain' });
  await add.getByLabel('Domain name (required)').fill(name);
  await add.getByRole('button', { name: 'Add domain' }).click();
}

/** Seam: the scheduler's DNS TXT win (no record can reach the dns-sink resolver). */
async function markTxtVerified(name: string): Promise<void> {
  const row = await domainRow(name);
  const now = new Date();
  await writerDb().domain.update({
    where: { id: row.id },
    data: {
      status: 'verified',
      statusReason: null,
      verifiedAt: now,
      statusChangedAt: now,
      ownershipMethod: 'dns_txt',
    },
  });
}

const stepButtons = (page: Page) =>
  page.getByRole('navigation', { name: 'Onboarding steps' }).getByRole('button');

test('inline regression: the full inline wizard, unchanged, without any /api-mode/domains request', async ({
  page,
}) => {
  const requests = trackApiModeDomainRequests(page);
  const name = newName('in');
  await signIn(page, 'etaAdmin', { next: '/domains/onboarding' });
  await expect(page.getByRole('radio', { name: /^Inline \(MX\)/ })).toBeChecked();
  await addDomain(page, 'inline', name);
  await expect(page).toHaveURL(/domainId=.*step=dns/);
  await expect(page.getByRole('heading', { name: '3. Publish DNS records' })).toBeVisible();
  const labels = await stepButtons(page).allTextContents();
  expect(labels).toHaveLength(8);
  expect(labels.join(' | ')).toMatch(
    /Protection mode.*Add domain.*Publish DNS records.*Verify ownership.*Destination mail server.*Recipient validation.*skipped.*Mailbox protection.*Activate/,
  );
  await expect(page.locator('main')).toContainText(/MX/);
  await page.getByRole('button', { name: 'I have published the records' }).click();
  await expect(page.getByRole('heading', { name: '4. Verify ownership' })).toBeVisible();
  await page.getByRole('button', { name: /verify now/i }).click();
  await expect(page.locator('main')).toContainText(/pending|not found|not yet/i);

  await markTxtVerified(name);
  await page.reload();
  await expect(page.getByRole('heading', { name: '4. Verify ownership' })).toBeVisible();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: '5. Destination mail server' })).toBeVisible();
  await page.getByRole('radio', { name: /Google Workspace/ }).click();
  await page.getByRole('button', { name: 'Save destinations' }).click();
  await expect(page).toHaveURL(/step=recipients/);
  await page.getByRole('button', { name: 'Skip for now' }).click();
  await expect(page.getByRole('heading', { name: '8. Activate' })).toBeVisible();
  await page.getByRole('button', { name: 'Activate domain' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Activate' }).click();
  await expect(page.getByRole('heading', { name: 'Onboarding complete' })).toBeVisible();
  expect((await domainRow(name)).status).toBe('active');
  expect(requests).toEqual([]);
});

test('api path: TXT-only ownership, provider ownership, connect, intake, scope, detect only, review and the first copy', async ({
  page,
}) => {
  const s = readState().onboarding;
  const name = newName('api');
  await signIn(page, 'etaAdmin', { next: '/domains/onboarding' });
  await addDomain(page, 'api', name);
  await expect(page).toHaveURL(/domainId=.*step=ownership/);
  await expect(page.getByRole('heading', { name: '3. Verify ownership' })).toBeVisible();
  const labels = (await stepButtons(page).allTextContents()).join(' | ');
  for (const step of ['Connect mailboxes', 'Intake', 'Which mailboxes', 'Threat action', 'Review'])
    expect(labels).toContain(step);
  for (const absent of ['Destination', 'Recipient', 'Publish DNS', 'skipped'])
    expect(labels).not.toContain(absent);
  const txt = page.getByRole('region', { name: 'Ownership TXT record' });
  await expect(txt).toContainText(`_emailgateway-verify.${name}`);
  await expect(txt.getByRole('button', { name: 'Copy value' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'DNS checks' })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, '/domains/onboarding (ownership, API)');

  // Ownership through the bound Microsoft 365 tenant (B3).
  const card = page.getByRole('region', { name: 'Automatic ownership verification' });
  await expect(card.getByRole('heading')).toHaveText(
    `Verify automatically through Microsoft 365 (${s.m365Name})`,
  );
  const check = page.waitForResponse(
    (r) => /\/ownership\/provider-check$/.test(new URL(r.url()).pathname) && r.status() === 202,
  );
  await card.getByRole('button', { name: 'Verify automatically' }).click();
  await check;
  await expect(card).toContainText('Checking with your provider');
  // Seam (1): the integration-worker's answer, then the api scheduler applies the win.
  const domain = await domainRow(name);
  await expect(async () => {
    const updated = await writerDb().domainVerification.updateMany({
      where: { domainId: domain.id, method: 'provider_tenant', status: 'pending' },
      data: { providerResult: 'verified', providerCheckedAt: new Date(), providerErrorCode: null },
    });
    expect(updated.count).toBe(1);
  }).toPass({ timeout: 15_000 });
  await expect(async () => {
    const row = await domainRow(name);
    expect(row.status).toBe('verified');
    expect(row.ownershipMethod).toBe('provider_tenant');
  }).toPass({ timeout: 120_000, intervals: [2_000] });
  await expect(page.getByText(/Ownership is verified through your provider tenant/)).toBeVisible({
    timeout: 30_000,
  });
  await page.getByRole('button', { name: 'Continue' }).click();

  // Connect: link the verified domain to the bound connection (B4).
  await expect(page.getByRole('heading', { name: '4. Connect mailboxes' })).toBeVisible();
  await page.getByRole('combobox', { name: 'Existing connection' }).click();
  await page.getByRole('option', { name: new RegExp(s.m365Name.replace(/[()]/g, '\\$&')) }).click();
  await page.getByRole('button', { name: `Link ${name}` }).click();
  await expect(page.getByText(/Bound \(the tenant is proven/)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByLabel('Step state')).toContainText('Done');
  await page.getByRole('button', { name: 'Continue' }).click();

  // Intake: the seeded verified journal source of the connection.
  await expect(page.getByRole('heading', { name: '5. Intake' })).toBeVisible();
  await expect(
    page
      .getByRole('region', { name: 'Journal copy' })
      .getByRole('link', { name: /Journal source/ }),
  ).toHaveAttribute('href', `/settings/journaling/intake/${s.journalSourceId}`);
  await expect(page.getByLabel('Step state')).toContainText('Done');
  // Seam (2): the mailbox the inventory or the first journal copy would discover.
  const orgId = await etaId();
  const mailbox = await seedEtaMailbox(writerDb(), {
    organizationId: orgId,
    domainId: domain.id,
    address: `ana@${name}`,
  });
  await page.getByRole('button', { name: 'Continue' }).click();

  // Which mailboxes: all (the default), saved with a reason.
  const scope = page.getByRole('form', { name: 'Which mailboxes' });
  await expect(scope.getByRole('radio', { name: 'All mailboxes (recommended)' })).toBeChecked();
  await scope.getByLabel('Reason (required)').fill('E2E: protect every mailbox');
  await scope.getByRole('button', { name: 'Save mailbox scope' }).click();
  await expect(page.getByText('Mailbox scope saved', { exact: false })).toBeVisible();
  await expect(page.getByText(/All mailboxes: 1 in scope/)).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Continue' }).click();

  // Threat action: detect only for 7 days, then remind (the default).
  await expect(page.getByRole('heading', { name: '7. Threat action' })).toBeVisible();
  await expect(
    page.getByRole('radio', { name: 'Detect only for 7 days, then remind me (recommended)' }),
  ).toBeChecked();
  await expect(page.getByLabel('What this choice does')).toContainText('(simulated)');
  await page.getByRole('button', { name: 'Save threat action' }).click();
  await expect(page.getByText('Threat action saved for the domain.')).toBeVisible();
  const policy = await writerDb().apiRemediationPolicy.findFirstOrThrow({
    where: { organizationId: orgId, domainId: domain.id },
    select: { mode: true, detectOnlyThen: true, detectOnlyUntil: true },
  });
  expect(policy.mode).toBe('detect_only');
  expect(policy.detectOnlyThen).toBe('remind');
  expect(Math.round((policy.detectOnlyUntil!.getTime() - Date.now()) / 86_400_000)).toBe(7);
  await page.getByRole('button', { name: 'Continue' }).click();

  // Review: activate, then the live first-copy check (polls every 5 s).
  await expect(page.getByRole('heading', { name: '8. Review and activate' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Summary' })).toContainText('Connect mailboxes');
  await page.getByRole('button', { name: 'Activate domain' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Activate' }).click();
  const firstCopy = page.getByRole('region', { name: 'First copy' });
  await expect(firstCopy).toContainText('Waiting for the first message', { timeout: 30_000 });
  await expectNoSeriousA11yViolations(page, '/domains/onboarding (review, API)');
  const copyId = await seedEtaFirstCopy(writerDb(), {
    organizationId: orgId,
    mailboxId: mailbox.mailboxId,
    apiConnectionId: mailbox.apiConnectionId,
  });
  await expect(firstCopy).toContainText('First message received', { timeout: 30_000 });
  await expect(firstCopy.getByRole('link', { name: 'Open the detection' })).toHaveAttribute(
    'href',
    `/api-mode?tab=detections&detection=${copyId}`,
  );
  expect((await domainRow(name)).status).toBe('active');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Onboarding complete' })).toBeVisible();

  // The domain page of an API-mode domain (B5): no DNS records, DKIM, destinations, recipients.
  await page.goto(`/domains/${domain.publicId}`);
  await expect(page.getByRole('heading', { name: 'API protection' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Ownership', exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'DNS records' })).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'Destinations' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'DKIM signing keys' })).toHaveCount(0);
  await expect(page.getByText('Provider tenant (Microsoft 365 or Google Workspace)')).toBeVisible();
  await expect(page.getByText('All mailboxes: 1 in scope, 0 excluded')).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/domains/[id] (API)');
});

test('hybrid path: the inline steps plus the API steps, with the provider option on verify', async ({
  page,
}) => {
  const name = newName('hy');
  await signIn(page, 'etaAdmin', { next: '/domains/onboarding' });
  await addDomain(page, 'hybrid', name);
  await expect(page).toHaveURL(/domainId=.*step=dns/);
  await expect(page.getByRole('heading', { name: '3. Publish DNS records' })).toBeVisible();
  const labels = await stepButtons(page).allTextContents();
  expect(labels).toHaveLength(11);
  expect(labels.join(' | ')).toMatch(
    /Publish DNS records.*Verify ownership.*Destination mail server.*Recipient validation.*Connect mailboxes.*Intake.*Which mailboxes.*Threat action.*Review and activate/,
  );
  expect(labels.join(' | ')).not.toContain('Mailbox protection');
  await page.getByRole('button', { name: 'I have published the records' }).click();
  await expect(page.getByRole('heading', { name: '4. Verify ownership' })).toBeVisible();
  await expect(
    page.getByRole('region', { name: 'Automatic ownership verification' }),
  ).toBeVisible();
  await markTxtVerified(name);
  await page.goto(
    `${new URL(page.url()).pathname}?domainId=${(await domainRow(name)).publicId}&step=connect`,
  );
  await expect(page.getByRole('heading', { name: '7. Connect mailboxes' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/domains/onboarding (connect, Hybrid)');
  await stepButtons(page).filter({ hasText: 'Review and activate' }).click();
  await expect(page.getByRole('heading', { name: '11. Review and activate' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Summary' })).toContainText('Which mailboxes');

  // The hybrid domain page: the inline tabs plus API protection.
  await page.goto(`/domains/${(await domainRow(name)).publicId}`);
  await expect(page.getByRole('heading', { name: 'API protection' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'DNS records' })).toBeVisible();
});

test('domain page per mode: the inline domain is unchanged (no API protection request)', async ({
  page,
}) => {
  const s = readState().onboarding;
  const requests = trackApiModeDomainRequests(page);
  await signIn(page, 'etaAdmin', { next: `/domains/${s.domains.inline}` });
  await expect(page.getByRole('heading', { level: 1, name: s.domainNames.inline })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'DNS records' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Verification' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Protection mode' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'API protection' })).toHaveCount(0);
  expect(requests).toEqual([]);
});

test('Protection by mode: navigation, matrix, per-domain gaps and links', async ({ page }) => {
  const s = readState().onboarding;
  await signIn(page, 'etaAdmin', { next: '/domains' });
  await expect(page.getByRole('link', { name: 'Protection by mode' }).first()).toBeVisible();
  await page
    .getByRole('navigation', { name: 'Main' })
    .getByRole('link', { name: 'Protection by mode' })
    .click();
  await expect(page).toHaveURL(/\/protection-by-mode$/);
  await expect(page.getByRole('heading', { level: 1, name: 'Protection by mode' })).toBeVisible();
  const matrix = page.getByRole('table', { name: 'What each protection mode covers' });
  await expect(matrix.getByRole('row')).toHaveCount(13);
  await expect(matrix.getByRole('row', { name: /Block threats before delivery/ })).toContainText(
    'No',
  );
  const table = page.getByRole('table', { name: 'Coverage of each domain' });
  const bound = table.getByRole('row', {
    name: new RegExp(s.domainNames.bound.replace(/\./g, '\\.')),
  });
  await expect(bound).toContainText('API');
  await expect(bound).toContainText('Journal verified');
  await expect(
    table.getByRole('row', { name: new RegExp(s.domainNames.inline.replace(/\./g, '\\.')) }),
  ).toContainText('MX at the gateway');
  await expectNoSeriousA11yViolations(page, '/protection-by-mode');
  await page.goto('/api-mode');
  await expect(page.getByRole('link', { name: 'Protection by mode' }).last()).toHaveAttribute(
    'href',
    '/protection-by-mode',
  );
});

test('read-only user: the wizard is refused; the domain page and Protection by mode without write controls', async ({
  page,
}) => {
  const s = readState().onboarding;
  await signIn(page, 'etaReadOnly', {
    next: `/domains/onboarding?domainId=${s.domains.bound}&step=mailboxes`,
  });
  // The wizard route needs domain create: the read-only user is refused there…
  await expect(page.getByText('You do not have access to this page')).toBeVisible();
  // …and sees the domain page and Protection by mode without any write control.
  await page.goto(`/domains/${s.domains.bound}`);
  await expect(page.getByRole('heading', { name: 'API protection' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Verify automatically' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Continue onboarding' })).toHaveCount(0);
  await page.goto('/protection-by-mode');
  await expect(page.getByRole('table', { name: 'Coverage of each domain' })).toBeVisible();
  await expect(page.locator('main').getByRole('button', { name: /Save|Change/ })).toHaveCount(0);
});
