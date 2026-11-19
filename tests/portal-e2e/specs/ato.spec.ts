/**
 * The suite's own portal sign-ins are real ATO events of the e2e tenants (the ato-worker runs), so
 * alpha and beta also get `gateway_user` accounts during the run; the explorer checks filter on
 * the seeded mailboxes (`kind=mailbox`) and the dashboard adds the users' figures read on the
 * writer (support/ato.ts `gatewayUserFigures`).
 *
 * Account takeover pages (step 8.4 §6, §10.6) against the real api over ATO rows written by the
 * libraries' stores (seed/ato.ts): the dashboard figures equal the seed plan's (computed from the
 * D11 arithmetic, not from the api), the account explorer's filters, the account tabs, settings
 * save and conflict (CAS), RBAC per role, tenant isolation (beta ids look missing) and axe on every
 * page. The incident workflow is incidents.spec.ts.
 */
import {
  atoAccount,
  atoTile,
  gatewayUserFigures,
  gatewayUserIncidents,
  geographyAvailable,
  pendingApprovals,
} from '../support/ato';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { checkPage, expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ timeout: 180_000 });

test('dashboard: figures of the seed plan, geography state, attention badge; axe', async ({
  page,
}) => {
  const plan = readState().ato.expected;
  await signIn(page, 'alphaAnalyst', { next: '/ato?range=24h' });
  await expect(page.getByRole('heading', { level: 1, name: 'Account takeover' })).toBeVisible();
  await expectSettled(page, '/ato');
  // The suite's own sign-ins are real ATO events (gateway_user accounts of alpha, which keep
  // changing while other specs sign in): their figures are read on the writer and added to the
  // seed plan's mailbox figures (both api-independent). The overview is cached for up to
  // API_ATO_OVERVIEW_CACHE_SECONDS (60), so the page is reloaded until both readings agree.
  const value = (label: string) => atoTile(page, label).locator('p.text-3xl');
  const tiles = async () =>
    Object.fromEntries(
      await Promise.all(
        [
          'Monitored accounts',
          'High-risk accounts',
          'Critical incidents',
          'Suspicious sign-ins',
          'Suspicious outbound activity',
          'Pending approvals',
        ].map(async (label) => [label, (await value(label).textContent())?.trim()] as const),
      ),
    );
  const expected = async () => {
    const users = await gatewayUserFigures(new Date(Date.now() - 24 * 3_600_000));
    const incidents = await gatewayUserIncidents();
    return {
      'Monitored accounts': String(plan.monitored + users.accounts),
      'High-risk accounts': String(plan.highRisk + users.highRisk),
      'Critical incidents': String(plan.criticalIncidents + incidents.critical),
      'Suspicious sign-ins': String(plan.suspiciousLogins + users.suspiciousLogins),
      'Suspicious outbound activity': String(plan.suspiciousOutbound),
      'Pending approvals': String(await pendingApprovals()),
    };
  };
  await expect
    .poll(
      async () => {
        const want = await expected();
        const shown = await tiles();
        if (JSON.stringify(shown) === JSON.stringify(want)) return 'equal';
        await page.reload();
        await expectSettled(page, '/ato (reload)');
        return JSON.stringify({ shown, want });
      },
      { timeout: 150_000, intervals: [10_000] },
    )
    .toBe('equal');
  await expect(atoTile(page, 'Monitored accounts')).toContainText(`${plan.monitored} mailboxes`);
  // Geography follows the worker's reported capability: the Compose worker mounts the synthetic
  // GeoIP databases; without a (fresh) report the dashboard shows the unavailable state (PO2).
  if (await geographyAvailable()) {
    await expect(page.getByRole('region', { name: 'Geography unavailable' })).toHaveCount(0);
    await expect(page.getByRole('term').filter({ hasText: /^Impossible travel$/ })).toBeVisible();
  } else {
    await expect(page.getByRole('region', { name: 'Geography unavailable' })).toBeVisible();
  }
  // The shell badge: active critical incidents + pending approvals (D16). `GET /ato/attention` is
  // cached for ATO_ATTENTION_CACHE_SECONDS (30) and polled every 60 s, so a gateway_user incident
  // raised by the suite's own sign-ins can reach the tiles before the badge: reload until the
  // badge shows the current figure (read on the writer at each attempt).
  const nav = page.getByRole('navigation', { name: 'Main' });
  const badge = nav.getByRole('link', { name: /^ATO dashboard/ });
  await expect
    .poll(
      async () => {
        const critical = plan.criticalIncidents + (await gatewayUserIncidents()).critical;
        const shown = await expect(badge)
          .toHaveAccessibleName(new RegExp(`\\b${critical} critical incident`), { timeout: 5_000 })
          .then(
            () => true,
            () => false,
          );
        if (shown) return 'equal';
        await page.reload();
        await expectSettled(page, '/ato (badge reload)');
        return `badge does not show ${critical} critical incident(s) yet`;
      },
      { timeout: 90_000, intervals: [10_000] },
    )
    .toBe('equal');
  await expectNoSeriousA11yViolations(page, '/ato');
});

test('account explorer: filters in the URL, kinds, levels, prefix; beta never listed', async ({
  page,
}) => {
  const victim = atoAccount('victim');
  const traveller = atoAccount('traveller');
  const quiet = atoAccount('quiet');
  const beta = atoAccount('beta-victim', 'beta');
  await signIn(page, 'alphaAnalyst', { next: '/ato/accounts?kind=mailbox' });
  const table = page.getByRole('table', { name: 'Monitored accounts' });
  await expect(table.getByRole('link', { name: victim.address })).toBeVisible();
  await expect(table.getByRole('link', { name: beta.address })).toHaveCount(0);
  // Highest risk first.
  await expect(table.getByRole('row').nth(1)).toContainText(victim.address);
  await expectNoSeriousA11yViolations(page, '/ato/accounts');

  await page.goto('/ato/accounts?kind=mailbox&level=high,critical');
  await expect(table.getByRole('link', { name: traveller.address })).toBeVisible();
  await expect(table.getByRole('row')).toHaveCount(3);
  await expect(table.getByRole('link', { name: quiet.address })).toHaveCount(0);

  await page.goto(`/ato/accounts?kind=mailbox&q=${encodeURIComponent('ato-quiet')}`);
  await expect(table.getByRole('row')).toHaveCount(2);
  await expect(table.getByRole('link', { name: quiet.address })).toBeVisible();

  await page.goto('/ato/accounts?kind=mailbox&incident=yes');
  await expect(table.getByRole('row')).toHaveCount(3);
  await page.getByRole('combobox', { name: 'Sort by' }).click();
  await page.getByRole('option', { name: 'Address (A–Z)' }).click();
  await expect(page).toHaveURL(/sort=address/);
  await expect(table.getByRole('row').nth(1)).toContainText(traveller.address);
});

test('account details: overview, sign-ins, signals, history, mailbox (8.5), trusted contexts', async ({
  page,
}) => {
  const victim = atoAccount('victim');
  await signIn(page, 'alphaAnalyst', { next: `/ato/accounts/${victim.accountId}` });
  await expect(page.getByRole('heading', { level: 1, name: victim.address })).toBeVisible();
  await expect(
    page.getByRole('meter', { name: /risk score 100 of 100, Critical/ }).first(),
  ).toBeVisible();
  const contributions = page.getByRole('table', { name: 'Top contributions to the score' });
  await expect(contributions).toContainText('Phishing sent from the account');
  await expect(page.getByRole('link', { name: /Active incident/ })).toHaveAttribute(
    'href',
    `/incidents/${victim.incidentId}`,
  );
  await expectNoSeriousA11yViolations(page, '/ato/accounts/[id]');

  await page.getByRole('tab', { name: 'Sign-ins' }).click();
  const signIns = page.getByRole('table', { name: 'Sign-ins of the account' });
  await expect(signIns.getByRole('row')).toHaveCount(5);
  await expect(signIns.getByText('Failure')).toHaveCount(3);
  await expect(signIns.getByText('203.0.113.40').first()).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'sign-ins tab');

  await page.getByRole('tab', { name: 'Detection reasons' }).click();
  const signals = page.getByRole('table', { name: 'Risk signals of the account' });
  await expect(signals.getByRole('row')).toHaveCount(4);
  await expect(signals).toContainText('ato.correlation.login_then_outbound');

  await page.getByRole('tab', { name: 'Score history' }).click();
  await expect(page.getByRole('table', { name: 'Score changes' })).toContainText('Signal');

  await page.getByRole('tab', { name: 'Mailbox changes' }).click();
  await expect(page.getByText('Arrives in step 8.5')).toBeVisible();

  await page.getByRole('tab', { name: 'Trusted contexts' }).click();
  await page.getByRole('button', { name: 'Add trusted context' }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Add a trusted context' });
  await dialog.getByLabel('Value').fill('198.51.100.0/24');
  await dialog.getByLabel(/Reason/).fill('Head office network (e2e)');
  await expectNoSeriousA11yViolations(page, 'add trusted context dialog');
  await dialog.getByRole('button', { name: 'Add' }).click();
  const list = page.getByRole('list', { name: 'Trusted contexts' });
  await expect(list).toContainText('198.51.100.0/24');
  await page.getByRole('button', { name: 'Remove trusted context 198.51.100.0/24' }).click();
  await page
    .getByRole('alertdialog', { name: 'Remove this trusted context?' })
    .getByRole('button', { name: 'Remove' })
    .click();
  await expect(page.getByText('No trusted contexts')).toBeVisible();
});

test('settings: save a change as a new version, then a stale tab gets the conflict', async ({
  page,
  context,
}) => {
  await signIn(page, 'alphaAdmin', { next: '/ato/settings?tab=notifications' });
  await expect(
    page.getByRole('heading', { level: 1, name: 'Account takeover settings' }),
  ).toBeVisible();
  await expectSettled(page, '/ato/settings');
  const stale = await context.newPage();
  await stale.goto('/ato/settings?tab=notifications');
  await expect(stale.getByLabel('At most one alert per (minutes)')).toBeVisible();

  const throttle = page.getByLabel('At most one alert per (minutes)');
  await throttle.fill('20');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('Settings saved as a new version')).toBeVisible();
  await expect(page.locator('main')).toContainText(/Version \d+/);

  await stale.getByLabel('At most one alert per (minutes)').fill('30');
  await stale.getByRole('button', { name: 'Save changes' }).click();
  await expect(stale.getByText(/changed by someone else/)).toBeVisible();
  await stale.getByRole('button', { name: 'Reload the current settings' }).click();
  await expect(stale.getByLabel('At most one alert per (minutes)')).toHaveValue('20');
  await stale.close();

  // Every tab renders; the delivery policy tab links to the builder's ATO test example.
  for (const tab of [
    'scoring',
    'rules',
    'reputation',
    'baselines',
    'automation',
    'policy',
    'providers',
  ]) {
    await checkPage(page, {
      path: `/ato/settings?tab=${tab}`,
      heading: 'Account takeover settings',
    });
  }
  await page.goto('/ato/settings?tab=policy');
  await expect(page.getByRole('link', { name: 'Create a hold rule' })).toHaveAttribute(
    'href',
    '/policies/new?testPreset=outbound_high_risk_account',
  );
  await page.goto('/ato/settings?tab=providers');
  await expect(page.getByText('Arrives in step 8.5')).toHaveCount(2);
});

test('RBAC: read-only user sees no Account security; auditor reads; analyst cannot configure', async ({
  page,
  context,
}) => {
  const victim = atoAccount('victim');
  await signIn(page, 'alphaReadOnly', { next: '/dashboard' });
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link', { name: 'Dashboard' })).toBeVisible();
  await expect(nav.getByText('Account security')).toHaveCount(0);
  await expect(nav.getByRole('link', { name: 'Incidents' })).toHaveCount(0);
  for (const path of ['/ato', '/ato/accounts', '/ato/responses', '/ato/settings', '/incidents']) {
    await page.goto(path);
    await expect(
      page.getByRole('heading', { level: 1, name: 'You do not have access to this page' }),
    ).toBeVisible();
  }
  await context.clearCookies();

  await signIn(page, 'alphaAuditor', { next: `/ato/accounts/${victim.accountId}` });
  await expect(page.getByRole('heading', { level: 1, name: victim.address })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Set override' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Protect account' })).toHaveCount(0);
  await page.goto('/ato/responses');
  await expect(page.getByRole('heading', { level: 1, name: 'Responses' })).toBeVisible();
  await expect(page.getByRole('button', { name: /^Approve/ })).toHaveCount(0);
  await context.clearCookies();

  await signIn(page, 'alphaAnalyst', { next: '/ato/settings' });
  await expect(page.getByText(/needs the ato:configure permission/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);
});

test('isolation: beta accounts and incidents look missing to alpha; beta sees only its own', async ({
  page,
  context,
}) => {
  const beta = atoAccount('beta-victim', 'beta');
  await signIn(page, 'alphaAdmin', { next: `/ato/accounts/${beta.accountId}` });
  await expect(page.getByText(/Page not found/i).first()).toBeVisible();
  await page.goto(`/incidents/${beta.incidentId}`);
  await expect(page.getByText(/Page not found/i).first()).toBeVisible();
  await context.clearCookies();

  await signIn(page, 'betaAdmin', { next: '/ato/accounts?kind=mailbox' });
  const table = page.getByRole('table', { name: 'Monitored accounts' });
  await expect(table.getByRole('link', { name: beta.address })).toBeVisible();
  await expect(table.getByRole('row')).toHaveCount(2);
  await page.goto(`/ato/accounts/${atoAccount('victim').accountId}`);
  await expect(page.getByText(/Page not found/i).first()).toBeVisible();
});

test('every account takeover page renders without an error state; axe', async ({ page }) => {
  const victim = atoAccount('victim');
  await signIn(page, 'alphaAdmin', { next: '/ato' });
  for (const check of [
    { path: '/ato?range=7d', heading: 'Account takeover', markers: ['Monitored accounts'] },
    { path: '/ato?range=30d', heading: 'Account takeover' },
    { path: '/ato/accounts', heading: 'Accounts', markers: [victim.address] },
    { path: `/ato/accounts/${victim.accountId}?tab=network`, heading: victim.address },
    { path: `/ato/accounts/${victim.accountId}?tab=outbound`, heading: victim.address },
    {
      path: `/ato/accounts/${victim.accountId}?tab=mailbox`,
      heading: victim.address,
      unavailable: ['8.5'],
    },
    { path: '/ato/responses', heading: 'Responses' },
    { path: '/ato/responses?tab=all', heading: 'Responses' },
    { path: '/ato/responses?tab=restrictions', heading: 'Responses' },
    { path: '/ato/settings', heading: 'Account takeover settings' },
  ]) {
    await checkPage(page, check);
  }
});
