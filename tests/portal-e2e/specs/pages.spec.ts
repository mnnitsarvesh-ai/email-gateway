/**
 * Every page of design §1.3 (22 pages, their tabs and sub-routes) and the routes linked from
 * emails (§1.2) render with the seeded data, show no error state, and pass axe (no serious or
 * critical violation). The unavailable states of steps 7.2, 7.3, 8.1, 8.2 and 8.3 and the two
 * "Not offered" states are present where the design puts them.
 */
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { checkPage, expectNoSeriousA11yViolations, type PageCheck } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ timeout: 300_000 });

test('public pages: login, forgot password and the emailed auth links', async ({ page }) => {
  for (const [path, heading] of [
    ['/login', 'Sign in'],
    ['/forgot-password', /forgot|reset/i],
    ['/auth/reset-password', /password/i],
    ['/auth/accept-invitation', /invitation/i],
    ['/auth/verify-email', /verif/i],
  ] as const) {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1, name: heading }).first()).toBeVisible();
    await expectNoSeriousA11yViolations(page, path);
  }
});

test('organization admin: overview, mail and security pages', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/dashboard' });
  const checks: PageCheck[] = [
    { path: '/dashboard', heading: 'Dashboard', markers: ['Total emails processed'] },
    { path: '/reports', heading: 'Reports', markers: [/traffic/i] },
    { path: '/reports?tab=threats', heading: 'Reports' },
    { path: '/reports?tab=delivery', heading: 'Reports' },
    { path: '/reports?tab=processing', heading: 'Reports' },
    { path: '/reports?tab=top-domains', heading: 'Reports', markers: [s.alpha.domainName] },
    {
      path: '/messages?range=7d',
      heading: 'Email explorer',
      markers: ['Alpha clean message 000'],
      unavailable: ['7.2'],
    },
    {
      path: `/messages/${s.alpha.messageId}`,
      heading: /email details|alpha clean message 000/i,
      markers: ['Alpha clean message 000'],
      unavailable: ['7.2'],
    },
    {
      path: `/messages/${s.alpha.messageId}/scans`,
      heading: /scan/i,
      unavailable: ['7.2'],
    },
    { path: '/quarantine', heading: 'Quarantine', markers: [s.alpha.domainName] },
    {
      path: `/quarantine/${s.alpha.previewEntryId}`,
      heading: /quarantine|entry/i,
      markers: ['E2E preview message'],
    },
    { path: '/quarantine/approvals', heading: 'Quarantine', markers: [/pending/i] },
    { path: `/quarantine/approvals/${s.alpha.pendingApprovalId}`, heading: /approval/i },
    { path: '/quarantine/settings', heading: 'Quarantine' },
    { path: '/mail-servers', heading: 'Mail servers', markers: [s.alpha.domainName] },
    { path: '/mail-servers?tab=connectors', heading: 'Mail servers' },
    { path: '/mail-servers?tab=suppressions', heading: 'Mail servers' },
    { path: '/mail-servers?tab=deliveries', heading: 'Mail servers' },
    { path: '/policies', heading: 'Policy management', unavailable: ['7.3'] },
    { path: '/policies?tab=executions', heading: 'Policy management' },
    { path: '/policies?tab=settings', heading: 'Policy management' },
    { path: '/policies?tab=risk', heading: 'Policy management' },
    { path: '/policies?tab=scanning', heading: 'Policy management' },
    { path: '/policies?tab=dlp', heading: 'Policy management' },
    { path: '/policies?tab=bec', heading: 'Policy management' },
    { path: '/policies/builder', heading: 'Policy builder', unavailable: ['7.3'] },
    { path: '/threat-intelligence', heading: 'Threat intelligence', notOffered: 1 },
    {
      path: '/url-protection?range=7d',
      heading: 'URL protection',
      markers: [/link\d\.external\.e2e-portal\.test/],
    },
    { path: '/attachments', heading: 'Attachment analysis' },
  ];
  for (const check of checks) await checkPage(page, check);
});

test('organization admin: directory and administration pages', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/domains' });
  const checks: PageCheck[] = [
    { path: '/domains', heading: 'Domains', markers: [s.alpha.domainName] },
    { path: `/domains/${s.alpha.domainId}`, heading: s.alpha.domainName },
    { path: '/domains/onboarding', heading: /add a domain|domain onboarding|add domain/i },
    { path: '/users', heading: 'Users', markers: ['member32@alpha.e2e-portal.test'] },
    { path: `/users/${s.alpha.memberUserId}`, heading: 'Alpha Member 01' },
    { path: '/roles', heading: 'Roles and permissions', markers: ['Organization Admin'] },
    { path: '/roles/organization_admin', heading: 'Organization Admin' },
    { path: '/organizations', heading: s.orgs.alpha.name, unavailable: ['8.3'] },
    {
      path: '/integrations',
      heading: 'Integrations',
      markers: ['Alpha SIEM (e2e)'],
      unavailable: ['8.2'],
    },
    { path: '/integrations/api-keys', heading: /api keys|integrations/i },
    { path: `/webhooks/${s.alpha.webhookId}`, heading: 'Alpha SIEM (e2e)' },
    {
      path: '/audit-logs?range=7d&action=user.invited',
      heading: 'Audit logs',
      markers: ['user.invited'],
    },
    { path: '/audit-logs?tab=sign-in', heading: 'Audit logs', markers: [/admin@alpha/] },
    { path: '/billing', heading: /usage and billing/i, notOffered: 1 },
    { path: '/settings', heading: 'Settings', markers: ['Organization profile'] },
    { path: '/settings?tab=notifications', heading: 'Settings' },
    { path: '/settings?tab=preferences', heading: 'Settings' },
    {
      path: '/settings?tab=security',
      heading: 'Settings',
      markers: ['Multi-factor authentication'],
    },
    { path: '/settings?tab=scanning', heading: 'Settings' },
    { path: '/settings?tab=archive', heading: 'Settings', unavailable: ['8.1'] },
  ];
  for (const check of checks) await checkPage(page, check);
});

test('mailbox user: the emailed self-service links', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaMailbox', { next: '/quarantine/me' });
  await checkPage(page, {
    path: '/quarantine/me',
    heading: /my quarantine/i,
    markers: ['E2E preview message'],
  });
  await checkPage(page, {
    path: `/quarantine/me/${s.alpha.previewEntryId}`,
    heading: /quarantine|message/i,
    markers: ['E2E preview message'],
  });
});

test('platform admin: organization catalogue, platform audit, threat intel and rescans', async ({
  page,
}) => {
  const s = readState();
  await signIn(page, 'platformAdmin', { next: '/organizations' });
  const checks: PageCheck[] = [
    {
      path: '/organizations',
      heading: /organizations/i,
      markers: [s.orgs.alpha.name, s.orgs.beta.name],
    },
    { path: `/organizations/${s.orgs.alpha.id}`, heading: s.orgs.alpha.name, unavailable: ['8.3'] },
    {
      path: '/dashboard',
      heading: 'Dashboard',
      markers: [/platform health|readiness|dependencies/i],
    },
    {
      path: `/audit-logs?tab=platform&organizationId=${s.orgs.alpha.id}&range=7d&action=user.invited`,
      heading: 'Audit logs',
      markers: ['user.invited'],
    },
    { path: '/threat-intelligence', heading: 'Threat intelligence' },
    { path: '/attachments', heading: 'Attachment analysis' },
  ];
  for (const check of checks) await checkPage(page, check);
});
