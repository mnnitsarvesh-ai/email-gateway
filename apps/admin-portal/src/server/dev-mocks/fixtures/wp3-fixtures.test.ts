// @vitest-environment node
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';

/** WP3 dev fixtures: every operation the WP3 pages call answers with a typed, sensible body. */
const API = 'http://api.test:3000';
const fetchImpl = createMockFetch(mergedFixtures());

async function login(role: string): Promise<string> {
  const response = await fetchImpl(`${API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: `${role}@example.com`, password: 'any' }),
  });
  return ((await response.json()) as { accessToken: string }).accessToken;
}

async function call(token: string, method: string, path: string, body?: unknown) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body === undefined ? null : JSON.stringify(body),
  });
  const text = await response.text();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in a test
  return { status: response.status, body: (text ? JSON.parse(text) : null) as Record<string, any> };
}

const range = (days: number) => {
  const to = new Date(Math.ceil(Date.now() / 3_600_000) * 3_600_000);
  const from = new Date(to.getTime() - days * 86_400_000);
  return `from=${from.toISOString()}&to=${to.toISOString()}`;
};

describe('WP3 dev fixtures', () => {
  it('reports agree with each other and keep the API rules', async () => {
    const token = await login('organization_admin');
    const traffic = await call(token, 'GET', `/reports/traffic?granularity=day&${range(7)}`);
    expect(traffic.status).toBe(200);
    // The window is floored and ceiled to whole days (like the api): 7 or 8 buckets.
    expect([7, 8]).toContain(traffic.body.buckets.length);
    const sum = traffic.body.buckets.reduce((a: number, b: { total: number }) => a + b.total, 0);
    expect(traffic.body.totals.total).toBe(sum);
    const threats = await call(token, 'GET', `/reports/threats?${range(7)}`);
    const outcomeSum = threats.body.outcomes.reduce(
      (a: number, o: { count: number }) => a + o.count,
      0,
    );
    expect(outcomeSum).toBe(threats.body.messages.total);
    expect(threats.body.messages.total).toBe(traffic.body.totals.total);
    const delivery = await call(token, 'GET', `/reports/delivery?granularity=day&${range(7)}`);
    expect(delivery.body.totals.successRate).toBeGreaterThan(0.9);
    const processing = await call(token, 'GET', `/reports/processing?granularity=hour&${range(1)}`);
    expect(processing.body.buckets).toHaveLength(24);
    expect(processing.body.totals.p95UpperBoundMs).not.toBeNull();
    const top = await call(token, 'GET', `/reports/top-domains?limit=3&${range(7)}`);
    expect(top.body.domains.length).toBeLessThanOrEqual(3);
    expect(
      (await call(token, 'GET', `/reports/traffic?granularity=hour&${range(30)}`)).status,
    ).toBe(400);
    expect((await call(token, 'GET', `/reports/url-clicks?${range(7)}`)).status).toBe(200);
  });

  it('mailbox users are refused (403) and anonymous calls are 401', async () => {
    const token = await login('mailbox_user');
    expect((await call(token, 'GET', '/reports/traffic')).status).toBe(403);
    expect((await call('nope', 'GET', '/reports/traffic')).status).toBe(401);
  });

  it('billing, usage, audit and settings answer for an organization admin', async () => {
    const token = await login('organization_admin');
    const plan = await call(token, 'GET', '/billing/plan');
    expect(plan.body.pricing).toBeNull();
    expect((await call(token, 'GET', '/billing/usage?month=2020-01')).body.code).toBe(
      'usage_period_unavailable',
    );
    expect((await call(token, 'GET', '/usage')).body.users.total).toBeGreaterThan(0);
    const audit = await call(token, 'GET', `/audit/logs?limit=25&${range(30)}`);
    expect(audit.body.data).toHaveLength(25);
    expect(audit.body.nextCursor).toEqual(expect.any(String));
    const prefixed = await call(token, 'GET', `/audit/logs?actionPrefix=quarantine.&${range(30)}`);
    expect(
      prefixed.body.data.every((r: { action: string }) => r.action.startsWith('quarantine.')),
    ).toBe(true);
    expect((await call(token, 'GET', '/audit/login-events')).body.data.length).toBeGreaterThan(0);
    const notifications = await call(token, 'GET', '/notifications/settings');
    const saved = await call(token, 'PUT', '/notifications/settings', {
      settings: { alerts: { includeOrganizationContact: true } },
      expectedRowVersion: notifications.body.rowVersion,
    });
    expect(saved.body.settings.alerts.includeOrganizationContact).toBe(true);
    const scan = await call(token, 'GET', '/scan-settings');
    const rspamd = scan.body.data.find((v: { engine: string }) => v.engine === 'rspamd');
    const replaced = await call(token, 'PUT', '/scan-settings/rspamd', {
      expectedVersion: rspamd.version,
      settings: { spamScore: 8 },
    });
    expect(replaced.body.effective.spamScore).toBe(8);
    expect(
      (
        await call(token, 'PUT', '/scan-settings/rspamd', {
          expectedVersion: rspamd.version,
          settings: {},
        })
      ).status,
    ).toBe(409);
  });

  it('organizations: catalogue for platform users, own organization for tenants, four-eyes deletion', async () => {
    const platform = await login('platform_admin');
    const superAdmin = await login('super_admin');
    const list = await call(platform, 'GET', '/organizations?limit=10');
    expect(list.body.data).toHaveLength(10);
    const tenant = await login('read_only_user');
    const own = await call(tenant, 'GET', '/organizations');
    expect(own.body.data).toHaveLength(1);
    const created = await call(superAdmin, 'POST', '/organizations', {
      name: 'Fixture Test',
      slug: `fx-${Date.now()}`,
      planCode: 'starter',
      deploymentMode: 'saas',
      dataRegion: 'eu-west-1',
    });
    expect(created.status).toBe(201);
    const id = created.body.id as string;
    const slug = created.body.slug as string;
    expect(
      (
        await call(superAdmin, 'POST', `/organizations/${id}/deletion`, {
          reason: 'Fixture deletion test',
          confirmSlug: slug,
        })
      ).body.state,
    ).toBe('pending_deletion');
    expect(
      (
        await call(superAdmin, 'POST', `/organizations/${id}/deletion/confirm`, {
          confirmSlug: slug,
        })
      ).status,
    ).toBe(403);
    expect(
      (await call(platform, 'POST', `/organizations/${id}/deletion/confirm`, { confirmSlug: slug }))
        .body.state,
    ).toBe('deleted');
    expect((await call(tenant, 'GET', `/organizations/${id}`)).status).toBe(404);
  });

  it('threat intelligence, URL clicks and attachments', async () => {
    const platform = await login('platform_admin');
    const lookup = await call(
      platform,
      'GET',
      '/threat-intelligence/lookup?type=domain&value=a.login.evil-example.test',
    );
    expect(lookup.body.known).toBe(true);
    expect(
      (await call(platform, 'GET', '/platform/threat-hashes?limit=25')).body.nextCursor,
    ).toEqual(expect.any(String));
    const analyst = await login('security_analyst');
    expect(
      (await call(analyst, 'GET', `/url-protection/clicks?${range(7)}`)).body.data.length,
    ).toBeGreaterThan(0);
    const sha = createHash('sha256').update('synthetic-sample-0').digest('hex');
    const found = await call(analyst, 'GET', `/attachments?sha256=${sha}&${range(31)}`);
    expect(found.body.data).toHaveLength(25);
    const dry = await call(platform, 'POST', '/platform/attachment-rescans', {
      windowHours: 24,
      reason: 'test',
      dryRun: true,
    });
    expect(dry.body.dryRun).toBe(true);
    const jobs = await call(platform, 'GET', '/platform/attachment-rescans?status=running');
    expect(jobs.body.data[0].status).toBe('running');
  });
});
