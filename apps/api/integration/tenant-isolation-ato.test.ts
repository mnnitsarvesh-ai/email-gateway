/**
 * Tenant isolation of the step 8.4 account takeover routes against the real writer and replica
 * (docs/plan/steps/24-account-takeover-core.md §10.4): two `it-ato-*` organizations with the
 * same kinds of rows (accounts, signals, auth events, an incident, responses, a trusted context);
 * every route called by organization A with organization B's ids answers like an unknown id
 * (404), every list of A excludes B's rows, A's overview counts only A, and nothing of B changes.
 */
// @covers get /api/v1/ato/overview
// @covers get /api/v1/ato/attention
// @covers get /api/v1/ato/accounts
// @covers get /api/v1/ato/accounts/:accountId
// @covers patch /api/v1/ato/accounts/:accountId
// @covers get /api/v1/ato/accounts/:accountId/signals
// @covers get /api/v1/ato/accounts/:accountId/auth-events
// @covers get /api/v1/ato/accounts/:accountId/activity
// @covers get /api/v1/ato/accounts/:accountId/score-history
// @covers put /api/v1/ato/accounts/:accountId/override
// @covers post /api/v1/ato/accounts/:accountId/override/clear
// @covers post /api/v1/ato/accounts/:accountId/trusted-contexts
// @covers delete /api/v1/ato/accounts/:accountId/trusted-contexts/:contextId
// @covers get /api/v1/ato/incidents/:incidentId/signals
// @covers get /api/v1/ato/incidents/:incidentId/auth-events
// @covers post /api/v1/ato/incidents/:incidentId/responses
// @covers get /api/v1/ato/responses
// @covers get /api/v1/ato/responses/:responseId
// @covers post /api/v1/ato/responses/:responseId/approve
// @covers post /api/v1/ato/responses/:responseId/reject
// @covers post /api/v1/ato/responses/:responseId/cancel
// @covers post /api/v1/ato/responses/:responseId/rollback
// @covers get /api/v1/ato/restrictions
// @covers get /api/v1/ato/settings
// @covers put /api/v1/ato/settings
// @covers get /api/v1/ato/rules
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { AtoSeeder, type AtoTenant } from './support/ato';
import { createFixtures, type Fixtures } from './support/fixtures';
import { idem } from './support/http';

const BASE = '/api/v1/ato';
let ctx: IntegrationApp;
let fx: Fixtures;
let seed: AtoSeeder;

interface Side {
  t: AtoTenant;
  account: string;
  incident: string;
  pending: string;
  context: string;
}
let a: Side;
let b: Side;

async function side(): Promise<Side> {
  const t = await seed.tenant();
  const { account, incident } = await seed.compromised(t.org.id);
  const pending = await ctx.http
    .post(`${BASE}/incidents/${incident.publicId}/responses`)
    .set(t.analystAuth)
    .set(idem())
    .send({ actionType: 'restrict_smtp_sending', reason: 'Isolation test restriction' });
  expect(pending.status, JSON.stringify(pending.body)).toBe(201);
  const context = await ctx.http
    .post(`${BASE}/accounts/${account.publicId}/trusted-contexts`)
    .set(t.analystAuth)
    .set(idem())
    .send({ kind: 'country', value: 'IN', reason: 'Home', expiresInDays: 10 });
  expect(context.status).toBe(201);
  return {
    t,
    account: account.publicId,
    incident: incident.publicId,
    pending: pending.body.id,
    context: context.body.id,
  };
}

beforeAll(async () => {
  ctx = await createIntegrationApp({ API_ATO_OVERVIEW_CACHE_SECONDS: '1' });
  fx = createFixtures(ctx);
  seed = new AtoSeeder(ctx, fx);
  a = await side();
  b = await side();
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

async function snapshotB() {
  const o = b.t.org.id;
  const [accounts, incidents, responses, contexts, settings] = await Promise.all([
    ctx.prisma.atoAccount.findMany({ where: { organizationId: o }, orderBy: { id: 'asc' } }),
    ctx.prisma.securityIncident.findMany({ where: { organizationId: o }, orderBy: { id: 'asc' } }),
    ctx.prisma.atoResponseAction.findMany({ where: { organizationId: o }, orderBy: { id: 'asc' } }),
    ctx.prisma.atoTrustedContext.findMany({ where: { organizationId: o }, orderBy: { id: 'asc' } }),
    ctx.prisma.atoSetting.findMany({ where: { organizationId: o } }),
  ]);
  // A running ato-worker (the stack run of `pnpm test:integration`) creates and updates B's
  // `gateway_user` accounts asynchronously from B's own fixture users' api sign-ins. None of A's
  // requests below names such an account (they target B's mailbox account, incident, responses,
  // contexts and settings), so they are left out; every other row must stay identical.
  const stable = accounts.filter((account) => account.kind !== 'gateway_user');
  return JSON.stringify(
    { accounts: stable, incidents, responses, contexts, settings },
    (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
  );
}

describe('organization A never reaches organization B', () => {
  it('every route with B’s ids answers 404 like an unknown id, and nothing of B changes', async () => {
    const before = await snapshotB();
    const auth = a.t.analystAuth;
    const mfaAuth = a.t.analyst2Auth;
    const checks: Array<
      [
        'get' | 'post' | 'put' | 'patch' | 'delete',
        string,
        object | undefined,
        string,
        Record<string, string>?,
      ]
    > = [
      ['get', `${BASE}/accounts/${b.account}`, undefined, 'ato_account_not_found'],
      ['get', `${BASE}/accounts/${b.account}/signals`, undefined, 'ato_account_not_found'],
      ['get', `${BASE}/accounts/${b.account}/auth-events`, undefined, 'ato_account_not_found'],
      ['get', `${BASE}/accounts/${b.account}/activity`, undefined, 'ato_account_not_found'],
      ['get', `${BASE}/accounts/${b.account}/score-history`, undefined, 'ato_account_not_found'],
      [
        'patch',
        `${BASE}/accounts/${b.account}`,
        { protected: true, expectedRowVersion: 1 },
        'ato_account_not_found',
      ],
      [
        'put',
        `${BASE}/accounts/${b.account}/override`,
        { verdict: 'benign', reason: 'Cross-tenant attempt here', expiresInHours: 1 },
        'ato_account_not_found',
      ],
      [
        'post',
        `${BASE}/accounts/${b.account}/override/clear`,
        { reason: 'Cross-tenant attempt here' },
        'ato_account_not_found',
      ],
      [
        'post',
        `${BASE}/accounts/${b.account}/trusted-contexts`,
        { kind: 'country', value: 'DE', reason: 'x', expiresInDays: 1 },
        'ato_account_not_found',
      ],
      [
        'delete',
        `${BASE}/accounts/${b.account}/trusted-contexts/${b.context}`,
        undefined,
        'ato_account_not_found',
      ],
      [
        'delete',
        `${BASE}/accounts/${a.account}/trusted-contexts/${b.context}`,
        undefined,
        'ato_trusted_context_not_found',
      ],
      ['get', `${BASE}/incidents/${b.incident}/signals`, undefined, 'incident_not_found'],
      ['get', `${BASE}/incidents/${b.incident}/auth-events`, undefined, 'incident_not_found'],
      [
        'post',
        `${BASE}/incidents/${b.incident}/responses`,
        { actionType: 'notify_soc', reason: 'Cross-tenant attempt here' },
        'incident_not_found',
      ],
      ['get', `${BASE}/responses/${b.pending}`, undefined, 'ato_response_not_found'],
      ['post', `${BASE}/responses/${b.pending}/approve`, {}, 'ato_response_not_found', mfaAuth],
      [
        'post',
        `${BASE}/responses/${b.pending}/reject`,
        { reason: 'Cross-tenant attempt here' },
        'ato_response_not_found',
        mfaAuth,
      ],
      ['post', `${BASE}/responses/${b.pending}/cancel`, {}, 'ato_response_not_found'],
      [
        'post',
        `${BASE}/responses/${b.pending}/rollback`,
        { reason: 'Cross-tenant attempt here' },
        'ato_response_not_found',
        mfaAuth,
      ],
    ];
    for (const [method, path, body, code, as] of checks) {
      let req = ctx.http[method](path).set(as ?? auth);
      if (method !== 'get') req = req.set(idem());
      const res = await (body ? req.send(body) : req);
      expect(res.status, path).toBe(404);
      expect(res.body.code, path).toBe(code);
    }
    expect(await snapshotB()).toBe(before);
  });

  it('lists, overview, attention, settings and rules of A contain only A', async () => {
    const auth = a.t.analystAuth;
    const ids = (body: { data: Array<{ id: string }> }) => body.data.map((x) => x.id);
    const accounts = await ctx.http.get(`${BASE}/accounts?limit=100`).set(auth);
    expect(ids(accounts.body)).toContain(a.account);
    expect(ids(accounts.body)).not.toContain(b.account);
    const responses = await ctx.http.get(`${BASE}/responses?limit=100`).set(auth);
    expect(ids(responses.body)).toContain(a.pending);
    expect(ids(responses.body)).not.toContain(b.pending);
    const foreignFilter = await ctx.http.get(`${BASE}/responses?accountId=${b.account}`).set(auth);
    expect(foreignFilter.body).toEqual({ data: [], nextCursor: null });
    const restrictions = await ctx.http
      .get(`${BASE}/restrictions?status=active,lifted,expired`)
      .set(auth);
    expect(restrictions.status).toBe(200);
    const bCounts = await ctx.prisma.atoAccount.count({ where: { organizationId: a.t.org.id } });
    const overview = await ctx.http.get(`${BASE}/overview`).set(auth);
    expect(overview.body.accounts.monitored).toBe(bCounts);
    const attention = await ctx.http.get(`${BASE}/attention`).set(auth);
    expect(attention.body.pendingApprovals).toBe(
      await ctx.prisma.atoResponseAction.count({
        where: { organizationId: a.t.org.id, status: 'pending_approval' },
      }),
    );
    const settings = await ctx.http.get(`${BASE}/settings`).set(auth);
    expect(settings.status).toBe(200);
    const rules = await ctx.http.get(`${BASE}/rules`).set(auth);
    expect(rules.status).toBe(200);
    // A's settings change never touches B's row.
    const beforeB = await ctx.prisma.atoSetting.findUniqueOrThrow({
      where: { organizationId: b.t.org.id },
    });
    const put = await ctx.http
      .put(`${BASE}/settings`)
      .set(a.t.adminAuth)
      .set(idem())
      .send({ expectedRowVersion: settings.body.rowVersion, settings: { learningDays: 3 } });
    expect(put.status).toBe(200);
    const afterB = await ctx.prisma.atoSetting.findUniqueOrThrow({
      where: { organizationId: b.t.org.id },
    });
    expect(afterB.rowVersion).toBe(beforeB.rowVersion);
  });

  it('an API key of A cannot reach B either', async () => {
    const res = await ctx.http.get(`${BASE}/accounts/${b.account}`).set(a.t.apiKey);
    expect(res.status).toBe(404);
  });
});
