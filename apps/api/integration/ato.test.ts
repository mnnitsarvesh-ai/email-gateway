/**
 * The account takeover routes of step 8.4 against the real writer, replica and Redis
 * (docs/plan/steps/24-account-takeover-core.md §5.1, §10.4): every route over rows written by the
 * library stores of the running api (accounts, auth events, signals, scores, an incident opened
 * by the incident policy, responses); approvals (self-approval refused, MFA required, API keys
 * never approve), the gateway restriction applied on approval and lifted by rollback, overrides
 * rescoring the account, trusted contexts, settings CAS and validation with versions and the
 * audit row, overview figures checked against counts computed independently from the fixtures,
 * the feature gate, and the EXPLAIN plans of every list at volume (≥ 100 000 signals and auth
 * events for one organization).
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
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { AtoSeeder, type AtoTenant } from './support/ato';
import { createFixtures, type Fixtures } from './support/fixtures';
import { idem } from './support/http';

const BASE = '/api/v1/ato';
let ctx: IntegrationApp;
let fx: Fixtures;
let seed: AtoSeeder;
let t: AtoTenant;
let compromised: Awaited<ReturnType<AtoSeeder['compromised']>>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Replica reads may lag the writer for a moment: retry until `ok` (≤ 10 s). */
async function eventually<T extends { status: number; body: unknown }>(
  call: () => Promise<T>,
  ok: (res: T) => boolean,
): Promise<T> {
  let last: T | undefined;
  for (let i = 0; i < 50; i += 1) {
    last = await call();
    if (ok(last)) return last;
    await sleep(200);
  }
  return last!;
}

beforeAll(async () => {
  ctx = await createIntegrationApp({ API_ATO_OVERVIEW_CACHE_SECONDS: '1' });
  fx = createFixtures(ctx);
  seed = new AtoSeeder(ctx, fx);
  t = await seed.tenant();
  compromised = await seed.compromised(t.org.id, `victim-${randomUUID().slice(0, 6)}`);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const get = (path: string, auth: Record<string, string> = t.analystAuth) =>
  ctx.http.get(path).set(auth);
const send = (
  method: 'post' | 'put' | 'patch' | 'delete',
  path: string,
  body?: object,
  auth: Record<string, string> = t.analystAuth,
) => {
  const req = ctx.http[method](path).set(auth).set(idem());
  return body ? req.send(body) : req;
};

describe('reads over rows written by the stores', () => {
  it('accounts list and detail show the incident, score and explanation', async () => {
    const list = await eventually(
      () => get(`${BASE}/accounts?hasActiveIncident=true`),
      (r) => (r.body as { data: unknown[] }).data?.length === 1,
    );
    expect(list.status).toBe(200);
    expect(list.body.data[0]).toMatchObject({
      id: compromised.account.publicId,
      kind: 'mailbox',
      activeIncident: { id: compromised.incident.publicId },
    });
    const detail = await get(`${BASE}/accounts/${compromised.account.publicId}`);
    expect(detail.status).toBe(200);
    expect(detail.body.riskScore).toBeGreaterThanOrEqual(50);
    expect(detail.body.explanation.text).toMatch(/^Risk \d+/);
    expect(detail.body.rowVersion).toBeGreaterThanOrEqual(1);
    expect(detail.body.capabilities.status).toMatch(/known|unknown/);
    const sorted = await get(`${BASE}/accounts?sort=-lastSignalAt`);
    expect(sorted.body.data[0].id).toBe(compromised.account.publicId);
    const prefix = await get(
      `${BASE}/accounts?q=${encodeURIComponent(compromised.account.address!.slice(0, 8))}&sort=address`,
    );
    expect(prefix.body.data.map((a: { id: string }) => a.id)).toContain(
      compromised.account.publicId,
    );
    // With a running ato-worker (the stack run of `pnpm test:integration`), the fixture users' own
    // api sign-ins become `gateway_user` accounts of this organization; the filter must return
    // only that kind and never the seeded mailbox.
    const filtered = await get(`${BASE}/accounts?kind=gateway_user`);
    expect(filtered.status).toBe(200);
    for (const account of filtered.body.data as { id: string; kind: string }[]) {
      expect(account.kind).toBe('gateway_user');
      expect(account.id).not.toBe(compromised.account.publicId);
    }
  });

  it('signals, auth events (audited), activity and score history', async () => {
    const id = compromised.account.publicId;
    const signals = await eventually(
      () => get(`${BASE}/accounts/${id}/signals`),
      (r) => (r.body as { data: unknown[] }).data?.length === 4,
    );
    expect(signals.body.data.map((s: { ruleCode: string }) => s.ruleCode).sort()).toEqual([
      'ato.access.new_asn',
      'ato.geo.impossible_travel',
      'ato.outbound.volume_spike',
      'ato.ti.malicious_ip_success',
    ]);
    const strong = await get(`${BASE}/accounts/${id}/signals?strength=strong`);
    expect(strong.body.data.every((s: { strength: string }) => s.strength === 'strong')).toBe(true);
    const events = await get(`${BASE}/accounts/${id}/auth-events`);
    expect(events.body.data).toHaveLength(1);
    expect(events.body.data[0]).toMatchObject({
      outcome: 'success',
      ipAddress: '203.0.113.45',
      geo: { countryCode: 'DE' },
    });
    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: t.org.id, action: 'ato.auth_events.viewed' },
    });
    expect(audit).toHaveLength(1);
    expect(JSON.stringify(audit[0]!.metadata)).not.toContain('203.0.113');
    const activity = await get(`${BASE}/accounts/${id}/activity`);
    expect(activity.status).toBe(200);
    expect(activity.body.account).toBe(id);
    const scores = await get(`${BASE}/accounts/${id}/score-history`);
    expect(scores.body.data.length).toBeGreaterThanOrEqual(1);
    expect(scores.body.data[0]).toMatchObject({ trigger: 'signal' });
  });

  it('incident evidence: linked signals and auth events; a non-ATO or unknown id is 404', async () => {
    const id = compromised.incident.publicId;
    const signals = await eventually(
      () => get(`${BASE}/incidents/${id}/signals`),
      (r) => (r.body as { data: unknown[] }).data?.length > 0,
    );
    expect(signals.body.data.length).toBe(4);
    const events = await get(`${BASE}/incidents/${id}/auth-events`);
    expect(events.body.data).toHaveLength(1);
    const unknown = await get(`${BASE}/incidents/${randomUUID()}/signals`);
    expect(unknown.status).toBe(404);
    expect(unknown.body.code).toBe('incident_not_found');
  });

  it('rules and settings reflect the stored settings and capabilities', async () => {
    const rules = await get(`${BASE}/rules`);
    expect(rules.body.data.length).toBeGreaterThan(40);
    const settings = await get(`${BASE}/settings`);
    expect(settings.body).toMatchObject({
      featureEnabled: true,
      schemaVersion: 'ato-settings/1',
      // Step 8.5: the integrations per provider (none bound in this suite).
      identityProviders: [
        { provider: 'microsoft_entra', integrations: [] },
        { provider: 'google_workspace', integrations: [] },
      ],
    });
    expect(settings.body.rowVersion).toBeGreaterThanOrEqual(1);
  });

  it('overview figures match counts computed from the fixtures', async () => {
    await sleep(1100);
    const o = t.org.id;
    const [accounts, active, critical, pending] = await Promise.all([
      ctx.prisma.atoAccount.count({ where: { organizationId: o, status: 'active' } }),
      ctx.prisma.securityIncident.count({
        where: {
          organizationId: o,
          category: 'account_takeover',
          status: { in: ['open', 'investigating', 'confirmed', 'mitigated'] },
        },
      }),
      ctx.prisma.securityIncident.count({
        where: {
          organizationId: o,
          category: 'account_takeover',
          severity: 'critical',
          status: { in: ['open', 'investigating', 'confirmed', 'mitigated'] },
        },
      }),
      ctx.prisma.atoResponseAction.count({
        where: { organizationId: o, status: 'pending_approval' },
      }),
    ]);
    const res = await eventually(
      () => get(`${BASE}/overview?range=24h`),
      (r) => (r.body as { accounts?: { monitored: number } }).accounts?.monitored === accounts,
    );
    expect(res.body.monitoring.featureEnabled).toBe(true);
    expect(res.body.accounts.monitored).toBe(accounts);
    expect(res.body.incidents.active).toBe(active);
    expect(res.body.incidents.openedInRange).toBe(active);
    expect(res.body.attention).toEqual({ criticalIncidents: critical, pendingApprovals: pending });
    expect(res.body.incidents.trend.length).toBeGreaterThanOrEqual(24);
    expect(res.body.incidents.trend.length).toBeLessThanOrEqual(25);
    const attention = await get(`${BASE}/attention`);
    expect(attention.body).toEqual({ criticalIncidents: critical, pendingApprovals: pending });
  });
});

describe('mutations through the ATO store', () => {
  it('PATCH protects the account with CAS on row_version', async () => {
    const id = compromised.account.publicId;
    const before = await ctx.prisma.atoAccount.findUniqueOrThrow({ where: { publicId: id } });
    const stale = await send('patch', `${BASE}/accounts/${id}`, {
      protected: true,
      reason: 'VIP',
      expectedRowVersion: before.rowVersion + 5,
    });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({
      code: 'ato_account_conflict',
      currentRowVersion: before.rowVersion,
    });
    const ok = await send('patch', `${BASE}/accounts/${id}`, {
      protected: true,
      reason: 'VIP mailbox',
      expectedRowVersion: before.rowVersion,
    });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({
      protected: true,
      rowVersion: before.rowVersion + 1,
      protection: { reason: 'VIP mailbox' },
    });
    const audit = await ctx.prisma.auditLog.count({
      where: { organizationId: t.org.id, action: 'ato.account_protected' },
    });
    expect(audit).toBe(1);
    const unprotect = await send('patch', `${BASE}/accounts/${id}`, {
      protected: false,
      expectedRowVersion: before.rowVersion + 1,
    });
    expect(unprotect.body.protected).toBe(false);
    const apiKey = await send(
      'patch',
      `${BASE}/accounts/${id}`,
      { protected: true, expectedRowVersion: 1 },
      t.apiKey,
    );
    expect(apiKey.status).toBe(403);
  });

  it('overrides rescore the account in the same transaction', async () => {
    const id = compromised.account.publicId;
    const benign = await send('put', `${BASE}/accounts/${id}/override`, {
      verdict: 'benign',
      reason: 'User confirmed the trip by phone',
      expiresInHours: 24,
    });
    expect(benign.status, JSON.stringify(benign.body)).toBe(200);
    expect(benign.body.override).toMatchObject({ verdict: 'benign' });
    expect(benign.body.riskScore).toBeLessThan(30);
    const scores = await ctx.prisma.atoRiskScore.findMany({
      where: { organizationId: t.org.id, accountId: compromised.account.id, trigger: 'override' },
    });
    expect(scores.length).toBeGreaterThanOrEqual(1);
    const cleared = await send('post', `${BASE}/accounts/${id}/override/clear`, {
      reason: 'Trip over; normal scoring',
    });
    expect(cleared.status).toBe(200);
    expect(cleared.body.override).toBeNull();
    expect(cleared.body.riskScore).toBeGreaterThanOrEqual(50);
    const again = await send('post', `${BASE}/accounts/${id}/override/clear`, {
      reason: 'Trip over; normal scoring',
    });
    expect(again.status).toBe(404);
    expect(again.body.code).toBe('ato_override_not_found');
  });

  it('trusted contexts are added (normalized), renewed and removed', async () => {
    const id = compromised.account.publicId;
    const added = await send('post', `${BASE}/accounts/${id}/trusted-contexts`, {
      kind: 'country',
      value: 'de',
      reason: 'Business trips',
      expiresInDays: 30,
    });
    expect(added.status, JSON.stringify(added.body)).toBe(201);
    expect(added.body).toMatchObject({ kind: 'country', value: 'DE', source: 'analyst' });
    const invalid = await send('post', `${BASE}/accounts/${id}/trusted-contexts`, {
      kind: 'ip_cidr',
      value: '10.0.0.0/4',
      reason: 'too wide',
      expiresInDays: 30,
    });
    expect(invalid.status).toBe(422);
    expect(invalid.body.code).toBe('ato_trusted_context_invalid');
    const removed = await send(
      'delete',
      `${BASE}/accounts/${id}/trusted-contexts/${added.body.id}`,
    );
    expect(removed.status).toBe(204);
    expect(await ctx.prisma.atoTrustedContext.count({ where: { publicId: added.body.id } })).toBe(
      0,
    );
    const gone = await send('delete', `${BASE}/accounts/${id}/trusted-contexts/${added.body.id}`);
    expect(gone.status).toBe(404);
  });

  it('responses: request, four-eyes approval with MFA, restriction applied, rollback lifts it', async () => {
    const incident = compromised.incident.publicId;
    const requested = await send('post', `${BASE}/incidents/${incident}/responses`, {
      actionType: 'restrict_smtp_sending',
      durationMinutes: 60,
      reason: 'Outbound burst after impossible travel',
    });
    expect(requested.status, JSON.stringify(requested.body)).toBe(201);
    expect(requested.body).toMatchObject({
      status: 'pending_approval',
      impact: 'high',
      requiresApproval: true,
      canDecide: false,
    });
    const id = requested.body.id as string;
    const duplicate = await send('post', `${BASE}/incidents/${incident}/responses`, {
      actionType: 'restrict_smtp_sending',
      reason: 'Outbound burst after impossible travel',
    });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body).toMatchObject({ code: 'ato_response_active', responseId: id });
    const self = await send('post', `${BASE}/responses/${id}/approve`, {});
    expect(self.status).toBe(403);
    expect(self.body.code).toBe('ato_approval_self');
    const byKey = await send('post', `${BASE}/responses/${id}/approve`, {}, t.apiKey);
    expect(byKey.status).toBe(403);
    expect(byKey.body.code).toBe('user_required');
    const auditor = await send('post', `${BASE}/responses/${id}/approve`, {}, t.auditorAuth);
    expect(auditor.status).toBe(403);
    const approved = await send(
      'post',
      `${BASE}/responses/${id}/approve`,
      { reason: 'Confirmed by phone' },
      t.analyst2Auth,
    );
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body).toMatchObject({
      status: 'succeeded',
      providerStatus: 'applied',
      resultCode: 'restriction_applied',
    });
    expect(approved.body.restriction).toMatchObject({
      kind: 'send_block',
      scope: 'mailbox',
      status: 'active',
    });
    expect(approved.body.attempts.map((a: { phase: string }) => a.phase)).toEqual([
      'authorize',
      'authorize',
      'execute',
    ]);
    const restrictions = await eventually(
      () => get(`${BASE}/restrictions`),
      (r) => (r.body as { data: unknown[] }).data?.length === 1,
    );
    expect(restrictions.body.data[0].responseId).toBe(id);
    const rolled = await send(
      'post',
      `${BASE}/responses/${id}/rollback`,
      { reason: 'Password reset done; lift it' },
      t.analyst2Auth,
    );
    expect(rolled.status, JSON.stringify(rolled.body)).toBe(200);
    expect(rolled.body.status).toBe('rolled_back');
    expect(rolled.body.restriction.status).toBe('lifted');
    const db = await ctx.prisma.atoSmtpRestriction.findFirstOrThrow({
      where: {
        organizationId: t.org.id,
        responseActionId:
          BigInt(0) +
          (await ctx.prisma.atoResponseAction.findUniqueOrThrow({ where: { publicId: id } })).id,
      },
    });
    expect(db.status).toBe('lifted');
    const changed = await ctx.prisma.messageOutbox.count({
      where: { organizationId: t.org.id, eventType: 'ato.restriction.changed.v1' },
    });
    expect(changed).toBe(2);
    const timeline = await ctx.prisma.securityIncidentEvent.findMany({
      where: { incidentId: compromised.incident.id, eventType: { startsWith: 'ato.response_' } },
      select: { eventType: true },
    });
    expect(timeline.map((e) => e.eventType)).toEqual(
      expect.arrayContaining([
        'ato.response_requested',
        'ato.response_approved',
        'ato.response_succeeded',
        'ato.response_rolled_back',
      ]),
    );
  });

  it('reject, cancel, low-impact execution, manual attestation and unsupported provider actions', async () => {
    const incident = compromised.incident.publicId;
    const soc = await send(
      'post',
      `${BASE}/incidents/${incident}/responses`,
      { actionType: 'notify_soc', reason: 'Critical: inform the SOC' },
      t.apiKey,
    );
    expect(soc.status, JSON.stringify(soc.body)).toBe(201);
    expect(soc.body).toMatchObject({
      status: 'succeeded',
      providerStatus: 'unconfirmed',
      requestedBy: { type: 'api_key' },
    });
    const manual = await send('post', `${BASE}/incidents/${incident}/responses`, {
      actionType: 'record_manual_action',
      reason: 'Sessions revoked by hand',
      description: 'Revoked all portal sessions through the Users page',
    });
    expect(manual.body).toMatchObject({ status: 'attested', providerStatus: 'unconfirmed' });
    const provider = await send('post', `${BASE}/incidents/${incident}/responses`, {
      actionType: 'revoke_sessions',
      reason: 'Revoke all identity provider sessions',
    });
    expect(provider.body.status).toBe('pending_approval');
    const unsupported = await send(
      'post',
      `${BASE}/responses/${provider.body.id}/approve`,
      {},
      t.analyst2Auth,
    );
    expect(unsupported.body).toMatchObject({
      status: 'unsupported',
      resultCode: 'no_provider_integration',
    });
    const block = await send('post', `${BASE}/incidents/${incident}/responses`, {
      actionType: 'block_smtp_auth',
      reason: 'Block the connector',
    });
    expect(block.status).toBe(422);
    expect(block.body.code).toBe('ato_response_invalid');
    const toReject = await send('post', `${BASE}/incidents/${incident}/responses`, {
      actionType: 'require_mfa',
      reason: 'Force MFA for this user',
    });
    const rejected = await send(
      'post',
      `${BASE}/responses/${toReject.body.id}/reject`,
      { reason: 'Not needed: travel confirmed' },
      t.analyst2Auth,
    );
    expect(rejected.body.status).toBe('rejected');
    const toCancel = await send(
      'post',
      `${BASE}/incidents/${incident}/responses`,
      { actionType: 'suspend_account', reason: 'Suspend until the review' },
      t.apiKey,
    );
    const cancelled = await send(
      'post',
      `${BASE}/responses/${toCancel.body.id}/cancel`,
      { reason: 'Requested in error' },
      t.apiKey,
    );
    expect(cancelled.body.status).toBe('cancelled');
    const list = await eventually(
      () => get(`${BASE}/responses?status=cancelled,rejected`),
      (r) => (r.body as { data: unknown[] }).data?.length === 2,
    );
    expect(list.body.data.map((r: { status: string }) => r.status).sort()).toEqual([
      'cancelled',
      'rejected',
    ]);
    const detail = await get(`${BASE}/responses/${toCancel.body.id}`);
    expect(detail.body.status).toBe('cancelled');
  });

  it('four eyes: a request made with an API key cannot be decided by the key creator', async () => {
    const victim = await seed.compromised(t.org.id, `keyed-${randomUUID().slice(0, 6)}`);
    const key = {
      'X-API-Key': await fx.createApiKey(t.org, ['ato:read', 'ato:respond'], {
        createdBy: t.analyst,
      }),
    };
    const requested = await send(
      'post',
      `${BASE}/incidents/${victim.incident.publicId}/responses`,
      {
        actionType: 'restrict_smtp_sending',
        durationMinutes: 60,
        reason: 'Requested by automation',
      },
      key,
    );
    expect(requested.status, JSON.stringify(requested.body)).toBe(201);
    expect(requested.body).toMatchObject({
      status: 'pending_approval',
      requestedBy: { type: 'api_key' },
    });
    const id = requested.body.id as string;
    const asCreator = await get(`${BASE}/responses/${id}`, t.analystAuth);
    expect(asCreator.status).toBe(200);
    expect(asCreator.body.canDecide).toBe(false);
    const asOther = await get(`${BASE}/responses/${id}`, t.analyst2Auth);
    expect(asOther.body.canDecide).toBe(true);
    for (const action of ['approve', 'reject']) {
      const self = await send(
        'post',
        `${BASE}/responses/${id}/${action}`,
        { reason: 'I created the key that asked for this' },
        t.analystAuth,
      );
      expect(self.status, JSON.stringify(self.body)).toBe(403);
      expect(self.body.code).toBe('ato_approval_self');
    }
    const approved = await send(
      'post',
      `${BASE}/responses/${id}/approve`,
      { reason: 'Second pair of eyes' },
      t.analyst2Auth,
    );
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body.status).toBe('succeeded');
    const lifted = await send(
      'post',
      `${BASE}/responses/${id}/rollback`,
      { reason: 'Test cleanup: lift it' },
      t.analyst2Auth,
    );
    expect(lifted.status, JSON.stringify(lifted.body)).toBe(200);
  });

  it('settings: CAS, validation with paths, a new version and the audit row with changed paths', async () => {
    const current = await get(`${BASE}/settings`);
    const rv = current.body.rowVersion as number;
    const invalid = await send(
      'put',
      `${BASE}/settings`,
      {
        expectedRowVersion: rv,
        settings: { scoring: { bands: { medium: 60, high: 50, critical: 75 } } },
      },
      t.adminAuth,
    );
    expect(invalid.status).toBe(400);
    expect(invalid.body.code).toBe('ato_settings_invalid');
    expect(invalid.body.issues.length).toBeGreaterThan(0);
    const conflict = await send(
      'put',
      `${BASE}/settings`,
      { expectedRowVersion: rv + 3, settings: {} },
      t.adminAuth,
    );
    expect(conflict.body).toMatchObject({ code: 'ato_settings_conflict', currentRowVersion: rv });
    const analyst = await send('put', `${BASE}/settings`, { expectedRowVersion: rv, settings: {} });
    expect(analyst.status).toBe(403);
    const ok = await send(
      'put',
      `${BASE}/settings`,
      {
        expectedRowVersion: rv,
        settings: { mode: 'monitor', notifications: { incidentMinSeverity: 'critical' } },
      },
      t.adminAuth,
    );
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.rowVersion).toBe(rv + 1);
    expect(ok.body.effective.notifications.incidentMinSeverity).toBe('critical');
    const versions = await ctx.prisma.atoSettingsVersion.count({
      where: { organizationId: t.org.id },
    });
    expect(versions).toBe(ok.body.version);
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: t.org.id, action: 'ato.settings_updated' },
      orderBy: { id: 'desc' },
    });
    expect((audit.metadata as { changedPaths: string[] }).changedPaths).toContain(
      'notifications.incidentMinSeverity',
    );
  });
});

describe('feature gate (D17)', () => {
  it('reads are empty and mutations are 403 ato_not_enabled while the feature is off', async () => {
    const off = await seed.tenant({ enabled: false });
    const account = await seed.mailbox(off.org.id);
    const list = await get(`${BASE}/accounts`, off.analystAuth);
    expect(list.body).toEqual({ data: [], nextCursor: null });
    const detail = await get(`${BASE}/accounts/${account.publicId}`, off.analystAuth);
    expect(detail.status).toBe(404);
    const overview = await get(`${BASE}/overview`, off.analystAuth);
    expect(overview.body.monitoring.featureEnabled).toBe(false);
    const patch = await send(
      'patch',
      `${BASE}/accounts/${account.publicId}`,
      { protected: true, expectedRowVersion: 1 },
      off.analystAuth,
    );
    expect(patch.status).toBe(403);
    expect(patch.body.code).toBe('ato_not_enabled');
  });
});

describe('query plans at volume (Agent 3)', () => {
  it('every ATO list uses its index with ≥ 100 000 signals and auth events for one organization', async () => {
    const o = t.org.id;
    const account = compromised.account.id;
    // 120 000 signals and auth events over the last 60 days (a digits cross join: no recursion
    // depth limit), written in one statement per table.
    const total = 120_000;
    const d =
      '(SELECT 0 i UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9)';
    const seq = `(SELECT a.i + b.i * 10 + c.i * 100 + e.i * 1000 + f.i * 10000 + g.i * 100000 AS n FROM ${d} a, ${d} b, ${d} c, ${d} e, ${d} f, ${d} g) seq WHERE n < ${total}`;
    await ctx.prisma.$executeRawUnsafe(`
      INSERT INTO ato_risk_signals (detected_at, organization_id, account_id, rule_code, category, strength, weight, status, dedupe_key, occurrences, first_occurred_at, last_occurred_at, evidence, source_kind, rules_version, settings_version, updated_at)
      SELECT NOW(3) - INTERVAL (n * 43) SECOND, ${o}, ${account} + (n % 7), 'ato.access.new_asn', 'access_context', 'moderate', 10, IF(n % 5 = 0, 'dismissed', 'active'), SHA2(CONCAT('vol', n), 256), 1, NOW(3), NOW(3), JSON_OBJECT('count', 1), 'window', 'ato-rules/1', 1, NOW(3) FROM ${seq}`);
    await ctx.prisma.$executeRawUnsafe(`
      INSERT INTO ato_auth_events (occurred_at, organization_id, account_id, source, channel, outcome, ip_address, geo_status, attempt_count, last_occurred_at, dedupe_key)
      SELECT NOW(3) - INTERVAL (n * 43) SECOND, ${o}, ${account} + (n % 7), 'smtp_auth', 'smtp', IF(n % 3 = 0, 'failure', 'success'), CONCAT('198.51.100.', n % 250), 'unavailable', 1, NOW(3), SHA2(CONCAT('vol', n), 256) FROM ${seq}`);
    expect(
      await ctx.prisma.atoRiskSignal.count({ where: { organizationId: o } }),
    ).toBeGreaterThanOrEqual(100_000);
    expect(
      await ctx.prisma.atoAuthEvent.count({ where: { organizationId: o } }),
    ).toBeGreaterThanOrEqual(100_000);
    await ctx.prisma.$queryRawUnsafe(
      'ANALYZE TABLE ato_risk_signals, ato_auth_events, ato_accounts, ato_response_actions, security_incidents',
    );
    const explain = async (sql: string) => {
      const rows = await ctx.prisma.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `EXPLAIN ${sql}`,
      );
      return rows.map((r) => {
        const v = Object.values(r);
        return {
          table: v[2],
          type: String(v[4]),
          key: String((v[6] as string | null) ?? ''),
          rows: Number(v[9]),
          extra: String((v[11] as string | null) ?? ''),
        };
      });
    };
    const from = `NOW(3) - INTERVAL 30 DAY`;
    const plans = {
      accountSignals: await explain(
        `SELECT id FROM ato_risk_signals WHERE organization_id = ${o} AND account_id = ${account} AND detected_at >= ${from} AND detected_at < NOW(3) ORDER BY detected_at DESC, id DESC LIMIT 26`,
      ),
      incidentSignals: await explain(
        `SELECT id FROM ato_risk_signals WHERE organization_id = ${o} AND incident_id = ${compromised.incident.id} AND detected_at >= ${from} ORDER BY detected_at DESC, id DESC LIMIT 26`,
      ),
      accountAuthEvents: await explain(
        `SELECT id FROM ato_auth_events WHERE organization_id = ${o} AND account_id = ${account} AND occurred_at >= NOW(3) - INTERVAL 7 DAY AND occurred_at < NOW(3) ORDER BY occurred_at DESC, id DESC LIMIT 26`,
      ),
      scoreHistory: await explain(
        `SELECT id FROM ato_risk_scores WHERE organization_id = ${o} AND account_id = ${account} AND computed_at >= ${from} ORDER BY computed_at DESC, id DESC LIMIT 26`,
      ),
      accountsByScore: await explain(
        `SELECT id FROM ato_accounts WHERE organization_id = ${o} ORDER BY risk_score DESC, id DESC LIMIT 26`,
      ),
      accountsBySignal: await explain(
        `SELECT id FROM ato_accounts WHERE organization_id = ${o} AND last_signal_at IS NOT NULL ORDER BY last_signal_at DESC, id DESC LIMIT 26`,
      ),
      responsesByStatus: await explain(
        `SELECT id FROM ato_response_actions WHERE organization_id = ${o} AND status = 'pending_approval' ORDER BY created_at DESC, id DESC LIMIT 26`,
      ),
      restrictions: await explain(
        `SELECT id FROM ato_smtp_restrictions WHERE organization_id = ${o} AND status = 'active' ORDER BY id DESC LIMIT 26`,
      ),
    };
    for (const [name, plan] of Object.entries(plans)) {
      const first = plan[0]!;
      expect(first.type, name).not.toBe('ALL');
      expect(first.key, name).toMatch(/organization_id|PRIMARY|org/);
      // Restrictions are few per organization (≤ ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG active,
      // lifted/expired rows purged after 400 days) and the table has no `(organization_id,
      // created_at)` index: the newest-first page sorts the organization's rows of the status
      // range (recorded in the WP5 note). Every other list is index-ordered.
      if (name !== 'restrictions') {
        expect(first.extra, `${name}: ${first.extra}`).not.toMatch(/Using filesort/);
      }
    }
    expect(plans.accountSignals[0]!.rows).toBeLessThan(40_000);
    expect(plans.accountAuthEvents[0]!.rows).toBeLessThan(40_000);
    // Lists return in bounded time over the volume (replica; first page and a filtered page).
    const started = Date.now();
    const page = await eventually(
      () => get(`${BASE}/accounts/${compromised.account.publicId}/signals?limit=100`),
      (r) => (r.body as { data: unknown[] }).data?.length === 100,
    );
    expect(page.status).toBe(200);
    const filtered = await get(
      `${BASE}/accounts/${compromised.account.publicId}/auth-events?outcome=failure&limit=50`,
    );
    expect(filtered.status).toBe(200);
    expect(Date.now() - started).toBeLessThan(20_000);
    if (process.env.EXPLAIN_OUT) {
      const { writeFileSync } = await import('node:fs');
      writeFileSync(process.env.EXPLAIN_OUT, JSON.stringify(plans, null, 2));
    }
  });
});
