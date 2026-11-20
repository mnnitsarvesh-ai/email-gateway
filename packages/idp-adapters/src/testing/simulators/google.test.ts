import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { GS_ADMIN_EMAIL, GS_CUSTOMER_ID, googleCustomer } from '../datasets/google';
import { GOOGLE_SIM_SCOPES, googleErrorBody } from './google';
import { runStandalone, startSimulators, type RunningSimulators } from './main';
import { SimTokenRegistry } from './tokens';

const now = new Date('2026-11-10T12:00:00.000Z');

describe('Google simulators (in-process, D12)', () => {
  let sims: RunningSimulators;
  const issue = (scopes: string[], subject?: string) => {
    sims.tokens.setGrant(GS_CUSTOMER_ID, `p${scopes.join('|')}`, scopes);
    return sims.tokens.issue({
      directoryId: GS_CUSTOMER_ID,
      resource: 'google',
      profile: `p${scopes.join('|')}`,
      ...(subject ? { subject } : {}),
      expiresAt: now.getTime() + 3_600_000,
    });
  };
  const get = async (base: string, path: string, token?: string, init: RequestInit = {}) => {
    const response = await fetch(`${sims.baseUrl(base)}${path}`, {
      ...init,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      },
    });
    const body: unknown = await response.json().catch(() => null);
    return { status: response.status, body };
  };

  beforeAll(async () => {
    sims = await startSimulators({
      dataset: { google: { customers: [googleCustomer(now)] } },
      tokens: new SimTokenRegistry({ now: () => now.getTime() }),
      now: () => now.getTime(),
    });
  });
  afterAll(async () => {
    await sims.stop();
  });
  afterEach(() => {
    sims.script.clearCalls();
  });

  it('answers in Google’s error shape and enforces bearer tokens', async () => {
    const unauthenticated = await get(
      'google-admin',
      '/admin/directory/v1/users?customer=my_customer',
    );
    expect(unauthenticated).toEqual({
      status: 401,
      body: {
        error: {
          code: 401,
          message: 'Simulated error.',
          errors: [{ domain: 'global', reason: 'authError', message: 'Simulated error.' }],
          status: 'UNAUTHENTICATED',
        },
      },
    });
    expect(googleErrorBody(429, 'TooManyRequests')).toMatchObject({
      error: { status: 'RESOURCE_EXHAUSTED', errors: [{ reason: 'rateLimitExceeded' }] },
    });
    expect(googleErrorBody(403, undefined, 'dailyLimitExceeded')).toMatchObject({
      error: { status: 'PERMISSION_DENIED', errors: [{ reason: 'dailyLimitExceeded' }] },
    });
  });

  it('enforces each endpoint’s scope and the administrator impersonation', async () => {
    const reports = issue([GOOGLE_SIM_SCOPES.reportsAudit], GS_ADMIN_EMAIL);
    const path = '/admin/reports/v1/activity/users/all/applications/login?maxResults=2';
    const page = await get('google-admin', path, reports);
    expect(page.status).toBe(200);
    expect((page.body as { items: unknown[]; nextPageToken: string }).items).toHaveLength(2);
    expect(
      (await get('google-admin', '/admin/directory/v1/users?customer=my_customer', reports)).body,
    ).toMatchObject({
      error: { code: 403, errors: [{ reason: 'insufficientPermissions' }] },
    });
    const nonAdmin = issue([GOOGLE_SIM_SCOPES.reportsAudit], 'alex@fabrikam-it.example');
    expect((await get('google-admin', path, nonAdmin)).status).toBe(403);
    const gmailBasic = issue([GOOGLE_SIM_SCOPES.gmailSettingsBasic], 'alex@fabrikam-it.example');
    expect(
      (await get('gmail', '/gmail/v1/users/me/settings/filters', gmailBasic)).body,
    ).toMatchObject({ filter: [{ id: 'ANe1BmgAlex0001' }, { id: 'ANe1BmgAlex0002' }] });
    // Auto-forwarding updates need gmail.settings.sharing.
    const update = await get('gmail', '/gmail/v1/users/me/settings/autoForwarding', gmailBasic, {
      method: 'PUT',
      body: JSON.stringify({ enabled: false }),
    });
    expect(update.status).toBe(403);
    // The impersonated user may read only its own mailbox.
    expect(
      (
        await get(
          'gmail',
          `/gmail/v1/users/${encodeURIComponent('blake@fabrikam-it.example')}/settings/filters`,
          gmailBasic,
        )
      ).status,
    ).toBe(403);
    expect(sims.script.writes().map((c) => c.status)).toEqual([403]); // refused, no effect
  });

  it('validates Reports windows, retention and paging parameters', async () => {
    const reports = issue([GOOGLE_SIM_SCOPES.reportsAudit], GS_ADMIN_EMAIL);
    const base = '/admin/reports/v1/activity/users/all/applications/login';
    const old = new Date(now.getTime() - 181 * 86_400_000).toISOString();
    for (const query of [
      `?startTime=${old}`,
      '?startTime=yesterday',
      `?startTime=${now.toISOString()}&endTime=${new Date(now.getTime() - 1000).toISOString()}`,
      '?maxResults=0',
      '?pageToken=bogus',
    ]) {
      expect((await get('google-admin', `${base}${query}`, reports)).status, query).toBe(400);
    }
    expect((await get('google-admin', `${base.replace('login', 'drive')}`, reports)).status).toBe(
      400,
    );
    const filtered = await get(
      'google-admin',
      `${base.replace('login', 'token')}?eventName=authorize`,
      reports,
    );
    expect((filtered.body as { items: unknown[] }).items).toHaveLength(2);
  });
});

describe('Google simulators (standalone, permissive tokens)', () => {
  let running: Awaited<ReturnType<typeof runStandalone>>;
  beforeAll(async () => {
    running = await runStandalone({
      IDP_SIM_HOST: '127.0.0.1',
      IDP_SIM_PORT: '0',
      IDP_SIM_ADMIN_PORT: '0',
      IDP_SIM_QUIET: 'true',
    });
  });
  afterAll(async () => {
    await running.stop();
  });

  it('serves /google-admin and /gmail for a Google-only dataset with per-customer permissions', async () => {
    const admin = `http://127.0.0.1:${running.adminPort}`;
    const data = `http://127.0.0.1:${running.dataPort}`;
    const post = (path: string, body: unknown) =>
      fetch(`${admin}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    expect(
      (await post('/admin/dataset', { google: { customers: [googleCustomer(new Date())] } }))
        .status,
    ).toBe(204);
    const auth = { headers: { Authorization: 'Bearer EXAMPLE-stack-token' } };
    const users = await fetch(
      `${data}/google-admin/admin/directory/v1/users?customer=my_customer`,
      auth,
    );
    expect(users.status).toBe(200);
    // Stack tokens carry no subject: Gmail is addressed by the owner's address (never `me`).
    const filters = await fetch(
      `${data}/gmail/gmail/v1/users/${encodeURIComponent('alex@fabrikam-it.example')}/settings/filters`,
      auth,
    );
    expect(filters.status).toBe(200);
    expect((await fetch(`${data}/gmail/gmail/v1/users/me/settings/filters`, auth)).status).toBe(
      400,
    );
    await post('/admin/permissions', {
      directoryId: GS_CUSTOMER_ID,
      permissions: [GOOGLE_SIM_SCOPES.reportsAudit],
    });
    expect(
      (await fetch(`${data}/google-admin/admin/directory/v1/users?customer=my_customer`, auth))
        .status,
    ).toBe(403);
    await post('/admin/inject', {
      simulator: 'google-admin',
      path: '/admin/reports',
      status: 403,
      reason: 'quotaExceeded',
    });
    const quota = await fetch(
      `${data}/google-admin/admin/reports/v1/activity/users/all/applications/login`,
      auth,
    );
    expect(quota.status).toBe(403);
    expect(await quota.json()).toMatchObject({ error: { errors: [{ reason: 'quotaExceeded' }] } });
    expect((await post('/admin/reset', {})).status).toBe(204);
  });
});
