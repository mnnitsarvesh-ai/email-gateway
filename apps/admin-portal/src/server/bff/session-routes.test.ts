// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { readMfaChallenge, readSession } from '@/server/session/session';
import {
  PORTAL,
  baseSession,
  cookieHeader,
  fakeUpstream,
  json,
  testConfig,
  testDeps,
  tokenResponse,
} from '@/server/test-helpers';
import {
  endOverride,
  getSession,
  login,
  logout,
  logoutAll,
  platformHealth,
  refresh,
  startOverride,
  verifyMfa,
} from './session-routes';

const now = Date.parse('2026-11-13T10:00:00.000Z');
const config = testConfig();

function post(path: string, body: unknown, headers: Record<string, string> = {}, method = 'POST') {
  return new Request(`${PORTAL}${path}`, {
    method,
    headers: { origin: PORTAL, 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function withSession(session = baseSession(now), extra: Record<string, string> = {}) {
  return {
    cookie: await cookieHeader(session, config, now),
    'x-csrf-token': session.csrf,
    ...extra,
  };
}

function cookieValue(response: Response, name: string): string | undefined {
  return response.headers
    .getSetCookie()
    .find((c) => c.startsWith(`${name}=`))
    ?.split(';')[0];
}

function route(call: { method: string; url: string }): string {
  return `${call.method} ${new URL(call.url).pathname}`;
}

function expiredAccess(overrides: Parameters<typeof baseSession>[1] = {}) {
  return baseSession(now, { atExp: now - 1, ...overrides });
}

/** Refresh answers new tokens; every other call 204. */
function refreshingUpstream() {
  return fakeUpstream((call) =>
    new URL(call.url).pathname === '/api/v1/auth/refresh'
      ? json(tokenResponse({ accessToken: 'refreshed-at', refreshToken: 'egr_refreshed' }))
      : new Response(null, { status: 204 }),
  );
}

describe('POST /bff/session/login', () => {
  it('seals the tokens into the session cookie and never returns them', async () => {
    const upstream = fakeUpstream(() => json(tokenResponse()));
    const response = await login(
      post(
        '/bff/session/login',
        { email: 'a@example.com', password: 'pw' },
        { 'user-agent': 'UA/1' },
      ),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({ status: 'authenticated', mfaEnrollmentRequired: false });
    expect(text).not.toContain('egr_');
    expect(upstream.calls[0]!.url).toMatch(/\/api\/v1\/auth\/login$/);
    expect(upstream.calls[0]!.headers.get('user-agent')).toBe('UA/1');
    expect(JSON.parse(upstream.calls[0]!.body ?? '')).toEqual({
      email: 'a@example.com',
      password: 'pw',
    });
    const session = await readSession(cookieValue(response, 'eg_session'), config);
    expect(session).toMatchObject({
      at: 'header.payload-access.sig',
      rt: tokenResponse().refreshToken,
      atExp: now + 600_000,
    });
    expect(cookieValue(response, 'eg_csrf')).toBe(`eg_csrf=${session?.csrf}`);
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('stores an MFA challenge in eg_mfa', async () => {
    const upstream = fakeUpstream(() =>
      json({ mfaRequired: true, mfaToken: 'egt_challenge', expiresIn: 300 }),
    );
    const response = await login(
      post('/bff/session/login', { email: 'a@example.com', password: 'pw' }),
      testDeps(upstream.fetch, { now }),
    );
    expect(await response.json()).toEqual({ status: 'mfa_required' });
    const challenge = await readMfaChallenge(cookieValue(response, 'eg_mfa'), config, now);
    expect(challenge).toMatchObject({ mfaToken: 'egt_challenge', exp: now + 300_000 });
  });

  it('passes api errors through with Retry-After', async () => {
    const upstream = fakeUpstream(() =>
      json(
        {
          statusCode: 429,
          error: 'TOO_MANY_REQUESTS',
          code: 'rate_limited',
          message: 'Too many requests',
          requestId: 'r-1',
        },
        429,
        { 'retry-after': '42' },
      ),
    );
    const response = await login(
      post('/bff/session/login', { email: 'a@example.com', password: 'pw' }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('42');
    expect(await response.json()).toMatchObject({ code: 'rate_limited', requestId: 'r-1' });
  });

  it('validates the body strictly and checks the Origin', async () => {
    const upstream = fakeUpstream(() => json(tokenResponse()));
    const unknown = await login(
      post('/bff/session/login', { email: 'a@example.com', password: 'pw', tenant: 'x' }),
      testDeps(upstream.fetch, { now }),
    );
    expect(unknown.status).toBe(400);
    expect(await unknown.json()).toMatchObject({ code: 'validation_failed' });
    const cross = await login(
      post(
        '/bff/session/login',
        { email: 'a@example.com', password: 'pw' },
        { origin: 'https://evil.example' },
      ),
      testDeps(upstream.fetch, { now }),
    );
    expect(cross.status).toBe(403);
    expect(upstream.calls).toHaveLength(0);
  });

  it('maps an unreachable api to 502', async () => {
    const upstream = fakeUpstream(() => {
      throw new TypeError('fetch failed');
    });
    const response = await login(
      post('/bff/session/login', { email: 'a@example.com', password: 'pw' }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({ code: 'upstream_unavailable' });
  });
});

describe('POST /bff/session/mfa', () => {
  it('verifies with the sealed challenge and establishes the session', async () => {
    const loginUp = fakeUpstream(() =>
      json({ mfaRequired: true, mfaToken: 'egt_challenge', expiresIn: 300 }),
    );
    const first = await login(
      post('/bff/session/login', { email: 'a@example.com', password: 'pw' }),
      testDeps(loginUp.fetch, { now }),
    );
    const mfaCookie = cookieValue(first, 'eg_mfa') ?? '';
    const upstream = fakeUpstream(() => json(tokenResponse({ mfaEnrollmentRequired: false })));
    const response = await verifyMfa(
      post('/bff/session/mfa', { code: '123456' }, { cookie: mfaCookie }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(200);
    expect(JSON.parse(upstream.calls[0]!.body ?? '')).toEqual({
      mfaToken: 'egt_challenge',
      code: '123456',
    });
    expect(cookieValue(response, 'eg_mfa')).toBe('eg_mfa=');
    expect(await readSession(cookieValue(response, 'eg_session'), config)).not.toBeNull();
  });

  it('refuses an expired or missing challenge and a body with both factors', async () => {
    const upstream = fakeUpstream(() => json(tokenResponse()));
    const missing = await verifyMfa(
      post('/bff/session/mfa', { code: '123456' }),
      testDeps(upstream.fetch, { now }),
    );
    expect(missing.status).toBe(401);
    expect(await missing.json()).toMatchObject({ code: 'mfa_challenge_expired' });
    const both = await verifyMfa(
      post('/bff/session/mfa', { code: '123456', recoveryCode: 'abcde-fghij' }),
      testDeps(upstream.fetch, { now }),
    );
    expect(both.status).toBe(400);
  });
});

describe('POST /bff/session/refresh', () => {
  it('short-circuits when the access token is fresh enough (another tab refreshed)', async () => {
    const upstream = fakeUpstream(() => json(tokenResponse()));
    const response = await refresh(
      post('/bff/session/refresh', {}, await withSession()),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(200);
    expect(upstream.calls).toHaveLength(0);
    expect(await response.json()).toMatchObject({ authenticated: true });
  });

  it('refreshes when close to expiry, rotating tokens and CSRF and keeping the override', async () => {
    const ovr = {
      id: 'ovr-1',
      at: 'ovr-at',
      exp: now + 600_000,
      organizationId: 'org-b',
      organizationName: 'Beta',
    };
    const session = baseSession(now, { atExp: now + 30_000, ovr });
    const upstream = fakeUpstream(() =>
      json(tokenResponse({ accessToken: 'new-at', refreshToken: 'egr_new' })),
    );
    const response = await refresh(
      post('/bff/session/refresh', {}, await withSession(session)),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(200);
    expect(JSON.parse(upstream.calls[0]!.body ?? '')).toEqual({ refreshToken: session.rt });
    const next = await readSession(cookieValue(response, 'eg_session'), config);
    expect(next).toMatchObject({ at: 'new-at', rt: 'egr_new', ovr });
    expect(next?.csrf).not.toBe(session.csrf);
  });

  it('force: true always calls the api (after MFA enrollment)', async () => {
    const upstream = fakeUpstream(() => json(tokenResponse()));
    await refresh(
      post('/bff/session/refresh', { force: true }, await withSession()),
      testDeps(upstream.fetch, { now }),
    );
    expect(upstream.calls).toHaveLength(1);
  });

  it('clears every cookie and answers 401 session_expired when the api refuses', async () => {
    const upstream = fakeUpstream(() =>
      json({ statusCode: 401, error: 'UNAUTHORIZED', message: 'Unauthorized' }, 401),
    );
    const response = await refresh(
      post('/bff/session/refresh', { force: true }, await withSession()),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'session_expired' });
    expect(response.headers.getSetCookie().map((c) => c.split('=')[0])).toEqual([
      'eg_session',
      'eg_csrf',
      'eg_mfa',
    ]);
  });

  it('requires the CSRF token', async () => {
    const upstream = fakeUpstream(() => json(tokenResponse()));
    const headers = await withSession();
    const response = await refresh(
      post('/bff/session/refresh', {}, { cookie: headers.cookie }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(403);
  });
});

describe('GET /bff/session', () => {
  it('returns the token-free state from the cookie only', async () => {
    const upstream = fakeUpstream(() => json({}));
    const response = await getSession(
      new Request(`${PORTAL}/bff/session`, { headers: { cookie: (await withSession()).cookie } }),
      testDeps(upstream.fetch, { now }),
    );
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ authenticated: true, override: null, devFixtures: false });
    expect(JSON.stringify(body)).not.toContain('access-token-current');
    expect(upstream.calls).toHaveLength(0);
  });
});

describe('logout', () => {
  it('ends an active override, logs out and clears the cookies', async () => {
    const ovr = {
      id: 'ovr-1',
      at: 'ovr-at',
      exp: now + 600_000,
      organizationId: 'org-b',
      organizationName: 'Beta',
    };
    const upstream = fakeUpstream(() => new Response(null, { status: 204 }));
    const response = await logout(
      post('/bff/session/logout', undefined, await withSession(baseSession(now, { ovr }))),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      'DELETE /api/v1/platform/overrides/ovr-1',
      'POST /api/v1/auth/logout',
    ]);
    expect(upstream.calls[1]!.headers.get('authorization')).toBe('Bearer access-token-current');
    expect(response.headers.getSetCookie()).toHaveLength(3);
  });

  it('clears the cookies even when the api is unreachable (502 logout_incomplete)', async () => {
    const upstream = fakeUpstream(() => {
      throw new TypeError('fetch failed');
    });
    const deps = testDeps(upstream.fetch, { now });
    const response = await logout(
      post('/bff/session/logout', undefined, await withSession()),
      deps,
    );
    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({ code: 'logout_incomplete' });
    expect(response.headers.getSetCookie().every((c) => c.includes('Max-Age=0'))).toBe(true);
    expect(deps.logger.calls.some((c) => c[0] === 'warn')).toBe(true);
  });

  it('logout-all calls the api and clears the cookies', async () => {
    const upstream = fakeUpstream(() => new Response(null, { status: 204 }));
    const response = await logoutAll(
      post('/bff/session/logout-all', undefined, await withSession()),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls.map(route)).toEqual(['POST /api/v1/auth/logout-all']);
    expect(response.headers.getSetCookie().every((c) => c.includes('Max-Age=0'))).toBe(true);
  });

  it('logout-all with an expired access token refreshes server-side first, then logs out everywhere', async () => {
    const upstream = refreshingUpstream();
    const response = await logoutAll(
      post('/bff/session/logout-all', undefined, await withSession(expiredAccess())),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls.map(route)).toEqual([
      'POST /api/v1/auth/refresh',
      'POST /api/v1/auth/logout-all',
    ]);
    expect(JSON.parse(upstream.calls[0]!.body ?? '')).toEqual({
      refreshToken: 'egr_refresh_current',
    });
    expect(upstream.calls[1]!.headers.get('authorization')).toBe('Bearer refreshed-at');
    expect(response.headers.getSetCookie().every((c) => c.includes('Max-Age=0'))).toBe(true);
  });

  it('logout-all clears the cookies and answers session_expired when the refresh token is refused', async () => {
    const upstream = fakeUpstream(() =>
      json({ statusCode: 401, error: 'UNAUTHORIZED', code: 'unauthorized', message: 'x' }, 401),
    );
    const response = await logoutAll(
      post('/bff/session/logout-all', undefined, await withSession(expiredAccess())),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'session_expired' });
    expect(upstream.calls.map(route)).toEqual(['POST /api/v1/auth/refresh']);
    expect(response.headers.getSetCookie().every((c) => c.includes('Max-Age=0'))).toBe(true);
  });

  it('logout with an expired access token refreshes first, then ends the override and the api session', async () => {
    const upstream = refreshingUpstream();
    const session = expiredAccess({
      ovr: {
        id: 'ovr-1',
        at: 'ovr-at',
        exp: now + 600_000,
        organizationId: 'org-b',
        organizationName: 'Beta',
      },
    });
    const response = await logout(
      post('/bff/session/logout', undefined, await withSession(session)),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls.map(route)).toEqual([
      'POST /api/v1/auth/refresh',
      'DELETE /api/v1/platform/overrides/ovr-1',
      'POST /api/v1/auth/logout',
    ]);
    expect(upstream.calls[1]!.headers.get('authorization')).toBe('Bearer refreshed-at');
    expect(upstream.calls[2]!.headers.get('authorization')).toBe('Bearer refreshed-at');
    expect(response.headers.getSetCookie().every((c) => c.includes('Max-Age=0'))).toBe(true);
  });

  it('logout counts a refused refresh token as an ended session (204)', async () => {
    const upstream = fakeUpstream(() =>
      json({ statusCode: 401, error: 'UNAUTHORIZED', code: 'unauthorized', message: 'x' }, 401),
    );
    const response = await logout(
      post('/bff/session/logout', undefined, await withSession(expiredAccess())),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls.map(route)).toEqual(['POST /api/v1/auth/refresh']);
  });

  it('logout checks an api 401 with a forced refresh and retries once with the new token', async () => {
    let logouts = 0;
    const upstream = fakeUpstream((call) => {
      const path = new URL(call.url).pathname;
      if (path === '/api/v1/auth/refresh') {
        return json(tokenResponse({ accessToken: 'refreshed-at', refreshToken: 'egr_next' }));
      }
      logouts += 1;
      return logouts === 1
        ? json({ statusCode: 401, error: 'UNAUTHORIZED', code: 'unauthorized', message: 'x' }, 401)
        : new Response(null, { status: 204 });
    });
    const response = await logout(
      post('/bff/session/logout', undefined, await withSession()),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls.map(route)).toEqual([
      'POST /api/v1/auth/logout',
      'POST /api/v1/auth/refresh',
      'POST /api/v1/auth/logout',
    ]);
    expect(upstream.calls[2]!.headers.get('authorization')).toBe('Bearer refreshed-at');
  });

  it('logout answers 502 logout_incomplete (cookies cleared) when the api session could not be ended', async () => {
    const upstream = fakeUpstream(() =>
      json({ statusCode: 503, error: 'SERVICE_UNAVAILABLE', code: 'x', message: 'x' }, 503),
    );
    const response = await logout(
      post('/bff/session/logout', undefined, await withSession()),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({ code: 'logout_incomplete' });
    expect(response.headers.getSetCookie()).toHaveLength(3);
    expect(response.headers.getSetCookie().every((c) => c.includes('Max-Age=0'))).toBe(true);
  });
});

describe('platform override', () => {
  const organizationId = '01930000-0000-7000-8000-0000000000e1';
  const startBody = {
    organizationId,
    reason: 'Ticket OPS-1234 investigation',
    durationMinutes: 30,
  };

  function overrideUpstream(orgName = 'Beta Logistics', onRefresh?: () => Response) {
    return fakeUpstream((call) => {
      const path = new URL(call.url).pathname;
      if (path === '/api/v1/auth/refresh' && onRefresh) return onRefresh();
      if (path === '/api/v1/platform/overrides') {
        return json(
          {
            overrideId: 'ovr-9',
            accessToken: 'override-access-token',
            tokenType: 'Bearer',
            expiresAt: new Date(now + 30 * 60_000).toISOString(),
            organization: { id: organizationId, slug: 'beta', name: 'From override response' },
          },
          201,
        );
      }
      if (path === `/api/v1/organizations/${organizationId}`)
        return json({ id: organizationId, name: orgName });
      return new Response(null, { status: 204 });
    });
  }

  it('starts an override with the user token, stores it sealed and returns no token', async () => {
    const upstream = overrideUpstream();
    const response = await startOverride(
      post('/bff/session/override', startBody, await withSession()),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(201);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({
      id: 'ovr-9',
      organizationId,
      organizationName: 'Beta Logistics',
      expiresAt: new Date(now + 30 * 60_000).toISOString(),
    });
    expect(text).not.toContain('override-access-token');
    expect(upstream.calls[0]!.headers.get('authorization')).toBe('Bearer access-token-current');
    expect(upstream.calls[1]!.headers.get('authorization')).toBe('Bearer access-token-current');
    const session = await readSession(cookieValue(response, 'eg_session'), config);
    expect(session?.ovr).toMatchObject({
      id: 'ovr-9',
      at: 'override-access-token',
      organizationName: 'Beta Logistics',
    });
  });

  it('refuses a second override, a bad body, and passes 403 mfa_required through', async () => {
    const upstream = overrideUpstream();
    const active = baseSession(now, {
      ovr: { id: 'o', at: 'a', exp: now + 1000, organizationId, organizationName: 'B' },
    });
    expect(
      (
        await startOverride(
          post('/bff/session/override', startBody, await withSession(active)),
          testDeps(upstream.fetch, { now }),
        )
      ).status,
    ).toBe(409);
    expect(
      (
        await startOverride(
          post('/bff/session/override', { ...startBody, reason: 'short' }, await withSession()),
          testDeps(upstream.fetch, { now }),
        )
      ).status,
    ).toBe(400);
    const mfa = fakeUpstream(() =>
      json(
        { statusCode: 403, error: 'FORBIDDEN', code: 'mfa_required', message: 'MFA required' },
        403,
      ),
    );
    const refused = await startOverride(
      post('/bff/session/override', startBody, await withSession()),
      testDeps(mfa.fetch, { now }),
    );
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ code: 'mfa_required' });
  });

  it('ends the override when it does not fit the cookie (override_cookie_too_large)', async () => {
    const upstream = overrideUpstream('N'.repeat(255));
    const session = baseSession(now, { at: 'x'.repeat(2400) });
    const response = await startOverride(
      post('/bff/session/override', startBody, await withSession(session)),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ code: 'override_cookie_too_large' });
    expect(upstream.calls.at(-1)).toMatchObject({ method: 'DELETE' });
  });

  it('ends the override and drops it from the session', async () => {
    const upstream = fakeUpstream(() => new Response(null, { status: 204 }));
    const session = baseSession(now, {
      ovr: { id: 'ovr-9', at: 'a', exp: now + 60_000, organizationId, organizationName: 'B' },
    });
    const response = await endOverride(
      post('/bff/session/override', undefined, await withSession(session), 'DELETE'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls[0]).toMatchObject({ method: 'DELETE' });
    expect(new URL(upstream.calls[0]!.url).pathname).toBe('/api/v1/platform/overrides/ovr-9');
    expect((await readSession(cookieValue(response, 'eg_session'), config))?.ovr).toBeUndefined();
  });

  it('starts an override with an expired access token: refreshes first and keeps the rotated tokens', async () => {
    const upstream = overrideUpstream('Beta Logistics', () =>
      json(tokenResponse({ accessToken: 'refreshed-at', refreshToken: 'egr_refreshed' })),
    );
    const response = await startOverride(
      post('/bff/session/override', startBody, await withSession(expiredAccess())),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(201);
    expect(upstream.calls.map(route).slice(0, 2)).toEqual([
      'POST /api/v1/auth/refresh',
      'POST /api/v1/platform/overrides',
    ]);
    expect(upstream.calls[1]!.headers.get('authorization')).toBe('Bearer refreshed-at');
    const next = await readSession(cookieValue(response, 'eg_session'), config);
    expect(next).toMatchObject({ at: 'refreshed-at', rt: 'egr_refreshed', ovr: { id: 'ovr-9' } });
  });

  it('keeps the rotated tokens when the override start fails after a server-side refresh', async () => {
    const upstream = fakeUpstream((call) =>
      new URL(call.url).pathname === '/api/v1/auth/refresh'
        ? json(tokenResponse({ accessToken: 'refreshed-at', refreshToken: 'egr_refreshed' }))
        : json({ statusCode: 403, error: 'FORBIDDEN', code: 'mfa_required', message: 'x' }, 403),
    );
    const response = await startOverride(
      post('/bff/session/override', startBody, await withSession(expiredAccess())),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(403);
    const next = await readSession(cookieValue(response, 'eg_session'), config);
    expect(next).toMatchObject({ at: 'refreshed-at', rt: 'egr_refreshed' });
  });

  it('ends an override with an expired access token: refreshes first, then ends it with the new token', async () => {
    const session = expiredAccess({
      ovr: { id: 'ovr-9', at: 'a', exp: now + 60_000, organizationId, organizationName: 'B' },
    });
    const upstream = refreshingUpstream();
    const response = await endOverride(
      post('/bff/session/override', undefined, await withSession(session), 'DELETE'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls.map(route)).toEqual([
      'POST /api/v1/auth/refresh',
      'DELETE /api/v1/platform/overrides/ovr-9',
    ]);
    expect(upstream.calls[1]!.headers.get('authorization')).toBe('Bearer refreshed-at');
    const next = await readSession(cookieValue(response, 'eg_session'), config);
    expect(next).toMatchObject({ at: 'refreshed-at', rt: 'egr_refreshed' });
    expect(next?.ovr).toBeUndefined();
  });

  it('does not treat an api 401 as an ended override: keeps it and passes the error through', async () => {
    const session = baseSession(now, {
      ovr: { id: 'ovr-9', at: 'a', exp: now + 60_000, organizationId, organizationName: 'B' },
    });
    const upstream = fakeUpstream(() =>
      json({ statusCode: 401, error: 'UNAUTHORIZED', code: 'unauthorized', message: 'x' }, 401),
    );
    const response = await endOverride(
      post('/bff/session/override', undefined, await withSession(session), 'DELETE'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'unauthorized' });
    expect(cookieValue(response, 'eg_session')).toBeUndefined();
  });

  it('keeps the override and the rotated tokens when the api fails after a server-side refresh', async () => {
    const session = expiredAccess({
      ovr: { id: 'ovr-9', at: 'a', exp: now + 60_000, organizationId, organizationName: 'B' },
    });
    const upstream = fakeUpstream((call) =>
      new URL(call.url).pathname === '/api/v1/auth/refresh'
        ? json(tokenResponse({ accessToken: 'refreshed-at', refreshToken: 'egr_refreshed' }))
        : json({ statusCode: 500, error: 'INTERNAL_SERVER_ERROR', code: 'x', message: 'x' }, 500),
    );
    const response = await endOverride(
      post('/bff/session/override', undefined, await withSession(session), 'DELETE'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(500);
    const next = await readSession(cookieValue(response, 'eg_session'), config);
    expect(next).toMatchObject({ rt: 'egr_refreshed', ovr: { id: 'ovr-9' } });
  });

  it('counts an api 404 as an already ended override', async () => {
    const session = baseSession(now, {
      ovr: { id: 'ovr-9', at: 'a', exp: now + 60_000, organizationId, organizationName: 'B' },
    });
    const upstream = fakeUpstream(() =>
      json({ statusCode: 404, error: 'NOT_FOUND', code: 'not_found', message: 'x' }, 404),
    );
    const response = await endOverride(
      post('/bff/session/override', undefined, await withSession(session), 'DELETE'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect((await readSession(cookieValue(response, 'eg_session'), config))?.ovr).toBeUndefined();
  });

  it('drops an expired override locally without calling the api', async () => {
    const upstream = fakeUpstream(() => new Response(null, { status: 204 }));
    const session = baseSession(now, {
      ovr: { id: 'ovr-9', at: 'a', exp: now - 1, organizationId, organizationName: 'B' },
    });
    const response = await endOverride(
      post('/bff/session/override', undefined, await withSession(session), 'DELETE'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(204);
    expect(upstream.calls).toHaveLength(0);
  });
});

describe('GET /bff/platform/health', () => {
  it('answers 403 without platform:operations', async () => {
    const upstream = fakeUpstream(() => json({ permissions: ['report:read'] }));
    const response = await platformHealth(
      new Request(`${PORTAL}/bff/platform/health`, {
        headers: { cookie: (await withSession()).cookie },
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(403);
    expect(upstream.calls).toHaveLength(1);
  });

  it('returns the readiness summary for platform operators', async () => {
    const upstream = fakeUpstream((call) =>
      new URL(call.url).pathname === '/api/v1/auth/me'
        ? json({ permissions: ['platform:operations'] })
        : json({
            service: 'api',
            status: 'ok',
            version: '1.2.3',
            uptimeSeconds: 1,
            checks: [{ name: 'mysql', status: 'ok', latencyMs: 2 }],
          }),
    );
    const response = await platformHealth(
      new Request(`${PORTAL}/bff/platform/health`, {
        headers: { cookie: (await withSession()).cookie },
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: 'ok',
      reachable: true,
      version: '1.2.3',
    });
    expect(new URL(upstream.calls[1]!.url).pathname).toBe('/health/ready');
  });
});
