// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { handleProxy } from './proxy';
import {
  API,
  PORTAL,
  TEST_FORWARDER_TOKEN,
  baseSession,
  cookieHeader,
  fakeUpstream,
  json,
  testConfig,
  testDeps,
} from './test-helpers';
import { UpstreamError } from './upstream';

const now = Date.parse('2026-11-13T10:00:00.000Z');
const config = testConfig();

async function request(
  path: string,
  init: RequestInit & { session?: ReturnType<typeof baseSession> | null } = {},
) {
  const headers = new Headers(init.headers);
  const session = init.session === undefined ? baseSession(now) : init.session;
  if (session) headers.set('cookie', await cookieHeader(session, config, now));
  return new Request(`${PORTAL}${path}`, { ...init, headers });
}

function ok() {
  return fakeUpstream(() =>
    json({ data: [], nextCursor: null }, 200, {
      'set-cookie': 'evil=1',
      'x-powered-by': 'x',
      'ratelimit-remaining': '9',
    }),
  );
}

describe('generic proxy (design P5)', () => {
  it('forwards an allow-listed operation with the session token and the allow-listed headers', async () => {
    const upstream = ok();
    const response = await handleProxy(
      await request('/bff/api/v1/domains?status=active&limit=25', {
        headers: {
          'x-forwarded-for': '127.0.0.1',
          'user-agent': 'Browser/1',
          'x-eg-client-ip': '6.6.6.6',
          'x-eg-forwarder-token': 'forged',
          'x-tenant-id': 'other-tenant',
          accept: 'application/json',
        },
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(200);
    const call = upstream.calls[0]!;
    expect(call.url).toBe(`${API}/api/v1/domains?status=active&limit=25`);
    expect(call.headers.get('authorization')).toBe('Bearer access-token-current');
    expect(call.headers.get('cookie')).toBeNull();
    expect(call.headers.get('x-tenant-id')).toBeNull();
    expect(call.headers.get('user-agent')).toBe('Browser/1');
    expect(call.headers.get('x-eg-client-ip')).toBe('127.0.0.1');
    expect(call.headers.get('x-eg-forwarder-token')).toBe(TEST_FORWARDER_TOKEN);
    expect(call.headers.get('x-correlation-id')).toMatch(/^[0-9a-f-]{36}$/);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('ratelimit-remaining')).toBe('9');
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(response.headers.get('x-powered-by')).toBeNull();
  });

  it('omits the forwarder headers without a trustworthy IP or without the token', async () => {
    const upstream = ok();
    await handleProxy(
      await request('/bff/api/v1/domains', {
        headers: { 'x-forwarded-for': 'not-an-ip' },
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(upstream.calls[0]!.headers.get('x-eg-client-ip')).toBeNull();
    const second = ok();
    await handleProxy(
      await request('/bff/api/v1/domains', { headers: { 'x-forwarded-for': '127.0.0.1' } }),
      testDeps(second.fetch, {
        now,
        config: testConfig({ API_TRUSTED_FORWARDER_TOKEN: undefined }),
      }),
    );
    expect(second.calls[0]!.headers.get('x-eg-forwarder-token')).toBeNull();
  });

  it('keeps a well-formed client correlation id', async () => {
    const upstream = ok();
    await handleProxy(
      await request('/bff/api/v1/domains', { headers: { 'x-correlation-id': 'portal-abc-123' } }),
      testDeps(upstream.fetch, { now }),
    );
    expect(upstream.calls[0]!.headers.get('x-correlation-id')).toBe('portal-abc-123');
  });

  it.each([
    '/bff/api/v1/health/ready',
    '/bff/api/v1/metrics',
    '/bff/api/v1/../../health/ready',
    '/bff/api/v1/domains/../../../metrics',
    '/bff/api/v1/domains/%2e%2e/auth',
    '/bff/api/v1/domains%2Fx',
    '/bff/api/v1/domains/a%2fb/dns/status',
    '/bff/api/v1/domains/a%5cb',
    '/bff/api/v1/domains//dns',
    '/bff/api/v1/domains/a%00b',
    '/bff/api/v1/domains/%E0%A4%A',
    '/bff/api/v1/',
  ])('refuses %s with 404 route_not_found (allow-list, traversal)', async (path) => {
    const upstream = ok();
    const response = await handleProxy(await request(path), testDeps(upstream.fetch, { now }));
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({
      statusCode: 404,
      error: 'NOT_FOUND',
      code: 'route_not_found',
    });
    expect(upstream.calls).toHaveLength(0);
  });

  it('refuses a raw dot segment that URL parsing did not normalize', async () => {
    const upstream = ok();
    const raw = await request('/bff/api/v1/domains');
    const forged = new Proxy(raw, {
      get(target, prop, receiver) {
        if (prop === 'url') return `${PORTAL}/bff/api/v1/domains/%2e./x`;
        const value: unknown = Reflect.get(target, prop, receiver);
        return typeof value === 'function'
          ? (value as (...a: unknown[]) => unknown).bind(target)
          : value;
      },
    });
    const response = await handleProxy(forged, testDeps(upstream.fetch, { now }));
    expect(response.status).toBe(404);
    expect(upstream.calls).toHaveLength(0);
  });

  it('refuses a method the operation does not have', async () => {
    const upstream = ok();
    const response = await handleProxy(
      await request('/bff/api/v1/domains', {
        method: 'PATCH',
        headers: { origin: PORTAL, 'x-csrf-token': baseSession(now).csrf },
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(404);
  });

  it.each([
    ['POST', '/bff/api/v1/auth/login'],
    ['POST', '/bff/api/v1/auth/mfa/verify'],
    ['POST', '/bff/api/v1/auth/refresh'],
    ['POST', '/bff/api/v1/auth/logout'],
    ['POST', '/bff/api/v1/auth/logout-all'],
    ['POST', '/bff/api/v1/platform/overrides'],
    ['DELETE', '/bff/api/v1/platform/overrides/01930000-0000-7000-8000-000000000001'],
  ])('refuses token-bearing %s %s with 403 bff_route_required', async (method, path) => {
    const upstream = ok();
    const response = await handleProxy(
      await request(path, { method, headers: { origin: PORTAL } }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'bff_route_required' });
    expect(upstream.calls).toHaveLength(0);
  });

  it('rebuilds the upstream path from the template with encoded parameters', async () => {
    const upstream = ok();
    await handleProxy(
      await request('/bff/api/v1/domains/abc%20def'),
      testDeps(upstream.fetch, { now }),
    );
    expect(upstream.calls[0]!.url).toBe(`${API}/api/v1/domains/abc%20def`);
  });

  it('sends public operations without Authorization and without a session', async () => {
    const upstream = fakeUpstream(() => json({ service: 'email-gateway-api' }));
    const response = await handleProxy(
      await request('/bff/api/v1/meta', { session: null }),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(200);
    expect(upstream.calls[0]!.headers.get('authorization')).toBeNull();
    const forgot = fakeUpstream(() => new Response(null, { status: 202 }));
    const response2 = await handleProxy(
      await request('/bff/api/v1/auth/password/forgot', {
        method: 'POST',
        session: null,
        headers: { origin: PORTAL, 'content-type': 'application/json' },
        body: '{"email":"a@example.com"}',
      }),
      testDeps(forgot.fetch, { now }),
    );
    expect(response2.status).toBe(202);
    expect(forgot.calls[0]!.headers.get('authorization')).toBeNull();
    expect(forgot.calls[0]!.body).toBe('{"email":"a@example.com"}');
  });

  it('answers 401 without a session and 401 access_token_expired without calling the api', async () => {
    const upstream = ok();
    const none = await handleProxy(
      await request('/bff/api/v1/domains', { session: null }),
      testDeps(upstream.fetch, { now }),
    );
    expect(none.status).toBe(401);
    expect(await none.json()).toMatchObject({ code: 'unauthorized' });
    const expired = await handleProxy(
      await request('/bff/api/v1/domains', { session: baseSession(now, { atExp: now - 1 }) }),
      testDeps(upstream.fetch, { now }),
    );
    expect(expired.status).toBe(401);
    expect(await expired.json()).toMatchObject({ code: 'access_token_expired' });
    expect(upstream.calls).toHaveLength(0);
  });

  it('passes an api 401 through (the proxy never refreshes)', async () => {
    const upstream = fakeUpstream(() =>
      json(
        { statusCode: 401, error: 'UNAUTHORIZED', code: 'unauthorized', message: 'Unauthorized' },
        401,
      ),
    );
    const response = await handleProxy(
      await request('/bff/api/v1/domains'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.status).toBe(401);
    expect(upstream.calls).toHaveLength(1);
  });

  it('uses the override token while an override is active and drops it once expired', async () => {
    const ovr = {
      id: 'ovr-1',
      at: 'override-token',
      exp: now + 60_000,
      organizationId: 'org-b',
      organizationName: 'Beta',
    };
    const upstream = ok();
    await handleProxy(
      await request('/bff/api/v1/domains', { session: baseSession(now, { ovr }) }),
      testDeps(upstream.fetch, { now }),
    );
    expect(upstream.calls[0]!.headers.get('authorization')).toBe('Bearer override-token');
    const expired = await handleProxy(
      await request('/bff/api/v1/domains', {
        session: baseSession(now, { ovr: { ...ovr, exp: now - 1 } }),
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(expired.status).toBe(401);
    expect(await expired.json()).toMatchObject({ code: 'override_expired' });
    const cookies = expired.headers.getSetCookie();
    expect(cookies.some((c) => c.startsWith('eg_session=v1.'))).toBe(true);
  });

  describe('CSRF and origin (P6)', () => {
    const csrf = baseSession(now).csrf;
    const cases: [string, Record<string, string>, number][] = [
      ['same origin + token', { origin: PORTAL, 'x-csrf-token': csrf }, 201],
      [
        'no Origin, Sec-Fetch-Site same-origin + token',
        { 'sec-fetch-site': 'same-origin', 'x-csrf-token': csrf },
        201,
      ],
      ['cross-site Origin', { origin: 'https://evil.example', 'x-csrf-token': csrf }, 403],
      [
        'no Origin, cross-site fetch',
        { 'sec-fetch-site': 'cross-site', 'x-csrf-token': csrf },
        403,
      ],
      ['neither Origin nor Sec-Fetch-Site', { 'x-csrf-token': csrf }, 403],
      ['same origin, missing token', { origin: PORTAL }, 403],
      ['same origin, wrong token', { origin: PORTAL, 'x-csrf-token': 'wrong' }, 403],
    ];
    it.each(cases)('%s → %i', async (_name, headers, status) => {
      const upstream = fakeUpstream(() => json({ id: 'x' }, 201));
      const response = await handleProxy(
        await request('/bff/api/v1/domains', {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...headers },
          body: '{"name":"a.example.test"}',
        }),
        testDeps(upstream.fetch, { now }),
      );
      expect(response.status).toBe(status);
      if (status === 403) expect(await response.json()).toMatchObject({ code: 'csrf_failed' });
    });

    it('a GET needs no CSRF token', async () => {
      const upstream = ok();
      const response = await handleProxy(
        await request('/bff/api/v1/domains'),
        testDeps(upstream.fetch, { now }),
      );
      expect(response.status).toBe(200);
    });
  });

  it('forwards the Idempotency-Key and refuses bodies over 1 MiB', async () => {
    const upstream = fakeUpstream(() => json({}, 202));
    const csrf = baseSession(now).csrf;
    await handleProxy(
      await request('/bff/api/v1/messages/01930000-0000-7000-8000-000000000001/rescan', {
        method: 'POST',
        headers: {
          origin: PORTAL,
          'x-csrf-token': csrf,
          'idempotency-key': 'key-1',
          'content-type': 'application/json',
        },
        body: '{}',
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(upstream.calls[0]!.headers.get('idempotency-key')).toBe('key-1');
    const big = await handleProxy(
      await request('/bff/api/v1/domains', {
        method: 'POST',
        headers: { origin: PORTAL, 'x-csrf-token': csrf },
        body: 'x'.repeat(1024 * 1024 + 1),
      }),
      testDeps(upstream.fetch, { now }),
    );
    expect(big.status).toBe(413);
    expect(await big.json()).toMatchObject({ code: 'payload_too_large' });
  });

  it('maps an upstream timeout to 504 and a connection failure to 502', async () => {
    const timeout = fakeUpstream(() => {
      throw new UpstreamError('timeout');
    });
    const slow = {
      fetch: (_url: string, init: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError')),
          );
        }),
    };
    const r1 = await handleProxy(
      await request('/bff/api/v1/domains'),
      testDeps(slow.fetch, { now, config: testConfig({ PORTAL_API_TIMEOUT_MS: '1000' }) }),
    );
    expect(r1.status).toBe(504);
    expect(await r1.json()).toMatchObject({ code: 'upstream_timeout' });
    void timeout;
    const down = fakeUpstream(() => {
      throw new TypeError('fetch failed');
    });
    const r2 = await handleProxy(
      await request('/bff/api/v1/domains'),
      testDeps(down.fetch, { now }),
    );
    expect(r2.status).toBe(502);
    expect(await r2.json()).toMatchObject({ code: 'upstream_unavailable' });
  });

  it('streams bodies through unchanged (downloads) with the api Content-Disposition', async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('chunk-1,'));
        controller.enqueue(new TextEncoder().encode('chunk-2'));
        controller.close();
      },
    });
    const upstream = fakeUpstream(
      () =>
        new Response(stream, {
          status: 200,
          headers: {
            'content-type': 'message/rfc822',
            'content-disposition': 'attachment; filename="m.eml"',
          },
        }),
    );
    const response = await handleProxy(
      await request('/bff/api/v1/quarantine/downloads/tok_abc'),
      testDeps(upstream.fetch, { now }),
    );
    expect(response.headers.get('content-disposition')).toBe('attachment; filename="m.eml"');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(await response.text()).toBe('chunk-1,chunk-2');
  });
});
