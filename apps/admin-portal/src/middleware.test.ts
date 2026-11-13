// @vitest-environment node
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetServerConfigForTests } from '@/server/config';
import { buildCsp, isPublicPath, loginRedirectPath } from '@/server/security-headers';
import {
  PORTAL,
  TEST_FORWARDER_TOKEN,
  TEST_KEY,
  baseSession,
  cookieHeader,
  testConfig,
} from '@/server/test-helpers';
import { middleware } from './middleware';

const env = {
  APP_ENV: 'local',
  API_INTERNAL_URL: 'http://api.test:3000',
  PORTAL_PUBLIC_URL: PORTAL,
  PORTAL_SESSION_KEY: TEST_KEY,
  API_TRUSTED_FORWARDER_TOKEN: TEST_FORWARDER_TOKEN,
};

beforeEach(() => {
  for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
  resetServerConfigForTests();
});
afterEach(() => {
  vi.unstubAllEnvs();
  resetServerConfigForTests();
});

const req = (path: string, init: { method?: string; headers?: Record<string, string> } = {}) =>
  new NextRequest(new URL(path, PORTAL), { method: init.method ?? 'GET', headers: init.headers });

describe('middleware (design P1, P6, P10)', () => {
  it('redirects console routes without a session to /login?next=', async () => {
    const response = await middleware(req('/domains?status=active'));
    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toBe(
      `${PORTAL}/login?next=%2Fdomains%3Fstatus%3Dactive`,
    );
    const root = await middleware(req('/'));
    expect(root.headers.get('location')).toBe(`${PORTAL}/login`);
  });

  it('redirects with an unreadable (tampered) cookie', async () => {
    const response = await middleware(
      req('/dashboard', { headers: { cookie: 'eg_session=v1.AAAA.BBBB' } }),
    );
    expect(response.status).toBe(307);
  });

  it('lets a valid session through with a CSP nonce on request and response', async () => {
    const now = Date.now();
    const cookie = await cookieHeader(baseSession(now), testConfig(), now);
    const response = await middleware(req('/dashboard', { headers: { cookie } }));
    expect(response.status).toBe(200);
    const csp = response.headers.get('content-security-policy') ?? '';
    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(response.headers.get('x-middleware-request-x-nonce')).toBe(nonce);
    expect(response.headers.get('x-middleware-request-content-security-policy')).toBe(csp);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-eval');
  });

  it('serves public pages without a session, each with a fresh nonce', async () => {
    const a = await middleware(req('/login'));
    const b = await middleware(req('/login'));
    expect(a.status).toBe(200);
    expect(a.headers.get('content-security-policy')).not.toBe(
      b.headers.get('content-security-policy'),
    );
    for (const path of [
      '/login/mfa',
      '/forgot-password',
      '/auth/reset-password',
      '/auth/accept-invitation',
      '/auth/verify-email',
    ]) {
      expect((await middleware(req(path))).status).toBe(200);
    }
    expect((await middleware(req('/mfa/enroll'))).status).toBe(307);
  });

  it('refuses cross-site state-changing /bff requests and allows same-origin ones', async () => {
    const cross = await middleware(
      req('/bff/session/login', { method: 'POST', headers: { origin: 'https://evil.example' } }),
    );
    expect(cross.status).toBe(403);
    expect(await cross.json()).toMatchObject({ code: 'csrf_failed' });
    const same = await middleware(
      req('/bff/session/login', { method: 'POST', headers: { origin: PORTAL } }),
    );
    expect(same.status).toBe(200);
    const get = await middleware(req('/bff/session'));
    expect(get.status).toBe(200);
  });

  it('adds HSTS only for an https public origin', async () => {
    expect((await middleware(req('/login'))).headers.get('strict-transport-security')).toBeNull();
    vi.stubEnv('PORTAL_PUBLIC_URL', 'https://portal.example.test');
    vi.stubEnv('APP_ENV', 'staging');
    vi.stubEnv('PORTAL_TRUST_PROXY_HOPS', '1');
    resetServerConfigForTests();
    const response = await middleware(new NextRequest('https://portal.example.test/login'));
    expect(response.headers.get('strict-transport-security')).toBe(
      'max-age=63072000; includeSubDomains',
    );
    expect(response.headers.get('content-security-policy')).toContain('upgrade-insecure-requests');
  });
});

describe('security header helpers', () => {
  it('builds the P10 CSP with development additions only in development', () => {
    const prod = buildCsp('n0', { development: false, secure: false });
    expect(prod).toBe(
      "default-src 'self'; script-src 'self' 'nonce-n0' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'; manifest-src 'self'",
    );
    const dev = buildCsp('n0', { development: true, secure: false });
    expect(dev).toContain("'unsafe-eval'");
    expect(dev).toContain("connect-src 'self' ws:");
  });

  it('classifies public paths and builds safe redirects', () => {
    expect(isPublicPath('/login')).toBe(true);
    expect(isPublicPath('/loginx')).toBe(false);
    expect(isPublicPath('/auth/reset-password')).toBe(true);
    expect(isPublicPath('/dashboard')).toBe(false);
    expect(loginRedirectPath('//evil.example')).toBe('/login');
    expect(loginRedirectPath('/users/1')).toBe('/login?next=%2Fusers%2F1');
  });
});
