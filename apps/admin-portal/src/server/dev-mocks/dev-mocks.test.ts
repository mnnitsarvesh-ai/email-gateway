// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { FEATURE_FIXTURES, createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { DEV_MOCK_MARKER } from '@/server/dev-mocks/types';
import { SeededRandom, paginate } from './generator';

const API = 'http://api.test:3000';
const call = (
  fetchImpl: ReturnType<typeof createMockFetch>,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
) =>
  fetchImpl(`${API}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });

describe('dev fixture layer (design P9)', () => {
  it('registers a typed (empty) stub for every wave-2 feature', async () => {
    expect(Object.keys(FEATURE_FIXTURES).sort()).toEqual(
      [
        'session',
        'dashboard',
        'reports',
        'billing',
        'audit',
        'organizations',
        'settings',
        'threat-intel',
        'url-protection',
        'attachments',
        'domains',
        'mail-servers',
        'users',
        'roles',
        'integrations',
        'messages',
        'quarantine',
        'policies',
      ].sort(),
    );
    for (const name of Object.keys(FEATURE_FIXTURES)) {
      const fixtureModule = (await import(`./fixtures/${name}.ts`)) as { DEV_MOCK_MARKER: string };
      expect(fixtureModule.DEV_MOCK_MARKER).toBe(DEV_MOCK_MARKER);
    }
  });

  it('answers 501 mock_not_implemented for operations without a fixture, 404 for unknown routes', async () => {
    const fetchImpl = createMockFetch({});
    const missing = await call(fetchImpl, 'GET', '/api/v1/domains');
    expect(missing.status).toBe(501);
    expect(await missing.json()).toMatchObject({ code: 'mock_not_implemented' });
    expect((await call(fetchImpl, 'GET', '/api/v1/nope')).status).toBe(404);
  });

  it('signs in by role hint, serves me with that role, rotates refresh tokens', async () => {
    const fetchImpl = createMockFetch(mergedFixtures());
    const loginResponse = await call(fetchImpl, 'POST', '/api/v1/auth/login', {
      email: 'read_only_user@example.com',
      password: 'any',
    });
    const tokens = (await loginResponse.json()) as { accessToken: string; refreshToken: string };
    expect(tokens.accessToken).not.toMatch(/^eyJ/);
    const me = (await (
      await call(fetchImpl, 'GET', '/api/v1/auth/me', undefined, tokens.accessToken)
    ).json()) as { roles: string[]; permissions: string[] };
    expect(me.roles).toEqual(['read_only_user']);
    expect(me.permissions).toContain('report:read');
    expect(me.permissions).not.toContain('user:manage');
    const refreshed = await call(fetchImpl, 'POST', '/api/v1/auth/refresh', {
      refreshToken: tokens.refreshToken,
    });
    expect(refreshed.status).toBe(200);
    expect(
      (await call(fetchImpl, 'POST', '/api/v1/auth/refresh', { refreshToken: tokens.refreshToken }))
        .status,
    ).toBe(401);
    expect(
      (
        await call(fetchImpl, 'POST', '/api/v1/auth/login', {
          email: 'nobody@elsewhere.test',
          password: 'x',
        })
      ).status,
    ).toBe(401);
  });

  it('challenges the MFA user and accepts a 6-digit code', async () => {
    const fetchImpl = createMockFetch(mergedFixtures());
    const challenge = (await (
      await call(fetchImpl, 'POST', '/api/v1/auth/login', {
        email: 'mfa.platform_admin@example.com',
        password: 'x',
      })
    ).json()) as { mfaRequired: boolean; mfaToken: string };
    expect(challenge.mfaRequired).toBe(true);
    const verified = await call(fetchImpl, 'POST', '/api/v1/auth/mfa/verify', {
      mfaToken: challenge.mfaToken,
      code: '000000',
    });
    expect(verified.status).toBe(200);
  });

  it('flags enrollment for the enroll.* hint', async () => {
    const fetchImpl = createMockFetch(mergedFixtures());
    const body = (await (
      await call(fetchImpl, 'POST', '/api/v1/auth/login', {
        email: 'enroll.organization_admin@example.com',
        password: 'x',
      })
    ).json()) as { mfaEnrollmentRequired: boolean };
    expect(body.mfaEnrollmentRequired).toBe(true);
  });

  it('generates deterministic synthetic data and paginates without totals', () => {
    expect(new SeededRandom('a').uuid()).toBe(new SeededRandom('a').uuid());
    const page1 = paginate(
      Array.from({ length: 30 }, (_, i) => i),
      new URLSearchParams('limit=25'),
    );
    expect(page1).toMatchObject({ nextCursor: expect.any(String) as unknown });
    const page2 = paginate(
      Array.from({ length: 30 }, (_, i) => i),
      new URLSearchParams(`limit=25&cursor=${String(page1.nextCursor)}`),
      'items',
    );
    expect(page2).toEqual({ items: [25, 26, 27, 28, 29], nextCursor: null });
  });
});
