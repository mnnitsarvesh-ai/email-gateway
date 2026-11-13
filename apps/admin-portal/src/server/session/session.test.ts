// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { baseSession, testConfig, TEST_KEY, TEST_PREVIOUS_KEY } from '@/server/test-helpers';
import { MFA_AAD, SESSION_AAD, seal, unseal } from './seal';
import {
  CookieTooLargeError,
  SESSION_COOKIE_MAX_BYTES,
  clearSessionCookies,
  cookieNames,
  readMfaChallenge,
  readSession,
  sealSession,
  serializeCookie,
  sessionCookies,
  sessionFromTokens,
  sessionView,
} from './session';

const now = Date.parse('2026-11-13T10:00:00.000Z');

describe('seal / unseal (AES-256-GCM, design P2)', () => {
  it('round-trips with the format v1.<iv>.<ciphertext>', async () => {
    const sealed = await seal({ hello: 'world' }, TEST_KEY, SESSION_AAD);
    expect(sealed).toMatch(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
    expect(await unseal(sealed, [TEST_KEY], SESSION_AAD)).toEqual({ hello: 'world' });
  });

  it('uses a fresh IV every time', async () => {
    const a = await seal({ x: 1 }, TEST_KEY, SESSION_AAD);
    const b = await seal({ x: 1 }, TEST_KEY, SESSION_AAD);
    expect(a).not.toBe(b);
  });

  it('accepts the previous key during rotation and refuses unknown keys', async () => {
    const sealedWithOld = await seal({ x: 1 }, TEST_PREVIOUS_KEY, SESSION_AAD);
    expect(await unseal(sealedWithOld, [TEST_KEY, TEST_PREVIOUS_KEY], SESSION_AAD)).toEqual({
      x: 1,
    });
    expect(await unseal(sealedWithOld, [TEST_KEY], SESSION_AAD)).toBeNull();
  });

  it('binds the purpose (AAD): an MFA challenge never opens as a session', async () => {
    const sealed = await seal({ x: 1 }, TEST_KEY, MFA_AAD);
    expect(await unseal(sealed, [TEST_KEY], SESSION_AAD)).toBeNull();
  });

  it('treats any tampering as logged out (null), never an exception', async () => {
    const sealed = await seal({ x: 1 }, TEST_KEY, SESSION_AAD);
    const [v, iv, data] = sealed.split('.') as [string, string, string];
    const flipped = data.slice(0, -2) + (data.endsWith('A') ? 'B' : 'A') + data.slice(-1);
    for (const bad of [
      `${v}.${iv}.${flipped}`,
      `v2.${iv}.${data}`,
      `${v}.${iv}`,
      'garbage',
      `${v}.!!.${data}`,
      '',
    ]) {
      expect(await unseal(bad, [TEST_KEY], SESSION_AAD)).toBeNull();
    }
  });
});

describe('session cookies', () => {
  const config = testConfig();

  it('uses eg_* names on http and __Host- names on https', () => {
    expect(cookieNames(false)).toEqual({ session: 'eg_session', mfa: 'eg_mfa', csrf: 'eg_csrf' });
    expect(cookieNames(true)).toEqual({
      session: '__Host-eg_session',
      mfa: '__Host-eg_mfa',
      csrf: '__Host-eg_csrf',
    });
    expect(
      testConfig({
        PORTAL_PUBLIC_URL: 'https://portal.example.test',
        APP_ENV: 'staging',
        PORTAL_TRUST_PROXY_HOPS: '1',
      }).secure,
    ).toBe(true);
  });

  it('sets the attributes of P2: HttpOnly (not on CSRF), Secure, SameSite=Strict, Path=/, Max-Age to rtExp', async () => {
    const session = baseSession(now);
    const [sessionCookie, csrfCookie] = await sessionCookies(session, config, now);
    expect(sessionCookie).toMatch(/^eg_session=v1\./);
    expect(sessionCookie).toContain('; Path=/; Secure; SameSite=Strict; HttpOnly; Max-Age=604800');
    expect(csrfCookie).toBe(
      `eg_csrf=${session.csrf}; Path=/; Secure; SameSite=Strict; Max-Age=604800`,
    );
    expect(serializeCookie('x', 'y', { httpOnly: true, maxAgeSeconds: 0 })).toBe(
      'x=y; Path=/; Secure; SameSite=Strict; HttpOnly; Max-Age=0',
    );
  });

  it('reads a session back from the Cookie header; a tampered cookie reads as none', async () => {
    const session = baseSession(now);
    const [cookie] = await sessionCookies(session, config, now);
    const value = cookie?.split(';')[0] ?? '';
    expect(await readSession(`other=1; ${value}`, config)).toEqual(session);
    expect(await readSession(`${value.slice(0, -3)}xyz`, config)).toBeNull();
    expect(await readSession(null, config)).toBeNull();
  });

  it('opens cookies sealed with PORTAL_SESSION_KEY_PREVIOUS after a key rotation', async () => {
    const old = testConfig({ PORTAL_SESSION_KEY: TEST_PREVIOUS_KEY });
    const rotated = testConfig({
      PORTAL_SESSION_KEY: TEST_KEY,
      PORTAL_SESSION_KEY_PREVIOUS: TEST_PREVIOUS_KEY,
    });
    const [cookie] = await sessionCookies(baseSession(now), old, now);
    expect(await readSession(cookie?.split(';')[0], rotated)).not.toBeNull();
    expect(await readSession(cookie?.split(';')[0], testConfig())).toBeNull();
  });

  it('fits two maximum-size JWTs and a 255-character organization name in the budget', async () => {
    // A maximal HS256 access token of the api: header with kid, issuer and audience up to 64
    // characters, every optional claim (mfa_enroll, ovr), amr pwd+otp ≈ 730 characters.
    const maxJwt = 'e'.repeat(800);
    const session = baseSession(now, {
      at: maxJwt,
      ovr: {
        id: '01930000-0000-7000-8000-0000000000d1',
        at: maxJwt,
        exp: now + 3_600_000,
        organizationId: '01930000-0000-7000-8000-0000000000e1',
        organizationName: 'Ö'.repeat(255),
      },
    });
    const sealed = await sealSession(session, config);
    expect(sealed.length).toBeLessThanOrEqual(SESSION_COOKIE_MAX_BYTES);
  });

  it('refuses (never truncates) a session over the budget', async () => {
    const session = baseSession(now, {
      at: 'e'.repeat(1500),
      ovr: {
        id: 'x',
        at: 'e'.repeat(1500),
        exp: now + 1,
        organizationId: 'y',
        organizationName: 'z',
      },
    });
    await expect(sealSession(session, config)).rejects.toBeInstanceOf(CookieTooLargeError);
  });

  it('clears all three cookies', () => {
    const cleared = clearSessionCookies(config);
    expect(cleared.map((c) => c.split('=')[0])).toEqual(['eg_session', 'eg_csrf', 'eg_mfa']);
    expect(cleared.every((c) => c.endsWith('Max-Age=0'))).toBe(true);
  });

  it('builds a session from a token response and rotates the CSRF token', () => {
    const tokens = {
      accessToken: 'at',
      expiresIn: 600,
      refreshToken: 'rt',
      refreshTokenExpiresAt: '2026-11-20T10:00:00.000Z',
      sessionId: 'sid',
      mfaEnrollmentRequired: true,
    };
    const a = sessionFromTokens(tokens, now);
    const b = sessionFromTokens(tokens, now);
    expect(a).toMatchObject({
      at: 'at',
      atExp: now + 600_000,
      rt: 'rt',
      mfaEnroll: true,
      rtExp: Date.parse('2026-11-20T10:00:00.000Z'),
    });
    expect(a.csrf).not.toBe(b.csrf);
  });

  it('exposes a token-free view', () => {
    const view = sessionView(baseSession(now), now);
    expect(JSON.stringify(view)).not.toContain('access-token-current');
    expect(JSON.stringify(view)).not.toContain('egr_');
    expect(view).toMatchObject({
      authenticated: true,
      mfaEnrollmentRequired: false,
      override: null,
    });
    expect(sessionView(null, now).authenticated).toBe(false);
  });

  it('expires MFA challenges', async () => {
    const { mfaChallengeCookie } = await import('./session');
    const cookie = await mfaChallengeCookie(
      { v: 1, mfaToken: 'egt_x', exp: now + 300_000 },
      config,
      now,
    );
    expect(cookie).toContain('Max-Age=300');
    const header = cookie.split(';')[0];
    expect(await readMfaChallenge(header, config, now)).toMatchObject({ mfaToken: 'egt_x' });
    expect(await readMfaChallenge(header, config, now + 301_000)).toBeNull();
  });
});
