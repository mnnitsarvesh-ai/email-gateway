/**
 * HTTP helpers for the API integration suites (WP3, reused by WP4/WP5). The harness trusts one
 * proxy hop, so `X-Forwarded-For: uniqueIp()` gives every test its own client address and the
 * per-IP rate limits and failure counters of one test never affect another. Set it on every
 * request to a rate-limited route, including authenticated ones (password change, MFA
 * enrollment): the counters live in the real Redis and outlast a test run.
 */
import { randomInt, randomUUID } from 'node:crypto';
import type { Test } from 'supertest';
import type { IntegrationApp } from './app';
import type { Fixtures, FixtureUser } from './fixtures';

let counter = 0;

/** A fresh private client address per call (`10.x.y.z`). */
export function uniqueIp(): string {
  counter += 1;
  const n = (randomInt(0, 2 ** 16) << 8) + (counter % 256);
  return `10.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`;
}

export const bearer = (accessToken: string): Record<string, string> => ({
  Authorization: `Bearer ${accessToken}`,
});

export const apiKeyHeader = (key: string): Record<string, string> => ({ 'X-API-Key': key });

export const fromIp = (ip: string): Record<string, string> => ({ 'X-Forwarded-For': ip });

/**
 * A fresh `Idempotency-Key` (step 6.1 §3.5): the legacy sensitive mutations (DKIM rotation,
 * invitations, MFA reset, organization status and deletion, policy and risk profile publish /
 * activate / reset, BEC/DLP purges, the Aadhaar switch and the platform operations) refuse a
 * request without one under `API_IDEMPOTENCY_LEGACY_MODE=enforce`. Pass a fixed `key` to replay.
 */
export const idem = (key: string = `it-${randomUUID()}`): Record<string, string> => ({
  'Idempotency-Key': key,
});

export interface LoginBody {
  email: string;
  password: string;
  organization?: string;
}

/** `POST /api/v1/auth/login` from the given client IP. */
export function login(ctx: IntegrationApp, body: LoginBody, ip: string = uniqueIp()): Test {
  return ctx.http.post('/api/v1/auth/login').set(fromIp(ip)).send(body);
}

export interface TokenResponseBody {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  expiresIn: number;
  mfaEnrollmentRequired: boolean;
  refreshTokenExpiresAt: string;
  user: { id: string; email: string; displayName: string };
  organization: { id: string; slug: string; name: string; kind: string };
}

/** Logs a user in (password, then TOTP when enabled) and returns the token response. */
export async function loginWithMfa(
  ctx: IntegrationApp,
  fixtures: Fixtures,
  user: FixtureUser,
  ip: string = uniqueIp(),
): Promise<TokenResponseBody> {
  const first = await login(
    ctx,
    { email: user.email, password: user.password, organization: user.organization.slug },
    ip,
  );
  if (first.status !== 200) throw new Error(`login failed with ${first.status}`);
  if (!first.body.mfaRequired) return first.body as TokenResponseBody;
  const second = await ctx.http
    .post('/api/v1/auth/mfa/verify')
    .set(fromIp(ip))
    .send({ mfaToken: first.body.mfaToken, code: await fixtures.totpNow(user) });
  if (second.status !== 200) throw new Error(`MFA verification failed with ${second.status}`);
  return second.body as TokenResponseBody;
}
