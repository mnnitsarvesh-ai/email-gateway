/**
 * A minimal api client of the seeder: signs a seeded user in through `POST /auth/login` (as any
 * client would) and calls the api with the bearer token. Writes through the api produce exactly
 * the rows, audit entries and outbox events the product writes. Tokens stay in memory only.
 */
import { randomUUID } from 'node:crypto';
import { apiOrigin } from '../support/env';

export interface ApiResult<T = Record<string, unknown>> {
  status: number;
  body: T;
}

export interface ApiSession {
  call<T = Record<string, unknown>>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    path: string,
    body?: unknown,
    options?: { idempotent?: boolean; expect?: number },
  ): Promise<ApiResult<T>>;
  logout(): Promise<void>;
}

export async function apiSession(
  email: string,
  password: string,
  mfa?: { code: string },
): Promise<ApiSession> {
  const base = apiOrigin();
  const login = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!login.ok) throw new Error(`seed login failed: ${login.status}`);
  let { accessToken, mfaToken } = (await login.json()) as {
    accessToken?: string;
    mfaToken?: string;
  };
  // Step 8.1: MFA routes (archive settings) need a session signed in with MFA.
  if (!accessToken && mfaToken && mfa) {
    const verified = await fetch(`${base}/api/v1/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mfaToken, code: mfa.code }),
    });
    if (!verified.ok) throw new Error(`seed MFA verification failed: ${verified.status}`);
    ({ accessToken } = (await verified.json()) as { accessToken: string });
    mfaToken = undefined;
  }
  if (!accessToken) throw new Error('seed login returned no access token');
  const headers = (extra: Record<string, string> = {}) => ({
    accept: 'application/json',
    authorization: `Bearer ${accessToken}`,
    ...extra,
  });
  return {
    async call<T>(
      method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
      path: string,
      body?: unknown,
      options: { idempotent?: boolean; expect?: number } = {},
    ): Promise<ApiResult<T>> {
      const res = await fetch(`${base}/api/v1${path}`, {
        method,
        headers: headers({
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          ...(options.idempotent ? { 'idempotency-key': randomUUID() } : {}),
        }),
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await res.text();
      const parsed = (text ? JSON.parse(text) : null) as T;
      if (options.expect !== undefined && res.status !== options.expect) {
        // The body of an api error carries codes and paths only (never credentials).
        throw new Error(
          `seed ${method} ${path}: expected ${options.expect}, got ${res.status} ${text}`,
        );
      }
      return { status: res.status, body: parsed };
    },
    async logout() {
      await fetch(`${base}/api/v1/auth/logout`, {
        method: 'POST',
        headers: headers({ 'content-type': 'application/json' }),
        body: '{}',
      }).catch(() => undefined);
    },
  };
}
