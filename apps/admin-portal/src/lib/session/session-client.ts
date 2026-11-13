import { readCsrfToken } from '@/lib/api/csrf';
import { ApiError, networkError, toApiError } from '@/lib/api/errors';

/** `GET /bff/session` (no tokens; from the cookie only). */
export interface SessionState {
  authenticated: boolean;
  accessExpiresAt: string | null;
  refreshExpiresAt: string | null;
  mfaEnrollmentRequired: boolean;
  override: {
    id: string;
    organizationId: string;
    organizationName: string;
    expiresAt: string;
  } | null;
  /** Dev fixture mode is on (badge in the top bar, design P9). */
  devFixtures: boolean;
}

export type LoginResult =
  { status: 'authenticated'; mfaEnrollmentRequired: boolean } | { status: 'mfa_required' };

function origin(): string {
  return typeof window === 'undefined' ? 'http://localhost' : window.location.origin;
}

/**
 * Calls a BFF session route (`/bff/session/*`). Mutations carry the CSRF double-submit header.
 * Errors are thrown as ApiError (same envelope as the api).
 */
export async function bffSessionCall<T>(
  path: string,
  init: { method?: 'GET' | 'POST' | 'DELETE'; body?: unknown } = {},
): Promise<T> {
  const method = init.method ?? 'GET';
  const headers = new Headers({ accept: 'application/json' });
  if (method !== 'GET') {
    const csrf = readCsrfToken();
    if (csrf) headers.set('x-csrf-token', csrf);
  }
  if (init.body !== undefined) headers.set('content-type', 'application/json');
  let response: Response;
  try {
    response = await globalThis.fetch(`${origin()}${path}`, {
      method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch (error) {
    throw networkError(error);
  }
  const text = await response.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      body = null;
    }
  }
  if (!response.ok) throw toApiError(response, body);
  return body as T;
}

export function getSessionState(): Promise<SessionState> {
  return bffSessionCall<SessionState>('/bff/session');
}

export function login(body: {
  email: string;
  password: string;
  organization?: string;
}): Promise<LoginResult> {
  return bffSessionCall<LoginResult>('/bff/session/login', { method: 'POST', body });
}

export function verifyMfa(body: { code: string } | { recoveryCode: string }): Promise<LoginResult> {
  return bffSessionCall<LoginResult>('/bff/session/mfa', { method: 'POST', body });
}

/** Web Lock shared by every refresh and sign-out of this origin (design P4). */
export const REFRESH_LOCK = 'eg-session-refresh';

interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

export function sessionLocks(): LockManagerLike | null {
  if (typeof navigator === 'undefined') return null;
  const locks = (navigator as Navigator & { locks?: LockManagerLike }).locks;
  return locks && typeof locks.request === 'function' ? locks : null;
}

/**
 * Runs `fn` under the refresh lock, so a sign-out never overlaps a refresh in any tab: a
 * refresh that completed after the logout would set the session cookie again (found by the
 * step 7.1 e2e suite with a 60 s access-token TTL).
 */
export function withSessionLock<T>(fn: () => Promise<T>): Promise<T> {
  const locks = sessionLocks();
  return locks ? locks.request(REFRESH_LOCK, fn) : fn();
}

/**
 * Signs out. The BFF refreshes an expired access token first, so the api session really ends; it
 * clears the cookies in every case and throws `502 logout_incomplete` when the api session could
 * not be ended.
 */
export async function logout(): Promise<void> {
  await withSessionLock(() => bffSessionCall<null>('/bff/session/logout', { method: 'POST' }));
}

/** Ends every session of the user; the BFF refreshes an expired access token first. */
export async function logoutAll(): Promise<void> {
  await withSessionLock(() => bffSessionCall<null>('/bff/session/logout-all', { method: 'POST' }));
}

export interface OverrideStarted {
  id: string;
  organizationId: string;
  organizationName: string;
  expiresAt: string;
}

/**
 * Starting and ending an override rewrite the session cookie and may refresh the access token
 * server-side (single-use refresh token), so they run under the session lock like a refresh.
 */
export function startOverride(body: {
  organizationId: string;
  reason: string;
  durationMinutes: number;
}): Promise<OverrideStarted> {
  return withSessionLock(() =>
    bffSessionCall<OverrideStarted>('/bff/session/override', { method: 'POST', body }),
  );
}

export async function endOverride(): Promise<void> {
  await withSessionLock(() => bffSessionCall<null>('/bff/session/override', { method: 'DELETE' }));
}

export { ApiError };
