import 'server-only';
import { vi } from 'vitest';
import { loadServerConfig, type ServerConfig } from '@/server/config';
import type { PortalLogger } from '@/server/log';
import { sessionCookies, type PortalSession } from '@/server/session/session';
import type { BffDeps, UpstreamFetch } from '@/server/upstream';

/** Test-only key material (random per run; never real secrets). */
export const TEST_KEY = 'a'.repeat(64);
export const TEST_PREVIOUS_KEY = 'b'.repeat(64);
export const TEST_FORWARDER_TOKEN = 'forwarder-token-for-tests-only-0123456789';
export const PORTAL = 'http://localhost:3001';
export const API = 'http://api.test:3000';

export function testConfig(overrides: Record<string, string | undefined> = {}): ServerConfig {
  return loadServerConfig({
    NODE_ENV: 'test',
    APP_ENV: 'local',
    API_INTERNAL_URL: API,
    PORTAL_PUBLIC_URL: PORTAL,
    PORTAL_SESSION_KEY: TEST_KEY,
    API_TRUSTED_FORWARDER_TOKEN: TEST_FORWARDER_TOKEN,
    PORTAL_API_TIMEOUT_MS: '1000',
    ...overrides,
  });
}

export interface RecordedCall {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}

export function silentLogger(): PortalLogger & { calls: unknown[][] } {
  const calls: unknown[][] = [];
  return {
    calls,
    info: (...args) => void calls.push(['info', ...args]),
    warn: (...args) => void calls.push(['warn', ...args]),
    error: (...args) => void calls.push(['error', ...args]),
  };
}

/** A fake upstream: records calls and answers with the handler's Response. */
export function fakeUpstream(handler: (call: RecordedCall) => Response | Promise<Response>) {
  const calls: RecordedCall[] = [];
  const fetchImpl: UpstreamFetch = vi.fn(async (url: string, init: RequestInit) => {
    const body =
      init.body === null || init.body === undefined
        ? null
        : typeof init.body === 'string'
          ? init.body
          : new TextDecoder().decode(init.body as Uint8Array);
    const call = { url, method: init.method ?? 'GET', headers: new Headers(init.headers), body };
    calls.push(call);
    return handler(call);
  });
  return { fetch: fetchImpl, calls };
}

export function testDeps(
  fetchImpl: UpstreamFetch,
  options: { config?: ServerConfig; now?: number } = {},
): BffDeps & { logger: ReturnType<typeof silentLogger> } {
  const now = options.now ?? Date.parse('2026-11-13T10:00:00.000Z');
  return {
    config: options.config ?? testConfig(),
    fetch: fetchImpl,
    logger: silentLogger(),
    now: () => now,
    devMocks: false,
  };
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'x-request-id': 'req-up-1', ...headers },
  });
}

export function tokenResponse(overrides: Record<string, unknown> = {}) {
  return {
    accessToken: 'header.payload-access.sig',
    tokenType: 'Bearer',
    expiresIn: 600,
    refreshToken: 'egr_refresh_token_value_0000000000000000000000',
    refreshTokenExpiresAt: '2026-11-20T10:00:00.000Z',
    sessionId: '01930000-0000-7000-8000-0000000000a1',
    mfaEnrollmentRequired: false,
    user: { id: '01930000-0000-7000-8000-0000000000b1', email: 'a@example.com', displayName: 'A' },
    organization: {
      id: '01930000-0000-7000-8000-0000000000c1',
      slug: 'alpha',
      name: 'Alpha',
      kind: 'customer',
    },
    ...overrides,
  };
}

export function baseSession(now: number, overrides: Partial<PortalSession> = {}): PortalSession {
  return {
    v: 1,
    at: 'access-token-current',
    atExp: now + 600_000,
    rt: 'egr_refresh_current',
    rtExp: now + 7 * 86_400_000,
    sid: '01930000-0000-7000-8000-0000000000a1',
    csrf: 'csrf-token-value-0123456789abcdef',
    mfaEnroll: false,
    ...overrides,
  };
}

/** `Cookie` header for a sealed session (plus the CSRF cookie). */
export async function cookieHeader(
  session: PortalSession,
  config: ServerConfig,
  now: number,
): Promise<string> {
  const cookies = await sessionCookies(session, config, now);
  return cookies.map((c) => c.split(';')[0]).join('; ');
}

export function setCookies(response: Response): string[] {
  return response.headers.getSetCookie();
}
