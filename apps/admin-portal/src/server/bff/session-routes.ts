import 'server-only';
import { z } from 'zod';
import { fetchPlatformHealth } from '@/lib/platform-health';
import { clientIpFromHeaders } from '@/server/client-ip';
import { hasValidCsrfToken, isSameOriginRequest } from '@/server/csrf';
import {
  BFF_RESPONSE_HEADERS,
  emptyResponse,
  jsonResponse,
  portalError,
  readJsonBody,
} from '@/server/http';
import {
  CookieTooLargeError,
  MFA_CHALLENGE_MAX_SECONDS,
  clearMfaCookie,
  clearSessionCookies,
  isTokenResponse,
  mfaChallengeCookie,
  readMfaChallenge,
  readSession,
  sessionCookies,
  sessionFromTokens,
  sessionView,
  type PortalSession,
} from '@/server/session/session';
import {
  UpstreamError,
  callUpstreamJson,
  correlationIdFrom,
  type BffDeps,
  type JsonResult,
} from '@/server/upstream';

/**
 * BFF session routes (design P3). Every response is `no-store`; tokens never leave the server.
 * Errors from the api pass through as its envelope; portal-coded errors use the same shape.
 */

const SESSION_BODY_LIMIT = 16 * 1024;
/** Refresh short-circuit: another tab refreshed recently (P3). */
export const FRESH_ENOUGH_MS = 60_000;

const PASS_HEADERS = [
  'retry-after',
  'x-request-id',
  'x-correlation-id',
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
];

const loginBody = z
  .object({
    email: z.string().min(1).max(320),
    password: z.string().min(1).max(1024),
    organization: z
      .string()
      .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/)
      .optional(),
  })
  .strict();

const mfaBody = z.union([
  z.object({ code: z.string().regex(/^\d{6}$/) }).strict(),
  z.object({ recoveryCode: z.string().min(10).max(32) }).strict(),
]);

const refreshBody = z.object({ force: z.boolean().optional() }).strict();

const overrideBody = z
  .object({
    organizationId: z.uuid(),
    reason: z.string().trim().min(10).max(500),
    durationMinutes: z.number().int().min(5).max(240).optional(),
  })
  .strict();

const overrideResponse = z.object({
  overrideId: z.string().min(1),
  accessToken: z.string().min(1),
  expiresAt: z.string().min(1),
  organization: z.object({ id: z.string(), name: z.string() }),
});

const mfaChallengeResponse = z.object({
  mfaRequired: z.literal(true),
  mfaToken: z.string().min(1),
  expiresIn: z.number().int().positive(),
});

const meResponse = z.object({ permissions: z.array(z.string()) });
const organizationResponse = z.object({ id: z.string(), name: z.string() });

function validationError(issues: z.core.$ZodIssue[]): Response {
  const body = {
    statusCode: 400,
    error: 'BAD_REQUEST',
    code: 'validation_failed',
    message: issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`),
  };
  return new Response(JSON.stringify(body), {
    status: 400,
    headers: { ...BFF_RESPONSE_HEADERS, 'content-type': 'application/json' },
  });
}

/** Re-emits an api error (status, envelope and the useful headers). */
function passThrough(result: JsonResult, extraCookies: readonly string[] = []): Response {
  const headers = new Headers({ ...BFF_RESPONSE_HEADERS, 'content-type': 'application/json' });
  for (const name of PASS_HEADERS) {
    const value = result.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  for (const cookie of extraCookies) headers.append('set-cookie', cookie);
  const body = result.body ?? {
    statusCode: result.status,
    error: 'ERROR',
    code: 'upstream_error',
    message: 'Request failed',
  };
  return new Response(JSON.stringify(body), { status: result.status, headers });
}

function upstreamFailure(error: unknown): Response {
  if (error instanceof UpstreamError && error.kind === 'timeout') {
    return portalError(504, 'upstream_timeout', 'The API did not answer in time');
  }
  return portalError(502, 'upstream_unavailable', 'The API is unavailable');
}

function forwardedHeaders(request: Request): Headers {
  const headers = new Headers();
  const agent = request.headers.get('user-agent');
  if (agent) headers.set('user-agent', agent);
  return headers;
}

function upstreamContext(request: Request, deps: BffDeps) {
  return {
    headers: forwardedHeaders(request),
    clientIp: clientIpFromHeaders(request.headers, deps.config.PORTAL_TRUST_PROXY_HOPS),
    correlationId: correlationIdFrom(request.headers),
  };
}

function originGuard(request: Request, deps: BffDeps): Response | null {
  return isSameOriginRequest(request.method, request.headers, deps.config)
    ? null
    : portalError(403, 'csrf_failed', 'Cross-site request refused');
}

type SessionCheck = { ok: true; session: PortalSession } | { ok: false; response: Response };

/** Session-bearing mutation: Origin, then session, then the double-submit token (P6). */
async function requireSessionMutation(request: Request, deps: BffDeps): Promise<SessionCheck> {
  const refused = originGuard(request, deps);
  if (refused) return { ok: false, response: refused };
  const session = await readSession(request.headers.get('cookie'), deps.config);
  if (!session || session.rtExp <= deps.now()) {
    return {
      ok: false,
      response: withCookies(
        portalError(401, 'session_expired', 'Not signed in'),
        clearSessionCookies(deps.config),
      ),
    };
  }
  if (!hasValidCsrfToken(request.headers, session.csrf)) {
    return {
      ok: false,
      response: portalError(403, 'csrf_failed', 'Missing or invalid CSRF token'),
    };
  }
  return { ok: true, session };
}

function withCookies(response: Response, cookies: readonly string[]): Response {
  response.headers.delete('set-cookie');
  for (const cookie of cookies) response.headers.append('set-cookie', cookie);
  return response;
}

async function establishSession(
  tokens: unknown,
  deps: BffDeps,
  previous: PortalSession | null,
): Promise<{ session: PortalSession; cookies: string[] } | Response> {
  if (!isTokenResponse(tokens)) {
    deps.logger.error('api returned an unexpected token response');
    return portalError(502, 'upstream_invalid_response', 'Unexpected response from the API');
  }
  const session = sessionFromTokens(tokens, deps.now(), previous);
  try {
    return { session, cookies: await sessionCookies(session, deps.config, deps.now()) };
  } catch (error) {
    if (error instanceof CookieTooLargeError) {
      deps.logger.error('session cookie over budget', { bytes: error.bytes });
      return portalError(502, 'session_cookie_too_large', 'The session does not fit in a cookie');
    }
    throw error;
  }
}

export async function login(request: Request, deps: BffDeps): Promise<Response> {
  const refused = originGuard(request, deps);
  if (refused) return refused;
  const read = await readJsonBody(request, SESSION_BODY_LIMIT);
  if (!read.ok) return read.response;
  const parsed = loginBody.safeParse(read.value);
  if (!parsed.success) return validationError(parsed.error.issues);

  let result: JsonResult;
  try {
    result = await callUpstreamJson(deps, {
      method: 'POST',
      path: '/api/v1/auth/login',
      json: parsed.data,
      ...upstreamContext(request, deps),
    });
  } catch (error) {
    return upstreamFailure(error);
  }
  if (result.status !== 200) return passThrough(result);

  const challenge = mfaChallengeResponse.safeParse(result.body);
  if (challenge.success) {
    const seconds = Math.min(challenge.data.expiresIn, MFA_CHALLENGE_MAX_SECONDS);
    const cookie = await mfaChallengeCookie(
      { v: 1, mfaToken: challenge.data.mfaToken, exp: deps.now() + seconds * 1000 },
      deps.config,
      deps.now(),
    );
    return jsonResponse({ status: 'mfa_required' }, 200, [
      cookie,
      ...clearSessionCookies(deps.config).slice(0, 2),
    ]);
  }
  const established = await establishSession(result.body, deps, null);
  if (established instanceof Response) return established;
  return jsonResponse(
    { status: 'authenticated', mfaEnrollmentRequired: established.session.mfaEnroll },
    200,
    [...established.cookies, clearMfaCookie(deps.config)],
  );
}

export async function verifyMfa(request: Request, deps: BffDeps): Promise<Response> {
  const refused = originGuard(request, deps);
  if (refused) return refused;
  const read = await readJsonBody(request, SESSION_BODY_LIMIT);
  if (!read.ok) return read.response;
  const parsed = mfaBody.safeParse(read.value);
  if (!parsed.success) return validationError(parsed.error.issues);
  const challenge = await readMfaChallenge(request.headers.get('cookie'), deps.config, deps.now());
  if (!challenge) {
    return portalError(
      401,
      'mfa_challenge_expired',
      'The sign-in challenge expired; sign in again',
      {
        'set-cookie': clearMfaCookie(deps.config),
      },
    );
  }
  let result: JsonResult;
  try {
    result = await callUpstreamJson(deps, {
      method: 'POST',
      path: '/api/v1/auth/mfa/verify',
      json: { mfaToken: challenge.mfaToken, ...parsed.data },
      ...upstreamContext(request, deps),
    });
  } catch (error) {
    return upstreamFailure(error);
  }
  if (result.status !== 200) return passThrough(result);
  const established = await establishSession(result.body, deps, null);
  if (established instanceof Response) return established;
  return jsonResponse(
    { status: 'authenticated', mfaEnrollmentRequired: established.session.mfaEnroll },
    200,
    [...established.cookies, clearMfaCookie(deps.config)],
  );
}

export async function refresh(request: Request, deps: BffDeps): Promise<Response> {
  const check = await requireSessionMutation(request, deps);
  if (!check.ok) return check.response;
  const read = await readJsonBody(request, SESSION_BODY_LIMIT);
  if (!read.ok) return read.response;
  const parsed = refreshBody.safeParse(read.value ?? {});
  if (!parsed.success) return validationError(parsed.error.issues);
  const { session } = check;
  const now = deps.now();
  if (!parsed.data.force && session.atExp - now > FRESH_ENOUGH_MS) {
    return jsonResponse({ ...sessionView(session, now), devFixtures: deps.devMocks });
  }
  let result: JsonResult;
  try {
    result = await callUpstreamJson(deps, {
      method: 'POST',
      path: '/api/v1/auth/refresh',
      json: { refreshToken: session.rt },
      ...upstreamContext(request, deps),
    });
  } catch (error) {
    return upstreamFailure(error);
  }
  if (result.status === 400 || result.status === 401) {
    return withCookies(
      portalError(401, 'session_expired', 'The session ended; sign in again'),
      clearSessionCookies(deps.config),
    );
  }
  if (result.status !== 200) return passThrough(result);
  const established = await establishSession(result.body, deps, session);
  if (established instanceof Response) return established;
  return jsonResponse(
    { ...sessionView(established.session, deps.now()), devFixtures: deps.devMocks },
    200,
    established.cookies,
  );
}

export async function getSession(request: Request, deps: BffDeps): Promise<Response> {
  const session = await readSession(request.headers.get('cookie'), deps.config);
  return jsonResponse({ ...sessionView(session, deps.now()), devFixtures: deps.devMocks });
}

/** A session mutation refreshes an access token this close to its expiry first (P4). */
export const ACCESS_REFRESH_MARGIN_MS = 5_000;

type FreshAccess =
  | { ok: true; session: PortalSession; cookies: string[] | null }
  | { ok: false; response: Response; ended: boolean };

/**
 * Server-side refresh before a session mutation (logout, logout-all, override start and end), so
 * those calls never reach the api with an expired access token (a tab hidden longer than the
 * access-token TTL never refreshed proactively). The client sends these routes under the session
 * lock (`withSessionLock`), so the single-use refresh token cannot race a refresh in another tab.
 *
 * `cookies` holds the rotated session (null when no refresh was needed); every response after a
 * refresh must set them, or the browser keeps the spent refresh token. `ended` means the api
 * refused the refresh token: the api session is already over (its tokens, including an override
 * token bound to it, are refused by the api).
 */
async function ensureFreshAccess(
  request: Request,
  deps: BffDeps,
  session: PortalSession,
  options: { force?: boolean } = {},
): Promise<FreshAccess> {
  if (!options.force && session.atExp - deps.now() > ACCESS_REFRESH_MARGIN_MS) {
    return { ok: true, session, cookies: null };
  }
  let result: JsonResult;
  try {
    result = await callUpstreamJson(deps, {
      method: 'POST',
      path: '/api/v1/auth/refresh',
      json: { refreshToken: session.rt },
      ...upstreamContext(request, deps),
    });
  } catch (error) {
    return { ok: false, response: upstreamFailure(error), ended: false };
  }
  if (result.status === 400 || result.status === 401) {
    return {
      ok: false,
      ended: true,
      response: withCookies(
        portalError(401, 'session_expired', 'The session ended; sign in again'),
        clearSessionCookies(deps.config),
      ),
    };
  }
  if (result.status !== 200) return { ok: false, response: passThrough(result), ended: false };
  const established = await establishSession(result.body, deps, session);
  if (established instanceof Response) return { ok: false, response: established, ended: false };
  return { ok: true, session: established.session, cookies: established.cookies };
}

/** Sets the rotated session cookies of a server-side refresh on any later response. */
function keepRefreshed(response: Response, cookies: string[] | null): Response {
  return cookies ? withCookies(response, cookies) : response;
}

async function endOverrideUpstream(
  request: Request,
  deps: BffDeps,
  session: PortalSession,
): Promise<JsonResult | null> {
  if (!session.ovr) return null;
  return callUpstreamJson(deps, {
    method: 'DELETE',
    path: `/api/v1/platform/overrides/${encodeURIComponent(session.ovr.id)}`,
    token: session.at,
    ...upstreamContext(request, deps),
  });
}

/**
 * Ends the api session (and an active override first). Refreshes an expired access token
 * before; a `401` from the logout call is checked with a forced refresh (a refused refresh token
 * means the session already ended). True when the api session is known to be over.
 */
async function revokeUpstreamSession(
  request: Request,
  deps: BffDeps,
  session: PortalSession,
): Promise<boolean> {
  if (session.rtExp <= deps.now()) return true;
  try {
    let fresh = await ensureFreshAccess(request, deps, session);
    for (let attempt = 0; ; attempt += 1) {
      if (!fresh.ok) {
        if (fresh.ended) return true;
        deps.logger.warn('api logout: refresh failed', { status: fresh.response.status });
        return false;
      }
      if (attempt === 0) {
        const ended = await endOverrideUpstream(request, deps, fresh.session);
        if (ended && ended.status >= 400 && ended.status !== 404) {
          // The logout below revokes the session the override token is bound to.
          deps.logger.warn('override end failed during logout', { status: ended.status });
        }
      }
      const result = await callUpstreamJson(deps, {
        method: 'POST',
        path: '/api/v1/auth/logout',
        token: fresh.session.at,
        ...upstreamContext(request, deps),
      });
      if (result.status < 400) return true;
      if (result.status === 401 && attempt === 0) {
        fresh = await ensureFreshAccess(request, deps, fresh.session, { force: true });
        continue;
      }
      deps.logger.warn('api logout failed', { status: result.status });
      return false;
    }
  } catch (error) {
    deps.logger.warn('api logout unreachable', {
      errorName: error instanceof Error ? error.name : 'unknown',
    });
    return false;
  }
}

/**
 * Ends the api session (and an active override), then clears every cookie even on failure. When
 * the api session could not be ended, answers `502 logout_incomplete` (cookies still cleared), so
 * the UI can say the server session may still be active.
 */
export async function logout(request: Request, deps: BffDeps): Promise<Response> {
  const refused = originGuard(request, deps);
  if (refused) return refused;
  const session = await readSession(request.headers.get('cookie'), deps.config);
  let revoked = true;
  if (session) {
    if (!hasValidCsrfToken(request.headers, session.csrf)) {
      return portalError(403, 'csrf_failed', 'Missing or invalid CSRF token');
    }
    revoked = await revokeUpstreamSession(request, deps, session);
  }
  const cleared = clearSessionCookies(deps.config);
  if (revoked) return emptyResponse(204, cleared);
  return withCookies(
    portalError(
      502,
      'logout_incomplete',
      'Signed out of this browser, but the server session could not be ended',
    ),
    cleared,
  );
}

/** Ends every session of the user (refreshing an expired access token first). */
export async function logoutAll(request: Request, deps: BffDeps): Promise<Response> {
  const check = await requireSessionMutation(request, deps);
  if (!check.ok) return check.response;
  const cleared = clearSessionCookies(deps.config);
  const fresh = await ensureFreshAccess(request, deps, check.session);
  if (!fresh.ok) return withCookies(fresh.response, cleared);
  let result: JsonResult;
  try {
    await endOverrideUpstream(request, deps, fresh.session);
    result = await callUpstreamJson(deps, {
      method: 'POST',
      path: '/api/v1/auth/logout-all',
      token: fresh.session.at,
      ...upstreamContext(request, deps),
    });
  } catch (error) {
    return withCookies(upstreamFailure(error), cleared);
  }
  if (result.status >= 400) return passThrough(result, cleared);
  return emptyResponse(204, cleared);
}

export async function startOverride(request: Request, deps: BffDeps): Promise<Response> {
  const check = await requireSessionMutation(request, deps);
  if (!check.ok) return check.response;
  const now = deps.now();
  if (check.session.ovr && check.session.ovr.exp > now) {
    return portalError(409, 'override_active', 'End the current override first');
  }
  const read = await readJsonBody(request, SESSION_BODY_LIMIT);
  if (!read.ok) return read.response;
  const parsed = overrideBody.safeParse(read.value);
  if (!parsed.success) return validationError(parsed.error.issues);
  const fresh = await ensureFreshAccess(request, deps, check.session);
  if (!fresh.ok) return fresh.response;
  const { session, cookies: refreshed } = fresh;
  const context = upstreamContext(request, deps);

  let started: JsonResult;
  try {
    started = await callUpstreamJson(deps, {
      method: 'POST',
      path: '/api/v1/platform/overrides',
      token: session.at,
      json: parsed.data,
      ...context,
    });
  } catch (error) {
    return keepRefreshed(upstreamFailure(error), refreshed);
  }
  if (started.status !== 201) return keepRefreshed(passThrough(started), refreshed);
  const override = overrideResponse.safeParse(started.body);
  if (!override.success || override.data.organization.id !== parsed.data.organizationId) {
    deps.logger.error('api returned an unexpected override response');
    return keepRefreshed(
      portalError(502, 'upstream_invalid_response', 'Unexpected response from the API'),
      refreshed,
    );
  }

  let organizationName = override.data.organization.name;
  try {
    const org = await callUpstreamJson(deps, {
      method: 'GET',
      path: `/api/v1/organizations/${encodeURIComponent(parsed.data.organizationId)}`,
      token: session.at,
      ...context,
    });
    const parsedOrg = organizationResponse.safeParse(org.body);
    if (
      org.status === 200 &&
      parsedOrg.success &&
      parsedOrg.data.id === parsed.data.organizationId
    ) {
      organizationName = parsedOrg.data.name;
    }
  } catch {
    // The name from the override response (same organization id) is used instead.
  }

  const expiresAt = Date.parse(override.data.expiresAt);
  const next: PortalSession = {
    ...session,
    ovr: {
      id: override.data.overrideId,
      at: override.data.accessToken,
      exp: Number.isFinite(expiresAt) ? expiresAt : now,
      organizationId: parsed.data.organizationId,
      organizationName,
    },
  };
  let cookies: string[];
  try {
    cookies = await sessionCookies(next, deps.config, deps.now());
  } catch (error) {
    if (!(error instanceof CookieTooLargeError)) throw error;
    deps.logger.error('override does not fit in the session cookie; ending it', {
      bytes: error.bytes,
    });
    try {
      await endOverrideUpstream(request, deps, next);
    } catch {
      // logged by callUpstream
    }
    return keepRefreshed(
      portalError(422, 'override_cookie_too_large', 'The override could not be stored'),
      refreshed,
    );
  }
  return jsonResponse(
    {
      id: override.data.overrideId,
      organizationId: parsed.data.organizationId,
      organizationName,
      expiresAt: new Date(next.ovr?.exp ?? now).toISOString(),
    },
    201,
    cookies,
  );
}

/**
 * Ends the tenant override on the api, then drops it from the session. Only `404` (already
 * ended) counts as ended; any other api error keeps the override in the session and passes the
 * error through. An expired access token is refreshed first.
 */
export async function endOverride(request: Request, deps: BffDeps): Promise<Response> {
  const check = await requireSessionMutation(request, deps);
  if (!check.ok) return check.response;
  if (!check.session.ovr) return emptyResponse(204);
  if (check.session.ovr.exp <= deps.now()) {
    const { ovr: _expired, ...rest } = check.session;
    return emptyResponse(204, await sessionCookies(rest, deps.config, deps.now()));
  }
  const fresh = await ensureFreshAccess(request, deps, check.session);
  if (!fresh.ok) return fresh.response;
  let result: JsonResult | null;
  try {
    result = await endOverrideUpstream(request, deps, fresh.session);
  } catch (error) {
    return keepRefreshed(upstreamFailure(error), fresh.cookies);
  }
  if (result && result.status >= 400 && result.status !== 404) {
    return keepRefreshed(passThrough(result), fresh.cookies);
  }
  const { ovr: _ended, ...rest } = fresh.session;
  return emptyResponse(204, await sessionCookies(rest, deps.config, deps.now()));
}

/** Platform readiness (former home page), only for holders of `platform:operations`. */
export async function platformHealth(request: Request, deps: BffDeps): Promise<Response> {
  const session = await readSession(request.headers.get('cookie'), deps.config);
  const now = deps.now();
  if (!session || session.rtExp <= now) return portalError(401, 'unauthorized', 'Not signed in');
  if (session.atExp <= now) {
    return portalError(401, 'access_token_expired', 'Access token expired; refresh the session');
  }
  let me: JsonResult;
  try {
    me = await callUpstreamJson(deps, {
      method: 'GET',
      path: '/api/v1/auth/me',
      token: session.at,
      ...upstreamContext(request, deps),
    });
  } catch (error) {
    return upstreamFailure(error);
  }
  if (me.status !== 200) return passThrough(me);
  const parsed = meResponse.safeParse(me.body);
  if (!parsed.success || !parsed.data.permissions.includes('platform:operations')) {
    return portalError(403, 'forbidden', 'Requires platform:operations');
  }
  const health = await fetchPlatformHealth({
    baseUrl: deps.config.API_INTERNAL_URL,
    fetchImpl: deps.fetch,
  });
  return jsonResponse(health);
}
