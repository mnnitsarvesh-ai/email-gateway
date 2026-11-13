import 'server-only';
import { buildPath, getOperation, matchOperation, splitRawPath } from '@/lib/api/operations';
import { clientIpFromHeaders } from '@/server/client-ip';
import { hasValidCsrfToken, isSafeMethod, isSameOriginRequest } from '@/server/csrf';
import { BFF_RESPONSE_HEADERS, portalError, readLimited } from '@/server/http';
import { readSession, sessionCookies, type PortalSession } from '@/server/session/session';
import { UpstreamError, callUpstream, correlationIdFrom, type BffDeps } from '@/server/upstream';

/** Generic proxy `/bff/api/v1/*` (design P5). */
export const PROXY_PREFIX = '/bff/api/v1/';
export const PROXY_BODY_LIMIT_BYTES = 1024 * 1024;

/** Request headers forwarded to the api; everything else (cookies, client `X-EG-*`) is dropped. */
export const FORWARDED_REQUEST_HEADERS = [
  'content-type',
  'accept',
  'idempotency-key',
  'user-agent',
] as const;

/** Response headers passed back to the browser. */
export const PASSED_RESPONSE_HEADERS = [
  'content-type',
  'content-disposition',
  'x-request-id',
  'x-correlation-id',
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
  'retry-after',
  'idempotency-replayed',
  'deprecation',
  'link',
] as const;

function rawApiPath(url: URL): string | null {
  // Keep the raw (percent-encoded) pathname: decoding first would hide %2F and friends.
  const pathname = url.pathname;
  if (!pathname.startsWith(PROXY_PREFIX)) return null;
  return pathname.slice(PROXY_PREFIX.length);
}

async function dropExpiredOverride(session: PortalSession, deps: BffDeps): Promise<string[]> {
  const { ovr: _dropped, ...rest } = session;
  return sessionCookies(rest, deps.config, deps.now());
}

export async function handleProxy(request: Request, deps: BffDeps): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const raw = rawApiPath(url);
  const segments = raw === null ? null : splitRawPath(raw);
  if (!segments) return portalError(404, 'route_not_found', 'Route not found');
  const match = matchOperation(method, segments);
  if (!match) return portalError(404, 'route_not_found', 'Route not found');
  const operation = getOperation(match.operationId);
  if (operation.bffOnly) {
    return portalError(
      403,
      'bff_route_required',
      'Use the portal session routes for this operation',
    );
  }

  if (!isSameOriginRequest(method, request.headers, deps.config)) {
    return portalError(403, 'csrf_failed', 'Cross-site request refused');
  }

  let token: string | null = null;
  if (!operation.public) {
    const session = await readSession(request.headers.get('cookie'), deps.config);
    const now = deps.now();
    if (!session || session.rtExp <= now) {
      return portalError(401, 'unauthorized', 'Not signed in');
    }
    if (!isSafeMethod(method) && !hasValidCsrfToken(request.headers, session.csrf)) {
      return portalError(403, 'csrf_failed', 'Missing or invalid CSRF token');
    }
    if (session.ovr) {
      if (session.ovr.exp <= now) {
        const cookies = await dropExpiredOverride(session, deps);
        const response = portalError(401, 'override_expired', 'The tenant override has ended');
        for (const cookie of cookies) response.headers.append('set-cookie', cookie);
        return response;
      }
      token = session.ovr.at;
    } else {
      if (session.atExp <= now) {
        return portalError(
          401,
          'access_token_expired',
          'Access token expired; refresh the session',
        );
      }
      token = session.at;
    }
  }

  let body: Uint8Array<ArrayBuffer> | null = null;
  if (isSafeMethod(method)) {
    if (request.body !== null && request.headers.get('content-length') !== '0') {
      const probe = await readLimited(request.body, PROXY_BODY_LIMIT_BYTES);
      if (probe === 'too_large' || probe.length > 0) {
        return portalError(400, 'validation_failed', 'A GET request must not have a body');
      }
    }
  } else {
    const declared = Number(request.headers.get('content-length') ?? '0');
    if (declared > PROXY_BODY_LIMIT_BYTES) {
      return portalError(413, 'payload_too_large', 'Request body too large');
    }
    const read = await readLimited(request.body, PROXY_BODY_LIMIT_BYTES);
    if (read === 'too_large') {
      return portalError(413, 'payload_too_large', 'Request body too large');
    }
    body = read.length > 0 ? read : null;
  }

  const forwarded = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value !== null) forwarded.set(name, value);
  }
  const correlationId = correlationIdFrom(request.headers);
  const upstreamPath = `${buildPath(operation.path, match.params)}${url.search}`;

  let upstream: Response;
  try {
    upstream = await callUpstream(deps, {
      method,
      path: upstreamPath,
      token,
      body,
      headers: forwarded,
      clientIp: clientIpFromHeaders(request.headers, deps.config.PORTAL_TRUST_PROXY_HOPS),
      correlationId,
    });
  } catch (error) {
    if (error instanceof UpstreamError && error.kind === 'timeout') {
      return portalError(504, 'upstream_timeout', 'The API did not answer in time', {
        'x-correlation-id': correlationId,
      });
    }
    return portalError(502, 'upstream_unavailable', 'The API is unavailable', {
      'x-correlation-id': correlationId,
    });
  }

  const headers = new Headers(BFF_RESPONSE_HEADERS);
  for (const name of PASSED_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  if (!headers.has('x-correlation-id')) headers.set('x-correlation-id', correlationId);
  const noBody = upstream.status === 204 || upstream.status === 304 || method === 'HEAD';
  return new Response(noBody ? null : upstream.body, { status: upstream.status, headers });
}
