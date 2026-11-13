import { NextResponse, type NextRequest } from 'next/server';
import { getServerConfig, type ServerConfig } from '@/server/config';
import { isSameOriginRequest } from '@/server/csrf';
import { portalError } from '@/server/http';
import { readSession } from '@/server/session/session';
import { buildCsp, isPublicPath, loginRedirectPath } from '@/server/security-headers';

/**
 * Middleware (design P1, P6, P10), Node runtime. Exactly three jobs, never an api call:
 * 1. CSP with a per-request nonce (the nonce travels in the request headers so Next applies it);
 * 2. console routes without a readable session cookie → `/login?next=<path>`;
 * 3. cross-site state-changing requests to `/bff/*` → 403 `csrf_failed`.
 */
export async function middleware(request: NextRequest): Promise<Response> {
  const config = getServerConfig();
  const response = await route(request, config);
  if (config.secure) {
    response.headers.set('strict-transport-security', 'max-age=63072000; includeSubDomains');
  }
  return response;
}

async function route(request: NextRequest, config: ServerConfig): Promise<Response> {
  const { pathname, search } = request.nextUrl;

  if (pathname.startsWith('/bff/')) {
    if (!isSameOriginRequest(request.method, request.headers, config)) {
      return portalError(403, 'csrf_failed', 'Cross-site request refused');
    }
    return NextResponse.next();
  }

  if (pathname === '/api/health' || pathname.startsWith('/api/')) {
    return NextResponse.next();
  }

  if (!isPublicPath(pathname)) {
    const session = await readSession(request.headers.get('cookie'), config);
    if (!session || session.rtExp <= Date.now()) {
      const target = new URL(loginRedirectPath(`${pathname}${search}`), request.url);
      return NextResponse.redirect(target, 307);
    }
  }

  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const csp = buildCsp(nonce, {
    development: process.env.NODE_ENV === 'development',
    secure: config.secure,
  });
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('content-security-policy', csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('content-security-policy', csp);
  return response;
}

export const config = {
  runtime: 'nodejs',
  matcher: ['/((?!_next/static|_next/image|favicon.ico|robots.txt).*)'],
};
