import 'server-only';
import type { ServerConfig } from '@/server/config';
import type { PortalLogger } from '@/server/log';

/** `fetch`-compatible function used for every api call (replaced by the dev fixture layer). */
export type UpstreamFetch = (url: string, init: RequestInit) => Promise<Response>;

export interface BffDeps {
  readonly config: ServerConfig;
  readonly fetch: UpstreamFetch;
  readonly logger: PortalLogger;
  readonly now: () => number;
  /** Set when the dev fixture layer answers instead of the api (badge, `GET /bff/session`). */
  readonly devMocks: boolean;
}

export class UpstreamError extends Error {
  constructor(readonly kind: 'timeout' | 'unavailable') {
    super(kind === 'timeout' ? 'Upstream timeout' : 'Upstream unavailable');
    this.name = 'UpstreamError';
  }
}

export interface UpstreamRequest {
  readonly method: string;
  /** Path and query below the api origin, e.g. `/api/v1/auth/me`. */
  readonly path: string;
  readonly token?: string | null;
  readonly body?: Uint8Array<ArrayBuffer> | string | null;
  readonly headers?: Headers;
  readonly clientIp?: string | null;
  readonly correlationId: string;
}

const CORRELATION_ID = /^[A-Za-z0-9._:-]{8,128}$/;

export function correlationIdFrom(headers: Headers): string {
  const given = headers.get('x-correlation-id');
  return given && CORRELATION_ID.test(given) ? given : crypto.randomUUID();
}

/**
 * Calls the api with the forwarder headers (ADR-0060). The timeout covers the time to response
 * headers only, so long downloads keep streaming; connection errors become `unavailable`.
 */
export async function callUpstream(deps: BffDeps, request: UpstreamRequest): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.set('x-correlation-id', request.correlationId);
  if (!headers.has('accept')) headers.set('accept', 'application/json');
  if (request.token) headers.set('authorization', `Bearer ${request.token}`);
  else headers.delete('authorization');
  const token = deps.config.API_TRUSTED_FORWARDER_TOKEN;
  if (token && request.clientIp) {
    headers.set('x-eg-client-ip', request.clientIp);
    headers.set('x-eg-forwarder-token', token);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), deps.config.PORTAL_API_TIMEOUT_MS);
  try {
    return await deps.fetch(`${deps.config.API_INTERNAL_URL}${request.path}`, {
      method: request.method,
      headers,
      body: request.body ?? null,
      redirect: 'manual',
      cache: 'no-store',
      signal: controller.signal,
    });
  } catch (error) {
    const kind = controller.signal.aborted ? 'timeout' : 'unavailable';
    deps.logger.warn('upstream call failed', {
      kind,
      method: request.method,
      correlationId: request.correlationId,
      errorName: error instanceof Error ? error.name : 'unknown',
    });
    throw new UpstreamError(kind);
  } finally {
    clearTimeout(timer);
  }
}

export interface JsonResult {
  readonly status: number;
  readonly body: unknown;
  readonly headers: Headers;
}

export async function callUpstreamJson(
  deps: BffDeps,
  request: Omit<UpstreamRequest, 'body'> & { json?: unknown },
): Promise<JsonResult> {
  const headers = new Headers(request.headers);
  let body: string | null = null;
  if (request.json !== undefined) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(request.json);
  }
  const response = await callUpstream(deps, { ...request, headers, body });
  const text = await response.text();
  let parsed: unknown = null;
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      parsed = null;
    }
  }
  return { status: response.status, body: parsed, headers: response.headers };
}
