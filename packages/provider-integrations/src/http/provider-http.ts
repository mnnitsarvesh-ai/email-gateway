import type { ReadableStreamReadResult } from 'node:stream/web';
import type { Logger } from '@email-gateway/logger';
import { ProviderRequestError, type ProviderErrorCode } from '../errors';

/**
 * The low-level provider request primitive (D2, D6). Every Microsoft and Google call of the
 * framework goes through it; step 8.5 uses it for its own clients under its own ADR.
 *
 * Rules: the URL is the configured `origin` (scheme, host, port and base path; never tenant
 * input) plus a relative `path`, and the result must stay under that origin and base path;
 * `redirect: 'error'`; responses are read through a byte cap and must be JSON; a timeout per
 * request; `429`/`503` honour `Retry-After` up to a cap; failures are classified
 * (`ProviderRequestError`) without bodies, tokens or secrets in messages or logs.
 */

export const DEFAULT_PROVIDER_TIMEOUT_MS = 10_000;
export const DEFAULT_PROVIDER_MAX_RESPONSE_BYTES = 1_048_576;
export const DEFAULT_RETRY_AFTER_CAP_MS = 60_000;

export type ProviderHttpMethod = 'GET' | 'POST' | 'PATCH' | 'DELETE';

export interface ProviderRequestObservation {
  /** Caller label (`m365.token`, `graph`, `google.token`, `google.admin`, …). */
  api: string;
  method: ProviderHttpMethod;
  status: number | null;
  result: 'ok' | ProviderErrorCode;
  durationMs: number;
}

export interface ProviderRequestOptions {
  /** The configured endpoint (e.g. `PROVIDER_M365_GRAPH_URL`); its path is the base path. */
  origin: URL;
  method: ProviderHttpMethod;
  /** Path relative to the origin's base path, starting with `/`; `''` = the origin itself. */
  path: string;
  query?: Record<string, string | number | boolean | undefined | null>;
  /** Extra request headers (`Authorization`, …). Never logged. */
  headers?: Record<string, string>;
  /** `URLSearchParams` = form-encoded; anything else = JSON. */
  body?: unknown;
  maxResponseBytes?: number;
  timeoutMs?: number;
  retryAfterCapMs?: number;
  /** Non-2xx statuses returned to the caller instead of thrown (e.g. `404` for lookups). */
  acceptStatuses?: readonly number[];
  signal: AbortSignal;
  /** Label for observations and debug logs. */
  api?: string;
  /** Allow `http:` origins (`PROVIDER_ALLOW_HTTP_ENDPOINTS`, local/ci only). */
  allowHttp?: boolean;
  fetch?: typeof fetch;
  logger?: Pick<Logger, 'debug' | 'warn'>;
  observe?: (observation: ProviderRequestObservation) => void;
}

export interface ProviderResponse {
  status: number;
  headers: Headers;
  json: unknown;
}

const SAFE_PATH = /^\/[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*$/;

/**
 * Builds the request URL from a configured origin and a relative path, refusing anything that
 * would leave the origin or its base path (absolute URLs, `//host`, dot segments, encoded
 * slashes or dots, query or fragment characters in the path).
 */
export function buildProviderUrl(
  origin: URL,
  path: string,
  query?: ProviderRequestOptions['query'],
): URL {
  if (typeof path !== 'string') throw new ProviderRequestError('bad_response');
  if (path !== '' && (!path.startsWith('/') || path.startsWith('//'))) {
    throw new ProviderRequestError('bad_response');
  }
  if (
    (path !== '' && !SAFE_PATH.test(path)) ||
    /%2f|%5c|%2e/i.test(path) ||
    /(^|\/)\.\.?(\/|$)/.test(path)
  ) {
    throw new ProviderRequestError('bad_response');
  }
  const base = origin.pathname.replace(/\/+$/, '');
  const url = new URL(origin.origin);
  url.pathname = path === '' ? base || '/' : `${base}${path}`;
  const inside = path === '' || url.pathname.startsWith(`${base}/`);
  if (url.origin !== origin.origin || !inside) {
    throw new ProviderRequestError('bad_response');
  }
  for (const [name, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null) continue;
    url.searchParams.set(name, String(value));
  }
  return url;
}

/** True when `candidate` is on the configured origin and under its base path (paging links). */
export function isUnderOrigin(origin: URL, candidate: string): boolean {
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return false;
  }
  const base = origin.pathname.replace(/\/+$/, '');
  return (
    url.origin === origin.origin &&
    url.username === '' &&
    url.password === '' &&
    url.pathname.startsWith(`${base}/`) &&
    !/(^|\/)\.\.?(\/|$)/.test(url.pathname)
  );
}

/** Refuses non-`https:` origins unless `allowHttp`; refuses credentials in the URL. */
export function assertProviderOrigin(origin: URL, allowHttp = false): void {
  const okScheme = origin.protocol === 'https:' || (allowHttp && origin.protocol === 'http:');
  if (!okScheme || origin.username || origin.password || origin.search || origin.hash) {
    throw new ProviderRequestError('bad_response');
  }
}

/** Parses `Retry-After` (seconds or HTTP date) into milliseconds, capped; undefined if absent. */
export function parseRetryAfter(
  value: string | null,
  capMs: number,
  now = Date.now(),
): number | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  let ms: number | undefined;
  if (/^\d+$/.test(trimmed)) ms = Number(trimmed) * 1000;
  else {
    const at = Date.parse(trimmed);
    if (!Number.isNaN(at)) ms = Math.max(0, at - now);
  }
  if (ms === undefined || !Number.isFinite(ms)) return undefined;
  return Math.min(Math.max(0, ms), capMs);
}

/** Reads a response body through a byte cap (`bad_response` when exceeded). */
async function readCapped(response: Response, maxBytes: number): Promise<Buffer> {
  const declared = Number(response.headers.get('content-length') ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    throw new ProviderRequestError('bad_response', { status: response.status });
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const chunk = (await reader.read()) as ReadableStreamReadResult<Uint8Array>;
    if (chunk.done) break;
    const value = chunk.value;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ProviderRequestError('bad_response', { status: response.status });
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

const isJsonType = (type: string | null): boolean =>
  !!type && /^application\/([a-z0-9.+-]+\+)?json\b/i.test(type.trim());

function parseJson(buffer: Buffer): unknown {
  if (buffer.length === 0) return null;
  try {
    return JSON.parse(buffer.toString('utf8'));
  } catch {
    return undefined;
  }
}

const AADSTS_CONSENT = new Set([65001, 700016, 7000112, 500011]);
const AADSTS_TENANT = new Set([90002, 900023, 90072, 90023]);
const AADSTS_CLIENT = new Set([7000215, 7000222, 700027, 700024, 50012, 7000218]);

/**
 * Error classification table (D2). Shapes recognised:
 * - OAuth token errors (Microsoft identity platform, Google OAuth): `{ error, error_codes? }`.
 * - Microsoft Graph: `{ error: { code } }`.
 * - Google APIs: `{ error: { code, status, errors[] } }`.
 * The body is inspected for classification only and never surfaces.
 */
export function classifyProviderFailure(
  status: number,
  body: unknown,
  options: { tokenEndpoint?: 'microsoft' | 'google' } = {},
): ProviderErrorCode {
  if (status === 429) return 'throttled';
  if (status === 408 || status === 504) return 'timeout';
  if (status >= 500) return 'unavailable';
  const record = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const oauthError = typeof record.error === 'string' ? record.error : undefined;
  if (oauthError) {
    const codes = Array.isArray(record.error_codes)
      ? record.error_codes.filter((c): c is number => typeof c === 'number')
      : [];
    if (codes.some((c) => AADSTS_TENANT.has(c))) return 'tenant_not_found';
    if (codes.some((c) => AADSTS_CONSENT.has(c))) return 'consent_missing';
    if (codes.some((c) => AADSTS_CLIENT.has(c))) return 'invalid_client';
    switch (oauthError) {
      case 'invalid_client':
        return 'invalid_client';
      case 'unauthorized_client':
        // Google: the service account is not authorized for domain-wide delegation of the
        // requested scopes = the Google counterpart of a missing admin consent.
        return options.tokenEndpoint === 'google' ? 'consent_missing' : 'unauthorized_client';
      case 'access_denied':
      case 'consent_required':
        return 'consent_missing';
      case 'invalid_scope':
        return options.tokenEndpoint === 'google' ? 'consent_missing' : 'unauthorized_client';
      case 'invalid_grant':
        return 'invalid_client';
      case 'temporarily_unavailable':
        return 'unavailable';
      default:
        break;
    }
  }
  if (status === 401) return options.tokenEndpoint ? 'invalid_client' : 'forbidden';
  if (status === 403) return 'forbidden';
  if (status === 404 && options.tokenEndpoint === 'microsoft') return 'tenant_not_found';
  return 'bad_response';
}

/** One provider request with the D2 rules. */
export async function providerRequest(
  options: ProviderRequestOptions & { tokenEndpoint?: 'microsoft' | 'google' },
): Promise<ProviderResponse> {
  const api = options.api ?? 'provider';
  const started = Date.now();
  const observe = (status: number | null, result: ProviderRequestObservation['result']) => {
    options.observe?.({
      api,
      method: options.method,
      status,
      result,
      durationMs: Date.now() - started,
    });
  };
  assertProviderOrigin(options.origin, options.allowHttp);
  const url = buildProviderUrl(options.origin, options.path, options.query);
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROVIDER_TIMEOUT_MS;
  const maxBytes = options.maxResponseBytes ?? DEFAULT_PROVIDER_MAX_RESPONSE_BYTES;
  const capMs = options.retryAfterCapMs ?? DEFAULT_RETRY_AFTER_CAP_MS;

  const headers: Record<string, string> = { accept: 'application/json', ...options.headers };
  let body: string | undefined;
  if (options.body instanceof URLSearchParams) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    body = options.body.toString();
  } else if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(options.body);
  }

  options.signal.throwIfAborted();
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = AbortSignal.any([options.signal, timeout]);
  const doFetch = options.fetch ?? fetch;

  let response: Response;
  try {
    response = await doFetch(url, {
      method: options.method,
      headers,
      ...(body !== undefined ? { body } : {}),
      redirect: 'error',
      signal,
    });
  } catch (error) {
    if (options.signal.aborted) throw options.signal.reason;
    const code: ProviderErrorCode = timeout.aborted
      ? 'timeout'
      : isRedirectError(error)
        ? 'bad_response'
        : 'unavailable';
    observe(null, code);
    options.logger?.debug({ api, method: options.method, code }, 'provider request failed');
    throw new ProviderRequestError(code);
  }

  let buffer: Buffer;
  try {
    buffer = await readCapped(response, maxBytes);
  } catch (error) {
    if (options.signal.aborted) throw options.signal.reason;
    const code: ProviderErrorCode =
      error instanceof ProviderRequestError
        ? error.code
        : timeout.aborted
          ? 'timeout'
          : 'unavailable';
    observe(response.status, code);
    throw new ProviderRequestError(code, { status: response.status });
  }

  const ok = response.status >= 200 && response.status < 300;
  const accepted = ok || (options.acceptStatuses ?? []).includes(response.status);
  const json = isJsonType(response.headers.get('content-type')) ? parseJson(buffer) : undefined;

  if (accepted) {
    if (response.status === 204 || buffer.length === 0) {
      observe(response.status, 'ok');
      return { status: response.status, headers: response.headers, json: null };
    }
    if (json === undefined) {
      observe(response.status, 'bad_response');
      throw new ProviderRequestError('bad_response', { status: response.status });
    }
    observe(response.status, 'ok');
    return { status: response.status, headers: response.headers, json };
  }

  const code = classifyProviderFailure(response.status, json, {
    ...(options.tokenEndpoint ? { tokenEndpoint: options.tokenEndpoint } : {}),
  });
  const retryAfterMs =
    response.status === 429 || response.status === 503
      ? parseRetryAfter(response.headers.get('retry-after'), capMs)
      : undefined;
  observe(response.status, code);
  options.logger?.debug(
    { api, method: options.method, status: response.status, code },
    'provider request refused',
  );
  throw new ProviderRequestError(code, {
    status: response.status,
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
  });
}

function isRedirectError(error: unknown): boolean {
  const cause =
    error && typeof error === 'object' ? (error as { cause?: unknown }).cause : undefined;
  const text = [error, cause]
    .map((e) => (e instanceof Error ? e.message : typeof e === 'string' ? e : ''))
    .join(' ');
  return /redirect/i.test(text);
}

const abortReason = (signal: AbortSignal): Error =>
  signal.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted', 'AbortError');

/** Waits `ms` unless the signal aborts first. */
export function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(abortReason(signal));
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortReason(signal));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

/** Shared HTTP settings of the clients (configuration-driven, D2). */
export interface ProviderHttpSettings {
  timeoutMs?: number;
  maxResponseBytes?: number;
  retryAfterCapMs?: number;
  allowHttp?: boolean;
  fetch?: typeof fetch;
  logger?: Pick<Logger, 'debug' | 'warn'>;
  observe?: (observation: ProviderRequestObservation) => void;
}

export function httpOptions(
  settings: ProviderHttpSettings | undefined,
): Partial<ProviderRequestOptions> {
  const s = settings ?? {};
  return {
    ...(s.timeoutMs !== undefined ? { timeoutMs: s.timeoutMs } : {}),
    ...(s.maxResponseBytes !== undefined ? { maxResponseBytes: s.maxResponseBytes } : {}),
    ...(s.retryAfterCapMs !== undefined ? { retryAfterCapMs: s.retryAfterCapMs } : {}),
    ...(s.allowHttp !== undefined ? { allowHttp: s.allowHttp } : {}),
    ...(s.fetch ? { fetch: s.fetch } : {}),
    ...(s.logger ? { logger: s.logger } : {}),
    ...(s.observe ? { observe: s.observe } : {}),
  };
}
