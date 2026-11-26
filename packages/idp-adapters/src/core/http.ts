/**
 * Provider HTTPS client (design note D2, ADR-0082) on Node's global fetch.
 *
 * - Fixed origin allow-list per API family; provider-returned links (`@odata.nextLink`,
 *   `NextPageUri`, `contentUri`) are followed only when same-origin and under the family's base
 *   path. `https:` only unless `allowHttpEndpoints` (local/CI).
 * - No redirects, no cookies, no proxy environment, timeouts through `AbortSignal.any`, a byte cap
 *   on bodies, JSON validated by a per-endpoint zod schema.
 * - Errors are classified (`ProviderCallError`); `401` drops the token and retries once.
 * - Redaction: no header, token, query string or body ever reaches an error, a log line or a
 *   metric. A debug line carries family, method, path template, status and duration.
 */
import { randomUUID } from 'node:crypto';
import type { ZodType } from 'zod';
import type { ApiFamily } from '../port/state-ports';
import { ProviderCallError, sanitizeProviderCode } from './errors';

export type OriginFamily = 'graph' | 'o365' | 'google_admin' | 'gmail';

export const ORIGIN_FAMILY_OF: Readonly<Record<ApiFamily, OriginFamily>> = {
  graph: 'graph',
  o365: 'o365',
  google_reports: 'google_admin',
  google_directory: 'google_admin',
  gmail: 'gmail',
};

/** pino-compatible subset (`logger.debug(obj, msg)`). */
export interface IdpLogger {
  debug(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
}

export const NOOP_LOGGER: IdpLogger = { debug: () => undefined, warn: () => undefined };

/** Counters and histograms without tenant, integration, identity or IP labels (D11). */
export interface IdpMetricsSink {
  httpRequest?(
    labels: { provider: string; family: ApiFamily; statusClass: string },
    seconds: number,
  ): void;
  throttled?(labels: { provider: string; family: ApiFamily }): void;
  rateBudgetWait?(labels: { family: ApiFamily }): void;
  events?(labels: { provider: string; stream: string; result: string }, count: number): void;
  cursorReset?(labels: { provider: string; stream: string }): void;
  snapshotItems?(labels: { provider: string; kind: string; change: string }, count: number): void;
  probe?(labels: { provider: string; result: string }): void;
  action?(labels: { provider: string; action: string; outcome: string }): void;
}

/** Supplies a bearer token; `invalidate` drops the cached one after a `401`. */
export interface TokenSource {
  get(signal: AbortSignal): Promise<string>;
  invalidate(): void;
}

export interface ProviderHttpClientOptions {
  /** Base URL per origin family (origin plus optional base path, e.g. `http://sim:8080/graph`). */
  baseUrls: Readonly<Record<OriginFamily, string>>;
  allowHttpEndpoints: boolean;
  timeoutMs: number;
  maxResponseBytes: number;
  maxBackoffMs: number;
  /** Provider label for metrics only. */
  provider?: string;
  logger?: IdpLogger;
  metrics?: IdpMetricsSink;
  fetch?: typeof fetch;
  random?: () => number;
  now?: () => number;
  /** Environment checked for proxy settings (defaults to process.env). */
  env?: Readonly<Record<string, string | undefined>>;
}

export interface ProviderRequest<T> {
  family: ApiFamily;
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  /** Path and query relative to the family base URL, or an absolute provider-returned link. */
  url: string;
  /** Path template for logs (`/v1.0/users/{id}`); never the concrete path or query. */
  pathTemplate: string;
  token: TokenSource;
  signal: AbortSignal;
  /** Response schema; omitted for answers without a body that 8.5 reads. */
  schema?: ZodType<T>;
  body?: unknown;
  headers?: Readonly<Record<string, string>>;
  /** Backoff attempt (consecutive failures so far) used when no Retry-After is given. */
  attempt?: number;
  /** Graph `client-request-id`; a fresh UUID when omitted. */
  requestId?: string;
}

/**
 * A streamed GET (step API-1 D9): MIME bodies (Graph `$value`) and Gmail `format=raw` JSON that
 * cannot be buffered whole. Same rules as `request` (origin allow-list, provider links same-origin
 * and under the base path only, no redirects, no proxy environment, `401` drop-and-retry-once,
 * classified errors with `Retry-After`, redaction); the body is never parsed here.
 */
export interface ProviderStreamRequest {
  family: ApiFamily;
  method: 'GET';
  /** Path and query relative to the family base URL, or an absolute provider-returned link. */
  url: string;
  /** Path template for logs; never the concrete path or query. */
  pathTemplate: string;
  token: TokenSource;
  signal: AbortSignal;
  /** Byte cap of the body: exceeding it (declared or while streaming) fails `response_too_large`. */
  maxBytes: number;
  /** `Accept` header (default `*\/*`). */
  accept?: string;
  headers?: Readonly<Record<string, string>>;
  attempt?: number;
  requestId?: string;
  /**
   * Upper bound for reading the whole body after the headers arrived (default 10 minutes). The
   * client's `timeoutMs` applies until the headers arrive and as the idle limit between chunks.
   */
  bodyTimeoutMs?: number;
}

export interface ProviderStreamResponse {
  status: number;
  requestId: string;
  headers: { contentType?: string; contentLength?: number };
  /**
   * The body, iterable once. Iteration fails with a `ProviderCallError` (`response_too_large`,
   * `aborted`, `provider_unavailable` on a timeout or a broken connection); breaking out of the
   * loop cancels the transfer.
   */
  body: AsyncIterable<Uint8Array>;
}

export const DEFAULT_STREAM_BODY_TIMEOUT_MS = 600_000;

export interface ProviderResponse<T> {
  status: number;
  data: T;
  requestId: string;
  /** Response headers 8.5 reads (`NextPageUri`); values are provider links, checked on use. */
  headers: { nextPageUri?: string };
}

const USER_AGENT = 'EmailGateway-ATO/1';
const ERROR_BODY_MAX_BYTES = 64 * 1024;
const BACKOFF_BASE_MS = 1_000;
const BACKOFF_STEP_CAP_MS = 64_000;
export const QUOTA_RETRY_AFTER_MS = 3_600_000;

/** Exponential 1 s → 64 s with full jitter, capped (D2). */
export function computeBackoffMs(attempt: number, random: () => number, capMs: number): number {
  const exponent = Math.max(0, Math.min(attempt, 6));
  const ceiling = Math.min(BACKOFF_STEP_CAP_MS, BACKOFF_BASE_MS * 2 ** exponent, capMs);
  return Math.max(1, Math.floor(random() * ceiling));
}

/** `Retry-After` in seconds or as an HTTP date, capped; `undefined` when absent or invalid. */
export function parseRetryAfter(
  value: string | null | undefined,
  nowMs: number,
  capMs: number,
): number | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (/^\d{1,10}$/.test(trimmed)) return Math.min(Number(trimmed) * 1000, capMs);
  const date = Date.parse(trimmed);
  if (Number.isNaN(date)) return undefined;
  return Math.min(Math.max(0, date - nowMs), capMs);
}

interface ParsedBase {
  origin: string;
  basePath: string; // without trailing slash
}

function parseBase(value: string, allowHttp: boolean): ParsedBase {
  const url = new URL(value);
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new Error('provider_base_url_scheme_refused');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('provider_base_url_invalid');
  }
  return { origin: url.origin, basePath: url.pathname.replace(/\/+$/, '') };
}

const GOOGLE_THROTTLE_REASONS = new Set(['rateLimitExceeded', 'userRateLimitExceeded']);
const GOOGLE_QUOTA_REASONS = new Set(['dailyLimitExceeded', 'quotaExceeded']);
const GOOGLE_PERMISSION_REASONS = new Set([
  'insufficientPermissions',
  'forbidden',
  'ACCESS_TOKEN_SCOPE_INSUFFICIENT',
  'accessNotConfigured',
  'domainPolicy',
]);
/** Graph / Office 365 Management codes meaning "licence or feature not available". */
const LICENSE_CODE = /NonPremium|License|Licence|NotLicensed|AF20023|AF10006/i;
/** Office 365 Management permission codes. */
const O365_PERMISSION_CODES = new Set(['AF10001', 'AF10002', 'AF10003', 'AF10004', 'AF10005']);

interface ErrorInfo {
  code?: string;
  reason?: string;
}

function extractErrorInfo(body: unknown): ErrorInfo {
  if (!body || typeof body !== 'object') return {};
  const error = (body as { error?: unknown }).error;
  if (!error || typeof error !== 'object') return {};
  const record = error as { code?: unknown; status?: unknown; errors?: unknown };
  let reason: string | undefined;
  if (Array.isArray(record.errors) && record.errors.length > 0) {
    const first: unknown = record.errors[0];
    if (first && typeof first === 'object') {
      reason = sanitizeProviderCode((first as { reason?: unknown }).reason);
    }
  }
  const code =
    typeof record.code === 'string'
      ? sanitizeProviderCode(record.code)
      : sanitizeProviderCode(record.status);
  return { code, reason };
}

export class ProviderHttpClient {
  private readonly bases: Readonly<Record<OriginFamily, ParsedBase>>;
  private readonly fetchImpl: typeof fetch;
  private readonly logger: IdpLogger;
  private readonly random: () => number;
  private readonly now: () => number;

  constructor(private readonly options: ProviderHttpClientOptions) {
    const env = options.env ?? process.env;
    const proxyFlag = env.NODE_USE_ENV_PROXY;
    if (proxyFlag && proxyFlag !== '0' && proxyFlag.toLowerCase() !== 'false') {
      // Node's global fetch reads proxy variables only with NODE_USE_ENV_PROXY: refused (D2).
      throw new Error('provider_http_proxy_env_refused');
    }
    this.bases = {
      graph: parseBase(options.baseUrls.graph, options.allowHttpEndpoints),
      o365: parseBase(options.baseUrls.o365, options.allowHttpEndpoints),
      google_admin: parseBase(options.baseUrls.google_admin, options.allowHttpEndpoints),
      gmail: parseBase(options.baseUrls.gmail, options.allowHttpEndpoints),
    };
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.logger = options.logger ?? NOOP_LOGGER;
    this.random = options.random ?? Math.random;
    this.now = options.now ?? Date.now;
  }

  /** The configured base URL (origin + base path) of a family. */
  baseUrl(family: ApiFamily): string {
    const base = this.bases[ORIGIN_FAMILY_OF[family]];
    return `${base.origin}${base.basePath}`;
  }

  /**
   * Resolves a relative path or a provider-returned absolute link against the family's base.
   * Returns the path relative to the base (`/v1.0/...?...`) or throws `blocked_host`.
   */
  relativize(family: ApiFamily, link: string): string {
    const base = this.bases[ORIGIN_FAMILY_OF[family]];
    if (link.startsWith('/')) return link;
    let url: URL;
    try {
      url = new URL(link);
    } catch {
      throw new ProviderCallError('blocked_host');
    }
    if (url.origin !== base.origin || url.username || url.password) {
      throw new ProviderCallError('blocked_host');
    }
    if (
      base.basePath &&
      !(url.pathname === base.basePath || url.pathname.startsWith(`${base.basePath}/`))
    ) {
      throw new ProviderCallError('blocked_host');
    }
    return `${url.pathname.slice(base.basePath.length) || '/'}${url.search}`;
  }

  private resolve(family: ApiFamily, link: string): URL {
    const base = this.bases[ORIGIN_FAMILY_OF[family]];
    const relative = this.relativize(family, link);
    const url = new URL(`${base.origin}${base.basePath}${relative}`);
    if (url.origin !== base.origin) throw new ProviderCallError('blocked_host');
    return url;
  }

  async request<T>(request: ProviderRequest<T>): Promise<ProviderResponse<T>> {
    try {
      return await this.attempt(request);
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'unauthorized') {
        // Token rejected: drop it once and retry once (D2).
        request.token.invalidate();
        return this.attempt(request);
      }
      throw error;
    }
  }

  /**
   * Streams a GET body (step API-1 D9) under the rules of `request`. The returned body must be
   * consumed or broken out of; it enforces `maxBytes`, the caller's signal and the timeouts.
   */
  async requestStream(request: ProviderStreamRequest): Promise<ProviderStreamResponse> {
    try {
      return await this.attemptStream(request);
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'unauthorized') {
        request.token.invalidate();
        return this.attemptStream(request);
      }
      throw error;
    }
  }

  private async prepare(request: {
    family: ApiFamily;
    url: string;
    token: TokenSource;
    signal: AbortSignal;
    headers?: Readonly<Record<string, string>>;
    requestId?: string;
    accept: string;
  }): Promise<{ url: URL; headers: Record<string, string>; requestId: string }> {
    const url = this.resolve(request.family, request.url);
    const token = await request.token.get(request.signal);
    const requestId = request.requestId ?? randomUUID();
    const headers: Record<string, string> = {
      ...(request.headers ?? {}),
      Accept: request.accept,
      'User-Agent': USER_AGENT,
      Authorization: `Bearer ${token}`,
    };
    if (request.family === 'graph') headers['client-request-id'] = requestId;
    return { url, headers, requestId };
  }

  private async attemptStream(request: ProviderStreamRequest): Promise<ProviderStreamResponse> {
    const { url, headers, requestId } = await this.prepare({
      ...request,
      accept: request.accept ?? '*/*',
    });
    // One controller for the whole transfer: the header timeout, then the idle and total body
    // limits (AbortSignal.timeout cannot be cleared once the headers have arrived).
    const transfer = new AbortController();
    const expire = () => transfer.abort();
    let headerTimer: NodeJS.Timeout | undefined = setTimeout(expire, this.options.timeoutMs);
    const signal = AbortSignal.any([request.signal, transfer.signal]);
    const started = this.now();
    const provider = this.options.provider ?? 'unknown';
    let status = 0;
    const clearHeaderTimer = () => {
      if (headerTimer !== undefined) clearTimeout(headerTimer);
      headerTimer = undefined;
    };
    try {
      let response: Response;
      try {
        response = await this.fetchImpl(url, {
          method: 'GET',
          headers,
          redirect: 'error',
          credentials: 'omit',
          signal,
        });
      } catch (error) {
        if (request.signal.aborted) throw new ProviderCallError('aborted', { retryable: false });
        if (isRedirectError(error))
          throw new ProviderCallError('redirect_refused', { retryable: false });
        throw new ProviderCallError('provider_unavailable');
      }
      status = response.status;
      if (status >= 300 && status < 400) {
        await discard(response);
        throw new ProviderCallError('redirect_refused', { status, retryable: false });
      }
      if (status >= 400) {
        throw await this.classify(response, request);
      }
      const declared = Number(response.headers.get('Content-Length') ?? NaN);
      if (Number.isFinite(declared) && declared > request.maxBytes) {
        await discard(response);
        throw new ProviderCallError('response_too_large', { status, retryable: false });
      }
      clearHeaderTimer();
      // The total limit starts now (not on first iteration), so an unconsumed body is released.
      const totalTimer = setTimeout(
        expire,
        request.bodyTimeoutMs ?? DEFAULT_STREAM_BODY_TIMEOUT_MS,
      );
      totalTimer.unref();
      const contentType = response.headers.get('Content-Type') ?? undefined;
      return {
        status,
        requestId,
        headers: {
          ...(contentType !== undefined ? { contentType } : {}),
          ...(Number.isFinite(declared) ? { contentLength: declared } : {}),
        },
        body: streamBody(response, {
          status,
          maxBytes: request.maxBytes,
          idleMs: this.options.timeoutMs,
          totalTimer,
          callerSignal: request.signal,
          expire,
        }),
      };
    } catch (error) {
      clearHeaderTimer();
      if (error instanceof ProviderCallError) {
        if (error.code === 'throttled' || error.code === 'quota_exhausted') {
          this.options.metrics?.throttled?.({ provider, family: request.family });
        }
        throw error;
      }
      if (request.signal.aborted) throw new ProviderCallError('aborted', { retryable: false });
      throw new ProviderCallError('provider_unavailable');
    } finally {
      const seconds = (this.now() - started) / 1000;
      const statusClass = status === 0 ? 'error' : `${Math.floor(status / 100)}xx`;
      this.options.metrics?.httpRequest?.(
        { provider, family: request.family, statusClass },
        seconds,
      );
      this.logger.debug(
        {
          family: request.family,
          method: 'GET',
          path: request.pathTemplate,
          status,
          durationMs: Math.round(seconds * 1000),
          stream: true,
        },
        'provider request',
      );
    }
  }

  private async attempt<T>(request: ProviderRequest<T>): Promise<ProviderResponse<T>> {
    const { url, headers, requestId } = await this.prepare({
      ...request,
      accept: 'application/json',
    });
    let body: string | undefined;
    if (request.body !== undefined) {
      body = JSON.stringify(request.body);
      headers['Content-Type'] = 'application/json';
    }
    const timeout = AbortSignal.timeout(this.options.timeoutMs);
    const signal = AbortSignal.any([request.signal, timeout]);
    const started = this.now();
    const provider = this.options.provider ?? 'unknown';
    let status = 0;
    try {
      let response: Response;
      try {
        response = await this.fetchImpl(url, {
          method: request.method,
          headers,
          body,
          redirect: 'error',
          credentials: 'omit',
          signal,
        });
      } catch (error) {
        if (request.signal.aborted) throw new ProviderCallError('aborted', { retryable: false });
        if (isRedirectError(error))
          throw new ProviderCallError('redirect_refused', { retryable: false });
        throw new ProviderCallError('provider_unavailable');
      }
      status = response.status;
      if (status >= 300 && status < 400) {
        await discard(response);
        throw new ProviderCallError('redirect_refused', { status, retryable: false });
      }
      if (status >= 400) {
        throw await this.classify(response, request);
      }
      const nextPageUri = response.headers.get('NextPageUri') ?? undefined;
      const text = await readCapped(response, this.options.maxResponseBytes, request.signal);
      let data: unknown = undefined;
      if (request.schema) {
        let parsed: unknown;
        try {
          parsed = text.length === 0 ? undefined : JSON.parse(text);
        } catch {
          throw new ProviderCallError('unexpected_response', { status, retryable: false });
        }
        const result = request.schema.safeParse(parsed);
        if (!result.success) {
          throw new ProviderCallError('unexpected_response', { status, retryable: false });
        }
        data = result.data;
      }
      return { status, data: data as T, requestId, headers: { nextPageUri } };
    } catch (error) {
      if (error instanceof ProviderCallError) {
        if (error.code === 'throttled' || error.code === 'quota_exhausted') {
          this.options.metrics?.throttled?.({ provider, family: request.family });
        }
        throw error;
      }
      if (request.signal.aborted) throw new ProviderCallError('aborted', { retryable: false });
      throw new ProviderCallError('provider_unavailable');
    } finally {
      const seconds = (this.now() - started) / 1000;
      const statusClass = status === 0 ? 'error' : `${Math.floor(status / 100)}xx`;
      this.options.metrics?.httpRequest?.(
        { provider, family: request.family, statusClass },
        seconds,
      );
      this.logger.debug(
        {
          family: request.family,
          method: request.method,
          path: request.pathTemplate,
          status,
          durationMs: Math.round(seconds * 1000),
        },
        'provider request',
      );
    }
  }

  private async classify(
    response: Response,
    request: { signal: AbortSignal; attempt?: number },
  ): Promise<ProviderCallError> {
    const status = response.status;
    const nowMs = this.now();
    const retryAfterHeader = parseRetryAfter(
      response.headers.get('Retry-After'),
      nowMs,
      this.options.maxBackoffMs,
    );
    let info: ErrorInfo = {};
    try {
      const text = await readCapped(response, ERROR_BODY_MAX_BYTES, request.signal);
      info = extractErrorInfo(text ? (JSON.parse(text) as unknown) : undefined);
    } catch {
      info = {};
    }
    const providerCode = info.reason ?? info.code;
    const backoff = () =>
      retryAfterHeader ??
      computeBackoffMs(request.attempt ?? 0, this.random, this.options.maxBackoffMs);

    if (status === 401)
      return new ProviderCallError('unauthorized', { status, retryable: false, providerCode });
    if (status === 429) {
      return new ProviderCallError('throttled', { status, retryAfterMs: backoff(), providerCode });
    }
    if (status === 403 || status === 400) {
      if (info.reason && GOOGLE_THROTTLE_REASONS.has(info.reason)) {
        return new ProviderCallError('throttled', {
          status,
          retryAfterMs: backoff(),
          providerCode,
        });
      }
      if (info.reason && GOOGLE_QUOTA_REASONS.has(info.reason)) {
        return new ProviderCallError('quota_exhausted', {
          status,
          retryAfterMs: QUOTA_RETRY_AFTER_MS, // a provider quota day/hour, not a back-off (D2)
          providerCode,
        });
      }
    }
    if (status === 403) {
      if (providerCode && LICENSE_CODE.test(providerCode)) {
        return new ProviderCallError('missing_license', { status, retryable: false, providerCode });
      }
      if (
        (info.reason && GOOGLE_PERMISSION_REASONS.has(info.reason)) ||
        info.code === 'Authorization_RequestDenied' ||
        info.code === 'Forbidden' ||
        info.code === 'PERMISSION_DENIED' ||
        (info.code !== undefined && O365_PERMISSION_CODES.has(info.code))
      ) {
        return new ProviderCallError('missing_permission', {
          status,
          retryable: false,
          providerCode,
        });
      }
      return new ProviderCallError('forbidden', { status, retryable: false, providerCode });
    }
    if (status === 404)
      return new ProviderCallError('not_found', { status, retryable: false, providerCode });
    if (status === 409 || status === 412) {
      return new ProviderCallError('conflict', { status, retryable: false, providerCode });
    }
    if (status >= 500) {
      return new ProviderCallError('provider_unavailable', {
        status,
        retryAfterMs: retryAfterHeader,
        providerCode,
      });
    }
    return new ProviderCallError('bad_request', { status, retryable: false, providerCode });
  }
}

function isRedirectError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const cause = (error as { cause?: unknown }).cause;
  const message = cause instanceof Error ? cause.message : '';
  return /redirect/i.test(message) || /redirect/i.test(error.message);
}

async function discard(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // ignore
  }
}

/** Reads a body up to `maxBytes`; larger bodies fail `response_too_large` (not retryable). */
async function readCapped(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<string> {
  const declared = Number(response.headers.get('Content-Length') ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await discard(response);
    throw new ProviderCallError('response_too_large', {
      status: response.status,
      retryable: false,
    });
  }
  if (!response.body) return '';
  const reader = response.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      if (signal.aborted) throw new ProviderCallError('aborted', { retryable: false });
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new ProviderCallError('response_too_large', {
          status: response.status,
          retryable: false,
        });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * The streamed body of `requestStream`: enforces the byte cap, the caller's signal, the idle limit
 * between chunks and the total body limit; cancels the transfer when the consumer stops early.
 */
async function* streamBody(
  response: Response,
  options: {
    status: number;
    maxBytes: number;
    idleMs: number;
    totalTimer: NodeJS.Timeout;
    callerSignal: AbortSignal;
    expire: () => void;
  },
): AsyncGenerator<Uint8Array, void, undefined> {
  if (!response.body) {
    clearTimeout(options.totalTimer);
    return;
  }
  const reader = response.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  let idle: NodeJS.Timeout | undefined;
  let received = 0;
  let finished = false;
  try {
    for (;;) {
      if (options.callerSignal.aborted)
        throw new ProviderCallError('aborted', { retryable: false });
      idle = setTimeout(options.expire, options.idleMs);
      let chunk: Awaited<ReturnType<typeof reader.read>>;
      try {
        chunk = await reader.read();
      } catch {
        if (options.callerSignal.aborted) {
          throw new ProviderCallError('aborted', { retryable: false });
        }
        // A timeout (idle or total) or a broken connection.
        throw new ProviderCallError('provider_unavailable', { status: options.status });
      } finally {
        clearTimeout(idle);
      }
      if (chunk.done) {
        finished = true;
        return;
      }
      received += chunk.value.byteLength;
      if (received > options.maxBytes) {
        throw new ProviderCallError('response_too_large', {
          status: options.status,
          retryable: false,
        });
      }
      yield chunk.value;
    }
  } finally {
    clearTimeout(options.totalTimer);
    if (!finished) {
      try {
        await reader.cancel();
      } catch {
        // ignore
      }
    }
    reader.releaseLock();
  }
}
