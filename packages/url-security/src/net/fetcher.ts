import { readFileSync } from 'node:fs';
import { context } from '@opentelemetry/api';
import { suppressTracing } from '@opentelemetry/core';
import http, { type IncomingMessage, type OutgoingHttpHeaders } from 'node:http';
import net, { type Socket } from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { decodeText } from '../extract/charset';
import { findMetaRefresh } from '../extract/html';
import type { LandingFeatures } from '../landing';
import { canonicalIp } from '../normalize/ip';
import { normalizeUrl } from '../normalize/url';
import { ConcurrencyLimiter } from './limiter';
import { literalOnlyLookup } from './literal-lookup';
import { type RestrictedResolver } from './resolver';
import {
  BLOCKED_REASONS,
  testSeamsAllowed,
  type BlockedReason,
  type SsrfGuard,
  type TestSeamEnv,
} from './ssrf-guard';

/**
 * The hardened fetcher (docs/plan/steps/11-url-protection.md U8). GET only, exact header set, no
 * cookies/credentials/referer, every hop validated by the guard BEFORE the request (scheme, name,
 * port, then DNS + address), the socket dials the validated IP literal (no TOCTOU) and the
 * connected `remoteAddress` is re-checked. Caps on connect/header/total time, header bytes and
 * count, body bytes, decompressed bytes (4 × body cap), hops; loop detection; meta refresh.
 *
 * Every request runs in an OpenTelemetry context with tracing suppressed (`untraced`): the
 * services that start tracing (email-worker, click-service) auto-instrument `http`, `net`,
 * `tls` and `dns`, and that instrumentation would otherwise add `traceparent`/`tracestate`/
 * `baggage` headers to requests sent to untrusted sites (breaking the exact header set and
 * leaking trace ids) and record the target's path and query in client spans sent to the
 * collector. Suppressed, no span is recorded and no context is injected.
 */

/** Runs `task` with OpenTelemetry tracing suppressed (no spans, no propagation headers). */
export function untraced<T>(task: () => T): T {
  return context.with(suppressTracing(context.active()), task);
}

export const FETCHER_VERSION = 'url-fetch/1';

export const FETCH_ERRORS = [
  'timeout',
  'dns_error',
  'tls_error',
  'connection_error',
  'http_error',
  'too_large',
  'header_limit',
  'redirect_limit',
] as const;
export type FetchError = (typeof FETCH_ERRORS)[number];

export type HopKind = 'initial' | 'http' | 'meta';

export interface FetchHop {
  host: string;
  /** Explicit non-default port, else null. */
  port: number | null;
  status: number | null;
  kind: HopKind;
  blocked: BlockedReason | null;
}

export interface FetchResult {
  status: 'completed' | 'error' | 'blocked';
  error: FetchError | null;
  blockedReason: BlockedReason | null;
  hops: FetchHop[];
  /** Redirect form of the last URL requested (or refused), null when the input was invalid. */
  finalUrl: string | null;
  finalStatus: number | null;
  landing: LandingFeatures | null;
  durationMs: number;
}

/** Header the egress proxy sets on its own 403 (bounded U8 reason). */
export const EGRESS_BLOCKED_HEADER = 'x-egress-blocked-reason';

export interface DialTarget {
  host: string;
  port: number;
}

const META_REFRESH_SCAN_BYTES = 65_536;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * TEST-ONLY dial map (`ip:port=host:port,…`, `[v6]:port` for IPv6): after the guard validated
 * the resolved address, the socket dials the mapped endpoint instead (host-run suites reach the
 * url-test container's published ports). Refused when NODE_ENV=production.
 */
export function parseDialMap(
  text: string | null | undefined,
  env: TestSeamEnv,
): Map<string, DialTarget> {
  const map = new Map<string, DialTarget>();
  const entries = (text ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (entries.length === 0) return map;
  if (!testSeamsAllowed(env)) {
    throw new Error(
      'URL_FETCH_TEST_DIAL_MAP is a test seam and is refused in production (NODE_ENV=production outside APP_ENV local/ci)',
    );
  }
  const endpoint = (value: string): DialTarget => {
    const match = /^(\[[0-9a-f:.]+\]|[0-9.]+):(\d{1,5})$/i.exec(value.trim());
    const ip = match ? canonicalIp(match[1] as string) : null;
    const port = match ? Number(match[2]) : 0;
    if (!match || ip === null || port < 1 || port > 65535)
      throw new Error(`invalid dial map endpoint ${value}`);
    return { host: ip, port };
  };
  for (const entry of entries) {
    const [from, to, extra] = entry.split('=');
    if (!from || !to || extra !== undefined) throw new Error(`invalid dial map entry ${entry}`);
    const source = endpoint(from);
    map.set(dialKey(source.host, source.port), endpoint(to));
  }
  return map;
}

const dialKey = (ip: string, port: number): string =>
  ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;

export interface ProxyConfig {
  /** URL_FETCH_EGRESS_PROXY_URL (`http://host:port`). */
  url: string;
  /** URL_EGRESS_PROXY_TOKEN (sent as Basic credentials, user `eg`). */
  token: string;
}

export const proxyAuthorization = (token: string): string =>
  `Basic ${Buffer.from(`eg:${token}`).toString('base64')}`;

export interface FetcherOptions {
  guard: SsrfGuard;
  resolver: RestrictedResolver;
  userAgent: string;
  connectTimeoutMs: number;
  headerTimeoutMs: number;
  totalTimeoutMs: number;
  maxHeaderBytes: number;
  maxHeaderCount?: number;
  maxBodyBytes: number;
  maxHops: number;
  /** Extra trusted CA certificates (PEM), added to Node's root store (URL_FETCH_CA_FILE). */
  ca?: string | Buffer | null;
  dialMap?: ReadonlyMap<string, DialTarget>;
  proxy?: ProxyConfig | null;
  /** Global concurrency (URL_FETCH_CONCURRENCY per process); share one limiter per process. */
  limiter?: ConcurrencyLimiter;
  /** Landing feature extractor for a final text/html 2xx page (U9). */
  landing?: (html: string, pageUrl: string) => LandingFeatures;
  hooks?: {
    onResult?: (result: FetchResult, mode: 'chain' | 'resource') => void;
    onBlocked?: (reason: BlockedReason) => void;
  };
}

export function readCaFile(path: string | null | undefined): Buffer | null {
  return path ? readFileSync(path) : null;
}

class FetchFailure extends Error {
  constructor(
    readonly kind: FetchError,
    message?: string,
  ) {
    super(message ?? kind);
    this.name = 'FetchFailure';
  }
}

class ProxyBlocked extends Error {
  constructor(readonly reason: BlockedReason) {
    super(`egress proxy refused (${reason})`);
    this.name = 'ProxyBlocked';
  }
}

const refusingLookup = (): never => {
  throw new Error('DNS lookup is not allowed on the guarded connector');
};

function classifyError(error: unknown): FetchError {
  if (error instanceof FetchFailure) return error.kind;
  const rawCode = (error as { code?: unknown } | null)?.code;
  const rawName = (error as { name?: unknown } | null)?.name;
  const code = typeof rawCode === 'string' ? rawCode : '';
  const name = typeof rawName === 'string' ? rawName : '';
  if (name === 'AbortError' || name === 'TimeoutError' || code === 'ABORT_ERR') return 'timeout';
  if (code === 'HPE_HEADER_OVERFLOW') return 'header_limit';
  if (code.startsWith('HPE_')) return 'http_error';
  if (
    code.startsWith('ERR_TLS') ||
    code.startsWith('ERR_SSL') ||
    code.startsWith('CERT_') ||
    code.includes('CERT') ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    code === 'EPROTO'
  ) {
    return 'tls_error';
  }
  if (code === 'ETIMEDOUT') return 'timeout';
  if (code === 'Z_DATA_ERROR' || code === 'Z_BUF_ERROR' || code.startsWith('ERR_ZLIB'))
    return 'http_error';
  return 'connection_error';
}

interface Response {
  status: number;
  headers: IncomingMessage['headers'];
  location: string | null;
  contentType: string;
  body: Buffer | null;
}

interface RequestPlan {
  url: URL;
  /** Validated IP to dial (direct mode); null in proxy mode. */
  ip: string | null;
  accept: string;
  /** Read the body (2xx with an accepted content type)? */
  wantBody: (status: number, contentType: string) => boolean;
  signal: AbortSignal;
}

export interface ResourceResult {
  status: 'completed' | 'error' | 'blocked';
  error: FetchError | null;
  blockedReason: BlockedReason | null;
  httpStatus: number | null;
  contentType: string | null;
  body: Buffer | null;
}

export class GuardedFetcher {
  private readonly ca: Array<string | Buffer> | undefined;
  private readonly limiter: ConcurrencyLimiter;
  private readonly maxHeaderCount: number;
  private readonly proxy: { host: string; port: number; authorization: string } | null;

  constructor(private readonly options: FetcherOptions) {
    this.ca = options.ca ? [...tls.rootCertificates, options.ca] : undefined;
    this.limiter = options.limiter ?? new ConcurrencyLimiter(8);
    this.maxHeaderCount = options.maxHeaderCount ?? 100;
    if (options.proxy?.url) {
      const proxyUrl = new URL(options.proxy.url);
      if (proxyUrl.protocol !== 'http:') throw new Error('the egress proxy URL must be http://');
      if (!options.proxy.token)
        throw new Error('URL_EGRESS_PROXY_TOKEN is required with an egress proxy');
      this.proxy = {
        host: proxyUrl.hostname.replace(/^\[|\]$/g, ''),
        port: proxyUrl.port ? Number(proxyUrl.port) : 80,
        authorization: proxyAuthorization(options.proxy.token),
      };
    } else {
      this.proxy = null;
    }
  }

  get proxyMode(): boolean {
    return this.proxy !== null;
  }

  /** Follows the redirect chain of `url` (scan time and click time). */
  async fetchChain(
    input: string,
    options: { signal?: AbortSignal; landing?: boolean } = {},
  ): Promise<FetchResult> {
    const started = Date.now();
    const signal = this.deadline(options.signal);
    const result = await untraced(() =>
      this.limiter.run(() => this.chain(input, signal, options.landing ?? true), signal),
    ).catch((): Omit<FetchResult, 'durationMs'> => this.failure('timeout', [], null));
    const final = { ...result, durationMs: Date.now() - started };
    this.options.hooks?.onResult?.(final, 'chain');
    return final;
  }

  /** One resource with validated redirects (RDAP): the final 2xx body up to `maxBytes`. */
  async fetchResource(
    input: string,
    options: { accept: string; maxBytes: number; signal?: AbortSignal },
  ): Promise<ResourceResult> {
    const signal = this.deadline(options.signal);
    const run = async (): Promise<ResourceResult> => {
      let current = input;
      const seen = new Set<string>();
      for (let hop = 0; ; hop += 1) {
        const normalized = normalizeUrl(current);
        if (!normalized.ok) return this.resourceError('http_error', null);
        const target = normalized.url;
        if (seen.has(target.identity) || hop > this.options.maxHops)
          return this.resourceError('redirect_limit', null);
        seen.add(target.identity);
        const url = new URL(target.identity);
        const validated = await this.validate(url, signal);
        if ('blocked' in validated)
          return {
            ...this.resourceError(null, null),
            status: 'blocked',
            blockedReason: validated.blocked,
          };
        if ('error' in validated) return this.resourceError(validated.error, null);
        let response: Response;
        try {
          response = await this.request(
            {
              url,
              ip: validated.ip,
              accept: options.accept,
              wantBody: (status) => status >= 200 && status < 300,
              signal,
            },
            options.maxBytes,
          );
        } catch (error) {
          if (error instanceof ProxyBlocked) {
            return {
              ...this.resourceError(null, null),
              status: 'blocked',
              blockedReason: error.reason,
            };
          }
          return this.resourceError(classifyError(error), null);
        }
        if (REDIRECT_STATUSES.has(response.status) && response.location) {
          current = new URL(response.location, url).href;
          continue;
        }
        return {
          status: 'completed',
          error: null,
          blockedReason: null,
          httpStatus: response.status,
          contentType: response.contentType || null,
          body: response.body,
        };
      }
    };
    const result = await untraced(() => this.limiter.run(run, signal)).catch(() =>
      this.resourceError('timeout', null),
    );
    return result;
  }

  private resourceError(error: FetchError | null, httpStatus: number | null): ResourceResult {
    return {
      status: 'error',
      error,
      blockedReason: null,
      httpStatus,
      contentType: null,
      body: null,
    };
  }

  private deadline(signal?: AbortSignal): AbortSignal {
    const total = AbortSignal.timeout(this.options.totalTimeoutMs);
    return signal ? AbortSignal.any([signal, total]) : total;
  }

  private failure(
    error: FetchError,
    hops: FetchHop[],
    finalUrl: string | null,
    finalStatus: number | null = null,
  ): Omit<FetchResult, 'durationMs'> {
    return {
      status: 'error',
      error,
      blockedReason: null,
      hops,
      finalUrl,
      finalStatus,
      landing: null,
    };
  }

  private blocked(
    reason: BlockedReason,
    hops: FetchHop[],
    finalUrl: string | null,
  ): Omit<FetchResult, 'durationMs'> {
    this.options.hooks?.onBlocked?.(reason);
    return {
      status: 'blocked',
      error: null,
      blockedReason: reason,
      hops,
      finalUrl,
      finalStatus: null,
      landing: null,
    };
  }

  /** Scheme, name, port; then the address (literal, or DNS with the any-blocked rule). */
  private async validate(
    url: URL,
    signal: AbortSignal,
  ): Promise<{ ip: string | null } | { blocked: BlockedReason } | { error: FetchError }> {
    const decision = this.options.guard.checkUrl(url);
    if (!decision.allowed) return { blocked: decision.reason };
    const literal = canonicalIp(url.hostname);
    if (literal !== null) return { ip: literal };
    // Proxy mode: the proxy resolves and guards; the client never resolves the target.
    if (this.proxy) return { ip: null };
    const resolved = await this.options.resolver.resolveValidated(
      url.hostname,
      this.options.guard,
      signal,
    );
    if (resolved.ok) return { ip: resolved.address };
    if (resolved.blocked) return { blocked: resolved.reason };
    return { error: signal.aborted ? 'timeout' : 'dns_error' };
  }

  private async chain(
    input: string,
    signal: AbortSignal,
    wantLanding: boolean,
  ): Promise<Omit<FetchResult, 'durationMs'>> {
    const hops: FetchHop[] = [];
    const seen = new Set<string>();
    let candidate = input;
    let kind: HopKind = 'initial';
    for (;;) {
      const normalized = normalizeUrl(candidate);
      if (!normalized.ok) {
        // A redirect to a non-http(s) scheme is refused by the guard; garbage is an HTTP error.
        if (normalized.code === 'url.unsupported_scheme') {
          hops.push({ host: '', port: null, status: null, kind, blocked: 'scheme' });
          return this.blocked('scheme', hops, null);
        }
        return this.failure('http_error', hops, null, hops.at(-1)?.status ?? null);
      }
      const target = normalized.url;
      const url = new URL(target.identity);
      const hop: FetchHop = {
        host: target.host,
        port: target.port,
        status: null,
        kind,
        blocked: null,
      };
      if (seen.has(target.identity)) return this.failure('redirect_limit', hops, target.redirect);
      if (hops.length > this.options.maxHops)
        return this.failure('redirect_limit', hops, target.redirect);
      seen.add(target.identity);
      hops.push(hop);

      const validated = await this.validate(url, signal);
      if ('blocked' in validated) {
        hop.blocked = validated.blocked;
        return this.blocked(validated.blocked, hops, target.redirect);
      }
      if ('error' in validated) return this.failure(validated.error, hops, target.redirect);

      let response: Response;
      try {
        response = await this.request(
          {
            url,
            ip: validated.ip,
            accept: 'text/html,*/*;q=0.5',
            wantBody: (status, contentType) =>
              status >= 200 && status < 300 && /^text\/html\b/i.test(contentType),
            signal,
          },
          Math.max(this.options.maxBodyBytes, wantLanding ? 0 : META_REFRESH_SCAN_BYTES),
        );
      } catch (error) {
        if (error instanceof ProxyBlocked) {
          hop.blocked = error.reason;
          return this.blocked(error.reason, hops, target.redirect);
        }
        return this.failure(classifyError(error), hops, target.redirect);
      }
      hop.status = response.status;

      if (REDIRECT_STATUSES.has(response.status) && response.location) {
        candidate = new URL(response.location, url).href;
        kind = 'http';
        continue;
      }
      let html: string | null = null;
      if (response.body !== null) {
        const charset = /charset\s*=\s*"?([^";\s]+)/i.exec(response.contentType)?.[1] ?? null;
        html = decodeText(response.body, charset, 'html').text;
        const refresh = findMetaRefresh(html.slice(0, META_REFRESH_SCAN_BYTES));
        if (refresh !== null) {
          candidate = new URL(refresh, url).href;
          kind = 'meta';
          continue;
        }
      }
      if (response.status >= 500)
        return this.failure('http_error', hops, target.redirect, response.status);
      const landing =
        wantLanding && html !== null && this.options.landing
          ? this.options.landing(html, target.redirect)
          : null;
      return {
        status: 'completed',
        error: null,
        blockedReason: null,
        hops,
        finalUrl: target.redirect,
        finalStatus: response.status,
        landing,
      };
    }
  }

  private headers(url: URL, accept: string): OutgoingHttpHeaders {
    // Exactly these headers (U8): never Cookie, Authorization, Referer or Proxy-*.
    return {
      Host: url.host,
      'User-Agent': this.options.userAgent,
      Accept: accept,
      'Accept-Encoding': 'gzip, deflate, br',
      Connection: 'close',
    };
  }

  /** Opens the transport: the validated IP (direct), or a CONNECT tunnel / the proxy (proxy mode). */
  private async openSocket(plan: RequestPlan): Promise<{ socket: Socket; absoluteForm: boolean }> {
    const { url } = plan;
    const isHttps = url.protocol === 'https:';
    const port = url.port ? Number(url.port) : isHttps ? 443 : 80;
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    const servername = canonicalIp(hostname) === null ? hostname : undefined;
    const connectTimeout = this.options.connectTimeoutMs;

    const withTimeout = <S extends Socket>(
      socket: S,
      event: 'connect' | 'secureConnect',
      check?: () => void,
    ): Promise<S> =>
      new Promise<S>((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.destroy();
          reject(new FetchFailure('timeout', 'connect timeout'));
        }, connectTimeout);
        const onAbort = (): void => {
          socket.destroy();
          reject(new FetchFailure('timeout', 'deadline'));
        };
        plan.signal.addEventListener('abort', onAbort, { once: true });
        socket.once(event, () => {
          clearTimeout(timer);
          plan.signal.removeEventListener('abort', onAbort);
          try {
            check?.();
            resolve(socket);
          } catch (error) {
            socket.destroy();
            reject(error instanceof Error ? error : new FetchFailure('connection_error'));
          }
        });
        // Stays attached: a late socket error must never become an unhandled 'error' event.
        socket.on('error', (error) => {
          clearTimeout(timer);
          plan.signal.removeEventListener('abort', onAbort);
          reject(error);
        });
      });

    if (this.proxy === null) {
      const ip = plan.ip as string;
      const dial = this.options.dialMap?.get(dialKey(ip, port)) ?? { host: ip, port };
      const mapped = dial.host !== ip || dial.port !== port;
      const recheck = (socket: Socket) => (): void => {
        const remote = canonicalIp(socket.remoteAddress ?? '') ?? '';
        if (remote !== dial.host)
          throw new FetchFailure('connection_error', 'remote address mismatch');
        // A dial-map target is the test's loopback port by design; the guard validated `ip`.
        if (!mapped && !this.options.guard.checkAddress(remote).allowed) {
          throw new FetchFailure('connection_error', 'remote address blocked');
        }
      };
      const raw = net.connect({ host: dial.host, port: dial.port, lookup: literalOnlyLookup });
      await withTimeout(raw, 'connect', recheck(raw));
      if (!isHttps) return { socket: raw, absoluteForm: false };
      const secure = tls.connect({
        socket: raw,
        servername,
        ALPNProtocols: ['http/1.1'],
        rejectUnauthorized: true,
        ...(this.ca ? { ca: this.ca } : {}),
        ...(servername === undefined
          ? {
              checkServerIdentity: (_h: string, cert: tls.PeerCertificate) =>
                tls.checkServerIdentity(hostname, cert),
            }
          : {}),
      });
      await withTimeout(secure, 'secureConnect');
      return { socket: secure, absoluteForm: false };
    }

    const proxy = this.proxy;
    const raw = net.connect({ host: proxy.host, port: proxy.port });
    await withTimeout(raw, 'connect');
    if (!isHttps) return { socket: raw, absoluteForm: true };
    // CONNECT host:port with the proxy credentials; the proxy resolves, guards and dials.
    const authority = hostname.includes(':') ? `[${hostname}]:${port}` : `${hostname}:${port}`;
    await new Promise<void>((resolve, reject) => {
      const request = http.request({
        method: 'CONNECT',
        path: authority,
        headers: { Host: authority, 'Proxy-Authorization': proxy.authorization },
        // No agent at all (`agent: false` would make Node create a fresh Agent and ignore createConnection).
        agent: undefined,
        createConnection: () => raw,
        lookup: refusingLookup,
      });
      const timer = setTimeout(() => {
        request.destroy(new FetchFailure('timeout', 'proxy connect timeout'));
      }, connectTimeout);
      request.once('connect', (response: IncomingMessage) => {
        clearTimeout(timer);
        if (response.statusCode === 200) return resolve();
        raw.destroy();
        const reason = String(response.headers[EGRESS_BLOCKED_HEADER] ?? '');
        if (response.statusCode === 403) {
          return reject(
            new ProxyBlocked(
              (BLOCKED_REASONS as readonly string[]).includes(reason)
                ? (reason as BlockedReason)
                : 'deny_list',
            ),
          );
        }
        reject(new FetchFailure('connection_error', `proxy CONNECT ${response.statusCode ?? 0}`));
      });
      request.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      request.end();
    });
    const secure = tls.connect({
      socket: raw,
      servername,
      ALPNProtocols: ['http/1.1'],
      rejectUnauthorized: true,
      ...(this.ca ? { ca: this.ca } : {}),
      ...(servername === undefined
        ? {
            checkServerIdentity: (_h: string, cert: tls.PeerCertificate) =>
              tls.checkServerIdentity(hostname, cert),
          }
        : {}),
    });
    await withTimeout(secure, 'secureConnect');
    return { socket: secure, absoluteForm: false };
  }

  /** One HTTP exchange; reads the body (decompressed, capped) only when `wantBody` says so. */
  private async request(plan: RequestPlan, maxBody: number): Promise<Response> {
    const { socket, absoluteForm } = await this.openSocket(plan);
    const headers = this.headers(plan.url, plan.accept);
    if (absoluteForm && this.proxy) headers['Proxy-Authorization'] = this.proxy.authorization;
    const path = absoluteForm
      ? plan.url.href.replace(/#.*$/, '')
      : `${plan.url.pathname}${plan.url.search}`;

    return new Promise<Response>((resolve, reject) => {
      let settled = false;
      const finish = (error: Error | null, response?: Response): void => {
        if (settled) return;
        settled = true;
        clearTimeout(headerTimer);
        plan.signal.removeEventListener('abort', onAbort);
        socket.destroy();
        if (error) reject(error);
        else resolve(response as Response);
      };
      const request = http.request({
        method: 'GET',
        path,
        headers,
        // No agent at all (`agent: false` would make Node create a fresh Agent and ignore createConnection).
        agent: undefined,
        setHost: false,
        createConnection: () => socket,
        lookup: refusingLookup,
        maxHeaderSize: this.options.maxHeaderBytes,
        insecureHTTPParser: false,
      });
      const headerTimer = setTimeout(
        () => request.destroy(new FetchFailure('timeout', 'header timeout')),
        this.options.headerTimeoutMs,
      );
      const onAbort = (): void => {
        request.destroy(new FetchFailure('timeout', 'deadline'));
      };
      plan.signal.addEventListener('abort', onAbort, { once: true });
      request.on('error', (error) => finish(error));
      request.once('response', (res: IncomingMessage) => {
        clearTimeout(headerTimer);
        // The socket is destroyed early on purpose (discarded bodies): never an unhandled error.
        res.on('error', () => undefined);
        if (res.rawHeaders.length / 2 > this.maxHeaderCount) {
          finish(new FetchFailure('header_limit', 'too many headers'));
          return;
        }
        const status = res.statusCode ?? 0;
        const contentType = String(res.headers['content-type'] ?? '');
        const location = typeof res.headers.location === 'string' ? res.headers.location : null;
        if (absoluteForm && status === 403 && res.headers[EGRESS_BLOCKED_HEADER] !== undefined) {
          const reason = String(res.headers[EGRESS_BLOCKED_HEADER]);
          finish(
            new ProxyBlocked(
              (BLOCKED_REASONS as readonly string[]).includes(reason)
                ? (reason as BlockedReason)
                : 'deny_list',
            ),
          );
          return;
        }
        if (!plan.wantBody(status, contentType)) {
          finish(null, { status, headers: res.headers, location, contentType, body: null });
          return;
        }
        this.readBody(res, maxBody).then(
          (body) => finish(null, { status, headers: res.headers, location, contentType, body }),
          (error: Error) => finish(error),
        );
      });
      request.end();
    });
  }

  /**
   * Reads at most `maxBody` raw bytes (then the socket is destroyed: the rest is discarded),
   * decompresses gzip/deflate/br with an output cap of 4 × `maxBody` (`too_large`), and keeps the
   * first `maxBody` decoded bytes.
   */
  private readBody(res: IncomingMessage, maxBody: number): Promise<Buffer> {
    const encoding = String(res.headers['content-encoding'] ?? 'identity')
      .trim()
      .toLowerCase();
    const decodedCap = maxBody * 4;
    let decoder: zlib.Gunzip | zlib.Inflate | zlib.BrotliDecompress | null = null;
    if (encoding === 'gzip' || encoding === 'x-gzip') decoder = zlib.createGunzip();
    else if (encoding === 'deflate') decoder = zlib.createInflate();
    else if (encoding === 'br') decoder = zlib.createBrotliDecompress();

    return new Promise<Buffer>((resolve, reject) => {
      const kept: Buffer[] = [];
      let keptBytes = 0;
      let decodedBytes = 0;
      let rawBytes = 0;
      let truncated = false;
      let done = false;
      const complete = (error: Error | null): void => {
        if (done) return;
        done = true;
        res.destroy();
        decoder?.destroy();
        if (error) reject(error);
        else resolve(Buffer.concat(kept, keptBytes));
      };
      const keep = (chunk: Buffer): void => {
        decodedBytes += chunk.length;
        if (decodedBytes > decodedCap) {
          complete(new FetchFailure('too_large', 'decompressed size'));
          return;
        }
        if (keptBytes < maxBody) {
          const part = chunk.subarray(0, maxBody - keptBytes);
          kept.push(part);
          keptBytes += part.length;
        }
      };
      if (decoder) {
        decoder.on('data', keep);
        decoder.once('end', () => complete(null));
        decoder.on('error', (error) => complete(truncated ? null : error));
      }
      res.on('data', (chunk: Buffer) => {
        if (done || truncated) return;
        let data = chunk;
        if (rawBytes + data.length >= maxBody) {
          data = data.subarray(0, maxBody - rawBytes);
          truncated = true;
        }
        rawBytes += data.length;
        if (decoder) decoder.write(data);
        else keep(data);
        if (truncated) {
          res.destroy();
          if (decoder) decoder.end();
          else complete(null);
        }
      });
      res.once('end', () => {
        if (decoder) decoder.end();
        else complete(null);
      });
      res.on('error', (error) => {
        if (!truncated) complete(error);
      });
      res.once('aborted', () => {
        if (!truncated) complete(new FetchFailure('connection_error', 'aborted'));
      });
    });
  }
}
