import http, { type IncomingMessage, type OutgoingHttpHeaders } from 'node:http';
import net, { type Socket } from 'node:net';
import tls from 'node:tls';
import { canonicalIp } from '../normalize/ip';
import { classifyError, type DialTarget, untraced } from './fetcher';
import { ConcurrencyLimiter } from './limiter';
import { literalOnlyLookup } from './literal-lookup';
import type { RestrictedResolver } from './resolver';
import {
  type BlockedReason,
  type SsrfGuard,
  testSeamsAllowed,
  type TestSeamEnv,
} from './ssrf-guard';

/**
 * The guarded POST client of webhook deliveries (docs/plan/steps/19-webhooks-notifications.md
 * W9, ADR-0055; built on the U8 primitives of step 4.3). One request per call, no redirects, no
 * cookies, no proxy environment variables, no compression:
 *
 * 1. `guard.checkUrl` (scheme, port allow-list, name checks); `https` only unless the TEST-ONLY
 *    `allowHttp`; no userinfo.
 * 2. Resolution with the restricted resolver (A + AAAA, ≤ 16 answers each): **every** answer must
 *    pass `guard.checkAddress` (any blocked answer blocks the attempt: DNS rebinding with mixed
 *    answers is refused). An IP-literal host is checked as an address.
 * 3. The socket dials the validated IP literal (`lookup` refuses every name), TLS ≥ 1.2 with
 *    `servername` = host and certificate verification against the host name; the connected
 *    `remoteAddress` is re-checked (must equal the dialed literal and pass the guard).
 * 4. `POST` with exactly the caller's headers plus `Host`, `User-Agent: EmailGateway-Webhooks/1`,
 *    `Content-Type: application/json`, `Content-Length`, `Accept-Encoding: identity` and
 *    `Connection: close`. A 3xx is outcome `redirect` (`Location` is never followed or returned).
 * 5. Connect timeout (TCP + TLS), total timeout (the whole exchange), response headers ≤ 16 KiB and
 *    ≤ 100 lines, response body read up to `maxResponseBytes` (then reading stops; the outcome
 *    follows the status, it is not an error).
 *
 * Requests run with OpenTelemetry tracing suppressed (`untraced`): no `traceparent` header is
 * added to a tenant-controlled destination and no span records its URL.
 */

export const WEBHOOK_USER_AGENT = 'EmailGateway-Webhooks/1';

export const POST_OUTCOMES = [
  'succeeded',
  'http_error',
  'redirect',
  'timeout',
  'dns_error',
  'connection_error',
  'tls_error',
  'blocked',
  'too_large',
] as const;
export type PostOutcome = (typeof POST_OUTCOMES)[number];

export interface PostResult {
  outcome: PostOutcome;
  /** The response status (null when no response was received). */
  httpStatus: number | null;
  /** From the start of the call to the end of the exchange (or the failure). */
  latencyMs: number;
  /** The raw `Retry-After` header of the response, if any (parsed by the caller). */
  retryAfter: string | null;
  /** The first ≤ `maxResponseBytes` bytes of the response body (untrusted; sanitize before use). */
  snippetBytes: Buffer;
  /** The guard's reason when `outcome = blocked`. */
  blockedReason: BlockedReason | null;
  /** A bounded code (`ECONNREFUSED`, `blocked:loopback`, `http_503`, …), never free text. */
  errorCode: string | null;
}

export interface PostRequest {
  url: string;
  /** The exact header set of the request (the fixed headers above are added and win). */
  headers: Readonly<Record<string, string>>;
  body: string | Buffer;
  signal?: AbortSignal;
}

export interface GuardedPosterOptions {
  guard: SsrfGuard;
  resolver: RestrictedResolver;
  /** WEBHOOK_HTTP_CONNECT_TIMEOUT_MS: TCP connect plus TLS handshake. */
  connectTimeoutMs: number;
  /** WEBHOOK_HTTP_TOTAL_TIMEOUT_MS: the whole exchange, resolution included. */
  totalTimeoutMs: number;
  /** WEBHOOK_RESPONSE_MAX_BYTES (default 4 096). */
  maxResponseBytes?: number;
  /** Response header bytes (default 16 384). */
  maxHeaderBytes?: number;
  /** Response header lines (default 100). */
  maxHeaderCount?: number;
  /** Global concurrency of the process (share one limiter). */
  limiter?: ConcurrencyLimiter;
  /** TEST-ONLY: plain `http://` endpoints. */
  allowHttp?: boolean;
  /** TEST-ONLY: dial `ip:port` at another endpoint after the guard validated the address. */
  dialMap?: ReadonlyMap<string, DialTarget>;
  /** TEST-ONLY: an extra trusted CA (PEM), added to Node's root store. */
  ca?: string | Buffer | null;
  /** NODE_ENV / APP_ENV deciding whether the test seams are allowed (absent = production). */
  env?: TestSeamEnv;
  hooks?: {
    onBlocked?: (reason: BlockedReason) => void;
    onResult?: (result: PostResult) => void;
  };
}

/** Raised by the client itself; carries the outcome it maps to. */
class PostFailure extends Error {
  constructor(
    readonly outcome: Exclude<PostOutcome, 'succeeded' | 'http_error' | 'redirect'>,
    readonly code: string,
    readonly blockedReason: BlockedReason | null = null,
  ) {
    super(code);
    this.name = 'PostFailure';
  }
}

const refusingLookup = (): never => {
  throw new Error('DNS lookup is not allowed on the guarded connector');
};

const dialKey = (ip: string, port: number): string =>
  ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;

/** A bounded error code: an upper-case Node code, else the outcome name. */
const CODE = /^[A-Z][A-Z0-9_]{1,40}$/;

/** Maps a socket / TLS / parser error onto a POST outcome (the fetcher's classification). */
function failureOf(error: unknown): { outcome: PostOutcome; code: string } {
  if (error instanceof PostFailure) return { outcome: error.outcome, code: error.code };
  const kind = classifyError(error);
  const raw = (error as { code?: unknown } | null)?.code;
  const code = typeof raw === 'string' && CODE.test(raw) ? raw : kind;
  switch (kind) {
    case 'timeout':
      return { outcome: 'timeout', code };
    case 'tls_error':
      return { outcome: 'tls_error', code };
    case 'header_limit':
    case 'too_large':
      return { outcome: 'too_large', code: 'header_limit' };
    case 'http_error':
      // A malformed response (HPE_*): the endpoint answered garbage.
      return { outcome: 'connection_error', code };
    default:
      return { outcome: 'connection_error', code };
  }
}

export class GuardedPoster {
  private readonly ca: Array<string | Buffer> | undefined;
  private readonly limiter: ConcurrencyLimiter;
  private readonly maxResponseBytes: number;
  private readonly maxHeaderBytes: number;
  private readonly maxHeaderCount: number;
  private readonly allowHttp: boolean;
  private readonly dialMap: ReadonlyMap<string, DialTarget>;

  constructor(private readonly options: GuardedPosterOptions) {
    const seams: string[] = [];
    if (options.allowHttp) seams.push('allowHttp');
    if (options.dialMap && options.dialMap.size > 0) seams.push('dialMap');
    if (options.ca) seams.push('ca');
    if (seams.length > 0 && !testSeamsAllowed(options.env ?? 'production')) {
      throw new Error(
        `GuardedPoster test seams (${seams.join(', ')}) are refused outside APP_ENV local/ci`,
      );
    }
    if (!(options.connectTimeoutMs > 0) || !(options.totalTimeoutMs > 0)) {
      throw new Error('GuardedPoster timeouts must be positive');
    }
    this.ca = options.ca ? [...tls.rootCertificates, options.ca] : undefined;
    this.limiter = options.limiter ?? new ConcurrencyLimiter(32);
    this.maxResponseBytes = options.maxResponseBytes ?? 4096;
    this.maxHeaderBytes = options.maxHeaderBytes ?? 16_384;
    this.maxHeaderCount = options.maxHeaderCount ?? 100;
    this.allowHttp = options.allowHttp ?? false;
    this.dialMap = options.dialMap ?? new Map();
  }

  /** One guarded POST; never throws (every failure is an outcome). */
  async post(request: PostRequest): Promise<PostResult> {
    const started = Date.now();
    const total = AbortSignal.timeout(this.options.totalTimeoutMs);
    const signal = request.signal ? AbortSignal.any([request.signal, total]) : total;
    const result = await untraced(() =>
      this.limiter.run(() => this.exchange(request, signal, started), signal),
    ).catch((error: unknown) => this.failed(error, started));
    if (result.outcome === 'blocked' && result.blockedReason !== null) {
      this.options.hooks?.onBlocked?.(result.blockedReason);
    }
    this.options.hooks?.onResult?.(result);
    return result;
  }

  private failed(error: unknown, started: number): PostResult {
    const { outcome, code } = failureOf(error);
    const blockedReason = error instanceof PostFailure ? error.blockedReason : null;
    return {
      outcome,
      httpStatus: null,
      latencyMs: Date.now() - started,
      retryAfter: null,
      snippetBytes: Buffer.alloc(0),
      blockedReason,
      errorCode: code,
    };
  }

  private blocked(reason: BlockedReason): PostFailure {
    return new PostFailure('blocked', `blocked:${reason}`, reason);
  }

  /** Scheme, userinfo, port and name; then the address (literal, or every resolved answer). */
  private async validate(url: URL, signal: AbortSignal): Promise<string> {
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && this.allowHttp)) {
      throw this.blocked('scheme');
    }
    if (url.username !== '' || url.password !== '') throw this.blocked('name');
    const decision = this.options.guard.checkUrl(url);
    if (!decision.allowed) throw this.blocked(decision.reason);
    const literal = canonicalIp(url.hostname);
    if (literal !== null) return literal;
    const resolved = await this.options.resolver.resolveValidated(
      url.hostname,
      this.options.guard,
      signal,
    );
    if (resolved.ok) return resolved.address;
    if (resolved.blocked) throw this.blocked(resolved.reason);
    if (signal.aborted) throw new PostFailure('timeout', 'timeout');
    throw new PostFailure('dns_error', `dns_${resolved.error}`);
  }

  private async exchange(
    request: PostRequest,
    signal: AbortSignal,
    started: number,
  ): Promise<PostResult> {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      throw this.blocked('scheme');
    }
    const ip = await this.validate(url, signal);
    const socket = await this.connect(url, ip, signal);
    const body =
      typeof request.body === 'string' ? Buffer.from(request.body, 'utf8') : request.body;
    return this.send(socket, url, request.headers, body, signal, started);
  }

  /** TCP to the validated literal (or its TEST-ONLY dial-map target), then TLS for https. */
  private async connect(url: URL, ip: string, signal: AbortSignal): Promise<Socket> {
    const isHttps = url.protocol === 'https:';
    const port = url.port ? Number(url.port) : isHttps ? 443 : 80;
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    const servername = canonicalIp(hostname) === null ? hostname : undefined;
    const dial = this.dialMap.get(dialKey(ip, port)) ?? { host: ip, port };
    const mapped = dial.host !== ip || dial.port !== port;
    const deadline = Date.now() + this.options.connectTimeoutMs;

    const settle = <S extends Socket>(
      socket: S,
      event: 'connect' | 'secureConnect',
      check?: () => void,
    ): Promise<S> =>
      new Promise<S>((resolve, reject) => {
        const timer = setTimeout(
          () => {
            socket.destroy();
            reject(new PostFailure('timeout', 'connect_timeout'));
          },
          Math.max(1, deadline - Date.now()),
        );
        const onAbort = (): void => {
          clearTimeout(timer);
          socket.destroy();
          reject(new PostFailure('timeout', 'timeout'));
        };
        if (signal.aborted) return onAbort();
        signal.addEventListener('abort', onAbort, { once: true });
        socket.once(event, () => {
          clearTimeout(timer);
          signal.removeEventListener('abort', onAbort);
          try {
            check?.();
            resolve(socket);
          } catch (error) {
            socket.destroy();
            reject(error instanceof Error ? error : new PostFailure('connection_error', 'check'));
          }
        });
        // Stays attached: a late socket error never becomes an unhandled 'error' event.
        socket.on('error', (error) => {
          clearTimeout(timer);
          signal.removeEventListener('abort', onAbort);
          reject(error);
        });
      });

    const raw = net.connect({ host: dial.host, port: dial.port, lookup: literalOnlyLookup });
    await settle(raw, 'connect', () => {
      const remote = canonicalIp(raw.remoteAddress ?? '') ?? '';
      if (remote !== dial.host) {
        throw new PostFailure('connection_error', 'remote_address_mismatch');
      }
      // A dial-map target is the test's loopback port by design; the guard validated `ip`.
      if (!mapped) {
        const decision = this.options.guard.checkAddress(remote);
        if (!decision.allowed) throw this.blocked(decision.reason);
      }
    });
    if (!isHttps) return raw;
    const secure = tls.connect({
      socket: raw,
      servername,
      minVersion: 'TLSv1.2',
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
    return settle(secure, 'secureConnect');
  }

  private headers(
    url: URL,
    caller: Readonly<Record<string, string>>,
    length: number,
  ): OutgoingHttpHeaders {
    const fixed = new Set([
      'host',
      'user-agent',
      'content-type',
      'content-length',
      'accept-encoding',
      'connection',
      'transfer-encoding',
      'cookie',
      'proxy-authorization',
    ]);
    const headers: OutgoingHttpHeaders = { Host: url.host };
    for (const [name, value] of Object.entries(caller)) {
      if (fixed.has(name.toLowerCase())) continue;
      headers[name] = value;
    }
    headers['User-Agent'] = WEBHOOK_USER_AGENT;
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(length);
    headers['Accept-Encoding'] = 'identity';
    headers.Connection = 'close';
    return headers;
  }

  /** One POST on the connected socket; reads at most `maxResponseBytes` of the body. */
  private send(
    socket: Socket,
    url: URL,
    callerHeaders: Readonly<Record<string, string>>,
    body: Buffer,
    signal: AbortSignal,
    started: number,
  ): Promise<PostResult> {
    return new Promise<PostResult>((resolve, reject) => {
      let settled = false;
      const finish = (error: Error | null, result?: PostResult): void => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        socket.destroy();
        if (error !== null) reject(error);
        else resolve(result as PostResult);
      };
      const request = http.request({
        method: 'POST',
        path: `${url.pathname}${url.search}`,
        headers: this.headers(url, callerHeaders, body.length),
        // No agent at all (`agent: false` would create a fresh Agent and ignore createConnection).
        agent: undefined,
        setHost: false,
        createConnection: () => socket,
        lookup: refusingLookup,
        maxHeaderSize: this.maxHeaderBytes,
        insecureHTTPParser: false,
      });
      const onAbort = (): void => {
        request.destroy(new PostFailure('timeout', 'timeout'));
      };
      if (signal.aborted) {
        onAbort();
      } else {
        signal.addEventListener('abort', onAbort, { once: true });
      }
      request.on('error', (error) => finish(error));
      request.once('response', (res: IncomingMessage) => {
        // The socket is destroyed early on purpose (capped bodies): never an unhandled error.
        res.on('error', () => undefined);
        if (res.rawHeaders.length / 2 > this.maxHeaderCount) {
          finish(new PostFailure('too_large', 'header_limit'));
          return;
        }
        const status = res.statusCode ?? 0;
        const retryAfterHeader = res.headers['retry-after'];
        const retryAfter =
          typeof retryAfterHeader === 'string' && retryAfterHeader.length <= 64
            ? retryAfterHeader
            : null;
        const outcome: PostOutcome =
          status >= 200 && status < 300
            ? 'succeeded'
            : status >= 300 && status < 400
              ? 'redirect'
              : 'http_error';
        this.readCapped(res, signal).then(
          (snippet) =>
            finish(null, {
              outcome,
              httpStatus: status,
              latencyMs: Date.now() - started,
              retryAfter,
              snippetBytes: snippet,
              blockedReason: null,
              errorCode: outcome === 'succeeded' ? null : `http_${status}`,
            }),
          (error: unknown) =>
            finish(error instanceof Error ? error : new PostFailure('connection_error', 'read')),
        );
      });
      request.end(body);
    });
  }

  /**
   * Reads at most `maxResponseBytes` raw bytes, then stops (the rest is discarded, the socket
   * closed). The body is never decompressed (`Accept-Encoding: identity` was requested).
   */
  private readCapped(res: IncomingMessage, signal: AbortSignal): Promise<Buffer> {
    const cap = this.maxResponseBytes;
    return new Promise<Buffer>((resolve, reject) => {
      const kept: Buffer[] = [];
      let size = 0;
      let done = false;
      const complete = (error: Error | null): void => {
        if (done) return;
        done = true;
        signal.removeEventListener('abort', onAbort);
        res.destroy();
        if (error !== null) reject(error);
        else resolve(Buffer.concat(kept, size));
      };
      const onAbort = (): void => complete(new PostFailure('timeout', 'timeout'));
      if (signal.aborted) return onAbort();
      signal.addEventListener('abort', onAbort, { once: true });
      res.on('data', (chunk: Buffer) => {
        if (done) return;
        const part = chunk.subarray(0, cap - size);
        kept.push(part);
        size += part.length;
        if (size >= cap) complete(null);
      });
      res.once('end', () => complete(null));
      res.once('aborted', () => complete(null));
      res.once('close', () => complete(null));
    });
  }
}
