import { timingSafeEqual } from 'node:crypto';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import net, { type Socket } from 'node:net';
import { Transform, type TransformCallback } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { canonicalIp } from '../normalize/ip';
import { EGRESS_BLOCKED_HEADER, type DialTarget } from './fetcher';
import { literalOnlyLookup } from './literal-lookup';
import { type RestrictedResolver } from './resolver';
import { type BlockedReason, type SsrfGuard } from './ssrf-guard';

/**
 * The egress proxy server (U15): an authenticated HTTP forward proxy for browser and fetcher
 * traffic. Absolute-form GET/HEAD/POST for http, CONNECT for https (TLS is never terminated).
 * Every request runs the same SsrfGuard + RestrictedResolver, dials the validated IP (no TOCTOU)
 * and re-checks `remoteAddress`. Caps: connections, bytes per connection (both directions), idle
 * time and connection duration. Refused targets get `403` with a bounded reason header; `Proxy-*`
 * request headers are stripped and nothing is added. WP4's url-egress-proxy entry point wraps it.
 */

export type EgressResult =
  | 'allowed'
  | 'blocked'
  | 'unauthorized'
  | 'bad_request'
  | 'method_not_allowed'
  | 'dns_error'
  | 'connect_error'
  | 'overloaded'
  | 'limit';

export interface EgressProxyHooks {
  onConnection?: (result: EgressResult, kind: 'connect' | 'forward') => void;
  onBlocked?: (reason: BlockedReason) => void;
  onBytes?: (direction: 'upstream' | 'downstream', bytes: number) => void;
  onActive?: (active: number) => void;
}

export interface EgressProxyOptions {
  /** URL_EGRESS_PROXY_TOKEN: the password of `Proxy-Authorization: Basic` (any user name). */
  token: string;
  guard: SsrfGuard;
  resolver: RestrictedResolver;
  /** URL_EGRESS_MAX_CONNECTIONS. */
  maxConnections: number;
  /** URL_EGRESS_MAX_BYTES_PER_CONNECTION (each direction). */
  maxBytesPerConnection: number;
  /** URL_EGRESS_IDLE_TIMEOUT_MS. */
  idleTimeoutMs: number;
  /** URL_EGRESS_MAX_CONNECTION_MS. */
  maxConnectionMs: number;
  connectTimeoutMs?: number;
  /** TEST-ONLY dial map (validated address → local endpoint), refused in production by its parser. */
  dialMap?: ReadonlyMap<string, DialTarget>;
  hooks?: EgressProxyHooks;
}

const FORWARD_METHODS = new Set(['GET', 'HEAD', 'POST']);
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

class ByteCap extends Transform {
  private total = 0;
  constructor(
    private readonly cap: number,
    private readonly onBytes: (n: number) => void,
  ) {
    super();
  }
  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.total += chunk.length;
    if (this.total > this.cap) {
      callback(new Error('byte limit'));
      return;
    }
    this.onBytes(chunk.length);
    callback(null, chunk);
  }
}

export function checkProxyAuthorization(header: string | undefined, token: string): boolean {
  if (!header) return false;
  const match = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header);
  if (!match) return false;
  const decoded = Buffer.from(match[1] as string, 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  if (colon < 0) return false;
  const given = Buffer.from(decoded.slice(colon + 1));
  const expected = Buffer.from(token);
  if (given.length !== expected.length) {
    timingSafeEqual(expected, expected);
    return false;
  }
  return timingSafeEqual(given, expected);
}

const dialKey = (ip: string, port: number): string =>
  ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;

export interface EgressProxy {
  readonly server: http.Server;
  listen(port: number, host?: string): Promise<number>;
  close(): Promise<void>;
  readonly activeConnections: number;
}

export function createEgressProxy(options: EgressProxyOptions): EgressProxy {
  const hooks = options.hooks ?? {};
  const connectTimeoutMs = options.connectTimeoutMs ?? 5000;
  let active = 0;
  const sockets = new Set<Socket>();
  const setActive = (delta: number): void => {
    active += delta;
    hooks.onActive?.(active);
  };

  /** Guard (scheme/port/name) → DNS + address (any-blocked) → validated IP. */
  async function resolveTarget(
    scheme: 'http' | 'https',
    host: string,
    port: number,
  ): Promise<{ ip: string } | { blocked: BlockedReason } | { error: 'dns_error' }> {
    const authority = host.includes(':') ? `[${host}]` : host;
    const decision = options.guard.checkUrl(`${scheme}://${authority}:${port}/`);
    if (!decision.allowed) return { blocked: decision.reason };
    const literal = canonicalIp(host);
    if (literal !== null) return { ip: literal };
    const resolved = await options.resolver.resolveValidated(host, options.guard);
    if (resolved.ok) return { ip: resolved.address };
    if (resolved.blocked) return { blocked: resolved.reason };
    return { error: 'dns_error' };
  }

  /** Dials the validated IP and re-checks the connected address. */
  function dial(ip: string, port: number): Promise<Socket> {
    const target = options.dialMap?.get(dialKey(ip, port)) ?? { host: ip, port };
    const mapped = target.host !== ip || target.port !== port;
    return new Promise<Socket>((resolve, reject) => {
      const socket = net.connect({
        host: target.host,
        port: target.port,
        lookup: literalOnlyLookup,
      });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error('connect timeout'));
      }, connectTimeoutMs);
      socket.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      socket.once('connect', () => {
        clearTimeout(timer);
        const remote = canonicalIp(socket.remoteAddress ?? '') ?? '';
        if (remote !== target.host || (!mapped && !options.guard.checkAddress(remote).allowed)) {
          socket.destroy();
          reject(new Error('remote address check failed'));
          return;
        }
        resolve(socket);
      });
    });
  }

  function limitSocket(socket: Socket): void {
    socket.setTimeout(options.idleTimeoutMs, () => socket.destroy());
    const timer = setTimeout(() => socket.destroy(), options.maxConnectionMs);
    socket.once('close', () => clearTimeout(timer));
  }

  const refuse = (
    res: ServerResponse,
    status: number,
    extra: Record<string, string> = {},
  ): void => {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(status, { 'content-type': 'text/plain', connection: 'close', ...extra });
    res.end(`${status}\n`);
  };

  const refuseSocket = (
    socket: Socket,
    status: number,
    text: string,
    extra: Record<string, string> = {},
  ): void => {
    const headers = Object.entries({ 'Content-Length': '0', Connection: 'close', ...extra })
      .map(([k, v]) => `${k}: ${v}\r\n`)
      .join('');
    socket.end(`HTTP/1.1 ${status} ${text}\r\n${headers}\r\n`);
  };

  const server = http.createServer();
  server.maxHeadersCount = 100;
  server.headersTimeout = 10_000;
  server.requestTimeout = options.maxConnectionMs;

  server.on('connection', (socket: Socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => undefined);
  });

  // Absolute-form forward proxy for http:// targets.
  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      if (!checkProxyAuthorization(req.headers['proxy-authorization'], options.token)) {
        hooks.onConnection?.('unauthorized', 'forward');
        refuse(res, 407, { 'proxy-authenticate': 'Basic realm="egress"' });
        return;
      }
      if (!FORWARD_METHODS.has(req.method ?? '')) {
        hooks.onConnection?.('method_not_allowed', 'forward');
        refuse(res, 405);
        return;
      }
      let target: URL;
      try {
        target = new URL(req.url ?? '');
      } catch {
        hooks.onConnection?.('bad_request', 'forward');
        refuse(res, 400);
        return;
      }
      if (target.protocol !== 'http:') {
        hooks.onConnection?.('blocked', 'forward');
        hooks.onBlocked?.('scheme');
        refuse(res, 403, { [EGRESS_BLOCKED_HEADER]: 'scheme' });
        return;
      }
      if (active >= options.maxConnections) {
        hooks.onConnection?.('overloaded', 'forward');
        refuse(res, 503);
        return;
      }
      setActive(1);
      res.once('close', () => setActive(-1));
      const host = target.hostname.replace(/^\[|\]$/g, '');
      const port = target.port ? Number(target.port) : 80;
      const resolved = await resolveTarget('http', host, port);
      if ('blocked' in resolved) {
        hooks.onConnection?.('blocked', 'forward');
        hooks.onBlocked?.(resolved.blocked);
        refuse(res, 403, { [EGRESS_BLOCKED_HEADER]: resolved.blocked });
        return;
      }
      if ('error' in resolved) {
        hooks.onConnection?.('dns_error', 'forward');
        refuse(res, 502);
        return;
      }
      let upstreamSocket: Socket;
      try {
        upstreamSocket = await dial(resolved.ip, port);
      } catch {
        hooks.onConnection?.('connect_error', 'forward');
        refuse(res, 502);
        return;
      }
      limitSocket(upstreamSocket);
      const headers: Record<string, string | string[]> = {};
      for (const [name, value] of Object.entries(req.headers)) {
        if (value === undefined || HOP_BY_HOP.has(name) || name.startsWith('proxy-')) continue;
        headers[name] = value;
      }
      headers.host = target.host;
      headers.connection = 'close';
      const upstream = http.request({
        method: req.method,
        path: `${target.pathname}${target.search}`,
        headers,
        // No agent at all (`agent: false` would make Node create a fresh Agent and ignore createConnection).
        agent: undefined,
        setHost: false,
        createConnection: () => upstreamSocket,
      });
      upstream.on('error', () => {
        hooks.onConnection?.('connect_error', 'forward');
        refuse(res, 502);
      });
      upstream.once('response', (upstreamRes) => {
        hooks.onConnection?.('allowed', 'forward');
        const responseHeaders: Record<string, string | string[]> = {};
        for (const [name, value] of Object.entries(upstreamRes.headers)) {
          if (value === undefined || HOP_BY_HOP.has(name)) continue;
          responseHeaders[name] = value;
        }
        responseHeaders.connection = 'close';
        res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);
        pipeline(
          upstreamRes,
          new ByteCap(options.maxBytesPerConnection, (n) => hooks.onBytes?.('downstream', n)),
          res,
        ).catch(() => {
          hooks.onConnection?.('limit', 'forward');
          res.destroy();
          upstreamSocket.destroy();
        });
      });
      pipeline(
        req,
        new ByteCap(options.maxBytesPerConnection, (n) => hooks.onBytes?.('upstream', n)),
        upstream,
      ).catch(() => {
        upstream.destroy();
        res.destroy();
      });
    })();
  });

  // CONNECT tunnels for https:// targets (TLS stays end to end).
  server.on('connect', (req: IncomingMessage, client: Socket, head: Buffer) => {
    void (async () => {
      client.on('error', () => undefined);
      if (!checkProxyAuthorization(req.headers['proxy-authorization'], options.token)) {
        hooks.onConnection?.('unauthorized', 'connect');
        refuseSocket(client, 407, 'Proxy Authentication Required', {
          'Proxy-Authenticate': 'Basic realm="egress"',
        });
        return;
      }
      const match = /^(\[[0-9a-fA-F:.]+\]|[^:[\]]+):(\d{1,5})$/.exec(req.url ?? '');
      if (!match) {
        hooks.onConnection?.('bad_request', 'connect');
        refuseSocket(client, 400, 'Bad Request');
        return;
      }
      if (active >= options.maxConnections) {
        hooks.onConnection?.('overloaded', 'connect');
        refuseSocket(client, 503, 'Service Unavailable');
        return;
      }
      setActive(1);
      client.once('close', () => setActive(-1));
      const host = (match[1] as string).replace(/^\[|\]$/g, '');
      const port = Number(match[2]);
      const resolved = await resolveTarget('https', host, port);
      if ('blocked' in resolved) {
        hooks.onConnection?.('blocked', 'connect');
        hooks.onBlocked?.(resolved.blocked);
        refuseSocket(client, 403, 'Forbidden', { [EGRESS_BLOCKED_HEADER]: resolved.blocked });
        return;
      }
      if ('error' in resolved) {
        hooks.onConnection?.('dns_error', 'connect');
        refuseSocket(client, 502, 'Bad Gateway');
        return;
      }
      let upstream: Socket;
      try {
        upstream = await dial(resolved.ip, port);
      } catch {
        hooks.onConnection?.('connect_error', 'connect');
        refuseSocket(client, 502, 'Bad Gateway');
        return;
      }
      hooks.onConnection?.('allowed', 'connect');
      limitSocket(upstream);
      limitSocket(client);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      const close = (): void => {
        upstream.destroy();
        client.destroy();
      };
      pipeline(
        client,
        new ByteCap(options.maxBytesPerConnection, (n) => hooks.onBytes?.('upstream', n)),
        upstream,
      ).catch(close);
      pipeline(
        upstream,
        new ByteCap(options.maxBytesPerConnection, (n) => hooks.onBytes?.('downstream', n)),
        client,
      ).catch(close);
    })();
  });

  return {
    server,
    get activeConnections() {
      return active;
    },
    listen(port: number, host = '0.0.0.0'): Promise<number> {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          const address = server.address();
          resolve(typeof address === 'object' && address ? address.port : port);
        });
      });
    },
    close(): Promise<void> {
      return new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      });
    },
  };
}
