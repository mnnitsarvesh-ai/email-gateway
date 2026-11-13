import http, {
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import https from 'node:https';
import net, { type AddressInfo, type Socket } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type GuardedPosterOptions, GuardedPoster, WEBHOOK_USER_AGENT } from './guarded-post';
import { ConcurrencyLimiter } from './limiter';
import {
  dialMap,
  fakeDns,
  generatePki,
  listen,
  testGuard,
  type TestPki,
  type TestServer,
} from './net.test-support';
import { type GuardDecision, SsrfGuard } from './ssrf-guard';

interface Seen {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

const seen: Seen[] = [];
let connections = 0;

function routes(req: IncomingMessage, res: ServerResponse): void {
  const chunks: Buffer[] = [];
  req.on('data', (c: Buffer) => chunks.push(c));
  req.on('end', () => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    seen.push({
      method: req.method ?? '',
      path,
      headers: req.headers,
      body: Buffer.concat(chunks),
    });
    if (path === '/ok') {
      res.writeHead(204);
      res.end();
      return;
    }
    if (path === '/ok-body') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('received');
      return;
    }
    if (path === '/redirect') {
      res.writeHead(302, { location: '/target' });
      res.end();
      return;
    }
    if (path === '/retry') {
      res.writeHead(503, { 'retry-after': '7', 'content-type': 'text/plain' });
      res.end('busy, try later');
      return;
    }
    if (path === '/huge') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      const chunk = Buffer.alloc(16_384, 0x61);
      const pump = (): void => {
        while (!res.destroyed && res.write(chunk));
        if (!res.destroyed) res.once('drain', pump);
      };
      pump();
      return;
    }
    if (path === '/many-headers') {
      const headers: Record<string, string> = {};
      for (let i = 0; i < 150; i += 1) headers[`x-h${i}`] = '1';
      res.writeHead(200, headers);
      res.end('x');
      return;
    }
    if (path === '/big-headers') {
      res.writeHead(200, { 'x-big': 'a'.repeat(32_000) });
      res.end('x');
      return;
    }
    if (path === '/hang') return; // never answers
    res.writeHead(404);
    res.end();
  });
}

let pki: TestPki;
let plain: TestServer;
let secure: TestServer;
let plainServer: http.Server;
let secureServer: https.Server;
let map: Map<string, { host: string; port: number }>;

const { resolver } = fakeDns({
  'hooks.receiver.test': { v4: ['203.0.113.20'] },
  'wrong-name.test': { v4: ['203.0.113.20'] },
  'metadata-v4.test': { v4: ['169.254.169.254'] },
  'metadata-v6.test': { v6: ['fd00:ec2::254'] },
  'private.test': { v4: ['10.1.2.3'] },
  'rebind.test': { v4: ['203.0.113.20', '127.0.0.1'] },
  'rebind-v6.test': { v4: ['203.0.113.20'], v6: ['fc00::1'] },
  'nat64.test': { v6: ['64:ff9b::7f00:1'] },
  'mapped.test': { v6: ['::ffff:10.0.0.1'] },
});

function poster(extra: Partial<GuardedPosterOptions> = {}): GuardedPoster {
  return new GuardedPoster({
    guard: testGuard({ allowedPorts: [443, 80] }),
    resolver,
    connectTimeoutMs: 1000,
    totalTimeoutMs: 2500,
    maxResponseBytes: 4096,
    dialMap: map,
    ca: pki.ca,
    env: { appEnv: 'ci' },
    ...extra,
  });
}

const BODY = JSON.stringify({ id: 'evt', type: 'email.received', data: { n: 1 } });
const HEADERS = {
  'EG-Signature': 't=1,v1=abc',
  'EG-Event-Id': '0193a1b2-0000-8000-8000-000000000001',
  'Idempotency-Key': '0193a1b2-0000-8000-8000-000000000001',
};

beforeAll(async () => {
  pki = generatePki(['hooks.receiver.test']);
  plainServer = http.createServer(routes);
  secureServer = https.createServer({ key: pki.key, cert: pki.cert }, routes);
  for (const server of [plainServer, secureServer]) {
    server.on('connection', () => {
      connections += 1;
    });
  }
  plain = await listen(plainServer);
  secure = await listen(secureServer);
  map = dialMap({ '203.0.113.20:80': plain.port, '203.0.113.20:443': secure.port });
});
afterAll(async () => {
  await plain.close();
  await secure.close();
});
beforeEach(() => {
  seen.length = 0;
});

describe('GuardedPoster (W9)', () => {
  it('POSTs the body over TLS with exactly the caller headers plus the fixed set', async () => {
    const result = await poster().post({
      url: 'https://hooks.receiver.test/ok?tenant=a',
      headers: HEADERS,
      body: BODY,
    });
    expect(result).toMatchObject({
      outcome: 'succeeded',
      httpStatus: 204,
      blockedReason: null,
      errorCode: null,
      retryAfter: null,
    });
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    expect(seen).toHaveLength(1);
    const request = seen[0]!;
    expect(request.method).toBe('POST');
    expect(request.path).toBe('/ok');
    expect(request.body.toString('utf8')).toBe(BODY);
    expect(Object.keys(request.headers).sort()).toEqual([
      'accept-encoding',
      'connection',
      'content-length',
      'content-type',
      'eg-event-id',
      'eg-signature',
      'host',
      'idempotency-key',
      'user-agent',
    ]);
    expect(request.headers).toMatchObject({
      host: 'hooks.receiver.test',
      'user-agent': WEBHOOK_USER_AGENT,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(BODY)),
      'accept-encoding': 'identity',
      connection: 'close',
      'eg-signature': 't=1,v1=abc',
    });
  });

  it('never lets the caller override the fixed headers or add cookies', async () => {
    await poster().post({
      url: 'https://hooks.receiver.test/ok',
      headers: { ...HEADERS, 'User-Agent': 'evil', Cookie: 'a=b', Host: 'other.test' },
      body: BODY,
    });
    const headers = seen[0]!.headers;
    expect(headers['user-agent']).toBe(WEBHOOK_USER_AGENT);
    expect(headers.host).toBe('hooks.receiver.test');
    expect(headers.cookie).toBeUndefined();
  });

  it('keeps the first bytes of a 2xx body as the snippet', async () => {
    const result = await poster().post({
      url: 'https://hooks.receiver.test/ok-body',
      headers: {},
      body: BODY,
    });
    expect(result.outcome).toBe('succeeded');
    expect(result.snippetBytes.toString('utf8')).toBe('received');
  });

  it('reports a 3xx as redirect and never follows Location', async () => {
    const result = await poster().post({
      url: 'https://hooks.receiver.test/redirect',
      headers: {},
      body: BODY,
    });
    expect(result).toMatchObject({ outcome: 'redirect', httpStatus: 302, errorCode: 'http_302' });
    expect(seen.map((s) => s.path)).toEqual(['/redirect']);
    expect(JSON.stringify(result)).not.toContain('/target');
  });

  it('returns the status, Retry-After and the snippet of an error answer', async () => {
    const result = await poster().post({
      url: 'https://hooks.receiver.test/retry',
      headers: {},
      body: BODY,
    });
    expect(result).toMatchObject({
      outcome: 'http_error',
      httpStatus: 503,
      retryAfter: '7',
      errorCode: 'http_503',
    });
    expect(result.snippetBytes.toString('utf8')).toBe('busy, try later');
  });

  it('stops reading at maxResponseBytes without failing', async () => {
    const result = await poster({ maxResponseBytes: 1000 }).post({
      url: 'https://hooks.receiver.test/huge',
      headers: {},
      body: BODY,
    });
    expect(result.outcome).toBe('succeeded');
    expect(result.snippetBytes.length).toBe(1000);
  });

  it('refuses too many or too large response headers (too_large)', async () => {
    const many = await poster().post({
      url: 'https://hooks.receiver.test/many-headers',
      headers: {},
      body: BODY,
    });
    expect(many).toMatchObject({ outcome: 'too_large', errorCode: 'header_limit' });
    const big = await poster().post({
      url: 'https://hooks.receiver.test/big-headers',
      headers: {},
      body: BODY,
    });
    expect(big).toMatchObject({ outcome: 'too_large', errorCode: 'header_limit' });
  });

  it('times out a hanging endpoint within the total timeout', async () => {
    const started = Date.now();
    const result = await poster({ totalTimeoutMs: 400 }).post({
      url: 'https://hooks.receiver.test/hang',
      headers: {},
      body: BODY,
    });
    expect(result.outcome).toBe('timeout');
    expect(result.httpStatus).toBeNull();
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('times out the connect phase (TCP accepted, TLS never answered)', async () => {
    const sockets: Socket[] = [];
    const server = net.createServer((socket) => {
      sockets.push(socket); // accepts TCP, never speaks TLS
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const silent = {
      port: (server.address() as AddressInfo).port,
      close: () =>
        new Promise<void>((resolve) => {
          for (const s of sockets) s.destroy();
          server.close(() => resolve());
        }),
    };
    try {
      const result = await poster({
        connectTimeoutMs: 300,
        totalTimeoutMs: 5000,
        dialMap: dialMap({ '203.0.113.20:443': silent.port }),
      }).post({ url: 'https://hooks.receiver.test/ok', headers: {}, body: BODY });
      expect(result).toMatchObject({ outcome: 'timeout', errorCode: 'connect_timeout' });
    } finally {
      await silent.close();
    }
  });

  it('honours an external abort signal', async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 100);
    const result = await poster({ totalTimeoutMs: 5000 }).post({
      url: 'https://hooks.receiver.test/hang',
      headers: {},
      body: BODY,
      signal: controller.signal,
    });
    expect(result.outcome).toBe('timeout');
  });

  it('fails TLS when the certificate does not name the host or the CA is untrusted', async () => {
    const mismatch = await poster().post({
      url: 'https://wrong-name.test/ok',
      headers: {},
      body: BODY,
    });
    expect(mismatch.outcome).toBe('tls_error');
    const untrusted = await poster({ ca: pki.otherCa }).post({
      url: 'https://hooks.receiver.test/ok',
      headers: {},
      body: BODY,
    });
    expect(untrusted.outcome).toBe('tls_error');
    expect(seen).toHaveLength(0);
  });

  it('refuses plain http unless allowHttp (test seam), then POSTs', async () => {
    const refused = await poster().post({
      url: 'http://hooks.receiver.test/ok',
      headers: {},
      body: BODY,
    });
    expect(refused).toMatchObject({
      outcome: 'blocked',
      blockedReason: 'scheme',
      errorCode: 'blocked:scheme',
    });
    const allowed = await poster({ allowHttp: true }).post({
      url: 'http://hooks.receiver.test/ok',
      headers: {},
      body: BODY,
    });
    expect(allowed.outcome).toBe('succeeded');
  });

  it('refuses ports outside the allow-list, userinfo and other schemes', async () => {
    const p = poster({ guard: testGuard({ allowedPorts: [443] }) });
    expect(
      (await p.post({ url: 'https://hooks.receiver.test:8443/ok', headers: {}, body: BODY }))
        .blockedReason,
    ).toBe('port');
    expect(
      (await p.post({ url: 'https://user:pw@hooks.receiver.test/ok', headers: {}, body: BODY }))
        .blockedReason,
    ).toBe('name');
    expect(
      (await p.post({ url: 'ftp://hooks.receiver.test/', headers: {}, body: BODY })).outcome,
    ).toBe('blocked');
    expect((await p.post({ url: 'not a url', headers: {}, body: BODY })).blockedReason).toBe(
      'scheme',
    );
    expect(seen).toHaveLength(0);
  });

  it.each([
    ['https://127.0.0.1/', 'loopback'],
    ['https://[::1]/', 'loopback'],
    ['https://10.0.0.1/', 'private'],
    ['https://172.16.5.4/', 'private'],
    ['https://192.168.1.1/', 'private'],
    ['https://100.64.0.1/', 'cgnat'],
    ['https://169.254.10.1/', 'link_local'],
    ['https://[fe80::1]/', 'link_local'],
    ['https://169.254.169.254/latest/meta-data/', 'metadata'],
    ['https://[fd00:ec2::254]/', 'metadata'],
    ['https://[fc00::1]/', 'ula'],
    ['https://[::ffff:127.0.0.1]/', 'loopback'],
    ['https://[64:ff9b::a00:1]/', 'mapped'],
    ['https://0.0.0.0/', 'unspecified'],
    ['https://localhost/', 'name'],
    ['https://metadata.google.internal/', 'name'],
    ['https://metadata-v4.test/', 'metadata'],
    ['https://metadata-v6.test/', 'metadata'],
    ['https://private.test/', 'private'],
    ['https://nat64.test/', 'mapped'],
    ['https://mapped.test/', 'private'],
  ])('blocks %s (%s) without connecting', async (url, reason) => {
    const before = connections;
    const blocked: string[] = [];
    const result = await poster({ hooks: { onBlocked: (r) => blocked.push(r) } }).post({
      url,
      headers: {},
      body: BODY,
    });
    expect(result).toMatchObject({ outcome: 'blocked', blockedReason: reason });
    expect(result.errorCode).toBe(`blocked:${reason}`);
    expect(blocked).toEqual([reason]);
    expect(connections).toBe(before);
  });

  it('blocks DNS rebinding: one allowed and one internal answer', async () => {
    const before = connections;
    const v4 = await poster().post({ url: 'https://rebind.test/ok', headers: {}, body: BODY });
    expect(v4).toMatchObject({ outcome: 'blocked', blockedReason: 'loopback' });
    const v6 = await poster().post({ url: 'https://rebind-v6.test/ok', headers: {}, body: BODY });
    expect(v6).toMatchObject({ outcome: 'blocked', blockedReason: 'ula' });
    expect(connections).toBe(before);
  });

  it('reports NXDOMAIN as dns_error', async () => {
    const result = await poster().post({ url: 'https://unknown.test/ok', headers: {}, body: BODY });
    expect(result).toMatchObject({ outcome: 'dns_error', errorCode: 'dns_nxdomain' });
  });

  it('re-checks the connected remote address with the guard', async () => {
    // A guard that admits the literal before the connect but refuses it at the re-check: the
    // socket connects (the server sees a TCP connection) and no request is ever written.
    class FlippingGuard extends SsrfGuard {
      calls = 0;
      override checkAddress(_value: string): GuardDecision {
        this.calls += 1;
        return this.calls === 1 ? { allowed: true } : { allowed: false, reason: 'loopback' };
      }
    }
    const guard = new FlippingGuard({ allowedPorts: [plain.port] });
    const before = connections;
    const result = await poster({ guard, allowHttp: true, dialMap: new Map() }).post({
      url: `http://127.0.0.1:${plain.port}/ok`,
      headers: {},
      body: BODY,
    });
    expect(result).toMatchObject({ outcome: 'blocked', blockedReason: 'loopback' });
    expect(guard.calls).toBe(2);
    await new Promise((r) => setTimeout(r, 50));
    expect(connections).toBe(before + 1);
    expect(seen).toHaveLength(0);
  });

  it('reports a refused connection as connection_error', async () => {
    const closed = await listen(http.createServer());
    const port = closed.port;
    await closed.close();
    const result = await poster({ dialMap: dialMap({ '203.0.113.20:443': port }) }).post({
      url: 'https://hooks.receiver.test/ok',
      headers: {},
      body: BODY,
    });
    expect(result).toMatchObject({ outcome: 'connection_error', errorCode: 'ECONNREFUSED' });
  });

  it('bounds concurrency with the shared limiter', async () => {
    const limiter = new ConcurrencyLimiter(1);
    const p = poster({ limiter });
    const results = await Promise.all(
      [1, 2, 3].map(() =>
        p.post({ url: 'https://hooks.receiver.test/ok', headers: {}, body: BODY }),
      ),
    );
    expect(results.every((r) => r.outcome === 'succeeded')).toBe(true);
    expect(limiter.inFlight).toBe(0);
  });

  it('refuses every test seam outside APP_ENV local/ci', () => {
    const base = { guard: testGuard(), resolver, connectTimeoutMs: 1000, totalTimeoutMs: 2000 };
    for (const env of [{ appEnv: 'production' }, { appEnv: 'staging' }, 'production', undefined]) {
      expect(() => new GuardedPoster({ ...base, env, allowHttp: true })).toThrow(/allowHttp/);
      expect(() => new GuardedPoster({ ...base, env, dialMap: map })).toThrow(/dialMap/);
      expect(() => new GuardedPoster({ ...base, env, ca: 'pem' })).toThrow(/ca/);
    }
    // No seam: fine in production.
    expect(() => new GuardedPoster({ ...base, env: { appEnv: 'production' } })).not.toThrow();
    expect(
      () => new GuardedPoster({ ...base, env: { appEnv: 'local' }, allowHttp: true, dialMap: map }),
    ).not.toThrow();
  });
});
