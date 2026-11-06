import http, { type IncomingHttpHeaders } from 'node:http';
import net from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  checkProxyAuthorization,
  createEgressProxy,
  type EgressProxy,
  type EgressResult,
} from './egress-proxy';
import { EGRESS_BLOCKED_HEADER, proxyAuthorization } from './fetcher';
import { dialMap, fakeDns, listen, testGuard, type TestServer } from './net.test-support';

const TOKEN = 'egress-token-0123456789abcdef';
let upstream: TestServer;
let proxy: EgressProxy;
let port: number;
const seen: IncomingHttpHeaders[] = [];
const results: EgressResult[] = [];
const bytes = { upstream: 0, downstream: 0 };

beforeAll(async () => {
  upstream = await listen(
    http.createServer((req, res) => {
      seen.push(req.headers);
      if (req.url === '/big') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end(Buffer.alloc(300_000, 0x61));
        return;
      }
      if (req.url === '/silent') return;
      res.writeHead(200, { 'content-type': 'text/plain', 'proxy-authenticate': 'x' });
      res.end('hello');
    }),
  );
  const { resolver } = fakeDns({
    'site.test': { v4: ['203.0.113.10'] },
    'private.test': { v4: ['10.0.0.5'] },
    'rebind.test': { v4: ['203.0.113.10', '127.0.0.1'] },
  });
  proxy = createEgressProxy({
    token: TOKEN,
    guard: testGuard(),
    resolver,
    maxConnections: 2,
    maxBytesPerConnection: 100_000,
    idleTimeoutMs: 300,
    maxConnectionMs: 2000,
    dialMap: dialMap({ '203.0.113.10:80': upstream.port, '203.0.113.10:443': upstream.port }),
    hooks: {
      onConnection: (result) => results.push(result),
      onBytes: (direction, n) => {
        bytes[direction] += n;
      },
    },
  });
  port = await proxy.listen(0, '127.0.0.1');
});
afterAll(async () => {
  await proxy.close();
  await upstream.close();
});

function forward(
  path: string,
  headers: Record<string, string> = {},
  method = 'GET',
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers });
    req.on('response', (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () =>
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString(),
        }),
      );
      res.on('error', reject);
      res.on('aborted', () =>
        resolve({ status: -1, headers: res.headers, body: Buffer.concat(chunks).toString() }),
      );
    });
    req.on('error', reject);
    req.end();
  });
}

function connect(
  authority: string,
  auth = proxyAuthorization(TOKEN),
): Promise<{ status: number; headers: Record<string, string>; socket: net.Socket }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nProxy-Authorization: ${auth}\r\n\r\n`,
      );
    });
    let buffer = '';
    const onData = (chunk: Buffer): void => {
      buffer += chunk.toString('latin1');
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      socket.off('data', onData);
      const [statusLine = '', ...lines] = buffer.slice(0, end).split('\r\n');
      const headers = Object.fromEntries(
        lines.map((l) => [
          l.slice(0, l.indexOf(':')).toLowerCase(),
          l.slice(l.indexOf(':') + 1).trim(),
        ]),
      );
      resolve({ status: Number(statusLine.split(' ')[1]), headers, socket });
    };
    socket.on('data', onData);
    socket.on('error', reject);
  });
}

describe('egress proxy', () => {
  it('requires Proxy-Authorization (constant-time token check)', async () => {
    expect((await forward('http://site.test/')).status).toBe(407);
    expect(
      (await forward('http://site.test/', { 'proxy-authorization': proxyAuthorization('wrong') }))
        .status,
    ).toBe(407);
    const tunnel = await connect('site.test:443', proxyAuthorization('wrong'));
    expect(tunnel.status).toBe(407);
    expect(tunnel.headers['proxy-authenticate']).toContain('Basic');
    tunnel.socket.destroy();
    expect(checkProxyAuthorization(proxyAuthorization(TOKEN), TOKEN)).toBe(true);
    expect(checkProxyAuthorization('Bearer x', TOKEN)).toBe(false);
    expect(checkProxyAuthorization(undefined, TOKEN)).toBe(false);
  });

  it('forwards absolute-form GET to the validated address and strips Proxy-* headers', async () => {
    seen.length = 0;
    const response = await forward('http://site.test/hello', {
      'proxy-authorization': proxyAuthorization(TOKEN),
      'proxy-connection': 'keep-alive',
      'x-test': '1',
    });
    expect(response).toMatchObject({ status: 200, body: 'hello' });
    expect(response.headers['proxy-authenticate']).toBeUndefined();
    expect(seen[0]?.['proxy-authorization']).toBeUndefined();
    expect(seen[0]?.['proxy-connection']).toBeUndefined();
    expect(seen[0]).toMatchObject({ host: 'site.test', 'x-test': '1' });
  });

  it('refuses other methods and non-http absolute targets', async () => {
    expect(
      (
        await forward(
          'http://site.test/',
          { 'proxy-authorization': proxyAuthorization(TOKEN) },
          'PUT',
        )
      ).status,
    ).toBe(405);
    expect(
      (
        await forward(
          'http://site.test/',
          { 'proxy-authorization': proxyAuthorization(TOKEN) },
          'DELETE',
        )
      ).status,
    ).toBe(405);
    const ftp = await forward('ftp://site.test/', {
      'proxy-authorization': proxyAuthorization(TOKEN),
    });
    expect(ftp.status).toBe(403);
  });

  it('runs the guard and the any-blocked resolver rule per request (403 with the reason)', async () => {
    const auth = { 'proxy-authorization': proxyAuthorization(TOKEN) };
    for (const [target, reason] of [
      ['http://private.test/', 'private'],
      ['http://rebind.test/', 'loopback'],
      ['http://127.0.0.1/', 'loopback'],
      ['http://169.254.169.254/latest/meta-data/', 'metadata'],
      ['http://localhost/', 'name'],
      ['http://site.test:22/', 'port'],
    ] as const) {
      const response = await forward(target, auth);
      expect(response.status).toBe(403);
      expect(response.headers[EGRESS_BLOCKED_HEADER]).toBe(reason);
    }
    for (const [authority, reason] of [
      ['private.test:443', 'private'],
      ['[::1]:443', 'loopback'],
      ['169.254.169.254:443', 'metadata'],
      ['site.test:25', 'port'],
    ] as const) {
      const tunnel = await connect(authority);
      expect(tunnel.status).toBe(403);
      expect(tunnel.headers[EGRESS_BLOCKED_HEADER]).toBe(reason);
      tunnel.socket.destroy();
    }
  });

  it('tunnels CONNECT to the validated address without terminating TLS', async () => {
    const tunnel = await connect('site.test:443');
    expect(tunnel.status).toBe(200);
    // The tunnel is a raw byte pipe: speak plain HTTP through it to the upstream test server.
    const answer = await new Promise<string>((resolve) => {
      let data = '';
      tunnel.socket.on('data', (c: Buffer) => {
        data += c.toString();
        if (data.includes('hello')) resolve(data);
      });
      tunnel.socket.write('GET /x HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n');
    });
    expect(answer).toContain('200');
    tunnel.socket.destroy();
  });

  it('caps bytes per connection and idle time', async () => {
    const big = await forward('http://site.test/big', {
      'proxy-authorization': proxyAuthorization(TOKEN),
    });
    expect(big.body.length).toBeLessThanOrEqual(100_000);
    expect(results).toContain('limit');
    const started = Date.now();
    const silent = await forward('http://site.test/silent', {
      'proxy-authorization': proxyAuthorization(TOKEN),
    }).catch(() => ({ status: -2 }));
    // The idle upstream is closed by the proxy: the client gets 502 (or a cut response) quickly.
    expect([502, -1, -2]).toContain(silent.status);
    expect(Date.now() - started).toBeLessThan(1900);
    expect(bytes.downstream).toBeGreaterThan(0);
  });

  it('limits concurrent connections (503 above the cap)', async () => {
    const a = await connect('site.test:443');
    const b = await connect('site.test:443');
    const c = await connect('site.test:443');
    expect([a.status, b.status]).toEqual([200, 200]);
    expect(c.status).toBe(503);
    for (const t of [a, b, c]) t.socket.destroy();
    await new Promise((r) => setTimeout(r, 50));
    expect(proxy.activeConnections).toBe(0);
  });
});
