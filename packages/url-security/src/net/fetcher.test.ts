import { gzipSync } from 'node:zlib';
import http, {
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import https from 'node:https';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { extractLandingFeatures } from '../landing';
import { createEgressProxy, type EgressProxy } from './egress-proxy';
import { GuardedFetcher, parseDialMap, type FetcherOptions } from './fetcher';
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

const seenHeaders: IncomingHttpHeaders[] = [];
let active = 0;
let maxActive = 0;
const bomb = gzipSync(Buffer.alloc(8 * 1024 * 1024));

function routes(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? '/', 'http://x');
  const path = url.pathname;
  seenHeaders.push(req.headers);
  active += 1;
  maxActive = Math.max(maxActive, active);
  res.once('close', () => {
    active -= 1;
  });
  const html = (body: string, status = 200): void => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body);
  };
  if (path === '/ok')
    return html(
      '<title>PayPal login</title><form action="https://collector.test/p"><input type=password></form>',
    );
  if (path === '/plain') {
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end('binary');
    return;
  }
  const hop = /^\/redirect\/(\d+)$/.exec(path);
  if (hop) {
    const n = Number(hop[1]);
    res.writeHead(302, { location: n === 0 ? '/ok' : `/redirect/${n - 1}` });
    res.end();
    return;
  }
  if (path === '/to') {
    res.writeHead(302, { location: url.searchParams.get('u') ?? '/' });
    res.end();
    return;
  }
  if (path === '/loop') {
    res.writeHead(301, { location: '/loop' });
    res.end();
    return;
  }
  if (path === '/meta')
    return html('<html><head><meta http-equiv="refresh" content="0; url=/ok"></head></html>');
  if (path === '/slow-headers') return; // never answers
  if (path === '/trickle') {
    res.writeHead(200, { 'content-type': 'text/html' });
    const timer = setInterval(() => res.write('x'), 200);
    res.once('close', () => clearInterval(timer));
    return;
  }
  if (path === '/huge') {
    res.writeHead(200, { 'content-type': 'text/html' });
    const chunk = Buffer.alloc(16384, 0x61);
    const pump = (): void => {
      while (!res.destroyed && res.write(chunk));
      if (!res.destroyed) res.once('drain', pump);
    };
    pump();
    return;
  }
  if (path === '/bomb') {
    res.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip' });
    res.end(bomb);
    return;
  }
  if (path === '/many-headers') {
    const headers: Record<string, string> = { 'content-type': 'text/html' };
    for (let i = 0; i < 150; i += 1) headers[`x-h${i}`] = '1';
    res.writeHead(200, headers);
    res.end('x');
    return;
  }
  if (path === '/big-headers') {
    res.writeHead(200, { 'content-type': 'text/html', 'x-big': 'a'.repeat(32_000) });
    res.end('x');
    return;
  }
  if (path === '/500') return html('err', 503);
  if (path === '/404') return html('nope', 404);
  if (path === '/cookie') {
    res.writeHead(302, { location: '/ok', 'set-cookie': 'session=secret; Path=/' });
    res.end();
    return;
  }
  if (path === '/slow-ok') {
    setTimeout(() => html('<p>ok</p>'), 150);
    return;
  }
  html('<p>default</p>');
}

let pki: TestPki;
let plain: TestServer;
let secure: TestServer;
const { resolver, queries } = fakeDns({
  'site.test': { v4: ['203.0.113.10'] },
  'other.test': { v4: ['203.0.113.10'] },
  'private.test': { v4: ['10.0.0.5'] },
  'mixed.test': { v4: ['203.0.113.10', '10.0.0.5'] },
  'meta-host.test': { v4: ['169.254.169.254'] },
  'v6loop.test': { v6: ['::1'] },
});
let map: Map<string, { host: string; port: number }>;

function fetcher(extra: Partial<FetcherOptions> = {}): GuardedFetcher {
  return new GuardedFetcher({
    guard: testGuard(),
    resolver,
    userAgent: 'TestScanner/1.0',
    connectTimeoutMs: 1000,
    headerTimeoutMs: 1000,
    totalTimeoutMs: 2500,
    maxHeaderBytes: 16384,
    maxBodyBytes: 16384,
    maxHops: 8,
    dialMap: map,
    ca: pki.ca,
    landing: (body, page) =>
      extractLandingFeatures(body, page, [
        { id: 'paypal', label: 'paypal', official: new Set(['paypal.com']) },
      ]),
    ...extra,
  });
}

beforeAll(async () => {
  pki = generatePki(['site.test', 'other.test']);
  plain = await listen(http.createServer(routes));
  secure = await listen(https.createServer({ key: pki.key, cert: pki.cert }, routes));
  map = dialMap({ '203.0.113.10:80': plain.port, '203.0.113.10:443': secure.port });
});
afterAll(async () => {
  await plain.close();
  await secure.close();
});

describe('GuardedFetcher (direct mode)', () => {
  it('fetches a page with exactly the allowed headers and extracts landing features', async () => {
    seenHeaders.length = 0;
    const result = await fetcher().fetchChain('http://user:pw@site.test/ok');
    expect(result).toMatchObject({
      status: 'completed',
      error: null,
      finalStatus: 200,
      finalUrl: 'http://site.test/ok',
      hops: [{ host: 'site.test', port: null, status: 200, kind: 'initial', blocked: null }],
      landing: {
        passwordFields: 1,
        forms: 1,
        crossOriginFormAction: true,
        formActionHosts: ['collector.test'],
        titleBrandMatches: ['paypal'],
      },
    });
    const headers = seenHeaders[0] ?? {};
    expect(Object.keys(headers).sort()).toEqual([
      'accept',
      'accept-encoding',
      'connection',
      'host',
      'user-agent',
    ]);
    expect(headers).toMatchObject({
      host: 'site.test',
      'user-agent': 'TestScanner/1.0',
      accept: 'text/html,*/*;q=0.5',
      'accept-encoding': 'gzip, deflate, br',
      connection: 'close',
    });
  });

  it('speaks TLS to the validated IP with SNI/identity of the URL host', async () => {
    const result = await fetcher().fetchChain('https://site.test/ok');
    expect(result).toMatchObject({ status: 'completed', finalStatus: 200 });
    const untrusted = await fetcher({ ca: pki.otherCa }).fetchChain('https://site.test/ok');
    expect(untrusted).toMatchObject({ status: 'error', error: 'tls_error' });
  });

  it('follows and records redirects, validating every hop', async () => {
    const result = await fetcher().fetchChain('http://site.test/redirect/3');
    expect(result.status).toBe('completed');
    expect(result.hops.map((h) => [h.kind, h.status])).toEqual([
      ['initial', 302],
      ['http', 302],
      ['http', 302],
      ['http', 302],
      ['http', 200],
    ]);
  });

  it('stops at the hop cap and on loops (redirect_limit)', async () => {
    // /redirect/n answers n + 1 redirects: 7 → 8 redirects (the cap), 8 → 9 (one too many).
    const eight = await fetcher().fetchChain('http://site.test/redirect/7');
    expect(eight).toMatchObject({ status: 'completed' });
    expect(eight.hops).toHaveLength(9);
    const limit = await fetcher().fetchChain('http://site.test/redirect/8');
    expect(limit).toMatchObject({ status: 'error', error: 'redirect_limit' });
    expect(limit.hops).toHaveLength(9);
    expect(await fetcher().fetchChain('http://site.test/loop')).toMatchObject({
      status: 'error',
      error: 'redirect_limit',
    });
  });

  it.each([
    ['http://127.0.0.1/', 'loopback'],
    ['http://2130706433/', 'loopback'],
    ['http://[::ffff:127.0.0.1]/', 'loopback'],
    ['http://169.254.169.254/latest/meta-data/', 'metadata'],
    ['http://[fd00:ec2::254]/', 'metadata'],
    ['http://10.0.0.5/', 'private'],
    ['http://metadata.google.internal/', 'name'],
    ['http://localhost/', 'name'],
    ['http://private.test/', 'private'],
    ['http://mixed.test/', 'private'],
    ['http://meta-host.test/', 'metadata'],
    ['http://v6loop.test/', 'loopback'],
    ['http://site.test:22/', 'port'],
    ['file:///etc/passwd', 'scheme'],
    ['gopher://site.test/', 'scheme'],
  ])('blocks a redirect to %s before connecting (%s)', async (target, reason) => {
    const before = seenHeaders.length;
    const result = await fetcher().fetchChain(
      `http://site.test/to?u=${encodeURIComponent(target)}`,
    );
    expect(result).toMatchObject({ status: 'blocked', blockedReason: reason });
    expect(result.hops.at(-1)?.blocked).toBe(reason);
    expect(seenHeaders.length).toBe(before + 1); // only the first hop reached a server
  });

  it('blocks a direct internal URL without any request', async () => {
    const before = seenHeaders.length;
    expect(await fetcher().fetchChain('http://private.test/')).toMatchObject({
      status: 'blocked',
      blockedReason: 'private',
      hops: [{ blocked: 'private' }],
    });
    expect(seenHeaders.length).toBe(before);
  });

  it('follows meta refresh hops', async () => {
    const result = await fetcher().fetchChain('http://site.test/meta');
    expect(result.status).toBe('completed');
    expect(result.hops.map((h) => h.kind)).toEqual(['initial', 'meta']);
  });

  it('never sends cookies it was given (Set-Cookie ignored)', async () => {
    seenHeaders.length = 0;
    await fetcher().fetchChain('http://site.test/cookie');
    expect(seenHeaders).toHaveLength(2);
    expect(seenHeaders[1]?.cookie).toBeUndefined();
    expect(seenHeaders[1]?.referer).toBeUndefined();
    expect(seenHeaders[1]?.authorization).toBeUndefined();
  });

  it('bounds time: header timeout and total timeout', async () => {
    const slow = await fetcher().fetchChain('http://site.test/slow-headers');
    expect(slow).toMatchObject({ status: 'error', error: 'timeout' });
    const started = Date.now();
    const trickle = await fetcher({ totalTimeoutMs: 800 }).fetchChain('http://site.test/trickle');
    expect(trickle).toMatchObject({ status: 'error', error: 'timeout' });
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('bounds the body (unbounded body is cut at the cap) and the decompressed size', async () => {
    const huge = await fetcher().fetchChain('http://site.test/huge');
    expect(huge).toMatchObject({ status: 'completed', finalStatus: 200 });
    const zip = await fetcher().fetchChain('http://site.test/bomb');
    expect(zip).toMatchObject({ status: 'error', error: 'too_large' });
  });

  it('bounds headers by bytes and by count', async () => {
    expect(await fetcher().fetchChain('http://site.test/big-headers')).toMatchObject({
      status: 'error',
      error: 'header_limit',
    });
    expect(await fetcher().fetchChain('http://site.test/many-headers')).toMatchObject({
      status: 'error',
      error: 'header_limit',
    });
  });

  it('reports a 5xx final as http_error, a 4xx as completed, non-HTML without landing', async () => {
    expect(await fetcher().fetchChain('http://site.test/500')).toMatchObject({
      status: 'error',
      error: 'http_error',
      finalStatus: 503,
    });
    expect(await fetcher().fetchChain('http://site.test/404')).toMatchObject({
      status: 'completed',
      finalStatus: 404,
    });
    expect(await fetcher().fetchChain('http://site.test/plain')).toMatchObject({
      status: 'completed',
      landing: null,
    });
  });

  it('maps DNS failures and connection failures', async () => {
    expect(await fetcher().fetchChain('http://nxdomain.test/')).toMatchObject({
      status: 'error',
      error: 'dns_error',
    });
    const noDial = await fetcher({
      dialMap: new Map([['203.0.113.10:80', { host: '127.0.0.1', port: 1 }]]),
    }).fetchChain('http://site.test/ok');
    expect(noDial).toMatchObject({ status: 'error', error: 'connection_error' });
  });

  it('fetches a resource with validated redirects (RDAP use)', async () => {
    const result = await fetcher().fetchResource('http://site.test/redirect/1', {
      accept: 'application/json',
      maxBytes: 1024,
    });
    expect(result).toMatchObject({ status: 'completed', httpStatus: 200 });
    expect(result.body?.toString()).toContain('password');
    expect(
      await fetcher().fetchResource('http://site.test/to?u=http%3A%2F%2F127.0.0.1%2F', {
        accept: 'application/json',
        maxBytes: 1024,
      }),
    ).toMatchObject({ status: 'blocked', blockedReason: 'loopback' });
  });

  it('limits global concurrency', async () => {
    maxActive = 0;
    const shared = new ConcurrencyLimiter(1);
    const f = fetcher({ limiter: shared });
    await Promise.all([
      f.fetchChain('http://site.test/slow-ok'),
      f.fetchChain('http://other.test/slow-ok'),
      f.fetchChain('http://site.test/slow-ok'),
    ]);
    expect(maxActive).toBe(1);
  });
});

describe('dial map (TEST-ONLY)', () => {
  it('parses entries and refuses production', () => {
    expect(
      parseDialMap('203.0.113.10:80=127.0.0.1:18080,[2001:db8::1]:443=127.0.0.1:18443', 'test'),
    ).toEqual(
      new Map([
        ['203.0.113.10:80', { host: '127.0.0.1', port: 18080 }],
        ['[2001:db8::1]:443', { host: '127.0.0.1', port: 18443 }],
      ]),
    );
    expect(parseDialMap('', 'production').size).toBe(0);
    expect(() => parseDialMap('203.0.113.10:80=127.0.0.1:18080', 'production')).toThrow(
      /production/,
    );
    expect(() =>
      parseDialMap('203.0.113.10:80=127.0.0.1:18080', {
        nodeEnv: 'production',
        appEnv: 'production',
      }),
    ).toThrow(/production/);
    expect(
      parseDialMap('203.0.113.10:80=127.0.0.1:18080', { nodeEnv: 'production', appEnv: 'local' })
        .size,
    ).toBe(1);
    expect(() => parseDialMap('host:80=127.0.0.1:1', 'test')).toThrow();
  });
});

describe('proxy client mode and the egress proxy', () => {
  let proxy: EgressProxy;
  let proxyPort: number;
  const proxyDns = fakeDns({
    'site.test': { v4: ['203.0.113.10'] },
    'private.test': { v4: ['10.0.0.5'] },
  });
  const blockedReasons: string[] = [];

  beforeAll(async () => {
    proxy = createEgressProxy({
      token: 'proxy-secret-token',
      guard: testGuard(),
      resolver: proxyDns.resolver,
      maxConnections: 8,
      maxBytesPerConnection: 1_000_000,
      idleTimeoutMs: 2000,
      maxConnectionMs: 5000,
      dialMap: map,
      hooks: { onBlocked: (reason) => blockedReasons.push(reason) },
    });
    proxyPort = await proxy.listen(0, '127.0.0.1');
  });
  afterAll(async () => {
    await proxy.close();
  });

  const viaProxy = (token = 'proxy-secret-token') =>
    fetcher({
      proxy: { url: `http://127.0.0.1:${proxyPort}`, token },
      // The client never resolves the target in proxy mode.
      resolver: fakeDns({}).resolver,
    });

  it('fetches http (absolute form) and https (CONNECT) through the proxy without client DNS', async () => {
    const before = queries.length;
    expect(await viaProxy().fetchChain('http://site.test/redirect/1')).toMatchObject({
      status: 'completed',
      finalStatus: 200,
    });
    expect(await viaProxy().fetchChain('https://site.test/ok')).toMatchObject({
      status: 'completed',
      finalStatus: 200,
    });
    expect(queries.length).toBe(before);
  });

  it('reports targets the proxy refused as blocked with its reason', async () => {
    blockedReasons.length = 0;
    expect(await viaProxy().fetchChain('http://private.test/')).toMatchObject({
      status: 'blocked',
      blockedReason: 'private',
    });
    expect(await viaProxy().fetchChain('https://private.test/')).toMatchObject({
      status: 'blocked',
      blockedReason: 'private',
    });
    // Literal internal addresses are refused by the client guard already.
    expect(await viaProxy().fetchChain('http://127.0.0.1/')).toMatchObject({
      status: 'blocked',
      blockedReason: 'loopback',
    });
    expect(blockedReasons).toEqual(['private', 'private']);
  });

  it('fails with a wrong proxy token', async () => {
    expect(
      await viaProxy('wrong-token-wrong-token').fetchChain('https://site.test/ok'),
    ).toMatchObject({ status: 'error', error: 'connection_error' });
  });
});
