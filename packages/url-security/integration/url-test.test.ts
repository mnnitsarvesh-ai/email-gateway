import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addressItems,
  ConcurrencyLimiter,
  DnsblProvider,
  GuardedFetcher,
  HostAddressResolver,
  ProtectedSet,
  RdapProvider,
  RestrictedResolver,
  SsrfGuard,
  createEgressProxy,
  extractLandingFeatures,
  loadBrands,
  parseDialMap,
  parseDnsblZones,
  type EgressProxy,
  type FetcherOptions,
} from '../src';

/**
 * Host-run integration of the URL security primitives against the TEST-ONLY smtp-test profile
 * (step 4.3 U19): dns-sink (127.0.0.1:${DNS_SINK_HOST_PORT}) is the only resolver, url-test is
 * reached through the dial map after the guard validated 203.0.113.10. Requires
 * `docker compose --profile smtp-test up -d test-pki dns-sink url-test`.
 */

const env = (name: string, fallback?: string): string => {
  const value = process.env[name] ?? fallback;
  if (value === undefined) throw new Error(`${name} is not set (.env, URL protection section)`);
  return value;
};

const repoRoot = resolve(__dirname, '../../..');
const dnsServers = [env('URL_DNS_SERVERS', `127.0.0.1:${env('DNS_SINK_HOST_PORT', '1053')}`)];
const dialMap = parseDialMap(env('URL_FETCH_TEST_DIAL_MAP'), { nodeEnv: 'test', appEnv: 'local' });
const resolver = new RestrictedResolver({ servers: dnsServers, timeoutMs: 2000, tries: 1 });
const guard = new SsrfGuard({
  testAllowCidrs: ['203.0.113.0/24'],
  nodeEnv: 'test',
  appEnv: 'local',
  clickHost: 'localhost',
});
const urlTestHttp = Number(env('URL_TEST_HTTP_HOST_PORT', '18080'));
let ca = '';
const brands = new ProtectedSet({ brands: loadBrands(), extraDomains: ['examplebank.test'] });

function fetcher(extra: Partial<FetcherOptions> = {}): GuardedFetcher {
  return new GuardedFetcher({
    guard,
    resolver,
    userAgent: 'Mozilla/5.0 (compatible; EmailGatewayLinkScanner/1.0)',
    connectTimeoutMs: 3000,
    headerTimeoutMs: 2000,
    totalTimeoutMs: 6000,
    maxHeaderBytes: 16384,
    maxBodyBytes: 262_144,
    maxHops: 8,
    ca,
    dialMap,
    limiter: new ConcurrencyLimiter(8),
    landing: (html, page) => extractLandingFeatures(html, page, brands.titleEntries()),
    ...extra,
  });
}

const reset = async (first: 'public' | 'private'): Promise<void> => {
  const response = await fetch(`http://127.0.0.1:${urlTestHttp}/reset?first=${first}`);
  expect(response.ok).toBe(true);
};

beforeAll(async () => {
  try {
    ca = execFileSync('docker', ['compose', 'exec', '-T', 'url-test', 'cat', '/pki/ca/ca.pem'], {
      cwd: repoRoot,
      encoding: 'utf8',
    });
  } catch {
    throw new Error(
      'url-test is not running: docker compose --profile smtp-test up -d test-pki dns-sink url-test',
    );
  }
  const health = await fetch(`http://127.0.0.1:${urlTestHttp}/health`).catch(() => null);
  if (!health?.ok) throw new Error('url-test is not reachable on its published port');
});

describe('restricted resolver against dns-sink', () => {
  it('resolves corpus names and applies the any-blocked rule', async () => {
    await expect(resolver.resolveValidated('clean-site.test', guard)).resolves.toMatchObject({
      ok: true,
      address: '203.0.113.10',
    });
    await expect(
      resolver.resolveValidated('xn--exmplebank-0qi.test', guard),
    ).resolves.toMatchObject({ ok: true });
    for (const [name, reason] of [
      ['private-a.test', 'private'],
      ['loopback-a.test', 'loopback'],
      ['meta-a.test', 'metadata'],
      ['cgnat-a.test', 'cgnat'],
      ['zero-a.test', 'unspecified'],
      ['v6-loop.test', 'loopback'],
      ['mapped-v6.test', 'loopback'],
      ['ula-v6.test', 'metadata'],
      ['mixed-a.test', 'private'],
    ] as const) {
      await expect(resolver.resolveValidated(name, guard)).resolves.toMatchObject({
        ok: false,
        blocked: true,
        reason,
      });
    }
    await expect(
      resolver.resolveValidated('nothing.invalid-zone.test', guard),
    ).resolves.toMatchObject({ ok: false, blocked: false });
  });
});

describe('guarded fetcher against url-test', () => {
  it('follows the clean shortener to the landing page', async () => {
    const result = await fetcher().fetchChain('http://short-link.test/s/clean');
    expect(result).toMatchObject({
      status: 'completed',
      finalUrl: 'http://clean-site.test/landing',
      finalStatus: 200,
    });
    expect(result.hops.map((h) => [h.host, h.status, h.kind])).toEqual([
      ['short-link.test', 301, 'initial'],
      ['clean-site.test', 200, 'http'],
    ]);
  });

  it('bounds redirect chains (2, 4, 10 redirects and a loop)', async () => {
    expect(
      (await fetcher().fetchChain('http://redirect-chain.test/hop/1/clean')).hops,
    ).toHaveLength(3);
    const four = await fetcher().fetchChain('http://redirect-chain.test/hop/3/clean');
    expect(four).toMatchObject({ status: 'completed' });
    expect(four.hops).toHaveLength(5);
    expect(await fetcher().fetchChain('http://short-link.test/s/chain10')).toMatchObject({
      status: 'error',
      error: 'redirect_limit',
    });
    expect(await fetcher().fetchChain('http://short-link.test/s/loop')).toMatchObject({
      status: 'error',
      error: 'redirect_limit',
    });
    const meta = await fetcher().fetchChain('http://short-link.test/s/meta');
    expect(meta.hops.map((h) => h.kind)).toEqual(['initial', 'http', 'meta']);
  });

  it.each([
    ['loopback', 'loopback'],
    ['loopback-short', 'loopback'],
    ['decimal', 'loopback'],
    ['octal', 'loopback'],
    ['hex', 'loopback'],
    ['v6-loopback', 'loopback'],
    ['v6-mapped-hex', 'loopback'],
    ['v6-mapped', 'loopback'],
    ['zero', 'unspecified'],
    ['private-10', 'private'],
    ['private-172', 'private'],
    ['private-192', 'private'],
    ['cgnat', 'cgnat'],
    ['metadata', 'metadata'],
    ['metadata-v6', 'metadata'],
    ['metadata-name', 'name'],
    ['localhost', 'name'],
    ['port22', 'port'],
    ['file', 'scheme'],
    ['gopher', 'scheme'],
  ])('refuses the redirect /to/%s (%s)', async (name, reason) => {
    const result = await fetcher().fetchChain(`http://clean-site.test/to/${name}`);
    expect(result).toMatchObject({ status: 'blocked', blockedReason: reason });
    expect(result.hops[0]).toMatchObject({ host: 'clean-site.test', status: 302 });
  });

  it('refuses shortener targets inside the platform and names resolving internally', async () => {
    expect(await fetcher().fetchChain('http://short-link.test/s/internal')).toMatchObject({
      status: 'blocked',
      blockedReason: 'loopback',
    });
    expect(await fetcher().fetchChain('http://short-link.test/s/metadata')).toMatchObject({
      status: 'blocked',
      blockedReason: 'metadata',
    });
    for (const name of [
      'private-a.test',
      'loopback-a.test',
      'meta-a.test',
      'mixed-a.test',
      'mapped-v6.test',
      'ula-v6.test',
    ]) {
      expect((await fetcher().fetchChain(`http://${name}/`)).status).toBe('blocked');
    }
  });

  it('DNS rebinding: private first → blocked; public first → the validated address; a redirect back re-resolves → blocked', async () => {
    await reset('private');
    expect(await fetcher().fetchChain('http://rebind.test/landing')).toMatchObject({
      status: 'blocked',
      blockedReason: 'loopback',
    });
    await reset('public');
    expect(await fetcher().fetchChain('http://rebind.test/landing')).toMatchObject({
      status: 'completed',
      finalStatus: 200,
    });
    await reset('public');
    const again = await fetcher().fetchChain('http://rebind.test/rebind-again');
    expect(again).toMatchObject({ status: 'blocked', blockedReason: 'loopback' });
    expect(again.hops.map((h) => [h.host, h.status, h.blocked])).toEqual([
      ['rebind.test', 302, null],
      ['rebind.test', null, 'loopback'],
    ]);
  });

  it('bounds slow, trickling, huge, many-header and gzip-bomb responses', async () => {
    expect(await fetcher().fetchChain('http://slow-site.test/')).toMatchObject({
      status: 'error',
      error: 'timeout',
    });
    const started = Date.now();
    expect(
      await fetcher({ totalTimeoutMs: 3000 }).fetchChain('http://trickle-site.test/'),
    ).toMatchObject({ status: 'error', error: 'timeout' });
    expect(Date.now() - started).toBeLessThan(5000);
    expect(await fetcher().fetchChain('http://huge-site.test/')).toMatchObject({
      status: 'completed',
      finalStatus: 200,
    });
    expect(await fetcher().fetchChain('http://many-headers.test/')).toMatchObject({
      status: 'error',
      error: 'header_limit',
    });
    expect(await fetcher().fetchChain('http://gzip-bomb.test/')).toMatchObject({
      status: 'error',
      error: 'too_large',
    });
  });

  it('extracts landing features over HTTPS with the test CA (credential forms, brand titles, IDN host)', async () => {
    const phish = await fetcher().fetchChain('https://phish-login.test/');
    expect(phish).toMatchObject({
      status: 'completed',
      landing: {
        passwordFields: 1,
        crossOriginFormAction: true,
        formActionHosts: ['collector-site.test'],
      },
    });
    const idn = await fetcher().fetchChain('https://xn--exmplebank-0qi.test/');
    expect(idn.landing).toMatchObject({
      passwordFields: 1,
      titleBrandMatches: ['examplebank.test'],
    });
    expect(await fetcher({ ca: null }).fetchChain('https://clean-site.test/landing')).toMatchObject(
      { status: 'error', error: 'tls_error' },
    );
  });
});

describe('reputation providers against dns-sink and url-test', () => {
  const signal = new AbortController().signal;
  it('dnsbl: test DBL phishing/malware, test RBL IP, NXDOMAIN clear', async () => {
    const provider = new DnsblProvider(resolver, {
      domainZones: parseDnsblZones(env('URL_DNSBL_DOMAIN_ZONES')),
      ipZones: parseDnsblZones(env('URL_DNSBL_IP_ZONES')),
    });
    const answers = await provider.lookup(
      [
        { kind: 'domain', value: 'evil-dbl.test' },
        { kind: 'domain', value: 'www.malware-dbl.test' },
        { kind: 'domain', value: 'clean-site.test' },
        { kind: 'ip', value: '203.0.113.66' },
        { kind: 'ip', value: '203.0.113.10' },
        { kind: 'ip', value: '198.51.100.99' },
      ],
      signal,
    );
    // 203.0.113.66 (bad-ip-host.test) is on the test RBL; the url-test server's 203.0.113.10 is not.
    expect(answers.map((a) => [a.status, a.category])).toEqual([
      ['listed', 'phishing'],
      ['listed', 'malware'],
      ['clear', null],
      ['listed', 'spam'],
      ['clear', null],
      ['clear', null],
    ]);
  });

  it('host addresses: bad-ip-host.test resolves to the RBL-listed 203.0.113.66 (resolved-IP reputation)', async () => {
    const addresses = await new HostAddressResolver(resolver, guard).resolve([
      'bad-ip-host.test',
      'clean-site.test',
      'private-a.test',
    ]);
    expect(Object.fromEntries(addresses)).toEqual({
      'bad-ip-host.test': ['203.0.113.66'],
      'clean-site.test': ['203.0.113.10'],
    });
    const provider = new DnsblProvider(resolver, {
      domainZones: [],
      ipZones: parseDnsblZones(env('URL_DNSBL_IP_ZONES')),
    });
    const [listed] = await provider.lookup(addressItems(['bad-ip-host.test'], addresses), signal);
    expect(listed).toMatchObject({ status: 'listed', category: 'spam' });
  });

  it('dnsbl: an unreachable resolver is error, never clear', async () => {
    const dead = new RestrictedResolver({ servers: ['127.0.0.1:9'], timeoutMs: 300, tries: 1 });
    const provider = new DnsblProvider(dead, {
      domainZones: parseDnsblZones('dbl.scan.test=127.0.1.4:phishing'),
      ipZones: [],
    });
    const [answer] = await provider.lookup([{ kind: 'domain', value: 'clean-site.test' }], signal);
    expect(answer?.status).toBe('error');
  });

  it('rdap: new-domain.test is new, others are old', async () => {
    const provider = new RdapProvider(fetcher(), {
      baseUrl: 'http://rdap.test',
      newDomainDays: 30,
    });
    const answers = await provider.lookup(
      [
        { kind: 'domain', value: 'new-domain.test' },
        { kind: 'domain', value: 'clean-site.test' },
      ],
      signal,
    );
    expect(answers.map((a) => [a.status, a.detail])).toEqual([
      ['listed', 'new_domain'],
      ['clear', null],
    ]);
  });
});

describe('egress proxy mode against url-test', () => {
  let proxy: EgressProxy;
  let port = 0;
  const token = 'integration-proxy-token-0123456789';
  beforeAll(async () => {
    proxy = createEgressProxy({
      token,
      guard,
      resolver,
      dialMap,
      maxConnections: 16,
      maxBytesPerConnection: 10_485_760,
      idleTimeoutMs: 5000,
      maxConnectionMs: 15_000,
    });
    port = await proxy.listen(0, '127.0.0.1');
  });
  afterAll(() => proxy.close());

  it('fetches through the proxy (CONNECT and absolute form); the proxy refuses internal targets', async () => {
    const viaProxy = fetcher({ proxy: { url: `http://127.0.0.1:${port}`, token } });
    expect(await viaProxy.fetchChain('https://clean-site.test/landing')).toMatchObject({
      status: 'completed',
      finalStatus: 200,
    });
    expect(await viaProxy.fetchChain('http://short-link.test/s/clean')).toMatchObject({
      status: 'completed',
      finalUrl: 'http://clean-site.test/landing',
    });
    expect(await viaProxy.fetchChain('http://private-a.test/')).toMatchObject({
      status: 'blocked',
      blockedReason: 'private',
    });
    expect(await viaProxy.fetchChain('https://meta-a.test/')).toMatchObject({
      status: 'blocked',
      blockedReason: 'metadata',
    });
    expect(await viaProxy.fetchChain('http://short-link.test/s/internal')).toMatchObject({
      status: 'blocked',
      blockedReason: 'loopback',
    });
  });
});
