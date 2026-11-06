import { describe, expect, it } from 'vitest';
import { RestrictedResolver, type DnsBackend } from './resolver';
import {
  SsrfGuard,
  canonicalizeAddress,
  validateTestAllowCidrs,
  type BlockedReason,
} from './ssrf-guard';

const guard = new SsrfGuard();
const reason = (address: string, g = guard): BlockedReason | 'allowed' => {
  const decision = g.checkAddress(address);
  return decision.allowed ? 'allowed' : decision.reason;
};

describe('SsrfGuard addresses: every non-globally-reachable IPv4 range', () => {
  it.each<[string, BlockedReason]>([
    ['0.0.0.0', 'unspecified'],
    ['0.255.255.255', 'unspecified'],
    ['10.0.0.5', 'private'],
    ['10.255.255.255', 'private'],
    ['100.64.0.1', 'cgnat'],
    ['100.127.255.255', 'cgnat'],
    ['127.0.0.1', 'loopback'],
    ['127.255.255.254', 'loopback'],
    ['169.254.169.254', 'metadata'],
    ['169.254.170.2', 'metadata'],
    ['169.254.1.1', 'link_local'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.0.0.8', 'reserved'],
    ['192.0.2.1', 'documentation'],
    ['192.88.99.1', 'reserved'],
    ['192.168.1.1', 'private'],
    ['198.18.0.1', 'reserved'],
    ['198.19.255.255', 'reserved'],
    ['198.51.100.7', 'documentation'],
    ['203.0.113.10', 'documentation'],
    ['224.0.0.1', 'multicast'],
    ['239.255.255.255', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['255.255.255.255', 'reserved'],
  ])('%s → %s', (address, expected) => {
    expect(reason(address)).toBe(expected);
  });

  it.each([
    '8.8.8.8',
    '1.1.1.1',
    '100.63.255.255',
    '100.128.0.0',
    '172.15.255.255',
    '172.32.0.0',
    '192.169.0.1',
    '198.17.255.255',
    '198.20.0.0',
    '223.255.255.255',
  ])('%s (global) is allowed', (address) => {
    expect(reason(address)).toBe('allowed');
  });
});

describe('SsrfGuard addresses: every non-globally-reachable IPv6 range', () => {
  it.each<[string, BlockedReason]>([
    ['::', 'unspecified'],
    ['::1', 'loopback'],
    ['64:ff9b:1::1', 'reserved'],
    ['100::1', 'reserved'],
    ['2001::1', 'reserved'], // Teredo
    ['2001:1ff:ffff::1', 'reserved'], // end of 2001::/23
    ['2001:db8::1', 'documentation'],
    ['3fff::1', 'documentation'],
    ['3fff:fff::1', 'documentation'],
    ['5f00::1', 'reserved'],
    ['fc00::1', 'ula'],
    ['fd12:3456::1', 'ula'],
    ['fd00:ec2::254', 'metadata'],
    ['fe80::1', 'link_local'],
    ['febf::1', 'link_local'],
    ['fec0::1', 'reserved'],
    ['ff02::1', 'multicast'],
    ['4000::1', 'reserved'], // outside 2000::/3
  ])('%s → %s', (address, expected) => {
    expect(reason(address)).toBe(expected);
  });

  it.each(['2606:4700:4700::1111', '2001:4860:4860::8888', '2a00:1450::1', '2001:200::1'])(
    '%s (global) is allowed',
    (address) => {
      expect(reason(address)).toBe('allowed');
    },
  );
});

describe('SsrfGuard canonicalization of every IPv4-in-IPv6 encoding', () => {
  it.each<[string, BlockedReason | 'allowed']>([
    ['::ffff:127.0.0.1', 'loopback'], // IPv4-mapped (dotted)
    ['::ffff:7f00:1', 'loopback'], // IPv4-mapped (hex)
    ['[::ffff:7f00:1]', 'loopback'],
    ['::ffff:169.254.169.254', 'metadata'],
    ['::ffff:10.0.0.5', 'private'],
    ['::ffff:8.8.8.8', 'allowed'],
    ['::127.0.0.1', 'loopback'], // IPv4-compatible
    ['::a00:5', 'private'], // IPv4-compatible 10.0.0.5
    ['64:ff9b::7f00:1', 'mapped'], // NAT64 → 127.0.0.1
    ['64:ff9b::a9fe:a9fe', 'mapped'], // NAT64 → 169.254.169.254
    ['64:ff9b::808:808', 'allowed'], // NAT64 → 8.8.8.8
    ['2002:7f00:1::1', 'mapped'], // 6to4 → 127.0.0.1
    ['2002:a00:5::', 'mapped'], // 6to4 → 10.0.0.5
    ['2002:808:808::1', 'allowed'], // 6to4 → 8.8.8.8
  ])('%s → %s', (address, expected) => {
    expect(reason(address)).toBe(expected);
  });

  it('reduces mapped/compatible forms to the IPv4 and reports the embedded IPv4 of NAT64/6to4', () => {
    expect(canonicalizeAddress('::ffff:7f00:1')).toEqual({
      address: '127.0.0.1',
      family: 'ipv4',
      embeddedIpv4: null,
    });
    expect(canonicalizeAddress('64:ff9b::a00:5')).toEqual({
      address: '64:ff9b::a00:5',
      family: 'ipv6',
      embeddedIpv4: '10.0.0.5',
    });
    expect(canonicalizeAddress('2002:c000:0201::')).toMatchObject({ embeddedIpv4: '192.0.2.1' });
    expect(canonicalizeAddress('not-an-ip')).toBeNull();
    expect(reason('not-an-ip')).toBe('reserved');
  });
});

describe('SsrfGuard names, ports, schemes, deny lists', () => {
  it.each([
    'localhost',
    'LOCALHOST.',
    'a.localhost',
    'printer.local',
    'metadata.google.internal',
    'x.internal',
    'router.home.arpa',
    'box.localdomain',
    'metadata',
    'instance-data',
    'metadata.azure.internal',
    'intranet',
  ])('blocks the name %s before DNS', (name) => {
    expect(guard.checkHostName(name)).toEqual({ allowed: false, reason: 'name' });
  });

  it('checks IP literal hosts as addresses and allows ordinary names', () => {
    expect(guard.checkUrl('http://127.0.0.1/')).toEqual({ allowed: false, reason: 'loopback' });
    expect(guard.checkUrl('http://[::1]/')).toEqual({ allowed: false, reason: 'loopback' });
    expect(guard.checkUrl('http://[::ffff:127.0.0.1]/')).toEqual({
      allowed: false,
      reason: 'loopback',
    });
    expect(guard.checkUrl('http://2130706433/')).toEqual({ allowed: false, reason: 'loopback' });
    expect(guard.checkUrl('http://0x7f.1/')).toEqual({ allowed: false, reason: 'loopback' });
    expect(guard.checkUrl('https://example.com/')).toEqual({ allowed: true });
  });

  it('allows only the configured ports (default 80, 443) and http(s)', () => {
    expect(guard.checkUrl('http://example.com:22/')).toEqual({ allowed: false, reason: 'port' });
    expect(guard.checkUrl('http://example.com:8080/')).toEqual({ allowed: false, reason: 'port' });
    expect(guard.checkUrl('https://example.com:443/')).toEqual({ allowed: true });
    expect(
      new SsrfGuard({ allowedPorts: [80, 443, 8080] }).checkUrl('http://example.com:8080/'),
    ).toEqual({ allowed: true });
    for (const url of [
      'file:///etc/passwd',
      'gopher://example.com/',
      'ftp://example.com/',
      'ws://example.com/',
      'not a url',
    ]) {
      expect(guard.checkUrl(url)).toEqual({ allowed: false, reason: 'scheme' });
    }
  });

  it('applies the deny lists and the click host (loop prevention)', () => {
    const g = new SsrfGuard({
      denyCidrs: ['8.8.8.0/24', '2606:4700::/32'],
      denyHosts: ['corp.example'],
      clickHost: 'protect.example.com',
    });
    expect(reason('8.8.8.8', g)).toBe('deny_list');
    expect(reason('2606:4700:4700::1111', g)).toBe('deny_list');
    expect(reason('8.8.4.4', g)).toBe('allowed');
    expect(g.checkHostName('vpn.corp.example')).toEqual({ allowed: false, reason: 'deny_list' });
    expect(g.checkHostName('protect.example.com')).toEqual({ allowed: false, reason: 'name' });
    expect(() => new SsrfGuard({ denyCidrs: ['nope'] })).toThrow();
    expect(() => new SsrfGuard({ allowedPorts: [0] })).toThrow();
  });
});

describe('test allow list (TEST-ONLY seam)', () => {
  it('allows only documentation ranges and keeps everything else blocked', () => {
    const g = new SsrfGuard({ testAllowCidrs: ['203.0.113.0/24'], nodeEnv: 'test' });
    expect(reason('203.0.113.10', g)).toBe('allowed');
    expect(reason('198.51.100.7', g)).toBe('documentation');
    expect(reason('127.0.0.1', g)).toBe('loopback');
    expect(reason('10.0.0.5', g)).toBe('private');
    expect(reason('169.254.169.254', g)).toBe('metadata');
    const deny = new SsrfGuard({
      testAllowCidrs: ['203.0.113.0/24'],
      denyCidrs: ['203.0.113.10/32'],
      nodeEnv: 'test',
    });
    expect(reason('203.0.113.10', deny)).toBe('deny_list');
  });

  it.each([
    '10.0.0.0/8',
    '127.0.0.0/8',
    '0.0.0.0/0',
    '203.0.112.0/23',
    '169.254.169.254/32',
    '2001:db8::/32',
  ])('refuses %s', (cidr) => {
    expect(() => validateTestAllowCidrs([cidr], 'test')).toThrow(/documentation ranges/);
  });

  it('accepts subnets of the documentation ranges and refuses the key in production', () => {
    expect(
      validateTestAllowCidrs(['203.0.113.10/32', '192.0.2.0/24', '198.51.100.0/25'], 'development'),
    ).toHaveLength(3);
    expect(() => validateTestAllowCidrs(['203.0.113.0/24'], 'production')).toThrow(/production/);
    expect(validateTestAllowCidrs([], 'production')).toEqual([]);
    // Local Compose containers: NODE_ENV=production with APP_ENV=local (or ci) keep the seam.
    expect(
      validateTestAllowCidrs(['203.0.113.0/24'], { nodeEnv: 'production', appEnv: 'local' }),
    ).toHaveLength(1);
    expect(
      validateTestAllowCidrs(['203.0.113.0/24'], { nodeEnv: 'production', appEnv: 'ci' }),
    ).toHaveLength(1);
    for (const appEnv of ['staging', 'production']) {
      expect(() =>
        validateTestAllowCidrs(['203.0.113.0/24'], { nodeEnv: 'development', appEnv }),
      ).toThrow(/production/);
    }
    expect(
      () =>
        new SsrfGuard({
          testAllowCidrs: ['203.0.113.0/24'],
          nodeEnv: 'production',
          appEnv: 'production',
        }),
    ).toThrow();
  });
});

describe('RestrictedResolver', () => {
  const backend =
    (answers: Record<string, { v4?: string[] | Error; v6?: string[] | Error }>) => () => {
      const make =
        (family: 'v4' | 'v6') =>
        (name: string): Promise<string[]> => {
          const value = answers[name]?.[family];
          if (value instanceof Error) return Promise.reject(value);
          if (value === undefined)
            return Promise.reject(Object.assign(new Error('nodata'), { code: 'ENODATA' }));
          return Promise.resolve(value);
        };
      return {
        resolve4: make('v4'),
        resolve6: make('v6'),
        cancel: () => undefined,
      } satisfies DnsBackend;
    };
  const nx = () => Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
  const servfail = () => Object.assign(new Error('sf'), { code: 'ESERVFAIL' });
  const timeout = () => Object.assign(new Error('to'), { code: 'ETIMEOUT' });
  const g = new SsrfGuard({ testAllowCidrs: ['203.0.113.0/24'], nodeEnv: 'test' });

  it('returns the first allowed IPv4, else IPv6', async () => {
    const r = new RestrictedResolver(
      {},
      backend({
        'a.test': { v4: ['203.0.113.10', '203.0.113.11'], v6: ['2606:4700::1'] },
        'b.test': { v6: ['2606:4700::1'] },
      }),
    );
    await expect(r.resolveValidated('a.test', g)).resolves.toMatchObject({
      ok: true,
      address: '203.0.113.10',
      family: 4,
    });
    await expect(r.resolveValidated('b.test', g)).resolves.toMatchObject({
      ok: true,
      address: '2606:4700::1',
      family: 6,
    });
  });

  it('blocks the host when ANY answer is blocked (mixed answers, either family)', async () => {
    const r = new RestrictedResolver(
      {},
      backend({
        'mixed-a.test': { v4: ['203.0.113.10', '10.0.0.5'] },
        'mixed-v6.test': { v4: ['203.0.113.10'], v6: ['::1'] },
        'mapped-v6.test': { v6: ['::ffff:127.0.0.1'] },
        'meta-a.test': { v4: ['169.254.169.254'] },
      }),
    );
    await expect(r.resolveValidated('mixed-a.test', g)).resolves.toMatchObject({
      ok: false,
      blocked: true,
      reason: 'private',
    });
    await expect(r.resolveValidated('mixed-v6.test', g)).resolves.toMatchObject({
      ok: false,
      blocked: true,
      reason: 'loopback',
    });
    await expect(r.resolveValidated('mapped-v6.test', g)).resolves.toMatchObject({
      ok: false,
      blocked: true,
      reason: 'loopback',
    });
    await expect(r.resolveValidated('meta-a.test', g)).resolves.toMatchObject({
      ok: false,
      blocked: true,
      reason: 'metadata',
    });
  });

  it('considers at most 16 answers per family', async () => {
    const v4 = [...Array.from({ length: 16 }, (_, i) => `203.0.113.${i + 1}`), '127.0.0.1'];
    const r = new RestrictedResolver({}, backend({ 'many.test': { v4 } }));
    await expect(r.resolveValidated('many.test', g)).resolves.toMatchObject({
      ok: true,
      address: '203.0.113.1',
    });
  });

  it('maps NXDOMAIN, SERVFAIL and timeouts to dns errors', async () => {
    const r = new RestrictedResolver(
      {},
      backend({
        'nx.test': { v4: nx(), v6: nx() },
        'sf.test': { v4: servfail(), v6: servfail() },
        'to.test': { v4: timeout(), v6: nx() },
      }),
    );
    await expect(r.resolveValidated('nx.test', g)).resolves.toEqual({
      ok: false,
      blocked: false,
      error: 'nxdomain',
    });
    await expect(r.resolveValidated('sf.test', g)).resolves.toEqual({
      ok: false,
      blocked: false,
      error: 'servfail',
    });
    await expect(r.resolveValidated('to.test', g)).resolves.toEqual({
      ok: false,
      blocked: false,
      error: 'timeout',
    });
    await expect(r.resolveValidated('none.test', g)).resolves.toEqual({
      ok: false,
      blocked: false,
      error: 'nodata',
    });
  });

  it('returns raw A records for DNSBL queries (NXDOMAIN → empty, failures throw)', async () => {
    const r = new RestrictedResolver(
      {},
      backend({
        'x.dbl.test': { v4: ['127.0.1.2'] },
        'nx.dbl.test': { v4: nx() },
        'sf.dbl.test': { v4: servfail() },
      }),
    );
    await expect(r.resolve4Raw('x.dbl.test')).resolves.toEqual(['127.0.1.2']);
    await expect(r.resolve4Raw('nx.dbl.test')).resolves.toEqual([]);
    await expect(r.resolve4Raw('sf.dbl.test')).rejects.toMatchObject({ kind: 'servfail' });
  });

  it('validates the server list with the real dns.Resolver', () => {
    expect(() => new RestrictedResolver({ servers: ['127.0.0.1:1053', '[::1]:53'] })).not.toThrow();
    expect(() => new RestrictedResolver({ servers: ['not a server'] })).toThrow();
  });
});
