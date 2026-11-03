import { describe, expect, it } from 'vitest';
import {
  findInternalOverlap,
  formatIpv6,
  isPublicNetwork,
  NetworkError,
  NON_PUBLIC_NETWORK_MESSAGE,
  NON_PUBLIC_NETWORKS,
  networksOverlap,
  parseIpv4,
  parseIpv6,
  parseNetwork,
} from './networks';

const hex = (b: Buffer) => b.toString('hex');

describe('parseNetwork (D10): canonical CIDR and ranges', () => {
  it.each([
    ['192.0.2.0/24', '192.0.2.0/24', 'c0000200', 'c00002ff'],
    ['192.0.2.77/24', '192.0.2.0/24', 'c0000200', 'c00002ff'],
    [' 198.51.100.7 ', '198.51.100.7/32', 'c6336407', 'c6336407'],
    ['10.20.0.0/16', '10.20.0.0/16', '0a140000', '0a14ffff'],
    ['203.0.113.5/31', '203.0.113.4/31', 'cb007104', 'cb007105'],
    ['255.255.255.255/32', '255.255.255.255/32', 'ffffffff', 'ffffffff'],
  ])('IPv4 %s → %s', (input, cidr, start, end) => {
    const n = parseNetwork(input);
    expect(n).toMatchObject({ cidr, ipVersion: 4 });
    expect(n.rangeStart).toHaveLength(4);
    expect([hex(n.rangeStart), hex(n.rangeEnd)]).toEqual([start, end]);
  });

  it.each([
    [
      '2001:db8::/48',
      '2001:db8::/48',
      '20010db8000000000000000000000000',
      '20010db80000ffffffffffffffffffff',
    ],
    [
      '2001:DB8:0:0:1::1/64',
      '2001:db8::/64',
      '20010db8000000000000000000000000',
      '20010db800000000ffffffffffffffff',
    ],
    [
      '2001:db8:abcd:12::7',
      '2001:db8:abcd:12::7/128',
      '20010db8abcd00120000000000000007',
      '20010db8abcd00120000000000000007',
    ],
    [
      '2001:db8:0:1:0:0:0:0/64',
      '2001:db8:0:1::/64',
      '20010db8000000010000000000000000',
      '20010db800000001ffffffffffffffff',
    ],
    [
      '2001:db8::1:0:0:1/128',
      '2001:db8::1:0:0:1/128',
      '20010db8000000000001000000000001',
      '20010db8000000000001000000000001',
    ],
    [
      '64:ff9b::192.0.2.1/128',
      '64:ff9b::c000:201/128',
      '0064ff9b0000000000000000c0000201',
      '0064ff9b0000000000000000c0000201',
    ],
  ])('IPv6 %s → %s', (input, cidr, start, end) => {
    const n = parseNetwork(input);
    expect(n).toMatchObject({ cidr, ipVersion: 6 });
    expect(n.rangeStart).toHaveLength(16);
    expect([hex(n.rangeStart), hex(n.rangeEnd)]).toEqual([start, end]);
  });

  it.each([
    ['10.0.0.0/15', 'must not be larger than /16 for IPv4 networks'],
    ['0.0.0.0/0', 'must not be larger than /16 for IPv4 networks'],
    ['2001:db8::/47', 'must not be larger than /48 for IPv6 networks'],
    ['::/0', 'must not be larger than /48 for IPv6 networks'],
    ['10.0.0.0/33', 'must have a prefix length between 0 and 32'],
    ['2001:db8::/129', 'must have a prefix length between 0 and 128'],
    ['10.0.0.0/024', 'must have a prefix length between 0 and 32'],
    ['10.0.0.0/', 'must have a prefix length between 0 and 32'],
    ['10.0.0/24', 'must be an IPv4 or IPv6 address or CIDR network'],
    ['010.0.0.0/24', 'must be an IPv4 or IPv6 address or CIDR network'],
    ['256.0.0.0/24', 'must be an IPv4 or IPv6 address or CIDR network'],
    ['fe80::1%eth0/128', 'must be an IPv4 or IPv6 address or CIDR network'],
    ['2001:db8:::1/64', 'must be an IPv4 or IPv6 address or CIDR network'],
    ['example.com/24', 'must be an IPv4 or IPv6 address or CIDR network'],
    ['', 'must be an IPv4 or IPv6 address or CIDR network'],
    ['::ffff:192.0.2.1/128', 'must use the IPv4 form for IPv4-mapped IPv6 addresses'],
  ])('refuses %j (%s)', (input, message) => {
    expect(() => parseNetwork(input)).toThrow(new NetworkError(message));
  });
});

describe('address parsers and formatting', () => {
  it('parses strict dotted quads only', () => {
    expect(parseIpv4('1.2.3.4')).toEqual(Buffer.from([1, 2, 3, 4]));
    for (const bad of ['1.2.3', '1.2.3.4.5', '1.2.3.04', '1.2.3.-1', '1.2.3.a', '1..3.4']) {
      expect(parseIpv4(bad)).toBeNull();
    }
  });

  it('parses IPv6 text forms and refuses malformed ones', () => {
    expect(parseIpv6('::')?.equals(Buffer.alloc(16))).toBe(true);
    expect(hex(parseIpv6('::1')!)).toBe('00000000000000000000000000000001');
    expect(hex(parseIpv6('1::')!)).toBe('00010000000000000000000000000000');
    for (const bad of [
      ':1::',
      '1:2:3:4:5:6:7',
      '1:2:3:4:5:6:7:8:9',
      '1::2::3',
      '12345::',
      'g::1',
      '1.2.3.4::',
    ]) {
      expect(parseIpv6(bad)).toBeNull();
    }
  });

  it('formats IPv6 per RFC 5952 (longest zero run, first on ties, no single-group ::)', () => {
    const f = (text: string) => formatIpv6(parseIpv6(text)!);
    expect(f('2001:0db8:0000:0000:0001:0000:0000:0001')).toBe('2001:db8::1:0:0:1');
    expect(f('2001:db8:0:1:1:1:1:1')).toBe('2001:db8:0:1:1:1:1:1');
    expect(f('0:0:0:0:0:0:0:0')).toBe('::');
    expect(f('2001:db8:0:0:1:0:0:0')).toBe('2001:db8:0:0:1::');
  });
});

describe('overlap math', () => {
  const n = (cidr: string) => parseNetwork(cidr);

  it.each([
    ['10.0.0.0/16', '10.0.5.0/24', true],
    ['10.0.0.0/24', '10.0.0.255/32', true],
    ['10.0.0.0/24', '10.0.1.0/24', false],
    ['10.0.0.0/25', '10.0.0.128/25', false],
    ['10.0.0.0/23', '10.0.1.128/25', true],
    ['2001:db8::/48', '2001:db8:0:ffff::/64', true],
    ['2001:db8::/48', '2001:db8:1::/48', false],
    ['2001:db8:0:0:8000::/65', '2001:db8::/65', false],
    ['2001:db8::/64', '2001:db8::ffff:ffff:ffff:ffff/128', true],
    // Same bytes in a different family never overlap.
    ['10.0.0.0/16', 'a00::/48', false],
  ])('%s vs %s → %s', (a, b, expected) => {
    expect(networksOverlap(n(a), n(b))).toBe(expected);
    expect(networksOverlap(n(b), n(a))).toBe(expected);
  });

  it('finds overlaps inside one request', () => {
    expect(findInternalOverlap([n('10.0.0.0/24'), n('10.0.1.0/24')])).toBeNull();
    expect(findInternalOverlap([n('10.0.0.0/24'), n('10.1.0.0/16'), n('10.1.2.3')])).toEqual([
      1, 2,
    ]);
  });
});

describe('public networks (review finding, step 2.2 §12.7)', () => {
  const n = (cidr: string) => parseNetwork(cidr);

  it.each([
    '10.0.0.0/16',
    '10.255.255.255',
    '172.16.0.0/16',
    '172.31.250.25',
    '192.168.0.0/16',
    '127.0.0.1',
    '169.254.169.254',
    '100.64.0.0/16',
    '100.127.0.1',
    '0.0.0.1',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '198.18.0.0/16',
    '198.51.100.7',
    '203.0.113.0/24',
    '224.0.0.1',
    '255.255.255.255',
    // A /16 that only partly covers a reserved range is refused as well.
    '192.0.0.0/16',
    '::1',
    'fd12:3456:789a::/48',
    'fe80::1',
    'ff02::1',
    '2001:db8::/48',
    '2001::/48',
    '3fff::/48',
  ])('%s is not public', (cidr) => {
    expect(isPublicNetwork(n(cidr))).toBe(false);
  });

  it.each([
    '45.10.0.0/16',
    '8.8.8.8',
    '172.15.255.0/24',
    '172.32.0.0/16',
    '100.63.0.0/16',
    '100.128.0.0/16',
    '198.17.0.0/16',
    '223.255.255.0/24',
    '2a10:1:2::/48',
    '2606:4700::/48',
    '2002:c000:0201::/48',
  ])('%s is public', (cidr) => {
    expect(isPublicNetwork(n(cidr))).toBe(true);
  });

  it('parses every special-purpose range of the list', () => {
    expect(NON_PUBLIC_NETWORKS.length).toBeGreaterThan(20);
    expect(NON_PUBLIC_NETWORK_MESSAGE).not.toMatch(/\d/);
  });
});
