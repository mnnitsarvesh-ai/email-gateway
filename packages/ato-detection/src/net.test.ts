import { describe, expect, it } from 'vitest';
import {
  anyCidrContains,
  canonicalIp,
  cidrContains,
  classifyIp,
  ipPrefix,
  parseCidr,
  parseIp,
} from './net';

describe('IP parsing', () => {
  it('canonicalizes IPv4, IPv6 and IPv4-mapped IPv6', () => {
    expect(canonicalIp('192.0.2.1')).toBe('192.0.2.1');
    expect(canonicalIp('2001:DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
    expect(canonicalIp('2001:db8:0:0:1:0:0:1')).toBe('2001:db8::1:0:0:1');
    expect(canonicalIp('::ffff:192.0.2.5')).toBe('192.0.2.5');
    expect(canonicalIp('::')).toBe('::');
    expect(canonicalIp('1::')).toBe('1::');
    expect(canonicalIp('192.0.2.256')).toBeNull();
    expect(canonicalIp('01.2.3.4')).toBeNull();
    expect(canonicalIp('fe80::1%eth0')).toBeNull();
    expect(parseIp('nonsense')).toBeNull();
  });
});

describe('classifyIp (D7)', () => {
  it.each([
    ['8.8.8.8', 'public', true],
    ['10.1.2.3', 'private', false],
    ['172.16.0.1', 'private', false],
    ['192.168.1.1', 'private', false],
    ['100.64.0.1', 'cgnat', false],
    ['127.0.0.1', 'loopback', false],
    ['169.254.1.1', 'link_local', false],
    ['224.0.0.1', 'multicast', false],
    ['240.0.0.1', 'reserved', false],
    ['0.0.0.0', 'unspecified', false],
    ['192.0.2.10', 'documentation', false],
    ['198.51.100.1', 'documentation', false],
    ['203.0.113.200', 'documentation', false],
    ['2001:db8::1', 'documentation', false],
    ['::1', 'loopback', false],
    ['fd00::1', 'private', false],
    ['fe80::1', 'link_local', false],
    ['ff02::1', 'multicast', false],
    ['2a00:1450::1', 'public', true],
    ['3fff::1', 'public', true],
    ['4000::1', 'reserved', false],
  ] as const)('%s is %s', (ip, cls, geo) => {
    const c = classifyIp(ip);
    expect(c.class).toBe(cls);
    expect(c.geolocatable).toBe(geo);
  });

  it('documentation ranges are geolocatable only when allowed (tests)', () => {
    expect(classifyIp('192.0.2.10', { allowDocumentationRanges: true }).geolocatable).toBe(true);
    expect(classifyIp('2001:db8::1', { allowDocumentationRanges: true }).geolocatable).toBe(true);
    expect(classifyIp('10.0.0.1', { allowDocumentationRanges: true }).geolocatable).toBe(false);
    expect(classifyIp('bogus').valid).toBe(false);
  });
});

describe('prefixes and CIDRs', () => {
  it('ipPrefix is /24 and /48 by default', () => {
    expect(ipPrefix('192.0.2.77')).toBe('192.0.2.0/24');
    expect(ipPrefix('2001:db8:1:2::5')).toBe('2001:db8:1::/48');
    expect(ipPrefix('192.0.2.77', 16)).toBe('192.0.0.0/16');
    expect(ipPrefix('x')).toBeNull();
  });

  it('parseCidr clears host bits, enforces minimum prefixes and computes ranges', () => {
    const c = parseCidr('192.0.2.77/24')!;
    expect(c.cidr).toBe('192.0.2.0/24');
    expect(c.start.equals(Buffer.from([192, 0, 2, 0]))).toBe(true);
    expect(c.end.equals(Buffer.from([192, 0, 2, 255]))).toBe(true);
    expect(parseCidr('10.0.0.0/7', { minV4Prefix: 8 })).toBeNull();
    expect(parseCidr('2001:db8::/31', { minV6Prefix: 32 })).toBeNull();
    expect(parseCidr('2001:db8::/32', { minV6Prefix: 32 })?.cidr).toBe('2001:db8::/32');
    expect(parseCidr('192.0.2.1')?.cidr).toBe('192.0.2.1/32');
    expect(parseCidr('192.0.2.0/33')).toBeNull();
    expect(parseCidr('192.0.2.0/024')).toBeNull();
  });

  it('cidrContains matches by version and range', () => {
    expect(cidrContains('192.0.2.0/25', '192.0.2.127')).toBe(true);
    expect(cidrContains('192.0.2.0/25', '192.0.2.128')).toBe(false);
    expect(cidrContains('2001:db8::/48', '2001:db8::abcd')).toBe(true);
    expect(cidrContains('2001:db8::/48', '192.0.2.1')).toBe(false);
    expect(cidrContains('bad', '192.0.2.1')).toBe(false);
    expect(anyCidrContains(['198.51.100.0/24', '192.0.2.0/24'], '192.0.2.9')).toBe(true);
  });
});
