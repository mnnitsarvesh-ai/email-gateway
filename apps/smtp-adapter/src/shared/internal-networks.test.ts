import { describe, expect, it } from 'vitest';
import { isAllowedClient, normalizeClientAddress, parseNetworkList } from './internal-networks';

const DEFAULT_NETWORKS = '127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';

describe('parseNetworkList', () => {
  it('parses the default IPv4 + IPv6 list', () => {
    const list = parseNetworkList(DEFAULT_NETWORKS);
    for (const allowed of ['127.0.0.1', '10.1.2.3', '172.31.250.25', '192.168.65.1', '::1']) {
      expect(isAllowedClient(list, allowed), allowed).toBe(true);
    }
    for (const denied of ['8.8.8.8', '172.32.0.1', '11.0.0.1', '::2', '2001:db8::1']) {
      expect(isAllowedClient(list, denied), denied).toBe(false);
    }
  });

  it('accepts whitespace, empty entries and bare host addresses', () => {
    const list = parseNetworkList(' 203.0.113.7 , ,2001:db8::/32,  fd00::1 ');
    expect(isAllowedClient(list, '203.0.113.7')).toBe(true);
    expect(isAllowedClient(list, '203.0.113.8')).toBe(false);
    expect(isAllowedClient(list, '2001:db8:ffff::1')).toBe(true);
    expect(isAllowedClient(list, 'fd00::1')).toBe(true);
    expect(isAllowedClient(list, 'fd00::2')).toBe(false);
  });

  it('honours /0 and host prefixes', () => {
    expect(isAllowedClient(parseNetworkList('0.0.0.0/0'), '198.51.100.1')).toBe(true);
    expect(isAllowedClient(parseNetworkList('0.0.0.0/0'), '2001:db8::1')).toBe(false);
    expect(isAllowedClient(parseNetworkList('::/0'), '2001:db8::1')).toBe(true);
    expect(isAllowedClient(parseNetworkList('198.51.100.1/32'), '198.51.100.1')).toBe(true);
  });

  it.each([
    '',
    ' , ',
    'localhost',
    '10.0.0.0/33',
    '10.0.0.0/-1',
    '10.0.0.0/08',
    '10.0.0.0/',
    '10.0.0.0/8/9',
    '::1/129',
    '256.0.0.1/8',
    'fe80::1%en0/64',
    '10.0.0.0/8;192.168.0.0/16',
  ])('throws on invalid input %j', (csv) => {
    expect(() => parseNetworkList(csv)).toThrow();
  });
});

describe('isAllowedClient', () => {
  const list = parseNetworkList('10.0.0.0/8,fd00::/8');

  it('maps IPv4-mapped IPv6 peers (dotted and hex) to IPv4', () => {
    expect(isAllowedClient(list, '::ffff:10.1.2.3')).toBe(true);
    expect(isAllowedClient(list, '::FFFF:10.1.2.3')).toBe(true);
    expect(isAllowedClient(list, '::ffff:a01:203')).toBe(true);
    expect(isAllowedClient(list, '::ffff:8.8.8.8')).toBe(false);
    expect(isAllowedClient(list, '::ffff:808:808')).toBe(false);
  });

  it('checks IPv6 peers against IPv6 networks, ignoring a zone id', () => {
    expect(isAllowedClient(list, 'fd12:3456::1')).toBe(true);
    expect(isAllowedClient(list, 'fd12:3456::1%eth0')).toBe(true);
    expect(isAllowedClient(list, 'fe80::1')).toBe(false);
  });

  it('refuses missing or invalid addresses', () => {
    for (const address of [undefined, '', 'nonsense', '10.0.0', '::ffff:999.1.1.1']) {
      expect(isAllowedClient(list, address), String(address)).toBe(false);
    }
  });

  it('normalizes addresses to a family', () => {
    expect(normalizeClientAddress('::ffff:192.0.2.1')).toEqual({
      address: '192.0.2.1',
      family: 'ipv4',
    });
    expect(normalizeClientAddress('::ffff:c000:201')).toEqual({
      address: '192.0.2.1',
      family: 'ipv4',
    });
    expect(normalizeClientAddress(' 2001:db8::1 ')).toEqual({
      address: '2001:db8::1',
      family: 'ipv6',
    });
    expect(normalizeClientAddress('host.example')).toBeNull();
  });
});
