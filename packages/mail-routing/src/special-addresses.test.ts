import { describe, expect, it } from 'vitest';
import {
  formatIpAddress,
  isMetadataAddress,
  isPublicIpAddress,
  METADATA_ADDRESSES,
  parseIpAddress,
} from './special-addresses';

describe('parseIpAddress / formatIpAddress', () => {
  it('parses dotted quads and IPv6 (compressed, full, embedded IPv4) into canonical text', () => {
    const canonical = (text: string) => {
      const parsed = parseIpAddress(text);
      return parsed ? formatIpAddress(parsed) : null;
    };
    expect(canonical('192.0.2.1')).toBe('192.0.2.1');
    expect(canonical('2001:DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
    expect(canonical('2001:db8::')).toBe('2001:db8::');
    expect(canonical('::')).toBe('::');
    expect(canonical('::1')).toBe('::1');
    expect(canonical('::ffff:192.0.2.1')).toBe('::ffff:c000:201');
    expect(canonical('::192.0.2.1')).toBe('::c000:201');
    expect(canonical('1:2:3:4:5:6:1.2.3.4')).toBe('1:2:3:4:5:6:102:304');
    expect(canonical('2001:db8:0:1:0:0:0:1')).toBe('2001:db8:0:1::1');
    expect(canonical('2001:0:0:1:0:0:0:1')).toBe('2001:0:0:1::1');
    expect(canonical('2001:0:0:1:0:0:1:1')).toBe('2001::1:0:0:1:1');
    expect(canonical('1:0:1:0:1:0:1:0')).toBe('1:0:1:0:1:0:1:0');
  });

  it('rejects names, legacy inet_aton forms, zone ids and garbage', () => {
    for (const text of [
      '',
      'example.com',
      '127.1',
      '0x7f.0.0.1',
      '017.0.0.1',
      '256.1.1.1',
      '1.2.3.4.5',
      'fe80::1%eth0',
      '[::1]',
      '1::2::3',
      '12345::',
      ' 1.2.3.4',
    ]) {
      expect(parseIpAddress(text), text).toBeNull();
    }
  });
});

describe('isPublicIpAddress', () => {
  it('accepts globally reachable IPv4 and IPv6 unicast', () => {
    for (const ip of [
      '1.1.1.1',
      '8.8.8.8',
      '93.184.216.34',
      '100.63.255.255',
      '100.128.0.0',
      '172.15.255.255',
      '172.32.0.0',
      '192.31.196.1', // AS112, reachable
      '192.52.193.1', // AMT, reachable
      '192.175.48.1', // AS112 direct delegation, reachable
      '198.17.255.255',
      '198.20.0.0',
      '223.255.255.255',
      '2606:4700:4700::1111',
      '2a00:1450:4001:82a::200e',
      '2001:4860:4860::8888',
      '2001:3::1', // AMT
      '2001:4:112::1', // AS112-v6
      '2001:20::1', // ORCHIDv2
      '2001:1::1', // PCP anycast
      '64:ff9b::808:808', // NAT64 of 8.8.8.8
      '2002:808:808::1', // 6to4 of 8.8.8.8
    ]) {
      expect(isPublicIpAddress(ip), ip).toBe(true);
    }
  });

  it('refuses every IPv4 special-purpose range', () => {
    for (const ip of [
      '0.0.0.0',
      '0.255.255.255',
      '10.0.0.1',
      '10.255.255.255',
      '100.64.0.1',
      '100.127.255.255',
      '127.0.0.1',
      '127.255.255.254',
      '169.254.1.1',
      '172.16.0.1',
      '172.31.255.255',
      '192.0.0.1',
      '192.0.0.9',
      '192.0.0.170',
      '192.0.2.10',
      '192.88.99.1',
      '192.168.1.1',
      '198.18.0.1',
      '198.19.255.255',
      '198.51.100.7',
      '203.0.113.9',
      '224.0.0.1',
      '239.255.255.255',
      '240.0.0.1',
      '255.255.255.255',
    ]) {
      expect(isPublicIpAddress(ip), ip).toBe(false);
    }
  });

  it('refuses IPv6 special-purpose, unallocated and embedding addresses', () => {
    for (const ip of [
      '::',
      '::1',
      '::ffff:8.8.8.8', // IPv4-mapped
      '::8.8.8.8', // IPv4-compatible (deprecated)
      '64:ff9b::a00:1', // NAT64 of 10.0.0.1
      '64:ff9b::7f00:1', // NAT64 of 127.0.0.1
      '64:ff9b:1::808:808', // local-use NAT64
      '100::1', // discard-only
      '2001::1', // Teredo with a non-public embedded client
      '2001:2::1', // benchmarking
      '2001:10::1', // deprecated ORCHID
      '2001:db8::1', // documentation
      '2001:db8:ffff::1',
      '2002:a00:1::1', // 6to4 of 10.0.0.1
      '2002:c0a8:101::1', // 6to4 of 192.168.1.1
      '3fff::1', // documentation (RFC 9637)
      '5f00::1', // SRv6 SIDs
      'fc00::1', // unique-local
      'fd12:3456::1',
      'fe80::1', // link-local
      'febf::1',
      'fec0::1', // deprecated site-local
      'ff02::1', // multicast
      '4000::1', // unallocated (outside 2000::/3)
    ]) {
      expect(isPublicIpAddress(ip), ip).toBe(false);
    }
  });

  it('accepts Teredo only when both embedded addresses are public', () => {
    // Server 65.54.227.120 (41 36 e3 78), client 8.8.8.8 inverted = f7f7:f7f7.
    expect(isPublicIpAddress('2001:0:4136:e378:8000:63bf:f7f7:f7f7')).toBe(true);
    // Client 10.0.0.1 inverted = f5ff:fffe.
    expect(isPublicIpAddress('2001:0:4136:e378:8000:63bf:f5ff:fffe')).toBe(false);
    // Server 192.168.0.1.
    expect(isPublicIpAddress('2001:0:c0a8:1:8000:63bf:f7f7:f7f7')).toBe(false);
  });

  it('is false for anything that is not an IP literal', () => {
    for (const value of ['mail.example.com', '', '[8.8.8.8]', 'fe80::1%en0']) {
      expect(isPublicIpAddress(value), value).toBe(false);
    }
  });
});

describe('isMetadataAddress', () => {
  it('matches the cloud metadata endpoints, also IPv4-mapped, compatible and NAT64 forms', () => {
    expect(METADATA_ADDRESSES).toEqual([
      '169.254.169.254',
      '169.254.170.2',
      'fd00:ec2::254',
      '100.100.100.200',
    ]);
    for (const ip of [
      ...METADATA_ADDRESSES,
      'FD00:EC2:0:0:0:0:0:254',
      '::ffff:169.254.169.254',
      '::169.254.169.254',
      '64:ff9b::a9fe:a9fe',
      '::ffff:100.100.100.200',
    ]) {
      expect(isMetadataAddress(ip), ip).toBe(true);
    }
  });

  it('does not match neighbouring or unrelated addresses', () => {
    for (const ip of [
      '169.254.169.253',
      '169.254.170.3',
      '100.100.100.201',
      'fd00:ec2::253',
      '8.8.8.8',
      'metadata.google.internal',
      '',
    ]) {
      expect(isMetadataAddress(ip), ip).toBe(false);
    }
  });
});
