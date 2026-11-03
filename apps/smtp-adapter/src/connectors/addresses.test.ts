import { describe, expect, it } from 'vitest';
import { ipInRange, normalizeFingerprint, parseIpKey } from './addresses';

describe('parseIpKey', () => {
  it('parses IPv4 into 4 big-endian bytes', () => {
    expect(parseIpKey('192.0.2.10')).toEqual({
      text: '192.0.2.10',
      version: 4,
      bytes: Buffer.from([192, 0, 2, 10]),
    });
  });

  it('turns IPv4-mapped IPv6 into IPv4', () => {
    expect(parseIpKey('::ffff:192.0.2.10')?.text).toBe('192.0.2.10');
    expect(parseIpKey('::FFFF:c000:020a')?.text).toBe('192.0.2.10');
  });

  it('parses IPv6 into 16 bytes with canonical text', () => {
    const key = parseIpKey('2001:DB8:0:0:0:0:0:1');
    expect(key?.version).toBe(6);
    expect(key?.text).toBe('2001:db8::1');
    expect(key?.bytes.toString('hex')).toBe('20010db8000000000000000000000001');
    expect(parseIpKey('::')?.bytes.equals(Buffer.alloc(16))).toBe(true);
    expect(parseIpKey('fe80::1%eth0')?.text).toBe('fe80::1');
    expect(parseIpKey('64:ff9b::192.0.2.1')?.bytes.toString('hex')).toBe(
      '0064ff9b0000000000000000c0000201',
    );
    expect(parseIpKey('2001:db8:1:0:0:1:0:0')?.text).toBe('2001:db8:1::1:0:0');
  });

  it('refuses truncated access-map keys and non-addresses', () => {
    for (const key of ['10.1.2', '10.1', '10', '2001:db8', 'unknown', '', 'a.b.c.d']) {
      expect(parseIpKey(key)).toBeNull();
    }
    expect(parseIpKey(undefined)).toBeNull();
  });
});

describe('ipInRange', () => {
  const start = Buffer.from([10, 0, 0, 0]);
  const end = Buffer.from([10, 0, 255, 255]);
  it('includes both ends and nothing outside', () => {
    expect(ipInRange(Buffer.from([10, 0, 0, 0]), start, end)).toBe(true);
    expect(ipInRange(Buffer.from([10, 0, 255, 255]), start, end)).toBe(true);
    expect(ipInRange(Buffer.from([10, 1, 0, 0]), start, end)).toBe(false);
    expect(ipInRange(Buffer.from([9, 255, 255, 255]), start, end)).toBe(false);
    expect(ipInRange(Buffer.alloc(16), start, end)).toBe(false);
  });
});

describe('normalizeFingerprint', () => {
  const hex = 'ab'.repeat(32);
  it("normalizes Postfix's colon-separated upper-case hex", () => {
    const postfix = hex.toUpperCase().match(/../g)!.join(':');
    expect(normalizeFingerprint(postfix)).toBe(hex);
    expect(normalizeFingerprint(hex)).toBe(hex);
  });

  it('refuses other lengths and characters', () => {
    expect(normalizeFingerprint('AB:CD')).toBeNull();
    expect(normalizeFingerprint('zz'.repeat(32))).toBeNull();
    expect(normalizeFingerprint(undefined)).toBeNull();
  });
});
