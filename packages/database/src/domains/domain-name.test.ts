import { describe, expect, it } from 'vitest';
import { DomainNameError, isDomainAtOrUnder, normalizeDomainName } from './domain-name';

const prod = { allowTestNames: false };
const local = { allowTestNames: true };

function errorCode(input: string, options = prod): string | null {
  try {
    normalizeDomainName(input, options);
    return null;
  } catch (error) {
    expect(error).toBeInstanceOf(DomainNameError);
    expect((error as DomainNameError).name).toBe('DomainNameError');
    return (error as DomainNameError).code;
  }
}

describe('normalizeDomainName', () => {
  it('lower-cases, trims and strips one trailing dot', () => {
    expect(normalizeDomainName('  Acme.COM.  ', prod)).toEqual({
      ascii: 'acme.com',
      unicode: 'acme.com',
    });
    expect(normalizeDomainName('mail.Acme.co.uk', prod).ascii).toBe('mail.acme.co.uk');
    expect(errorCode('acme.com..')).toBe('invalid');
  });

  it('converts IDN to punycode and returns the unicode form for display', () => {
    expect(normalizeDomainName('Bücher.Example.de', prod)).toEqual({
      ascii: 'xn--bcher-kva.example.de',
      unicode: 'bücher.example.de',
    });
    expect(normalizeDomainName('xn--bcher-kva.de', prod)).toEqual({
      ascii: 'xn--bcher-kva.de',
      unicode: 'bücher.de',
    });
    // Full-width characters map to ASCII (UTS #46).
    expect(normalizeDomainName('ＡＣＭＥ.com', prod).ascii).toBe('acme.com');
    // IDNA label separators (ideographic full stop) map to '.'.
    expect(normalizeDomainName('acme\u3002com', prod).ascii).toBe('acme.com');
    // IDN top-level label.
    expect(normalizeDomainName('example.рф', prod).ascii).toBe('example.xn--p1ai');
  });

  it('accepts subdomains, digits and inner hyphens', () => {
    for (const name of ['a.io', 'mail.acme.com', '1-2-3.acme.com', '123.com', 'ab--cd.com']) {
      expect(normalizeDomainName(name, prod).ascii, name).toBe(name);
    }
  });

  it('rejects malformed names as invalid', () => {
    for (const name of [
      '',
      '   ',
      '.',
      'acme',
      '.acme.com',
      'acme..com',
      '-acme.com',
      'acme-.com',
      'ac me.com',
      'acme.com:25',
      'user@acme.com',
      'acme.com/path',
      'acme.com?x',
      'acme.com#x',
      'a\\b.com',
      'acme.com／path',
      'ac\tme.com',
      'xn--zz.com',
      'acme.c0m1',
      'acme.123',
      'acme.c-m',
    ]) {
      expect(errorCode(name), JSON.stringify(name)).toBe('invalid');
    }
  });

  it('rejects wildcards, underscores and percent-encoding', () => {
    expect(errorCode('*.acme.com')).toBe('invalid');
    expect(errorCode('_dmarc.acme.com')).toBe('invalid');
    expect(errorCode('a%41.com')).toBe('invalid');
  });

  it('rejects IPv4 and IPv6 literals', () => {
    for (const name of ['192.168.0.1', '10.0.0.1.', '0x7f.1', '[::1]', '::1', '[2001:db8::1]']) {
      expect(errorCode(name), name).toBe('invalid');
    }
  });

  it('enforces the label and name length limits', () => {
    const label63 = 'a'.repeat(63);
    expect(normalizeDomainName(`${label63}.com`, prod).ascii).toBe(`${label63}.com`);
    expect(errorCode(`${'a'.repeat(64)}.com`)).toBe('invalid');

    // 4 × 63 + 1 = 253 characters with the dots.
    const max = [label63, label63, label63, 'a'.repeat(57), 'com'].join('.');
    expect(max).toHaveLength(253);
    expect(normalizeDomainName(max, prod).ascii).toBe(max);
    expect(normalizeDomainName(`${max}.`, prod).ascii).toBe(max);
    expect(errorCode(`a${max}`)).toBe('too_long');
    expect(errorCode('a.'.repeat(600) + 'com')).toBe('too_long');
  });

  it('always rejects special-use names as reserved', () => {
    for (const name of [
      'localhost',
      'LOCALHOST.',
      'foo.localhost',
      'printer.local',
      'x.invalid',
      '1.0.0.127.in-addr.arpa',
      'abc.onion',
      'corp.internal',
      'name.alt',
    ]) {
      expect(errorCode(name, prod), name).toBe('reserved');
      expect(errorCode(name, local), name).toBe('reserved');
    }
  });

  it('rejects test and documentation names unless allowTestNames', () => {
    for (const name of [
      'gateway.test',
      'test',
      'a.example',
      'example.com',
      'mail.example.com',
      'example.net',
      'example.org',
    ]) {
      expect(errorCode(name, prod), name).toBe('reserved');
    }
    expect(normalizeDomainName('Gateway.Test.', local).ascii).toBe('gateway.test');
    expect(normalizeDomainName('mail.example.com', local).ascii).toBe('mail.example.com');
    // A single label is still not a domain, even when test names are allowed.
    expect(errorCode('test', local)).toBe('invalid');
    // Only the exact suffixes are reserved.
    expect(normalizeDomainName('myexample.com', prod).ascii).toBe('myexample.com');
    expect(normalizeDomainName('example.co', prod).ascii).toBe('example.co');
    expect(normalizeDomainName('latest.io', prod).ascii).toBe('latest.io');
  });
});

describe('isDomainAtOrUnder', () => {
  it('matches the name itself and subdomains, not lookalikes', () => {
    expect(isDomainAtOrUnder('test', 'test')).toBe(true);
    expect(isDomainAtOrUnder('a.b.test', 'test')).toBe(true);
    expect(isDomainAtOrUnder('contest', 'test')).toBe(false);
    expect(isDomainAtOrUnder('a.example.com', 'example.com')).toBe(true);
    expect(isDomainAtOrUnder('notexample.com', 'example.com')).toBe(false);
  });
});
