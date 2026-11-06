import { describe, expect, it } from 'vitest';
import { bytesToIpv6, canonicalIp, ipv6ToBytes, reverseIpLabel } from './ip';
import {
  hostMatchesDomain,
  normalizeDomainInput,
  normalizeIndicator,
  normalizeUrl,
  registrableDomainOf,
  sha256Hex,
  type NormalizedUrl,
} from './url';

const norm = (input: string, maxLength?: number): NormalizedUrl => {
  const result = normalizeUrl(input, maxLength ? { maxLength } : {});
  if (!result.ok) throw new Error(`not normalized: ${input} (${result.code})`);
  return result.url;
};

describe('normalizeUrl', () => {
  it('lower-cases scheme and host, removes default ports, resolves dot segments, keeps query order', () => {
    const url = norm('HTTP://ExAmple.COM:80/a/./b/../c?z=1&a=2#Frag');
    expect(url.scheme).toBe('http');
    expect(url.host).toBe('example.com');
    expect(url.port).toBeNull();
    expect(url.identity).toBe('http://example.com/a/c?z=1&a=2');
    expect(url.redirect).toBe('http://example.com/a/c?z=1&a=2#Frag');
    expect(url.flags).toEqual([]);
    expect(norm('https://example.com:443/').identity).toBe('https://example.com/');
  });

  it('keeps and flags non-standard ports', () => {
    const url = norm('https://example.com:8443/x');
    expect(url.port).toBe(8443);
    expect(url.flags).toContain('url.nonstandard_port');
    expect(url.identity).toBe('https://example.com:8443/x');
  });

  it('removes userinfo from both forms and flags it', () => {
    const url = norm('http://user:secret@example.com/path#f');
    expect(url.identity).toBe('http://example.com/path');
    expect(url.redirect).toBe('http://example.com/path#f');
    expect(url.identity).not.toContain('secret');
    expect(url.flags).toContain('url.userinfo');
  });

  it('removes the trailing dot of the host and flags it', () => {
    const url = norm('http://example.com./x');
    expect(url.host).toBe('example.com');
    expect(url.identity).toBe('http://example.com/x');
    expect(url.flags).toContain('url.trailing_dot');
  });

  it.each([
    ['http://2130706433/', '127.0.0.1'],
    ['http://0177.0.0.1/', '127.0.0.1'],
    ['http://0x7f.0.0.1/', '127.0.0.1'],
    ['http://0x7f.1/', '127.0.0.1'],
    ['http://127.1/', '127.0.0.1'],
  ])('canonicalizes the obfuscated IPv4 %s and flags it', (input, host) => {
    const url = norm(input);
    expect(url.host).toBe(host);
    expect(url.hostKind).toBe('ipv4');
    expect(url.flags).toContain('url.ip_obfuscated');
    expect(url.registrableDomain).toBeNull();
  });

  it('does not flag a plain dotted IPv4', () => {
    const url = norm('http://203.0.113.10/');
    expect(url.hostKind).toBe('ipv4');
    expect(url.flags).not.toContain('url.ip_obfuscated');
  });

  it('compresses IPv6 (RFC 5952) and stores it without brackets', () => {
    const url = norm('http://[0:0:0:0:0:0:0:1]:8080/x');
    expect(url.host).toBe('::1');
    expect(url.hostKind).toBe('ipv6');
    expect(url.port).toBe(8080);
    expect(url.identity).toBe('http://[::1]:8080/x');
    expect(norm('http://[::ffff:127.0.0.1]/').host).toBe('::ffff:7f00:1');
  });

  it('flags a percent-encoded host', () => {
    const url = norm('http://%65xample.com/');
    expect(url.host).toBe('example.com');
    expect(url.flags).toContain('url.obfuscated_host');
  });

  it('keeps IDN hosts as A-labels with a Unicode display form (UTS #46 non-transitional)', () => {
    const cyrillic = norm('http://exаmplebank.test/login');
    expect(cyrillic.host).toBe('xn--exmplebank-0qi.test');
    expect(cyrillic.unicodeHost).toBe('exаmplebank.test');
    expect(cyrillic.flags).toContain('url.idn');
    expect(cyrillic.registrableDomain).toBe('xn--exmplebank-0qi.test');
    // Deviation characters are kept (non-transitional), not mapped to ss / σ.
    expect(norm('https://faß.de/').host).toBe('xn--fa-hia.de');
    expect(norm('https://ςa.gr/').host).toBe('xn--a-xmb.gr');
    expect(norm('http://example.com/').unicodeHost).toBeNull();
  });

  it('refuses invalid IDN and non-http(s) schemes', () => {
    expect(normalizeUrl('http://xn--a.com/')).toEqual({ ok: false, code: 'url.invalid' });
    expect(normalizeUrl('http://a b.com/')).toEqual({ ok: false, code: 'url.invalid' });
    expect(normalizeUrl('not a url')).toEqual({ ok: false, code: 'url.invalid' });
    expect(normalizeUrl('ftp://example.com/')).toMatchObject({
      ok: false,
      code: 'url.unsupported_scheme',
      scheme: 'ftp',
    });
    expect(normalizeUrl('javascript:alert(1)')).toMatchObject({
      ok: false,
      code: 'url.unsupported_scheme',
    });
  });

  it('computes the registrable domain with private suffixes and the default rule for .test', () => {
    expect(norm('http://a.b.example.co.uk/').registrableDomain).toBe('example.co.uk');
    expect(norm('https://user.github.io/').registrableDomain).toBe('user.github.io');
    expect(norm('http://a.foo.test/').registrableDomain).toBe('foo.test');
    expect(norm('http://login.paypal.com.evil.tld/').registrableDomain).toBe('evil.tld');
    expect(registrableDomainOf('co.uk')).toBeNull();
    expect(registrableDomainOf('10.0.0.1')).toBeNull();
  });

  it('hashes the identity form (fragment and userinfo do not change the hash)', () => {
    const a = norm('http://u:p@example.com/x#one');
    const b = norm('http://example.com/x#two');
    expect(a.sha256).toBe(b.sha256);
    expect(a.sha256).toBe(sha256Hex('http://example.com/x'));
  });

  it('marks URLs longer than the maximum as truncated and stores a prefix', () => {
    const long = `http://example.com/${'a'.repeat(3000)}`;
    const url = norm(long, 2048);
    expect(url.truncated).toBe(true);
    expect(url.stored).toHaveLength(2048);
    expect(url.flags).toContain('url.too_long');
    expect(url.sha256).toBe(sha256Hex(long));
    expect(norm('http://example.com/short').truncated).toBe(false);
  });

  it('resolves relative URLs only against an absolute http(s) base', () => {
    expect(normalizeUrl('/x', { base: 'http://b.test/a/' })).toMatchObject({
      ok: true,
      url: { identity: 'http://b.test/x' },
    });
    expect(normalizeUrl('/x', { base: 'file:///etc/' })).toEqual({
      ok: false,
      code: 'url.invalid',
    });
  });
});

describe('domain helpers', () => {
  it('matches hosts on whole labels', () => {
    expect(hostMatchesDomain('a.example.com', 'example.com')).toBe(true);
    expect(hostMatchesDomain('example.com', 'example.com')).toBe(true);
    expect(hostMatchesDomain('badexample.com', 'example.com')).toBe(false);
    expect(hostMatchesDomain('example.com', '')).toBe(false);
  });

  it('normalizes administrator input and refuses public suffixes, IPs and single labels', () => {
    expect(normalizeDomainInput('Bücher.Example.')).toMatchObject({
      ok: true,
      domain: 'xn--bcher-kva.example',
    });
    expect(normalizeDomainInput('co.uk')).toEqual({ ok: false, code: 'public_suffix' });
    expect(normalizeDomainInput('github.io')).toEqual({ ok: false, code: 'public_suffix' });
    expect(normalizeDomainInput('10.0.0.1')).toEqual({ ok: false, code: 'ip_literal' });
    expect(normalizeDomainInput('[::1]')).toEqual({ ok: false, code: 'ip_literal' });
    expect(normalizeDomainInput('intranet')).toEqual({ ok: false, code: 'single_label' });
    expect(normalizeDomainInput('a/b.com')).toEqual({ ok: false, code: 'invalid' });
  });

  it('normalizes threat-indicator values', () => {
    expect(normalizeIndicator('url', 'HTTP://Evil.Test/x#y')).toEqual({
      ok: true,
      type: 'url',
      value: 'http://evil.test/x',
      valueSha256: sha256Hex('http://evil.test/x'),
    });
    expect(normalizeIndicator('ip', '::ffff:7f00:1')).toMatchObject({
      ok: true,
      value: '::ffff:7f00:1',
    });
    expect(normalizeIndicator('ip', '0:0::1')).toMatchObject({ ok: true, value: '::1' });
    expect(normalizeIndicator('domain', 'Evil.Test')).toMatchObject({
      ok: true,
      value: 'evil.test',
    });
    expect(normalizeIndicator('domain', 'com')).toEqual({ ok: false, code: 'single_label' });
    expect(normalizeIndicator('ip', 'nope')).toEqual({ ok: false, code: 'invalid' });
  });
});

describe('ip helpers', () => {
  it('round-trips IPv6 bytes with RFC 5952 compression', () => {
    expect(bytesToIpv6(ipv6ToBytes('2001:db8:0:0:1:0:0:1') as Uint8Array)).toBe(
      '2001:db8::1:0:0:1',
    );
    expect(bytesToIpv6(ipv6ToBytes('::ffff:1.2.3.4') as Uint8Array)).toBe('::ffff:102:304');
    expect(canonicalIp('[FD00:EC2::254]')).toBe('fd00:ec2::254');
    expect(canonicalIp('1.2.3')).toBeNull();
  });

  it('builds DNSBL query labels', () => {
    expect(reverseIpLabel('203.0.113.10')).toBe('10.113.0.203');
    expect(reverseIpLabel('2001:db8::1')).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2',
    );
  });
});
