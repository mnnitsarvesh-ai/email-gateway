import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { indeterminate, negative, txtAnswer } from '../../../../test/support/dns/dns-results';
import { TestDnsServer } from '../../../../test/support/dns/test-dns-server';
import { SystemDnsResolver } from '../../../dns/system-dns-resolver';
import {
  countSpfLookups,
  evaluateSpf,
  isSpfRecord,
  parseSpf,
  recommendSpf,
  SPF_MAX_RESOLUTIONS,
} from './spf';

const INCLUDE = '_spf.mail-gateway.test';
let dns: TestDnsServer;
let resolver: SystemDnsResolver;

beforeAll(async () => {
  dns = await TestDnsServer.start();
  resolver = new SystemDnsResolver({ servers: [dns.address], timeoutMs: 300, tries: 1 });
});
afterAll(() => dns.close());
beforeEach(() => {
  dns.reset();
  // The gateway's own SPF record: ip ranges only (no further lookups).
  dns.setTxt(INCLUDE, ['v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all']);
});

describe('parseSpf', () => {
  it('recognises SPF records case-insensitively and only as v=spf1', () => {
    expect(isSpfRecord('v=spf1 -all')).toBe(true);
    expect(isSpfRecord('V=SPF1 mx')).toBe(true);
    expect(isSpfRecord('v=spf1')).toBe(true);
    expect(isSpfRecord('v=spf10 -all')).toBe(false);
    expect(isSpfRecord('google-site-verification=x')).toBe(false);
  });

  it('parses mechanisms with qualifiers and modifiers', () => {
    const { terms, syntaxErrors } = parseSpf(
      'v=spf1 +a mx/24 -ip4:192.0.2.1 ~include:_spf.example.net ?exists:%{i}.x.test redirect=_spf.acme.test exp=explain.acme.test',
    );
    expect(syntaxErrors).toEqual([]);
    expect(
      terms.map((t) => (t.kind === 'mechanism' ? `${t.qualifier}${t.name}` : `${t.name}=`)),
    ).toEqual(['+a', '+mx', '-ip4', '~include', '?exists', 'redirect=', 'exp=']);
  });

  it('reports syntax errors per term', () => {
    expect(parseSpf('v=spf1 include ip4:300 all:x foo -all').syntaxErrors).toEqual([
      'include',
      'ip4:300',
      'all:x',
      'foo',
    ]);
  });
});

describe('recommendSpf', () => {
  it('recommends a new record when there is none', () => {
    expect(recommendSpf(null, INCLUDE)).toBe(`v=spf1 include:${INCLUDE} ~all`);
  });

  it('inserts the include right after v=spf1 and keeps everything else', () => {
    expect(
      recommendSpf('v=spf1 mx  include:_spf.google.com redirect=_spf.acme.test', INCLUDE),
    ).toBe(`v=spf1 include:${INCLUDE} mx include:_spf.google.com redirect=_spf.acme.test`);
    expect(recommendSpf('v=spf1 -all', INCLUDE)).toBe(`v=spf1 include:${INCLUDE} -all`);
  });

  it('keeps a record that already includes the gateway (case-insensitive)', () => {
    expect(recommendSpf(`v=spf1 mx include:_SPF.Mail-Gateway.test -all`, INCLUDE)).toBe(
      'v=spf1 mx include:_SPF.Mail-Gateway.test -all',
    );
  });
});

describe('countSpfLookups', () => {
  it('counts DNS-querying terms recursively through include and redirect', async () => {
    dns.setTxt('a.acme.test', ['v=spf1 include:b.acme.test mx a ~all']);
    dns.setTxt('b.acme.test', ['v=spf1 exists:x.acme.test ptr -all']);
    dns.setTxt('r.acme.test', ['v=spf1 a -all']);
    const result = await countSpfLookups(
      `v=spf1 include:${INCLUDE} include:a.acme.test ip4:10.0.0.1 redirect=r.acme.test`,
      resolver,
    );
    // top: 2 includes + redirect = 3; a: include+mx+a = 3; b: exists+ptr = 2; r: a = 1
    expect(result).toEqual({ lookupCount: 9, exact: true, resolutions: 4, loops: [] });
  });

  it('ignores redirect when the record has an all mechanism', async () => {
    const result = await countSpfLookups('v=spf1 mx -all redirect=r.acme.test', resolver);
    expect(result.lookupCount).toBe(1);
    expect(dns.queries).toEqual([]);
  });

  it('detects include loops and treats them as over the limit', async () => {
    dns.setTxt('loop1.acme.test', ['v=spf1 include:loop2.acme.test -all']);
    dns.setTxt('loop2.acme.test', ['v=spf1 include:loop1.acme.test -all']);
    const result = await countSpfLookups('v=spf1 include:loop1.acme.test -all', resolver);
    expect(result.loops).toEqual(['loop1.acme.test']);
    expect(result.lookupCount).toBeGreaterThan(10);
    expect(result.resolutions).toBe(2);
  });

  it('marks the count inexact when an include is indeterminate or uses macros', async () => {
    dns.fail('broken.acme.test', 'servfail');
    const result = await countSpfLookups(
      'v=spf1 include:broken.acme.test include:%{d}.spf.acme.test -all',
      resolver,
    );
    expect(result).toMatchObject({ lookupCount: 2, exact: false });
  });

  it('stops after 20 resolutions and marks the count inexact', async () => {
    const chainLength = 25;
    for (let i = 0; i < chainLength; i++) {
      dns.setTxt(`w${i}.acme.test`, ['v=spf1 -all']);
    }
    const includes = Array.from({ length: chainLength }, (_, i) => `include:w${i}.acme.test`);
    const result = await countSpfLookups(`v=spf1 ${includes.join(' ')} -all`, resolver);
    expect(result.resolutions).toBe(SPF_MAX_RESOLUTIONS);
    expect(result.exact).toBe(false);
    expect(result.lookupCount).toBe(chainLength);
  });

  it('stops at depth 10', async () => {
    for (let i = 0; i < 12; i++)
      dns.setTxt(`d${i}.acme.test`, [`v=spf1 include:d${i + 1}.acme.test -all`]);
    const result = await countSpfLookups('v=spf1 include:d0.acme.test -all', resolver);
    expect(result.exact).toBe(false);
    expect(result.resolutions).toBe(10);
  });

  it('counts nothing below an include without SPF or with several SPF records', async () => {
    dns.setTxt('nospf.acme.test', ['hello']);
    dns.setTxt('two.acme.test', ['v=spf1 mx -all', 'v=spf1 a -all']);
    const result = await countSpfLookups(
      'v=spf1 include:nospf.acme.test include:two.acme.test include:none.acme.test -all',
      resolver,
    );
    expect(result).toMatchObject({ lookupCount: 3, exact: true });
  });
});

describe('evaluateSpf', () => {
  const domain = 'acme.test';

  it('is missing without an SPF record and recommends the default', async () => {
    for (const apex of [
      negative<string>(domain, 'nxdomain'),
      negative<string>(domain, 'nodata'),
      txtAnswer(domain, ['google-site-verification=x']),
    ]) {
      const result = await evaluateSpf(apex, INCLUDE, resolver);
      expect(result).toMatchObject({
        outcome: 'missing',
        observedValue: null,
        recommendedValue: `v=spf1 include:${INCLUDE} ~all`,
        lookupCount: 1,
        lookupCountExact: true,
        warnings: [],
      });
    }
  });

  it('is valid with the include and at most 10 lookups', async () => {
    const record = `v=spf1 include:${INCLUDE} mx -all`;
    const result = await evaluateSpf(txtAnswer(domain, [record, 'other']), INCLUDE, resolver);
    expect(result).toMatchObject({
      outcome: 'valid',
      observedValue: record,
      recommendedValue: record,
      lookupCount: 2,
      records: [record],
      warnings: [],
    });
  });

  it('is invalid without the include and recommends a merge', async () => {
    const result = await evaluateSpf(txtAnswer(domain, ['v=spf1 mx ~all']), INCLUDE, resolver);
    expect(result).toMatchObject({
      outcome: 'invalid',
      recommendedValue: `v=spf1 include:${INCLUDE} mx ~all`,
    });
  });

  it('is invalid with several SPF records (permerror at receivers)', async () => {
    const result = await evaluateSpf(
      txtAnswer(domain, [`v=spf1 include:${INCLUDE} -all`, 'v=spf1 mx -all']),
      INCLUDE,
      resolver,
    );
    expect(result).toMatchObject({
      outcome: 'invalid',
      warnings: ['spf_multiple_records'],
      recommendedValue: `v=spf1 include:${INCLUDE} -all`,
    });
  });

  it('is invalid over 10 lookups, counting the gateway include', async () => {
    const terms = Array.from({ length: 10 }, (_, i) => `a:h${i}.acme.test`).join(' ');
    const record = `v=spf1 include:${INCLUDE} ${terms} -all`;
    const result = await evaluateSpf(txtAnswer(domain, [record]), INCLUDE, resolver);
    expect(result).toMatchObject({
      outcome: 'invalid',
      lookupCount: 11,
      warnings: ['spf_lookup_limit_exceeded'],
    });
  });

  it('warns about ptr, +all, long records, syntax errors and unknown counts', async () => {
    dns.fail('flaky.acme.test', 'timeout');
    const record = `v=spf1 include:${INCLUDE} include:flaky.acme.test ptr ip4:${'1'.repeat(3)} bogus +all ${'ip4:192.0.2.1 '.repeat(30).trim()}`;
    const result = await evaluateSpf(txtAnswer(domain, [record]), INCLUDE, resolver);
    expect(result.outcome).toBe('valid');
    expect(result.warnings).toEqual([
      'spf_lookup_count_unknown',
      'spf_ptr_mechanism',
      'spf_plus_all',
      'spf_syntax_error:ip4:111',
      'spf_syntax_error:bogus',
      'spf_record_too_long',
    ]);
    expect(result.lookupCountExact).toBe(false);
  });

  it('stays indeterminate when the apex lookup is', async () => {
    const result = await evaluateSpf(indeterminate<string>(domain, 'timeout'), INCLUDE, resolver);
    expect(result).toMatchObject({ outcome: 'indeterminate', observedValue: null });
  });
});
