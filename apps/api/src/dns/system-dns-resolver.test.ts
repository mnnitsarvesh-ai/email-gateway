import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../../test/support/dns/test-dns-server';
import { SystemDnsResolver } from './system-dns-resolver';

let dns: TestDnsServer;
let resolver: SystemDnsResolver;

beforeAll(async () => {
  dns = await TestDnsServer.start();
  resolver = new SystemDnsResolver({ servers: [dns.address], timeoutMs: 300, tries: 1 });
});
afterAll(() => dns.close());
beforeEach(() => dns.reset());

describe('SystemDnsResolver', () => {
  it('identifies its upstream', () => {
    expect(resolver.upstream).toBe(`system:${dns.address}`);
    expect(new SystemDnsResolver({ servers: [], timeoutMs: 300, tries: 1 }).upstream).toBe(
      'system:default',
    );
  });

  it('returns TXT answers, one joined string per record, without a TTL', async () => {
    dns.setTxt('acme.test', ['v=spf1 -all', 'other']);
    const result = await resolver.resolveTxt('acme.test');
    expect(result).toMatchObject({
      outcome: 'answer',
      ttlSeconds: null,
      upstream: `system:${dns.address}`,
      queriedName: 'acme.test',
      fromCache: false,
    });
    expect(result.outcome === 'answer' && [...result.records].sort()).toEqual([
      'other',
      'v=spf1 -all',
    ]);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('joins long TXT records split into 255-byte strings', async () => {
    const long = `v=DKIM1; k=rsa; p=${'A'.repeat(600)}`;
    dns.setTxt('sel._domainkey.acme.test', [long]);
    const result = await resolver.resolveTxt('sel._domainkey.acme.test');
    expect(result.outcome === 'answer' && result.records).toEqual([long]);
  });

  it('falls back to TCP when the UDP answer is truncated', async () => {
    const values = ['a', 'b', 'c'].map((c) => c.repeat(700));
    dns.setTxt('big.acme.test', values);
    const result = await resolver.resolveTxt('big.acme.test');
    expect(result.outcome === 'answer' && [...result.records].sort()).toEqual(values);
    expect(dns.queries.map((q) => q.transport)).toEqual(['udp', 'tcp']);
  });

  it('lower-cases MX exchanges', async () => {
    dns.setMx('acme.test', [{ priority: 10, exchange: 'MX1.Mail-Gateway.TEST' }]);
    const result = await resolver.resolveMx('acme.test');
    expect(result.outcome === 'answer' && result.records).toEqual([
      { priority: 10, exchange: 'mx1.mail-gateway.test' },
    ]);
  });

  it('maps NXDOMAIN and NODATA (other type, empty non-terminal)', async () => {
    dns.setMx('acme.test', [{ priority: 10, exchange: 'mx.acme.test' }]);
    dns.setTxt('_dmarc.sub.acme.test', ['v=DMARC1; p=none']);
    expect((await resolver.resolveTxt('missing.test')).outcome).toBe('nxdomain');
    expect((await resolver.resolveTxt('acme.test')).outcome).toBe('nodata');
    expect((await resolver.resolveTxt('sub.acme.test')).outcome).toBe('nodata');
  });

  it.each([
    ['servfail', 'servfail'],
    ['refused', 'refused'],
    ['timeout', 'timeout'],
  ] as const)('maps an injected %s to indeterminate/%s', async (failure, reason) => {
    dns.fail('acme.test', failure);
    const result = await resolver.resolveTxt('acme.test');
    expect(result).toMatchObject({ outcome: 'indeterminate', reason });
  });

  it('retries up to DNS_TRIES on timeouts', async () => {
    const twice = new SystemDnsResolver({ servers: [dns.address], timeoutMs: 150, tries: 2 });
    dns.fail('slow.acme.test', 'timeout');
    expect((await twice.resolveTxt('slow.acme.test')).outcome).toBe('indeterminate');
    expect(dns.queries.length).toBeGreaterThanOrEqual(2);
  });

  it('reports an unreachable upstream as indeterminate, never as a negative answer', async () => {
    const closed = new SystemDnsResolver({ servers: ['127.0.0.1:9'], timeoutMs: 200, tries: 1 });
    const result = await closed.resolveTxt('acme.test');
    expect(result.outcome).toBe('indeterminate');
    if (result.outcome === 'indeterminate') expect(['network', 'timeout']).toContain(result.reason);
  });

  it('throws for an invalid query name (programming error)', async () => {
    await expect(resolver.resolveTxt('acme.test.')).rejects.toThrow(/normalized/);
    await expect(resolver.resolveTxt('')).rejects.toThrow();
    await expect(resolver.resolveMx('bad name.test')).rejects.toThrow();
  });
});
