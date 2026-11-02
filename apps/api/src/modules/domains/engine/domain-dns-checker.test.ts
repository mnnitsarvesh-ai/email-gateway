import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../../../../test/support/dns/test-dns-server';
import { TestDohServer } from '../../../../test/support/dns/test-doh-server';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import { TEST_DOMAIN_ENV } from '../../../../test/support/test-env';
import { type ApiConfig, loadApiConfig } from '../../../config';
import { DnsResolver, type DnsResult, type MxAnswer } from '../../../dns/dns-resolver';
import { createDnsResolverSet, StaticDnsResolverSet } from '../../../dns/dns-resolver-set';
import { dkimTxtValue } from './dkim';
import { DomainDnsChecker, boundEvidence, EVIDENCE_MAX_BYTES } from './domain-dns-checker';
import { verificationRecord } from './verification';

const domain = 'acme.test';
const token = 'c'.repeat(40);
const ownership = verificationRecord(domain, token, '_emailgateway-verify');
const verification = { host: ownership.host, expectedValue: ownership.value };
const rsaKey = {
  selector: 'egr20261102abcd',
  algorithm: 'rsa_2048' as const,
  publicKeyDns: 'MIIBrsaKey',
};
const edKey = {
  selector: 'ege20261102wxyz',
  algorithm: 'ed25519' as const,
  publicKeyDns: 'ed25519Key=',
};

function config(extra: Record<string, string> = {}): ApiConfig {
  return loadApiConfig({
    ...TEST_DOMAIN_ENV,
    DATABASE_URL: 'mysql://u:p@mysql:3306/db',
    REDIS_URL: 'redis://redis:6379',
    S3_REGION: 'ap-south-1',
    S3_BUCKET_MAIL: 'mail',
    S3_BUCKET_ARCHIVE: 'archive',
    AUTH_JWT_SECRET: 'j'.repeat(64),
    AUTH_TOKEN_PEPPER: 'p'.repeat(64),
    DATA_ENCRYPTION_KEY: 'a'.repeat(64),
    GATEWAY_DMARC_RUA: 'mailto:dmarc-reports@mail-gateway.test',
    DNS_TIMEOUT_MS: '300',
    DNS_TRIES: '1',
    ...extra,
  });
}

let dns: TestDnsServer;
let second: TestDnsServer;

beforeAll(async () => {
  [dns, second] = await Promise.all([TestDnsServer.start(), TestDnsServer.start()]);
});
afterAll(async () => {
  await Promise.all([dns.close(), second.close()]);
});
beforeEach(() => {
  dns.reset();
  second.reset();
});

function publishEverything(server: TestDnsServer): void {
  server.setTxt(ownership.host, [ownership.value]);
  server.setMx(domain, [
    { priority: 10, exchange: 'mx1.mail-gateway.test' },
    { priority: 20, exchange: 'mx2.mail-gateway.test' },
  ]);
  server.setTxt(domain, ['v=spf1 include:_spf.mail-gateway.test -all']);
  server.setTxt('_spf.mail-gateway.test', ['v=spf1 ip4:192.0.2.0/24 -all']);
  server.setTxt(`${rsaKey.selector}._domainkey.${domain}`, [
    dkimTxtValue('rsa_2048', rsaKey.publicKeyDns),
  ]);
  server.setTxt(`${edKey.selector}._domainkey.${domain}`, [
    dkimTxtValue('ed25519', edKey.publicKeyDns),
  ]);
  server.setTxt(`_dmarc.${domain}`, ['v=DMARC1; p=reject; rua=mailto:d@acme.test']);
}

function checkerFor(cfg: ApiConfig, kv = new InMemoryKeyValueStore()): DomainDnsChecker {
  return new DomainDnsChecker(createDnsResolverSet(cfg, kv), cfg);
}

describe('DomainDnsChecker', () => {
  it('reports every record valid for a fully configured domain', async () => {
    publishEverything(dns);
    publishEverything(second);
    const checker = checkerFor(
      config({ DNS_SERVERS: dns.address, DNS_PROPAGATION_UPSTREAMS: second.address }),
    );
    const report = await checker.check(
      { domain, verification, dkimKeys: [rsaKey, edKey] },
      { bypassCache: false },
    );
    expect(report.checkedAt).toBeInstanceOf(Date);
    expect(report.indeterminate).toBe(false);
    expect(report.records.map((r) => [r.recordKey, r.outcome])).toEqual([
      ['verification', 'valid'],
      ['mx:mx1.mail-gateway.test', 'valid'],
      ['mx:mx2.mail-gateway.test', 'valid'],
      ['spf', 'valid'],
      [`dkim:${rsaKey.selector}`, 'valid'],
      [`dkim:${edKey.selector}`, 'valid'],
      ['dmarc', 'valid'],
    ]);
    expect(report.records.find((r) => r.recordKey === 'mx:mx2.mail-gateway.test')).toMatchObject({
      expectedValue: '20 mx2.mail-gateway.test',
      observedValue: '10 mx1.mail-gateway.test\n20 mx2.mail-gateway.test',
    });
    expect(report.mx).toEqual({
      observed: [
        { priority: 10, exchange: 'mx1.mail-gateway.test' },
        { priority: 20, exchange: 'mx2.mail-gateway.test' },
      ],
      propagation: [{ upstream: `system:${second.address}`, outcome: 'valid' }],
    });
    expect(report.spf).toEqual({
      lookupCount: 1,
      lookupCountExact: true,
      recommendedValue: 'v=spf1 include:_spf.mail-gateway.test -all',
    });
    expect(report.dmarc).toMatchObject({ stage: 'reject', partial: false });
    const spf = report.records.find((r) => r.recordKey === 'spf')!;
    expect(spf.evidence).toMatchObject({
      lookupCount: 1,
      lookupCountExact: true,
      query: { upstream: `system:${dns.address}`, outcome: 'answer', fromCache: false },
    });
  });

  it('reports a new domain as missing and recommends the default SPF/DMARC', async () => {
    const checker = checkerFor(config({ DNS_SERVERS: dns.address }));
    const report = await checker.check(
      { domain, verification, dkimKeys: [rsaKey] },
      { bypassCache: true },
    );
    expect(report.records.every((r) => r.outcome === 'missing')).toBe(true);
    expect(report.records.every((r) => r.observedValue === null)).toBe(true);
    expect(report.mx.observed).toEqual([]);
    expect(report.records.find((r) => r.recordKey === 'spf')?.expectedValue).toBe(
      'v=spf1 include:_spf.mail-gateway.test ~all',
    );
    expect(report.dmarc).toEqual({
      stage: 'missing',
      partial: false,
      recommendedValue: 'v=DMARC1; p=none; rua=mailto:dmarc-reports@mail-gateway.test; fo=1',
      nextStep: 'Publish a monitoring policy (p=none) and review the aggregate reports.',
    });
  });

  it('keeps SERVFAIL/timeouts indeterminate and never definitive', async () => {
    publishEverything(dns);
    dns.fail(ownership.host, 'servfail');
    dns.fail(domain, 'timeout');
    const checker = checkerFor(config({ DNS_SERVERS: dns.address }));
    const report = await checker.check(
      { domain, verification, dkimKeys: [rsaKey] },
      { bypassCache: false },
    );
    const outcome = (key: string) => report.records.find((r) => r.recordKey === key);
    expect(outcome('verification')).toMatchObject({
      outcome: 'indeterminate',
      observedValue: null,
      evidence: { query: { outcome: 'indeterminate', reason: 'servfail' } },
    });
    expect(outcome('mx:mx1.mail-gateway.test')?.outcome).toBe('indeterminate');
    expect(outcome('spf')?.outcome).toBe('indeterminate');
    expect(outcome(`dkim:${rsaKey.selector}`)?.outcome).toBe('valid');
    expect(report.mx.observed).toBeNull();
    expect(report.indeterminate).toBe(true);
  });

  it('omits the verification record when there is no challenge', async () => {
    const checker = checkerFor(config({ DNS_SERVERS: dns.address }));
    const report = await checker.check(
      { domain, verification: null, dkimKeys: [] },
      { bypassCache: false },
    );
    expect(report.records.map((r) => r.recordKey)).toEqual([
      'mx:mx1.mail-gateway.test',
      'mx:mx2.mail-gateway.test',
      'spf',
      'dmarc',
    ]);
  });

  it('honours bypassCache (reads skipped, results still cached)', async () => {
    const kv = new InMemoryKeyValueStore();
    const checker = checkerFor(config({ DNS_SERVERS: dns.address }), kv);
    const input = { domain, verification, dkimKeys: [] };
    await checker.check(input, { bypassCache: false });
    dns.setTxt(ownership.host, [ownership.value]);
    const cached = await checker.check(input, { bypassCache: false });
    expect(cached.records[0]).toMatchObject({
      outcome: 'missing',
      evidence: { query: { fromCache: true } },
    });
    const fresh = await checker.check(input, { bypassCache: true });
    expect(fresh.records[0]).toMatchObject({
      outcome: 'valid',
      evidence: { query: { fromCache: false } },
    });
  });

  it('turns queries still running at the deadline into indeterminate/timeout', async () => {
    /** Answers MX at once; never answers TXT. */
    class HangingTxtResolver extends DnsResolver {
      readonly upstream = 'system:hanging';
      resolveTxt(): Promise<DnsResult<string>> {
        return new Promise(() => undefined);
      }
      resolveMx(name: string): Promise<DnsResult<MxAnswer>> {
        return Promise.resolve({
          upstream: this.upstream,
          queriedName: name,
          durationMs: 0,
          fromCache: false,
          outcome: 'answer',
          records: [{ priority: 10, exchange: 'mx1.mail-gateway.test' }],
          ttlSeconds: null,
        });
      }
    }
    const cfg = config({ DOMAIN_CHECK_DEADLINE_MS: '1000' });
    const checker = new DomainDnsChecker(
      new StaticDnsResolverSet(new HangingTxtResolver(), []),
      cfg,
    );
    const started = Date.now();
    const report = await checker.check(
      { domain, verification, dkimKeys: [rsaKey] },
      { bypassCache: false },
    );
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(950);
    expect(elapsed).toBeLessThan(2000);
    expect(report.records.find((r) => r.recordKey === 'mx:mx1.mail-gateway.test')?.outcome).toBe(
      'valid',
    );
    for (const key of ['verification', 'spf', `dkim:${rsaKey.selector}`, 'dmarc']) {
      expect(report.records.find((r) => r.recordKey === key)).toMatchObject({
        outcome: 'indeterminate',
        evidence: { query: { reason: 'timeout', detail: 'domain check deadline exceeded' } },
      });
    }
    expect(report.indeterminate).toBe(true);
  });

  it('turns a query that throws into indeterminate/other instead of rejecting the check', async () => {
    // The real adapters throw for names they refuse (assertQueryName), e.g. a host over 253.
    publishEverything(dns);
    const real = createDnsResolverSet(
      config({ DNS_SERVERS: dns.address }),
      new InMemoryKeyValueStore(),
    ).primary;
    class ThrowingDkimResolver extends DnsResolver {
      readonly upstream = real.upstream;
      resolveTxt(name: string): Promise<DnsResult<string>> {
        if (name.includes('._domainkey.')) throw new Error('programming error');
        return real.resolveTxt(name);
      }
      resolveMx(name: string): Promise<DnsResult<MxAnswer>> {
        return real.resolveMx(name);
      }
    }
    const checker = new DomainDnsChecker(
      new StaticDnsResolverSet(new ThrowingDkimResolver(), []),
      config(),
    );
    const report = await checker.check(
      { domain, verification, dkimKeys: [rsaKey] },
      { bypassCache: true },
    );
    expect(report.records.find((r) => r.recordKey === `dkim:${rsaKey.selector}`)).toMatchObject({
      outcome: 'indeterminate',
      observedValue: null,
      evidence: { query: { reason: 'other', detail: 'query failed' } },
    });
    expect(report.records.find((r) => r.recordKey === 'verification')?.outcome).toBe('valid');
    expect(report.indeterminate).toBe(true);
  });

  it('works in DoH mode through the factory', async () => {
    const doh = await TestDohServer.start(dns);
    try {
      publishEverything(dns);
      const checker = checkerFor(config({ DNS_RESOLVER_MODE: 'doh', DNS_DOH_URL: doh.url }));
      const report = await checker.check(
        { domain, verification, dkimKeys: [rsaKey] },
        { bypassCache: true },
      );
      expect(report.records.every((r) => r.outcome === 'valid')).toBe(true);
      expect(report.records[0]?.evidence).toMatchObject({
        query: { upstream: `doh:${doh.url}`, dnssecAuthenticated: false, ttlSeconds: 300 },
      });
    } finally {
      await doh.close();
    }
  });
});

describe('boundEvidence', () => {
  it('keeps small evidence as is and bounds large evidence to 8 KiB', () => {
    expect(boundEvidence({ a: 1, b: ['x'] })).toEqual({ a: 1, b: ['x'] });
    const big = boundEvidence({
      upstream: 'system:x',
      query: { answers: Array.from({ length: 100 }, () => 'y'.repeat(2000)) },
    });
    expect(Buffer.byteLength(JSON.stringify(big))).toBeLessThanOrEqual(EVIDENCE_MAX_BYTES);
    expect(big).toMatchObject({ upstream: 'system:x', truncated: true });
  });

  it('drops non-JSON values', () => {
    expect(boundEvidence({ when: undefined, n: 1 })).toEqual({ n: 1 });
  });
});
