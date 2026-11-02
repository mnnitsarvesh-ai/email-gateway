import { Global, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import { InMemoryKeyValueStore } from '../../test/support/in-memory-key-value-store';
import { TEST_DOMAIN_ENV } from '../../test/support/test-env';
import { API_CONFIG } from '../api-config.token';
import { loadApiConfig } from '../config';
import { KeyValueStore } from '../kv/key-value-store';
import { CachingDnsResolver } from './caching-dns-resolver';
import { DnsResolver, DnsResolverSet } from './dns-resolver';
import { createDnsResolverSet } from './dns-resolver-set';
import { DnsModule } from './dns.module';
import { DohDnsResolver } from './doh-dns-resolver';
import { SystemDnsResolver } from './system-dns-resolver';

const env = {
  ...TEST_DOMAIN_ENV,
  DATABASE_URL: 'mysql://u:p@mysql:3306/db',
  REDIS_URL: 'redis://redis:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'mail',
  S3_BUCKET_ARCHIVE: 'archive',
  AUTH_JWT_SECRET: 'j'.repeat(64),
  AUTH_TOKEN_PEPPER: 'p'.repeat(64),
  DATA_ENCRYPTION_KEY: 'a'.repeat(64),
};

describe('createDnsResolverSet', () => {
  it('builds cached system resolvers with canonical upstream ids', () => {
    const set = createDnsResolverSet(
      loadApiConfig({
        ...env,
        DNS_SERVERS: '10.0.0.2,[::1]:5353',
        DNS_PROPAGATION_UPSTREAMS: '1.1.1.1,8.8.8.8:53',
      }),
      new InMemoryKeyValueStore(),
    );
    expect(set.primary).toBeInstanceOf(CachingDnsResolver);
    expect(set.primary.upstream).toBe('system:10.0.0.2:53,[::1]:5353');
    expect(set.propagation.map((r) => r.upstream)).toEqual([
      'system:1.1.1.1:53',
      'system:8.8.8.8:53',
    ]);
  });

  it('builds DoH resolvers in doh mode', () => {
    const set = createDnsResolverSet(
      loadApiConfig({
        ...env,
        DNS_RESOLVER_MODE: 'doh',
        DNS_DOH_URL: 'https://dns.example.net/dns-query',
        DNS_PROPAGATION_UPSTREAMS: 'https://doh2.example.net/dns-query',
      }),
      new InMemoryKeyValueStore(),
    );
    expect(set.primary.upstream).toBe('doh:https://dns.example.net/dns-query');
    expect(set.propagation.map((r) => r.upstream)).toEqual([
      'doh:https://doh2.example.net/dns-query',
    ]);
  });

  it('skips the cache when DNS_CACHE_MAX_TTL_SECONDS is 0', () => {
    const system = createDnsResolverSet(
      loadApiConfig({ ...env, DNS_CACHE_MAX_TTL_SECONDS: '0' }),
      new InMemoryKeyValueStore(),
    );
    expect(system.primary).toBeInstanceOf(SystemDnsResolver);
    expect(system.primary.upstream).toBe('system:default');
    const doh = createDnsResolverSet(
      loadApiConfig({ ...env, DNS_CACHE_MAX_TTL_SECONDS: '0', DNS_RESOLVER_MODE: 'doh' }),
      new InMemoryKeyValueStore(),
    );
    expect(doh.primary).toBeInstanceOf(DohDnsResolver);
    expect(doh.propagation).toEqual([]);
  });
});

describe('DnsModule', () => {
  it('provides the resolver set and the primary resolver without network I/O', async () => {
    const config = loadApiConfig({ ...env, DNS_SERVERS: '127.0.0.1:5399' });
    /** Stands in for the root module and ApiCommonModule, which provide these globally. */
    @Global()
    @Module({
      providers: [
        { provide: API_CONFIG, useValue: config },
        { provide: KeyValueStore, useValue: new InMemoryKeyValueStore() },
      ],
      exports: [API_CONFIG, KeyValueStore],
    })
    class GlobalsModule {}
    const moduleRef = await Test.createTestingModule({
      imports: [GlobalsModule, DnsModule],
    }).compile();
    const set = moduleRef.get(DnsResolverSet);
    expect(set.primary.upstream).toBe('system:127.0.0.1:5399');
    expect(moduleRef.get(DnsResolver)).toBe(set.primary);
    await moduleRef.close();
  });
});
