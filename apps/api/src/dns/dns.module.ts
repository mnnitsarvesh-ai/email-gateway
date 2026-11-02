import { Module } from '@nestjs/common';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';
import { KeyValueStore } from '../kv/key-value-store';
import { DnsResolver, DnsResolverSet } from './dns-resolver';
import { createDnsResolverSet } from './dns-resolver-set';

/**
 * DNS resolution (ADR-0017). Not global: feature modules that verify DNS import it. Provides the
 * resolver set (primary + MX propagation upstreams) and the primary as `DnsResolver`. Construction
 * performs no network I/O. Relies on `API_CONFIG` and the global `KeyValueStore`.
 */
@Module({
  providers: [
    {
      provide: DnsResolverSet,
      useFactory: (config: ApiConfig, kv: KeyValueStore) => createDnsResolverSet(config, kv),
      inject: [API_CONFIG, KeyValueStore],
    },
    {
      provide: DnsResolver,
      useFactory: (set: DnsResolverSet) => set.primary,
      inject: [DnsResolverSet],
    },
  ],
  exports: [DnsResolverSet, DnsResolver],
})
export class DnsModule {}
