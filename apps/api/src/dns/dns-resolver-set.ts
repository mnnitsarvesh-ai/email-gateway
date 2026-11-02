import type { ApiConfig } from '../config';
import type { KeyValueStore } from '../kv/key-value-store';
import { CachingDnsResolver } from './caching-dns-resolver';
import { parseDnsServer } from './dns-names';
import { type DnsResolver, DnsResolverSet } from './dns-resolver';
import { DohDnsResolver } from './doh-dns-resolver';
import { SystemDnsResolver } from './system-dns-resolver';

export type DnsResolverConfig = Pick<
  ApiConfig,
  | 'DNS_RESOLVER_MODE'
  | 'DNS_SERVERS'
  | 'DNS_DOH_URL'
  | 'DNS_TIMEOUT_MS'
  | 'DNS_TRIES'
  | 'DNS_PROPAGATION_UPSTREAMS'
  | 'DNS_CACHE_MAX_TTL_SECONDS'
  | 'DNS_CACHE_NEGATIVE_TTL_SECONDS'
>;

export class StaticDnsResolverSet extends DnsResolverSet {
  constructor(
    readonly primary: DnsResolver,
    readonly propagation: readonly DnsResolver[],
  ) {
    super();
  }
}

function servers(entries: readonly string[]): string[] {
  return entries.map((entry) => {
    const server = parseDnsServer(entry);
    // The config schema validated every entry; reaching this is a programming error.
    if (server === null) throw new Error('DNS server entry is not a valid address');
    return server;
  });
}

/**
 * Builds the primary resolver (`DNS_SERVERS` or `DNS_DOH_URL`) and one resolver per
 * `DNS_PROPAGATION_UPSTREAMS` entry, each behind the Redis cache unless
 * `DNS_CACHE_MAX_TTL_SECONDS = 0`. No network I/O happens here.
 */
export function createDnsResolverSet(config: DnsResolverConfig, kv: KeyValueStore): DnsResolverSet {
  const timing = { timeoutMs: config.DNS_TIMEOUT_MS, tries: config.DNS_TRIES };
  const build = (upstream: { servers: string[] } | { url: string }): DnsResolver => {
    const adapter =
      'url' in upstream
        ? new DohDnsResolver({ url: upstream.url, ...timing })
        : new SystemDnsResolver({ servers: upstream.servers, ...timing });
    return config.DNS_CACHE_MAX_TTL_SECONDS > 0
      ? new CachingDnsResolver(adapter, kv, {
          maxTtlSeconds: config.DNS_CACHE_MAX_TTL_SECONDS,
          negativeTtlSeconds: config.DNS_CACHE_NEGATIVE_TTL_SECONDS,
        })
      : adapter;
  };

  if (config.DNS_RESOLVER_MODE === 'doh') {
    return new StaticDnsResolverSet(
      build({ url: config.DNS_DOH_URL }),
      config.DNS_PROPAGATION_UPSTREAMS.map((url) => build({ url })),
    );
  }
  return new StaticDnsResolverSet(
    build({ servers: servers(config.DNS_SERVERS) }),
    servers(config.DNS_PROPAGATION_UPSTREAMS).map((server) => build({ servers: [server] })),
  );
}
