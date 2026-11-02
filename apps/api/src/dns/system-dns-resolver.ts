import { Resolver } from 'node:dns/promises';
import { performance } from 'node:perf_hooks';
import {
  assertQueryName,
  type DnsIndeterminateReason,
  DnsResolver,
  type DnsResult,
  type MxAnswer,
  stripTrailingDot,
} from './dns-resolver';

export interface SystemDnsResolverOptions {
  /** Canonical `ip:port` / `[ipv6]:port` entries (see `parseDnsServer`); empty = host resolvers. */
  servers: readonly string[];
  /** Per try (c-ares `timeout`). */
  timeoutMs: number;
  tries: number;
}

/** `node:dns` error codes → indeterminate reasons (ADR-0017 §2). */
const INDETERMINATE_CODES: Readonly<Record<string, DnsIndeterminateReason>> = {
  ETIMEOUT: 'timeout',
  ESERVFAIL: 'servfail',
  EREFUSED: 'refused',
  ECONNREFUSED: 'network',
  ECONNRESET: 'network',
  EADDRGETNETWORKPARAMS: 'network',
  EBADRESP: 'malformed',
  EFORMERR: 'malformed',
  EBADNAME: 'malformed',
};

function errorCode(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : 'UNKNOWN';
}

/**
 * `node:dns` (c-ares) adapter: no search list, one `Resolver` per upstream set. c-ares uses EDNS
 * and retries over TCP when a UDP answer is truncated. `node:dns` does not expose TTLs for TXT
 * or MX, so `ttlSeconds` is always null (the cache then uses its negative-TTL cap).
 */
export class SystemDnsResolver extends DnsResolver {
  readonly upstream: string;
  private readonly resolver: Resolver;

  constructor(options: SystemDnsResolverOptions) {
    super();
    this.resolver = new Resolver({ timeout: options.timeoutMs, tries: options.tries });
    if (options.servers.length > 0) this.resolver.setServers([...options.servers]);
    this.upstream = `system:${options.servers.length > 0 ? options.servers.join(',') : 'default'}`;
  }

  resolveTxt(name: string): Promise<DnsResult<string>> {
    return this.query(name, async () =>
      (await this.resolver.resolveTxt(name)).map((chunks) => chunks.join('')),
    );
  }

  resolveMx(name: string): Promise<DnsResult<MxAnswer>> {
    return this.query(name, async () =>
      (await this.resolver.resolveMx(name)).map((mx) => ({
        priority: mx.priority,
        exchange: stripTrailingDot(mx.exchange).toLowerCase(),
      })),
    );
  }

  private async query<T>(name: string, run: () => Promise<T[]>): Promise<DnsResult<T>> {
    assertQueryName(name);
    const started = performance.now();
    const base = () => ({
      upstream: this.upstream,
      queriedName: name,
      durationMs: Math.round(performance.now() - started),
      fromCache: false,
    });
    try {
      const records = await run();
      // c-ares reports an empty answer as ENODATA; keep the invariant "answer has records".
      if (records.length === 0) return { ...base(), outcome: 'nodata', ttlSeconds: null };
      return { ...base(), outcome: 'answer', records, ttlSeconds: null };
    } catch (err) {
      const code = errorCode(err);
      if (code === 'ENOTFOUND') return { ...base(), outcome: 'nxdomain', ttlSeconds: null };
      if (code === 'ENODATA') return { ...base(), outcome: 'nodata', ttlSeconds: null };
      return {
        ...base(),
        outcome: 'indeterminate',
        reason: INDETERMINATE_CODES[code] ?? 'other',
        detail: code,
      };
    }
  }
}
