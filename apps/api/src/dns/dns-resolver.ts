/**
 * DNS resolution port (ADR-0017, design D5 of step 2.1). Adapters return one of four outcomes;
 * `indeterminate` means "unknown" and must never be treated as a negative answer.
 */
export type DnsIndeterminateReason =
  'timeout' | 'servfail' | 'refused' | 'network' | 'malformed' | 'other';

export interface MxAnswer {
  priority: number;
  /** Lower-case, no trailing dot. */
  exchange: string;
}

interface DnsResultBase {
  /** Stable id of the upstream that answered, e.g. `system:127.0.0.1:53` or `doh:https://…`. */
  upstream: string;
  queriedName: string;
  durationMs: number;
  fromCache: boolean;
  /**
   * DoH only: the `AD` (authentic data) flag of the upstream's response. Evidence only: the
   * gateway does not validate DNSSEC itself (ADR-0017). Absent for the system resolver.
   */
  dnssecAuthenticated?: boolean;
}

export type DnsResult<T> =
  | (DnsResultBase & { outcome: 'answer'; records: T[]; ttlSeconds: number | null })
  | (DnsResultBase & { outcome: 'nxdomain' | 'nodata'; ttlSeconds: number | null })
  | (DnsResultBase & {
      outcome: 'indeterminate';
      reason: DnsIndeterminateReason;
      detail: string;
    });

export interface DnsQueryOptions {
  /** Skip cache reads (results are still cached). User-triggered verification sets it. */
  bypassCache?: boolean;
}

export abstract class DnsResolver {
  abstract readonly upstream: string;
  /** Each TXT record's character-strings joined in order (one string per record). */
  abstract resolveTxt(name: string, options?: DnsQueryOptions): Promise<DnsResult<string>>;
  abstract resolveMx(name: string, options?: DnsQueryOptions): Promise<DnsResult<MxAnswer>>;
}

/** Injectable: the configured primary resolver plus the MX propagation resolvers. */
export abstract class DnsResolverSet {
  abstract readonly primary: DnsResolver;
  abstract readonly propagation: readonly DnsResolver[];
}

/** Record types the port resolves. */
export type DnsRecordType = 'TXT' | 'MX';

/** True for `answer`, `nxdomain` and `nodata`. */
export function isDefinitive<T>(
  result: DnsResult<T>,
): result is Exclude<DnsResult<T>, { outcome: 'indeterminate' }> {
  return result.outcome !== 'indeterminate';
}

/**
 * Argument check shared by the adapters: names are queried as given (normalized ASCII, no
 * trailing dot). An invalid name is a programming error, so this throws.
 */
export function assertQueryName(name: string): void {
  if (
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > 253 ||
    name.endsWith('.') ||
    !/^[A-Za-z0-9_.-]+$/.test(name) ||
    name.split('.').some((label) => label.length === 0 || label.length > 63)
  ) {
    throw new Error('DNS query name must be a normalized ASCII domain name');
  }
}

/** Strips one trailing dot (answers from some upstreams are absolute). */
export function stripTrailingDot(name: string): string {
  return name.endsWith('.') ? name.slice(0, -1) : name;
}
