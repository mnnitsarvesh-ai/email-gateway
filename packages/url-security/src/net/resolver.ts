import { promises as dns } from 'node:dns';
import { type BlockedReason, type SsrfGuard } from './ssrf-guard';

/**
 * The restricted resolver (U8): `dns.promises.Resolver` with explicit servers, timeout and tries.
 * Never `dns.lookup`/getaddrinfo, never /etc/hosts. A and AAAA in parallel, at most 16 answers
 * each; if ANY answer is blocked the host is blocked (mixed answers are a rebinding or
 * split-horizon signal); else the first allowed IPv4, else the first IPv6. No cache: every hop
 * resolves again.
 */

export const MAX_DNS_ANSWERS = 16;

export interface ResolverOptions {
  /** URL_DNS_SERVERS (`ip`, `ip:port`, `[v6]:port`); empty = the system resolver's servers. */
  servers?: readonly string[];
  /** URL_DNS_TIMEOUT_MS (per try). */
  timeoutMs?: number;
  /** URL_DNS_TRIES. */
  tries?: number;
  maxAnswers?: number;
}

/** DNS error classes (bounded). `nxdomain`/`nodata` are answers, the rest are failures. */
export type DnsErrorKind = 'nxdomain' | 'nodata' | 'servfail' | 'timeout' | 'refused' | 'error';

export class DnsLookupError extends Error {
  constructor(
    readonly kind: DnsErrorKind,
    readonly code: string,
  ) {
    super(`dns ${kind} (${code})`);
    this.name = 'DnsLookupError';
  }
}

export function classifyDnsError(error: unknown): DnsLookupError {
  const code = (error as { code?: unknown })?.code;
  const text = typeof code === 'string' ? code : 'UNKNOWN';
  switch (text) {
    case dns.NOTFOUND:
      return new DnsLookupError('nxdomain', text);
    case dns.NODATA:
      return new DnsLookupError('nodata', text);
    case dns.SERVFAIL:
      return new DnsLookupError('servfail', text);
    case dns.TIMEOUT:
    case dns.CANCELLED:
      return new DnsLookupError('timeout', text);
    case dns.REFUSED:
    case dns.CONNREFUSED:
      return new DnsLookupError('refused', text);
    default:
      return new DnsLookupError('error', text);
  }
}

export type ResolveOutcome =
  | { ok: true; address: string; family: 4 | 6; answers: string[] }
  | { ok: false; blocked: true; reason: BlockedReason; answers: string[] }
  | { ok: false; blocked: false; error: DnsErrorKind };

/** The subset of dns.promises.Resolver used here (tests substitute a fake). */
export interface DnsBackend {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  cancel(): void;
}

export type DnsBackendFactory = (
  options: Required<Omit<ResolverOptions, 'maxAnswers'>>,
) => DnsBackend;

const defaultFactory: DnsBackendFactory = ({ servers, timeoutMs, tries }) => {
  const resolver = new dns.Resolver({ timeout: timeoutMs, tries });
  if (servers.length > 0) resolver.setServers([...servers]);
  return resolver;
};

export class RestrictedResolver {
  private readonly options: Required<Omit<ResolverOptions, 'maxAnswers'>>;
  private readonly maxAnswers: number;

  constructor(
    options: ResolverOptions = {},
    private readonly factory: DnsBackendFactory = defaultFactory,
  ) {
    this.options = {
      servers: options.servers ?? [],
      timeoutMs: options.timeoutMs ?? 2000,
      tries: options.tries ?? 2,
    };
    this.maxAnswers = options.maxAnswers ?? MAX_DNS_ANSWERS;
    // Validate the server list once (setServers throws on a malformed entry).
    this.factory(this.options).cancel();
  }

  /** One family; a fresh backend per query, so `cancel` on abort affects only this query. */
  private async query(kind: 4 | 6, name: string, signal?: AbortSignal): Promise<string[]> {
    const backend = this.factory(this.options);
    const onAbort = (): void => backend.cancel();
    if (signal?.aborted) throw new DnsLookupError('timeout', 'ECANCELLED');
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      const answers = await (kind === 4 ? backend.resolve4(name) : backend.resolve6(name));
      return answers.slice(0, this.maxAnswers);
    } catch (error) {
      throw classifyDnsError(error);
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  /** Raw A records (DNSBL queries): NXDOMAIN/NODATA → empty list; other failures throw. */
  async resolve4Raw(name: string, signal?: AbortSignal): Promise<string[]> {
    try {
      return await this.query(4, name, signal);
    } catch (error) {
      if (
        error instanceof DnsLookupError &&
        (error.kind === 'nxdomain' || error.kind === 'nodata')
      ) {
        return [];
      }
      throw error;
    }
  }

  /** A + AAAA of a host (both may be empty; a failure of both families throws). */
  async resolveAll(host: string, signal?: AbortSignal): Promise<{ v4: string[]; v6: string[] }> {
    const [v4, v6] = await Promise.allSettled([
      this.query(4, host, signal),
      this.query(6, host, signal),
    ]);
    const answer = (r: PromiseSettledResult<string[]>): string[] | DnsLookupError =>
      r.status === 'fulfilled'
        ? r.value
        : r.reason instanceof DnsLookupError
          ? r.reason
          : classifyDnsError(r.reason);
    const a = answer(v4);
    const b = answer(v6);
    const empty = (x: string[] | DnsLookupError): boolean =>
      Array.isArray(x) || x.kind === 'nxdomain' || x.kind === 'nodata';
    // A real failure of one family while the other has no answer is a failure (never partial).
    if (!Array.isArray(a) && !empty(a) && (!Array.isArray(b) || b.length === 0)) throw a;
    if (!Array.isArray(b) && !empty(b) && (!Array.isArray(a) || a.length === 0)) throw b;
    const v4list = Array.isArray(a) ? a : [];
    const v6list = Array.isArray(b) ? b : [];
    if (v4list.length === 0 && v6list.length === 0) {
      const kind = !Array.isArray(a) ? a.kind : !Array.isArray(b) ? b.kind : 'nodata';
      throw new DnsLookupError(kind, 'NOANSWER');
    }
    return { v4: v4list, v6: v6list };
  }

  /** Resolves and validates a host with the any-blocked rule. */
  async resolveValidated(
    host: string,
    guard: SsrfGuard,
    signal?: AbortSignal,
  ): Promise<ResolveOutcome> {
    let answers: { v4: string[]; v6: string[] };
    try {
      answers = await this.resolveAll(host, signal);
    } catch (error) {
      return {
        ok: false,
        blocked: false,
        error: error instanceof DnsLookupError ? error.kind : 'error',
      };
    }
    const all = [...answers.v4, ...answers.v6];
    for (const address of all) {
      const decision = guard.checkAddress(address);
      if (!decision.allowed)
        return { ok: false, blocked: true, reason: decision.reason, answers: all };
    }
    const v4 = answers.v4[0];
    if (v4 !== undefined) return { ok: true, address: v4, family: 4, answers: all };
    return { ok: true, address: answers.v6[0] as string, family: 6, answers: all };
  }
}
