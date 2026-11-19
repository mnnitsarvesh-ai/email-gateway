import { Resolver } from 'node:dns/promises';

/** The lookups the checks need (a fake implements it in unit tests). */
export interface ProbeResolver {
  /** IPv4 and IPv6 addresses of a host (empty when it has none). */
  addresses(host: string): Promise<string[]>;
  /** TXT strings (each record's chunks joined) of a name; empty when none. */
  txt(name: string): Promise<string[]>;
  /** CNAME targets of a name; empty when none. */
  cname(name: string): Promise<string[]>;
}

const NO_DATA = new Set(['ENODATA', 'ENOTFOUND', 'NXDOMAIN', 'ENONAME']);

const noData = (error: unknown): boolean => {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && NO_DATA.has(code);
};

/**
 * DNS for SMTP probes and DKIM evidence (D10): `INTEGRATION_PROBE_DNS_SERVERS` (empty = the
 * system resolver; locally the dns-sink). "No such name / no data" is an empty answer; any other
 * failure (timeout, SERVFAIL, refused) is thrown, so callers can tell "absent" from "unknown".
 */
export class DnsProbeResolver implements ProbeResolver {
  private readonly resolver: Resolver;

  constructor(options: { servers: readonly string[]; timeoutMs: number }) {
    this.resolver = new Resolver({
      timeout: Math.max(500, Math.floor(options.timeoutMs / 2)),
      tries: 2,
    });
    if (options.servers.length > 0) this.resolver.setServers([...options.servers]);
  }

  async addresses(host: string): Promise<string[]> {
    const [v4, v6] = await Promise.allSettled([
      this.resolver.resolve4(host),
      this.resolver.resolve6(host),
    ]);
    const out: string[] = [];
    let failure: Error | null = null;
    for (const result of [v4, v6]) {
      if (result.status === 'fulfilled') out.push(...result.value);
      else if (!noData(result.reason)) {
        failure = result.reason instanceof Error ? result.reason : new Error('dns lookup failed');
      }
    }
    if (out.length === 0 && failure !== null) throw failure;
    return out;
  }

  async txt(name: string): Promise<string[]> {
    try {
      return (await this.resolver.resolveTxt(name)).map((chunks) => chunks.join(''));
    } catch (error) {
      if (noData(error)) return [];
      throw error;
    }
  }

  async cname(name: string): Promise<string[]> {
    try {
      return await this.resolver.resolveCname(name);
    } catch (error) {
      if (noData(error)) return [];
      throw error;
    }
  }
}
