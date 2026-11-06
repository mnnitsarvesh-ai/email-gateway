import { canonicalIp } from '../normalize/ip';
import { mapLimit } from '../net/limiter';
import type { RestrictedResolver } from '../net/resolver';
import type { SsrfGuard } from '../net/ssrf-guard';

/**
 * Addresses of host names for IP reputation (U3 step 5 "resolved/literal IP", brief item 4):
 * every domain host of a message (scan time) or of a clicked URL and its chain (click time) is
 * resolved through the restricted resolver (A + AAAA, explicit servers, never getaddrinfo), and
 * its public addresses become `ip` reputation items. Internal answers (loopback, private,
 * metadata, …) are dropped: an internal address is an SSRF finding of the fetcher, and sending
 * it to an external DNSBL would leak it. A failed or timed-out resolution yields no address
 * (the host's domain reputation still answers); NXDOMAIN is simply "no address".
 */

export interface HostAddressOptions {
  /** Addresses kept per host (in answer order, IPv4 first). Default 4. */
  maxPerHost?: number;
  /** Concurrent resolutions. Default 8. */
  concurrency?: number;
}

export class HostAddressResolver {
  private readonly maxPerHost: number;
  private readonly concurrency: number;

  constructor(
    private readonly resolver: Pick<RestrictedResolver, 'resolveValidated'>,
    private readonly guard: Pick<SsrfGuard, 'checkAddress'>,
    options: HostAddressOptions = {},
  ) {
    this.maxPerHost = Math.max(1, options.maxPerHost ?? 4);
    this.concurrency = Math.max(1, options.concurrency ?? 8);
  }

  /** Host (lower case, as given) → its public addresses; hosts without one are absent. */
  async resolve(hosts: Iterable<string>, signal?: AbortSignal): Promise<Map<string, string[]>> {
    const names = [
      ...new Set(
        [...hosts]
          .map((h) => h.replace(/^\[|\]$/g, '').toLowerCase())
          .filter((h) => h !== '' && canonicalIp(h) === null),
      ),
    ];
    const out = new Map<string, string[]>();
    await mapLimit(names, this.concurrency, async (host) => {
      if (signal?.aborted) return;
      let answers: string[];
      try {
        const outcome = await this.resolver.resolveValidated(host, this.guard as SsrfGuard, signal);
        if (outcome.ok || outcome.blocked) answers = outcome.answers;
        else return;
      } catch {
        return;
      }
      const kept: string[] = [];
      for (const answer of answers) {
        const ip = canonicalIp(answer);
        if (ip === null || kept.includes(ip) || !this.guard.checkAddress(ip).allowed) continue;
        kept.push(ip);
        if (kept.length >= this.maxPerHost) break;
      }
      if (kept.length > 0) out.set(host, kept);
    });
    return out;
  }
}
