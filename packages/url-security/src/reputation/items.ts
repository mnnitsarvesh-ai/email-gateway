import type { FetchResult } from '../net/fetcher';
import { canonicalIp } from '../normalize/ip';
import { normalizeUrl, type NormalizedUrl } from '../normalize/url';
import { type ReputationItem } from './types';

/** Resolved addresses by host (HostAddressResolver); absent hosts have none. */
export type HostAddresses = ReadonlyMap<string, readonly string[]>;

/**
 * The reputation items of one URL (U3 step 5): the URL (identity form), its host (domain kind;
 * providers expand to parents / the registrable domain themselves) or its IP literal, plus any
 * extra IPs (resolved addresses). Unique, in this order.
 */
export function reputationItemsFor(
  url: NormalizedUrl,
  extraIps: readonly string[] = [],
): ReputationItem[] {
  const items: ReputationItem[] = [{ kind: 'url', value: url.identity }];
  if (url.hostKind === 'domain') items.push({ kind: 'domain', value: url.host });
  else items.push({ kind: 'ip', value: url.host });
  for (const ip of extraIps) {
    const canonical = canonicalIp(ip);
    if (canonical !== null && !items.some((i) => i.kind === 'ip' && i.value === canonical)) {
      items.push({ kind: 'ip', value: canonical });
    }
  }
  return items;
}

/** Items of a URL given as text (final URLs of chains); empty when it does not normalize. */
export function reputationItemsForText(url: string | null): ReputationItem[] {
  if (!url) return [];
  const result = normalizeUrl(url);
  return result.ok ? reputationItemsFor(result.url) : [];
}

/** Unique items over several lists (stable order). */
export function uniqueItems(lists: ReadonlyArray<readonly ReputationItem[]>): ReputationItem[] {
  const seen = new Set<string>();
  const out: ReputationItem[] = [];
  for (const list of lists) {
    for (const item of list) {
      const key = `${item.kind}\u0000${item.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(item);
    }
  }
  return out;
}

/** `ip` items of the addresses the given hosts resolved to (unique, stable order). */
export function addressItems(hosts: Iterable<string>, addresses: HostAddresses): ReputationItem[] {
  const items: ReputationItem[] = [];
  for (const host of hosts) {
    for (const ip of addresses.get(host.toLowerCase()) ?? []) {
      if (!items.some((i) => i.value === ip)) items.push({ kind: 'ip', value: ip });
    }
  }
  return items;
}

/** The domain hosts of a fetch chain that are looked up: the final URL's and later hops'. */
export function chainHosts(result: Pick<FetchResult, 'hops' | 'finalUrl'>): string[] {
  const hosts: string[] = [];
  if (result.finalUrl) {
    const final = normalizeUrl(result.finalUrl);
    if (final.ok && final.url.hostKind === 'domain') hosts.push(final.url.host);
  }
  for (const hop of result.hops.slice(1)) {
    if (hop.blocked) continue;
    const host = hop.host.replace(/^\[|\]$/g, '').toLowerCase();
    if (host && canonicalIp(host) === null && !hosts.includes(host)) hosts.push(host);
  }
  return hosts;
}

/**
 * The reputation items of a fetch result's chain (scan time and click time): the final URL and
 * its host, the hosts of later hops (blocked hops excluded), and — with `addresses` — the
 * addresses those domain hosts resolved to.
 */
export function chainItems(
  result: Pick<FetchResult, 'hops' | 'finalUrl'>,
  addresses: HostAddresses = new Map(),
): ReputationItem[] {
  const items: ReputationItem[] = [];
  const push = (item: ReputationItem): void => {
    if (!items.some((i) => i.kind === item.kind && i.value === item.value)) items.push(item);
  };
  if (result.finalUrl) {
    const final = normalizeUrl(result.finalUrl);
    if (final.ok) {
      push({ kind: 'url', value: final.url.identity });
      push({ kind: final.url.hostKind === 'domain' ? 'domain' : 'ip', value: final.url.host });
    }
  }
  for (const hop of result.hops.slice(1)) {
    if (hop.blocked) continue;
    const host = hop.host.replace(/^\[|\]$/g, '').toLowerCase();
    if (!host) continue;
    const ip = canonicalIp(host);
    push(ip !== null ? { kind: 'ip', value: ip } : { kind: 'domain', value: host });
  }
  for (const item of addressItems(chainHosts(result), addresses)) push(item);
  return items;
}
