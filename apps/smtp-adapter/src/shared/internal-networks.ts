import { BlockList, isIPv4, isIPv6 } from 'node:net';

/**
 * Peer allow-list of the adapter's internal listeners (step 2.2 D7, D20):
 * `SMTP_INTERNAL_CLIENT_NETWORKS` (default loopback + RFC 1918). Every listener refuses peers
 * outside it, so a host-mode adapter is reachable from Docker but not from other networks.
 */

const IPV4_MAPPED_DOTTED = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;
const IPV4_MAPPED_HEX = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i;
const PREFIX = /^(0|[1-9][0-9]{0,2})$/;

/**
 * Parses a comma-separated list of IPv4/IPv6 CIDRs (a bare address means a single host) into a
 * `BlockList` used as an allow-list. Whitespace around entries is ignored. Throws on an empty
 * list or any invalid entry, so a typo fails at startup instead of silently refusing (or
 * admitting) peers.
 */
export function parseNetworkList(csv: string): BlockList {
  const entries = csv
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (entries.length === 0) throw new Error('Network list is empty');

  const list = new BlockList();
  for (const entry of entries) {
    const slash = entry.indexOf('/');
    const address = slash === -1 ? entry : entry.slice(0, slash);
    const prefixText = slash === -1 ? undefined : entry.slice(slash + 1);
    const family = isIPv4(address)
      ? 'ipv4'
      : isIPv6(address) && !address.includes('%')
        ? 'ipv6'
        : null;
    if (family === null) throw new Error(`Invalid network "${entry}": not an IP address`);
    const max = family === 'ipv4' ? 32 : 128;
    let prefix = max;
    if (prefixText !== undefined) {
      if (!PREFIX.test(prefixText) || Number(prefixText) > max) {
        throw new Error(`Invalid network "${entry}": prefix must be 0..${max}`);
      }
      prefix = Number(prefixText);
    }
    list.addSubnet(address, prefix, family);
  }
  return list;
}

/**
 * Canonical form for the allow-list check: IPv4-mapped IPv6 (`::ffff:a.b.c.d`, or its hex
 * form) becomes plain IPv4, an IPv6 zone id is dropped. Null for anything that is not an IP.
 */
export function normalizeClientAddress(
  address: string | undefined,
): { address: string; family: 'ipv4' | 'ipv6' } | null {
  if (typeof address !== 'string') return null;
  let candidate = address.trim();
  const zone = candidate.indexOf('%');
  if (zone !== -1) candidate = candidate.slice(0, zone);

  const dotted = IPV4_MAPPED_DOTTED.exec(candidate);
  if (dotted && isIPv4(dotted[1]!)) return { address: dotted[1]!, family: 'ipv4' };
  const hex = IPV4_MAPPED_HEX.exec(candidate);
  if (hex) {
    const high = parseInt(hex[1]!, 16);
    const low = parseInt(hex[2]!, 16);
    return {
      address: [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.'),
      family: 'ipv4',
    };
  }
  if (isIPv4(candidate)) return { address: candidate, family: 'ipv4' };
  if (isIPv6(candidate)) return { address: candidate, family: 'ipv6' };
  return null;
}

/** True when the peer address is inside the allow-list. Unknown or invalid addresses → false. */
export function isAllowedClient(list: BlockList, address: string | undefined): boolean {
  const normalized = normalizeClientAddress(address);
  if (!normalized) return false;
  return list.check(normalized.address, normalized.family);
}
