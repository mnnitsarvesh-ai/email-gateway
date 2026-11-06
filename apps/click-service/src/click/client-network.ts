import { canonicalizeAddress, ipv6ToBytes } from '@email-gateway/url-security';

/**
 * The client's network (U14): IPv4 truncated to /24, IPv6 to /48 (IPv4-mapped/compatible IPv6
 * is treated as its IPv4). Used as the rate-limit key and, when CLICK_STORE_CLIENT_NETWORK is
 * on, stored in `url_click_events.client_network` — never the full address. Unknown or
 * unparsable input → `unknown`.
 */
export function clientNetwork(address: string | undefined | null): string {
  const canonical = address ? canonicalizeAddress(address.trim()) : null;
  if (canonical === null) return 'unknown';
  if (canonical.family === 'ipv4') {
    const [a, b, c] = canonical.address.split('.');
    return `${a}.${b}.${c}.0/24`;
  }
  const bytes = ipv6ToBytes(canonical.address);
  if (bytes === null) return 'unknown';
  const groups = [0, 2, 4].map((i) => (((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0)).toString(16));
  return `${groups.join(':')}::/48`;
}
