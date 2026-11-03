/**
 * Client networks of `source_ip` / `client_certificate` connectors (step 2.2 D10, §3). Pure:
 * parsing, canonical CIDR text, the 4/16-byte big-endian range stored in
 * `smtp_connector_networks.range_start/range_end`, and overlap math. The smtp-adapter looks a
 * client IP up with `range_start <= ip ORDER BY range_start DESC LIMIT 1` and then checks
 * `range_end >= ip`, which is only correct because ranges never overlap (enforced by the api).
 */

/** Smallest prefix accepted per IP version (D10): at most a /16 (IPv4) or a /48 (IPv6). */
export const MIN_PREFIX = { 4: 16, 6: 48 } as const;
export const MAX_PREFIX = { 4: 32, 6: 128 } as const;
/** Networks per connector (D10). */
export const MAX_NETWORKS_PER_CONNECTOR = 20;

export type IpVersion = 4 | 6;

export interface ParsedNetwork {
  /** Canonical text: network address (host bits cleared) + `/prefix`, RFC 5952 for IPv6. */
  cidr: string;
  ipVersion: IpVersion;
  prefix: number;
  /** First address, 4 or 16 bytes big-endian. */
  rangeStart: Buffer;
  /** Last address, same length as `rangeStart`. */
  rangeEnd: Buffer;
}

/** A refused network; `message` is safe to return (it never echoes the input). */
export class NetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NetworkError';
  }
}

const DECIMAL_OCTET = /^(0|[1-9][0-9]{0,2})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/i;
const PREFIX = /^(0|[1-9][0-9]{0,2})$/;

/** Strict dotted-quad parser (no leading zeros, no shorthand); null when invalid. */
export function parseIpv4(text: string): Buffer | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const bytes = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i]!;
    if (!DECIMAL_OCTET.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes[i] = value;
  }
  return bytes;
}

/** RFC 4291 text form (with `::` and an embedded dotted quad); null when invalid or zoned. */
export function parseIpv6(text: string): Buffer | null {
  if (text.length === 0 || text.length > 45 || text.includes('%')) return null;
  let head = text;
  let tail = '';
  const doubleColon = text.indexOf('::');
  if (doubleColon !== -1) {
    if (text.indexOf('::', doubleColon + 1) !== -1) return null;
    head = text.slice(0, doubleColon);
    tail = text.slice(doubleColon + 2);
  }
  const groups = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    const items = part.split(':');
    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      if (i === items.length - 1 && item.includes('.')) {
        const v4 = parseIpv4(item);
        if (!v4) return null;
        out.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!);
      } else {
        if (!HEX_GROUP.test(item)) return null;
        out.push(parseInt(item, 16));
      }
    }
    return out;
  };
  const before = groups(head);
  const after = groups(tail);
  if (!before || !after) return null;
  // An embedded IPv4 is only allowed at the very end.
  if (doubleColon !== -1 && head.includes('.')) return null;
  let all: number[];
  if (doubleColon === -1) {
    if (before.length !== 8) return null;
    all = before;
  } else {
    const missing = 8 - before.length - after.length;
    if (missing < 1) return null;
    all = [...before, ...new Array<number>(missing).fill(0), ...after];
  }
  const bytes = Buffer.alloc(16);
  all.forEach((group, i) => bytes.writeUInt16BE(group, i * 2));
  return bytes;
}

/** RFC 5952 canonical text of a 16-byte IPv6 address (lower case, longest zero run as `::`). */
export function formatIpv6(bytes: Buffer): string {
  const groups = Array.from({ length: 8 }, (_, i) => bytes.readUInt16BE(i * 2));
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = (list: number[]) => list.map((g) => g.toString(16)).join(':');
  if (bestLength < 2) return hex(groups);
  return `${hex(groups.slice(0, bestStart))}::${hex(groups.slice(bestStart + bestLength))}`;
}

export function formatIpv4(bytes: Buffer): string {
  return Array.from(bytes).join('.');
}

/** Clears (`fill = 0`) or sets (`fill = 1`) every bit after `prefix`. */
function maskFrom(address: Buffer, prefix: number, fill: 0 | 1): Buffer {
  const out = Buffer.from(address);
  for (let bit = prefix; bit < out.length * 8; bit++) {
    const byte = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    out[byte] = fill ? out[byte]! | mask : out[byte]! & ~mask;
  }
  return out;
}

const IPV4_MAPPED_PREFIX = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);

/**
 * Parses `address/prefix` (a bare address means a single host: /32 or /128) into its canonical
 * form and range. Host bits are cleared (`192.0.2.7/24` → `192.0.2.0/24`). Refuses prefixes
 * shorter than /16 (IPv4) or /48 (IPv6), IPv6 zone ids and IPv4-mapped IPv6 addresses (use the
 * IPv4 form: Postfix reports IPv4 clients as IPv4).
 */
export function parseNetwork(input: string): ParsedNetwork {
  const text = input.trim();
  const slash = text.indexOf('/');
  const addressText = slash === -1 ? text : text.slice(0, slash);
  const prefixText = slash === -1 ? undefined : text.slice(slash + 1);

  let ipVersion: IpVersion;
  let address: Buffer | null = parseIpv4(addressText);
  if (address) {
    ipVersion = 4;
  } else {
    address = parseIpv6(addressText);
    if (!address) throw new NetworkError('must be an IPv4 or IPv6 address or CIDR network');
    ipVersion = 6;
    if (address.subarray(0, 12).equals(IPV4_MAPPED_PREFIX)) {
      throw new NetworkError('must use the IPv4 form for IPv4-mapped IPv6 addresses');
    }
  }

  const max: number = MAX_PREFIX[ipVersion];
  let prefix = max;
  if (prefixText !== undefined) {
    if (!PREFIX.test(prefixText) || Number(prefixText) > max) {
      throw new NetworkError(`must have a prefix length between 0 and ${max}`);
    }
    prefix = Number(prefixText);
  }
  if (prefix < MIN_PREFIX[ipVersion]) {
    throw new NetworkError(
      `must not be larger than /${MIN_PREFIX[ipVersion]} for IPv${ipVersion} networks`,
    );
  }

  const rangeStart = maskFrom(address, prefix, 0);
  const rangeEnd = maskFrom(address, prefix, 1);
  const base = ipVersion === 4 ? formatIpv4(rangeStart) : formatIpv6(rangeStart);
  return { cidr: `${base}/${prefix}`, ipVersion, prefix, rangeStart, rangeEnd };
}

/** True when two networks share at least one address (same IP version, ranges intersect). */
export function networksOverlap(
  a: Pick<ParsedNetwork, 'ipVersion' | 'rangeStart' | 'rangeEnd'>,
  b: Pick<ParsedNetwork, 'ipVersion' | 'rangeStart' | 'rangeEnd'>,
): boolean {
  if (a.ipVersion !== b.ipVersion) return false;
  return (
    Buffer.compare(a.rangeStart, b.rangeEnd) <= 0 && Buffer.compare(b.rangeStart, a.rangeEnd) <= 0
  );
}

/** Index pairs `[i, j]` (i < j) of networks in the list that overlap each other. */
export function findInternalOverlap(networks: readonly ParsedNetwork[]): [number, number] | null {
  for (let i = 0; i < networks.length; i++) {
    for (let j = i + 1; j < networks.length; j++) {
      if (networksOverlap(networks[i]!, networks[j]!)) return [i, j];
    }
  }
  return null;
}

/**
 * Ranges that are not globally reachable (IANA IPv4/IPv6 Special-Purpose Address Registries,
 * "Globally Reachable: False", plus multicast and the reserved/limited-broadcast block). A
 * connector network overlapping any of them is refused unless the deployment allows it
 * (`SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS`, dedicated deployments relaying from a customer's
 * private networks). Otherwise one tenant could claim the gateway's own internal ranges (so
 * internal peers that reach port 25 would be attributed to its connector) or ranges that are
 * meaningless on the Internet, and lock every other tenant out of them (review finding,
 * docs/plan/steps/04-smtp-gateway.md §12.7).
 */
export const NON_PUBLIC_NETWORKS: readonly string[] = [
  '0.0.0.0/8', // "this network"
  '10.0.0.0/8', // RFC 1918
  '100.64.0.0/10', // shared address space (CGNAT)
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local
  '172.16.0.0/12', // RFC 1918
  '192.0.0.0/24', // IETF protocol assignments
  '192.0.2.0/24', // TEST-NET-1
  '192.88.99.0/24', // deprecated 6to4 relay anycast
  '192.168.0.0/16', // RFC 1918
  '198.18.0.0/15', // benchmarking
  '198.51.100.0/24', // TEST-NET-2
  '203.0.113.0/24', // TEST-NET-3
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, limited broadcast
  '::/128', // unspecified
  '::1/128', // loopback
  '64:ff9b:1::/48', // local-use IPv4/IPv6 translation
  '100::/64', // discard-only
  '2001::/32', // Teredo
  '2001:2::/48', // benchmarking
  '2001:10::/28', // ORCHID (deprecated)
  '2001:20::/28', // ORCHIDv2
  '2001:db8::/32', // documentation
  '3fff::/20', // documentation (RFC 9637)
  '5f00::/16', // SRv6 SIDs
  'fc00::/7', // unique local
  'fe80::/10', // link-local
  'fec0::/10', // site-local (deprecated)
  'ff00::/8', // multicast
];

/** Parsed once; the list above is static. */
const NON_PUBLIC_PARSED: readonly ParsedNetwork[] = NON_PUBLIC_NETWORKS.map((cidr) =>
  parseRange(cidr),
);

/** Like `parseNetwork`, without the /16 and /48 floor (the special-purpose list needs /4…). */
function parseRange(cidr: string): ParsedNetwork {
  const [addressText, prefixText] = cidr.split('/') as [string, string];
  const v4 = parseIpv4(addressText);
  const address = v4 ?? parseIpv6(addressText);
  if (!address) throw new Error(`invalid special-purpose range ${cidr}`);
  const ipVersion: IpVersion = v4 ? 4 : 6;
  const prefix = Number(prefixText);
  return {
    cidr,
    ipVersion,
    prefix,
    rangeStart: maskFrom(address, prefix, 0),
    rangeEnd: maskFrom(address, prefix, 1),
  };
}

/** True when the network is entirely globally reachable (overlaps no non-public range). */
export function isPublicNetwork(
  network: Pick<ParsedNetwork, 'ipVersion' | 'rangeStart' | 'rangeEnd'>,
): boolean {
  return !NON_PUBLIC_PARSED.some((reserved) => networksOverlap(network, reserved));
}

/** Safe to return (never echoes the input). */
export const NON_PUBLIC_NETWORK_MESSAGE =
  'must be a publicly routable network (private, loopback, link-local, shared, documentation, multicast and reserved ranges are refused)';
