import { isIPv4, isIPv6 } from 'node:net';

/**
 * IP literal classification for destination hosts (step 2.3 R3). Self-contained: the api's own
 * address helpers are not shared with packages (module boundaries).
 *
 * "Public" means globally reachable per the IANA IPv4 and IPv6 Special-Purpose Address
 * Registries (RFC 6890 and its updates). Anything a special-purpose entry marks as not globally
 * reachable, anything outside IPv6 global unicast (2000::/3), and addresses that embed a
 * non-public IPv4 address (NAT64 well-known prefix, 6to4, Teredo) are not public. Where the
 * registry marks a tiny anycast service block inside a non-public range as reachable
 * (192.0.0.9/32, 192.0.0.10/32), the whole range is still refused: those are never mail servers,
 * and refusing fails closed.
 */

/** A parsed IP literal: 4 or 16 network-order bytes. */
export interface ParsedIpAddress {
  version: 4 | 6;
  bytes: Uint8Array;
}

interface Cidr {
  bytes: Uint8Array;
  prefix: number;
}

function parseIPv4(text: string): Uint8Array | null {
  if (!isIPv4(text)) return null;
  const parts = text.split('.').map((part) => Number(part));
  return Uint8Array.from(parts);
}

function parseIPv6(text: string): Uint8Array | null {
  if (!isIPv6(text) || text.includes('%')) return null;
  let head = text;
  let tail: number[] = [];
  // Embedded dotted IPv4 in the last 32 bits (e.g. ::ffff:192.0.2.1).
  const lastColon = head.lastIndexOf(':');
  const last = head.slice(lastColon + 1);
  if (last.includes('.')) {
    const v4 = parseIPv4(last);
    if (!v4) return null;
    tail = [(v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!];
    head = head.slice(0, lastColon + 1);
    if (head.endsWith(':') && !head.endsWith('::')) head = head.slice(0, -1);
  }
  const groupsWanted = 8 - tail.length;
  const [leftText, rightText] = head.split('::') as [string, string | undefined];
  const toGroups = (part: string): number[] =>
    part === '' ? [] : part.split(':').map((group) => Number.parseInt(group, 16));
  const left = toGroups(leftText);
  const right = rightText === undefined ? [] : toGroups(rightText);
  const fill = rightText === undefined ? 0 : groupsWanted - left.length - right.length;
  if (fill < 0) return null;
  const groups = [...left, ...new Array<number>(fill).fill(0), ...right, ...tail];
  if (groups.length !== 8 || groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) {
    return null;
  }
  const bytes = new Uint8Array(16);
  groups.forEach((group, i) => {
    bytes[i * 2] = group >> 8;
    bytes[i * 2 + 1] = group & 0xff;
  });
  return bytes;
}

/**
 * Parses an IPv4 dotted quad or an IPv6 literal (no brackets, no zone id). Returns null for
 * anything else, including the legacy inet_aton forms (`127.1`, `0x7f.0.0.1`).
 */
export function parseIpAddress(text: string): ParsedIpAddress | null {
  if (typeof text !== 'string') return null;
  const v4 = parseIPv4(text);
  if (v4) return { version: 4, bytes: v4 };
  const v6 = parseIPv6(text);
  if (v6) return { version: 6, bytes: v6 };
  return null;
}

/** RFC 5952 text of a parsed address (lower-case, longest zero run compressed). */
export function formatIpAddress(address: ParsedIpAddress): string {
  const { bytes } = address;
  if (address.version === 4) return Array.from(bytes).join('.');
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i]! << 8) | bytes[i + 1]!);
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLength < 2) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

function cidr(text: string): Cidr {
  const [address, prefixText] = text.split('/') as [string, string];
  const parsed = parseIpAddress(address);
  if (!parsed) throw new Error(`Invalid CIDR constant ${text}`);
  return { bytes: parsed.bytes, prefix: Number(prefixText) };
}

function inCidr(bytes: Uint8Array, range: Cidr): boolean {
  if (bytes.length !== range.bytes.length) return false;
  const full = Math.floor(range.prefix / 8);
  for (let i = 0; i < full; i += 1) if (bytes[i] !== range.bytes[i]) return false;
  const rest = range.prefix % 8;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (bytes[full]! & mask) === (range.bytes[full]! & mask);
}

/** IANA IPv4 Special-Purpose Address Registry entries that are not globally reachable. */
const IPV4_NOT_PUBLIC: readonly Cidr[] = [
  '0.0.0.0/8', // "this network"
  '10.0.0.0/8', // private
  '100.64.0.0/10', // shared address space (CGNAT)
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local
  '172.16.0.0/12', // private
  '192.0.0.0/24', // IETF protocol assignments (incl. the anycast /32s, refused on purpose)
  '192.0.2.0/24', // documentation TEST-NET-1
  '192.88.99.0/24', // deprecated 6to4 relay anycast
  '192.168.0.0/16', // private
  '198.18.0.0/15', // benchmarking
  '198.51.100.0/24', // documentation TEST-NET-2
  '203.0.113.0/24', // documentation TEST-NET-3
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, includes limited broadcast 255.255.255.255
].map(cidr);

/** IPv6 global unicast; everything outside it is unspecified, special or unallocated. */
const IPV6_GLOBAL_UNICAST = cidr('2000::/3');
const NAT64_WELL_KNOWN = cidr('64:ff9b::/96');
const TEREDO = cidr('2001::/32');
const SIX_TO_FOUR = cidr('2002::/16');

/** Globally reachable exceptions inside 2001::/23 (IETF protocol assignments). */
const IPV6_IETF_REACHABLE: readonly Cidr[] = [
  '2001:1::1/128', // Port Control Protocol anycast
  '2001:1::2/128', // TURN anycast
  '2001:1::3/128', // DNS-SD service registration protocol anycast
  '2001:3::/32', // AMT
  '2001:4:112::/48', // AS112-v6
  '2001:20::/28', // ORCHIDv2
  '2001:30::/28', // drone remote ID entity tags
].map(cidr);

/** Non-public blocks inside 2000::/3. */
const IPV6_NOT_PUBLIC: readonly Cidr[] = [
  '2001::/23', // IETF protocol assignments (exceptions above; Teredo handled separately)
  '2001:db8::/32', // documentation
  '3fff::/20', // documentation (RFC 9637)
].map(cidr);

function isPublicIPv4Bytes(bytes: Uint8Array): boolean {
  return !IPV4_NOT_PUBLIC.some((range) => inCidr(bytes, range));
}

function isPublicIPv6Bytes(bytes: Uint8Array): boolean {
  if (inCidr(bytes, NAT64_WELL_KNOWN)) return isPublicIPv4Bytes(bytes.subarray(12, 16));
  if (!inCidr(bytes, IPV6_GLOBAL_UNICAST)) return false;
  if (inCidr(bytes, TEREDO)) {
    // RFC 4380: server IPv4 in bits 32-63, client IPv4 (bitwise inverted) in bits 96-127.
    const server = bytes.subarray(4, 8);
    const client = Uint8Array.from(bytes.subarray(12, 16), (b) => ~b & 0xff);
    return isPublicIPv4Bytes(server) && isPublicIPv4Bytes(client);
  }
  if (inCidr(bytes, SIX_TO_FOUR)) return isPublicIPv4Bytes(bytes.subarray(2, 6));
  if (IPV6_IETF_REACHABLE.some((range) => inCidr(bytes, range))) return true;
  return !IPV6_NOT_PUBLIC.some((range) => inCidr(bytes, range));
}

/**
 * True when `ip` (an IPv4 dotted quad or an IPv6 literal without brackets) is globally
 * reachable. False for every special-purpose range (private, loopback, link-local, CGNAT,
 * documentation, benchmarking, multicast, reserved, `0/8`, broadcast, unique-local `fc00::/7`,
 * link-local `fe80::/10`, IPv4-mapped and IPv4-compatible IPv6, NAT64 / 6to4 / Teredo with a
 * non-public embedded IPv4 address), for zone-scoped IPv6 and for anything that is not an IP
 * literal.
 */
export function isPublicIpAddress(ip: string): boolean {
  const parsed = parseIpAddress(ip);
  if (!parsed) return false;
  return parsed.version === 4 ? isPublicIPv4Bytes(parsed.bytes) : isPublicIPv6Bytes(parsed.bytes);
}

/** Cloud instance metadata endpoints (AWS IMDS, ECS task metadata, AWS IPv6 IMDS, Alibaba). */
export const METADATA_ADDRESSES: readonly string[] = Object.freeze([
  '169.254.169.254',
  '169.254.170.2',
  'fd00:ec2::254',
  '100.100.100.200',
]);

const METADATA_BYTES: readonly ParsedIpAddress[] = METADATA_ADDRESSES.map((address) =>
  parseIpAddress(address)!,
);
const IPV4_MAPPED = cidr('::ffff:0:0/96');
const IPV4_COMPATIBLE = cidr('::/96');

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

/**
 * True for a cloud metadata address, also when written as IPv4-mapped / IPv4-compatible /
 * NAT64-embedded IPv6. These are refused even when non-public destinations are allowed.
 */
export function isMetadataAddress(ip: string): boolean {
  const parsed = parseIpAddress(ip);
  if (!parsed) return false;
  const candidates = [parsed.bytes];
  if (
    parsed.version === 6 &&
    (inCidr(parsed.bytes, IPV4_MAPPED) ||
      inCidr(parsed.bytes, IPV4_COMPATIBLE) ||
      inCidr(parsed.bytes, NAT64_WELL_KNOWN))
  ) {
    candidates.push(parsed.bytes.subarray(12, 16));
  }
  return candidates.some((bytes) => METADATA_BYTES.some((m) => sameBytes(m.bytes, bytes)));
}
