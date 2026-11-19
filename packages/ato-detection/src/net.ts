/**
 * IP helpers (step 8.4 D7, D8, §4.3): parsing and canonical text, classification of geolocatable
 * addresses (public unicast only; documentation ranges only when explicitly allowed for tests),
 * the /24 and /48 prefixes used as novelty keys, and CIDR parsing and containment for trusted and
 * blocked networks, trusted contexts and `connector_ip` restrictions.
 */
import { isIP } from 'node:net';

export type IpVersion = 4 | 6;

export interface ParsedIp {
  version: IpVersion;
  /** 4 or 16 bytes. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is returned as IPv4. */
  bytes: Buffer;
}

function parseV4(ip: string): Buffer | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const out = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i]!;
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseV6(ip: string): Buffer | null {
  let text = ip.toLowerCase();
  const zone = text.indexOf('%');
  if (zone >= 0) return null;
  let tail: Buffer | null = null;
  const lastColon = text.lastIndexOf(':');
  if (text.includes('.', lastColon)) {
    tail = parseV4(text.slice(lastColon + 1));
    if (!tail) return null;
    text = `${text.slice(0, lastColon + 1)}0:0`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (halves.length === 1 && head.length !== 8) return null;
  if (groups < 0 || (halves.length === 2 && groups < 1)) return null;
  const all = [...head, ...Array<string>(groups).fill('0'), ...rest];
  if (all.length !== 8) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const g = all[i]!;
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.writeUInt16BE(parseInt(g, 16), i * 2);
  }
  if (tail) tail.copy(out, 12);
  return out;
}

const V4_MAPPED_PREFIX = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);

/** Parses an IP literal (no zone, no brackets). IPv4-mapped IPv6 becomes IPv4. */
export function parseIp(ip: string): ParsedIp | null {
  const kind = isIP(ip);
  if (kind === 4) {
    const bytes = parseV4(ip);
    return bytes ? { version: 4, bytes } : null;
  }
  if (kind === 6) {
    const bytes = parseV6(ip);
    if (!bytes) return null;
    if (bytes.subarray(0, 12).equals(V4_MAPPED_PREFIX)) {
      return { version: 4, bytes: Buffer.from(bytes.subarray(12)) };
    }
    return { version: 6, bytes };
  }
  return null;
}

/** Canonical text of bytes: dotted IPv4, RFC 5952 compressed lower-case IPv6. */
export function formatIp(parsed: ParsedIp): string {
  if (parsed.version === 4) return [...parsed.bytes].join('.');
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(parsed.bytes.readUInt16BE(i));
  // Longest run of ≥ 2 zero groups (first one on ties) becomes `::`.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

/** Canonical text of an IP literal, or null when it is not one. */
export function canonicalIp(ip: string): string | null {
  const parsed = parseIp(ip);
  return parsed ? formatIp(parsed) : null;
}

export type IpClass =
  | 'public'
  | 'private'
  | 'loopback'
  | 'link_local'
  | 'cgnat'
  | 'multicast'
  | 'reserved'
  | 'documentation'
  | 'unspecified';

export interface IpClassification {
  valid: boolean;
  version: IpVersion | null;
  class: IpClass | null;
  /** Public unicast, or a documentation range when `allowDocumentationRanges` (tests only). */
  geolocatable: boolean;
}

interface Range {
  cidr: ParsedCidr;
  class: IpClass;
}

const range = (cidr: string, cls: IpClass): Range => {
  const parsed = parseCidr(cidr);
  if (!parsed) throw new Error(`bad built-in range ${cidr}`);
  return { cidr: parsed, class: cls };
};

let RANGES: Range[] | null = null;
function ranges(): Range[] {
  RANGES ??= [
    range('0.0.0.0/32', 'unspecified'),
    range('0.0.0.0/8', 'reserved'),
    range('10.0.0.0/8', 'private'),
    range('100.64.0.0/10', 'cgnat'),
    range('127.0.0.0/8', 'loopback'),
    range('169.254.0.0/16', 'link_local'),
    range('172.16.0.0/12', 'private'),
    range('192.0.0.0/24', 'reserved'),
    // RFC 5737 documentation ranges.
    range('192.0.2.0/24', 'documentation'),
    range('198.51.100.0/24', 'documentation'),
    range('203.0.113.0/24', 'documentation'),
    range('192.168.0.0/16', 'private'),
    range('198.18.0.0/15', 'reserved'),
    range('224.0.0.0/4', 'multicast'),
    range('240.0.0.0/4', 'reserved'),
    range('::/128', 'unspecified'),
    range('::1/128', 'loopback'),
    range('64:ff9b::/96', 'reserved'),
    range('100::/64', 'reserved'),
    // RFC 3849 documentation range.
    range('2001:db8::/32', 'documentation'),
    range('2001::/23', 'reserved'),
    range('fc00::/7', 'private'),
    range('fe80::/10', 'link_local'),
    range('ff00::/8', 'multicast'),
  ];
  return RANGES;
}

const GLOBAL_UNICAST_V6 = (): ParsedCidr => parseCidr('2000::/3')!;

/** Classifies an IP (D7): only public unicast is geolocatable, documentation ranges on request. */
export function classifyIp(
  ip: string,
  options: { allowDocumentationRanges?: boolean } = {},
): IpClassification {
  const parsed = parseIp(ip);
  if (!parsed) return { valid: false, version: null, class: null, geolocatable: false };
  let cls: IpClass = 'public';
  for (const r of ranges()) {
    if (r.cidr.version === parsed.version && containsParsed(r.cidr, parsed)) {
      cls = r.class;
      break;
    }
  }
  if (cls === 'public' && parsed.version === 6 && !containsParsed(GLOBAL_UNICAST_V6(), parsed)) {
    cls = 'reserved';
  }
  const geolocatable =
    cls === 'public' || (cls === 'documentation' && options.allowDocumentationRanges === true);
  return { valid: true, version: parsed.version, class: cls, geolocatable };
}

function maskBytes(bytes: Buffer, prefix: number): Buffer {
  const out = Buffer.from(bytes);
  for (let i = 0; i < out.length; i++) {
    const bits = Math.max(0, Math.min(8, prefix - i * 8));
    out[i] = out[i]! & ((0xff << (8 - bits)) & 0xff);
  }
  return out;
}

function lastBytes(bytes: Buffer, prefix: number): Buffer {
  const out = Buffer.from(bytes);
  for (let i = 0; i < out.length; i++) {
    const bits = Math.max(0, Math.min(8, prefix - i * 8));
    out[i] = out[i]! | (0xff >> bits);
  }
  return out;
}

/** Network prefix of an IP as CIDR text (IPv4 /24 and IPv6 /48 by default, D9). */
export function ipPrefix(ip: string, v4Bits = 24, v6Bits = 48): string | null {
  const parsed = parseIp(ip);
  if (!parsed) return null;
  const bits = parsed.version === 4 ? v4Bits : v6Bits;
  const network = maskBytes(parsed.bytes, bits);
  return `${formatIp({ version: parsed.version, bytes: network })}/${bits}`;
}

export interface ParsedCidr {
  /** Canonical text (network address / prefix). */
  cidr: string;
  version: IpVersion;
  prefix: number;
  /** First and last address bytes (`range_start`, `range_end`). */
  start: Buffer;
  end: Buffer;
}

/**
 * Parses CIDR text (host bits are cleared: `192.0.2.7/24` → `192.0.2.0/24`). A bare address is a
 * host route. `minPrefix` refuses ranges wider than allowed (settings: IPv4 ≥ /8, IPv6 ≥ /32).
 */
export function parseCidr(
  text: string,
  options: { minV4Prefix?: number; minV6Prefix?: number } = {},
): ParsedCidr | null {
  const slash = text.indexOf('/');
  const addr = slash >= 0 ? text.slice(0, slash) : text;
  const parsed = parseIp(addr);
  if (!parsed) return null;
  const max = parsed.version === 4 ? 32 : 128;
  let prefix = max;
  if (slash >= 0) {
    const p = text.slice(slash + 1);
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null;
    prefix = Number(p);
    // An IPv4-mapped IPv6 CIDR is expressed against the IPv6 width.
    if (parsed.version === 4 && isIP(addr) === 6) prefix -= 96;
  }
  if (prefix < 0 || prefix > max) return null;
  const min = parsed.version === 4 ? (options.minV4Prefix ?? 0) : (options.minV6Prefix ?? 0);
  if (prefix < min) return null;
  const start = maskBytes(parsed.bytes, prefix);
  const end = lastBytes(start, prefix);
  return {
    cidr: `${formatIp({ version: parsed.version, bytes: start })}/${prefix}`,
    version: parsed.version,
    prefix,
    start,
    end,
  };
}

function containsParsed(cidr: ParsedCidr, ip: ParsedIp): boolean {
  if (cidr.version !== ip.version) return false;
  return Buffer.compare(ip.bytes, cidr.start) >= 0 && Buffer.compare(ip.bytes, cidr.end) <= 0;
}

/** Whether `ip` lies in `cidr` (text or parsed). False for malformed input. */
export function cidrContains(cidr: string | ParsedCidr, ip: string): boolean {
  const range = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  const parsed = parseIp(ip);
  if (!range || !parsed) return false;
  return containsParsed(range, parsed);
}

/** Whether `ip` lies in any of `cidrs`. */
export function anyCidrContains(cidrs: readonly (string | ParsedCidr)[], ip: string): boolean {
  return cidrs.some((c) => cidrContains(c, ip));
}
