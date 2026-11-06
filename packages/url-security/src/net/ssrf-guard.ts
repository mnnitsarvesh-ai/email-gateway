import { BlockList, isIPv4, isIPv6 } from 'node:net';
import { bytesToIpv6, canonicalIp, ipv6ToBytes, numberToIpv4 } from '../normalize/ip';
import { hostMatchesDomain } from '../normalize/url';

/**
 * The SSRF guard (docs/plan/steps/11-url-protection.md U8). Used by every outbound request of
 * step 4.3 (scan-time fetch, click-time recheck, RDAP, the egress proxy): scheme, port and name
 * checks before DNS, then every resolved or literal address is canonicalized (IPv4-mapped and
 * IPv4-compatible → the IPv4; NAT64 64:ff9b::/96 and 6to4 2002::/16 → the embedded IPv4, which must
 * also pass) and checked against every non-globally-reachable range of the IANA IPv4/IPv6
 * special-purpose registries, plus the platform deny list.
 */

export const BLOCKED_REASONS = [
  'loopback',
  'private',
  'link_local',
  'cgnat',
  'multicast',
  'reserved',
  'documentation',
  'metadata',
  'ula',
  'unspecified',
  'mapped',
  'name',
  'scheme',
  'port',
  'deny_list',
] as const;
export type BlockedReason = (typeof BLOCKED_REASONS)[number];

/** Reasons that are about the target's address or name (U10 S5), not port/scheme. */
export const INTERNAL_BLOCK_REASONS: ReadonlySet<BlockedReason> = new Set([
  'loopback',
  'private',
  'link_local',
  'cgnat',
  'multicast',
  'reserved',
  'documentation',
  'metadata',
  'ula',
  'unspecified',
  'mapped',
  'name',
  'deny_list',
]);

export type GuardDecision = { allowed: true } | { allowed: false; reason: BlockedReason };
const ALLOW: GuardDecision = { allowed: true };
const block = (reason: BlockedReason): GuardDecision => ({ allowed: false, reason });

type Range = readonly [string, number, BlockedReason];

/** Most specific first: metadata hosts inside link-local / ULA are reported as `metadata`. */
const IPV4_RANGES: readonly Range[] = [
  ['169.254.169.254', 32, 'metadata'],
  ['169.254.170.2', 32, 'metadata'],
  ['0.0.0.0', 8, 'unspecified'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'cgnat'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link_local'],
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'reserved'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.88.99.0', 24, 'reserved'],
  ['192.168.0.0', 16, 'private'],
  ['198.18.0.0', 15, 'reserved'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
  ['255.255.255.255', 32, 'reserved'],
];

const IPV6_RANGES: readonly Range[] = [
  ['fd00:ec2::254', 128, 'metadata'],
  ['::', 128, 'unspecified'],
  ['::1', 128, 'loopback'],
  ['64:ff9b:1::', 48, 'reserved'],
  ['100::', 64, 'reserved'],
  ['2001:db8::', 32, 'documentation'],
  ['2001::', 23, 'reserved'],
  ['3fff::', 20, 'documentation'],
  ['5f00::', 16, 'reserved'],
  ['fc00::', 7, 'ula'],
  ['fe80::', 10, 'link_local'],
  ['fec0::', 10, 'reserved'],
  ['ff00::', 8, 'multicast'],
];

/** The documentation ranges: the only CIDRs URL_FETCH_TEST_ALLOW_CIDRS may contain. */
export const DOCUMENTATION_CIDRS = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'] as const;

/** Names refused before DNS (exact names; suffixes match the name and every subdomain). */
const BLOCKED_NAMES = new Set([
  'localhost',
  'metadata',
  'instance-data',
  'metadata.azure.internal',
]);
const BLOCKED_SUFFIXES = ['localhost', 'local', 'internal', 'home.arpa', 'localdomain'];

export interface Cidr {
  address: string;
  prefix: number;
  family: 'ipv4' | 'ipv6';
}

export function parseCidr(text: string): Cidr {
  const [address = '', prefixText, extra] = text.trim().split('/');
  if (extra !== undefined) throw new Error(`invalid CIDR ${text}`);
  const ip = canonicalIp(address);
  if (ip === null) throw new Error(`invalid CIDR ${text}`);
  const family = isIPv4(ip) ? 'ipv4' : 'ipv6';
  const max = family === 'ipv4' ? 32 : 128;
  const prefix = prefixText === undefined ? max : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max || !/^\d*$/.test(prefixText ?? '')) {
    throw new Error(`invalid CIDR ${text}`);
  }
  return { address: ip, prefix, family };
}

function cidrInside(inner: Cidr, outer: Cidr): boolean {
  if (inner.family !== outer.family || inner.prefix < outer.prefix) return false;
  const list = new BlockList();
  list.addSubnet(outer.address, outer.prefix, outer.family);
  return list.check(inner.address, inner.family);
}

/**
 * Where TEST-ONLY seams (URL_FETCH_TEST_ALLOW_CIDRS, URL_FETCH_TEST_DIAL_MAP) may be used. The
 * local Compose containers run NODE_ENV=production with APP_ENV=local, so the rule follows the
 * repository precedent (plaintext SMTP, packages/config): allowed when APP_ENV is `local` or
 * `ci`; refused for APP_ENV `staging`/`production`, and for NODE_ENV=production without an
 * APP_ENV. A plain string is NODE_ENV alone.
 */
export type TestSeamEnv =
  string | undefined | { nodeEnv?: string | undefined; appEnv?: string | undefined };

export function testSeamsAllowed(env: TestSeamEnv): boolean {
  const { nodeEnv, appEnv } = typeof env === 'object' ? env : { nodeEnv: env, appEnv: undefined };
  if (appEnv !== undefined && appEnv !== '') return appEnv === 'local' || appEnv === 'ci';
  return nodeEnv !== 'production';
}

export interface SsrfGuardOptions {
  /** URL_FETCH_ALLOWED_PORTS (default 80, 443). */
  allowedPorts?: readonly number[];
  /** URL_FETCH_DENY_CIDRS (production: the platform's own public ranges). */
  denyCidrs?: readonly string[];
  /** URL_FETCH_DENY_HOSTS (names and their subdomains). */
  denyHosts?: readonly string[];
  /** TEST-ONLY URL_FETCH_TEST_ALLOW_CIDRS: inside the documentation ranges only. */
  testAllowCidrs?: readonly string[];
  /** The click-service host (URL_CLICK_BASE_URL): loop prevention. */
  clickHost?: string | null;
  /** NODE_ENV (and APP_ENV) deciding whether test seams are allowed (`testSeamsAllowed`). */
  nodeEnv?: string;
  appEnv?: string;
}

/** Validates URL_FETCH_TEST_ALLOW_CIDRS (§8 risk "test seams leaking into production"). */
export function validateTestAllowCidrs(cidrs: readonly string[], env: TestSeamEnv): Cidr[] {
  if (cidrs.length === 0) return [];
  if (!testSeamsAllowed(env)) {
    throw new Error(
      'URL_FETCH_TEST_ALLOW_CIDRS is a test seam and is refused in production (NODE_ENV=production outside APP_ENV local/ci)',
    );
  }
  const documentation = DOCUMENTATION_CIDRS.map(parseCidr);
  return cidrs.map((text) => {
    const cidr = parseCidr(text);
    if (!documentation.some((doc) => cidrInside(cidr, doc))) {
      throw new Error(
        `URL_FETCH_TEST_ALLOW_CIDRS may only contain documentation ranges, not ${text}`,
      );
    }
    return cidr;
  });
}

/** The address a canonical check applies to, with the IPv4 it embeds (if any). */
export interface CanonicalAddress {
  /** Canonical text of the address as given (IPv4-mapped/compatible already reduced to IPv4). */
  address: string;
  family: 'ipv4' | 'ipv6';
  /** Embedded IPv4 of a NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address. */
  embeddedIpv4: string | null;
}

export function canonicalizeAddress(value: string): CanonicalAddress | null {
  const text = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
  if (isIPv4(text))
    return { address: canonicalIp(text) as string, family: 'ipv4', embeddedIpv4: null };
  if (!isIPv6(text)) return null;
  const bytes = ipv6ToBytes(text);
  if (!bytes) return null;
  const at = (i: number): number => bytes[i] ?? 0;
  const v4At = (offset: number): string =>
    numberToIpv4(
      ((at(offset) << 24) | (at(offset + 1) << 16) | (at(offset + 2) << 8) | at(offset + 3)) >>> 0,
    );
  const zeros = (from: number, to: number): boolean => {
    for (let i = from; i < to; i += 1) if (at(i) !== 0) return false;
    return true;
  };
  // ::ffff:a.b.c.d (IPv4-mapped) → the IPv4 itself.
  if (zeros(0, 10) && at(10) === 0xff && at(11) === 0xff) {
    return { address: v4At(12), family: 'ipv4', embeddedIpv4: null };
  }
  // ::a.b.c.d (IPv4-compatible, deprecated) → the IPv4 itself; :: and ::1 stay IPv6.
  if (zeros(0, 12) && !(zeros(12, 15) && at(15) <= 1)) {
    return { address: v4At(12), family: 'ipv4', embeddedIpv4: null };
  }
  const canonical = bytesToIpv6(bytes);
  // NAT64 well-known prefix 64:ff9b::/96.
  if (at(0) === 0x00 && at(1) === 0x64 && at(2) === 0xff && at(3) === 0x9b && zeros(4, 12)) {
    return { address: canonical, family: 'ipv6', embeddedIpv4: v4At(12) };
  }
  // 6to4 2002:V4ADDR::/48.
  if (at(0) === 0x20 && at(1) === 0x02) {
    return { address: canonical, family: 'ipv6', embeddedIpv4: v4At(2) };
  }
  return { address: canonical, family: 'ipv6', embeddedIpv4: null };
}

/** True when the host is an IP literal (with or without brackets). */
export const isIpLiteral = (host: string): boolean => canonicalIp(host) !== null;

export class SsrfGuard {
  private readonly allowedPorts: ReadonlySet<number>;
  private readonly rangeLists: ReadonlyArray<{ list: BlockList; reason: BlockedReason }>;
  private readonly denyList: BlockList;
  private readonly testAllow: BlockList;
  private readonly hasTestAllow: boolean;
  private readonly denyHosts: readonly string[];
  private readonly clickHost: string | null;

  constructor(options: SsrfGuardOptions = {}) {
    this.allowedPorts = new Set(options.allowedPorts ?? [80, 443]);
    for (const port of this.allowedPorts) {
      if (!Number.isInteger(port) || port < 1 || port > 65535)
        throw new Error(`invalid port ${port}`);
    }
    this.rangeLists = [
      ...IPV4_RANGES.map((r) => [r, 'ipv4'] as const),
      ...IPV6_RANGES.map((r) => [r, 'ipv6'] as const),
    ].map(([[address, prefix, reason], family]) => {
      const list = new BlockList();
      list.addSubnet(address, prefix, family);
      return { list, reason };
    });
    this.denyList = new BlockList();
    for (const text of options.denyCidrs ?? []) {
      const cidr = parseCidr(text);
      this.denyList.addSubnet(cidr.address, cidr.prefix, cidr.family);
    }
    this.testAllow = new BlockList();
    const allow = validateTestAllowCidrs(options.testAllowCidrs ?? [], {
      nodeEnv: options.nodeEnv,
      appEnv: options.appEnv,
    });
    for (const cidr of allow) this.testAllow.addSubnet(cidr.address, cidr.prefix, cidr.family);
    this.hasTestAllow = allow.length > 0;
    this.denyHosts = (options.denyHosts ?? [])
      .map((h) => h.trim().toLowerCase().replace(/\.+$/, ''))
      .filter(Boolean);
    this.clickHost = options.clickHost ? options.clickHost.toLowerCase().replace(/\.+$/, '') : null;
  }

  checkScheme(scheme: string): GuardDecision {
    const s = scheme.toLowerCase().replace(/:$/, '');
    return s === 'http' || s === 'https' ? ALLOW : block('scheme');
  }

  checkPort(port: number): GuardDecision {
    return this.allowedPorts.has(port) ? ALLOW : block('port');
  }

  /** Name checks before DNS (an IP literal is checked as an address). */
  checkHostName(host: string): GuardDecision {
    const name = host.toLowerCase().replace(/\.+$/, '');
    if (isIpLiteral(name)) return this.checkAddress(name);
    if (!name) return block('name');
    if (this.clickHost !== null && name === this.clickHost) return block('name');
    if (this.denyHosts.some((deny) => hostMatchesDomain(name, deny))) return block('deny_list');
    if (BLOCKED_NAMES.has(name)) return block('name');
    if (BLOCKED_SUFFIXES.some((suffix) => hostMatchesDomain(name, suffix))) return block('name');
    if (!name.includes('.')) return block('name');
    return ALLOW;
  }

  /** Scheme, port and name of a URL (everything that is decided before DNS). */
  checkUrl(input: URL | string): GuardDecision {
    let url: URL;
    try {
      url = typeof input === 'string' ? new URL(input) : input;
    } catch {
      return block('scheme');
    }
    const scheme = this.checkScheme(url.protocol);
    if (!scheme.allowed) return scheme;
    const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
    const portDecision = this.checkPort(port);
    if (!portDecision.allowed) return portDecision;
    return this.checkHostName(url.hostname);
  }

  /** An address (resolved or literal), after canonicalization. */
  checkAddress(value: string): GuardDecision {
    const canonical = canonicalizeAddress(value);
    if (!canonical) return block('reserved');
    if (canonical.embeddedIpv4 !== null) {
      const inner = this.checkAddressCanonical(canonical.embeddedIpv4, 'ipv4');
      if (!inner.allowed) return block('mapped');
    }
    return this.checkAddressCanonical(canonical.address, canonical.family);
  }

  private checkAddressCanonical(address: string, family: 'ipv4' | 'ipv6'): GuardDecision {
    if (this.denyList.check(address, family)) return block('deny_list');
    for (const { list, reason } of this.rangeLists) {
      if (!list.check(address, family)) continue;
      if (
        reason === 'documentation' &&
        this.hasTestAllow &&
        this.testAllow.check(address, family)
      ) {
        return ALLOW;
      }
      return block(reason);
    }
    // IPv6 outside global unicast 2000::/3 (after the NAT64/6to4 handling above) is reserved.
    if (family === 'ipv6') {
      const first = (ipv6ToBytes(address) ?? new Uint8Array(1))[0] ?? 0;
      const nat64 = address.startsWith('64:ff9b::');
      if (!nat64 && (first & 0xe0) !== 0x20) return block('reserved');
    }
    return ALLOW;
  }
}
