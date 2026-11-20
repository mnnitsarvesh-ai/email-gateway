/**
 * Network rules of journal intake sources (step 8.6 D1, `intake-networks/1`): the on-premises
 * kinds (`exchange_onprem_journal`, `smtp_bcc`) name 1–32 CIDRs their mail comes from. They are
 * refused when too broad (a prefix shorter than /16 for IPv4 or /32 for IPv6), when they overlap
 * any provider egress range (8.2 D10: shared provider infrastructure is never a tenant
 * credential), and, unless `allowPrivate` (local and CI only), when they are private, loopback,
 * link-local or otherwise non-public. Pure: no DNS, no I/O.
 */

export type IpFamily = 4 | 6;

/** A parsed CIDR: the network address as an integer, the prefix length and the family. */
export interface ParsedCidr {
  family: IpFamily;
  /** The network address (host bits are zero for a valid network). */
  network: bigint;
  prefix: number;
  /** Canonical text: `a.b.c.d/p` or a compressed lower-case IPv6 `x::y/p`. */
  text: string;
}

export const INTAKE_NETWORKS_MIN = 1;
export const INTAKE_NETWORKS_MAX = 32;
/** The broadest allowed prefixes (D1). */
export const INTAKE_NETWORK_MIN_PREFIX: Readonly<Record<IpFamily, number>> = Object.freeze({
  4: 16,
  6: 32,
});

const bitsOf = (family: IpFamily) => (family === 4 ? 32 : 128);

function parseIpv4(text: string): bigint | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

function parseIpv6(text: string): bigint | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return null;
  let head = text;
  let tailV4: bigint | null = null;
  // An embedded dotted quad in the last 32 bits (`::ffff:192.0.2.1`).
  const lastColon = text.lastIndexOf(':');
  if (text.includes('.')) {
    tailV4 = parseIpv4(text.slice(lastColon + 1));
    if (tailV4 === null) return null;
    head = `${text.slice(0, lastColon + 1)}0:0`;
  }
  const doubles = head.split('::');
  if (doubles.length > 2) return null;
  const group = (g: string) => /^[0-9a-fA-F]{1,4}$/.test(g);
  const left = doubles[0] === '' ? [] : doubles[0]!.split(':');
  const right = doubles.length === 2 ? (doubles[1] === '' ? [] : doubles[1]!.split(':')) : [];
  if (![...left, ...right].every(group)) return null;
  let groups: string[];
  if (doubles.length === 2) {
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...Array<string>(missing).fill('0'), ...right];
  } else {
    groups = left;
  }
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const g of groups) value = (value << 16n) | BigInt(parseInt(g, 16));
  if (tailV4 !== null) value = (value & ~0xffff_ffffn) | tailV4;
  return value;
}

function formatIpv4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((s) => String((value >> s) & 0xffn)).join('.');
}

function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  // RFC 5952: compress the longest run (≥ 2) of zero groups, the first one on a tie.
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

/** Parses `address[/prefix]` (a bare address is a host route); null when invalid. */
export function parseCidr(value: string): (ParsedCidr & { hostBitsSet: boolean }) | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) return null;
  const trimmed = value.trim();
  const slash = trimmed.indexOf('/');
  const addressText = slash < 0 ? trimmed : trimmed.slice(0, slash);
  const prefixText = slash < 0 ? null : trimmed.slice(slash + 1);
  let family: IpFamily;
  let address: bigint | null;
  if (addressText.includes(':')) {
    family = 6;
    address = parseIpv6(addressText);
  } else {
    family = 4;
    address = parseIpv4(addressText);
  }
  if (address === null) return null;
  const bits = bitsOf(family);
  let prefix = bits;
  if (prefixText !== null) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(prefixText)) return null;
    prefix = Number(prefixText);
    if (prefix > bits) return null;
  }
  const mask = prefixMask(family, prefix);
  const network = address & mask;
  return {
    family,
    network,
    prefix,
    hostBitsSet: network !== address,
    text: `${family === 4 ? formatIpv4(network) : formatIpv6(network)}/${prefix}`,
  };
}

function prefixMask(family: IpFamily, prefix: number): bigint {
  const bits = BigInt(bitsOf(family));
  const all = (1n << bits) - 1n;
  return prefix === 0 ? 0n : (all << (bits - BigInt(prefix))) & all;
}

/** Whether two networks of the same family share at least one address. */
export function cidrsOverlap(a: ParsedCidr, b: ParsedCidr): boolean {
  if (a.family !== b.family) return false;
  const prefix = Math.min(a.prefix, b.prefix);
  const mask = prefixMask(a.family, prefix);
  return (a.network & mask) === (b.network & mask);
}

/** Whether `inner` lies entirely inside `outer`. */
export function cidrContains(outer: ParsedCidr, inner: ParsedCidr): boolean {
  return (
    outer.family === inner.family &&
    outer.prefix <= inner.prefix &&
    (inner.network & prefixMask(outer.family, outer.prefix)) === outer.network
  );
}

const cidr = (text: string): ParsedCidr => {
  const parsed = parseCidr(text);
  if (parsed === null) throw new Error(`invalid built-in range ${text}`);
  return parsed;
};

/**
 * Non-public ranges refused without `allowPrivate`: RFC 1918, shared address space, loopback,
 * link-local, "this network", multicast and reserved IPv4; unique-local, link-local, loopback,
 * unspecified, IPv4-mapped/translated and multicast IPv6.
 */
export const NON_PUBLIC_RANGES: readonly ParsedCidr[] = Object.freeze(
  [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '::/128',
    '::1/128',
    '::ffff:0:0/96',
    '64:ff9b::/96',
    'fc00::/7',
    'fe80::/10',
    'ff00::/8',
  ].map(cidr),
);

export type IntakeNetworkIssueCode =
  | 'count'
  | 'invalid'
  | 'host_bits_set'
  | 'too_broad'
  | 'private_not_allowed'
  | 'provider_overlap'
  | 'duplicate';

export interface IntakeNetworkIssue {
  code: IntakeNetworkIssueCode;
  /** Index of the offending entry; null for `count`. */
  index: number | null;
}

export interface ValidateIntakeNetworksOptions {
  /** Private ranges are allowed (local and CI only). */
  allowPrivate: boolean;
  /** Every active provider egress range (8.2 `provider_egress_ranges`), as CIDR text. */
  providerRanges: readonly string[];
}

export type IntakeNetworksValidation =
  { ok: true; cidrs: string[] } | { ok: false; issues: IntakeNetworkIssue[] };

/**
 * Validates and canonicalizes the networks of an on-premises intake source (D1). Issues name the
 * entry index and a code, never echo the value. `providerRanges` must all be valid (they come
 * from the egress index); an invalid one throws `RangeError`, because skipping it would weaken
 * the overlap rule.
 */
export function validateIntakeNetworks(
  cidrs: readonly string[],
  options: ValidateIntakeNetworksOptions,
): IntakeNetworksValidation {
  const providers = options.providerRanges.map((r) => {
    const parsed = parseCidr(r);
    if (parsed === null) throw new RangeError('providerRanges contains an invalid range');
    return parsed;
  });
  const issues: IntakeNetworkIssue[] = [];
  if (cidrs.length < INTAKE_NETWORKS_MIN || cidrs.length > INTAKE_NETWORKS_MAX) {
    issues.push({ code: 'count', index: null });
  }
  const seen = new Set<string>();
  const out: string[] = [];
  cidrs.forEach((value, index) => {
    const parsed = parseCidr(value);
    if (parsed === null) {
      issues.push({ code: 'invalid', index });
      return;
    }
    if (parsed.hostBitsSet) {
      issues.push({ code: 'host_bits_set', index });
      return;
    }
    if (parsed.prefix < INTAKE_NETWORK_MIN_PREFIX[parsed.family]) {
      issues.push({ code: 'too_broad', index });
      return;
    }
    if (!options.allowPrivate && NON_PUBLIC_RANGES.some((r) => cidrsOverlap(r, parsed))) {
      issues.push({ code: 'private_not_allowed', index });
      return;
    }
    if (providers.some((p) => cidrsOverlap(p, parsed))) {
      issues.push({ code: 'provider_overlap', index });
      return;
    }
    if (seen.has(parsed.text)) {
      issues.push({ code: 'duplicate', index });
      return;
    }
    seen.add(parsed.text);
    out.push(parsed.text);
  });
  return issues.length > 0 ? { ok: false, issues } : { ok: true, cidrs: out };
}

/** Whether an address (IPv4, IPv6 or IPv4-mapped IPv6) is inside one of the CIDRs. */
export function addressInCidrs(address: string, cidrs: readonly string[]): boolean {
  let host = parseCidr(address.replace(/^\[|\]$/g, ''));
  if (host === null) return false;
  // `::ffff:a.b.c.d` as Postfix may report it.
  if (host.family === 6 && host.prefix === 128 && host.network >> 32n === 0xffffn) {
    host = { ...host, family: 4, network: host.network & 0xffff_ffffn, prefix: 32 };
  }
  return cidrs.some((c) => {
    const parsed = parseCidr(c);
    return parsed !== null && cidrContains(parsed, host);
  });
}
