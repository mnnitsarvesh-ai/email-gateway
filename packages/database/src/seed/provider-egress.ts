import { createHash } from 'node:crypto';
import type { IntegrationProvider, Prisma } from '@prisma/client';

/**
 * Provider egress range snapshot (step 8.2 §3.2, D7, ADR-0078): the address ranges Microsoft 365
 * (Exchange Online Protection) and Google Workspace (Gmail) send outbound mail from, as known to
 * the architect at design time. The smtp-adapter accepts provider-relay sessions only from the
 * provider's `active` set.
 *
 * The snapshot is a CONVENIENCE for local, CI and first deployments, NOT authoritative data:
 * operators import the providers' current lists with the import CLI before enabling outbound
 * relay (the staleness alert `ProviderEgressRangesStale` fires otherwise). `pnpm db:seed` inserts
 * it only for a provider that has no set at all, so it never overwrites an operator import.
 */

export interface EgressSnapshotDef {
  provider: IntegrationProvider;
  version: number;
  /** The provider's publication (documentation) URL of the data; stored, never fetched. */
  source: string;
  /** Publication date of the data the snapshot was copied from. */
  publishedAt: Date;
  importedBy: string;
  cidrs: readonly string[];
}

const SNAPSHOT_PUBLISHED_AT = new Date('2026-06-01T00:00:00.000Z');

/** Copied verbatim from the design note §3.2. */
export const PROVIDER_EGRESS_SNAPSHOT: readonly EgressSnapshotDef[] = Object.freeze([
  {
    provider: 'microsoft_365',
    version: 1,
    source:
      'https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges ' +
      '(Exchange Online, Exchange Online Protection outbound)',
    publishedAt: SNAPSHOT_PUBLISHED_AT,
    importedBy: 'seed',
    cidrs: Object.freeze([
      '40.92.0.0/15',
      '40.107.0.0/16',
      '52.100.0.0/15',
      '52.102.0.0/16',
      '52.103.0.0/17',
      '104.47.0.0/17',
      '2a01:111:f400::/48',
      '2a01:111:f403::/48',
    ]),
  },
  {
    provider: 'google_workspace',
    version: 1,
    source:
      'https://support.google.com/a/answer/10026322 (Google mail netblocks, ' +
      '_netblocks*.google.com SPF records)',
    publishedAt: SNAPSHOT_PUBLISHED_AT,
    importedBy: 'seed',
    cidrs: Object.freeze([
      '35.190.247.0/24',
      '64.233.160.0/19',
      '66.102.0.0/20',
      '66.249.80.0/20',
      '72.14.192.0/18',
      '74.125.0.0/16',
      '108.177.8.0/21',
      '173.194.0.0/16',
      '209.85.128.0/17',
      '216.58.192.0/19',
      '216.239.32.0/19',
      '172.217.0.0/19',
      '172.217.32.0/20',
      '172.217.128.0/19',
      '172.217.160.0/20',
      '172.217.192.0/19',
      '172.253.56.0/21',
      '172.253.112.0/20',
      '108.177.96.0/19',
      '35.191.0.0/16',
      '130.211.0.0/22',
      '2001:4860:4000::/36',
      '2404:6800:4000::/36',
      '2607:f8b0:4000::/36',
      '2800:3f0:4000::/36',
      '2a00:1450:4000::/36',
      '2c0f:fb50:4000::/36',
    ]),
  },
] as const satisfies readonly EgressSnapshotDef[]);

/** One egress CIDR in the `provider_egress_ranges` encoding (as `smtp_connector_networks`). */
export interface EgressRange {
  /** Canonical text: network address + `/prefix`, RFC 5952 for IPv6. */
  cidr: string;
  ipVersion: 4 | 6;
  prefix: number;
  /** First address, 4 or 16 bytes big-endian. */
  rangeStart: Buffer;
  /** Last address, same length as `rangeStart`. */
  rangeEnd: Buffer;
}

const DECIMAL_OCTET = /^(0|[1-9][0-9]{0,2})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/;
const PREFIX = /^(0|[1-9][0-9]{0,2})$/;

function parseIpv4(text: string): Buffer | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const out = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i]!;
    if (!DECIMAL_OCTET.test(part) || Number(part) > 255) return null;
    out[i] = Number(part);
  }
  return out;
}

/** Hexadecimal IPv6 text with at most one `::` (no embedded IPv4, no zone id); lower case. */
function parseIpv6(text: string): Buffer | null {
  if (text.length === 0 || text.length > 39) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const groups = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    for (const item of part.split(':')) {
      if (!HEX_GROUP.test(item)) return null;
      out.push(parseInt(item, 16));
    }
    return out;
  };
  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  if (!head || !tail) return null;
  let all: number[];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    all = head;
  } else {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    all = [...head, ...new Array<number>(missing).fill(0), ...tail];
  }
  const out = Buffer.alloc(16);
  all.forEach((group, i) => out.writeUInt16BE(group, i * 2));
  return out;
}

/** RFC 5952 text of a 16-byte IPv6 address (lower case, longest zero run of ≥ 2 as `::`). */
function formatIpv6(bytes: Buffer): string {
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

function maskFrom(address: Buffer, prefix: number, fill: 0 | 1): Buffer {
  const out = Buffer.from(address);
  for (let bit = prefix; bit < out.length * 8; bit++) {
    const byte = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    out[byte] = fill ? out[byte]! | mask : out[byte]! & ~mask;
  }
  return out;
}

/**
 * Parses one egress CIDR (`address/prefix`, prefix required) strictly: the text must already be
 * canonical (lower case, host bits clear, RFC 5952 for IPv6), so the stored text, the unique key
 * `(set_id, cidr)` and the set's SHA-256 are unambiguous. Throws on anything else.
 */
export function parseEgressCidr(text: string): EgressRange {
  const slash = text.indexOf('/');
  if (slash === -1) throw new Error('egress CIDR must have a prefix length');
  const addressText = text.slice(0, slash);
  const prefixText = text.slice(slash + 1);
  const v4 = parseIpv4(addressText);
  const address = v4 ?? parseIpv6(addressText);
  if (!address) throw new Error('egress CIDR must be an IPv4 or IPv6 network');
  const ipVersion: 4 | 6 = v4 ? 4 : 6;
  const max = ipVersion === 4 ? 32 : 128;
  if (!PREFIX.test(prefixText) || Number(prefixText) > max) {
    throw new Error(`egress CIDR prefix must be between 0 and ${max}`);
  }
  const prefix = Number(prefixText);
  // A /0 would make every client a provider client.
  if (prefix < 8) throw new Error('egress CIDR prefix must be at least /8');
  const rangeStart = maskFrom(address, prefix, 0);
  const rangeEnd = maskFrom(address, prefix, 1);
  const cidr = `${ipVersion === 4 ? Array.from(rangeStart).join('.') : formatIpv6(rangeStart)}/${prefix}`;
  if (cidr !== text) throw new Error('egress CIDR must be canonical (host bits clear, RFC 5952)');
  return { cidr, ipVersion, prefix, rangeStart, rangeEnd };
}

/** Sort order of a set's ranges: IPv4 before IPv6, then by first address, then by prefix. */
export function compareEgressRanges(a: EgressRange, b: EgressRange): number {
  return (
    a.ipVersion - b.ipVersion || Buffer.compare(a.rangeStart, b.rangeStart) || a.prefix - b.prefix
  );
}

/**
 * `provider_egress_range_sets.sha256`: lower-case hex SHA-256 of the canonical CIDRs in
 * `compareEgressRanges` order, joined by `\n` (no trailing newline). The import CLI computes the
 * same value, so re-importing identical data is recognisable.
 */
export function egressSetSha256(ranges: readonly EgressRange[]): string {
  const text = [...ranges]
    .sort(compareEgressRanges)
    .map((r) => r.cidr)
    .join('\n');
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export interface ProviderEgressSeedSummary {
  /** Providers whose snapshot set was inserted by this run (empty once seeded or imported). */
  created: IntegrationProvider[];
}

/**
 * Inserts the snapshot set (status `active`) of every provider that has NO egress range set yet,
 * in the caller's transaction. Idempotent: a provider with any set (seeded or imported by an
 * operator, active or superseded) is left untouched; a concurrent run fails on the unique key
 * `(provider, version)` instead of inserting twice.
 */
export async function seedProviderEgress(
  tx: Prisma.TransactionClient,
  snapshot: readonly EgressSnapshotDef[] = PROVIDER_EGRESS_SNAPSHOT,
): Promise<ProviderEgressSeedSummary> {
  const created: IntegrationProvider[] = [];
  for (const def of snapshot) {
    const existing = await tx.providerEgressRangeSet.findFirst({
      where: { provider: def.provider },
      select: { id: true },
    });
    if (existing) continue;
    const ranges = def.cidrs.map(parseEgressCidr).sort(compareEgressRanges);
    if (new Set(ranges.map((r) => r.cidr)).size !== ranges.length) {
      throw new Error(`egress snapshot of ${def.provider} has duplicate CIDRs`);
    }
    await tx.providerEgressRangeSet.create({
      data: {
        provider: def.provider,
        version: def.version,
        status: 'active',
        source: def.source,
        publishedAt: def.publishedAt,
        sha256: egressSetSha256(ranges),
        rangeCount: ranges.length,
        importedBy: def.importedBy,
        ranges: {
          createMany: {
            data: ranges.map((r) => ({
              provider: def.provider,
              cidr: r.cidr,
              ipVersion: r.ipVersion,
              rangeStart: Uint8Array.from(r.rangeStart),
              rangeEnd: Uint8Array.from(r.rangeEnd),
            })),
          },
        },
      },
    });
    created.push(def.provider);
  }
  return { created };
}
