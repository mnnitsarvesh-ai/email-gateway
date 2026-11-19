import {
  compareEgressRanges,
  egressSetSha256,
  parseEgressCidr,
  type EgressRange,
} from '@email-gateway/database';
import { formatIpAddress, isPublicIpAddress, parseIpAddress } from '@email-gateway/mail-routing';
import { INTEGRATION_PROVIDERS, type IntegrationProvider } from '../types';

/**
 * Operator egress-range imports (D11 CLI rules, ADR-0078). The import file is
 * `{ "provider": "microsoft_365" | "google_workspace", "cidrs": ["…"] }` (an optional
 * `"schema": "provider-egress-import/1"`): the operator converts the provider's published
 * list into it (no automatic Internet fetch, §15 Q8). Ranges are canonicalized and hashed with
 * the seed's helpers (`@email-gateway/database`, D-WP1-2), so identical data hashes identically.
 */
export const EGRESS_IMPORT_SCHEMA = 'provider-egress-import/1';
export const EGRESS_IMPORT_MAX_ENTRIES = 5_000;
export const EGRESS_MIN_PREFIX_V4 = 8;
export const EGRESS_MIN_PREFIX_V6 = 16;
/** A new set may remove at most this fraction of the active ranges without `--force`. */
export const EGRESS_MAX_REMOVED_FRACTION = 0.5;

export class EgressImportError extends Error {
  override readonly name = 'EgressImportError';
  constructor(
    message: string,
    /** Index of the offending entry, when one entry is at fault. */
    readonly index?: number,
  ) {
    super(message);
  }
}

export interface EgressImport {
  provider: IntegrationProvider;
  /** Canonical CIDRs, IPv4 then IPv6, by address. */
  cidrs: string[];
  ranges: EgressRange[];
  /** `provider_egress_range_sets.sha256`. */
  sha256: string;
  /** Exact duplicates removed from the input. */
  duplicatesRemoved: number;
}

/**
 * Special-purpose blocks (RFC 6890 and successors) a provider range may not even partly cover;
 * the end-point check alone would accept e.g. `100.0.0.0/8` around the CGNAT block.
 */
const SPECIAL_PURPOSE = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
  '::/8',
  '64:ff9b::/96',
  '100::/64',
  '2001::/23',
  '2001:db8::/32',
  '2002::/16',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
].map((text) => {
  const [addr, prefix] = text.split('/') as [string, string];
  const parsed = parseIpAddress(addr)!;
  const bits = Number(prefix);
  const start = Buffer.from(parsed.bytes);
  const end = Buffer.from(parsed.bytes);
  for (let bit = bits; bit < start.length * 8; bit++) {
    const mask = 0x80 >> (bit & 7);
    start[bit >> 3] = start[bit >> 3]! & ~mask;
    end[bit >> 3] = end[bit >> 3]! | mask;
  }
  return { version: parsed.version, start, end };
});

function overlapsSpecialPurpose(range: EgressRange): boolean {
  return SPECIAL_PURPOSE.some(
    (block) =>
      block.version === range.ipVersion &&
      Buffer.compare(range.rangeStart, block.end) <= 0 &&
      Buffer.compare(block.start, range.rangeEnd) <= 0,
  );
}

/** Canonical text of one CIDR (lower case, RFC 5952); host bits must be clear. */
export function canonicalizeCidr(text: string, index?: number): EgressRange {
  if (typeof text !== 'string') throw new EgressImportError('entry is not a string', index);
  const trimmed = text.trim().toLowerCase();
  const slash = trimmed.indexOf('/');
  if (slash <= 0) throw new EgressImportError('entry is not a CIDR (address/prefix)', index);
  const address = parseIpAddress(trimmed.slice(0, slash));
  const prefixText = trimmed.slice(slash + 1);
  if (!address || !/^\d{1,3}$/.test(prefixText)) {
    throw new EgressImportError('entry is not a valid IPv4 or IPv6 CIDR', index);
  }
  const prefix = Number(prefixText);
  const max = address.version === 4 ? 32 : 128;
  if (prefix > max) throw new EgressImportError('prefix length out of range', index);
  const min = address.version === 4 ? EGRESS_MIN_PREFIX_V4 : EGRESS_MIN_PREFIX_V6;
  if (prefix < min) {
    throw new EgressImportError(`prefix must be at least /${min} for IPv${address.version}`, index);
  }
  let range: EgressRange;
  try {
    range = parseEgressCidr(`${formatIpAddress(address)}/${prefix}`);
  } catch {
    throw new EgressImportError('host bits must be clear (network address required)', index);
  }
  const first = formatIpAddress({
    version: address.version,
    bytes: Uint8Array.from(range.rangeStart),
  });
  const last = formatIpAddress({
    version: address.version,
    bytes: Uint8Array.from(range.rangeEnd),
  });
  if (!isPublicIpAddress(first) || !isPublicIpAddress(last) || overlapsSpecialPurpose(range)) {
    throw new EgressImportError(
      'range is not globally reachable (private or special-purpose)',
      index,
    );
  }
  return range;
}

/** Validates an import document (D11): syntax, public ranges only, prefix limits, ≤ 5 000 entries. */
export function parseEgressImport(
  json: unknown,
  options: { expectedProvider?: IntegrationProvider } = {},
): EgressImport {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new EgressImportError('import file must be a JSON object { provider, cidrs }');
  }
  const doc = json as Record<string, unknown>;
  const allowed = new Set(['schema', 'provider', 'cidrs']);
  const unknown = Object.keys(doc).filter((k) => !allowed.has(k));
  if (unknown.length > 0)
    throw new EgressImportError(`unknown fields: ${unknown.slice(0, 5).join(', ')}`);
  if (doc.schema !== undefined && doc.schema !== EGRESS_IMPORT_SCHEMA) {
    throw new EgressImportError(`schema must be ${EGRESS_IMPORT_SCHEMA}`);
  }
  const provider = doc.provider;
  if (
    typeof provider !== 'string' ||
    !(INTEGRATION_PROVIDERS as readonly string[]).includes(provider)
  ) {
    throw new EgressImportError('provider must be microsoft_365 or google_workspace');
  }
  if (options.expectedProvider && provider !== options.expectedProvider) {
    throw new EgressImportError(`file is for ${provider}, not ${options.expectedProvider}`);
  }
  if (!Array.isArray(doc.cidrs)) throw new EgressImportError('cidrs must be an array');
  if (doc.cidrs.length === 0) throw new EgressImportError('cidrs must not be empty');
  if (doc.cidrs.length > EGRESS_IMPORT_MAX_ENTRIES) {
    throw new EgressImportError(`at most ${EGRESS_IMPORT_MAX_ENTRIES} entries`);
  }
  const byCidr = new Map<string, EgressRange>();
  doc.cidrs.forEach((entry, index) => {
    const range = canonicalizeCidr(entry as string, index);
    byCidr.set(range.cidr, range);
  });
  const ranges = [...byCidr.values()].sort(compareEgressRanges);
  return {
    provider: provider as IntegrationProvider,
    cidrs: ranges.map((r) => r.cidr),
    ranges,
    sha256: egressSetSha256(ranges),
    duplicatesRemoved: doc.cidrs.length - ranges.length,
  };
}

export interface EgressSetDiff {
  added: string[];
  removed: string[];
  /** Fraction of the active ranges the new set removes (0 when there is no active set). */
  removedFraction: number;
  /** More than 50 % removed: the CLI refuses without `--force` (D11). */
  requiresForce: boolean;
  unchanged: boolean;
}

export function diffEgressSets(active: readonly string[], next: readonly string[]): EgressSetDiff {
  const before = new Set(active);
  const after = new Set(next);
  const added = [...after].filter((c) => !before.has(c));
  const removed = [...before].filter((c) => !after.has(c));
  const removedFraction = before.size === 0 ? 0 : removed.length / before.size;
  return {
    added,
    removed,
    removedFraction,
    requiresForce: removedFraction > EGRESS_MAX_REMOVED_FRACTION,
    unchanged: added.length === 0 && removed.length === 0,
  };
}
