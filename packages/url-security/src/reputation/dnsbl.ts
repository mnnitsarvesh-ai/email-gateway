import { createHash } from 'node:crypto';
import { isIPv4 } from 'node:net';
import { canonicalIp, reverseIpLabel } from '../normalize/ip';
import { registrableDomainOf } from '../normalize/url';
import { mapLimit } from '../net/limiter';
import { DnsLookupError, type RestrictedResolver } from '../net/resolver';
import {
  clearAnswer,
  combineAnswers,
  errorAnswer,
  THREAT_CATEGORIES,
  type ProviderAnswer,
  type ReputationItem,
  type ReputationProvider,
  type ThreatCategory,
} from './types';

/**
 * Generic DNS blocklist provider (U6) over the restricted resolver. Domain zones are queried with
 * `<registrable domain>.<zone>` and `<host>.<zone>`, IP zones with reversed octets / nibbles.
 * Zone syntax `zone=code:category[,code:category…]`, zones separated by `;`. Answers in the error
 * code list and answers outside 127.0.0.0/8 are `error` (never listed or clear); NXDOMAIN is
 * `clear`; SERVFAIL/timeout `error`. An answer inside 127/8 that is not configured is listed with
 * category `other`. Covers Spamhaus DBL/ZEN (DQS: the key is part of the zone name), SURBL and
 * URIBL by configuration.
 */

export interface DnsblZone {
  zone: string;
  codes: ReadonlyMap<string, ThreatCategory>;
}

export const DEFAULT_DNSBL_ERROR_CODES = [
  '127.255.255.252',
  '127.255.255.254',
  '127.255.255.255',
  '127.0.1.255',
] as const;

const ZONE_NAME =
  /^(?=.{1,200}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/i;

/** Parses URL_DNSBL_DOMAIN_ZONES / URL_DNSBL_IP_ZONES. Throws on any malformed part. */
export function parseDnsblZones(text: string | null | undefined): DnsblZone[] {
  const zones: DnsblZone[] = [];
  for (const raw of (text ?? '').split(';')) {
    const part = raw.trim();
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq <= 0) throw new Error(`invalid DNSBL zone "${part}": expected zone=code:category[,…]`);
    const zone = part.slice(0, eq).trim().toLowerCase().replace(/\.+$/, '');
    if (!ZONE_NAME.test(zone)) throw new Error(`invalid DNSBL zone name "${zone}"`);
    if (zones.some((z) => z.zone === zone)) throw new Error(`duplicate DNSBL zone "${zone}"`);
    const codes = new Map<string, ThreatCategory>();
    for (const entry of part.slice(eq + 1).split(',')) {
      const [code = '', category = '', extra] = entry.trim().split(':');
      if (extra !== undefined || !isIPv4(code.trim()) || !code.trim().startsWith('127.')) {
        throw new Error(`invalid DNSBL return code "${entry.trim()}" in zone ${zone}`);
      }
      const cat = category.trim().toLowerCase();
      if (!(THREAT_CATEGORIES as readonly string[]).includes(cat)) {
        throw new Error(`invalid DNSBL category "${cat}" in zone ${zone}`);
      }
      codes.set(code.trim(), cat as ThreatCategory);
    }
    if (codes.size === 0) throw new Error(`DNSBL zone ${zone} has no return codes`);
    zones.push({ zone, codes });
  }
  return zones;
}

export function parseErrorCodes(text: string | null | undefined): string[] {
  const codes = (text ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const code of codes) if (!isIPv4(code)) throw new Error(`invalid DNSBL error code ${code}`);
  return codes;
}

export interface DnsblOptions {
  domainZones: readonly DnsblZone[];
  ipZones: readonly DnsblZone[];
  errorCodes?: readonly string[];
  /** Parallel DNS queries of one lookup (URL_PROVIDER_CONCURRENCY). */
  concurrency?: number;
}

const zoneConfig = (zones: readonly DnsblZone[]): string =>
  zones
    .map(
      (z) =>
        `${z.zone}=${[...z.codes]
          .map(([c, cat]) => `${c}:${cat}`)
          .sort()
          .join(',')}`,
    )
    .sort()
    .join(';');

const severityOf = (category: ThreatCategory): 'high' | 'medium' =>
  category === 'phishing' || category === 'malware' || category === 'c2' ? 'high' : 'medium';

export class DnsblProvider implements ReputationProvider {
  readonly id = 'dnsbl';
  readonly version: string;
  readonly kinds = ['domain', 'ip'] as const;
  readonly cacheable = true;
  private readonly errorCodes: ReadonlySet<string>;

  constructor(
    private readonly resolver: RestrictedResolver,
    private readonly options: DnsblOptions,
  ) {
    this.errorCodes = new Set(options.errorCodes ?? DEFAULT_DNSBL_ERROR_CODES);
    const config = `${zoneConfig(options.domainZones)}|${zoneConfig(options.ipZones)}|${[...this.errorCodes].sort().join(',')}`;
    this.version = `dnsbl/1;${createHash('sha256').update(config).digest('hex').slice(0, 8)}`;
  }

  /** The DNS names one item is checked with. */
  queriesFor(item: ReputationItem): Array<{ name: string; zone: DnsblZone }> {
    if (item.kind === 'ip') {
      const ip = canonicalIp(item.value);
      const label = ip === null ? null : reverseIpLabel(ip);
      return label === null
        ? []
        : this.options.ipZones.map((zone) => ({ name: `${label}.${zone.zone}`, zone }));
    }
    if (item.kind !== 'domain') return [];
    const host = item.value.toLowerCase().replace(/\.+$/, '');
    const names = [...new Set([registrableDomainOf(host) ?? host, host])];
    return this.options.domainZones.flatMap((zone) =>
      names.map((name) => ({ name: `${name}.${zone.zone}`, zone })),
    );
  }

  async lookup(items: readonly ReputationItem[], signal: AbortSignal): Promise<ProviderAnswer[]> {
    return mapLimit(
      items,
      Math.max(1, Math.ceil((this.options.concurrency ?? 16) / 2)),
      async (item) => {
        const queries = this.queriesFor(item);
        if (queries.length === 0) return clearAnswer(item, 'not_applicable');
        const answers = await mapLimit(queries, 2, (query) =>
          this.query(item, query.name, query.zone, signal),
        );
        return combineAnswers(item, answers);
      },
    );
  }

  private async query(
    item: ReputationItem,
    name: string,
    zone: DnsblZone,
    signal: AbortSignal,
  ): Promise<ProviderAnswer> {
    let addresses: string[];
    try {
      addresses = await this.resolver.resolve4Raw(name, signal);
    } catch (error) {
      return errorAnswer(item, error instanceof DnsLookupError ? `dns_${error.kind}` : 'dns_error');
    }
    if (addresses.length === 0) return clearAnswer(item);
    const listed: ProviderAnswer[] = [];
    for (const address of addresses) {
      if (this.errorCodes.has(address) || !address.startsWith('127.')) {
        return errorAnswer(item, 'dnsbl_error_code');
      }
      const category = zone.codes.get(address) ?? 'other';
      listed.push({
        kind: item.kind,
        value: item.value,
        status: 'listed',
        category,
        severity: severityOf(category),
        detail: address,
      });
    }
    return combineAnswers(item, listed);
  }
}
