import {
  anyCidrContains,
  type AtoWindows,
  canonicalIp,
  classifyIp,
  deviceFromUserAgent,
  ipPrefix,
  sha256Hex,
  type AtoIpReputation,
  type GeoView,
  type RedisLike,
  type ResolvedAtoSettings,
} from '@email-gateway/ato-detection';
import type { PrismaClient } from '@email-gateway/database';
import type { AtoGeoIp } from './geoip';
import type { AtoReputation } from './reputation';

/** Everything the authentication rules need about one client IP (D7). */
export interface IpEnrichment {
  ip: string;
  ipPrefix: string | null;
  geo: GeoView;
  reputation: AtoIpReputation | null;
  dnsblListed: boolean | null;
  ipFlag: { flagged: boolean; distinctAccounts: number } | null;
  /** In a tenant blocked network (treated as listed, high). */
  blockedNetwork: boolean;
  /** In a tenant trusted network. */
  trustedNetwork: boolean;
}

const UNAVAILABLE_GEO: GeoView = {
  status: 'unavailable',
  country: null,
  region: null,
  city: null,
  latitude: null,
  longitude: null,
  accuracyKm: null,
  asn: null,
  asnOrg: null,
  anonymizerFlags: null,
};

/**
 * Enrichment of authentication observations (D7): GeoIP City/ASN/Anonymous, IP reputation through
 * the single `AtoReputation` adapter, the platform campaign flag (D8), tenant trusted and blocked
 * networks, device family (bowser) and the T4 breach check (platform `email` indicators by
 * SHA-256 of the address, at most once per account and UTC day).
 */
export class Enricher {
  private readonly breachGate: RedisLike;

  constructor(
    private readonly geo: AtoGeoIp,
    private readonly reputation: AtoReputation,
    private readonly windows: AtoWindows,
    redis: RedisLike,
    private readonly prisma: PrismaClient,
    private readonly options: { allowDocumentationRanges: boolean; now: () => Date },
  ) {
    this.breachGate = redis;
  }

  /** Canonical text of a client IP, or null. */
  static canonical(ip: string | null | undefined): string | null {
    if (!ip) return null;
    return canonicalIp(ip);
  }

  /** Looks the IPs up once (one reputation call for all of them). */
  async enrichIps(
    organizationId: bigint,
    ips: readonly (string | null)[],
    settings: ResolvedAtoSettings,
    signal: AbortSignal,
  ): Promise<Map<string, IpEnrichment>> {
    const canonical = [
      ...new Set(ips.map((ip) => Enricher.canonical(ip)).filter((v): v is string => v !== null)),
    ];
    const out = new Map<string, IpEnrichment>();
    if (canonical.length === 0) return out;
    // Reputation only for routable addresses (private and loopback clients are never listed).
    const lookup = canonical.filter(
      (ip) =>
        classifyIp(ip, { allowDocumentationRanges: this.options.allowDocumentationRanges })
          .geolocatable,
    );
    const rep = await this.reputation.lookupIps(organizationId, lookup, signal, {
      useLocalFeed: settings.ipReputation.useLocalFeed,
      useDnsbl: settings.ipReputation.useDnsbl,
    });
    for (const ip of canonical) {
      const r = rep.get(ip);
      out.set(ip, {
        ip,
        ipPrefix: ipPrefix(ip),
        geo: this.geo.lookup(ip) ?? UNAVAILABLE_GEO,
        reputation: r?.reputation ?? null,
        dnsblListed: r?.dnsblListed ?? null,
        ipFlag: await this.windows.ipFlag(ip),
        blockedNetwork: anyCidrContains(settings.ipReputation.blockedNetworks, ip),
        trustedNetwork: anyCidrContains(settings.ipReputation.trustedNetworks, ip),
      });
    }
    return out;
  }

  device(userAgent: string | null | undefined): { hash: string; label: string } | null {
    const d = deviceFromUserAgent(userAgent ?? null);
    return d ? { hash: d.hash, label: d.label } : null;
  }

  geolocate(ip: string): GeoView {
    return this.geo.lookup(ip);
  }

  /**
   * T4 (D7): whether the address is a platform `email` indicator, checked on the account's first
   * event of the UTC day (gate `ato:t4:{org}:{account}:{day}`, 48 h TTL); null when not checked.
   */
  async breachListed(
    organizationId: bigint,
    accountId: bigint,
    address: string | null,
  ): Promise<boolean | null> {
    if (!address) return null;
    const now = this.options.now();
    const day = Math.floor(now.getTime() / 86_400_000);
    const first = await this.breachGate.set(
      `ato:t4:${organizationId}:${accountId}:${day}`,
      '1',
      'EX',
      48 * 3600,
      'NX',
    );
    if (first !== 'OK') return null;
    const row = await this.prisma.threatIndicator.findFirst({
      where: {
        orgScope: 0n,
        indicatorType: 'email',
        valueSha256: sha256Hex(address.toLowerCase()),
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: { id: true },
    });
    return row !== null;
  }
}
