import type { AtoIpReputation } from '@email-gateway/ato-detection';
import {
  createReputationProviders,
  parseDnsblZones,
  ReputationService,
  RestrictedResolver,
  UrlCache,
  type FeedQuery,
  type ProviderAnswer,
  type RedisLike as CacheRedis,
  type ReputationItem,
  type ReputationLookup,
} from '@email-gateway/url-security';
import type { PrismaClient } from '@email-gateway/database';
import type { AtoMetrics } from '../metrics/ato-metrics';

/**
 * The Reputation contract of step 8.4 D7 (PO5, binding for ATP-1): this file is the ONLY place in
 * the ato-worker that calls url-security's `ReputationService`. Every ATO IP lookup builds
 * `ReputationItem { kind: 'ip', value }` and calls `ReputationService.lookup(items, signal)`; rules
 * consume only the normalized `AtoIpReputation` (feed providers) and the DNSBL flag (T2).
 *
 * Today the providers are the platform `local_feed` (`threat_indicators` of type `ip`,
 * `org_scope = 0`, never cached) and, with `ATO_DNSBL_IP_ZONES`, a DNSBL provider over those zones
 * only. `confidence` is `null` (the platform feed has no trust model). When ATP-1 adds tenant
 * indicators and confidence/trust gating behind `ReputationService`, only this adapter passes the
 * organization through and maps the confidence; no ATO rule, table or event changes. Errors and
 * timeouts are `error`, never `clear`. ATO never reads `threat_indicators` for IPs directly.
 */

/** One IP's result: the feed reputation (T1, T6) and the DNSBL listing (T2). */
export interface AtoIpLookup {
  /** Null when no feed provider was consulted (the tenant disabled the local feed). */
  reputation: AtoIpReputation | null;
  /** True listed, false clear, null when DNSBL is not configured, disabled or failed. */
  dnsblListed: boolean | null;
}

export interface AtoReputationOptions {
  /** Per-organization switches (`settings.ipReputation.useLocalFeed`, `.useDnsbl`). */
  useLocalFeed: boolean;
  useDnsbl: boolean;
}

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 } as const;
const DNSBL_PROVIDER = 'dnsbl';

/** Maps the feed answers of one IP to `AtoIpReputation` (any listed → the most severe listed). */
export function toAtoIpReputation(answers: readonly ReputationLookup[]): AtoIpReputation {
  const providers = [...new Set(answers.map((a) => a.provider))].sort();
  const listed = answers.filter((a) => a.status === 'listed');
  if (listed.length > 0) {
    const top = [...listed].sort(
      (a, b) => SEVERITY_RANK[b.severity ?? 'low'] - SEVERITY_RANK[a.severity ?? 'low'],
    )[0] as ProviderAnswer;
    return {
      status: 'listed',
      severity: top.severity ?? 'medium',
      category: top.category,
      // ATP-1 maps a provider confidence here; the platform feed has none today.
      confidence: null,
      providers,
    };
  }
  const error = answers.some((a) => a.status === 'error');
  return {
    status: error || answers.length === 0 ? 'error' : 'clear',
    severity: null,
    category: null,
    confidence: null,
    providers,
  };
}

export class AtoReputation {
  readonly dnsblZones: number;

  constructor(
    private readonly service: ReputationService,
    private readonly metrics: AtoMetrics | null,
    dnsblZones: number,
  ) {
    this.dnsblZones = dnsblZones;
  }

  /** Whether the DNSBL capability (T2) exists on this worker. */
  get dnsblConfigured(): boolean {
    return this.dnsblZones > 0;
  }

  /**
   * `AtoReputation.lookupIps(organizationId, ips, signal)` (D7). The organization is not used by the
   * platform providers today; ATP-1's tenant indicators will be scoped by it here.
   */
  async lookupIps(
    organizationId: bigint,
    ips: readonly string[],
    signal: AbortSignal,
    options: AtoReputationOptions = { useLocalFeed: true, useDnsbl: true },
  ): Promise<Map<string, AtoIpLookup>> {
    void organizationId;
    const unique = [...new Set(ips)];
    const out = new Map<string, AtoIpLookup>();
    if (unique.length === 0) return out;
    const items: ReputationItem[] = unique.map((value) => ({ kind: 'ip', value }));
    let answers: ReputationLookup[];
    try {
      answers = await this.service.lookup(items, signal);
    } catch {
      answers = [];
    }
    for (const a of answers)
      this.metrics?.reputationLookups.inc({ provider: a.provider, result: a.status });
    for (const ip of unique) {
      const mine = answers.filter((a) => a.kind === 'ip' && a.value === ip);
      const feed = mine.filter((a) => a.provider !== DNSBL_PROVIDER);
      const dnsbl = mine.filter((a) => a.provider === DNSBL_PROVIDER);
      let dnsblListed: boolean | null = null;
      if (options.useDnsbl && this.dnsblConfigured && dnsbl.length > 0) {
        if (dnsbl.some((a) => a.status === 'listed')) dnsblListed = true;
        else if (dnsbl.every((a) => a.status === 'clear')) dnsblListed = false;
      }
      out.set(ip, {
        reputation: options.useLocalFeed ? toAtoIpReputation(feed) : null,
        dnsblListed,
      });
    }
    return out;
  }
}

/** The platform feed query of `local_feed` for IPs (`org_scope = 0`, unexpired). */
export function platformFeedQuery(prisma: PrismaClient, now: () => Date): FeedQuery {
  return async (kind, hashes) => {
    if (hashes.length === 0) return [];
    const rows = await prisma.threatIndicator.findMany({
      where: {
        orgScope: 0n,
        indicatorType: kind,
        valueSha256: { in: [...hashes] },
        OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }],
      },
      select: { orgScope: true, valueSha256: true, severity: true, category: true },
    });
    const requested = new Set(hashes);
    return rows
      .filter((r) => r.orgScope === 0n && requested.has(r.valueSha256))
      .map((r) => ({ valueSha256: r.valueSha256, severity: r.severity, category: r.category }));
  };
}

export interface AtoReputationConfig {
  ATO_DNSBL_IP_ZONES?: string | undefined;
  ATO_DNS_SERVERS: readonly string[];
  ATO_REPUTATION_TIMEOUT_MS: number;
  ATO_HMAC_KEY: string;
}

/**
 * Builds the adapter: `local_feed` always, `dnsbl` over `ATO_DNSBL_IP_ZONES` when set, the
 * restricted resolver (`ATO_DNS_SERVERS`), and the namespaced cache `eg:ato:rep:v1:…` sealed with
 * `ATO_HMAC_KEY` (DNSBL answers only; the feed is never cached).
 */
export function createAtoReputation(
  config: AtoReputationConfig,
  deps: {
    prisma: PrismaClient;
    redis: CacheRedis | null;
    metrics: AtoMetrics | null;
    now?: () => Date;
    resolver?: RestrictedResolver;
  },
): AtoReputation {
  const now = deps.now ?? (() => new Date());
  const zones = parseDnsblZones(config.ATO_DNSBL_IP_ZONES ?? null);
  const resolver =
    deps.resolver ??
    new RestrictedResolver({
      servers: config.ATO_DNS_SERVERS,
      timeoutMs: Math.max(100, Math.floor(config.ATO_REPUTATION_TIMEOUT_MS / 2)),
      tries: 1,
    });
  const providers = createReputationProviders(
    {
      providers: zones.length > 0 ? ['local_feed', 'dnsbl'] : ['local_feed'],
      dnsblIpZones: config.ATO_DNSBL_IP_ZONES ?? null,
    },
    { resolver, feedQuery: platformFeedQuery(deps.prisma, now) },
  );
  const cache = deps.redis
    ? new UrlCache({ client: deps.redis, hmacKey: config.ATO_HMAC_KEY, namespace: 'ato' })
    : null;
  const service = new ReputationService(providers, {
    timeoutMs: config.ATO_REPUTATION_TIMEOUT_MS,
    breakerThreshold: 5,
    breakerResetMs: 30_000,
    cache,
    now: () => now().getTime(),
  });
  return new AtoReputation(service, deps.metrics, zones.length);
}
