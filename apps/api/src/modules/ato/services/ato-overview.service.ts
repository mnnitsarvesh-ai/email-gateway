import { Inject, Injectable, Logger } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { KeyValueStore } from '../../../kv/key-value-store';
import { ATO_ATTENTION_CACHE_SECONDS, type AtoConfig } from '../ato.constants';
import type { AttentionView, OverviewQuery, OverviewRange, OverviewView } from '../dto/ato.schemas';
import { AtoReadRepository, type OverviewCounts } from '../repositories/ato-read.repository';
import { AtoAccessService } from './ato-access.service';

const HOUR = 3_600_000;
const DAY = 86_400_000;

/** Range length and trend bucket of each overview range. */
export const OVERVIEW_WINDOWS: Readonly<Record<OverviewRange, { ms: number; bucketMs: number }>> = {
  '24h': { ms: 24 * HOUR, bucketMs: HOUR },
  '7d': { ms: 7 * DAY, bucketMs: DAY },
  '30d': { ms: 30 * DAY, bucketMs: DAY },
};

const EMPTY_COUNTS: OverviewCounts = {
  monitored: { mailbox: 0, gateway_user: 0, smtp_connector: 0 },
  highRisk: 0,
  criticalRisk: 0,
  activeBySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
  openedInRange: [],
  resolvedInRange: {},
  failedLogins: 0,
  suspiciousLogins: 0,
  outboundSignals: 0,
  restrictedAccounts: 0,
  policyHeld: 0,
  topCountries: [],
  newCountrySignals: {},
  impossibleTravel: 0,
  pendingApproval: 0,
  executedInRange: 0,
  failedInRange: 0,
};

/** The trend buckets of `[from, to)` (UTC-aligned starts; the first may be partial). */
export function trendBuckets(
  from: Date,
  to: Date,
  bucketMs: number,
  opened: OverviewCounts['openedInRange'],
): OverviewView['incidents']['trend'] {
  const start = Math.floor(from.getTime() / bucketMs) * bucketMs;
  const out: OverviewView['incidents']['trend'] = [];
  for (let t = start; t < to.getTime(); t += bucketMs) {
    out.push({ bucketStart: new Date(t).toISOString(), low: 0, medium: 0, high: 0, critical: 0 });
  }
  for (const o of opened) {
    const index = Math.floor((o.detectedAt.getTime() - start) / bucketMs);
    const bucket = out[index];
    if (bucket) bucket[o.severity] += 1;
  }
  return out;
}

/**
 * `GET /ato/overview` and `GET /ato/attention` (step 8.4 §5.1 #1, #2; D16): replica figures of the
 * organization, cached per organization and range (`API_ATO_OVERVIEW_CACHE_SECONDS`; attention
 * 30 s) in the key-value store. With the feature off: `featureEnabled: false` and zero figures,
 * never cached. A cache failure falls back to the database (logged).
 */
@Injectable()
export class AtoOverviewService {
  private readonly logger = new Logger(AtoOverviewService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Pick<AtoConfig, 'API_ATO_OVERVIEW_CACHE_SECONDS'>,
    private readonly reads: AtoReadRepository,
    private readonly access: AtoAccessService,
    private readonly kv: KeyValueStore,
  ) {}

  now(): Date {
    return new Date();
  }

  private async cached<T>(key: string, ttl: number, load: () => Promise<T>): Promise<T> {
    try {
      const hit = await this.kv.get(key);
      if (hit !== null) return JSON.parse(hit) as T;
    } catch (error) {
      this.logger.warn({ message: 'ATO cache read failed', errName: (error as Error).name });
    }
    const value = await load();
    try {
      await this.kv.set(key, JSON.stringify(value), ttl);
    } catch (error) {
      this.logger.warn({ message: 'ATO cache write failed', errName: (error as Error).name });
    }
    return value;
  }

  async overview(scope: TenantScope, query: OverviewQuery): Promise<OverviewView> {
    const enabled = await this.access.enabled(scope);
    if (!enabled) return this.build(query.range, this.now(), false, null, EMPTY_COUNTS, false);
    return this.cached(
      `ato:overview:v1:${scope.organizationId.toString()}:${query.range}`,
      this.config.API_ATO_OVERVIEW_CACHE_SECONDS,
      async () => {
        const now = this.now();
        const window = OVERVIEW_WINDOWS[query.range];
        const from = new Date(now.getTime() - window.ms);
        const [loaded, capabilities] = await Promise.all([
          this.access.settings(scope),
          this.access.capabilities(),
        ]);
        const counts = await this.reads.overview(
          scope,
          { from, to: now },
          loaded.settings.scoring.bands,
        );
        const geoAvailable = capabilities.known && capabilities.view.geoipCity === 'available';
        return this.build(query.range, now, true, loaded, counts, geoAvailable, capabilities.known);
      },
    );
  }

  private build(
    range: OverviewRange,
    now: Date,
    featureEnabled: boolean,
    loaded: Awaited<ReturnType<AtoAccessService['settings']>> | null,
    c: OverviewCounts,
    geoAvailable: boolean,
    capabilitiesKnown = false,
  ): OverviewView {
    const window = OVERVIEW_WINDOWS[range];
    const from = new Date(now.getTime() - window.ms);
    const active = c.activeBySeverity;
    const resolvedFp = c.resolvedInRange.false_positive ?? 0;
    const resolvedRemediated = c.resolvedInRange.remediated ?? 0;
    const resolvedAll = Object.values(c.resolvedInRange).reduce((a, b) => a + b, 0);
    return {
      generatedAt: now.toISOString(),
      range,
      from: from.toISOString(),
      to: now.toISOString(),
      monitoring: {
        featureEnabled,
        mode: featureEnabled ? (loaded?.settings.mode ?? 'monitor') : 'off',
        learning: loaded?.learning ?? false,
        learningEndsAt: loaded?.learningEndsAt?.toISOString() ?? null,
      },
      accounts: {
        monitored: c.monitored.mailbox + c.monitored.gateway_user + c.monitored.smtp_connector,
        byKind: c.monitored,
        highRisk: c.highRisk,
        criticalRisk: c.criticalRisk,
      },
      incidents: {
        active: active.low + active.medium + active.high + active.critical,
        activeBySeverity: active,
        critical: active.critical,
        openedInRange: c.openedInRange.length,
        trend: trendBuckets(from, now, window.bucketMs, c.openedInRange),
        resolvedInRange: {
          remediated: resolvedRemediated,
          falsePositive: resolvedFp,
          other: resolvedAll - resolvedFp - resolvedRemediated,
        },
      },
      logins: { failedInRange: c.failedLogins, suspiciousInRange: c.suspiciousLogins },
      outbound: {
        suspiciousInRange: c.outboundSignals,
        restrictedAccounts: c.restrictedAccounts,
        policyHeldInRange: c.policyHeld,
      },
      geography: {
        available: geoAvailable,
        reason: geoAvailable
          ? null
          : featureEnabled && !capabilitiesKnown
            ? 'capabilities_unknown'
            : 'geoip_unavailable',
        topCountries: geoAvailable
          ? c.topCountries.slice(0, 10).map((t) => ({
              countryCode: t.countryCode,
              successfulAuth: t.successfulAuth,
              newCountrySignals: c.newCountrySignals[t.countryCode] ?? 0,
            }))
          : [],
        impossibleTravelInRange: c.impossibleTravel,
      },
      responses: {
        pendingApproval: c.pendingApproval,
        executedInRange: c.executedInRange,
        failedInRange: c.failedInRange,
      },
      attention: { criticalIncidents: active.critical, pendingApprovals: c.pendingApproval },
    };
  }

  async attention(scope: TenantScope): Promise<AttentionView> {
    if (!(await this.access.enabled(scope))) return { criticalIncidents: 0, pendingApprovals: 0 };
    return this.cached(
      `ato:attention:v1:${scope.organizationId.toString()}`,
      ATO_ATTENTION_CACHE_SECONDS,
      () => this.reads.attention(scope),
    );
  }
}
