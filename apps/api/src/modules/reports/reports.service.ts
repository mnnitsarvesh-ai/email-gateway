import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import {
  addLatency,
  averageMs,
  DELIVERY_LATENCY_BOUNDS_MS,
  emptyLatency,
  histogramOf,
  type LatencySamples,
  percentileUpperBound,
  PROCESSING_LATENCY_BOUNDS_MS,
  successRate,
} from './domain/latency-histogram';
import {
  bucketStarts,
  DEFAULT_REPORT_RANGE_MS,
  maxRangeDays,
  type ReportGranularity,
  type ReportWindow,
  resolveReportWindow,
} from './domain/report-window';
import {
  rankTopDomains,
  tallyDomains,
  THREAT_VERDICTS,
  TOP_DOMAINS_DEFAULT_LIMIT,
  topDomainCandidates,
} from './domain/top-domains';
import { ReportExecutor } from './report-executor';
import {
  DELIVERY_STATUSES,
  type OutcomeCountRow,
  QUARANTINE_PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  ReportsRepository,
  SCAN_STATUSES,
  URL_CLICK_DECISIONS,
} from './reports.repository';
import {
  ACTION_KEYS,
  type DeliveryReport,
  type DeliveryReportQuery,
  PROCESSING_DEFINITION,
  type ProcessingReport,
  type ProcessingReportQuery,
  type ThreatsReport,
  type ThreatsReportQuery,
  type TopDomainsReport,
  type TopDomainsReportQuery,
  type TrafficReport,
  type TrafficReportQuery,
  type UrlClicksReport,
  type UrlClicksReportQuery,
  VERDICT_KEYS,
  zeroCounts,
} from './reports.schemas';

/** Default bucket size of the traffic and URL-click reports. */
export const DEFAULT_REPORT_GRANULARITY: ReportGranularity = 'day';

type TrafficCounts = TrafficReport['totals'];
type ClickCounts = UrlClicksReport['totals'];

const emptyTraffic = (): TrafficCounts => ({
  total: 0,
  inbound: 0,
  outbound: 0,
  internal: 0,
  verdicts: zeroCounts(VERDICT_KEYS),
});

const emptyClicks = (): ClickCounts => ({ total: 0, decisions: zeroCounts(URL_CLICK_DECISIONS) });

type DeliveryCounts = DeliveryReport['totals'];

interface DeliveryAccumulator {
  total: number;
  statuses: DeliveryCounts['statuses'];
}

const emptyDeliveries = (): DeliveryAccumulator => ({
  total: 0,
  statuses: zeroCounts(DELIVERY_STATUSES),
});

interface RoundAccumulator {
  rounds: number;
  statuses: ProcessingReport['totals']['statuses'];
  latency: LatencySamples;
}

const emptyRounds = (): RoundAccumulator => ({
  rounds: 0,
  statuses: zeroCounts(SCAN_STATUSES),
  latency: emptyLatency(PROCESSING_LATENCY_BOUNDS_MS),
});

/**
 * The verdict × action pairs of the threats report (step 7.1 P15): non-zero pairs, ordered by
 * count (descending), then verdict and action (code-point order).
 */
export function outcomePairs(rows: readonly OutcomeCountRow[]): ThreatsReport['outcomes'] {
  const pairs = new Map<string, ThreatsReport['outcomes'][number]>();
  for (const row of rows) {
    const verdict = row.verdict ?? 'none';
    const action = row.action ?? 'none';
    const key = `${verdict}|${action}`;
    const pair = pairs.get(key) ?? { verdict, action, count: 0 };
    pair.count += row.count;
    pairs.set(key, pair);
  }
  const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  return [...pairs.values()]
    .filter((p) => p.count > 0)
    .sort((a, b) => b.count - a.count || cmp(a.verdict, b.verdict) || cmp(a.action, b.action));
}

const windowParams = (window: ReportWindow) => ({
  from: window.from.toISOString(),
  to: window.to.toISOString(),
  granularity: window.granularity,
});

/**
 * Traffic, threat and URL-click reports (step 6.1 D12) and the delivery, processing and
 * top-domains reports (step 7.1 §3.3) of the caller's organization: bounded,
 * bucket-aligned UTC windows, computed on the replica by ReportsRepository (one GROUP BY per
 * table, `MAX_EXECUTION_TIME`), zero-filled, and cached per organization and normalized window by
 * ReportExecutor. No count is invented: every number is a COUNT(*) of recorded rows.
 */
@Injectable()
export class ReportsService {
  constructor(
    private readonly repository: ReportsRepository,
    private readonly executor: ReportExecutor,
    @Inject(API_CONFIG) private readonly config: Pick<ApiConfig, 'REPORTS_MAX_RANGE_DAYS'>,
  ) {}

  traffic(
    scope: TenantScope,
    query: TrafficReportQuery,
    now: Date = new Date(),
  ): Promise<TrafficReport> {
    const window = this.window(query, query.granularity ?? DEFAULT_REPORT_GRANULARITY, now);
    const direction = query.direction;
    const params = { ...windowParams(window), direction: direction ?? null };
    return this.executor.run(scope, 'traffic', params, async () => {
      const rows = await this.repository.traffic(scope, window, window.granularity, direction);
      const buckets = new Map(
        bucketStarts(window).map((start) => [start.getTime(), emptyTraffic()]),
      );
      const totals = emptyTraffic();
      for (const row of rows) {
        const bucket = buckets.get(row.bucket.getTime());
        for (const target of bucket ? [bucket, totals] : [totals]) {
          target.total += row.count;
          target[row.direction] += row.count;
          target.verdicts[row.verdict ?? 'none'] += row.count;
        }
      }
      return {
        from: window.from.toISOString(),
        to: window.to.toISOString(),
        generatedAt: new Date().toISOString(),
        granularity: window.granularity,
        direction: direction ?? null,
        buckets: [...buckets].map(([start, counts]) => ({
          start: new Date(start).toISOString(),
          ...counts,
        })),
        totals,
      };
    });
  }

  threats(
    scope: TenantScope,
    query: ThreatsReportQuery,
    now: Date = new Date(),
  ): Promise<ThreatsReport> {
    // Totals only; the window is aligned to hours so repeated dashboard calls share an entry.
    const window = resolveReportWindow(query, {
      granularity: 'hour',
      maxDays: this.config.REPORTS_MAX_RANGE_DAYS,
      defaultMs: DEFAULT_REPORT_RANGE_MS.day,
      now,
    });
    const params = { from: window.from.toISOString(), to: window.to.toISOString() };
    return this.executor.run(scope, 'threats', params, async () => {
      const [outcomes, quarantine] = await Promise.all([
        this.repository.outcomes(scope, window),
        this.repository.quarantine(scope, window),
      ]);
      const verdicts = zeroCounts(VERDICT_KEYS);
      const actions = zeroCounts(ACTION_KEYS);
      let messages = 0;
      for (const row of outcomes) {
        messages += row.count;
        verdicts[row.verdict ?? 'none'] += row.count;
        actions[row.action ?? 'none'] += row.count;
      }
      const reasons = zeroCounts(QUARANTINE_REASONS);
      const primaryEngines = zeroCounts(QUARANTINE_PRIMARY_ENGINES);
      let entries = 0;
      for (const row of quarantine) {
        entries += row.count;
        reasons[row.reason] += row.count;
        primaryEngines[row.primaryEngine] += row.count;
      }
      return {
        from: window.from.toISOString(),
        to: window.to.toISOString(),
        generatedAt: new Date().toISOString(),
        messages: { total: messages, verdicts, actions },
        outcomes: outcomePairs(outcomes),
        quarantine: { total: entries, reasons, primaryEngines },
      };
    });
  }

  /**
   * Deliveries of messages received in the window by bucket and status, the success rate and
   * the delivery latency histogram (step 7.1 §3.3).
   */
  delivery(
    scope: TenantScope,
    query: DeliveryReportQuery,
    now: Date = new Date(),
  ): Promise<DeliveryReport> {
    const window = this.window(query, query.granularity ?? DEFAULT_REPORT_GRANULARITY, now);
    return this.executor.run(scope, 'delivery', windowParams(window), async () => {
      const rows = await this.repository.deliveries(scope, window, window.granularity);
      const buckets = new Map(
        bucketStarts(window).map((start) => [start.getTime(), emptyDeliveries()]),
      );
      const totals = emptyDeliveries();
      const latency = emptyLatency(DELIVERY_LATENCY_BOUNDS_MS);
      for (const row of rows) {
        const bucket = buckets.get(row.bucket.getTime());
        for (const target of bucket ? [bucket, totals] : [totals]) {
          target.total += row.count;
          target.statuses[row.status] += row.count;
        }
        addLatency(latency, row.latency);
      }
      const withRate = (counts: DeliveryAccumulator): DeliveryCounts => ({
        ...counts,
        successRate: successRate(counts.statuses),
      });
      return {
        from: window.from.toISOString(),
        to: window.to.toISOString(),
        generatedAt: new Date().toISOString(),
        granularity: window.granularity,
        buckets: [...buckets].map(([start, counts]) => ({
          start: new Date(start).toISOString(),
          ...withRate(counts),
        })),
        totals: withRate(totals),
        latency: {
          delivered: latency.samples,
          averageMs: averageMs(latency),
          p50UpperBoundMs: percentileUpperBound(DELIVERY_LATENCY_BOUNDS_MS, latency, 50),
          p95UpperBoundMs: percentileUpperBound(DELIVERY_LATENCY_BOUNDS_MS, latency, 95),
          histogram: histogramOf(DELIVERY_LATENCY_BOUNDS_MS, latency),
        },
      };
    });
  }

  /**
   * Initial scan rounds of messages received in the window by bucket and status, and the time
   * to verdict (receipt → initial round completed) per bucket and in total (step 7.1 §3.3).
   */
  processing(
    scope: TenantScope,
    query: ProcessingReportQuery,
    now: Date = new Date(),
  ): Promise<ProcessingReport> {
    const window = this.window(query, query.granularity ?? DEFAULT_REPORT_GRANULARITY, now);
    const bounds = PROCESSING_LATENCY_BOUNDS_MS;
    return this.executor.run(scope, 'processing', windowParams(window), async () => {
      const rows = await this.repository.scanRounds(scope, window, window.granularity);
      const buckets = new Map(
        bucketStarts(window).map((start) => [start.getTime(), emptyRounds()]),
      );
      const totals = emptyRounds();
      for (const row of rows) {
        const bucket = buckets.get(row.bucket.getTime());
        for (const target of bucket ? [bucket, totals] : [totals]) {
          target.rounds += row.count;
          target.statuses[row.status] += row.count;
          addLatency(target.latency, row.latency);
        }
      }
      return {
        from: window.from.toISOString(),
        to: window.to.toISOString(),
        generatedAt: new Date().toISOString(),
        granularity: window.granularity,
        buckets: [...buckets].map(([start, acc]) => ({
          start: new Date(start).toISOString(),
          rounds: acc.rounds,
          statuses: acc.statuses,
          averageMs: averageMs(acc.latency),
          p95UpperBoundMs: percentileUpperBound(bounds, acc.latency, 95),
        })),
        totals: {
          rounds: totals.rounds,
          statuses: totals.statuses,
          averageMs: averageMs(totals.latency),
          p50UpperBoundMs: percentileUpperBound(bounds, totals.latency, 50),
          p95UpperBoundMs: percentileUpperBound(bounds, totals.latency, 95),
          histogram: histogramOf(bounds, totals.latency),
        },
        definition: PROCESSING_DEFINITION,
      };
    });
  }

  /**
   * Inbound messages with a threat verdict per tenant domain (step 7.1 §3.3): the top `limit`
   * domains with threats, names resolved inside the tenant, plus the unattributed messages.
   */
  topDomains(
    scope: TenantScope,
    query: TopDomainsReportQuery,
    now: Date = new Date(),
  ): Promise<TopDomainsReport> {
    // Aligned to whole hours like the threats report so dashboard calls share a cache entry.
    const window = resolveReportWindow(query, {
      granularity: 'hour',
      maxDays: this.config.REPORTS_MAX_RANGE_DAYS,
      defaultMs: DEFAULT_REPORT_RANGE_MS.day,
      now,
    });
    const limit = query.limit ?? TOP_DOMAINS_DEFAULT_LIMIT;
    const params = { from: window.from.toISOString(), to: window.to.toISOString(), limit };
    return this.executor.run(scope, 'top-domains', params, async () => {
      const tallies = tallyDomains(await this.repository.domainVerdicts(scope, window));
      const candidates = topDomainCandidates(tallies.domains, limit);
      const domains = await this.repository.domains(
        scope,
        candidates.map((c) => c.domainId),
      );
      const named = candidates.map((c) => ({ ...c, domain: domains.get(c.domainId)! }));
      const ranked = rankTopDomains(
        named.map((c) => ({ ...c, name: c.domain.name })),
        limit,
      );
      return {
        from: window.from.toISOString(),
        to: window.to.toISOString(),
        generatedAt: new Date().toISOString(),
        threatVerdicts: [...THREAT_VERDICTS],
        domains: ranked.map((d) => ({
          domainId: d.domain.publicId,
          name: d.domain.name,
          status: d.domain.status,
          deleted: d.domain.deleted,
          inbound: d.inbound,
          threats: d.threats,
          verdicts: d.verdicts,
        })),
        unattributed: tallies.unattributed,
      };
    });
  }

  urlClicks(
    scope: TenantScope,
    query: UrlClicksReportQuery,
    now: Date = new Date(),
  ): Promise<UrlClicksReport> {
    const window = this.window(query, query.granularity ?? DEFAULT_REPORT_GRANULARITY, now);
    return this.executor.run(scope, 'url_clicks', windowParams(window), async () => {
      const rows = await this.repository.clicks(scope, window, window.granularity);
      const buckets = new Map(
        bucketStarts(window).map((start) => [start.getTime(), emptyClicks()]),
      );
      const totals = emptyClicks();
      for (const row of rows) {
        const bucket = buckets.get(row.bucket.getTime());
        for (const target of bucket ? [bucket, totals] : [totals]) {
          target.total += row.count;
          target.decisions[row.decision] += row.count;
        }
      }
      return {
        from: window.from.toISOString(),
        to: window.to.toISOString(),
        generatedAt: new Date().toISOString(),
        granularity: window.granularity,
        buckets: [...buckets].map(([start, counts]) => ({
          start: new Date(start).toISOString(),
          ...counts,
        })),
        totals,
      };
    });
  }

  private window(
    query: { from?: Date | undefined; to?: Date | undefined },
    granularity: ReportGranularity,
    now: Date,
  ): ReportWindow {
    return resolveReportWindow(query, {
      granularity,
      maxDays: maxRangeDays(granularity, this.config.REPORTS_MAX_RANGE_DAYS),
      now,
    });
  }
}
