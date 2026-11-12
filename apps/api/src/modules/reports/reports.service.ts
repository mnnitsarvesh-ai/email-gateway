import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import {
  bucketStarts,
  DEFAULT_REPORT_RANGE_MS,
  maxRangeDays,
  type ReportGranularity,
  type ReportWindow,
  resolveReportWindow,
} from './domain/report-window';
import { ReportExecutor } from './report-executor';
import {
  QUARANTINE_PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  ReportsRepository,
  URL_CLICK_DECISIONS,
} from './reports.repository';
import {
  ACTION_KEYS,
  type ThreatsReport,
  type ThreatsReportQuery,
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

const windowParams = (window: ReportWindow) => ({
  from: window.from.toISOString(),
  to: window.to.toISOString(),
  granularity: window.granularity,
});

/**
 * Traffic, threat and URL-click reports of the caller's organization (step 6.1 D12): bounded,
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
        quarantine: { total: entries, reasons, primaryEngines },
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
