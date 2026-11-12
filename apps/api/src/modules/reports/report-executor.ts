import { Inject, Injectable, Logger } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { KeyValueStore } from '../../kv/key-value-store';
import { type ReportName, type ReportParams, reportCacheKey } from './domain/report-cache-key';
import { ReportQueryTimeoutError, reportTimeout } from './domain/report-errors';
import { ReportMetrics } from './report-metrics';

/** What is stored under a report key: the owner is checked again on every read. */
interface CacheEnvelope {
  v: 1;
  organizationId: string;
  report: ReportName;
  data: unknown;
}

/**
 * Runs a report computation behind the per-organization Redis cache (step 6.1 D12): key
 * `rpt:v1:<organizationId>:<report>:<sha256(params)>`, JSON, TTL `REPORTS_CACHE_TTL_SECONDS`.
 *
 * - A hit is served only when the stored envelope names the same organization and report (a
 *   foreign or malformed entry is a miss and is overwritten); entries are never shared.
 * - A cache read or write failure is logged and the report is computed (never a failed request,
 *   never another organization's entry).
 * - A computation interrupted by `MAX_EXECUTION_TIME` (`ReportQueryTimeoutError`) is
 *   `503 report_timeout` and counted in `api_report_timeouts_total{report}`; nothing is cached.
 * - `api_report_duration_seconds{report}` times computations, `api_report_cache_total{report,
 *   outcome}` counts lookups.
 */
@Injectable()
export class ReportExecutor {
  private readonly logger = new Logger(ReportExecutor.name);

  constructor(
    private readonly kv: KeyValueStore,
    private readonly metrics: ReportMetrics,
    @Inject(API_CONFIG) private readonly config: Pick<ApiConfig, 'REPORTS_CACHE_TTL_SECONDS'>,
  ) {}

  async run<T>(
    scope: TenantScope,
    report: ReportName,
    params: ReportParams,
    compute: () => Promise<T>,
  ): Promise<T> {
    const organizationId = scope.organizationId.toString(10);
    const key = reportCacheKey(scope.organizationId, report, params);
    const cached = await this.read(key, organizationId, report);
    if (cached !== undefined) {
      this.metrics.cache.inc({ report, outcome: 'hit' });
      return cached as T;
    }

    const started = process.hrtime.bigint();
    let data: T;
    try {
      data = await compute();
    } catch (err) {
      if (err instanceof ReportQueryTimeoutError) {
        this.metrics.timeouts.inc({ report });
        this.logger.warn({ message: 'Report query timed out', report, query: err.query });
        throw reportTimeout();
      }
      throw err;
    } finally {
      this.metrics.duration.observe(
        { report },
        Number(process.hrtime.bigint() - started) / 1_000_000_000,
      );
    }
    await this.write(key, { v: 1, organizationId, report, data }, report);
    return data;
  }

  private async read(key: string, organizationId: string, report: ReportName): Promise<unknown> {
    let raw: string | null;
    try {
      raw = await this.kv.get(key);
    } catch (err) {
      this.metrics.cache.inc({ report, outcome: 'error' });
      this.logger.warn({ message: 'Report cache read failed; computing the report', report, err });
      return undefined;
    }
    if (raw === null) {
      this.metrics.cache.inc({ report, outcome: 'miss' });
      return undefined;
    }
    try {
      const envelope = JSON.parse(raw) as Partial<CacheEnvelope>;
      if (
        envelope.v === 1 &&
        envelope.organizationId === organizationId &&
        envelope.report === report &&
        envelope.data !== undefined
      ) {
        return envelope.data;
      }
    } catch {
      // A malformed entry is a miss; it is overwritten below.
    }
    this.metrics.cache.inc({ report, outcome: 'miss' });
    this.logger.warn({ message: 'Report cache entry did not match its key; ignored', report });
    return undefined;
  }

  private async write(key: string, envelope: CacheEnvelope, report: ReportName): Promise<void> {
    try {
      await this.kv.set(key, JSON.stringify(envelope), this.config.REPORTS_CACHE_TTL_SECONDS);
    } catch (err) {
      this.logger.warn({ message: 'Report cache write failed; result not cached', report, err });
    }
  }
}
