import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../auth-contracts/decorators';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { RateClass } from '../../rate-limit/rate-class.decorator';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiQueryFrom } from '../organizations/api-docs';
import { ApiOkExample, ApiReadErrors } from './api-docs';
import { REPORT_TIMEOUT } from './domain/report-errors';
import {
  DELIVERY_REPORT_EXAMPLE,
  type DeliveryReport,
  type DeliveryReportQuery,
  DeliveryReportQuerySchema,
  DeliveryReportSchema,
  PROCESSING_REPORT_EXAMPLE,
  type ProcessingReport,
  type ProcessingReportQuery,
  ProcessingReportQuerySchema,
  ProcessingReportSchema,
  THREATS_REPORT_EXAMPLE,
  type ThreatsReport,
  type ThreatsReportQuery,
  ThreatsReportQuerySchema,
  ThreatsReportSchema,
  TOP_DOMAINS_REPORT_EXAMPLE,
  type TopDomainsReport,
  type TopDomainsReportQuery,
  TopDomainsReportQuerySchema,
  TopDomainsReportSchema,
  TRAFFIC_REPORT_EXAMPLE,
  type TrafficReport,
  type TrafficReportQuery,
  TrafficReportQuerySchema,
  TrafficReportSchema,
  URL_CLICKS_REPORT_EXAMPLE,
  type UrlClicksReport,
  type UrlClicksReportQuery,
  UrlClicksReportQuerySchema,
  UrlClicksReportSchema,
} from './reports.schemas';
import { ReportsService } from './reports.service';

export const REPORT_READ = 'report:read';

const COMMON =
  'Computed on the read replica from recorded rows (no estimates) for the caller’s ' +
  'organization, over a bounded UTC window aligned to bucket boundaries (`from` floored, `to` ' +
  'ceiled); every bucket is listed, empty ones with zeros. Results are cached per organization ' +
  'and normalized window for `REPORTS_CACHE_TTL_SECONDS` (`generatedAt` shows when). Class ' +
  '`expensive` of the API rate limiter. A query interrupted by `REPORTS_QUERY_TIMEOUT_MS` is ' +
  '`503 report_timeout`: narrow the range.';

/** `/reports/*` (step 6.1 §3.3, D12; step 7.1 §3.3): thin; the work is in ReportsService. */
@ApiTags('reports')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'reports', version: '1' })
export class ReportsController {
  constructor(private readonly reports: ReportsService) {}

  @Get('traffic')
  @RequirePermissions(REPORT_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Mail traffic report',
    description:
      'Messages received per bucket by direction and final verdict (`none` = not decided yet), ' +
      'with totals. `granularity=hour` covers at most 7 days (default the last 24 hours), `day` ' +
      'at most `REPORTS_MAX_RANGE_DAYS` (default the last 7 days); `direction` restricts the ' +
      'counts to one direction. Counted index-only over ' +
      '`(organization_id, received_at, direction, final_verdict)`. ' +
      COMMON,
  })
  @ApiQueryFrom(TrafficReportQuerySchema)
  @ApiOkExample(TrafficReportSchema, TRAFFIC_REPORT_EXAMPLE)
  @ApiReadErrors({ extra503: [REPORT_TIMEOUT] })
  traffic(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(TrafficReportQuerySchema)) query: TrafficReportQuery,
  ): Promise<TrafficReport> {
    return this.reports.traffic(scope, query);
  }

  @Get('threats')
  @RequirePermissions(REPORT_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Threat report',
    description:
      'Messages by final verdict and final action, the verdict × action matrix `outcomes` ' +
      '(non-zero pairs, `none` = not decided yet, ordered by count descending, then verdict and ' +
      'action), and quarantine entries (one per recipient) by reason and primary engine, in the ' +
      'window (default the last 7 days, at most `REPORTS_MAX_RANGE_DAYS`, aligned to whole ' +
      'hours). ' +
      COMMON,
  })
  @ApiQueryFrom(ThreatsReportQuerySchema)
  @ApiOkExample(ThreatsReportSchema, THREATS_REPORT_EXAMPLE)
  @ApiReadErrors({ extra503: [REPORT_TIMEOUT] })
  threats(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ThreatsReportQuerySchema)) query: ThreatsReportQuery,
  ): Promise<ThreatsReport> {
    return this.reports.threats(scope, query);
  }

  @Get('url-clicks')
  @RequirePermissions(REPORT_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'URL click report',
    description:
      'Clicks on rewritten URLs (the click-service’s decisions: allowed, warned, blocked, ' +
      'continued, expired, not_found) per bucket, with totals. Same window rules as the traffic ' +
      'report. ' +
      COMMON,
  })
  @ApiQueryFrom(UrlClicksReportQuerySchema)
  @ApiOkExample(UrlClicksReportSchema, URL_CLICKS_REPORT_EXAMPLE)
  @ApiReadErrors({ extra503: [REPORT_TIMEOUT] })
  urlClicks(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(UrlClicksReportQuerySchema)) query: UrlClicksReportQuery,
  ): Promise<UrlClicksReport> {
    return this.reports.urlClicks(scope, query);
  }

  @Get('delivery')
  @RequirePermissions(REPORT_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Delivery report',
    description:
      'Deliveries (one per recipient delivery chain) of the messages received in the window, per ' +
      'bucket and status, with `successRate` = delivered ÷ (delivered + bounced + failed + ' +
      'expired), 4 decimals, `null` when none of those final states occurred; and the delivery ' +
      'latency (`delivered_at − received_at` of delivered deliveries) as a histogram with fixed ' +
      'bounds, the mean and the p50/p95 histogram upper bounds (`null` without samples or above ' +
      'the last bound). Same window rules as the traffic report. Counted index-only over ' +
      '`(organization_id, received_at, status, delivered_at)`. ' +
      COMMON,
  })
  @ApiQueryFrom(DeliveryReportQuerySchema)
  @ApiOkExample(DeliveryReportSchema, DELIVERY_REPORT_EXAMPLE)
  @ApiReadErrors({ extra503: [REPORT_TIMEOUT] })
  delivery(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DeliveryReportQuerySchema)) query: DeliveryReportQuery,
  ): Promise<DeliveryReport> {
    return this.reports.delivery(scope, query);
  }

  @Get('processing')
  @RequirePermissions(REPORT_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Processing (time to verdict) report',
    description:
      'Initial scan rounds of the messages received in the window, per bucket and status, and ' +
      'the time to verdict: receipt (`email_scans.received_at`) to completion of the initial ' +
      'round (`completed_at`), completed rounds only, as a histogram with fixed bounds, the mean ' +
      'and the p50/p95 histogram upper bounds (`null` without samples or above the last bound). ' +
      'Same window rules as the traffic report. Counted index-only over ' +
      '`(organization_id, received_at, scan_kind, status, completed_at)`. ' +
      COMMON,
  })
  @ApiQueryFrom(ProcessingReportQuerySchema)
  @ApiOkExample(ProcessingReportSchema, PROCESSING_REPORT_EXAMPLE)
  @ApiReadErrors({ extra503: [REPORT_TIMEOUT] })
  processing(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ProcessingReportQuerySchema)) query: ProcessingReportQuery,
  ): Promise<ProcessingReport> {
    return this.reports.processing(scope, query);
  }

  @Get('top-domains')
  @RequirePermissions(REPORT_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Top attacked domains report',
    description:
      'Inbound messages per domain of the organization with a threat verdict (spam, phishing, ' +
      'malware, bec, suspicious): the domains with threats, ordered by threats and inbound ' +
      '(descending), then name, at most `limit` (default 10, at most 25); deleted domains are ' +
      'included with `deleted: true`; messages without a domain are counted in `unattributed`. ' +
      'Window: default the last 7 days, at most `REPORTS_MAX_RANGE_DAYS`, aligned to whole ' +
      'hours. Counted index-only over the message covering index. ' +
      COMMON,
  })
  @ApiQueryFrom(TopDomainsReportQuerySchema)
  @ApiOkExample(TopDomainsReportSchema, TOP_DOMAINS_REPORT_EXAMPLE)
  @ApiReadErrors({ extra503: [REPORT_TIMEOUT] })
  topDomains(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(TopDomainsReportQuerySchema)) query: TopDomainsReportQuery,
  ): Promise<TopDomainsReport> {
    return this.reports.topDomains(scope, query);
  }
}
