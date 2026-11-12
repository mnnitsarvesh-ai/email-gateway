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
  THREATS_REPORT_EXAMPLE,
  type ThreatsReport,
  type ThreatsReportQuery,
  ThreatsReportQuerySchema,
  ThreatsReportSchema,
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

/** `/reports/*` (step 6.1 §3.3, D12): thin; the work is in ReportsService. */
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
      'Messages by final verdict and final action, and quarantine entries (one per recipient) ' +
      'by reason and primary engine, in the window (default the last 7 days, at most ' +
      '`REPORTS_MAX_RANGE_DAYS`, aligned to whole hours). ' +
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
}
