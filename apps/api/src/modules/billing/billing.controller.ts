import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { RateClass } from '../../rate-limit/rate-class.decorator';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiQueryFrom } from '../organizations/api-docs';
import { ApiCodedError, ApiOkExample, ApiReadErrors } from '../reports/api-docs';
import { REPORT_TIMEOUT } from '../reports/domain/report-errors';
import {
  BILLING_PLAN_EXAMPLE,
  BILLING_USAGE_EXAMPLE,
  type BillingPlan,
  BillingPlanQuerySchema,
  BillingPlanSchema,
  type BillingUsage,
  type BillingUsageQuery,
  BillingUsageQuerySchema,
  BillingUsageSchema,
} from './billing.schemas';
import { BillingService } from './billing.service';
import { USAGE_PERIOD_UNAVAILABLE } from './domain/billing-month';

export const BILLING_READ = 'billing:read';

/** `/billing/*` (step 6.1 §3.3, D12): read only; no prices or invoices exist. */
@ApiTags('billing')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'billing', version: '1' })
export class BillingController {
  constructor(private readonly billing: BillingService) {}

  @Get('plan')
  @RequirePermissions(BILLING_READ)
  @ApiOperation({
    summary: 'Plan and entitlements',
    description:
      'The organization’s plan (code, name, description) and its effective limits and features ' +
      'with their source (`plan` default or platform `override`). `pricing` is always null: the ' +
      'platform records no prices, invoices, payment methods or subscriptions. Read replica.',
  })
  @ApiOkExample(BillingPlanSchema, BILLING_PLAN_EXAMPLE)
  @ApiReadErrors()
  @ApiCodedError(404, ['not_found'], 'The organization no longer exists')
  plan(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BillingPlanQuerySchema)) _query: Record<string, never>,
  ): Promise<BillingPlan> {
    return this.billing.plan(principal, scope);
  }

  @Get('usage')
  @RequirePermissions(BILLING_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Metered usage of a month',
    description:
      'Quantities recorded for a calendar month (UTC, `month=YYYY-MM`, default the current ' +
      'month, counted up to now): messages received by direction (index-only count, ' +
      '`MAX_EXECUTION_TIME`), and the current users, domains, active API keys and limits. A ' +
      'month in the future, or older than the message retention (6 months plus the current ' +
      'one), is `400 usage_period_unavailable`. Cached per organization and month for ' +
      '`REPORTS_CACHE_TTL_SECONDS`; class `expensive`; read replica. No prices or invoices.',
  })
  @ApiQueryFrom(BillingUsageQuerySchema)
  @ApiOkExample(BillingUsageSchema, BILLING_USAGE_EXAMPLE)
  @ApiReadErrors({ extra400: [USAGE_PERIOD_UNAVAILABLE], extra503: [REPORT_TIMEOUT] })
  @ApiCodedError(404, ['not_found'], 'The organization no longer exists')
  usage(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BillingUsageQuerySchema)) query: BillingUsageQuery,
  ): Promise<BillingUsage> {
    return this.billing.usage(principal, scope, query);
  }
}
