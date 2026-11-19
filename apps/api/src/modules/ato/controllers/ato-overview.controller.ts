import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiAtoForbidden, ApiAtoResponse, ApiAtoUnavailable } from '../api-docs';
import { ATO_PERMISSIONS as P } from '../ato.constants';
import { ATO_EXAMPLES as X } from '../dto/ato.examples';
import {
  AttentionSchema,
  type AttentionView,
  OVERVIEW_RANGES,
  type OverviewQuery,
  OverviewQuerySchema,
  OverviewSchema,
  type OverviewView,
} from '../dto/ato.schemas';
import { AtoOverviewService } from '../services/ato-overview.service';

/**
 * The account takeover dashboard (step 8.4 §5.1 #1, #2; D16): the overview of a range and the
 * shell badge. Translation only.
 */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato', version: '1' })
export class AtoOverviewController {
  constructor(private readonly overviews: AtoOverviewService) {}

  @Get('overview')
  @RequirePermissions(P.read)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Get the account takeover overview',
    description:
      'Figures of your organization for the last `range` (`24h`, `7d` default, `30d`): monitoring ' +
      'state (feature, mode, learning period), monitored accounts by kind and risk, ATO ' +
      'incidents (active by severity, opened in range with a trend, resolved by resolution), ' +
      'failed and suspicious logins, suspicious outbound activity, restricted accounts, mail held ' +
      'by an `ato.*` policy rule (`policyHeldInRange`: evaluations with ATO facts and a hold ' +
      'disposition), geography (only when the GeoIP City database is loaded: `available: false` ' +
      'with a reason otherwise), responses and the attention counts. Cached per organization ' +
      'and range for API_ATO_OVERVIEW_CACHE_SECONDS (default 60). From the read replica. Rate ' +
      'class `expensive`. With ATO not enabled: `monitoring.featureEnabled: false` and zero figures.',
  })
  @ApiQuery({
    name: 'range',
    required: false,
    description: '`24h`, `7d` (default) or `30d`',
    schema: { type: 'string', enum: [...OVERVIEW_RANGES] },
  })
  @ApiAtoResponse(200, OverviewSchema, X.overview, 'The overview')
  @ApiCodedError(400, 'Unknown `range` or parameter (`validation_failed`)', ['validation_failed'])
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  overview(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(OverviewQuerySchema)) query: OverviewQuery,
  ): Promise<OverviewView> {
    return this.overviews.overview(scope, query);
  }

  @Get('attention')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the account takeover attention counts',
    description:
      'Active critical ATO incidents and responses awaiting approval (the portal shell badge). ' +
      'Cached 30 s per organization; zeros while ATO is not enabled.',
  })
  @ApiAtoResponse(200, AttentionSchema, X.attention, 'The attention counts')
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  attention(@CurrentScope() scope: TenantScope): Promise<AttentionView> {
    return this.overviews.attention(scope);
  }
}
