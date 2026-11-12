import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Principal } from '../../auth-contracts/principal';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../auth-contracts/decorators';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiQueryFrom } from '../organizations/api-docs';
import {
  type UsageQuery,
  UsageQuerySchema,
  UsageResponseSchema,
} from '../organizations/dto/organizations.schemas';
import { ORGANIZATION_READ } from '../organizations/domain/organization-access';
import type { UsageResponse } from '../organizations/services/organization-usage.service';
import { ApiCodedError, ApiOkExample, ApiReadErrors } from '../reports/api-docs';
import { USAGE_EXAMPLE } from './usage.example';
import { UsageService } from './usage.service';

/** `GET /usage` (step 6.1 §3.3, D12): the caller's own organization usage. */
@ApiTags('usage')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'usage', version: '1' })
export class UsageController {
  constructor(private readonly usage: UsageService) {}

  @Get()
  @RequirePermissions(ORGANIZATION_READ)
  @ApiOperation({
    summary: 'Usage of the caller’s organization',
    description:
      'Exactly `GET /organizations/{id}/usage` for the organization of the caller (the API ' +
      'key’s organization, the user’s organization, or the target of a platform override): ' +
      'users, domains, messages by direction in the period and today (UTC), active quarantine ' +
      'entries, API keys and sessions, and the limits with their current use. Period: default ' +
      'the last 30 days, at most 31 days. Served from the read replica.',
  })
  @ApiQueryFrom(UsageQuerySchema)
  @ApiOkExample(UsageResponseSchema, USAGE_EXAMPLE)
  @ApiReadErrors()
  @ApiCodedError(404, ['not_found'], 'The organization no longer exists')
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(UsageQuerySchema)) query: UsageQuery,
  ): Promise<UsageResponse> {
    return this.usage.get(principal, scope, query);
  }
}
