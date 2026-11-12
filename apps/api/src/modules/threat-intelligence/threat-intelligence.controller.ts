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
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import { ApiQueryFrom } from '../organizations/api-docs';
import { ApiOkExample, ApiReadErrors } from '../reports/api-docs';
import {
  THREAT_LOOKUP_EXAMPLE,
  type ThreatLookupQuery,
  ThreatLookupQuerySchema,
  type ThreatLookupResponse,
  ThreatLookupResponseSchema,
} from './threat-intelligence.schemas';
import { ThreatIntelligenceService } from './threat-intelligence.service';

export const THREAT_INTEL_READ = 'threat_intel:read';

/** `GET /threat-intelligence/lookup` (step 6.1 §3.3): thin; the work is in the service. */
@ApiTags('threat-intelligence')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'threat-intelligence', version: '1' })
export class ThreatIntelligenceController {
  constructor(private readonly threatIntel: ThreatIntelligenceService) {}

  @Get('lookup')
  @RequirePermissions(THREAT_INTEL_READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Look up a value in the platform threat intelligence',
    description:
      'Normalizes `value` exactly as the scan engines do (URL identity form, IDNA ASCII domain, ' +
      'canonical IP, lower-case SHA-256) and matches it by `value_sha256` against the platform ' +
      'indicators the URL engine and the click-service use (`org_scope = 0`, not expired; a ' +
      'domain also matches indicators of its parent domains down to the registrable domain) ' +
      'and, for `sha256`, the known-threat hash catalogue the attachment engine uses. Returns ' +
      'severities, categories and dates only (never analyst reasons or user ids). Every lookup ' +
      'is audited (`threat_intel.looked_up`, the value’s SHA-256 only); class `expensive`.',
  })
  @ApiQueryFrom(ThreatLookupQuerySchema)
  @ApiOkExample(ThreatLookupResponseSchema, THREAT_LOOKUP_EXAMPLE)
  @ApiReadErrors()
  lookup(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ThreatLookupQuerySchema)) query: ThreatLookupQuery,
    @Client() client: ClientContext,
  ): Promise<ThreatLookupResponse> {
    return this.threatIntel.lookup(principal, scope, query, client);
  }
}
