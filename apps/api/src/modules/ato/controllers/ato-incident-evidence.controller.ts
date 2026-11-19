import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiAtoForbidden,
  ApiAtoResponse,
  ApiAtoUnavailable,
  ApiIncidentIdParam,
  ApiIncidentNotFound,
  FEATURE_OFF_READ,
} from '../api-docs';
import { ATO_PERMISSIONS as P } from '../ato.constants';
import { ATO_EXAMPLES as X } from '../dto/ato.examples';
import {
  type AuthEventPage,
  AuthEventPageSchema,
  type IncidentEvidenceQuery,
  IncidentEvidenceQuerySchema,
  PAGE_PARAMETERS,
  type SignalPage,
  SignalPageSchema,
} from '../dto/ato.schemas';
import { AtoEvidenceService } from '../services/ato-evidence.service';

/**
 * The ATO evidence of a security incident (step 8.4 §5.1 #14, #15; D24): signals and
 * authentication events linked to an `account_takeover` incident. Translation only.
 */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato/incidents', version: '1' })
export class AtoIncidentEvidenceController {
  constructor(private readonly evidence: AtoEvidenceService) {}

  @Get(':incidentId/signals')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the signals of an account takeover incident',
    description:
      'The risk signals linked to the incident, newest first (rule, category, strength, ' +
      'weight, status, explanation, evidence). The id must be an `account_takeover` incident of ' +
      'your organization, else `404 incident_not_found`.' +
      FEATURE_OFF_READ,
  })
  @ApiIncidentIdParam()
  @ApiListQuery(IncidentEvidenceQuerySchema, { ...PAGE_PARAMETERS, sort: '`-at`' })
  @ApiAtoResponse(200, SignalPageSchema, X.signalPage, 'One page of linked signals')
  @ApiListErrors()
  @ApiIncidentNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  signals(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Query(new ZodValidationPipe(IncidentEvidenceQuerySchema)) query: IncidentEvidenceQuery,
  ): Promise<SignalPage> {
    return this.evidence.signals(principal, scope, incidentId, query);
  }

  @Get(':incidentId/auth-events')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the authentication events of an account takeover incident',
    description:
      'The authentication events linked to the incident (at most 1 000 are linked; counts beyond ' +
      'that are in the incident detail), newest first.' +
      FEATURE_OFF_READ,
  })
  @ApiIncidentIdParam()
  @ApiListQuery(IncidentEvidenceQuerySchema, { ...PAGE_PARAMETERS, sort: '`-at`' })
  @ApiAtoResponse(200, AuthEventPageSchema, X.authEventPage, 'One page of linked events')
  @ApiListErrors()
  @ApiIncidentNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  authEvents(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Query(new ZodValidationPipe(IncidentEvidenceQuerySchema)) query: IncidentEvidenceQuery,
  ): Promise<AuthEventPage> {
    return this.evidence.authEvents(principal, scope, incidentId, query);
  }
}
