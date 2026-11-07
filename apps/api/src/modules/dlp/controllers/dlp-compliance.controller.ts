import { Body, Controller, Delete, Get, Put, Query } from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import {
  CurrentScope,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiInconsistentRead,
  ApiVersionConflict,
  DLP_APPLY_NOTE,
  DLP_COMPLIANCE_MANAGE,
  DLP_READ,
  DlpController,
} from '../api-docs';
import {
  type DlpAadhaarDeleteQuery,
  DlpAadhaarDeleteQuerySchema,
  type DlpAadhaarPut,
  DlpAadhaarPutSchema,
  type DlpComplianceView,
  DlpComplianceViewSchema,
} from '../dto/dlp.schemas';
import { DlpComplianceService } from '../services/dlp-compliance.service';

/** The Aadhaar detection compliance basis (step 4.5 D17, D21). Translation only. */
@DlpController()
@Controller({ path: 'dlp/compliance', version: '1' })
export class DlpComplianceController {
  constructor(private readonly compliance: DlpComplianceService) {}

  @Get()
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'Get the DLP compliance settings',
    description:
      'The recorded Aadhaar detection basis and whether detection is `active` (enabled, ' +
      'attested, a basis and reference recorded, review date in the future). Without it the ' +
      'Aadhaar detector (NI2) does not run at all. From the read replica.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(DlpComplianceViewSchema) })
  @ApiErrors(401, 403)
  get(@CurrentScope() scope: TenantScope): Promise<DlpComplianceView> {
    return this.compliance.get(scope);
  }

  @Put('aadhaar')
  @RequirePermissions(DLP_COMPLIANCE_MANAGE)
  @RequireMfa()
  @UserOnly()
  @ApiOperation({
    summary: 'Record the Aadhaar detection compliance basis',
    description:
      'Enables Aadhaar number detection for the organization with a recorded basis ' +
      '(regulatory_obligation, uidai_authorised_entity, data_protection_policy, other), the ' +
      'organization’s document or approval reference, the caller’s attestation (`attested: ' +
      'true`) and a review date (future, at most 365 days ahead; detection stops after it). ' +
      'The platform records the attestation; whether the basis is lawful is the ' +
      'organization’s decision. Aadhaar numbers are stored masked (last 4) only, even inside ' +
      'evidence. `expectedVersion` must be the current version (0 = never recorded; `409 ' +
      'version_conflict`). MFA-authenticated users only. Audited as ' +
      `\`dlp_compliance.aadhaar_enabled\` with the setting before and after. ${DLP_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(DlpAadhaarPutSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DlpComplianceViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiVersionConflict()
  @ApiInconsistentRead()
  enable(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(DlpAadhaarPutSchema)) body: DlpAadhaarPut,
    @Client() client: ClientContext,
  ): Promise<DlpComplianceView> {
    return this.compliance.enableAadhaar(principal, scope, body, client);
  }

  @Delete('aadhaar')
  @RequirePermissions(DLP_COMPLIANCE_MANAGE)
  @RequireMfa()
  @UserOnly()
  @ApiOperation({
    summary: 'Disable Aadhaar detection',
    description:
      'Clears the recorded basis; the detector stops running. Idempotent (nothing recorded or ' +
      'already disabled: unchanged, not audited). Optionally only at `?expectedVersion=`. ' +
      'MFA-authenticated users only. Audited as `dlp_compliance.aadhaar_disabled` with the ' +
      `setting before. ${DLP_APPLY_NOTE}`,
  })
  @ApiQueryFrom(DlpAadhaarDeleteQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DlpComplianceViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiVersionConflict()
  @ApiInconsistentRead()
  disable(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DlpAadhaarDeleteQuerySchema)) query: DlpAadhaarDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<DlpComplianceView> {
    return this.compliance.disableAadhaar(principal, scope, query.expectedVersion, client);
  }
}
