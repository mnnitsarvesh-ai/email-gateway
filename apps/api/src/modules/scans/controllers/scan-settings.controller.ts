import { Body, Controller, Delete, Get, Param, Put, Query, UseFilters } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiEngineParam,
  ApiScanEngineNotFound,
  ApiScanSettingsInvalid,
  ApiVersionConflict,
  POLICY_READ,
  SCAN_SETTINGS_MANAGE,
} from '../api-docs';
import {
  type ScanSettingsDeleteQuery,
  ScanSettingsDeleteQuerySchema,
  type ScanSettingsList,
  ScanSettingsListSchema,
  type ScanSettingsPut,
  ScanSettingsPutSchema,
  type ScanSettingsResponse,
  ScanSettingsResponseSchema,
  SETTINGS_APPLY_NOTE,
} from '../dto/scan-settings.schemas';
import { ScanSettingsService } from '../services/scan-settings.service';

/**
 * Security scan settings of the caller's organization (step 4.1 S8, S16; step 4.2 A8): the
 * Rspamd thresholds and severities and the attachment type rules within the platform bounds.
 * Translation only; the logic is in ScanSettingsService.
 */
@ApiTags('scan-settings')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'scan-settings', version: '1' })
export class ScanSettingsController {
  constructor(private readonly settings: ScanSettingsService) {}

  @Get()
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'List the security scan settings',
    description:
      'For every registered scan engine: whether it is required, the platform settings, the ' +
      'bounds an override must respect, the organization’s override, the effective settings ' +
      'and the override `version` (0 = none). An override that no longer fits the platform ' +
      `settings is listed with its violations and not applied. ${SETTINGS_APPLY_NOTE} From the ` +
      'read replica.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(ScanSettingsListSchema) })
  @ApiErrors(401, 403)
  list(@CurrentScope() scope: TenantScope): Promise<ScanSettingsList> {
    return this.settings.list(scope);
  }

  @Put(':engine')
  @RequirePermissions(SCAN_SETTINGS_MANAGE)
  @ApiOperation({
    summary: 'Set the organization’s scan settings of an engine',
    description:
      'Replaces the override with `settings` (rspamd: `spamScore` and `suspiciousScore` within ' +
      'the platform score bounds with suspiciousScore below spamScore; `phishingVerdict`, ' +
      '`dmarcRejectVerdict` and `authFailureVerdict` may only be raised above the platform ' +
      'value; attachment: `deniedTypes` added to the platform deny list, `allowedTypes` for ' +
      'allow-list mode (never a platform-denied type), `deniedTypeVerdict`, ' +
      '`typeMismatchVerdict` and `encryptedArchiveVerdict` raise-only (`suspicious` → ' +
      '`malicious`), `maxAttachmentBytes` tighten-only; archive, CPU and memory limits are ' +
      'platform-only). Compare-and-set on `expectedVersion` (0 when there is no override yet). ' +
      'Audited as `scan_settings.updated` with the settings before and after. A required ' +
      `engine cannot be disabled. ${SETTINGS_APPLY_NOTE}`,
  })
  @ApiEngineParam()
  @ApiBody({ schema: zodToOpenApi(ScanSettingsPutSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(ScanSettingsResponseSchema) })
  @ApiErrors(400, 401, 403)
  @ApiScanEngineNotFound()
  @ApiVersionConflict()
  @ApiScanSettingsInvalid()
  replace(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('engine') engine: string,
    @Body(new ZodValidationPipe(ScanSettingsPutSchema)) body: ScanSettingsPut,
    @Client() client: ClientContext,
  ): Promise<ScanSettingsResponse> {
    return this.settings.replace(principal, scope, engine, body, client);
  }

  @Delete(':engine')
  @RequirePermissions(SCAN_SETTINGS_MANAGE)
  @ApiOperation({
    summary: 'Reset an engine to the platform settings',
    description:
      'Removes the organization’s override (compare-and-set on `expectedVersion`; the version ' +
      'still increases, so an older `expectedVersion` never matches again). Audited as ' +
      '`scan_settings.reset` with the settings before. Without an override nothing changes. ' +
      SETTINGS_APPLY_NOTE,
  })
  @ApiEngineParam()
  @ApiQueryFrom(ScanSettingsDeleteQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(ScanSettingsResponseSchema) })
  @ApiErrors(400, 401, 403)
  @ApiScanEngineNotFound()
  @ApiVersionConflict()
  reset(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('engine') engine: string,
    @Query(new ZodValidationPipe(ScanSettingsDeleteQuerySchema)) query: ScanSettingsDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<ScanSettingsResponse> {
    return this.settings.reset(principal, scope, engine, query.expectedVersion, client);
  }
}
