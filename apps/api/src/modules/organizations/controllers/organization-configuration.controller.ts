import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Put } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { FeatureKey, LimitKey } from '@email-gateway/database';
import {
  RequireAnyPermission,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiOrganizationId } from '../api-docs';
import {
  ORGANIZATION_MANAGE,
  ORGANIZATION_READ,
  type OrganizationAccess,
  PLATFORM_ORGANIZATIONS,
} from '../domain/organization-access';
import {
  FeatureKeySchema,
  FeatureListResponseSchema,
  type FeatureOverrideInput,
  FeatureOverrideSchema,
  FeatureResponseSchema,
  LimitKeySchema,
  LimitListResponseSchema,
  type LimitOverrideInput,
  LimitOverrideSchema,
  LimitResponseSchema,
  SettingsResponseSchema,
  type SettingsUpdate,
  SettingsUpdateSchema,
  UuidParamSchema,
} from '../dto/organizations.schemas';
import { OrgAccess } from '../organization-access.decorator';
import type { FeatureResponse, LimitResponse, SettingsResponse } from '../organization.mapper';
import {
  type FeatureList,
  type LimitList,
  OrganizationEntitlementsService,
} from '../services/organization-entitlements.service';
import { OrganizationSettingsService } from '../services/organization-settings.service';

const idPipe = new ZodValidationPipe(UuidParamSchema);
const featureKeyPipe = new ZodValidationPipe(FeatureKeySchema);
const limitKeyPipe = new ZodValidationPipe(LimitKeySchema);

const ApiFeatureKey = () =>
  ApiParam({ name: 'featureKey', schema: zodToOpenApi(FeatureKeySchema, { io: 'input' }) });
const ApiLimitKey = () =>
  ApiParam({ name: 'limitKey', schema: zodToOpenApi(LimitKeySchema, { io: 'input' }) });

/** Settings, feature flags and limits of an organization (§4.3, D12). */
@ApiTags('organizations')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@Controller({ path: 'organizations', version: '1' })
export class OrganizationConfigurationController {
  constructor(
    private readonly settings: OrganizationSettingsService,
    private readonly entitlements: OrganizationEntitlementsService,
  ) {}

  // ---- Settings ----------------------------------------------------------------------------

  @Get(':id/settings')
  @RequireAnyPermission(ORGANIZATION_READ, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({ summary: 'Get organization settings' })
  @ApiOrganizationId()
  @ApiOkResponse({ schema: zodToOpenApi(SettingsResponseSchema) })
  @ApiErrors(400, 401, 403, 404)
  getSettings(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
  ): Promise<SettingsResponse> {
    return this.settings.get(access, id);
  }

  @Put(':id/settings')
  @RequireAnyPermission(ORGANIZATION_MANAGE, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'Update organization settings',
    description:
      'Changes the given fields (at least one). timezone: IANA zone; locale: BCP 47; ' +
      'quarantineRetentionDays: 1 … min(organization limit quarantine_retention_days, platform ' +
      'quarantine.max_retention_days); digestSchedule: 5-field cron; preferences: JSON object ' +
      '≤ 16 KiB; mfaRequired cannot be turned off for the platform organization.',
  })
  @ApiOrganizationId()
  @ApiBody({ schema: zodToOpenApi(SettingsUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(SettingsResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  updateSettings(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(SettingsUpdateSchema)) body: SettingsUpdate,
    @Client() client: ClientContext,
  ): Promise<SettingsResponse> {
    return this.settings.update(access, id, body, client);
  }

  // ---- Feature flags -----------------------------------------------------------------------

  @Get(':id/features')
  @RequireAnyPermission(ORGANIZATION_READ, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({ summary: 'List organization feature flags' })
  @ApiOrganizationId()
  @ApiOkResponse({ schema: zodToOpenApi(FeatureListResponseSchema) })
  @ApiErrors(400, 401, 403, 404)
  listFeatures(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
  ): Promise<FeatureList> {
    return this.entitlements.listFeatures(access, id);
  }

  @Put(':id/features/:featureKey')
  @RequirePermissions(PLATFORM_ORGANIZATIONS)
  @UserOnly()
  @ApiOperation({ summary: 'Override a feature flag (source override)' })
  @ApiOrganizationId()
  @ApiFeatureKey()
  @ApiBody({ schema: zodToOpenApi(FeatureOverrideSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(FeatureResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  overrideFeature(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Param('featureKey', featureKeyPipe) featureKey: FeatureKey,
    @Body(new ZodValidationPipe(FeatureOverrideSchema)) body: FeatureOverrideInput,
    @Client() client: ClientContext,
  ): Promise<FeatureResponse> {
    return this.entitlements.overrideFeature(access, id, featureKey, body, client);
  }

  @Delete(':id/features/:featureKey')
  @RequirePermissions(PLATFORM_ORGANIZATIONS)
  @UserOnly()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Reset a feature flag to the plan value (source plan)' })
  @ApiOrganizationId()
  @ApiFeatureKey()
  @ApiNoContentResponse({ description: 'Restored to the plan value' })
  @ApiErrors(400, 401, 403, 404, 409)
  async resetFeature(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Param('featureKey', featureKeyPipe) featureKey: FeatureKey,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.entitlements.resetFeature(access, id, featureKey, client);
  }

  // ---- Limits ------------------------------------------------------------------------------

  @Get(':id/limits')
  @RequireAnyPermission(ORGANIZATION_READ, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({ summary: 'List organization limits' })
  @ApiOrganizationId()
  @ApiOkResponse({ schema: zodToOpenApi(LimitListResponseSchema) })
  @ApiErrors(400, 401, 403, 404)
  listLimits(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
  ): Promise<LimitList> {
    return this.entitlements.listLimits(access, id);
  }

  @Put(':id/limits/:limitKey')
  @RequirePermissions(PLATFORM_ORGANIZATIONS)
  @UserOnly()
  @ApiOperation({ summary: 'Override a limit (source override)' })
  @ApiOrganizationId()
  @ApiLimitKey()
  @ApiBody({ schema: zodToOpenApi(LimitOverrideSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(LimitResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  overrideLimit(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Param('limitKey', limitKeyPipe) limitKey: LimitKey,
    @Body(new ZodValidationPipe(LimitOverrideSchema)) body: LimitOverrideInput,
    @Client() client: ClientContext,
  ): Promise<LimitResponse> {
    return this.entitlements.overrideLimit(access, id, limitKey, body, client);
  }

  @Delete(':id/limits/:limitKey')
  @RequirePermissions(PLATFORM_ORGANIZATIONS)
  @UserOnly()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Reset a limit to the plan value (source plan)' })
  @ApiOrganizationId()
  @ApiLimitKey()
  @ApiNoContentResponse({ description: 'Restored to the plan value' })
  @ApiErrors(400, 401, 403, 404, 409)
  async resetLimit(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Param('limitKey', limitKeyPipe) limitKey: LimitKey,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.entitlements.resetLimit(access, id, limitKey, client);
  }
}
