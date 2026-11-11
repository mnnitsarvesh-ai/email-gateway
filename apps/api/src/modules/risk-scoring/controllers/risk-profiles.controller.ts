import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
} from '@nestjs/common';
import {
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiInconsistentRead,
  ApiRiskConflict,
  ApiRiskProfileInvalid,
  ApiRiskVersionId,
  ApiRiskVersionNotFound,
  POLICY_MANAGE,
  POLICY_PUBLISH,
  POLICY_READ,
  RISK_APPLY_NOTE,
  RISK_DOC_NOTE,
  RiskController,
  riskVersionIdPipe,
} from '../api-docs';
import {
  type RiskPlatformProfileView,
  RiskPlatformProfileViewSchema,
  type RiskPointerChange,
  RiskPointerChangeDocSchema,
  RiskPointerChangeSchema,
  type RiskProfileView,
  RiskProfileViewSchema,
  type RiskPublishResult,
  RiskPublishResultSchema,
  type RiskVersionCreate,
  RiskVersionCreateDocSchema,
  RiskVersionCreateSchema,
  type RiskVersionDeleteQuery,
  RiskVersionDeleteQuerySchema,
  type RiskVersionDetail,
  RiskVersionDetailSchema,
  type RiskVersionListQuery,
  RiskVersionListQuerySchema,
  type RiskVersionPage,
  RiskVersionPageSchema,
  type RiskVersionPublish,
  RiskVersionPublishSchema,
  type RiskVersionUpdate,
  RiskVersionUpdateDocSchema,
  RiskVersionUpdateSchema,
} from '../dto/risk-scoring.schemas';
import {
  RISK_PROFILE_LIMIT_REACHED,
  RISK_PROFILE_VERSION_CONFLICT,
  RISK_PROFILE_VERSION_IMMUTABLE,
  RISK_PROFILE_VERSION_NOT_PUBLISHED,
} from '../risk-scoring.errors';
import { RiskProfilesService } from '../services/risk-profiles.service';

/**
 * The platform risk profile and the organization's risk scoring profile and versions (step 5.1
 * R10, R15). Translation only; the logic is in RiskProfilesService.
 */
@RiskController()
@Controller({ path: 'risk-scoring', version: '1' })
export class RiskProfilesController {
  constructor(private readonly profiles: RiskProfilesService) {}

  @Get('platform-profile')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get the platform risk profile, its override bounds and the signal map',
    description:
      'The effective platform default (RISK_PLATFORM_PROFILE) with its SHA-256, the bounds a ' +
      'tenant override must stay within (R10), the scoring groups, the versioned signal map ' +
      '(`risk-signals/1`: every signal with the `engine:code` assertions, default weight, ' +
      'directions and whether trust may reduce it) and the hard-block catalog. Library data; ' +
      `no database access. ${RISK_DOC_NOTE}`,
  })
  @ApiOkResponse({ schema: zodToOpenApi(RiskPlatformProfileViewSchema) })
  @ApiErrors(401, 403)
  platformProfile(): RiskPlatformProfileView {
    return this.profiles.platform();
  }

  @Get('profile')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get the organization’s active risk profile',
    description:
      'The active source (the platform default, or a published tenant version with its ' +
      'public id and number), the effective profile the next round is scored with (a version ' +
      'the platform bounds no longer accept falls back to the platform default and is listed ' +
      'with its violations), the counts of drafts and published versions and the version ' +
      `limit. From the read replica. ${RISK_APPLY_NOTE} ${RISK_DOC_NOTE}`,
  })
  @ApiOkResponse({ schema: zodToOpenApi(RiskProfileViewSchema) })
  @ApiErrors(401, 403)
  profile(@CurrentScope() scope: TenantScope): Promise<RiskProfileView> {
    return this.profiles.profile(scope);
  }

  @Get('profile/versions')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'List the risk profile versions',
    description:
      'Newest first, cursor-paginated, optionally only drafts or published versions. From the ' +
      'read replica.',
  })
  @ApiQueryFrom(RiskVersionListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(RiskVersionPageSchema) })
  @ApiErrors(400, 401, 403)
  listVersions(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(RiskVersionListQuerySchema)) query: RiskVersionListQuery,
  ): Promise<RiskVersionPage> {
    return this.profiles.listVersions(scope, query);
  }

  @Get('profile/versions/:versionId')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get a risk profile version',
    description:
      'The overrides document, the effective profile resolved now against the platform ' +
      'profile (with violations if the platform bounds changed since it was written), the ' +
      'hashes and who changed and published it when. From the read replica.',
  })
  @ApiRiskVersionId()
  @ApiOkResponse({ schema: zodToOpenApi(RiskVersionDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiRiskVersionNotFound()
  getVersion(
    @CurrentScope() scope: TenantScope,
    @Param('versionId', riskVersionIdPipe) versionId: string,
  ): Promise<RiskVersionDetail> {
    return this.profiles.getVersion(scope, versionId);
  }

  @Post('profile/versions')
  @RequirePermissions(POLICY_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a draft risk profile version',
    description:
      'A draft with bounded overrides of the platform profile (thresholds, level actions, ' +
      'group multipliers, hard-block switches and actions, failure handling, floors, trust, ' +
      'AI tagging; see `GET /risk-scoring/platform-profile` for the bounds), validated before ' +
      'it is stored (`400 risk_profile_invalid` with violations by path). `basedOnVersionId` ' +
      'copies the overrides (unless given) and the base profile of another version. Numbered ' +
      '1, 2, … per organization; at most RISK_PROFILE_MAX_VERSIONS drafts and published ' +
      'versions (`409 risk_profile_limit_reached`). A draft is never used for scoring until ' +
      'it is published and activated; use the dry-run to try it on a stored round. Audited ' +
      `as \`risk_profile.draft_created\` with the changed override paths. ${RISK_DOC_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(RiskVersionCreateDocSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(RiskVersionDetailSchema) })
  @ApiErrors(401, 403)
  @ApiRiskProfileInvalid()
  @ApiRiskVersionNotFound()
  @ApiRiskConflict([RISK_PROFILE_LIMIT_REACHED])
  @ApiInconsistentRead()
  createDraft(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(RiskVersionCreateSchema)) body: RiskVersionCreate,
    @Client() client: ClientContext,
  ): Promise<RiskVersionDetail> {
    return this.profiles.createDraft(principal, scope, body, client);
  }

  @Put('profile/versions/:versionId')
  @RequirePermissions(POLICY_MANAGE)
  @ApiOperation({
    summary: 'Replace a draft risk profile version',
    description:
      'Replaces the overrides (and the change note when given) of a **draft** at ' +
      '`expectedRowVersion` (`409 risk_profile_version_conflict`); a published version is ' +
      'immutable (`409 risk_profile_version_immutable`). Validated like a new draft. Audited ' +
      'as `risk_profile.draft_updated` with both hashes and the changed override paths.',
  })
  @ApiRiskVersionId()
  @ApiBody({ schema: zodToOpenApi(RiskVersionUpdateDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RiskVersionDetailSchema) })
  @ApiErrors(401, 403)
  @ApiRiskProfileInvalid()
  @ApiRiskVersionNotFound()
  @ApiRiskConflict([RISK_PROFILE_VERSION_CONFLICT, RISK_PROFILE_VERSION_IMMUTABLE])
  @ApiInconsistentRead()
  updateDraft(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('versionId', riskVersionIdPipe) versionId: string,
    @Body(new ZodValidationPipe(RiskVersionUpdateSchema)) body: RiskVersionUpdate,
    @Client() client: ClientContext,
  ): Promise<RiskVersionDetail> {
    return this.profiles.updateDraft(principal, scope, versionId, body, client);
  }

  @Delete('profile/versions/:versionId')
  @RequirePermissions(POLICY_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a draft risk profile version',
    description:
      'Drafts only (`409 risk_profile_version_immutable` for a published version), optionally ' +
      'only at `?expectedRowVersion=`. Audited as `risk_profile.draft_deleted`.',
  })
  @ApiRiskVersionId()
  @ApiQueryFrom(RiskVersionDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiRiskVersionNotFound()
  @ApiRiskConflict([RISK_PROFILE_VERSION_CONFLICT, RISK_PROFILE_VERSION_IMMUTABLE])
  @ApiInconsistentRead()
  async deleteDraft(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('versionId', riskVersionIdPipe) versionId: string,
    @Query(new ZodValidationPipe(RiskVersionDeleteQuerySchema)) query: RiskVersionDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.profiles.deleteDraft(principal, scope, versionId, query.expectedRowVersion, client);
  }

  @Post('profile/versions/:versionId/publish')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Publish a draft risk profile version (and activate it)',
    description:
      'Re-validates the draft at `expectedRowVersion` against the platform profile, records ' +
      'the SHA-256 of its effective profile, who and when, and makes it **immutable**. With ' +
      '`activate` (default true) it also becomes the active version. Audited as ' +
      '`risk_profile.published` (and `risk_profile.activated` with the previous and new ' +
      `version). ${RISK_APPLY_NOTE} ${RISK_DOC_NOTE}`,
  })
  @ApiRiskVersionId()
  @ApiBody({ schema: zodToOpenApi(RiskVersionPublishSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RiskPublishResultSchema) })
  @ApiErrors(401, 403)
  @ApiRiskProfileInvalid()
  @ApiRiskVersionNotFound()
  @ApiRiskConflict([RISK_PROFILE_VERSION_CONFLICT, RISK_PROFILE_VERSION_IMMUTABLE])
  @ApiInconsistentRead()
  publish(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('versionId', riskVersionIdPipe) versionId: string,
    @Body(new ZodValidationPipe(RiskVersionPublishSchema)) body: RiskVersionPublish,
    @Client() client: ClientContext,
  ): Promise<RiskPublishResult> {
    return this.profiles.publish(principal, scope, versionId, body, client);
  }

  @Post('profile/versions/:versionId/activate')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Activate a published risk profile version (rollback)',
    description:
      'Makes a **published** version of the organization the active one ' +
      '(`409 risk_profile_version_not_published` for a draft), optionally only at ' +
      '`expectedProfileVersion`; activating an earlier version is the rollback. Activating ' +
      'the active version changes nothing. Audited as `risk_profile.activated` with the ' +
      `previous and new version. ${RISK_APPLY_NOTE} ${RISK_DOC_NOTE}`,
  })
  @ApiRiskVersionId()
  @ApiBody({ required: false, schema: zodToOpenApi(RiskPointerChangeDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RiskProfileViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiRiskVersionNotFound()
  @ApiRiskConflict([RISK_PROFILE_VERSION_NOT_PUBLISHED, RISK_PROFILE_VERSION_CONFLICT])
  @ApiInconsistentRead()
  activate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('versionId', riskVersionIdPipe) versionId: string,
    @Body(new ZodValidationPipe(RiskPointerChangeSchema)) body: RiskPointerChange,
    @Client() client: ClientContext,
  ): Promise<RiskProfileView> {
    return this.profiles.activate(principal, scope, versionId, body, client);
  }

  @Post('profile/reset')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset the organization to the platform risk profile',
    description:
      'Clears the active version (the platform default applies), optionally only at ' +
      '`expectedProfileVersion`; versions are kept. Resetting while the platform default is ' +
      `active changes nothing. Audited as \`risk_profile.reset\`. ${RISK_APPLY_NOTE}`,
  })
  @ApiBody({ required: false, schema: zodToOpenApi(RiskPointerChangeDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RiskProfileViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiRiskConflict([RISK_PROFILE_VERSION_CONFLICT])
  @ApiInconsistentRead()
  reset(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(RiskPointerChangeSchema)) body: RiskPointerChange,
    @Client() client: ClientContext,
  ): Promise<RiskProfileView> {
    return this.profiles.reset(principal, scope, body, client);
  }
}
