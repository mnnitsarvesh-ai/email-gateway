import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
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
  ApiDefinitionInvalid,
  ApiInconsistentRead,
  ApiPolicyConflict,
  ApiPolicyId,
  ApiPolicyNotFound,
  ApiVersionNo,
  ApiVersionNotFound,
  POLICY_MANAGE,
  POLICY_PUBLISH,
  POLICY_READ,
  PoliciesController,
  policyIdPipe,
  policyVersionNoPipe,
} from '../api-docs';
import { POLICY_APPLY_NOTE, POLICY_ENFORCEMENT_NOTE } from '../domain/policy-definition';
import {
  type ExpectedRowVersionQuery,
  ExpectedRowVersionQuerySchema,
  type PolicyChangeResult,
  PolicyChangeResultSchema,
  type PolicyCreate,
  type PolicyCreated,
  PolicyCreatedSchema,
  PolicyCreateSchema,
  type PolicyDetail,
  PolicyDetailSchema,
  type PolicyListQuery,
  PolicyListQuerySchema,
  type PolicyPage,
  PolicyPageSchema,
  type PolicyRowChange,
  PolicyRowChangeDocSchema,
  PolicyRowChangeSchema,
  type PolicyUpdate,
  PolicyUpdateDocSchema,
  PolicyUpdateSchema,
  type PolicyVersionCreate,
  PolicyVersionCreateDocSchema,
  PolicyVersionCreateSchema,
  type PolicyVersionDetail,
  PolicyVersionDetailSchema,
  type PolicyVersionListQuery,
  PolicyVersionListQuerySchema,
  type PolicyVersionPage,
  PolicyVersionPageSchema,
  type PolicyVersionPublish,
  PolicyVersionPublishSchema,
  type PolicyVersionUpdate,
  PolicyVersionUpdateSchema,
} from '../dto/policies.schemas';
import {
  POLICY_CONFLICT,
  POLICY_LIMIT_REACHED,
  POLICY_NAME_TAKEN,
  POLICY_NO_ACTIVE_VERSION,
  POLICY_RULE_LIMIT_REACHED,
  POLICY_VERSION_IMMUTABLE,
  POLICY_VERSION_LIMIT_REACHED,
  POLICY_VERSION_NOT_PUBLISHED,
} from '../policies.errors';
import { PoliciesService } from '../services/policies.service';

/**
 * Tenant policies and their versions (step 5.2 P17, P22). Translation only; the lifecycle is in
 * PoliciesService.
 */
@PoliciesController()
@Controller({ path: 'policies', version: '1' })
export class PolicyManagementController {
  constructor(private readonly policies: PoliciesService) {}

  @Get()
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'List policies',
    description:
      'The organization’s policies (archived ones are not listed), newest first, optionally ' +
      'by status and direction, cursor-paginated, with the organization’s policy generation. ' +
      'From the read replica.',
  })
  @ApiQueryFrom(PolicyListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(PolicyPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(PolicyListQuerySchema)) query: PolicyListQuery,
  ): Promise<PolicyPage> {
    return this.policies.list(scope, query);
  }

  @Post()
  @RequirePermissions(POLICY_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a policy with a first draft',
    description:
      'Creates the policy (status `draft`, never evaluated) and its draft version 1 from a ' +
      '`policy-dsl/1` definition validated before it is stored (`400 policy_definition_invalid` ' +
      'with every violation by path). Names are unique per organization, archived policies ' +
      'included (`409 policy_name_taken`); at most POLICY_MAX_POLICIES policies ' +
      '(`409 policy_limit_reached`). A draft is never evaluated until it is published and ' +
      'activated; use `POST /policies/test` or the message dry-run to try it. Audited as ' +
      `\`policy.created\`. ${POLICY_ENFORCEMENT_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(PolicyCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(PolicyCreatedSchema) })
  @ApiErrors(401, 403)
  @ApiDefinitionInvalid()
  @ApiPolicyConflict([POLICY_NAME_TAKEN, POLICY_LIMIT_REACHED])
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(PolicyCreateSchema)) body: PolicyCreate,
    @Client() client: ClientContext,
  ): Promise<PolicyCreated> {
    return this.policies.create(principal, scope, body, client);
  }

  @Get(':policyId')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get a policy',
    description:
      'The policy, its active version (number, hash, rule count, override flag), the newest ' +
      'version number and the version counts. From the read replica.',
  })
  @ApiPolicyId()
  @ApiOkResponse({ schema: zodToOpenApi(PolicyDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiPolicyNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
  ): Promise<PolicyDetail> {
    return this.policies.get(scope, policyId);
  }

  @Patch(':policyId')
  @RequirePermissions(POLICY_MANAGE)
  @ApiOperation({
    summary: 'Rename or describe a policy',
    description:
      'Changes the name and/or description at `expectedRowVersion` (`409 policy_conflict`). ' +
      'Does not change evaluation (no generation change). Audited as `policy.updated`.',
  })
  @ApiPolicyId()
  @ApiBody({ schema: zodToOpenApi(PolicyUpdateDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiPolicyNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT, POLICY_NAME_TAKEN])
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Body(new ZodValidationPipe(PolicyUpdateSchema)) body: PolicyUpdate,
    @Client() client: ClientContext,
  ): Promise<PolicyDetail> {
    return this.policies.update(principal, scope, policyId, body, client);
  }

  @Post(':policyId/disable')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Disable a policy',
    description:
      'An active policy stops being evaluated (status `disabled`; versions kept). Disabling a ' +
      'policy that is not active changes nothing. Audited as `policy.disabled`. ' +
      POLICY_APPLY_NOTE,
  })
  @ApiPolicyId()
  @ApiBody({ required: false, schema: zodToOpenApi(PolicyRowChangeDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiPolicyNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT])
  @ApiInconsistentRead()
  disable(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Body(new ZodValidationPipe(PolicyRowChangeSchema)) body: PolicyRowChange,
    @Client() client: ClientContext,
  ): Promise<PolicyDetail> {
    return this.policies.disable(principal, scope, policyId, body, client);
  }

  @Post(':policyId/enable')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Enable a policy',
    description:
      'A disabled policy with an active version is evaluated again (`409 ' +
      'policy_no_active_version` without one; `409 policy_rule_limit_reached` when the active ' +
      'rules would exceed POLICY_MAX_ACTIVE_RULES). Enabling an active policy changes nothing. ' +
      `Audited as \`policy.enabled\`. ${POLICY_APPLY_NOTE}`,
  })
  @ApiPolicyId()
  @ApiBody({ required: false, schema: zodToOpenApi(PolicyRowChangeDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyDetailSchema) })
  @ApiErrors(401, 403)
  @ApiDefinitionInvalid()
  @ApiPolicyNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT, POLICY_NO_ACTIVE_VERSION, POLICY_RULE_LIMIT_REACHED])
  @ApiInconsistentRead()
  enable(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Body(new ZodValidationPipe(PolicyRowChangeSchema)) body: PolicyRowChange,
    @Client() client: ClientContext,
  ): Promise<PolicyDetail> {
    return this.policies.enable(principal, scope, policyId, body, client);
  }

  @Delete(':policyId')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete (archive) a policy',
    description:
      'Soft delete: the policy becomes `archived` (invisible in lists and routes; versions and ' +
      'its name kept for history), optionally only at `?expectedRowVersion=`. Deleting an ' +
      `active policy stops its evaluation. Audited as \`policy.deleted\`. ${POLICY_APPLY_NOTE}`,
  })
  @ApiPolicyId()
  @ApiQueryFrom(ExpectedRowVersionQuerySchema)
  @ApiNoContentResponse({ description: 'Archived' })
  @ApiErrors(400, 401, 403)
  @ApiPolicyNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT])
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Query(new ZodValidationPipe(ExpectedRowVersionQuerySchema)) query: ExpectedRowVersionQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.policies.remove(principal, scope, policyId, query.expectedRowVersion, client);
  }

  @Get(':policyId/versions')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'List the versions of a policy',
    description: 'Newest first, optionally by status, cursor-paginated. From the read replica.',
  })
  @ApiPolicyId()
  @ApiQueryFrom(PolicyVersionListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(PolicyVersionPageSchema) })
  @ApiErrors(400, 401, 403)
  @ApiPolicyNotFound()
  listVersions(
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Query(new ZodValidationPipe(PolicyVersionListQuerySchema)) query: PolicyVersionListQuery,
  ): Promise<PolicyVersionPage> {
    return this.policies.listVersions(scope, policyId, query);
  }

  @Post(':policyId/versions')
  @RequirePermissions(POLICY_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a draft version',
    description:
      'A new draft numbered after the newest version, from `definition` or a copy of ' +
      '`basedOnVersionNo`, validated before it is stored. At most ' +
      'POLICY_MAX_VERSIONS_PER_POLICY versions (`409 policy_version_limit_reached`). Audited ' +
      'as `policy.version_draft_created`.',
  })
  @ApiPolicyId()
  @ApiBody({ schema: zodToOpenApi(PolicyVersionCreateDocSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(PolicyVersionDetailSchema) })
  @ApiErrors(401, 403)
  @ApiDefinitionInvalid()
  @ApiVersionNotFound()
  @ApiPolicyConflict([POLICY_VERSION_LIMIT_REACHED])
  @ApiInconsistentRead()
  createDraft(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Body(new ZodValidationPipe(PolicyVersionCreateSchema)) body: PolicyVersionCreate,
    @Client() client: ClientContext,
  ): Promise<PolicyVersionDetail> {
    return this.policies.createDraft(principal, scope, policyId, body, client);
  }

  @Get(':policyId/versions/:versionNo')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get a policy version',
    description:
      'The definition, hashes, references, rule count, who changed and published it when, and ' +
      'the definition validated now (violations if the DSL moved). From the read replica.',
  })
  @ApiPolicyId()
  @ApiVersionNo()
  @ApiOkResponse({ schema: zodToOpenApi(PolicyVersionDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiVersionNotFound()
  getVersion(
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Param('versionNo', policyVersionNoPipe) versionNo: number,
  ): Promise<PolicyVersionDetail> {
    return this.policies.getVersion(scope, policyId, versionNo);
  }

  @Put(':policyId/versions/:versionNo')
  @RequirePermissions(POLICY_MANAGE)
  @ApiOperation({
    summary: 'Replace a draft version',
    description:
      'Replaces the definition (and the change note when given) of a **draft** at ' +
      '`expectedRowVersion` (`409 policy_conflict`); a published version is immutable ' +
      '(`409 policy_version_immutable`). Audited as `policy.version_draft_updated`.',
  })
  @ApiPolicyId()
  @ApiVersionNo()
  @ApiBody({ schema: zodToOpenApi(PolicyVersionUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyVersionDetailSchema) })
  @ApiErrors(401, 403)
  @ApiDefinitionInvalid()
  @ApiVersionNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT, POLICY_VERSION_IMMUTABLE])
  @ApiInconsistentRead()
  updateDraft(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Param('versionNo', policyVersionNoPipe) versionNo: number,
    @Body(new ZodValidationPipe(PolicyVersionUpdateSchema)) body: PolicyVersionUpdate,
    @Client() client: ClientContext,
  ): Promise<PolicyVersionDetail> {
    return this.policies.updateDraft(principal, scope, policyId, versionNo, body, client);
  }

  @Delete(':policyId/versions/:versionNo')
  @RequirePermissions(POLICY_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a draft version',
    description:
      'Drafts only (`409 policy_version_immutable` otherwise), optionally only at ' +
      '`?expectedRowVersion=`. Audited as `policy.version_draft_deleted`.',
  })
  @ApiPolicyId()
  @ApiVersionNo()
  @ApiQueryFrom(ExpectedRowVersionQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiVersionNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT, POLICY_VERSION_IMMUTABLE])
  @ApiInconsistentRead()
  async deleteDraft(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Param('versionNo', policyVersionNoPipe) versionNo: number,
    @Query(new ZodValidationPipe(ExpectedRowVersionQuerySchema)) query: ExpectedRowVersionQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.policies.deleteDraft(
      principal,
      scope,
      policyId,
      versionNo,
      query.expectedRowVersion,
      client,
    );
  }

  @Post(':policyId/versions/:versionNo/publish')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Publish a draft version (and activate it)',
    description:
      'Re-validates the draft at `expectedRowVersion` (the DSL, and that every referenced ' +
      'department and user exists), stores its SHA-256, references, rule count, override flag, ' +
      'DSL version and who/when, and makes it **immutable**. With `activate` (default true) it ' +
      'also becomes the active version (status `active`; `409 policy_rule_limit_reached` when ' +
      'the organization’s active rules would exceed POLICY_MAX_ACTIVE_RULES; publish and ' +
      'activation commit together or not at all). Audited as `policy.version_published` (+ ' +
      '`policy.version_activated`, + `policy.override_rules_published` with the override rule ' +
      `ids). ${POLICY_APPLY_NOTE} ${POLICY_ENFORCEMENT_NOTE}`,
  })
  @ApiPolicyId()
  @ApiVersionNo()
  @ApiBody({ schema: zodToOpenApi(PolicyVersionPublishSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyChangeResultSchema) })
  @ApiErrors(401, 403)
  @ApiDefinitionInvalid()
  @ApiVersionNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT, POLICY_VERSION_IMMUTABLE, POLICY_RULE_LIMIT_REACHED])
  @ApiInconsistentRead()
  publish(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Param('versionNo', policyVersionNoPipe) versionNo: number,
    @Body(new ZodValidationPipe(PolicyVersionPublishSchema)) body: PolicyVersionPublish,
    @Client() client: ClientContext,
  ): Promise<PolicyChangeResult> {
    return this.policies.publish(principal, scope, policyId, versionNo, body, client);
  }

  @Post(':policyId/versions/:versionNo/activate')
  @RequirePermissions(POLICY_PUBLISH)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Activate a published version (rollback)',
    description:
      'Makes a **published** version the active one and the policy `active` ' +
      '(`409 policy_version_not_published` for a draft), optionally only at the policy ' +
      '`expectedRowVersion`; activating an earlier version is the rollback. Re-checks the DSL, ' +
      'the references and the active-rule bound. Activating the active version of an active ' +
      'policy changes nothing. Audited as `policy.version_activated` with the previous and new ' +
      `version. ${POLICY_APPLY_NOTE}`,
  })
  @ApiPolicyId()
  @ApiVersionNo()
  @ApiBody({ required: false, schema: zodToOpenApi(PolicyRowChangeDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyChangeResultSchema) })
  @ApiErrors(401, 403)
  @ApiDefinitionInvalid()
  @ApiVersionNotFound()
  @ApiPolicyConflict([POLICY_CONFLICT, POLICY_VERSION_NOT_PUBLISHED, POLICY_RULE_LIMIT_REACHED])
  @ApiInconsistentRead()
  activate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId', policyIdPipe) policyId: string,
    @Param('versionNo', policyVersionNoPipe) versionNo: number,
    @Body(new ZodValidationPipe(PolicyRowChangeSchema)) body: PolicyRowChange,
    @Client() client: ClientContext,
  ): Promise<PolicyChangeResult> {
    return this.policies.activate(principal, scope, policyId, versionNo, body, client);
  }
}
