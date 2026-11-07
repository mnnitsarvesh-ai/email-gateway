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
  ApiDlpId,
  ApiInconsistentRead,
  ApiPolicyConflict,
  ApiPolicyNotFound,
  ApiReferenceInvalid,
  ApiRuleConflict,
  ApiRuleNotFound,
  DLP_APPLY_NOTE,
  DLP_MANAGE,
  DLP_READ,
  DlpController,
  dlpIdPipe,
} from '../api-docs';
import {
  type DlpDeleteQuery,
  DlpDeleteQuerySchema,
  type DlpListQuery,
  DlpListQuerySchema,
  type DlpPolicyCreate,
  DlpPolicyCreateSchema,
  type DlpPolicyDetail,
  DlpPolicyDetailSchema,
  type DlpPolicyPage,
  DlpPolicyPageSchema,
  type DlpPolicyUpdate,
  DlpPolicyUpdateSchema,
  type DlpRuleCreate,
  DlpRuleCreateDocSchema,
  DlpRuleCreateSchema,
  type DlpRuleUpdate,
  DlpRuleUpdateDocSchema,
  DlpRuleUpdateSchema,
  type DlpRuleView,
  DlpRuleViewSchema,
} from '../dto/dlp.schemas';
import { DlpPoliciesService } from '../services/dlp-policies.service';

/**
 * DLP policies and their rules (step 4.5 D11, D21) of the caller's organization. Translation
 * only; the logic is in DlpPoliciesService.
 */
@DlpController()
@Controller({ path: 'dlp/policies', version: '1' })
export class DlpPoliciesController {
  constructor(private readonly policies: DlpPoliciesService) {}

  @Get()
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'List the DLP policies',
    description:
      'Newest first, cursor-paginated, optionally only enabled or disabled policies, with the ' +
      'rule count. From the read replica.',
  })
  @ApiQueryFrom(DlpListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DlpPolicyPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DlpListQuerySchema)) query: DlpListQuery,
  ): Promise<DlpPolicyPage> {
    return this.policies.list(scope, query);
  }

  @Get(':id')
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'Get a DLP policy with its rules',
    description: 'Rules by priority, then creation. From the read replica.',
  })
  @ApiDlpId('id', 'Policy public id')
  @ApiOkResponse({ schema: zodToOpenApi(DlpPolicyDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiPolicyNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
  ): Promise<DlpPolicyDetail> {
    return this.policies.get(scope, id);
  }

  @Post()
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a DLP policy',
    description:
      'A named policy (unique per organization, `409 dlp_policy_exists`) with a mode ' +
      '(`enforce`, or `monitor`: matches recorded, the action never changed), a priority ' +
      '(ascending evaluation order) and directions. At most DLP_POLICIES_MAX_PER_TENANT ' +
      '(`409 dlp_limit_reached`). Without an enabled policy for a direction the platform default ' +
      'policy applies (`defaultPolicy` of the dlp scan settings). Audited as ' +
      `\`dlp_policy.created\`. ${DLP_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(DlpPolicyCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(DlpPolicyDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiPolicyConflict()
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(DlpPolicyCreateSchema)) body: DlpPolicyCreate,
    @Client() client: ClientContext,
  ): Promise<DlpPolicyDetail> {
    return this.policies.create(principal, scope, body, client);
  }

  @Patch(':id')
  @RequirePermissions(DLP_MANAGE)
  @ApiOperation({
    summary: 'Update a DLP policy',
    description:
      '`version` must be the current version (`409 version_conflict`). Narrowing `directions` ' +
      'is refused while a rule names a direction outside them (`400 dlp_directions_invalid`). ' +
      `Audited as \`dlp_policy.updated\` with the policy before and after. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Policy public id')
  @ApiBody({ schema: zodToOpenApi(DlpPolicyUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DlpPolicyDetailSchema) })
  @ApiErrors(401, 403)
  @ApiReferenceInvalid()
  @ApiPolicyNotFound()
  @ApiPolicyConflict()
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Body(new ZodValidationPipe(DlpPolicyUpdateSchema)) body: DlpPolicyUpdate,
    @Client() client: ClientContext,
  ): Promise<DlpPolicyDetail> {
    return this.policies.update(principal, scope, id, body, client);
  }

  @Delete(':id')
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a DLP policy and its rules',
    description:
      'Optionally only at `?version=`. Refused while exceptions target the policy or one of ' +
      'its rules (`409 dlp_policy_in_use`). Audited as `dlp_policy.deleted` with the policy ' +
      `and its rules as they were. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Policy public id')
  @ApiQueryFrom(DlpDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiPolicyNotFound()
  @ApiPolicyConflict()
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Query(new ZodValidationPipe(DlpDeleteQuerySchema)) query: DlpDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.policies.remove(principal, scope, id, query.version, client);
  }

  @Post(':id/rules')
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Add a rule to a DLP policy',
    description:
      'Conditions (`dlpRuleConditionsSchema`, strict) and an action. Directions must be within ' +
      'the policy’s (`400 dlp_directions_invalid`); selected custom pattern and dictionary ids ' +
      'must be the organization’s (`400 dlp_reference_invalid`). Unique name per policy (`409 ' +
      'dlp_rule_exists`), at most DLP_RULES_MAX_PER_POLICY (`409 dlp_limit_reached`). A rule ' +
      'selecting NI2 or `national_id` is accepted while Aadhaar detection is disabled but is ' +
      `inert for NI2. Audited as \`dlp_rule.created\`. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Policy public id')
  @ApiBody({ schema: zodToOpenApi(DlpRuleCreateDocSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(DlpRuleViewSchema) })
  @ApiErrors(401, 403)
  @ApiReferenceInvalid()
  @ApiPolicyNotFound()
  @ApiRuleConflict()
  @ApiInconsistentRead()
  createRule(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Body(new ZodValidationPipe(DlpRuleCreateSchema)) body: DlpRuleCreate,
    @Client() client: ClientContext,
  ): Promise<DlpRuleView> {
    return this.policies.createRule(principal, scope, id, body, client);
  }

  @Patch(':id/rules/:ruleId')
  @RequirePermissions(DLP_MANAGE)
  @ApiOperation({
    summary: 'Update a DLP rule',
    description:
      '`version` must be the current version (`409 version_conflict`); conditions are ' +
      're-validated as on create. Audited as `dlp_rule.updated` with the rule before and ' +
      `after. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Policy public id')
  @ApiDlpId('ruleId', 'Rule public id')
  @ApiBody({ schema: zodToOpenApi(DlpRuleUpdateDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DlpRuleViewSchema) })
  @ApiErrors(401, 403)
  @ApiReferenceInvalid()
  @ApiRuleNotFound()
  @ApiRuleConflict()
  @ApiInconsistentRead()
  updateRule(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Param('ruleId', dlpIdPipe) ruleId: string,
    @Body(new ZodValidationPipe(DlpRuleUpdateSchema)) body: DlpRuleUpdate,
    @Client() client: ClientContext,
  ): Promise<DlpRuleView> {
    return this.policies.updateRule(principal, scope, id, ruleId, body, client);
  }

  @Delete(':id/rules/:ruleId')
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a DLP rule',
    description:
      'Optionally only at `?version=`. Refused while exceptions target the rule (`409 ' +
      `dlp_rule_in_use\`). Audited as \`dlp_rule.deleted\`. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Policy public id')
  @ApiDlpId('ruleId', 'Rule public id')
  @ApiQueryFrom(DlpDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiRuleNotFound()
  @ApiRuleConflict()
  @ApiInconsistentRead()
  async removeRule(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Param('ruleId', dlpIdPipe) ruleId: string,
    @Query(new ZodValidationPipe(DlpDeleteQuerySchema)) query: DlpDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.policies.removeRule(principal, scope, id, ruleId, query.version, client);
  }
}
