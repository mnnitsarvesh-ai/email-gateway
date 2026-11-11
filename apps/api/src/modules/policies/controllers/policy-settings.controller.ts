import { Body, Controller, Get, Put } from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
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
import {
  ApiInconsistentRead,
  ApiPolicyConflict,
  ApiSettingsInvalid,
  POLICY_PUBLISH,
  POLICY_READ,
  PoliciesController,
} from '../api-docs';
import { POLICY_APPLY_NOTE } from '../domain/policy-definition';
import {
  type PolicySettingsUpdate,
  PolicySettingsUpdateDocSchema,
  PolicySettingsUpdateSchema,
  type PolicySettingsView,
  PolicySettingsViewSchema,
} from '../dto/policies.schemas';
import { POLICY_CONFLICT } from '../policies.errors';
import { PoliciesService } from '../services/policies.service';

/** The organization's policy settings (step 5.2 P11, P22). Translation only. */
@PoliciesController()
@Controller({ path: 'policy-settings', version: '1' })
export class PolicySettingsController {
  constructor(private readonly policies: PoliciesService) {}

  @Get()
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get the policy settings',
    description:
      'The stored settings document, the effective settings (defaults: overrides of the ' +
      'platform recommendation off, sender non-delivery notices on, alerts on, platform tag ' +
      'header on inbound/internal, off outbound), violations when the stored document is ' +
      'invalid (the defaults then apply), the generation and the row version. From the read ' +
      'replica.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(PolicySettingsViewSchema) })
  @ApiErrors(401, 403)
  get(@CurrentScope() scope: TenantScope): Promise<PolicySettingsView> {
    return this.policies.getSettings(scope);
  }

  @Put()
  @RequirePermissions(POLICY_PUBLISH)
  @ApiOperation({
    summary: 'Replace the policy settings',
    description:
      'Replaces the whole settings document at `expectedRowVersion` (`409 policy_conflict`; 0 ' +
      'before the first change). `allowRecommendationOverrides` lets a level-only ' +
      'recommendation be weakened by a rule with `override: true`; it never weakens the floor ' +
      '(hard blocks, failures, the DLP binding, missing data). An identical document changes ' +
      'nothing. Audited as `policy.settings_updated` (and `policy.settings_overrides_enabled` ' +
      `when overrides turn on). ${POLICY_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(PolicySettingsUpdateDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicySettingsViewSchema) })
  @ApiErrors(401, 403)
  @ApiSettingsInvalid()
  @ApiPolicyConflict([POLICY_CONFLICT])
  @ApiInconsistentRead()
  put(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(PolicySettingsUpdateSchema)) body: PolicySettingsUpdate,
    @Client() client: ClientContext,
  ): Promise<PolicySettingsView> {
    return this.policies.putSettings(principal, scope, body, client);
  }
}
