import { Body, Controller, Get, HttpCode, HttpStatus, Param, Post } from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { CurrentScope, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { ApiMessageNotFound } from '../../messages/api-docs';
import {
  ApiDryRunErrors,
  ApiPolicyScanId,
  MESSAGE_READ,
  POLICY_MANAGE,
  PoliciesController,
  policyScanIdPipe,
} from '../api-docs';
import { POLICY_ENFORCEMENT_NOTE } from '../domain/policy-definition';
import {
  type MessagePolicyEvaluations,
  MessagePolicyEvaluationsSchema,
  type PolicyDryRun,
  type PolicyDryRunResponse,
  PolicyDryRunResponseSchema,
  PolicyDryRunSchema,
} from '../dto/policies.schemas';
import { PolicyEvaluationService } from '../services/policy-evaluation.service';
import { PolicyHistoryService } from '../services/policy-history.service';

/**
 * The policy routes under a message (step 5.2 P16, P22): the stored evaluations and the dry-run
 * of a stored round. Translation only.
 */
@PoliciesController()
@Controller({ path: 'messages', version: '1' })
export class PolicyMessagesController {
  constructor(
    private readonly evaluation: PolicyEvaluationService,
    private readonly historyService: PolicyHistoryService,
  ) {}

  @Get(':messageId/policy-evaluations')
  @RequirePermissions(MESSAGE_READ)
  @ApiOperation({
    summary: 'List the policy evaluations of a message',
    description:
      'Every stored policy evaluation of a message of the organization, newest round first ' +
      '(a parse-failure evaluation has no scan): disposition, final verdict and action, ' +
      'decisive source/policy/rule, actions with applicability and the status the engine ' +
      'achieved (`enforced`, `requested`, `recorded`, `not_applicable`), delivery header ' +
      'edits, trace, floor, recommendation, override and clamps, explanation, delivered ' +
      'object, versions, generation and hashes. Never addresses or message content. From the ' +
      `read replica. ${POLICY_ENFORCEMENT_NOTE}`,
  })
  @ApiMessageId()
  @ApiOkResponse({ schema: zodToOpenApi(MessagePolicyEvaluationsSchema) })
  @ApiErrors(400, 401, 403)
  @ApiMessageNotFound()
  evaluations(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
  ): Promise<MessagePolicyEvaluations> {
    return this.historyService.forMessage(scope, messageId);
  }

  @Post(':messageId/scans/:scanId/policy/dry-run')
  @RateClass('expensive')
  @RequirePermissions(POLICY_MANAGE, MESSAGE_READ)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Dry-run the policy evaluation of a stored scan round',
    description:
      'Reads a finished round of a message of the organization from the read replica (the ' +
      'same rows the policy-engine evaluates: message and recipients, the round’s finals, ' +
      'authentication, BEC, DLP, risk revisions, attachments, URLs and the rewrite, and the ' +
      'directory memberships of its addresses), evaluates it against `target` and returns the ' +
      'result next to the stored evaluation of the round (`stored`). `reproducible` is true ' +
      'with `target: active` when the stored input and snapshot hashes equal the recomputed ' +
      'ones (a later policy, settings or directory change, or a late sandbox revision, makes ' +
      'it false). **Writes nothing**: no evaluation row, no audit row, no event. A round still ' +
      'pending or running (or not replicated yet) is `409 scan_round_not_complete`. Requires ' +
      `\`policy:manage\` and \`message:read\`. ${POLICY_ENFORCEMENT_NOTE}`,
  })
  @ApiMessageId()
  @ApiPolicyScanId()
  @ApiBody({ schema: zodToOpenApi(PolicyDryRunSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyDryRunResponseSchema) })
  @ApiErrors(401, 403)
  @ApiDryRunErrors()
  dryRun(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Param('scanId', policyScanIdPipe) scanId: string,
    @Body(new ZodValidationPipe(PolicyDryRunSchema)) body: PolicyDryRun,
  ): Promise<PolicyDryRunResponse> {
    return this.evaluation.dryRun(scope, messageId, BigInt(scanId), body);
  }
}
