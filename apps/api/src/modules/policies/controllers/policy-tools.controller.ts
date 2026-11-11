import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query } from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiTestFactsInvalid,
  ApiVersionNotFound,
  POLICY_MANAGE,
  POLICY_READ,
  PoliciesController,
} from '../api-docs';
import { POLICY_APPLY_NOTE, POLICY_ENFORCEMENT_NOTE } from '../domain/policy-definition';
import {
  type PolicyCatalog,
  PolicyCatalogSchema,
  type PolicyExecutionPage,
  PolicyExecutionPageSchema,
  type PolicyExecutionQuery,
  PolicyExecutionQueryDocSchema,
  PolicyExecutionQuerySchema,
  type PolicyTest,
  type PolicyTestResponse,
  PolicyTestResponseSchema,
  PolicyTestSchema,
} from '../dto/policies.schemas';
import { PoliciesService } from '../services/policies.service';
import { PolicyEvaluationService } from '../services/policy-evaluation.service';
import { PolicyHistoryService } from '../services/policy-history.service';

/**
 * The static `/policies/*` routes (step 5.2 P22): catalog, test and execution history. Declared
 * in a controller registered before PolicyManagementController so `/policies/{policyId}` never
 * shadows them. Translation only.
 */
@PoliciesController()
@Controller({ path: 'policies', version: '1' })
export class PolicyToolsController {
  constructor(
    private readonly policies: PoliciesService,
    private readonly evaluation: PolicyEvaluationService,
    private readonly historyService: PolicyHistoryService,
  ) {}

  @Get('catalog')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get the policy DSL catalog',
    description:
      'The DSL, input and evaluator versions, every field with its type, scope, operators, ' +
      'identity and AI flags and vocabulary, the operators, the nine actions, the dispositions ' +
      '(weakest first), the limits (P4 with this deployment’s organization bounds applied), the ' +
      'settings defaults and the platform default. Library data; no database access. ' +
      POLICY_ENFORCEMENT_NOTE,
  })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyCatalogSchema) })
  @ApiErrors(401, 403)
  catalog(): PolicyCatalog {
    return this.policies.catalog();
  }

  @Post('test')
  @RequirePermissions(POLICY_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Test policies against synthetic facts',
    description:
      'Evaluates synthetic facts (every field optional with documented defaults; ' +
      '`evaluationTime` defaults to the request time) against `target` with the same ' +
      'evaluator the policy-engine runs (floor and platform default included) and returns the ' +
      'full result: disposition, decisive rule, actions with applicability, delivery header ' +
      'edits, trace, floor, recommendation, override and clamps, explanation and hashes. The ' +
      'synthetic risk facts are trusted for the test only. Active policies and versions are ' +
      'read from the read replica. **Writes nothing**: no evaluation row, no audit row, no ' +
      `event. ${POLICY_ENFORCEMENT_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(PolicyTestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyTestResponseSchema) })
  @ApiErrors(401, 403)
  @ApiTestFactsInvalid()
  @ApiVersionNotFound()
  test(
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(PolicyTestSchema)) body: PolicyTest,
  ): Promise<PolicyTestResponse> {
    return this.evaluation.test(scope, body);
  }

  @Get('executions')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'List policy executions (history)',
    description:
      'Stored evaluations of the organization’s messages with `receivedAt` in [`from`, `to`) ' +
      '(both required; at most POLICY_HISTORY_MAX_RANGE_DAYS apart), newest first, filtered by ' +
      'direction, disposition, decision source, decisive policy and rule, override and trigger; ' +
      'cursor-paginated by `(receivedAt, id)`. Each row: message public id, round, trigger, ' +
      'direction, disposition, final action, decisive source/policy/version/rule, action types ' +
      'with their statuses (`enforced`, `requested`, `recorded`, `not_applicable`), matched rule ' +
      'count, override, generation, input hash, duration and time. Never addresses or content. ' +
      `From the read replica. ${POLICY_APPLY_NOTE}`,
  })
  @ApiQueryFrom(PolicyExecutionQueryDocSchema)
  @ApiOkResponse({ schema: zodToOpenApi(PolicyExecutionPageSchema) })
  @ApiErrors(400, 401, 403)
  history(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(PolicyExecutionQuerySchema)) query: PolicyExecutionQuery,
  ): Promise<PolicyExecutionPage> {
    return this.historyService.history(scope, query);
  }
}
