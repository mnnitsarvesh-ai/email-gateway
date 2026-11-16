import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query } from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { CurrentScope, CursorList, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiPolicyBodyTooLarge,
  ApiSampleDryRunErrors,
  BODY_LIMIT_NOTE,
  ApiTestFactsInvalid,
  ApiValidateBadRequest,
  ApiVersionNotFound,
  MESSAGE_READ,
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
  type PolicySampleDryRun,
  type PolicySampleDryRunResponse,
  PolicySampleDryRunResponseSchema,
  PolicySampleDryRunSchema,
  type PolicyTest,
  type PolicyTestResponse,
  PolicyTestResponseSchema,
  PolicyTestSchema,
  type PolicyValidate,
  type PolicyValidateResponse,
  PolicyValidateResponseSchema,
  PolicyValidateSchema,
} from '../dto/policies.schemas';
import { POLICY_BUILDER_EXAMPLES } from '../dto/policy-builder.examples';
import { PolicySampleDryRunRateLimit } from '../policy-sample-dry-run-rate-limit';
import { PoliciesService } from '../services/policies.service';
import { PolicyEvaluationService } from '../services/policy-evaluation.service';
import { PolicyHistoryService } from '../services/policy-history.service';
import { PolicySampleDryRunService } from '../services/policy-sample-dry-run.service';
import { PolicyValidationService } from '../services/policy-validation.service';

/**
 * The static `/policies/*` routes (step 5.2 P22): catalog, test and execution history, and (step
 * 7.3 §4.2, §4.3) validation without saving and the sample dry-run. Declared in a controller
 * registered before PolicyManagementController so `/policies/{policyId}` never shadows them.
 * Translation only.
 */
@PoliciesController()
@Controller({ path: 'policies', version: '1' })
export class PolicyToolsController {
  constructor(
    private readonly policies: PoliciesService,
    private readonly evaluation: PolicyEvaluationService,
    private readonly historyService: PolicyHistoryService,
    private readonly validation: PolicyValidationService,
    private readonly sample: PolicySampleDryRunService,
  ) {}

  @Get('catalog')
  @RequirePermissions(POLICY_READ)
  @ApiOperation({
    summary: 'Get the policy DSL catalog',
    description:
      'The DSL, input and evaluator versions, every field with its type, scope, operators, ' +
      'identity and AI flags and vocabulary, the operators, the nine actions, the dispositions ' +
      '(weakest first), the limits (P4 with this deployment’s organization bounds applied, plus ' +
      '`dryRunSampleMax` and `dryRunSamplesPerMinute`), the settings defaults and the platform ' +
      'default. Step 7.3 (ADR-0063) adds the presentation metadata a visual builder renders from: ' +
      'per field a `label`, `group`, `unit`, code `suggestions` and the `contexts` it may be used ' +
      'in; `fieldGroups`, `operatorDefinitions` (label, summary phrase, value shape, item kind and ' +
      'limits, negation), `actionDefinitions` (label, kind, disposition and parameter ' +
      'definitions), `quantifiers`, `scopeNouns`, `contextRules`, `weekdays`, `timeZones` (of the ' +
      'api runtime), `policyDirections` and `messageDirections`. Library data; no database ' +
      'access. ' +
      POLICY_ENFORCEMENT_NOTE,
  })
  @ApiOkResponse({ schema: zodToOpenApi(PolicyCatalogSchema) })
  @ApiErrors(401, 403)
  catalog(): PolicyCatalog {
    return this.policies.catalog();
  }

  @Post('test')
  @ApiPolicyBodyTooLarge()
  @RateClass('expensive')
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

  @Post('validate')
  @ApiPolicyBodyTooLarge()
  @RequirePermissions(POLICY_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Validate a policy definition without saving it',
    description:
      'Checks a `policy-dsl/1` document exactly as a draft save does (every violation with a ' +
      'stable code and a JSON path such as `rules[2].when.all[0].value`, at most 100, sorted by ' +
      'path; regular expressions, globs, CIDRs and time zones are validated here, never in a ' +
      'client) and, for a valid document, the departments and users it references against the ' +
      'read replica (`referenceViolations`: `department_unknown`, `user_unknown`; they do not ' +
      'make it invalid because drafts may name a department created later, but publish, ' +
      'activation and enable refuse them). An invalid document is a result (`200`, `valid: ' +
      'false`), not an error. **Writes nothing**: no row, no audit row, no event, no ' +
      'idempotency record (no Idempotency-Key). Requires `policy:manage`; the organization comes ' +
      `from the credentials. ${BODY_LIMIT_NOTE}`,
  })
  @ApiBody({
    schema: zodToOpenApi(PolicyValidateSchema, { io: 'input' }),
    examples: {
      confidentialOutbound: { value: POLICY_BUILDER_EXAMPLES.validateBody },
      invalidRegex: { value: POLICY_BUILDER_EXAMPLES.validateInvalidBody },
    },
  })
  @ApiOkResponse({
    description: 'The validation result (also for an invalid definition)',
    schema: {
      ...zodToOpenApi(PolicyValidateResponseSchema),
      example: POLICY_BUILDER_EXAMPLES.validated,
    },
  })
  @ApiValidateBadRequest()
  @ApiErrors(401, 403)
  validate(
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(PolicyValidateSchema)) body: PolicyValidate,
  ): Promise<PolicyValidateResponse> {
    return this.validation.validate(scope, body);
  }

  @Post('dry-run')
  @ApiPolicyBodyTooLarge()
  @RateClass('expensive')
  @RequirePermissions(POLICY_MANAGE, MESSAGE_READ)
  @PolicySampleDryRunRateLimit()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Dry-run policies against recent stored evaluations',
    description:
      'Re-evaluates the newest stored evaluation of each message of your organization (rounds ' +
      'with a scan) whose `receivedAt` is in [`sample.from`, `sample.to`) (default: the last 7 ' +
      'days; at most POLICY_HISTORY_MAX_RANGE_DAYS), optionally of one `direction`, newest ' +
      'first, against `target` (`active`, `platform`, `{ policyId, versionNo }` or an inline `{ ' +
      'definition }`, as `POST /policies/test`). The target snapshot is compiled once; each ' +
      'round’s facts are read from the read replica exactly as `POST /messages/{messageId}/' +
      'scans/{scanId}/policy/dry-run` reads them, one round after the other. Bounds: ' +
      '`sample.limit` 1..POLICY_DRY_RUN_SAMPLE_MAX (default 25; above → `400`), at most ' +
      '`limit × 4` stored rows read, and POLICY_DRY_RUN_DEADLINE_MS (on expiry the evaluated ' +
      'prefix is returned with `truncated: true`). Each item compares the stored and the ' +
      'recomputed message-level disposition and decisive rule (`dispositionChanged`, ' +
      '`decisiveChanged`); the summary counts them and the transitions. Items carry message ' +
      'public ids, times, enums, rule ids and counts only, never subjects, addresses or ' +
      'content. **Writes nothing**: no evaluation row, no audit row, no event, no idempotency ' +
      'record. Requires `policy:manage` and `message:read`; class `expensive` plus ' +
      'POLICY_SAMPLE_DRY_RUNS_PER_MINUTE per user or API key (`429 rate_limited`, `scope: ' +
      `route\`). ${BODY_LIMIT_NOTE} ${POLICY_ENFORCEMENT_NOTE}`,
  })
  @ApiBody({
    schema: zodToOpenApi(PolicySampleDryRunSchema, { io: 'input' }),
    examples: {
      activeLastWeek: { value: POLICY_BUILDER_EXAMPLES.sampleBody },
      draftVersionOutbound: { value: POLICY_BUILDER_EXAMPLES.sampleVersionBody },
    },
  })
  @ApiOkResponse({
    description: 'Stored versus recomputed decisions of the sampled rounds',
    schema: {
      ...zodToOpenApi(PolicySampleDryRunResponseSchema),
      example: POLICY_BUILDER_EXAMPLES.sample,
    },
  })
  @ApiErrors(401, 403)
  @ApiSampleDryRunErrors()
  sampleDryRun(
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(PolicySampleDryRunSchema)) body: PolicySampleDryRun,
  ): Promise<PolicySampleDryRunResponse> {
    return this.sample.sampleDryRun(scope, body);
  }

  @Get('executions')
  @CursorList('v0')
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
