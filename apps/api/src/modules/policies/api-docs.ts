import { applyDecorators, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiParam, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { MESSAGE_NOT_FOUND } from '../messages/messages.errors';
import { PolicyIdSchema, PolicyScanIdSchema, PolicyVersionNoSchema } from './dto/policies.schemas';
import {
  INCONSISTENT_READ,
  POLICY_CONFLICT,
  POLICY_DEFINITION_INVALID,
  POLICY_INPUT_INVALID,
  POLICY_LIMIT_REACHED,
  POLICY_NAME_TAKEN,
  POLICY_NO_ACTIVE_VERSION,
  POLICY_NOT_FOUND,
  POLICY_RULE_LIMIT_REACHED,
  POLICY_SCAN_NOT_FOUND,
  POLICY_SETTINGS_INVALID,
  POLICY_TEST_FACTS_INVALID,
  POLICY_VERSION_IMMUTABLE,
  POLICY_VERSION_LIMIT_REACHED,
  POLICY_VERSION_NOT_FOUND,
  POLICY_VERSION_NOT_PUBLISHED,
  SCAN_ROUND_NOT_COMPLETE,
} from './policies.errors';

/** Permissions of the policy routes (existing seed catalog: no new keys). */
export const POLICY_READ = 'policy:read';
export const POLICY_MANAGE = 'policy:manage';
export const POLICY_PUBLISH = 'policy:publish';
export const MESSAGE_READ = 'message:read';

/** Shared class decorators of the policy controllers: tag, security schemes, coded errors. */
export const PoliciesController = (): ClassDecorator =>
  applyDecorators(
    ApiTags('policies'),
    ApiBearerAuth(ACCESS_TOKEN_SCHEME),
    ApiSecurity(API_KEY_SCHEME),
    UseFilters(CodedExceptionFilter),
  );

export const policyIdPipe = new ZodValidationPipe(PolicyIdSchema);
export const policyVersionNoPipe = new ZodValidationPipe(PolicyVersionNoSchema);
export const policyScanIdPipe = new ZodValidationPipe(PolicyScanIdSchema);

export const ApiPolicyId = (): MethodDecorator =>
  ApiParam({ name: 'policyId', format: 'uuid', description: 'Policy public id' });

export const ApiVersionNo = (): MethodDecorator =>
  ApiParam({ name: 'versionNo', type: 'integer', description: 'Version number of the policy' });

export const ApiPolicyScanId = (): MethodDecorator =>
  ApiParam({
    name: 'scanId',
    description: 'Decimal scan id (`scanId` of the round in `GET /messages/{messageId}/scans`)',
  });

const VIOLATIONS = {
  violations: {
    type: 'array',
    items: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        code: { type: 'string' },
        message: { type: 'string' },
      },
      required: ['path', 'code', 'message'] as string[],
    },
  },
} as const;

/** 400: the standard validation body, or `policy_definition_invalid` with violations by path. */
export const ApiDefinitionInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), or `policy_definition_invalid`: the definition breaks ' +
      'the `policy-dsl/1` schema (unknown keys, fields, operators or actions, a value of the ' +
      'wrong type, a limit, an exception that is not positive or uses raw sender identity, a ' +
      'relaxing rule matching on spoofable identity, an AI-derived field in a hold rule, ' +
      'header-unsafe text, an invalid RE2 pattern, CIDR or time zone), or (publish and ' +
      'activation) names a department or user that is not the organization’s ' +
      '(`department_unknown`, `user_unknown`); `violations` lists every problem by path',
    [POLICY_DEFINITION_INVALID],
    VIOLATIONS,
  );

export const ApiSettingsInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), or `policy_settings_invalid`: unknown key or a value ' +
      'that is not a boolean; `violations` by path',
    [POLICY_SETTINGS_INVALID],
    VIOLATIONS,
  );

export const ApiPolicyNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown or archived policy, or a policy of another organization', [
    POLICY_NOT_FOUND,
  ]);

export const ApiVersionNotFound = (): MethodDecorator =>
  ApiCodedError(
    404,
    'Unknown, archived or another organization’s policy, or an unknown version number',
    [POLICY_NOT_FOUND, POLICY_VERSION_NOT_FOUND],
  );

const CONFLICT_TEXT: Record<string, string> = {
  [POLICY_NAME_TAKEN]: '`policy_name_taken`: the name exists in the organization (archived too)',
  [POLICY_LIMIT_REACHED]: '`policy_limit_reached`: POLICY_MAX_POLICIES policies exist (`limit`)',
  [POLICY_CONFLICT]: '`policy_conflict`: `expectedRowVersion` is not current (`currentRowVersion`)',
  [POLICY_VERSION_LIMIT_REACHED]:
    '`policy_version_limit_reached`: POLICY_MAX_VERSIONS_PER_POLICY versions exist (`limit`)',
  [POLICY_VERSION_IMMUTABLE]:
    '`policy_version_immutable`: the version is published (never changed or deleted)',
  [POLICY_VERSION_NOT_PUBLISHED]:
    '`policy_version_not_published`: only a published version can be activated',
  [POLICY_NO_ACTIVE_VERSION]: '`policy_no_active_version`: publish and activate a version first',
  [POLICY_RULE_LIMIT_REACHED]:
    '`policy_rule_limit_reached`: the active versions would hold more than ' +
    'POLICY_MAX_ACTIVE_RULES rules (`limit`, `requested`)',
};

const CONFLICT_DETAILS = {
  limit: { type: 'integer', minimum: 1 },
  requested: { type: 'integer', minimum: 1 },
  currentRowVersion: { type: 'integer', minimum: 0 },
} as const;

export const ApiPolicyConflict = (codes: readonly string[]): MethodDecorator =>
  ApiCodedError(409, codes.map((c) => CONFLICT_TEXT[c]).join('; '), [...codes], CONFLICT_DETAILS);

export const ApiInconsistentRead = (): MethodDecorator =>
  ApiCodedError(503, 'The database returned an inconsistent read twice; retry the request', [
    INCONSISTENT_READ,
  ]);

export const ApiTestFactsInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), `policy_definition_invalid` (an inline definition, ' +
      'with violations), or `policy_test_facts_invalid` (the facts do not form an input)',
    [POLICY_DEFINITION_INVALID, POLICY_TEST_FACTS_INVALID],
    VIOLATIONS,
  );

/** Every error of the dry-run besides 401/403. */
export const ApiDryRunErrors = (): MethodDecorator =>
  applyDecorators(
    ApiCodedError(
      400,
      'Validation failed (standard body), or `policy_definition_invalid` for an inline target',
      [POLICY_DEFINITION_INVALID],
      VIOLATIONS,
    ),
    ApiCodedError(
      404,
      'Unknown message or scan, one of another organization, or (`{ policyId, versionNo }`) a ' +
        'version that is not the organization’s',
      [MESSAGE_NOT_FOUND, POLICY_SCAN_NOT_FOUND, POLICY_VERSION_NOT_FOUND],
    ),
    ApiCodedError(
      409,
      '`scan_round_not_complete`: the round is pending or running on the read replica (or not ' +
        'replicated yet; `status`); `policy_input_invalid`: the stored rows of the round do not ' +
        'form a policy input (a defect; the policy-engine dead-letters such a round)',
      [SCAN_ROUND_NOT_COMPLETE, POLICY_INPUT_INVALID],
      { status: { type: 'string' } },
    ),
  );
