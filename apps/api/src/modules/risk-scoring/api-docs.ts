import { applyDecorators, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiParam, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { MESSAGE_NOT_FOUND } from '../messages/messages.errors';
import { RiskScanIdSchema, RiskVersionIdSchema } from './dto/risk-scoring.schemas';
import {
  INCONSISTENT_READ,
  RISK_PROFILE_INVALID,
  RISK_PROFILE_LIMIT_REACHED,
  RISK_PROFILE_VERSION_CONFLICT,
  RISK_PROFILE_VERSION_IMMUTABLE,
  RISK_PROFILE_VERSION_NOT_FOUND,
  RISK_PROFILE_VERSION_NOT_PUBLISHED,
  RISK_REVISION_UNAVAILABLE,
  RISK_SCAN_NOT_FOUND,
  SCAN_ROUND_NOT_COMPLETE,
} from './risk-scoring.errors';

/** Permissions of the risk scoring routes (existing seed catalog, step 5.1 §7: no new keys). */
export const POLICY_READ = 'policy:read';
export const POLICY_MANAGE = 'policy:manage';
export const POLICY_PUBLISH = 'policy:publish';
export const MESSAGE_READ = 'message:read';

/** The disclaimer every risk scoring route description carries (§2.0-3, §8). */
export const RISK_DOC_NOTE =
  'Step 5.1 **recommends and does not enforce**: policy (5.2) decides and quarantine (5.3) ' +
  'acts (only the local/CI development pass-through holds on a recommendation). The default ' +
  'weights and thresholds are engineering defaults calibrated on a synthetic dataset; **they ' +
  'are not validated detection accuracy**.';

/** How a profile change takes effect (R10, R13). */
export const RISK_APPLY_NOTE =
  'A profile change applies to the **next scan round only**: each round snapshots the active ' +
  'version when it opens, so open rounds and stored scores never change.';

/** Shared class decorators of the risk scoring controllers: tag, security schemes, coded errors. */
export const RiskController = (): ClassDecorator =>
  applyDecorators(
    ApiTags('risk-scoring'),
    ApiBearerAuth(ACCESS_TOKEN_SCHEME),
    ApiSecurity(API_KEY_SCHEME),
    UseFilters(CodedExceptionFilter),
  );

export const riskVersionIdPipe = new ZodValidationPipe(RiskVersionIdSchema);
export const riskScanIdPipe = new ZodValidationPipe(RiskScanIdSchema);

export const ApiRiskVersionId = (): MethodDecorator =>
  ApiParam({ name: 'versionId', format: 'uuid', description: 'Risk profile version public id' });

export const ApiRiskScanId = (): MethodDecorator =>
  ApiParam({
    name: 'scanId',
    description: 'Decimal scan id (`scanId` of the round in `GET /messages/{messageId}/scans`)',
  });

const VIOLATIONS = {
  violations: {
    type: 'array',
    items: {
      type: 'object',
      properties: { path: { type: 'string' }, message: { type: 'string' } },
      required: ['path', 'message'] as string[],
    },
  },
} as const;

/** 400: the standard validation body, or `risk_profile_invalid` with violations by path. */
export const ApiRiskProfileInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), or `risk_profile_invalid`: the overrides break the ' +
      'strict key set or an R10 bound (thresholds out of range or too close, an action not ' +
      'allowed for its level or weaker than the level below, a multiplier out of [500, 2000] ' +
      'or of a locked group, a locked hard block switched off or its action changed, a failure ' +
      'or floor setting below the platform default, a trust factor out of [250, 1000], an ' +
      'unknown key, or a retired base profile); `violations` lists every problem by path ' +
      '(never values)',
    [RISK_PROFILE_INVALID],
    VIOLATIONS,
  );

export const ApiRiskVersionNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown version, or a version of another organization', [
    RISK_PROFILE_VERSION_NOT_FOUND,
  ]);

const CONFLICT_DETAILS = {
  limit: { type: 'integer', minimum: 1 },
  currentRowVersion: { type: 'integer', minimum: 1 },
  currentProfileVersion: { type: 'integer', minimum: 0 },
} as const;

/** 409 of the version routes (one schema per status: every code of the route). */
export const ApiRiskConflict = (
  codes: ReadonlyArray<
    | typeof RISK_PROFILE_LIMIT_REACHED
    | typeof RISK_PROFILE_VERSION_CONFLICT
    | typeof RISK_PROFILE_VERSION_IMMUTABLE
    | typeof RISK_PROFILE_VERSION_NOT_PUBLISHED
  >,
): MethodDecorator => {
  const text: Record<string, string> = {
    [RISK_PROFILE_LIMIT_REACHED]:
      '`risk_profile_limit_reached`: RISK_PROFILE_MAX_VERSIONS versions exist (`limit`)',
    [RISK_PROFILE_VERSION_CONFLICT]:
      '`risk_profile_version_conflict`: `expectedRowVersion` / `expectedProfileVersion` is not ' +
      'current (`currentRowVersion` / `currentProfileVersion`)',
    [RISK_PROFILE_VERSION_IMMUTABLE]:
      '`risk_profile_version_immutable`: the version is published (published versions never ' +
      'change and are never deleted)',
    [RISK_PROFILE_VERSION_NOT_PUBLISHED]:
      '`risk_profile_version_not_published`: only a published version can be activated',
  };
  return ApiCodedError(409, codes.map((c) => text[c]).join('; '), [...codes], CONFLICT_DETAILS);
};

export const ApiInconsistentRead = (): MethodDecorator =>
  ApiCodedError(503, 'The database returned an inconsistent read twice; retry the request', [
    INCONSISTENT_READ,
  ]);

/** Every error of the dry-run besides 401/403. */
export const ApiDryRunErrors = (): MethodDecorator =>
  applyDecorators(
    ApiRiskProfileInvalid(),
    ApiCodedError(
      404,
      'Unknown message or scan, a message or scan of another organization, or (`{ versionId }`) ' +
        'a version that is not the organization’s',
      [MESSAGE_NOT_FOUND, RISK_SCAN_NOT_FOUND, RISK_PROFILE_VERSION_NOT_FOUND],
    ),
    ApiCodedError(
      409,
      '`scan_round_not_complete`: the round is pending or running on the read replica (or not ' +
        'replicated yet; `status`); `risk_revision_unavailable`: revision 1 needs a non-skipped ' +
        'sandbox result for the round',
      [SCAN_ROUND_NOT_COMPLETE, RISK_REVISION_UNAVAILABLE],
      { status: { type: 'string' } },
    ),
  );
