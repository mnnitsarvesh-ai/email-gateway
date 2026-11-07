import { applyDecorators, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiParam, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { MESSAGE_NOT_FOUND } from '../messages/messages.errors';
import {
  DLP_DICTIONARY_CODES,
  DLP_DICTIONARY_EXISTS,
  DLP_DICTIONARY_IN_USE,
  DLP_DICTIONARY_NOT_FOUND,
  DLP_DIRECTIONS_INVALID,
  DLP_EVIDENCE_NOT_FOUND,
  DLP_EXCEPTION_EXISTS,
  DLP_EXCEPTION_NOT_FOUND,
  DLP_LIMIT_REACHED,
  DLP_PATTERN_CODES,
  DLP_PATTERN_EXISTS,
  DLP_PATTERN_IN_USE,
  DLP_PATTERN_NOT_FOUND,
  DLP_POLICY_EXISTS,
  DLP_POLICY_IN_USE,
  DLP_POLICY_NOT_FOUND,
  DLP_REFERENCE_INVALID,
  DLP_RULE_EXISTS,
  DLP_RULE_IN_USE,
  DLP_RULE_NOT_FOUND,
  DLP_SCAN_NOT_FOUND,
  DLP_VERSION_CONFLICT,
  EVIDENCE_EXPIRED,
  EVIDENCE_PURGED,
  EVIDENCE_UNAVAILABLE,
  EVIDENCE_UNREADABLE,
  INCONSISTENT_READ,
} from './dlp.errors';
import { DlpIdSchema, DlpScanIdSchema } from './dto/dlp.schemas';

/** Permissions of the DLP routes (seed catalog, step 4.5 D21). */
export const DLP_READ = 'dlp:read';
export const DLP_MANAGE = 'dlp:manage';
export const DLP_EVIDENCE_READ = 'dlp:evidence_read';
export const DLP_COMPLIANCE_MANAGE = 'dlp:compliance_manage';

/** How quickly the engine sees a change (D3 tenant data cache). */
export const DLP_APPLY_NOTE =
  'The DLP engine caches the organization’s policies, rules, exceptions, custom patterns, ' +
  'dictionaries and compliance setting for up to DLP_TENANT_DATA_CACHE_TTL_MS (default 30 ' +
  'seconds): a change applies to messages scanned after that; finished rounds keep their result.';

/** Shared class decorators of the DLP controllers: tag, security schemes, coded errors. */
export const DlpController = (): ClassDecorator =>
  applyDecorators(
    ApiTags('dlp'),
    ApiBearerAuth(ACCESS_TOKEN_SCHEME),
    ApiSecurity(API_KEY_SCHEME),
    UseFilters(CodedExceptionFilter),
  );

export const dlpIdPipe = new ZodValidationPipe(DlpIdSchema);
export const dlpScanIdPipe = new ZodValidationPipe(DlpScanIdSchema);

export const ApiDlpId = (name: string, description: string): MethodDecorator =>
  ApiParam({ name, format: 'uuid', description });

export const ApiDlpScanId = (): MethodDecorator =>
  ApiParam({
    name: 'scanId',
    description: 'Decimal scan id (`scanId` of the round in `GET /messages/{messageId}/scans`)',
  });

const notFound = (codes: string[], what: string): MethodDecorator =>
  ApiCodedError(404, `${what} not found (also for another organization’s id)`, codes);

export const ApiPolicyNotFound = (): MethodDecorator =>
  notFound([DLP_POLICY_NOT_FOUND], 'DLP policy');
export const ApiRuleNotFound = (): MethodDecorator =>
  notFound([DLP_POLICY_NOT_FOUND, DLP_RULE_NOT_FOUND], 'DLP policy or rule');
export const ApiExceptionNotFound = (): MethodDecorator =>
  notFound([DLP_EXCEPTION_NOT_FOUND], 'DLP exception');
export const ApiPatternNotFound = (): MethodDecorator =>
  notFound([DLP_PATTERN_NOT_FOUND], 'Custom pattern');
export const ApiDictionaryNotFound = (): MethodDecorator =>
  notFound([DLP_DICTIONARY_NOT_FOUND], 'Keyword dictionary');
export const ApiEvidenceNotFound = (): MethodDecorator =>
  notFound(
    [MESSAGE_NOT_FOUND, DLP_SCAN_NOT_FOUND, DLP_EVIDENCE_NOT_FOUND],
    'Message, scan or evidence',
  );

const CONFLICT_DETAILS = {
  id: { type: 'string', format: 'uuid' },
  currentVersion: { type: 'integer', minimum: 0 },
  resource: { type: 'string' },
  limit: { type: 'integer', minimum: 1 },
  references: { type: 'integer', minimum: 1 },
} as const;

/** 409: the unique key is taken, the version moved, the cap is reached, or it is in use. */
export const ApiDlpConflict = (exists: string, inUse?: string): MethodDecorator =>
  ApiCodedError(
    409,
    '`' +
      exists +
      '` (`id` when known), `version_conflict` (`currentVersion`), `dlp_limit_reached` ' +
      '(`resource`, `limit`)' +
      (inUse === undefined ? '' : `, \`${inUse}\` (\`references\`)`),
    [exists, DLP_VERSION_CONFLICT, DLP_LIMIT_REACHED, ...(inUse === undefined ? [] : [inUse])],
    CONFLICT_DETAILS,
  );

export const ApiPolicyConflict = (): MethodDecorator =>
  ApiDlpConflict(DLP_POLICY_EXISTS, DLP_POLICY_IN_USE);
export const ApiRuleConflict = (): MethodDecorator =>
  ApiDlpConflict(DLP_RULE_EXISTS, DLP_RULE_IN_USE);
export const ApiExceptionConflict = (): MethodDecorator => ApiDlpConflict(DLP_EXCEPTION_EXISTS);
export const ApiPatternConflict = (): MethodDecorator =>
  ApiDlpConflict(DLP_PATTERN_EXISTS, DLP_PATTERN_IN_USE);
export const ApiDictionaryConflict = (): MethodDecorator =>
  ApiDlpConflict(DLP_DICTIONARY_EXISTS, DLP_DICTIONARY_IN_USE);

export const ApiVersionConflict = (): MethodDecorator =>
  ApiCodedError(409, '`version` is not the current version', [DLP_VERSION_CONFLICT], {
    currentVersion: CONFLICT_DETAILS.currentVersion,
  });

export const ApiReferenceInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), or a coded refusal: `dlp_reference_invalid` (a ' +
      'referenced policy, rule, pattern or dictionary id is not the organization’s; `field`, ' +
      '`index`) or `dlp_directions_invalid` (rule directions outside the policy’s; `references`)',
    [DLP_REFERENCE_INVALID, DLP_DIRECTIONS_INVALID],
    {
      field: { type: 'string' },
      index: { type: 'integer', minimum: 0 },
      references: { type: 'integer', minimum: 1 },
    },
  );

export const ApiPatternInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), or the D9 safety validation refused the pattern ' +
      '(`repetitionProduct`, `length`; never the pattern)',
    [...DLP_PATTERN_CODES],
    {
      repetitionProduct: { type: 'integer', minimum: 0 },
      length: { type: 'integer', minimum: 0 },
    },
  );

export const ApiDictionaryInvalid = (): MethodDecorator =>
  ApiCodedError(
    400,
    'Validation failed (standard body), or the terms were refused (`index` of the first bad ' +
      'term; never the term)',
    [...DLP_DICTIONARY_CODES],
    { index: { type: 'integer', minimum: 0 } },
  );

export const ApiEvidenceGone = (): MethodDecorator =>
  ApiCodedError(
    410,
    '`evidence_purged` (crypto-shredded: tenant request, retention or organization ' +
      'deletion) or `evidence_expired` (past its retention)',
    [EVIDENCE_PURGED, EVIDENCE_EXPIRED],
  );

export const ApiEvidenceUnreadable = (): MethodDecorator =>
  applyDecorators(
    ApiCodedError(
      500,
      'The evidence object is missing, altered or cannot be decrypted (the read and its ' +
        'failure are audited)',
      [EVIDENCE_UNREADABLE],
    ),
    ApiCodedError(
      503,
      '`evidence_unavailable` (object storage failed; retry) or `inconsistent_read`',
      [EVIDENCE_UNAVAILABLE, INCONSISTENT_READ],
    ),
  );

export const ApiInconsistentRead = (): MethodDecorator =>
  ApiCodedError(503, 'The database returned an inconsistent read twice; retry the request', [
    INCONSISTENT_READ,
  ]);
