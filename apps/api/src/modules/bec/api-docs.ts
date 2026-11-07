import { ApiParam } from '@nestjs/swagger';
import { ApiCodedError } from '../../http/coded-exception';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import {
  BEC_EXECUTIVE_NOT_FOUND,
  BEC_LIMIT_REACHED,
  BEC_RESULT_NOT_FOUND,
  BEC_SCAN_NOT_FOUND,
  BEC_SUPPRESSION_NOT_FOUND,
  BEC_TRUSTED_SENDER_NOT_FOUND,
  BEC_VENDOR_NOT_FOUND,
  BEC_VERSION_CONFLICT,
  EXECUTIVE_EXISTS,
  FEEDBACK_CODES_INVALID,
  FEEDBACK_EXISTS,
  INCONSISTENT_READ,
  SUPPRESSION_NOT_ALLOWED,
  TRUSTED_DOMAIN_FREEMAIL,
  TRUSTED_SENDER_EXISTS,
  VENDOR_DOMAIN_FREEMAIL,
  VENDOR_EXISTS,
} from './bec.errors';
import { BecIdSchema, BecScanIdSchema } from './dto/bec.schemas';
import { MESSAGE_NOT_FOUND } from '../messages/messages.errors';

/** Permissions of the BEC routes (seed catalog, step 4.4 B18). */
export const BEC_READ = 'bec:read';
export const BEC_MANAGE = 'bec:manage';
export const BEC_FEEDBACK = 'bec:feedback';
export const BEC_FEEDBACK_EXPORT = 'bec:feedback_export';

/** How quickly the engine sees a change (B4 tenant data cache). */
export const BEC_APPLY_NOTE =
  'The BEC engine caches the organization’s profiles, trusted senders and suppressions for up ' +
  'to BEC_TENANT_DATA_CACHE_TTL_MS (default 30 seconds): a change applies to messages scanned ' +
  'after that.';

/** `{id}` of a BEC resource: its public id. */
export const becIdPipe = new ZodValidationPipe(BecIdSchema);
export const scanIdPipe = new ZodValidationPipe(BecScanIdSchema);

export const ApiBecId = (description: string): MethodDecorator =>
  ApiParam({ name: 'id', format: 'uuid', description });

export const ApiScanId = (): MethodDecorator =>
  ApiParam({
    name: 'scanId',
    description: 'Decimal scan id (`scanId` of the round in `GET /messages/{messageId}/scans`)',
  });

export const ApiBecNotFound = (code: string, what: string): MethodDecorator =>
  ApiCodedError(404, `${what} not found (also for another organization’s id)`, [code]);

export const ApiExecutiveNotFound = (): MethodDecorator =>
  ApiBecNotFound(BEC_EXECUTIVE_NOT_FOUND, 'Executive profile');
export const ApiVendorNotFound = (): MethodDecorator =>
  ApiBecNotFound(BEC_VENDOR_NOT_FOUND, 'Vendor profile');
export const ApiTrustedSenderNotFound = (): MethodDecorator =>
  ApiBecNotFound(BEC_TRUSTED_SENDER_NOT_FOUND, 'Trusted sender');
export const ApiSuppressionNotFound = (): MethodDecorator =>
  ApiBecNotFound(BEC_SUPPRESSION_NOT_FOUND, 'Suppression rule');

export const ApiFeedbackTargetNotFound = (): MethodDecorator =>
  ApiCodedError(
    404,
    'The message, the scan or its BEC result is not found (also for another organization)',
    [MESSAGE_NOT_FOUND, BEC_SCAN_NOT_FOUND, BEC_RESULT_NOT_FOUND],
  );

const conflictCodes = (exists: string) => [exists, BEC_VERSION_CONFLICT, BEC_LIMIT_REACHED];

/** 409: the unique key is taken, the version moved, or the per-tenant cap is reached. */
export const ApiBecConflict = (exists: string): MethodDecorator =>
  ApiCodedError(
    409,
    '`' +
      exists +
      '` (the normalized key exists; `id` when known), `version_conflict` ' +
      '(`currentVersion`) or `bec_limit_reached` (`resource`, `limit`)',
    conflictCodes(exists),
    {
      id: { type: 'string', format: 'uuid' },
      currentVersion: { type: 'integer', minimum: 1 },
      resource: { type: 'string' },
      limit: { type: 'integer', minimum: 1 },
    },
  );

export const ApiExecutiveConflict = (): MethodDecorator => ApiBecConflict(EXECUTIVE_EXISTS);
export const ApiVendorConflict = (): MethodDecorator => ApiBecConflict(VENDOR_EXISTS);
export const ApiTrustedSenderConflict = (): MethodDecorator =>
  ApiBecConflict(TRUSTED_SENDER_EXISTS);

export const ApiVersionOnlyConflict = (): MethodDecorator =>
  ApiCodedError(409, '`version` is not the current version', [BEC_VERSION_CONFLICT], {
    currentVersion: { type: 'integer', minimum: 1 },
  });

export const ApiVendorDomainFreemail = (): MethodDecorator =>
  ApiCodedError(422, 'A vendor domain is a free-mail domain (`index`)', [VENDOR_DOMAIN_FREEMAIL], {
    index: { type: 'integer', minimum: 0 },
  });

export const ApiTrustedDomainFreemail = (): MethodDecorator =>
  ApiCodedError(422, 'A trusted domain is a free-mail domain', [TRUSTED_DOMAIN_FREEMAIL]);

export const ApiFeedbackConflict = (): MethodDecorator =>
  ApiCodedError(
    409,
    '`feedback_exists` (one feedback per scan, user and kind) or `bec_limit_reached` ' +
      '(BEC_SUPPRESSIONS_MAX_PER_TENANT active suppression rules)',
    [FEEDBACK_EXISTS, BEC_LIMIT_REACHED],
    { resource: { type: 'string' }, limit: { type: 'integer', minimum: 1 } },
  );

export const ApiFeedbackInvalid = (): MethodDecorator =>
  ApiCodedError(
    422,
    '`feedback_codes_invalid` (a disputed code is not a code of the result) or ' +
      '`suppression_not_allowed` (`reason`: not_false_positive, code_not_suppressible, ' +
      'code_not_in_result, sender_unavailable, freemail_domain)',
    [FEEDBACK_CODES_INVALID, SUPPRESSION_NOT_ALLOWED],
    { reason: { type: 'string' }, reasonCode: { type: 'string' } },
  );

export const ApiInconsistentRead = (): MethodDecorator =>
  ApiCodedError(503, 'The database returned an inconsistent read twice; retry the request', [
    INCONSISTENT_READ,
  ]);
