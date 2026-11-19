import { applyDecorators } from '@nestjs/common';
import { ApiParam, ApiResponse } from '@nestjs/swagger';
import type { z } from 'zod';
import { ApiCodedError } from '../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_INVALID,
  IDEMPOTENCY_KEY_REQUIRED,
  IDEMPOTENCY_KEY_REUSED,
  IDEMPOTENCY_REPLAYED_HEADER,
  IDEMPOTENCY_REQUEST_IN_PROGRESS,
} from '../../http/idempotency/idempotency-key';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ATO_ERROR_CODES as C } from './ato.errors';

/**
 * OpenAPI decorators of the account takeover routes (step 8.4 §5.1; conventions of 6.1 D14):
 * zod-derived 2xx schemas with examples, the standard coded errors of every route and the extra
 * codes of each operation.
 */

const REPLAYED_HEADER = {
  [IDEMPOTENCY_REPLAYED_HEADER]: {
    description: '`true` when this is the stored response of an earlier identical request',
    schema: { type: 'string', enum: ['true'] },
  },
};

/** A 2xx with the zod-derived schema and an example (the replay header on keyed routes). */
export const ApiAtoResponse = (
  status: 200 | 201,
  schema: z.ZodType,
  example: unknown,
  description: string,
  keyed = false,
): MethodDecorator =>
  ApiResponse({
    status,
    description,
    schema: { ...zodToOpenApi(schema), example },
    ...(keyed && { headers: REPLAYED_HEADER }),
  });

/** `400` of a keyed route plus the in-progress `409` code and the reuse `422` code. */
export const ApiAtoKeyedErrors = (
  conflicts: readonly string[] = [],
  unprocessable: readonly string[] = [],
  extra400: readonly string[] = [],
): MethodDecorator =>
  applyDecorators(
    ApiCodedError(
      400,
      'The body or an id is invalid (`validation_failed`), or the Idempotency-Key header is ' +
        'missing (`idempotency_key_required`) or invalid (`idempotency_key_invalid`)' +
        (extra400.length > 0 ? `, or ${extra400.map((c) => `\`${c}\``).join(', ')}` : ''),
      ['validation_failed', IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID, ...extra400],
      extra400.length > 0
        ? {
            issues: {
              type: 'array',
              items: {
                type: 'object',
                properties: { path: { type: 'string' }, message: { type: 'string' } },
              },
            },
          }
        : {},
    ),
    ApiCodedError(
      409,
      'A request with this Idempotency-Key is still in progress' +
        (conflicts.length > 0 ? `, or ${conflicts.map((c) => `\`${c}\``).join(', ')}` : ''),
      [IDEMPOTENCY_REQUEST_IN_PROGRESS, ...conflicts],
      { currentRowVersion: { type: 'integer' }, responseId: { type: 'string', format: 'uuid' } },
    ),
    ApiCodedError(
      422,
      'The Idempotency-Key was already used for a different request (`idempotency_key_reused`)' +
        (unprocessable.length > 0 ? `, or ${unprocessable.map((c) => `\`${c}\``).join(', ')}` : ''),
      [IDEMPOTENCY_KEY_REUSED, ...unprocessable],
    ),
  );

/** `403` of the ATO routes: permission, MFA, users only, the feature gate on mutations. */
export const ApiAtoForbidden = (extra: readonly string[] = [], mutation = false): MethodDecorator =>
  ApiCodedError(
    403,
    'Missing permission (`forbidden`), API key on a user-only route (`user_required`), session ' +
      'without MFA on an MFA route (`mfa_required`)' +
      (mutation ? ', ATO not enabled for the organization (`ato_not_enabled`)' : '') +
      (extra.length > 0 ? `, ${extra.map((c) => `\`${c}\``).join(', ')}` : ''),
    ['forbidden', 'user_required', 'mfa_required', ...(mutation ? [C.notEnabled] : []), ...extra],
  );

/** `503` of the ATO routes: an echo check failed or a dependency is down. */
export const ApiAtoUnavailable = (): MethodDecorator =>
  ApiCodedError(
    503,
    'The database returned a row that does not echo the query (`inconsistent_read`, retry) or ' +
      'a dependency (database, cache) is unavailable',
    [C.inconsistentRead, 'service_unavailable'],
  );

export const ApiAccountIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'accountId',
    description: 'Monitored account public id (UUID)',
    format: 'uuid',
  });
export const ApiResponseIdParam = (): MethodDecorator =>
  ApiParam({ name: 'responseId', description: 'Response action public id (UUID)', format: 'uuid' });
export const ApiIncidentIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'incidentId',
    description: 'Public id (UUID) of an `account_takeover` security incident',
    format: 'uuid',
  });
export const ApiContextIdParam = (): MethodDecorator =>
  ApiParam({ name: 'contextId', description: 'Trusted context public id (UUID)', format: 'uuid' });

export const ApiAccountNotFound = (): MethodDecorator =>
  ApiCodedError(
    404,
    'Unknown account, one of another organization, or ATO is not enabled (`ato_account_not_found`)',
    [C.accountNotFound],
  );
export const ApiResponseNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown response action or one of another organization', [
    C.responseNotFound,
  ]);
export const ApiIncidentNotFound = (): MethodDecorator =>
  ApiCodedError(
    404,
    'Unknown incident, one of another organization, or not an `account_takeover` incident ' +
      '(`incident_not_found`)',
    [C.incidentNotFound],
  );

/** The rule shared by every ATO read when the feature is off (D17). */
export const FEATURE_OFF_READ =
  ' When ATO is not enabled for the organization (plan feature `ato_detection`, off by default; ' +
  'a platform operator enables it per organization), lists are empty and details answer 404.';

/** The rule shared by every ATO mutation (§5.1). */
export const MUTATION_RULE =
  ' Requires the Idempotency-Key header (transactional: the change, its audit rows and the ' +
  'stored response commit together); rate class `sensitive`; `403 ato_not_enabled` while ATO ' +
  'is not enabled for the organization.';
