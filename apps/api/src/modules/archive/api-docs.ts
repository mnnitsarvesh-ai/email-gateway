import { applyDecorators, SetMetadata } from '@nestjs/common';
import { ApiExtension, ApiParam, ApiResponse } from '@nestjs/swagger';
import type { z } from 'zod';
import { ApiCodedError } from '../../http/coded-exception';
import {
  ApiIdempotencyKey,
  IDEMPOTENCY_KEY_INVALID,
  IDEMPOTENCY_KEY_REQUIRED,
  IDEMPOTENCY_KEY_REUSED,
  IDEMPOTENCY_REPLAYED_HEADER,
  IDEMPOTENCY_REQUEST_IN_PROGRESS,
} from '../../http/idempotency/idempotency-key';
import { type RateClass as RateClassName, RateClass } from '../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { TRANSACTIONAL_IDEMPOTENCY_KEY } from '../messages/api-docs';
import { ARCHIVE_ERROR_CODES as C } from './archive.errors';

/**
 * A step 8.1 keyed mutation: the transactional Idempotency-Key marker (the effect, its audit row
 * and the stored response commit together), the documented required header,
 * `x-eg-idempotency: required` and the rate class — `sensitive` like every §3.5 mutation, or
 * `expensive` for the two worker-queued requests (case searches and exports, §4.4 #33, #38).
 */
export function ArchiveIdempotency(
  operation: string,
  rateClass: RateClassName = 'sensitive',
): MethodDecorator {
  if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(operation)) {
    throw new Error(`ArchiveIdempotency: invalid operation ${operation}`);
  }
  return applyDecorators(
    SetMetadata(TRANSACTIONAL_IDEMPOTENCY_KEY, Object.freeze({ operation })),
    ApiIdempotencyKey(),
    ApiExtension('x-eg-idempotency', 'required'),
    RateClass(rateClass),
  );
}

const REPLAYED_HEADER = {
  [IDEMPOTENCY_REPLAYED_HEADER]: {
    description: '`true` when this is the stored response of an earlier identical request',
    schema: { type: 'string', enum: ['true'] },
  },
};

const NO_STORE_HEADER = {
  'Cache-Control': { description: '`no-store`', schema: { type: 'string', enum: ['no-store'] } },
};

/** A 2xx with the zod-derived schema and an example (optionally the replay header). */
export const ApiArchiveResponse = (
  status: 200 | 201 | 202,
  schema: z.ZodType,
  example: unknown,
  description: string,
  keyed = false,
): MethodDecorator =>
  ApiResponse({
    status,
    description,
    schema: { ...zodToOpenApi(schema), example },
    headers: keyed ? { ...REPLAYED_HEADER, ...NO_STORE_HEADER } : NO_STORE_HEADER,
  });

/** `400` of a keyed route plus the in-progress `409` and the reuse `422`. */
export const ApiKeyedErrors = (): MethodDecorator =>
  applyDecorators(
    ApiCodedError(
      400,
      'The body or an id is invalid (`validation_failed`, `message` lists the issues), or the ' +
        'Idempotency-Key header is missing (`idempotency_key_required`) or invalid ' +
        '(`idempotency_key_invalid`)',
      ['validation_failed', IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID],
    ),
    ApiCodedError(
      422,
      'The Idempotency-Key was already used for a different request (body, path, operation or ' +
        'caller), or a rule of the operation refused it (see the operation description)',
      [IDEMPOTENCY_KEY_REUSED],
    ),
  );

/** `409` codes of an operation plus `idempotency_request_in_progress` when it is keyed. */
export const ApiArchiveConflicts = (
  codes: readonly string[],
  description: string,
  keyed: boolean,
  details: Record<string, { type: string }> = {},
): MethodDecorator =>
  ApiCodedError(
    409,
    description +
      (keyed ? '. `idempotency_request_in_progress` when the same key is still running' : ''),
    [...codes, ...(keyed ? [IDEMPOTENCY_REQUEST_IN_PROGRESS] : [])],
    details,
  );

/** `422` codes of an operation plus the key reuse when keyed. */
export const ApiArchiveUnprocessable = (
  codes: readonly string[],
  description: string,
  keyed: boolean,
  details: Record<string, { type: string }> = {},
): MethodDecorator =>
  ApiCodedError(
    422,
    description + (keyed ? '; `idempotency_key_reused`' : ''),
    [...codes, ...(keyed ? [IDEMPOTENCY_KEY_REUSED] : [])],
    details,
  );

/** `403` of the archive routes: permission, MFA, user, entitlement, override. */
export const ApiArchiveForbidden = (
  extra: readonly string[] = [],
  description = '',
): MethodDecorator =>
  ApiCodedError(
    403,
    'Missing permission (`forbidden`), API key on a user-only route (`user_required`), session ' +
      'without MFA on an MFA route (`mfa_required`)' +
      (description ? `, ${description}` : ''),
    ['forbidden', 'user_required', 'mfa_required', ...extra],
    { filter: { type: 'string' } },
  );

/** `503` of the archive routes: an echo check failed or a store is down. */
export const ApiArchiveUnavailable = (extra: readonly string[] = []): MethodDecorator =>
  ApiCodedError(
    503,
    'The database returned a row that does not echo the query (`inconsistent_read`, retry) or ' +
      'a dependency (database, rate-limit store, search) is unavailable',
    [C.inconsistentRead, 'service_unavailable', ...extra],
  );

export const ApiMessageIdParam = (): MethodDecorator =>
  ApiParam({ name: 'messageId', description: 'Message public id (UUID)', format: 'uuid' });
export const ApiPolicyIdParam = (): MethodDecorator =>
  ApiParam({ name: 'policyId', description: 'Retention policy public id (UUID)', format: 'uuid' });

export const ApiArchiveMessageNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown archived message, or one of another organization', [
    C.messageNotFound,
  ]);

export const ApiContentGone = (): MethodDecorator =>
  ApiCodedError(
    410,
    'The record is being disposed or was disposed (`archive_content_unavailable`): content is ' +
      'never served from a crypto-shredded record',
    [C.contentUnavailable],
  );

export const ApiIntegrityFailed = (): MethodDecorator =>
  ApiCodedError(
    500,
    'An archived object failed decryption or its integrity check (`archive_integrity_failed`; ' +
      'alerted)',
    [C.integrityFailed],
  );
