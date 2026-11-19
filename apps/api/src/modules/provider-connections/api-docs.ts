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
import { PROVIDER_ERROR_CODES as C } from './provider-connections.errors';

/**
 * A step 8.2 keyed mutation (§5.1): the transactional Idempotency-Key marker (the change, its
 * audit row and the stored response commit together), the documented required header and
 * `x-eg-idempotency: required`, plus the rate class — `sensitive` for the grant, consent,
 * credential, disconnect and validation mutations (D17), none (`null`) for the connection
 * create, domain links, attestations, the mail-flow apply (own 30/min limit) and the
 * per-connection health check (own 6/hour limit).
 */
export function ProviderIdempotency(
  operation: string,
  rateClass: RateClassName | null = 'sensitive',
): MethodDecorator {
  if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(operation)) {
    throw new Error(`ProviderIdempotency: invalid operation ${operation}`);
  }
  return applyDecorators(
    SetMetadata(TRANSACTIONAL_IDEMPOTENCY_KEY, Object.freeze({ operation })),
    ApiIdempotencyKey(),
    ApiExtension('x-eg-idempotency', 'required'),
    ...(rateClass === null ? [] : [RateClass(rateClass)]),
  );
}

/** The keyed-mutation rule shared by the operation descriptions (§5.1). */
export const KEYED_RULE =
  ' Requires the Idempotency-Key header (transactional: the change, its audit row and the ' +
  'stored response commit together; a repeat with the same key returns the stored response with ' +
  '`Idempotency-Replayed: true`).';

/** ADR-0057: the value shown once and redacted in the stored response. */
export const REDACTED_REPLAY_RULE = (field: string): string =>
  ` \`${field}\` is shown ONLY in this response: the stored response under the Idempotency-Key ` +
  `carries \`${field}: null\`, so a replay returns it redacted (ADR-0057).`;

export const ApiConnectionId = (): MethodDecorator =>
  ApiParam({ name: 'id', description: 'Provider connection public id (UUID)', format: 'uuid' });
export const ApiProfileParam = (): MethodDecorator =>
  ApiParam({
    name: 'profile',
    description: 'Permission profile key (`m365.mail_flow`, `google.mail_flow`)',
    schema: { type: 'string', example: 'm365.mail_flow' },
  });
export const ApiRunId = (): MethodDecorator =>
  ApiParam({ name: 'runId', description: 'Validation run public id (UUID)', format: 'uuid' });

const REPLAYED_HEADER = {
  [IDEMPOTENCY_REPLAYED_HEADER]: {
    description: '`true` when this is the stored response of an earlier identical request',
    schema: { type: 'string', enum: ['true'] },
  },
};

/** A 2xx of a keyed route with the zod-derived schema, an example and the replay header. */
export const ApiKeyedResponse = (
  status: 200 | 201 | 202,
  schema: z.ZodType,
  example: unknown,
  description: string,
): MethodDecorator =>
  ApiResponse({
    status,
    description,
    schema: { ...zodToOpenApi(schema), example },
    headers: REPLAYED_HEADER,
  });

/** `400` of a keyed route: body/id validation and the Idempotency-Key header. */
export const ApiKeyedBadRequest = (): MethodDecorator =>
  ApiCodedError(
    400,
    'The body or an id is invalid (`validation_failed`, `message` lists the issues), or the ' +
      'Idempotency-Key header is missing (`idempotency_key_required`) or invalid ' +
      '(`idempotency_key_invalid`)',
    ['validation_failed', IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID],
  );

export const ApiConnectionNotFound = (extra: string[] = []): MethodDecorator =>
  ApiCodedError(
    404,
    'Unknown connection, or a connection of another organization' +
      (extra.length ? ` (also: ${extra.map((c) => `\`${c}\``).join(', ')})` : ''),
    [C.connectionNotFound, ...extra],
  );

/** `409` of a keyed route: the route's own codes and the in-progress key. */
export const ApiKeyedConflict = (codes: string[], description: string): MethodDecorator =>
  ApiCodedError(
    409,
    `${description}. \`idempotency_request_in_progress\` when the same key is still running ` +
      '(not stored under the key).',
    [...codes, IDEMPOTENCY_REQUEST_IN_PROGRESS],
    {
      limit: { type: 'integer' },
      status: { type: 'string' },
      outboundMode: { type: 'string' },
      reason: { type: 'string' },
      domainId: { type: 'string', format: 'uuid' },
      currentRowVersion: { type: 'integer' },
    },
  );

/** `422` of a keyed route: the route's own codes and the reused key. */
export const ApiKeyedUnprocessable = (codes: string[] = [], description = ''): MethodDecorator =>
  ApiCodedError(
    422,
    (description ? `${description}; ` : '') +
      '`idempotency_key_reused` when the key was used for another request',
    [...codes, IDEMPOTENCY_KEY_REUSED],
    {
      authMethod: { type: 'string' },
      field: { type: 'string' },
      domainId: { type: 'string', format: 'uuid' },
      issues: { type: 'integer' },
    },
  );

/** `503` of reads and writes. */
export const ApiUnavailable = (): MethodDecorator =>
  ApiCodedError(
    503,
    'The database returned a row that does not echo the query (`inconsistent_read`, retry) or ' +
      'a dependency (database, rate-limit store) is unavailable',
    [C.inconsistentRead, 'service_unavailable'],
  );

/** The `403` of a mail-flow change: `integration:manage` and the change's own permission. */
export const ApiChangeForbidden = (): MethodDecorator =>
  ApiCodedError(
    403,
    'Missing permission: `integration:manage` and the change’s own permission ' +
      '(`domain:routing_manage` for `inbound`, `connector:manage` for the other kinds)',
    ['forbidden'],
  );

/** Every documented outcome shared by connection-scoped routes. */
export const ApiConnectionBasics = (): MethodDecorator =>
  applyDecorators(ApiConnectionNotFound(), ApiUnavailable());
