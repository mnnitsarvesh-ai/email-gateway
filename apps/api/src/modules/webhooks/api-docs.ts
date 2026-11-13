import { applyDecorators } from '@nestjs/common';
import { ApiAcceptedResponse, ApiParam, ApiResponse } from '@nestjs/swagger';
import { BLOCKED_REASONS } from '@email-gateway/url-security';
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
import { WEBHOOK_ERROR_CODES as C } from './webhooks.errors';

/** Permissions of the webhook routes (seed catalog; `webhook:read` is new in step 6.2). */
export const WEBHOOK_READ = 'webhook:read';
export const WEBHOOK_MANAGE = 'webhook:manage';

/** The redacted-replay rule of the two secret routes (ADR-0057), for operation descriptions. */
export const REDACTED_REPLAY_RULE =
  'Requires the Idempotency-Key header (transactional: the change, its audit row and the ' +
  'stored response commit together; rate class `sensitive`). The secret is shown ONLY in this ' +
  'response: the stored response under the key is the same body with `secret: null`, so ' +
  'repeating the request with the same key returns it with `Idempotency-Replayed: true` and ' +
  '`secret: null` (ADR-0057). A client that lost the original response rotates the secret ' +
  '(with a new key).';

export const ApiWebhookId = (): MethodDecorator =>
  ApiParam({ name: 'webhookId', description: 'Webhook public id (UUID)', format: 'uuid' });
export const ApiDeliveryId = (): MethodDecorator =>
  ApiParam({ name: 'deliveryId', description: 'Delivery public id (UUID)', format: 'uuid' });
export const ApiReplayId = (): MethodDecorator =>
  ApiParam({ name: 'replayId', description: 'Range replay public id (UUID)', format: 'uuid' });

const REPLAYED_HEADER = {
  [IDEMPOTENCY_REPLAYED_HEADER]: {
    description: '`true` when this is the stored response of an earlier identical request',
    schema: { type: 'string', enum: ['true'] },
  },
};

/** A 2xx with the zod-derived schema, an explicit example and the replay header. */
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

/** `202` without the replay header (test ping). */
export const ApiAcceptedExample = (
  schema: z.ZodType,
  example: unknown,
  description: string,
): MethodDecorator =>
  ApiAcceptedResponse({ description, schema: { ...zodToOpenApi(schema), example } });

/** `400` of a keyed route: body/id validation and the Idempotency-Key header. */
export const ApiKeyedBadRequest = (): MethodDecorator =>
  ApiCodedError(
    400,
    'The body or an id is invalid (`validation_failed`, `message` lists the issues), or the ' +
      'Idempotency-Key header is missing (`idempotency_key_required`) or invalid ' +
      '(`idempotency_key_invalid`)',
    ['validation_failed', IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID],
  );

export const ApiKeyReused = (): MethodDecorator =>
  ApiCodedError(
    422,
    'The Idempotency-Key was already used for a different request (body, path, operation or ' +
      'caller)',
    [IDEMPOTENCY_KEY_REUSED],
  );

export const ApiWebhookNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown webhook, or a webhook of another organization', [C.notFound]);

export const ApiNotEnabled = (): MethodDecorator =>
  ApiCodedError(
    403,
    'Missing permission, or the organization’s plan does not include webhooks ' +
      '(`webhooks_not_enabled`)',
    ['forbidden', C.notEnabled],
  );

/** `422` of create/update: URL rules and filter domains, plus key reuse on keyed routes. */
export const ApiUrlRules = (keyed: boolean): MethodDecorator =>
  ApiCodedError(
    422,
    '`webhook_url_not_allowed` (`reason`: the rule that refused the URL: `scheme`, `port`, ' +
      '`name`, `deny_list`, an address class such as `loopback` or `private`, or `format` for ' +
      'userinfo, fragments, whitespace or length), `webhook_filter_invalid` (`path`: a ' +
      '`domainIds` entry that is not one of your domains)' +
      (keyed ? ', or `idempotency_key_reused`' : ''),
    [C.urlNotAllowed, C.filterInvalid, ...(keyed ? [IDEMPOTENCY_KEY_REUSED] : [])],
    {
      reason: { type: 'string', enum: [...BLOCKED_REASONS, 'format'] },
      path: { type: 'string' },
    },
  );

export const ApiInProgress = (extra: { codes: string[]; description: string }): MethodDecorator =>
  ApiCodedError(
    409,
    extra.description +
      '. `idempotency_request_in_progress` when the same key is still running. Not stored ' +
      'under the Idempotency-Key.',
    [...extra.codes, IDEMPOTENCY_REQUEST_IN_PROGRESS],
    {
      status: { type: 'string' },
      limit: { type: 'integer' },
      replayId: { type: 'string', format: 'uuid' },
      currentRowVersion: { type: 'integer' },
    },
  );

/** `503` of reads and writes: an echo check failed (`inconsistent_read`) or a store is down. */
export const ApiUnavailable = (): MethodDecorator =>
  ApiCodedError(
    503,
    'The database returned a row that does not echo the query (`inconsistent_read`, retry) or ' +
      'a dependency (database, rate-limit store) is unavailable',
    [C.inconsistentRead, 'service_unavailable'],
  );

/** Every documented outcome shared by the subscription-scoped mutations. */
export const ApiMutationBasics = (): MethodDecorator =>
  applyDecorators(ApiWebhookNotFound(), ApiNotEnabled(), ApiUnavailable());
