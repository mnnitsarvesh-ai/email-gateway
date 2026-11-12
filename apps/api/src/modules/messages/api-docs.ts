import { applyDecorators, SetMetadata } from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiCreatedResponse,
  ApiExtension,
  ApiOkResponse,
  ApiQuery,
  ApiResponse,
} from '@nestjs/swagger';
import type { SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';
import { MESSAGE_STATES } from '@email-gateway/event-contracts';
import type { z } from 'zod';
import { ApiCodedError } from '../../http/coded-exception';
import { CURSOR_INVALID } from '../../http/cursor/cursor-codec';
import {
  ApiIdempotencyKey,
  IDEMPOTENCY_KEY_INVALID,
  IDEMPOTENCY_REPLAYED_HEADER,
  IDEMPOTENCY_KEY_REQUIRED,
  IDEMPOTENCY_KEY_REUSED,
} from '../../http/idempotency/idempotency-key';
import { RateClass } from '../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ApiErrors } from '../auth/api-docs';
import {
  MESSAGE_NOT_FOUND,
  MESSAGE_STATE_CONFLICT,
  MESSAGE_VERSION_CONFLICT,
  QUARANTINE_WORKFLOW_REQUIRED,
} from './messages.errors';

/** Permissions of the lifecycle routes (seed catalog; `message:rescan` is new in step 3.3). */
export const MESSAGE_READ = 'message:read';
export const MESSAGE_RESCAN = 'message:rescan';
export const QUARANTINE_RELEASE = 'quarantine:release';

const STANDARD_400: SchemaObject = {
  type: 'object',
  properties: {
    statusCode: { type: 'integer', enum: [400] },
    error: { type: 'string' },
    code: {
      type: 'string',
      enum: [IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID],
      description: 'Present for Idempotency-Key errors only',
    },
    message: { oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }] },
    correlationId: { type: 'string' },
  },
  required: ['statusCode', 'error', 'message'],
};

/** `404 message_not_found`: unknown id or another organization's message. */
export const ApiMessageNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown message, or a message of another organization', [MESSAGE_NOT_FOUND]);

/** Every documented outcome of a lifecycle write route besides its 202. */
export function ApiLifecycleWriteErrors(conflicts: readonly string[]): MethodDecorator {
  return applyDecorators(
    ApiResponse({
      status: 400,
      description:
        '`messageId` is not a UUID, the body is invalid (`message` lists the issues), or the ' +
        'Idempotency-Key header is missing (`idempotency_key_required`) or invalid ' +
        '(`idempotency_key_invalid`)',
      schema: STANDARD_400,
    }),
    ApiErrors(401, 403),
    ApiMessageNotFound(),
    ApiCodedError(
      409,
      '`message_version_conflict`: `expectedVersion` is not the current version; ' +
        '`message_state_conflict`: the current state does not allow the operation' +
        (conflicts.includes(QUARANTINE_WORKFLOW_REQUIRED)
          ? '; `quarantine_workflow_required` (step 5.3 Q30): every `quarantined` or ' +
            '`held_for_review` message is released per recipient through the quarantine ' +
            'workflow (`entries`: the number of its entries, `route`: the quarantine release ' +
            'route)'
          : '') +
        '. `currentState` and `currentVersion` describe the message now. Not stored under the ' +
        'Idempotency-Key.',
      conflicts,
      {
        currentState: { type: 'string', enum: [...MESSAGE_STATES] },
        currentVersion: { type: 'integer', minimum: 0 },
        ...(conflicts.includes(QUARANTINE_WORKFLOW_REQUIRED) && {
          entries: { type: 'integer', minimum: 0 },
          route: { type: 'string' },
        }),
      },
    ),
    ApiCodedError(
      422,
      'The Idempotency-Key was already used for a different request (body, path, operation or ' +
        'caller)',
      [IDEMPOTENCY_KEY_REUSED],
    ),
  );
}

export const RESCAN_CONFLICTS = [MESSAGE_VERSION_CONFLICT, MESSAGE_STATE_CONFLICT] as const;
export const RELEASE_CONFLICTS = [
  MESSAGE_VERSION_CONFLICT,
  MESSAGE_STATE_CONFLICT,
  QUARANTINE_WORKFLOW_REQUIRED,
] as const;

/** The `202` of a lifecycle write route with the replay header. */
export const ApiLifecycleAccepted = (schema: z.ZodType, description: string): MethodDecorator =>
  ApiAcceptedResponse({
    description,
    schema: zodToOpenApi(schema),
    headers: {
      [IDEMPOTENCY_REPLAYED_HEADER]: {
        description: '`true` when this is the stored response of an earlier identical request',
        schema: { type: 'string', enum: ['true'] },
      },
    },
  });

/**
 * Metadata key of a route whose Idempotency-Key is handled by the transactional
 * `IdempotencyService.execute` inside its service (step 3.3 L11, step 6.1 D9 mechanism 1): the
 * effect, its audit row and the stored response commit in one writer transaction. Not the
 * reservation interceptor (`@Idempotent`), so `IDEMPOTENT_KEY` is deliberately not set.
 */
export const TRANSACTIONAL_IDEMPOTENCY_KEY = 'http:idempotentTransactional';

export interface TransactionalIdempotencyOptions {
  /** Stable operation name stored in `api_idempotency_keys.operation`, e.g. `message.rescan`. */
  operation: string;
}

/**
 * A §3.5 sensitive mutation with transactional idempotency: the marker above, the documented
 * required `Idempotency-Key` header, `x-eg-idempotency: required` and the `sensitive` rate class.
 */
export function TransactionalIdempotency(operation: string): MethodDecorator {
  if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(operation)) {
    throw new Error(`TransactionalIdempotency: invalid operation ${operation}`);
  }
  return applyDecorators(
    SetMetadata(TRANSACTIONAL_IDEMPOTENCY_KEY, Object.freeze({ operation })),
    ApiIdempotencyKey(),
    ApiExtension('x-eg-idempotency', 'required'),
    RateClass('sensitive'),
  );
}

/** The strict object behind a `defineListQuery` schema (a pipe into a transform). */
function listQueryShape(schema: z.ZodType): Record<string, z.ZodType> {
  const def = (schema as unknown as { _zod: { def: { type: string; in?: unknown } } })._zod.def;
  const inner = (def.type === 'pipe' ? def.in : schema) as { shape?: Record<string, z.ZodType> };
  if (!inner.shape) throw new Error('ApiListQuery: not a list query schema');
  return inner.shape;
}

/**
 * Documents every query parameter of a v1 list (`defineListQuery`): its input type, whether it
 * is required and its description.
 */
export function ApiListQuery(
  schema: z.ZodType,
  descriptions: Record<string, string>,
  required: readonly string[] = [],
): MethodDecorator {
  return applyDecorators(
    ...Object.entries(listQueryShape(schema)).map(([name, field]) =>
      ApiQuery({
        name,
        required: required.includes(name),
        ...(descriptions[name] !== undefined && { description: descriptions[name] }),
        schema: zodToOpenApi(field, { io: 'input' }),
      }),
    ),
  );
}

/** `400 cursor_invalid` and validation errors of a v1 list. */
export const ApiListErrors = (): MethodDecorator =>
  ApiResponse({
    status: 400,
    description:
      'Validation failed (`validation_failed`: unknown parameter or operator, wrong type, too ' +
      'many values, range too long; `message` lists `"<path>: <issue>"`) or the cursor is ' +
      'invalid, expired or belongs to other filters, another sort or another caller ' +
      '(`cursor_invalid`)',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'integer', enum: [400] },
        error: { type: 'string' },
        code: { type: 'string', enum: ['validation_failed', CURSOR_INVALID] },
        message: { oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }] },
        correlationId: { type: 'string' },
        requestId: { type: 'string', format: 'uuid' },
      },
      required: ['statusCode', 'error', 'code', 'message'],
    },
  });

/** `503 inconsistent_read` (D15) of the replica reads. */
export const ApiInconsistentRead = (): MethodDecorator =>
  ApiCodedError(
    503,
    'The replica returned a row that does not echo the query (`inconsistent_read`, retry) or a ' +
      'dependency is unavailable',
    ['inconsistent_read', 'service_unavailable'],
  );

/** The short-page rule of every scan-bounded v1 list (D6), for operation descriptions. */
export const SCAN_BUDGET_RULE =
  'Pages follow the v1 list contract: `{ data, nextCursor }`, no totals. When filters need ' +
  'non-indexed columns, each request examines at most API_LIST_SCAN_BUDGET_ROWS index entries ' +
  '(default 5 000), so a page may hold fewer rows than `limit` (even none) while `nextCursor` is ' +
  'set; follow `nextCursor` until it is null. The cursor is signed and bound to the filters, the ' +
  'sort, your organization and the first page’s time window: repeat the same filters (or omit ' +
  '`from`/`to`) with it, anything else is `400 cursor_invalid`.';

/** `200` with the zod-derived schema and an explicit example (D14: every 6.1 route). */
export const ApiOkExample = (schema: z.ZodType, example: unknown, description?: string) =>
  ApiOkResponse({
    ...(description !== undefined && { description }),
    schema: { ...zodToOpenApi(schema), example },
  });

/** `201` with the schema, an explicit example and the replay header. */
export const ApiCreatedExample = (schema: z.ZodType, example: unknown, description: string) =>
  ApiCreatedResponse({
    description,
    schema: { ...zodToOpenApi(schema), example },
    headers: {
      [IDEMPOTENCY_REPLAYED_HEADER]: {
        description: '`true` when this is the stored response of an earlier identical request',
        schema: { type: 'string', enum: ['true'] },
      },
    },
  });
