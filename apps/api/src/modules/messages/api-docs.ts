import { applyDecorators } from '@nestjs/common';
import { ApiAcceptedResponse, ApiResponse } from '@nestjs/swagger';
import type { SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';
import { MESSAGE_STATES } from '@email-gateway/event-contracts';
import type { z } from 'zod';
import { ApiCodedError } from '../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_INVALID,
  IDEMPOTENCY_REPLAYED_HEADER,
  IDEMPOTENCY_KEY_REQUIRED,
  IDEMPOTENCY_KEY_REUSED,
} from '../../http/idempotency/idempotency-key';
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
