import { ApiParam, ApiResponse } from '@nestjs/swagger';
import type { z } from 'zod';
import { ApiCodedError } from '../../http/coded-exception';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ASSISTANT_ERROR_CODES as C } from './assistant.errors';

/** OpenAPI helpers of the assistant routes (step AI-1 §4.1, contracts §35). */

const NO_STORE_HEADER = {
  'Cache-Control': { description: '`no-store`', schema: { type: 'string', enum: ['no-store'] } },
};

/** A 2xx JSON answer with the zod-derived schema and an example. */
export const ApiAssistantResponse = (
  status: 200 | 201 | 202,
  schema: z.ZodType,
  example: unknown,
  description: string,
): MethodDecorator =>
  ApiResponse({
    status,
    description,
    schema: { ...zodToOpenApi(schema), example },
    headers: NO_STORE_HEADER,
  });

/** Every route is `@UserOnly()`: API keys answer `403 user_required`. */
export const USER_ONLY_RULE =
  ' Users only (API keys `403 user_required`); the tenant always comes from your session.';

export const ApiAssistantForbidden = (
  extra: readonly string[] = [],
  description = '',
): MethodDecorator =>
  ApiCodedError(
    403,
    'Missing permission (`forbidden`), API key on a user-only route (`user_required`), MFA ' +
      'enrollment pending (`mfa_enrollment_required`)' +
      (description ? `, ${description}` : ''),
    ['forbidden', 'user_required', 'mfa_enrollment_required', ...extra],
  );

export const ApiAssistantUnavailable = (
  extra: readonly string[] = [],
  description = '',
): MethodDecorator =>
  ApiCodedError(
    503,
    'The database returned an inconsistent read (`inconsistent_read`) or a dependency is down ' +
      '(`service_unavailable`)' +
      (description ? `; ${description}` : ''),
    ['inconsistent_read', 'service_unavailable', ...extra],
  );

/** The gates of new conversations and "more" pages (platform switch, feature, tenant setting). */
export const ApiAssistantGates = (): MethodDecorator =>
  ApiAssistantForbidden(
    [C.notEnabled, C.tenantDisabled],
    'the organization feature `ai_assistant` is off (`assistant_not_enabled`) or the ' +
      'organization turned the assistant off (`assistant_tenant_disabled`)',
  );

export const ApiConversationIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'conversationId',
    description: 'Conversation public id (UUID)',
    format: 'uuid',
  });

export const ApiExecutionIdParam = (): MethodDecorator =>
  ApiParam({ name: 'executionId', description: 'Tool execution public id (UUID)', format: 'uuid' });

export const ApiTurnIdParam = (): MethodDecorator =>
  ApiParam({ name: 'turnId', description: 'Turn public id (UUID)', format: 'uuid' });

export const ApiConversationNotFound = (): MethodDecorator =>
  ApiCodedError(
    404,
    'Unknown conversation, one of another user or organization, or a deleted one',
    [C.conversationNotFound],
  );

export const ApiExecutionNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown execution, or one of another user or organization', [
    C.executionNotFound,
  ]);
