import { ApiParam, ApiResponse } from '@nestjs/swagger';
import type { z } from 'zod';
import { ApiCodedError } from '../../http/coded-exception';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { INSIGHTS_ERROR_CODES as C } from './insights.errors';

/**
 * OpenAPI helpers of the insights routes (step AI-6, contracts §35.6). The same conventions as the
 * assistant routes (tag `assistant`, access-token scheme, `Cache-Control: no-store`, coded errors),
 * so the registry generator classifies the operations `not_applicable` like the other assistant
 * routes.
 */

const NO_STORE_HEADER = {
  'Cache-Control': { description: '`no-store`', schema: { type: 'string', enum: ['no-store'] } },
};

export const ApiInsightsResponse = (
  status: 200 | 201,
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

/** Admin and audit routes: never message text (I24). */
export const METADATA_ONLY_RULE =
  ' Metadata only: never a conversation title, message text, provider transcript, result card, ' +
  'report object or HTML, or recipient address.';

export const ApiInsightsForbidden = (): MethodDecorator =>
  ApiCodedError(
    403,
    'Missing permission (`forbidden`), API key on a user-only route (`user_required`), MFA ' +
      'enrollment pending (`mfa_enrollment_required`)',
    ['forbidden', 'user_required', 'mfa_enrollment_required'],
  );

export const ApiInsightsUnavailable = (
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

export const ApiMessageIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'messageId',
    description: 'Assistant message public id (UUID)',
    format: 'uuid',
  });

export const ApiAdminConversationIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'conversationId',
    description: 'Conversation public id (UUID)',
    format: 'uuid',
  });

export const ApiMessageNotFound = (description: string): MethodDecorator =>
  ApiCodedError(404, description, [C.messageNotFound]);

export const ApiAdminConversationNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown conversation, or one of another organization', [
    C.adminConversationNotFound,
  ]);

export const ApiFeedbackNotAllowed = (): MethodDecorator =>
  ApiCodedError(
    409,
    'The answer’s turn did not complete (failed, cancelled or running), or the conversation’s content was purged',
    [C.feedbackNotAllowed],
  );
