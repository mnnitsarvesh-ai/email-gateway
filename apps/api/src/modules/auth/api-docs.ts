import { applyDecorators } from '@nestjs/common';
import { ApiResponse } from '@nestjs/swagger';
import type { SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';

/** The standard error body (AllExceptionsFilter). */
const ERROR_SCHEMA: SchemaObject = {
  type: 'object',
  properties: {
    statusCode: { type: 'integer' },
    error: { type: 'string' },
    message: { oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }] },
    correlationId: { type: 'string' },
  },
  required: ['statusCode', 'error', 'message'],
};

const DESCRIPTIONS: Record<number, string> = {
  400: 'Validation failed (`message` lists `"<path>: <issue>"`) or the token is invalid/expired',
  401: 'Missing or invalid credentials',
  403: 'Authenticated but not allowed (permission, MFA, enrollment restriction)',
  404: 'Not found (also for resources of another tenant)',
  409: 'Conflicts with the current state',
  429: 'Rate limited (`Retry-After` header when known)',
  503: 'Authentication backend unavailable (fail closed)',
};

/** Documents the listed error statuses with the standard error body. */
export function ApiErrors(...statuses: Array<keyof typeof DESCRIPTIONS>): MethodDecorator {
  return applyDecorators(
    ...statuses.map((status) =>
      ApiResponse({ status, description: DESCRIPTIONS[status], schema: ERROR_SCHEMA }),
    ),
  );
}
