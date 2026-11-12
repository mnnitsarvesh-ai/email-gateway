import { applyDecorators } from '@nestjs/common';
import { ApiOkResponse, ApiResponse } from '@nestjs/swagger';
import type { z } from 'zod';
import { codedErrorSchema } from '../../http/coded-exception';
import { zodToOpenApi } from '../../validation/zod-openapi';

/**
 * OpenAPI helpers of the step 6.1 insight routes (audit logs, reports, usage, billing, threat
 * intelligence): an explicit `200` example next to the zod-derived schema (D14) and coded errors
 * with their `code` values (§3.2). The standard error responses are added by
 * `postProcessOpenApiDocument`; an operation documents only what it says more precisely.
 */
export function ApiOkExample(schema: z.ZodType, example: unknown): MethodDecorator {
  return ApiOkResponse({ schema: { ...zodToOpenApi(schema), example }, example });
}

export function ApiCodedError(
  status: number,
  codes: readonly string[],
  description: string,
): MethodDecorator {
  return ApiResponse({ status, description, schema: codedErrorSchema(status, codes) });
}

/** `400 validation_failed` (+ specific 400 codes) and the read-path `503` codes. */
export function ApiReadErrors(
  options: { extra400?: readonly string[]; extra503?: readonly string[] } = {},
): MethodDecorator {
  const extra400 = options.extra400 ?? [];
  const extra503 = options.extra503 ?? [];
  return applyDecorators(
    ApiCodedError(
      400,
      ['validation_failed', ...extra400],
      'Invalid query: unknown parameter, wrong type or range (`message` lists `"<path>: <issue>"`)' +
        (extra400.length > 0 ? `, or: ${extra400.join(', ')}` : ''),
    ),
    ApiCodedError(
      503,
      ['service_unavailable', 'inconsistent_read', ...extra503],
      'A dependency is unavailable or the replica returned an inconsistent read (retry)' +
        (extra503.length > 0 ? `, or: ${extra503.join(', ')}` : ''),
    ),
  );
}
