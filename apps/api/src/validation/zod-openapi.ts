import type { SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';
import { z } from 'zod';

export interface ZodToOpenApiOptions {
  /** `input` for request bodies and queries (defaults optional), `output` for responses. */
  io?: 'input' | 'output';
}

function stripSchemaKeyword(schema: Record<string, unknown>): SchemaObject {
  const { $schema: _ignored, ...rest } = schema;
  return rest;
}

/**
 * Converts a zod schema to an OpenAPI 3.0 schema object for `@ApiBody({ schema })`,
 * `@ApiOkResponse({ schema })` and `@ApiQuery`, so the zod schema stays the single source of
 * truth (D3). Falls back to the default JSON Schema draft (without `$schema`) if the installed
 * zod does not support the `openapi-3.0` target.
 */
export function zodToOpenApi(schema: z.ZodType, options: ZodToOpenApiOptions = {}): SchemaObject {
  const io = options.io ?? 'output';
  try {
    return stripSchemaKeyword(
      z.toJSONSchema(schema, { target: 'openapi-3.0', io, unrepresentable: 'any' }),
    );
  } catch (err) {
    if (!(err instanceof Error) || !/target/i.test(err.message)) throw err;
    return stripSchemaKeyword(z.toJSONSchema(schema, { io, unrepresentable: 'any' }));
  }
}
