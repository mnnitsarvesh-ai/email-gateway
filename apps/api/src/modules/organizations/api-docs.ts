import { applyDecorators } from '@nestjs/common';
import { ApiParam, ApiQuery } from '@nestjs/swagger';
import type { z } from 'zod';
import { zodToOpenApi } from '../../validation/zod-openapi';

/** `{id}` path parameter: the organization's public id. */
export const ApiOrganizationId = (): MethodDecorator =>
  ApiParam({ name: 'id', format: 'uuid', description: 'Organization public id' });

/** Documents every field of a zod query object as an optional query parameter. */
export function ApiQueryFrom(schema: z.ZodObject): MethodDecorator {
  return applyDecorators(
    ...Object.entries(schema.shape).map(([name, field]) =>
      ApiQuery({
        name,
        required: false,
        schema: zodToOpenApi(field as z.ZodType, { io: 'input' }),
      }),
    ),
  );
}
