import { BadRequestException, Injectable, type PipeTransform } from '@nestjs/common';
import type { z } from 'zod';

/** `"<path>: <issue>"` for each issue. Zod messages describe the rule, never the input value. */
export function formatZodIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.map(String).join('.');
    return `${path || '(root)'}: ${issue.message}`;
  });
}

/**
 * Validates and transforms a body, query or param with a zod schema (the single source of truth
 * for request shapes, D3). Invalid input is a `400` whose `message` lists every issue; input
 * values are never echoed. Use per parameter: `@Body(new ZodValidationPipe(Schema))`.
 */
@Injectable()
export class ZodValidationPipe<S extends z.ZodType> implements PipeTransform<unknown, z.output<S>> {
  constructor(private readonly schema: S) {}

  transform(value: unknown): z.output<S> {
    const result = this.schema.safeParse(value);
    if (!result.success) {
      throw new BadRequestException(formatZodIssues(result.error));
    }
    return result.data;
  }
}
