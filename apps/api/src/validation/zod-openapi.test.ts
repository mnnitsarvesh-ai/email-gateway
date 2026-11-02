import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { zodToOpenApi } from './zod-openapi';

describe('zodToOpenApi', () => {
  const Schema = z.object({
    name: z.string().min(1).max(255),
    description: z.string().nullable(),
    limit: z.number().int().default(25),
  });

  it('produces an OpenAPI 3.0 schema object without $schema', () => {
    const schema = zodToOpenApi(Schema) as Record<string, unknown>;
    expect(schema).not.toHaveProperty('$schema');
    expect(schema.type).toBe('object');
    const props = schema.properties as Record<string, Record<string, unknown>>;
    expect(props.name).toMatchObject({ type: 'string', minLength: 1, maxLength: 255 });
    // OpenAPI 3.0 expresses null with `nullable`, not a type union.
    expect(props.description).toMatchObject({ type: 'string', nullable: true });
  });

  it('treats defaulted fields as optional for request bodies (io: input)', () => {
    const input = zodToOpenApi(Schema, { io: 'input' }) as { required?: string[] };
    const output = zodToOpenApi(Schema) as { required?: string[] };
    expect(input.required).not.toContain('limit');
    expect(output.required).toContain('limit');
  });

  it('does not throw for types JSON Schema cannot represent', () => {
    expect(() => zodToOpenApi(z.object({ at: z.date(), id: z.bigint() }))).not.toThrow();
  });
});
