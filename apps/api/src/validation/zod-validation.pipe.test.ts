import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ZodValidationPipe } from './zod-validation.pipe';

const Body = z.object({
  email: z.email(),
  password: z.string().min(12),
  role: z.enum(['a', 'b']),
  nested: z.object({ count: z.coerce.number().int().min(1) }),
});

function messages(fn: () => unknown): string[] {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(BadRequestException);
    const response = (err as BadRequestException).getResponse() as { message: string[] };
    expect((err as BadRequestException).getStatus()).toBe(400);
    return response.message;
  }
  return expect.fail('expected BadRequestException');
}

describe('ZodValidationPipe', () => {
  const pipe = new ZodValidationPipe(Body);

  it('returns the parsed (transformed) value', () => {
    expect(
      pipe.transform({
        email: 'a@b.example',
        password: 'x'.repeat(12),
        role: 'a',
        nested: { count: '2' },
      }),
    ).toEqual({ email: 'a@b.example', password: 'x'.repeat(12), role: 'a', nested: { count: 2 } });
  });

  it('lists every issue as "<path>: <issue>"', () => {
    const result = messages(() =>
      pipe.transform({ email: 'nope', password: 'short', role: 'c', nested: { count: 0 } }),
    );
    expect(result).toHaveLength(4);
    expect(result.map((m) => m.split(':')[0])).toEqual([
      'email',
      'password',
      'role',
      'nested.count',
    ]);
  });

  it('never echoes input values', () => {
    const secret = 'Hunter2-TopSecret';
    const result = messages(() =>
      pipe.transform({
        email: secret,
        password: secret.slice(0, 5),
        role: secret,
        nested: { count: secret },
      }),
    );
    expect(JSON.stringify(result)).not.toContain('Hunter2');
  });

  it('reports a non-object body at the root', () => {
    expect(messages(() => pipe.transform('text'))).toEqual([expect.stringMatching(/^\(root\): /)]);
  });
});
