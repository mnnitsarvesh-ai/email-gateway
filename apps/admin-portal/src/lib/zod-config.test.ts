import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import './zod-config';

describe('zod-config', () => {
  afterEach(() => vi.restoreAllMocks());

  it('turns the JIT (and its eval probe) off so the CSP never reports script-src eval', () => {
    expect(z.config().jitless).toBe(true);
    const FunctionSpy = vi.spyOn(globalThis, 'Function');
    const schema = z.object({ email: z.string(), code: z.string().length(6) }).strict();
    expect(schema.parse({ email: 'a@b.example.test', code: '123456' })).toEqual({
      email: 'a@b.example.test',
      code: '123456',
    });
    expect(schema.safeParse({ email: 1 }).success).toBe(false);
    expect(FunctionSpy).not.toHaveBeenCalled();
  });
});
