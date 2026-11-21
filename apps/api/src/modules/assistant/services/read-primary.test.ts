import { readsOnWriter } from '@email-gateway/common';
import type { NextFunction, Request, Response } from 'express';
import { describe, expect, it } from 'vitest';
import {
  AssistantReadPrimaryMiddleware,
  READ_PRIMARY_HEADER,
  readPrimaryToken,
} from './read-primary';

const PEPPER = 'c'.repeat(64);

/** Runs the middleware; returns whether `next` ran on the writer and the headers left. */
async function run(
  headers: Record<string, string | string[]>,
  pepper: string = PEPPER,
): Promise<{ onWriter: boolean; afterAwait: boolean; headers: Record<string, unknown> }> {
  const middleware = new AssistantReadPrimaryMiddleware({
    AUTH_TOKEN_PEPPER: pepper,
  });
  const req = { headers: { ...headers } } as unknown as Request;
  return new Promise((resolve) => {
    const next: NextFunction = () => {
      const onWriter = readsOnWriter();
      void Promise.resolve().then(() =>
        resolve({ onWriter, afterAwait: readsOnWriter(), headers: req.headers }),
      );
    };
    middleware.use(req, {} as Response, next);
  });
}

describe('AssistantReadPrimaryMiddleware (step AI-2 review: precondition reads on the writer)', () => {
  it('runs the request on the writer with the server token, and removes the header', async () => {
    const result = await run({ [READ_PRIMARY_HEADER]: readPrimaryToken(PEPPER), accept: 'x' });
    expect(result).toEqual({ onWriter: true, afterAwait: true, headers: { accept: 'x' } });
    expect(readsOnWriter()).toBe(false);
  });

  it('ignores a missing, wrong, repeated or pepper-less header (normal reads)', async () => {
    expect((await run({})).onWriter).toBe(false);
    const wrong = await run({ [READ_PRIMARY_HEADER]: readPrimaryToken('d'.repeat(64)) });
    expect(wrong).toEqual({ onWriter: false, afterAwait: false, headers: {} });
    expect((await run({ [READ_PRIMARY_HEADER]: 'short' })).onWriter).toBe(false);
    const token = readPrimaryToken(PEPPER);
    expect((await run({ [READ_PRIMARY_HEADER]: [token, token] })).onWriter).toBe(false);
    expect((await run({ [READ_PRIMARY_HEADER]: token }, '')).onWriter).toBe(false);
  });

  it('derives a stable token that does not reveal the pepper', () => {
    const token = readPrimaryToken(PEPPER);
    expect(token).toBe(readPrimaryToken(PEPPER));
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(token).not.toContain(PEPPER.slice(0, 8));
  });
});
