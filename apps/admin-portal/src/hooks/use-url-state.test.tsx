import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { currentTestUrl, setTestRoute, testRouter } from '@/test/router';
import { parseSearchParams, useUrlState } from './use-url-state';

const shape = {
  status: z.enum(['active', 'disabled']).optional().catch(undefined),
  page: z.coerce.number().int().min(1).default(1).catch(1),
  verdict: z
    .array(z.enum(['spam', 'phishing']))
    .optional()
    .catch(undefined),
  q: z.string().max(10).optional().catch(undefined),
};

describe('useUrlState (design P8)', () => {
  it('parses each key on its own; invalid values fall back to defaults', () => {
    expect(
      parseSearchParams(
        shape,
        new URLSearchParams('status=bogus&page=3&verdict=spam,phishing&q=x'),
      ),
    ).toEqual({
      status: undefined,
      page: 3,
      verdict: ['spam', 'phishing'],
      q: 'x',
    });
    expect(parseSearchParams(shape, new URLSearchParams('page=-1')).page).toBe(1);
  });

  it('writes state into the URL, drops defaults and keeps unrelated params', () => {
    setTestRoute('/domains?tab=x');
    const { result } = renderHook(() => useUrlState(shape));
    act(() => result.current[1]({ status: 'active', page: 1, verdict: ['spam'] }));
    expect(currentTestUrl()).toBe('/domains?tab=x&status=active&verdict=spam');
    expect(testRouter.replace).toHaveBeenCalled();
    expect(result.current[0]).toMatchObject({ status: 'active', verdict: ['spam'] });
    act(() => result.current[1]({ status: undefined }, { push: true }));
    expect(currentTestUrl()).toBe('/domains?tab=x&verdict=spam');
    expect(testRouter.push).toHaveBeenCalled();
  });

  it('keeps every write made before the router applies the previous one', () => {
    // Next applies a navigation asynchronously: two filters committing in the same tick both
    // run against the URL of the last render. The second write must build on the first.
    setTestRoute('/audit-logs?status=active&q=old');
    const queued: string[] = [];
    testRouter.replace.mockImplementation((href: string) => void queued.push(href));
    const { result } = renderHook(() => useUrlState(shape));
    act(() => {
      result.current[1]({ q: undefined });
      result.current[1]({ verdict: ['phishing'] });
    });
    expect(queued).toEqual([
      '/audit-logs?status=active',
      '/audit-logs?status=active&verdict=phishing',
    ]);
    // The router catches up with the first write only; a third write still builds on the last.
    act(() => setTestRoute(queued[0]!));
    act(() => result.current[1]({ page: 2 }));
    expect(queued.at(-1)).toBe('/audit-logs?status=active&verdict=phishing&page=2');
    // Once the URL reaches the latest write, or moves elsewhere, the URL is the base again.
    act(() => setTestRoute('/audit-logs?status=disabled'));
    act(() => result.current[1]({ q: 'new' }));
    expect(queued.at(-1)).toBe('/audit-logs?status=disabled&q=new');
  });
});
