import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { decodeCursor, encodeCursor, PageQuerySchema, pageWindow, toPage } from './pagination';

describe('PageQuerySchema', () => {
  it('defaults to 25 rows without a cursor', () => {
    expect(PageQuerySchema.parse({})).toEqual({ limit: 25 });
  });

  it('coerces the query-string limit', () => {
    expect(PageQuerySchema.parse({ limit: '100', cursor: 'MTA' })).toEqual({
      limit: 100,
      cursor: 'MTA',
    });
  });

  it.each(['0', '101', '2.5', 'abc'])('rejects limit=%s', (limit) => {
    expect(PageQuerySchema.safeParse({ limit }).success).toBe(false);
  });
});

describe('cursors', () => {
  it('round-trips ids, including the BIGINT UNSIGNED maximum', () => {
    for (const id of [1n, 42n, 18446744073709551615n]) {
      expect(decodeCursor(encodeCursor(id))).toBe(id);
    }
  });

  it('is opaque base64url', () => {
    expect(encodeCursor(42n)).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encodeCursor(42n)).not.toContain('42');
  });

  it.each([
    ['garbage', 'not base64 of an id'],
    [Buffer.from('0').toString('base64url'), 'zero'],
    [Buffer.from('-5').toString('base64url'), 'negative'],
    [Buffer.from('007').toString('base64url'), 'leading zeros'],
    [Buffer.from('18446744073709551616').toString('base64url'), 'out of range'],
    [`${encodeCursor(42n)}==`, 'non-canonical padding'],
  ])('rejects %s (%s) with 400', (cursor) => {
    expect(() => decodeCursor(cursor)).toThrow(BadRequestException);
  });
});

describe('pageWindow and toPage', () => {
  const rows = (ids: number[]) => ids.map((id) => ({ id: BigInt(id), name: `row-${id}` }));

  it('fetches one extra row and passes the decoded cursor', () => {
    expect(pageWindow({ limit: 2 })).toEqual({ take: 3 });
    expect(pageWindow({ limit: 2, cursor: encodeCursor(10n) })).toEqual({ take: 3, beforeId: 10n });
  });

  it('returns a next cursor when more rows exist', () => {
    const page = toPage(rows([9, 8, 7]), 2, (r) => r.name);
    expect(page.data).toEqual(['row-9', 'row-8']);
    expect(page.nextCursor).toBe(encodeCursor(8n));
  });

  it('returns null on the last page', () => {
    expect(toPage(rows([2, 1]), 2, (r) => r.name)).toEqual({
      data: ['row-2', 'row-1'],
      nextCursor: null,
    });
    expect(toPage(rows([]), 25, (r) => r.name)).toEqual({ data: [], nextCursor: null });
  });
});
