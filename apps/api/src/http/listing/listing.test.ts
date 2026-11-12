import { BadRequestException, HttpStatus, Logger } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { CodedHttpException } from '../coded-exception';
import { formatZodIssues } from '../../validation/zod-validation.pipe';
import { assertEcho, INCONSISTENT_READ, InconsistentReadError } from './echo-check';
import { filterHash } from './filter-hash';
import { defineListQuery } from './list-query';
import { rangeWindow, resolveRange } from './range';
import { boundaryOffset, decideKeysetPage, decideScanPage } from './scan-budget';

const Query = defineListQuery({
  filters: {
    direction: { type: 'enum', values: ['inbound', 'outbound', 'internal'] },
    verdict: { type: 'enum', values: ['clean', 'spam', 'phishing', 'malware'], maxValues: 3 },
    sender: { type: 'email' },
    headerFrom: { type: 'string', maxLength: 20 },
    domainId: { type: 'publicId' },
    riskScore: { type: 'int', min: 0, max: 100, range: true },
    hasAttachments: { type: 'bool' },
    clickedAt: { type: 'datetime', range: true },
  },
  sorts: ['-receivedAt', 'receivedAt'],
  defaultSort: '-receivedAt',
  range: true,
});

function issues(input: Record<string, unknown>): string[] {
  const result = Query.safeParse(input);
  if (result.success) return expect.fail('expected a validation failure');
  return formatZodIssues(result.error);
}

describe('defineListQuery (step 6.1 D4)', () => {
  it('defaults limit 25 and the default sort, with no filters', () => {
    expect(Query.parse({})).toEqual({ limit: 25, sort: '-receivedAt', filters: {} });
  });

  it('parses limit, cursor, sort and the range', () => {
    expect(
      Query.parse({
        limit: '100',
        cursor: 'abc.def',
        sort: 'receivedAt',
        from: '2026-11-01T00:00:00Z',
        to: '2026-11-02T00:00:00.000+05:30',
      }),
    ).toEqual({
      limit: 100,
      cursor: 'abc.def',
      sort: 'receivedAt',
      from: new Date('2026-11-01T00:00:00Z'),
      to: new Date('2026-11-01T18:30:00.000Z'),
      filters: {},
    });
  });

  it.each([
    [{ limit: '0' }, 'limit'],
    [{ limit: '101' }, 'limit'],
    [{ limit: '2.5' }, 'limit'],
    [{ limit: 'ten' }, 'limit'],
    [{ sort: 'subject' }, 'sort'],
    [{ from: 'yesterday' }, 'from'],
    [{ to: '2026-11-01' }, 'to'],
    [{ cursor: '' }, 'cursor'],
    [{ cursor: 'a'.repeat(513) }, 'cursor'],
  ])('refuses %o naming %s', (input, key) => {
    expect(issues(input).join(' ')).toContain(`${key}:`);
  });

  it('parses every operator with its type', () => {
    expect(
      Query.parse({
        direction: 'inbound',
        verdict: 'spam,phishing',
        sender: '  Alice@Example.COM ',
        headerFrom: 'Alice <a@x>',
        domainId: '01930c2e-7d1a-7000-8000-000000000001',
        'riskScore.gte': '10',
        'riskScore.lt': '90',
        riskScore: '50',
        hasAttachments: 'false',
        'clickedAt.gt': '2026-11-01T00:00:00Z',
        'clickedAt.lte': '2026-11-02T00:00:00Z',
      }).filters,
    ).toEqual({
      direction: { values: ['inbound'] },
      verdict: { values: ['spam', 'phishing'] },
      sender: { values: ['alice@example.com'] },
      headerFrom: { values: ['Alice <a@x>'] },
      domainId: { values: ['01930c2e-7d1a-7000-8000-000000000001'] },
      riskScore: { gte: 10, lt: 90, values: [50] },
      hasAttachments: { values: [false] },
      clickedAt: {
        gt: new Date('2026-11-01T00:00:00Z'),
        lte: new Date('2026-11-02T00:00:00Z'),
      },
    });
    expect(Query.parse({ 'riskScore.lte': '0', hasAttachments: 'true' }).filters).toEqual({
      riskScore: { lte: 0 },
      hasAttachments: { values: [true] },
    });
  });

  it('is strict: unknown fields and operators are refused', () => {
    expect(issues({ subject: 'x' }).join(' ')).toMatch(/Unrecognized key/);
    expect(issues({ 'direction.gte': 'inbound' }).join(' ')).toMatch(/Unrecognized key/);
    expect(issues({ 'riskScore.ne': '1' }).join(' ')).toMatch(/Unrecognized key/);
    expect(issues({ clickedAt: '2026-11-01T00:00:00Z' }).join(' ')).toMatch(/Unrecognized key/);
    expect(issues({ 'verdict.gte': 'spam' }).join(' ')).toMatch(/Unrecognized key/);
  });

  it('enforces the maximum number of values and refuses lists where none are allowed', () => {
    expect(issues({ verdict: 'spam,phishing,malware,clean' }).join(' ')).toContain(
      'at most 3 values',
    );
    expect(issues({ verdict: 'spam,spam' }).join(' ')).toContain('must not repeat');
    expect(issues({ direction: 'inbound,outbound' }).join(' ')).toContain('direction');
    expect(issues({ verdict: 'spam,' }).join(' ')).toContain('verdict');
  });

  it('refuses type errors, naming the parameter and never echoing the value', () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ direction: 'sideways' }, 'direction'],
      [{ sender: 'not-an-address' }, 'sender'],
      [{ headerFrom: 'x'.repeat(21) }, 'headerFrom'],
      [{ domainId: 'nope' }, 'domainId'],
      [{ 'riskScore.gte': '101' }, 'riskScore.gte'],
      [{ 'riskScore.gte': '-1' }, 'riskScore.gte'],
      [{ 'riskScore.gte': '1.5' }, 'riskScore.gte'],
      [{ hasAttachments: 'yes' }, 'hasAttachments'],
      [{ 'clickedAt.gt': 'monday-SECRET' }, 'clickedAt.gt'],
      // A repeated parameter arrives as an array from the query parser.
      [{ direction: ['inbound', 'outbound'] }, 'direction'],
    ];
    for (const [input, key] of cases) {
      const text = issues(input).join(' ');
      expect(text, key).toContain(`${key}:`);
      expect(text).not.toContain('SECRET');
    }
  });

  it('refuses invalid definitions (programming errors)', () => {
    expect(() =>
      defineListQuery({ filters: { limit: { type: 'bool' } }, sorts: ['a'], defaultSort: 'a' }),
    ).toThrow();
    expect(() =>
      defineListQuery({
        filters: { score: { type: 'int', min: 5, max: 1 } },
        sorts: ['a'],
        defaultSort: 'a',
      }),
    ).toThrow();
    expect(() => defineListQuery({ filters: {}, sorts: ['a'], defaultSort: 'b' as 'a' })).toThrow();
  });
});

describe('filterHash (step 6.1 D3)', () => {
  it('is 16 hex characters and independent of key and value order', () => {
    const a = Query.parse({ verdict: 'spam,phishing', direction: 'inbound' });
    const b = Query.parse({ direction: 'inbound', verdict: 'phishing,spam' });
    const hashA = filterHash({ resource: 'messages', filters: a.filters, sort: a.sort });
    expect(hashA).toMatch(/^[0-9a-f]{16}$/);
    expect(filterHash({ resource: 'messages', filters: b.filters, sort: b.sort })).toBe(hashA);
  });

  it('changes with the filters, the sort and the resource', () => {
    const base = Query.parse({ direction: 'inbound' });
    const hash = filterHash({ resource: 'messages', filters: base.filters, sort: base.sort });
    const other = Query.parse({ direction: 'outbound' });
    expect(filterHash({ resource: 'messages', filters: other.filters, sort: base.sort })).not.toBe(
      hash,
    );
    expect(
      filterHash({ resource: 'messages', filters: base.filters, sort: 'receivedAt' }),
    ).not.toBe(hash);
    expect(filterHash({ resource: 'audit_logs', filters: base.filters, sort: base.sort })).not.toBe(
      hash,
    );
    const dated = Query.parse({ 'clickedAt.gt': '2026-11-01T00:00:00Z' });
    const sameInstant = Query.parse({ 'clickedAt.gt': '2026-11-01T05:30:00+05:30' });
    expect(filterHash({ resource: 'x', filters: dated.filters, sort: 'a' })).toBe(
      filterHash({ resource: 'x', filters: sameInstant.filters, sort: 'a' }),
    );
    // Empty filters equal no filters.
    expect(filterHash({ resource: 'x', filters: { direction: {} }, sort: 'a' })).toBe(
      filterHash({ resource: 'x', filters: {}, sort: 'a' }),
    );
  });
});

describe('resolveRange (step 6.1 D4)', () => {
  const now = new Date('2026-11-12T10:00:00.000Z');
  const options = { defaultMs: 86_400_000, maxDays: 31, now };

  it('defaults to the last defaultMs before now, or before to', () => {
    expect(resolveRange({}, options)).toEqual({
      from: new Date('2026-11-11T10:00:00.000Z'),
      to: now,
    });
    const to = new Date('2026-11-05T00:00:00.000Z');
    expect(resolveRange({ to }, options)).toEqual({
      from: new Date('2026-11-04T00:00:00.000Z'),
      to,
    });
  });

  it('allows exactly maxDays and refuses more, and refuses from >= to (400)', () => {
    const to = now;
    const from = new Date(now.getTime() - 31 * 86_400_000);
    expect(resolveRange({ from, to }, options)).toEqual({ from, to });
    const tooWide = new Date(from.getTime() - 1);
    expect(() => resolveRange({ from: tooWide, to }, options)).toThrow(BadRequestException);
    try {
      resolveRange({ from: tooWide, to }, options);
    } catch (error) {
      expect((error as BadRequestException).getResponse()).toMatchObject({
        message: ['to: the range may cover at most 31 days'],
      });
    }
    expect(() => resolveRange({ from: to, to }, options)).toThrow(BadRequestException);
    expect(() => resolveRange({ from: to, to }, { ...options, maxDays: 1 })).toThrow('Bad Request');
  });

  it('reuses the cursor window; other explicit values are cursor_invalid', () => {
    const window: [number, number] = [now.getTime() - 3_600_000, now.getTime()];
    const later = { ...options, now: new Date(now.getTime() + 60_000), cursorWindow: window };
    expect(rangeWindow(resolveRange({}, later))).toEqual(window);
    expect(
      rangeWindow(resolveRange({ from: new Date(window[0]), to: new Date(window[1]) }, later)),
    ).toEqual(window);
    for (const query of [{ from: new Date(window[0] + 1) }, { to: new Date(window[1] - 1) }]) {
      try {
        resolveRange(query, later);
        expect.fail('expected cursor_invalid');
      } catch (error) {
        expect(error).toBeInstanceOf(CodedHttpException);
        expect((error as CodedHttpException).code).toBe('cursor_invalid');
      }
    }
  });
});

describe('scan budget decisions (step 6.1 D5 plan 4, D6)', () => {
  const keyOf = (row: number) => row;

  it('reads the boundary at offset budget - 1', () => {
    expect(boundaryOffset(5000)).toBe(4999);
    expect(boundaryOffset(1)).toBe(0);
    expect(() => boundaryOffset(0)).toThrow();
  });

  it('a filled page continues after its last row', () => {
    expect(decideScanPage({ fetched: [9, 8, 7, 6], limit: 3, boundary: 2, keyOf })).toEqual({
      rows: 3,
      next: 7,
      budgetExhausted: false,
    });
    expect(decideScanPage({ fetched: [9, 8, 7, 6], limit: 3, boundary: null, keyOf })).toEqual({
      rows: 3,
      next: 7,
      budgetExhausted: false,
    });
  });

  it('a short page within a full window continues at the boundary (even when empty)', () => {
    expect(decideScanPage({ fetched: [9], limit: 3, boundary: 2, keyOf })).toEqual({
      rows: 1,
      next: 2,
      budgetExhausted: true,
    });
    expect(decideScanPage({ fetched: [], limit: 3, boundary: 2, keyOf })).toEqual({
      rows: 0,
      next: 2,
      budgetExhausted: true,
    });
  });

  it('a short page with the index exhausted is the last page', () => {
    expect(decideScanPage({ fetched: [9, 8, 7], limit: 3, boundary: null, keyOf })).toEqual({
      rows: 3,
      next: null,
      budgetExhausted: false,
    });
    expect(decideScanPage({ fetched: [], limit: 3, boundary: null, keyOf })).toEqual({
      rows: 0,
      next: null,
      budgetExhausted: false,
    });
  });

  it('plain keyset pages use the extra row only as a has-more marker', () => {
    expect(decideKeysetPage({ fetched: [3, 2, 1], limit: 2, keyOf })).toEqual({ rows: 2, next: 2 });
    expect(decideKeysetPage({ fetched: [3, 2], limit: 2, keyOf })).toEqual({ rows: 2, next: null });
  });
});

describe('assertEcho (step 6.1 D15)', () => {
  const rows = [
    { organizationId: 7n, messageId: 1n, receivedAt: new Date(5), status: 'a' },
    { organizationId: 7n, messageId: 2n, receivedAt: new Date(5), status: 'b' },
  ];

  it('passes rows that echo the organization and the queried keys', () => {
    expect(() =>
      assertEcho('messages.list', rows, {
        organizationId: 7n,
        messageId: [1n, 2n],
        receivedAt: new Date(5),
      }),
    ).not.toThrow();
    expect(() =>
      assertEcho('x', [] as { organizationId: bigint }[], { organizationId: 1n }),
    ).not.toThrow();
  });

  it('refuses another organization or key as 503 inconsistent_read', () => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    for (const expected of [
      { organizationId: 8n },
      { organizationId: 7n, messageId: 1n },
      { organizationId: 7n, status: ['a'] },
      { organizationId: 7n, receivedAt: new Date(6) },
    ]) {
      try {
        assertEcho('messages.list', rows, expected);
        expect.fail('expected InconsistentReadError');
      } catch (error) {
        expect(error).toBeInstanceOf(InconsistentReadError);
        expect((error as CodedHttpException).getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
        expect((error as CodedHttpException).code).toBe(INCONSISTENT_READ);
        expect((error as InconsistentReadError).read).toBe('messages.list');
      }
    }
    expect(warn).toHaveBeenCalledTimes(4);
    warn.mockRestore();
  });
});
