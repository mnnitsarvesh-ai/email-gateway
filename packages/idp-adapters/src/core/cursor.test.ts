import { describe, expect, it } from 'vitest';
import {
  CURSOR_MAX_LENGTH,
  CursorTooLargeError,
  companionCursor,
  cursorSeq,
  decodeCursor,
  encodeCursor,
  initialCursor,
  resolveCursor,
} from './cursor';

const V = 'msgraph-ato/1';
const NOW = new Date('2026-11-10T12:00:00.000Z');

describe('cursor codec v1 (D7.3)', () => {
  it('round-trips every field as base64url', () => {
    const cursor = {
      v: 1 as const,
      a: V,
      seq: 42,
      wm: '2026-11-10T11:00:00.000Z',
      ws: '2026-11-10T10:45:00.000Z',
      we: '2026-11-10T11:58:00.000Z',
      page: {
        next: '/api/v1.0/t/activity/feed/subscriptions/content?nextPage=3',
        blob: { id: 'b1', offset: 7 },
      },
      sw: { at: '2026-11-10T06:00:00.000Z', next: 'tok', alt: true },
      pq: ['a'.repeat(64)],
    };
    const encoded = encodeCursor(cursor);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeCursor(encoded, V)).toEqual({ ok: true, cursor });
  });

  it('bounds the size at 4 096 characters', () => {
    expect(() =>
      encodeCursor({ v: 1, a: V, seq: 1, page: 'x'.repeat(2048), sw: { next: 'y'.repeat(2048) } }),
    ).toThrow(CursorTooLargeError);
    expect(decodeCursor('A'.repeat(CURSOR_MAX_LENGTH + 1), V)).toEqual({
      ok: false,
      reason: 'cursor_invalid',
    });
  });

  it('refuses another adapter version, malformed values and unknown fields', () => {
    const other = encodeCursor({ v: 1, a: 'gws-ato/1', seq: 1 });
    expect(decodeCursor(other, V).ok).toBe(false);
    expect(decodeCursor('not base64!', V).ok).toBe(false);
    expect(
      decodeCursor(Buffer.from('{"v":2,"a":"msgraph-ato/1","seq":1}').toString('base64url'), V).ok,
    ).toBe(false);
    expect(
      decodeCursor(
        Buffer.from('{"v":1,"a":"msgraph-ato/1","seq":1,"x":1}').toString('base64url'),
        V,
      ).ok,
    ).toBe(false);
    expect(decodeCursor(Buffer.from('[1]').toString('base64url'), V).ok).toBe(false);
    expect(decodeCursor('', V).ok).toBe(false);
  });

  it('restarts an invalid cursor at now − overlap with a seq above any page counter', () => {
    const fresh = resolveCursor(null, V, NOW);
    expect(fresh).toEqual({ cursor: { v: 1, a: V, seq: 0 }, reset: false });
    const reset = resolveCursor('garbage', V, NOW);
    expect(reset.reset).toBe(true);
    expect(reset.cursor.wm).toBeUndefined(); // the window starts at now − overlap, never the epoch
    expect(reset.cursor.seq).toBe(Math.floor(NOW.getTime() / 1000));
  });

  it('reads the seq of cursors and builds initial and companion cursors', () => {
    const start = initialCursor(V, new Date('2026-11-03T12:00:00.000Z'), 9);
    expect(cursorSeq(start, V)).toBe(9);
    expect(cursorSeq(null, V)).toBe(0);
    expect(cursorSeq('bad', V)).toBe(0);
    expect(companionCursor('risk_events')).toBe('companion:v1:risk_events');
  });
});
