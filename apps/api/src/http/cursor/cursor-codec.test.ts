import { createHmac, randomBytes } from 'node:crypto';
import { HttpStatus } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { CodedHttpException } from '../coded-exception';
import {
  CURSOR_INVALID,
  CURSOR_MAX_LENGTH,
  CursorCodec,
  type CursorPosition,
} from './cursor-codec';

const KEY = randomBytes(32).toString('hex');
const OTHER_KEY = randomBytes(32).toString('hex');
const NOW = Date.parse('2026-11-12T10:00:00.000Z');

function codec(overrides: { key?: string; previous?: string; ttl?: number; now?: number } = {}) {
  const metrics = { cursorRejected: { inc: vi.fn() } };
  const c = new CursorCodec(
    {
      API_CURSOR_KEY: overrides.key ?? KEY,
      API_CURSOR_KEY_PREVIOUS: overrides.previous,
      API_CURSOR_TTL_SECONDS: overrides.ttl ?? 86_400,
    },
    metrics as never,
  );
  vi.spyOn(c, 'now').mockReturnValue(overrides.now ?? NOW);
  return { c, metrics };
}

const position: CursorPosition = {
  resource: 'messages',
  organizationPublicId: '01930c2e-7d1a-7000-8000-000000000001',
  keys: ['2026-11-12T09:59:00.000Z', '123456789'],
  filterHash: '0123456789abcdef',
  direction: 'desc',
  window: [NOW - 86_400_000, NOW],
};
const expected = {
  resource: position.resource,
  organizationPublicId: position.organizationPublicId,
  filterHash: position.filterHash,
};

function rejects(fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(CodedHttpException);
    const coded = error as CodedHttpException;
    expect(coded.getStatus()).toBe(HttpStatus.BAD_REQUEST);
    expect(coded.code).toBe(CURSOR_INVALID);
    expect(coded.message).toBe('Invalid cursor');
    expect(coded.details).toEqual({});
    return;
  }
  expect.fail('expected 400 cursor_invalid');
}

function flip(text: string, index: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const current = alphabet.indexOf(text[index]!);
  return text.slice(0, index) + alphabet[(current + 1) % 64] + text.slice(index + 1);
}

describe('CursorCodec (step 6.1 D3)', () => {
  it('round-trips keys, direction, window and issue time', () => {
    const { c } = codec();
    const cursor = c.encode(position);
    expect(cursor.length).toBeLessThanOrEqual(CURSOR_MAX_LENGTH);
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/);
    expect(c.decode(cursor, expected)).toEqual({
      keys: position.keys,
      direction: 'desc',
      window: position.window,
      issuedAt: Math.floor(NOW / 1000),
    });
    const { window: _w, ...withoutWindow } = position;
    const plain = c.encode({ ...withoutWindow, direction: 'asc' });
    expect(c.decode(plain, expected)).toEqual({
      keys: position.keys,
      direction: 'asc',
      issuedAt: Math.floor(NOW / 1000),
    });
  });

  it('has exactly the documented format (payload, MAC over domain, resource, organization)', () => {
    const { c } = codec();
    const cursor = c.encode(position);
    const [payloadB64, macB64] = cursor.split('.') as [string, string];
    expect(JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'))).toEqual({
      v: 1,
      r: 'messages',
      k: position.keys,
      f: position.filterHash,
      d: 'desc',
      w: position.window,
      t: Math.floor(NOW / 1000),
    });
    const mac = createHmac('sha256', Buffer.from(KEY, 'hex'))
      .update(`eg-cursor/v1\0messages\0${position.organizationPublicId}\0${payloadB64}`)
      .digest()
      .subarray(0, 16)
      .toString('base64url');
    expect(macB64).toBe(mac);
    // The organization is bound through the MAC only, never readable in the payload.
    expect(Buffer.from(payloadB64, 'base64url').toString()).not.toContain(
      position.organizationPublicId,
    );
  });

  it('refuses a payload bit flip', () => {
    const { c, metrics } = codec();
    const cursor = c.encode(position);
    rejects(() => c.decode(flip(cursor, 5), expected));
    expect(metrics.cursorRejected.inc).toHaveBeenCalledTimes(1);
  });

  it('refuses a signature flip', () => {
    const { c } = codec();
    const cursor = c.encode(position);
    rejects(() => c.decode(flip(cursor, cursor.length - 3), expected));
  });

  it('refuses a cursor of another organization, resource or filter hash', () => {
    const { c } = codec();
    const cursor = c.encode(position);
    rejects(() =>
      c.decode(cursor, {
        ...expected,
        organizationPublicId: '01930c2e-7d1a-7000-8000-000000000002',
      }),
    );
    rejects(() => c.decode(cursor, { ...expected, resource: 'audit_logs' }));
    rejects(() => c.decode(cursor, { ...expected, filterHash: 'fedcba9876543210' }));
  });

  it('refuses an expired cursor and one issued in the future', () => {
    const cursor = codec().c.encode(position);
    expect(() => codec({ now: NOW + 86_400_000 }).c.decode(cursor, expected)).not.toThrow();
    rejects(() => codec({ now: NOW + 86_401_000 }).c.decode(cursor, expected));
    rejects(() => codec({ now: NOW - 120_000 }).c.decode(cursor, expected));
  });

  it('accepts a cursor signed with the previous key while rotating, never an unknown key', () => {
    const old = codec({ key: OTHER_KEY }).c.encode(position);
    rejects(() => codec().c.decode(old, expected));
    expect(codec({ previous: OTHER_KEY }).c.decode(old, expected).keys).toEqual(position.keys);
    // New cursors are signed with the current key.
    const fresh = codec({ previous: OTHER_KEY }).c.encode(position);
    rejects(() => codec({ key: OTHER_KEY }).c.decode(fresh, expected));
  });

  it('refuses cursors that are too long, not base64url or malformed', () => {
    const { c } = codec();
    rejects(() => c.decode('A'.repeat(CURSOR_MAX_LENGTH + 1), expected));
    rejects(() => c.decode('', expected));
    rejects(() => c.decode('not base64!.abc', expected));
    rejects(() => c.decode('abc', expected));
    rejects(() => c.decode('a.b.c', expected));
    rejects(() => c.decode(`${c.encode(position)}=`, expected));
    // A legacy v0 cursor (base64url of a decimal id) is not a v1 cursor.
    rejects(() => c.decode(Buffer.from('123').toString('base64url'), expected));
  });

  it('refuses a correctly signed payload that is not a v1 payload', () => {
    const { c } = codec();
    const sign = (payload: unknown) => {
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const mac = createHmac('sha256', Buffer.from(KEY, 'hex'))
        .update(`eg-cursor/v1\0messages\0${position.organizationPublicId}\0${payloadB64}`)
        .digest()
        .subarray(0, 16)
        .toString('base64url');
      return `${payloadB64}.${mac}`;
    };
    const base = {
      v: 1,
      r: 'messages',
      k: ['1'],
      f: position.filterHash,
      d: 'desc',
      t: NOW / 1000,
    };
    expect(c.decode(sign(base), expected).keys).toEqual(['1']);
    rejects(() => c.decode(sign({ ...base, v: 2 }), expected));
    rejects(() => c.decode(sign({ ...base, k: [] }), expected));
    rejects(() => c.decode(sign({ ...base, k: [1] }), expected));
    rejects(() => c.decode(sign({ ...base, d: 'up' }), expected));
    rejects(() => c.decode(sign({ ...base, w: [2, 1] }), expected));
    rejects(() => c.decode(sign({ ...base, extra: true }), expected));
    rejects(() => c.decode(sign([1, 2]), expected));
  });

  it('refuses to encode an invalid position (programming errors)', () => {
    const { c } = codec();
    expect(() => c.encode({ ...position, filterHash: 'nothex' })).toThrow();
    expect(() => c.encode({ ...position, resource: 'Bad Name' })).toThrow();
    expect(() => c.encode({ ...position, keys: [] })).toThrow();
    expect(() => c.encode({ ...position, organizationPublicId: '' })).toThrow();
  });
});
