import { describe, expect, it } from 'vitest';
import { uuidv7 } from './uuidv7';

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('uuidv7', () => {
  it('is an RFC 9562 version 7 UUID carrying the millisecond timestamp', () => {
    const now = Date.UTC(2026, 10, 3, 12, 0, 0, 123);
    const id = uuidv7(now);
    expect(id).toMatch(UUID_V7);
    expect(parseInt(id.replaceAll('-', '').slice(0, 12), 16)).toBe(now);
  });

  it('is unique and sortable within one millisecond and across milliseconds', () => {
    const now = Date.now() + 10_000;
    const ids = Array.from({ length: 2000 }, () => uuidv7(now));
    expect(new Set(ids).size).toBe(ids.length);
    expect([...ids].sort()).toEqual(ids);
    const later = uuidv7(now + 5000);
    expect(later > ids[ids.length - 1]!).toBe(true);
  });
});
