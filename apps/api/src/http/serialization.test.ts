import { describe, expect, it } from 'vitest';
import { formatId, toIso, toIsoOrNull } from './serialization';

describe('serialization helpers', () => {
  const date = new Date('2026-11-02T10:20:30.456Z');

  it('formats dates as ISO 8601', () => {
    expect(toIso(date)).toBe('2026-11-02T10:20:30.456Z');
    expect(toIsoOrNull(date)).toBe('2026-11-02T10:20:30.456Z');
  });

  it('maps missing dates to null', () => {
    expect(toIsoOrNull(null)).toBeNull();
    expect(toIsoOrNull(undefined)).toBeNull();
  });

  it('re-exports formatId for numeric log ids', () => {
    expect(formatId(12345678901234567890n)).toBe('12345678901234567890');
    expect(JSON.stringify({ id: formatId(1n) })).toBe('{"id":"1"}');
  });
});
