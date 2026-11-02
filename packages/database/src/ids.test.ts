import { describe, expect, it } from 'vitest';
import { MAX_ID, formatId, isIdString, parseId } from './ids';

describe('formatId', () => {
  it('formats ids as canonical decimal strings', () => {
    expect(formatId(1n)).toBe('1');
    expect(formatId(1234567890123n)).toBe('1234567890123');
    expect(formatId(MAX_ID)).toBe('18446744073709551615');
  });

  it('rejects zero, negative and out-of-range values', () => {
    expect(() => formatId(0n)).toThrow(/Invalid id/);
    expect(() => formatId(-1n)).toThrow(/Invalid id/);
    expect(() => formatId(MAX_ID + 1n)).toThrow(/Invalid id/);
  });
});

describe('parseId', () => {
  it('parses canonical decimal ids', () => {
    expect(parseId('1')).toBe(1n);
    expect(parseId('42')).toBe(42n);
    expect(parseId('18446744073709551615')).toBe(MAX_ID);
  });

  it('round-trips with formatId', () => {
    for (const id of [1n, 9n, 10n, 9007199254740993n, MAX_ID]) {
      expect(parseId(formatId(id))).toBe(id);
    }
  });

  it.each([
    '',
    '0',
    '007',
    '-1',
    '+1',
    ' 1',
    '1 ',
    '1.0',
    '1e3',
    '0x10',
    'abc',
    '018446744073709551615',
    '123456789012345678901',
  ])('rejects %j', (value) => {
    expect(() => parseId(value)).toThrow(/Invalid id/);
  });

  it('rejects values above the BIGINT UNSIGNED maximum', () => {
    expect(() => parseId('18446744073709551616')).toThrow(/exceeds the BIGINT UNSIGNED maximum/);
    expect(() => parseId('99999999999999999999')).toThrow(/exceeds/);
  });
});

describe('isIdString', () => {
  it('accepts canonical ids within range', () => {
    expect(isIdString('1')).toBe(true);
    expect(isIdString('18446744073709551615')).toBe(true);
  });

  it('rejects everything else', () => {
    expect(isIdString('0')).toBe(false);
    expect(isIdString('01')).toBe(false);
    expect(isIdString('18446744073709551616')).toBe(false);
    expect(isIdString('0190a3c2-7b1e-7c2d-9f00-000000000000')).toBe(false);
  });
});
