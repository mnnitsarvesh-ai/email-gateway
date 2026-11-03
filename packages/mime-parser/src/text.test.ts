import { describe, expect, it } from 'vitest';
import {
  codePointLength,
  decodeUtf8Strict,
  normalizeText,
  toWellFormed,
  truncateCodePoints,
} from './text';

describe('text helpers', () => {
  it('replaces lone surrogates and keeps pairs', () => {
    expect(toWellFormed('a\uD800b\uDC00c😀')).toBe('a\uFFFDb\uFFFDc😀');
  });

  it('normalizes to NFC', () => {
    expect(normalizeText('e\u0301')).toBe('é');
  });

  it('counts and truncates code points without splitting a pair', () => {
    const value = 'a😀b😀';
    expect(codePointLength(value)).toBe(4);
    expect(truncateCodePoints(value, 2)).toEqual({ value: 'a😀', truncated: true });
    expect(truncateCodePoints(value, 4)).toEqual({ value, truncated: false });
  });

  it('decodes strict UTF-8 only', () => {
    expect(decodeUtf8Strict(Buffer.from('Grüße'))).toBe('Grüße');
    expect(decodeUtf8Strict(Buffer.from([0x47, 0xfc]))).toBeNull();
  });
});
