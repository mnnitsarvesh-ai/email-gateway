import { describe, expect, it } from 'vitest';
import { ApiError } from '@/lib/api/errors';
import { exceedsDocumentLimit, formatSize, isTooLarge, sizeAgainstLimit } from './size';

describe('policy request size (B16, §14.8)', () => {
  it('warns only above the catalogue’s document limit', () => {
    expect(exceedsDocumentLimit(150 * 1024, 262_144)).toBe(false);
    expect(exceedsDocumentLimit(262_144, 262_144)).toBe(false);
    expect(exceedsDocumentLimit(262_145, 262_144)).toBe(true);
    expect(exceedsDocumentLimit(10_000_000, undefined)).toBe(false);
  });

  it('formats the size against the limit', () => {
    expect(formatSize(512)).toBe('512 B');
    expect(sizeAgainstLimit(153_600, 262_144)).toBe('150.0 KiB of 256.0 KiB');
    expect(sizeAgainstLimit(2048, undefined)).toBe('2.0 KiB');
  });

  it('treats only 413 as the request size limit, never a 500', () => {
    expect(isTooLarge(new ApiError({ status: 413, code: 'payload_too_large', message: 'x' }))).toBe(
      true,
    );
    expect(isTooLarge(new ApiError({ status: 500, code: 'internal_error', message: 'x' }))).toBe(
      false,
    );
    expect(isTooLarge(null)).toBe(false);
  });
});
