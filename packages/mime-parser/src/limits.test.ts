import { describe, expect, it } from 'vitest';
import { ATTACHMENT_FLAGS, MIME_DEFECT_CODES, MIME_LIMIT_NAMES, PARSER_VERSION } from './constants';
import { assertMimeLimits, DEFAULT_MIME_LIMITS } from './limits';

describe('constants', () => {
  it('lists the twelve limit names of design M5 in order', () => {
    expect(MIME_LIMIT_NAMES).toEqual([
      'message_size',
      'nesting_depth',
      'part_count',
      'header_count',
      'header_line_length',
      'header_block_size',
      'attachment_count',
      'attachment_size',
      'body_size',
      'decoded_ratio',
      'total_decoded_size',
      'parse_timeout',
    ]);
  });

  it('uses snake_case codes of at most 48 characters (event contract pattern), unique', () => {
    for (const list of [MIME_LIMIT_NAMES, MIME_DEFECT_CODES, ATTACHMENT_FLAGS]) {
      expect(new Set(list).size).toBe(list.length);
      for (const code of list) expect(code).toMatch(/^[a-z0-9_]{1,48}$/);
    }
    expect(PARSER_VERSION).toMatch(/^.{1,32}$/);
  });
});

describe('limits', () => {
  it('defaults to the values of design §5', () => {
    expect(DEFAULT_MIME_LIMITS).toEqual({
      maxMessageBytes: 53_477_376,
      maxDepth: 10,
      maxParts: 250,
      maxHeaders: 1000,
      maxHeaderLineBytes: 32_768,
      maxHeaderBlockBytes: 262_144,
      maxAttachments: 100,
      maxAttachmentBytes: 26_214_400,
      maxBodyBytes: 10_485_760,
      maxDecodedRatio: 1.1,
      maxTotalDecodedBytes: 104_857_600,
      parseTimeoutMs: 120_000,
      maxStoredHeaders: 200,
      filenameMaxChars: 200,
      archiveMaxEntries: 1000,
      archiveMaxRatio: 100,
      archiveMaxTotalUncompressedBytes: 1_073_741_824,
      archiveMaxCentralDirectoryBytes: 8_388_608,
    });
    expect(() => assertMimeLimits(DEFAULT_MIME_LIMITS)).not.toThrow();
  });

  it('refuses values the parser cannot work with', () => {
    expect(() => assertMimeLimits({ ...DEFAULT_MIME_LIMITS, maxParts: 0 })).toThrow(RangeError);
    expect(() => assertMimeLimits({ ...DEFAULT_MIME_LIMITS, maxDepth: 1.5 })).toThrow(RangeError);
    expect(() => assertMimeLimits({ ...DEFAULT_MIME_LIMITS, maxDecodedRatio: 0 })).toThrow(
      RangeError,
    );
    expect(() => assertMimeLimits({ ...DEFAULT_MIME_LIMITS, archiveMaxRatio: Number.NaN })).toThrow(
      RangeError,
    );
    expect(() => assertMimeLimits({ ...DEFAULT_MIME_LIMITS, filenameMaxChars: 15 })).toThrow(
      RangeError,
    );
  });
});
