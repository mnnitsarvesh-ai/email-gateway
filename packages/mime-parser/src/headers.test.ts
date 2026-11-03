import { describe, expect, it } from 'vitest';
import type { MimeDefectCode } from './constants';
import {
  checkHeaderBlock,
  decodeHeaderValue,
  extractTopLevelHeaders,
  HEADER_VALUE_MAX_CODE_POINTS,
  type RawHeaderLine,
} from './headers';
import { DEFAULT_MIME_LIMITS } from './limits';

const line = (raw: string): RawHeaderLine => ({
  key: raw.slice(0, raw.indexOf(':')).trim().toLowerCase(),
  line: raw,
});
const latin1Line = (bytes: Buffer): RawHeaderLine => line(bytes.toString('latin1'));

function decode(raw: string | Buffer): { value: string; defects: MimeDefectCode[] } {
  const defects = new Set<MimeDefectCode>();
  const text = typeof raw === 'string' ? raw : raw.toString('latin1');
  const { value } = decodeHeaderValue(text, HEADER_VALUE_MAX_CODE_POINTS, defects);
  return { value, defects: [...defects] };
}

describe('decodeHeaderValue', () => {
  it('unfolds and trims', () => {
    expect(decode('Subject: one\r\n two\r\n\tthree  ')).toEqual({
      value: 'one two\tthree',
      defects: [],
    });
  });

  it('decodes RFC 2047 words in UTF-8, ISO-8859-1, Shift_JIS and KOI8-R', () => {
    expect(decode('Subject: =?UTF-8?B?w5xiZXJ3ZWlzdW5nIOKckw==?=').value).toBe('Überweisung ✓');
    expect(decode('Subject: =?ISO-8859-1?Q?Andr=E9_M=FCller?=').value).toBe('André Müller');
    expect(decode('Subject: =?Shift_JIS?B?k/qWe4zq?=').value).toBe('日本語');
    expect(decode('Subject: =?KOI8-R?Q?=F0=D2=C9=D7=C5=D4?=').value).toBe('Привет');
    expect(decode('Subject: =?utf-8?q?a?= =?utf-8?q?b?=').value).toBe('ab');
  });

  it('flags an unknown encoded-word charset and keeps going', () => {
    const result = decode('Subject: =?x-unknown?Q?abc?=');
    expect(result.defects).toContain('unknown_charset');
    expect(result.value).toBe('abc');
  });

  it('leaves broken encoded words raw and flags them', () => {
    for (const raw of [
      'Subject: =?utf-8?Q?bad=ZZ?=',
      'Subject: =?utf-8?B?not-base64!?=',
      'Subject: =?utf-8?Q?unterminated',
    ]) {
      expect(decode(raw).defects, raw).toContain('invalid_encoded_word');
    }
    expect(decode('Subject: =?utf-8?Q?unterminated').value).toBe('=?utf-8?Q?unterminated');
  });

  it('keeps raw UTF-8 (RFC 6532) and reads invalid 8-bit as latin1 with unknown_charset', () => {
    expect(decode(Buffer.from('Subject: Grüße 👋')).value).toBe('Grüße 👋');
    const latin = decode(Buffer.concat([Buffer.from('Subject: caf'), Buffer.from([0xe9])]));
    expect(latin).toEqual({ value: 'café', defects: ['unknown_charset'] });
  });

  it('normalizes to NFC', () => {
    expect(decode(Buffer.from('Subject: Cafe\u0301')).value).toBe('Café');
  });

  it('replaces controls (not HT) with U+FFFD and flags bidi controls but keeps them', () => {
    expect(decode(Buffer.from('Subject: a\u0000b\u0007c\td\u007Fe\u0085'))).toEqual({
      value: 'a\uFFFDb\uFFFDc\td\uFFFDe\uFFFD',
      defects: ['header_control_chars'],
    });
    const bidi = decode(Buffer.from('Subject: invoice\u202Efdp.exe'));
    expect(bidi).toEqual({ value: 'invoice\u202Efdp.exe', defects: ['header_bidi_control'] });
  });

  it('truncates at a code-point boundary', () => {
    const defects = new Set<MimeDefectCode>();
    const value = `${'a'.repeat(2047)}😀😀`;
    const result = decodeHeaderValue(`X: ${Buffer.from(value).toString('latin1')}`, 2048, defects);
    expect(result).toEqual({ value: `${'a'.repeat(2047)}😀`, truncated: true });
  });
});

describe('checkHeaderBlock', () => {
  const limits = { ...DEFAULT_MIME_LIMITS, maxHeaders: 3, maxHeaderLineBytes: 20 };

  it('counts fields against maxHeaders (limit passes, limit + 1 fails)', () => {
    const three = [line('A: 1'), line('B: 2'), line('C: 3')];
    expect(checkHeaderBlock(three, limits).limit).toBeNull();
    expect(checkHeaderBlock([...three, line('D: 4')], limits).limit).toBe('header_count');
  });

  it('measures the unfolded field against maxHeaderLineBytes', () => {
    expect(checkHeaderBlock([line('Subject: 12345678901')], limits).limit).toBeNull(); // 20 bytes
    expect(checkHeaderBlock([line('Subject: 123456\r\n 7890')], limits).limit).toBeNull(); // unfolded 20
    expect(checkHeaderBlock([line('Subject: 123456789012')], limits).limit).toBe(
      'header_line_length',
    );
  });

  it('flags invalid lines, a first line that is no header and NUL bytes', () => {
    const result = checkHeaderBlock(
      [line('not a header'), line('Bad Name: x'), line('X: a\u0000b')],
      DEFAULT_MIME_LIMITS,
    );
    expect(result.firstLineInvalid).toBe(true);
    expect(result.defects).toEqual(['invalid_header_line', 'nul_bytes']);
    expect(
      checkHeaderBlock([line('From: a'), line(': empty name')], DEFAULT_MIME_LIMITS)
        .firstLineInvalid,
    ).toBe(false);
  });
});

describe('extractTopLevelHeaders', () => {
  it('stores allow-listed headers only, canonical names, in order, every occurrence', () => {
    const defects = new Set<MimeDefectCode>();
    const lines = [
      line('received: from x'),
      line('FROM: a@example.com'),
      line('authentication-results: mx; spf=pass'),
      line('X-Mailer: test'),
      line('Authentication-Results: mx; dkim=pass'),
      line('message-id: <1@x>'),
      line('return-path: <b@example.com>'),
      line('subject: hello'),
    ];
    const result = extractTopLevelHeaders(lines, DEFAULT_MIME_LIMITS, defects);
    expect(result.headers).toEqual([
      { seq: 0, name: 'From', value: 'a@example.com' },
      { seq: 1, name: 'Authentication-Results', value: 'mx; spf=pass' },
      { seq: 2, name: 'Authentication-Results', value: 'mx; dkim=pass' },
      { seq: 3, name: 'Message-ID', value: '<1@x>' },
      { seq: 4, name: 'Return-Path', value: '<b@example.com>' },
      { seq: 5, name: 'Subject', value: 'hello' },
    ]);
    expect(result.subject).toBe('hello');
    expect([...defects]).toEqual([]);
  });

  it('flags duplicate singletons but not repeated Authentication-Results', () => {
    const defects = new Set<MimeDefectCode>();
    extractTopLevelHeaders([line('Subject: a'), line('Subject: b')], DEFAULT_MIME_LIMITS, defects);
    expect([...defects]).toEqual(['duplicate_singleton_header']);
    const none = new Set<MimeDefectCode>();
    extractTopLevelHeaders(
      [line('Authentication-Results: a'), line('Authentication-Results: b')],
      DEFAULT_MIME_LIMITS,
      none,
    );
    expect([...none]).toEqual([]);
  });

  it('caps stored rows and flags the rest, but still reads the subject', () => {
    const defects = new Set<MimeDefectCode>();
    const lines = [line('To: a'), line('Cc: b'), line('Subject: late')];
    const result = extractTopLevelHeaders(
      lines,
      { ...DEFAULT_MIME_LIMITS, maxStoredHeaders: 2 },
      defects,
    );
    expect(result.headers.map((header) => header.name)).toEqual(['To', 'Cc']);
    expect(result.subject).toBe('late');
    expect([...defects]).toEqual(['stored_headers_truncated']);
  });

  it('truncates the subject at 998 and header rows at 2048 code points', () => {
    const defects = new Set<MimeDefectCode>();
    const long = 'x'.repeat(3000);
    const result = extractTopLevelHeaders(
      [latin1Line(Buffer.from(`Subject: ${long}`))],
      DEFAULT_MIME_LIMITS,
      defects,
    );
    expect(result.subject).toHaveLength(998);
    expect(result.headers[0]?.value).toHaveLength(2048);
    expect([...defects].sort()).toEqual(['header_value_truncated', 'subject_truncated']);
  });

  it('returns a null subject when there is none', () => {
    expect(
      extractTopLevelHeaders([line('From: a')], DEFAULT_MIME_LIMITS, new Set()).subject,
    ).toBeNull();
  });
});
