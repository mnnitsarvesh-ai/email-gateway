import { describe, expect, it } from 'vitest';
import { HeaderScanner, headerAddress, parseFields, truncateCodePoints } from './header-scanner';

function scan(message: string | Buffer, max = 65_536, chunkSize = 7) {
  const bytes = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
  const scanner = new HeaderScanner(max);
  for (let i = 0; i < bytes.length && !scanner.done; i += chunkSize) {
    scanner.push(bytes.subarray(i, i + chunkSize));
  }
  scanner.finish();
  return scanner.result();
}

describe('HeaderScanner', () => {
  it('extracts unfolded Message-ID, Subject, From, Received count and every trace (CRLF)', () => {
    const meta = scan(
      [
        'Received: from a by b; Mon, 2 Nov 2026 10:00:00 +0000',
        'Received: from c',
        '\tby d; Mon, 2 Nov 2026 10:00:01 +0000',
        'X-Gateway-Trace: v=1; g=gw; d=in;',
        ' t=1; s=abc',
        'x-gateway-trace: second',
        'Message-ID: <id-1@example.test>',
        'Message-ID: <id-2@example.test>',
        'From: "Alice, A." <alice@example.test>',
        'Subject: Hello',
        '\tworld',
        '',
        'Subject: not a header',
        '',
      ].join('\r\n'),
    );
    expect(meta).toEqual({
      messageId: '<id-1@example.test>',
      subject: 'Hello\tworld',
      from: 'alice@example.test',
      fromValues: ['"Alice, A." <alice@example.test>'],
      receivedCount: 2,
      traces: ['v=1; g=gw; d=in; t=1; s=abc', 'second'],
      complete: true,
      truncated: false,
    });
  });

  it('handles LF line endings and a header block split across every chunk boundary', () => {
    const message = 'From: bob@example.test\nSubject: s\n\nbody\n\nmore';
    for (const size of [1, 2, 3, 5, 64]) {
      const meta = scan(message, 65_536, size);
      expect(meta.from).toBe('bob@example.test');
      expect(meta.subject).toBe('s');
      expect(meta.complete).toBe(true);
    }
  });

  it('returns nulls for missing headers and handles an empty header block', () => {
    expect(scan('\r\nbody\r\n')).toMatchObject({
      messageId: null,
      subject: null,
      from: null,
      receivedCount: 0,
      traces: [],
      complete: true,
    });
    expect(scan('X-Only: yes')).toMatchObject({ complete: false, truncated: false });
    expect(scan('X-Only: yes').messageId).toBeNull();
  });

  it('stops at INGEST_HEADER_MAX_BYTES and parses only complete lines', () => {
    const big = `Subject: first\r\nX-Pad: ${'a'.repeat(2_000)}\r\nFrom: late@example.test\r\n\r\nbody`;
    const meta = scan(big, 1_024, 100);
    expect(meta.truncated).toBe(true);
    expect(meta.complete).toBe(false);
    expect(meta.subject).toBe('first');
    expect(meta.from).toBeNull();
  });

  it('keeps raw encoded-words and cuts Subject at 998 characters without splitting a code point', () => {
    const encoded = scan('Subject: =?UTF-8?B?w6TDtsO8?=\r\n\r\n');
    expect(encoded.subject).toBe('=?UTF-8?B?w6TDtsO8?=');
    const long = scan(`Subject: ${'x'.repeat(997)}😀😀\r\n\r\n`);
    expect([...long.subject!].length).toBe(998);
    expect(long.subject!.endsWith('x😀')).toBe(true);
    const utf8 = scan(`Subject: ${'ä'.repeat(1_200)}\r\n\r\n`);
    expect(utf8.subject).toBe('ä'.repeat(998));
  });

  it('limits From to 320 characters and Message-ID to 998', () => {
    const meta = scan(`From: ${'f'.repeat(400)}\r\nMessage-ID: <${'m'.repeat(1_100)}>\r\n\r\n`);
    expect(meta.from).toHaveLength(320);
    expect(meta.messageId).toHaveLength(998);
  });

  it('ignores lines that are neither fields nor continuations', () => {
    expect(parseFields('From sender Mon Nov  2\r\nSubject: ok\r\n')).toEqual([
      { name: 'subject', value: 'ok' },
    ]);
  });

  it('helpers', () => {
    expect(headerAddress('Bob <bob@x.test> (comment)')).toBe('bob@x.test');
    expect(headerAddress(' bare@x.test ')).toBe('bare@x.test');
    expect(truncateCodePoints('ab😀c', 3)).toBe('ab😀');
    expect(truncateCodePoints('abc', 5)).toBe('abc');
  });
});
