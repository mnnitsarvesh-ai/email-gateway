import { describe, expect, it } from 'vitest';
import {
  isValidSignatureName,
  parseCtime,
  parseScanReply,
  parseVersion,
  ReplyReader,
  splitSessionReply,
} from './reply';

describe('parseVersion', () => {
  it('parses the clamd 1.4.6 VERSION reply', () => {
    expect(parseVersion('ClamAV 1.4.6/28173/Tue Nov  3 06:27:52 2026')).toEqual({
      engine: '1.4.6',
      dbVersion: 28173,
      dbTime: new Date('2026-11-03T06:27:52.000Z'),
    });
  });

  it('parses two-digit days and a trailing newline', () => {
    expect(parseVersion('ClamAV 1.4.6/28174/Thu Nov 12 23:59:01 2026\n')?.dbTime).toEqual(
      new Date('2026-11-12T23:59:01.000Z'),
    );
  });

  it.each([
    'ClamAV 1.4.6',
    'ClamAV 1.4.6/abc/Tue Nov  3 06:27:52 2026',
    'ClamAV 1.4.6/28173/yesterday',
    'ClamAV 1.4.6/28173/Tue Feb 31 06:27:52 2026',
    'ClamAV 1.4.6/28173/Tue Nov  3 25:27:52 2026',
    'ClamAV 1.4.6/99999999999/Tue Nov  3 06:27:52 2026',
    `ClamAV ${'9'.repeat(40)}/1/Tue Nov  3 06:27:52 2026`,
    'PONG',
    '',
  ])('rejects %j', (text) => {
    expect(parseVersion(text)).toBeNull();
  });
});

describe('parseCtime', () => {
  it('rejects malformed text', () => {
    expect(parseCtime('Tue Nov 3 06:27:52')).toBeNull();
    expect(parseCtime('Foo Nov  3 06:27:52 2026')).toBeNull();
  });
});

describe('parseScanReply', () => {
  it('maps OK, FOUND, size limit and other errors', () => {
    expect(parseScanReply('stream: OK')).toEqual({ status: 'clean' });
    expect(parseScanReply('stream: Eicar-Test-Signature FOUND')).toEqual({
      status: 'found',
      signature: 'Eicar-Test-Signature',
    });
    expect(parseScanReply('stream: Heuristics.OLE2.ContainsMacros FOUND')).toEqual({
      status: 'found',
      signature: 'Heuristics.OLE2.ContainsMacros',
    });
    expect(parseScanReply('INSTREAM size limit exceeded. ERROR')).toEqual({
      status: 'size_limit',
    });
    expect(parseScanReply("stream: Can't allocate memory ERROR")).toEqual({
      status: 'server_error',
    });
    expect(parseScanReply('COMMAND READ TIMED OUT ERROR')).toEqual({ status: 'server_error' });
  });

  it('refuses signature names outside printable ASCII or longer than 128', () => {
    expect(parseScanReply('stream: bad name FOUND')).toEqual({ status: 'invalid_signature' });
    expect(parseScanReply(`stream: ${'A'.repeat(129)} FOUND`)).toEqual({
      status: 'invalid_signature',
    });
    expect(parseScanReply('stream: Win.é FOUND')).toEqual({ status: 'invalid_signature' });
    expect(isValidSignatureName('A'.repeat(128))).toBe(true);
  });

  it('returns null for garbage', () => {
    expect(parseScanReply('hello')).toBeNull();
    expect(parseScanReply('stream: FOUND')).toBeNull();
  });
});

describe('splitSessionReply', () => {
  it('splits the id prefix', () => {
    expect(splitSessionReply('2: stream: OK')).toEqual({ id: 2, text: 'stream: OK' });
    expect(splitSessionReply('UNKNOWN COMMAND')).toEqual({ id: null, text: 'UNKNOWN COMMAND' });
  });
});

describe('ReplyReader', () => {
  it('yields complete null-terminated replies across chunks', () => {
    const reader = new ReplyReader();
    expect(reader.push(Buffer.from('1: ClamAV 1.4'))).toEqual([]);
    expect(reader.push(Buffer.from('.6\x002: stream: OK\x00'))).toEqual([
      '1: ClamAV 1.4.6',
      '2: stream: OK',
    ]);
    expect(reader.trailingBytes).toBe(0);
  });

  it('bounds reply size and count', () => {
    expect(() => new ReplyReader(16).push(Buffer.alloc(17, 0x41))).toThrow('reply_too_large');
    expect(() => new ReplyReader(16).push(Buffer.from(`${'A'.repeat(17)}\0`))).toThrow(
      'reply_too_large',
    );
    expect(() => new ReplyReader(16, 2).push(Buffer.from('a\0b\0c\0'))).toThrow('reply_too_large');
  });
});
