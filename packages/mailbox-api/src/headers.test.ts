import { describe, expect, it } from 'vitest';
import {
  extractCopyHeaders,
  normalizeAddrSpec,
  parseAddressList,
  parseRfc5322Date,
  receivedHeaderDate,
} from './headers';

const CRLF = (lines: string[]): string => `${lines.join('\r\n')}\r\n`;

describe('extractCopyHeaders (D7.8, D9)', () => {
  it('reads the copy metadata with folding and several Received headers', () => {
    const headers = extractCopyHeaders(
      CRLF([
        'Received: from mx2.provider.example (mx2.provider.example [192.0.2.7])',
        '\tby mx1.provider.example with ESMTPS id ABC;',
        '\tTue, 10 Nov 2026 12:00:05 +0000',
        'Received: from mail.sender.example by mx2.provider.example; Tue, 10 Nov 2026 11:59:59 +0000',
        'From: "Doe, Jane" <Jane.Doe@Sender.EXAMPLE>',
        'To: Alex <alex@example.com>, bob@example.com,',
        ' "Team (all)" <team@Example.com>',
        'Cc: undisclosed-recipients:;',
        'Cc: carol@example.com (Carol)',
        'Subject: =?utf-8?q?Hello?=',
        '  world',
        'Date: Tue, 10 Nov 2026 13:59:00 +0200 (CEST)',
        'Message-ID:',
        ' <abc.123@mail.sender.example>',
        'Message-ID: <second@ignored.example>',
        '',
        'From: body@ignored.example',
      ]),
    );
    expect(headers).toEqual({
      messageId: '<abc.123@mail.sender.example>',
      from: 'Jane.Doe@sender.example',
      date: new Date('2026-11-10T11:59:00.000Z'),
      subject: '=?utf-8?q?Hello?=  world',
      to: ['alex@example.com', 'bob@example.com', 'team@example.com'],
      cc: ['carol@example.com'],
      topReceivedAt: new Date('2026-11-10T12:00:05.000Z'),
      complete: true,
    });
  });

  it('handles LF-only messages, missing headers and bad dates', () => {
    const headers = extractCopyHeaders(
      'Received: by host.example; not a date\nDate: 31 Feb 2026 10:00:00 +0000\nFrom: nobody\n\nbody',
    );
    expect(headers).toMatchObject({
      messageId: null,
      from: null,
      date: null,
      subject: null,
      to: [],
      cc: [],
      topReceivedAt: null,
      complete: true,
    });
  });

  it('is bounded: only complete lines within maxBytes; a block without end is incomplete', () => {
    const long = CRLF([
      'Message-ID: <id@example.com>',
      `Subject: ${'s'.repeat(2000)}`,
      'From: late@example.com',
    ]);
    const cut = extractCopyHeaders(Buffer.from(long), { maxBytes: 100 });
    expect(cut.messageId).toBe('<id@example.com>');
    expect(cut.subject).toBeNull(); // the partial Subject line is dropped
    expect(cut.from).toBeNull();
    expect(cut.complete).toBe(false);
    const full = extractCopyHeaders(long);
    expect(full.subject).toHaveLength(998);
    expect(full.complete).toBe(false);
    expect(extractCopyHeaders('\r\nFrom: body@example.com\r\n').from).toBeNull();
  });
});

describe('RFC 5322 dates', () => {
  it.each([
    ['Tue, 10 Nov 2026 12:00:00 +0000', '2026-11-10T12:00:00.000Z'],
    ['10 Nov 2026 12:00 -0130', '2026-11-10T13:30:00.000Z'],
    ['Tue, 10 Nov 26 12:00:00 GMT', '2026-11-10T12:00:00.000Z'],
    ['Tue, 10 Nov 99 12:00:00 EST', '1999-11-10T17:00:00.000Z'],
    ['Tue, 10 Nov 126 12:00:00 UT', '2026-11-10T12:00:00.000Z'],
    ['Tue,  1 Dec 2026 01:02:03 PDT (comment)', '2026-12-01T08:02:03.000Z'],
    ['Tue, 10 November 2026 12:00:00 +0000', '2026-11-10T12:00:00.000Z'],
    ['Tue, 10 Nov 2026 12:00:00 Z', '2026-11-10T12:00:00.000Z'],
    ['Tue, 10 Nov 2026 12:00:00', '2026-11-10T12:00:00.000Z'],
  ])('%s', (input, iso) => {
    expect(parseRfc5322Date(input)?.toISOString()).toBe(iso);
  });

  it.each([
    'yesterday',
    '2026-11-10T12:00:00Z',
    '32 Nov 2026 12:00:00 +0000',
    '10 Foo 2026 12:00:00 +0000',
    '10 Nov 2026 25:00:00 +0000',
    '10 Nov 2026 12:00:00 +2460',
    '29 Feb 2026 12:00:00 +0000',
    '10 Nov 2026 12:00:00 XYZ',
  ])('rejects %s', (input) => {
    expect(parseRfc5322Date(input)).toBeNull();
  });

  it('reads the date after the last semicolon of a Received value', () => {
    expect(receivedHeaderDate('from a; by b; Tue, 10 Nov 2026 12:00:00 +0000')?.getTime()).toBe(
      Date.parse('2026-11-10T12:00:00Z'),
    );
    expect(receivedHeaderDate('from a by b')).toBeNull();
  });
});

describe('addresses', () => {
  it('parses lists with groups, quotes, comments and routes', () => {
    expect(
      parseAddressList(
        'Group: a@example.com, "x, y" <b@EXAMPLE.com>;, c@example.com (C), <@relay.example:d@example.com>',
      ),
    ).toEqual(['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com']);
    expect(parseAddressList('undisclosed-recipients:;')).toEqual([]);
    expect(normalizeAddrSpec('no-at-sign')).toBeNull();
    expect(normalizeAddrSpec('a@')).toBeNull();
    expect(normalizeAddrSpec(`${'x'.repeat(400)}@example.com`)).toHaveLength(320);
  });
});
