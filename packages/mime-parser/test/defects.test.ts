import { describe, expect, it } from 'vitest';
import { MIME_DEFECT_CODES, type MimeDefectCode } from '../src/constants';
import { crlf, multipart, parse, simpleMessage } from './helpers';

/** One minimal message per design M6 code (the corpus covers them again as files). */
const CASES: Record<MimeDefectCode, string | Buffer> = {
  no_headers: crlf('', 'body starts right away'),
  invalid_header_line: simpleMessage(['From: a@example.com', 'this line is no header'], 'body'),
  missing_boundary_parameter: simpleMessage(['Content-Type: multipart/mixed'], 'content'),
  boundary_not_found: simpleMessage(
    ['Content-Type: multipart/mixed; boundary="b"'],
    'no delimiter here',
  ),
  missing_closing_boundary: multipart(
    'mixed',
    'b',
    [{ headers: ['Content-Type: text/plain'], body: 'x' }],
    { close: false },
  ),
  invalid_base64: simpleMessage(['Content-Transfer-Encoding: base64'], 'QUJD$RA=='),
  invalid_quoted_printable: simpleMessage(
    ['Content-Transfer-Encoding: quoted-printable'],
    'a =XY b',
  ),
  unknown_transfer_encoding: simpleMessage(['Content-Transfer-Encoding: x-gzip64'], 'abc'),
  unknown_charset: simpleMessage(['Content-Type: text/html; charset=x-made-up'], '<p>x</p>'),
  invalid_encoded_word: simpleMessage(['Subject: =?utf-8?B?***?='], 'b'),
  duplicate_singleton_header: simpleMessage(['Message-ID: <1@x>', 'Message-ID: <2@x>'], 'b'),
  header_control_chars: simpleMessage(['Subject: bell\u0007'], 'b'),
  header_bidi_control: Buffer.from(simpleMessage(['Subject: abc\u202Edef'], 'b')),
  header_value_truncated: simpleMessage([`To: ${'r'.repeat(2100)}`], 'b'),
  stored_headers_truncated: simpleMessage(
    Array.from({ length: 201 }, (_, index) => `Received-Via-To: x${index}`).map(
      (_, index) => `To: r${index}@x`,
    ),
    'b',
  ),
  subject_truncated: simpleMessage([`Subject: ${'s'.repeat(1000)}`], 'b'),
  nul_bytes: simpleMessage(['X-Nul: a\u0000b'], 'b'),
  empty_message: Buffer.alloc(0),
};

describe('defects (design M6)', () => {
  it('covers every defect code', () => {
    expect(Object.keys(CASES).sort()).toEqual([...MIME_DEFECT_CODES].sort());
  });

  it.each(Object.entries(CASES))('%s', async (code, message) => {
    const { result } = await parse(message);
    expect(result.defects).toContain(code);
    expect(result.status).toBe('parsed_with_defects');
  });

  it('a clean message has no defects', async () => {
    const { result } = await parse(simpleMessage(['From: a@example.com', 'Subject: hi'], 'hello'));
    expect(result).toMatchObject({ status: 'parsed', defects: [], limitsExceeded: [] });
  });

  it('flags an inner multipart left open while the outer one closes', async () => {
    const inner = multipart(
      'alternative',
      'inner',
      [{ headers: ['Content-Type: text/plain'], body: 'x' }],
      { close: false },
    );
    const raw = inner.toString('latin1');
    const end = raw.indexOf('\r\n\r\n');
    const message = multipart('mixed', 'outer', [
      { headers: raw.slice(0, end).split('\r\n'), body: raw.slice(end + 4) },
      { headers: ['Content-Type: text/plain'], body: 'after the inner part' },
    ]);
    const { result } = await parse(message);
    expect(result.defects).toEqual(['missing_closing_boundary']);
    // mailsplit's ancestor delimiter rule still finds the part after the open inner multipart.
    expect(result.structure.map((node) => node.path)).toEqual(['0', '0.1', '0.1.1', '0.2']);
  });

  it('treats a multipart without a boundary as one leaf', async () => {
    const { result, sink } = await parse(CASES.missing_boundary_parameter);
    expect(result.structure).toHaveLength(1);
    expect(result.attachments[0]).toMatchObject({
      declaredContentType: 'multipart/mixed',
      sizeBytes: 7,
    });
    expect(sink.text(result.attachments[0]?.key)).toBe('content');
  });

  it('decodes an unknown body charset as UTF-8 with replacement characters', async () => {
    const message = Buffer.concat([
      Buffer.from(crlf('Content-Type: text/plain; charset=x-unknown', '', '')),
      Buffer.from([0x61, 0xff, 0x62]),
    ]);
    const { result, sink } = await parse(message);
    expect(result.defects).toEqual(['unknown_charset']);
    expect(sink.text(result.textBody?.key)).toBe('a\uFFFDb');
    expect(result.textBody?.charset).toBe('x-unknown');
  });
});
