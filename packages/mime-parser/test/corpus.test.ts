import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { MimeDefectCode, MimeLimitName, MimeParseStatus } from '../src/constants';
import { buildCorpus, FIXTURES } from './fixtures/generate';
import { parse, sha256 } from './helpers';

const dir = join(__dirname, 'fixtures');
const read = (name: string): Buffer => readFileSync(join(dir, name));

describe('fixture corpus', () => {
  it('matches the generator byte for byte (no drift, CRLF kept)', () => {
    const corpus = buildCorpus();
    const committed = readdirSync(dir)
      .filter((name) => name.endsWith('.eml'))
      .sort();
    expect(committed).toEqual([...corpus.keys()].sort());
    for (const [name, data] of corpus) expect(read(name).equals(data), name).toBe(true);
    expect(read('alternative.eml').includes('\r\n')).toBe(true);
  });

  interface Expectation {
    status: MimeParseStatus;
    defects?: MimeDefectCode[];
    limits?: MimeLimitName[];
  }
  const expectations: Record<string, Expectation> = {
    'missing-boundary-parameter.eml': {
      status: 'parsed_with_defects',
      defects: ['missing_boundary_parameter'],
    },
    'boundary-not-found.eml': { status: 'parsed_with_defects', defects: ['boundary_not_found'] },
    'unterminated-multipart.eml': {
      status: 'parsed_with_defects',
      defects: ['missing_closing_boundary'],
    },
    'base64-truncated.eml': { status: 'parsed_with_defects', defects: ['invalid_base64'] },
    'base64-invalid-chars.eml': { status: 'parsed_with_defects', defects: ['invalid_base64'] },
    'qp-invalid.eml': { status: 'parsed_with_defects', defects: ['invalid_quoted_printable'] },
    'unknown-cte.eml': { status: 'parsed_with_defects', defects: ['unknown_transfer_encoding'] },
    'unknown-charset.eml': { status: 'parsed_with_defects', defects: ['unknown_charset'] },
    'mislabelled-charset.eml': { status: 'parsed', defects: [] },
    'garbage-binary.eml': {
      status: 'parsed_with_defects',
      defects: ['nul_bytes', 'invalid_header_line', 'no_headers'],
    },
    'empty.eml': { status: 'parsed_with_defects', defects: ['no_headers', 'empty_message'] },
    'headers-only.eml': { status: 'parsed', defects: [] },
    'no-headers.eml': { status: 'parsed_with_defects', defects: ['no_headers'] },
    'nul-in-headers.eml': {
      status: 'parsed_with_defects',
      defects: ['nul_bytes', 'header_control_chars'],
    },
    'duplicate-from-subject.eml': {
      status: 'parsed_with_defects',
      defects: ['duplicate_singleton_header'],
    },
    'nested-rfc822.eml': { status: 'parsed', defects: [] },
    'depth-at-limit.eml': { status: 'parsed', defects: [] },
    'depth-over-limit.eml': { status: 'parse_limit_exceeded', limits: ['nesting_depth'] },
    'multiple-attachments.eml': { status: 'parsed', defects: [] },
    'inline-image.eml': { status: 'parsed', defects: [] },
    'alternative.eml': { status: 'parsed', defects: [] },
    'html-only.eml': { status: 'parsed', defects: [] },
    'pdf-root.eml': { status: 'parsed', defects: [] },
    'encoded-words.eml': {
      status: 'parsed_with_defects',
      defects: ['invalid_encoded_word', 'header_control_chars', 'unknown_charset'],
    },
    'rfc2231.eml': { status: 'parsed', defects: [] },
    'raw-utf8-headers.eml': { status: 'parsed', defects: [] },
    'filename-traversal.eml': { status: 'parsed', defects: [] },
    'filename-bidi.eml': { status: 'parsed', defects: [] },
    'filename-zero-width.eml': { status: 'parsed', defects: [] },
    'filename-double-extension.eml': { status: 'parsed', defects: [] },
    'filename-reserved.eml': { status: 'parsed', defects: [] },
    'filename-long.eml': { status: 'parsed', defects: [] },
    'header-flood.eml': { status: 'parse_limit_exceeded', limits: ['header_count'] },
    'header-long-line.eml': { status: 'parse_limit_exceeded', limits: ['header_line_length'] },
    'part-flood.eml': { status: 'parse_limit_exceeded', limits: ['attachment_count'] },
  };

  it('has an expectation for every fixture', () => {
    expect(Object.keys(expectations).sort()).toEqual(Object.keys(FIXTURES).sort());
  });

  it.each(Object.entries(expectations))('%s', async (name, expected) => {
    const data = read(name);
    const { result, sink } = await parse(data);
    expect(result.status).toBe(expected.status);
    if (expected.defects) expect(result.defects).toEqual(expected.defects);
    expect(result.limitsExceeded).toEqual(expected.limits ?? []);
    // Every input byte is counted and hashed, and every stored object matches its row.
    expect(result.stats).toMatchObject({
      bytesRead: data.length,
      sha256: sha256(data),
      inputComplete: true,
    });
    for (const row of [result.textBody, result.htmlBody, ...result.attachments]) {
      if (row?.key)
        expect(sha256(sink.objects.get(row.key)?.data ?? Buffer.alloc(0))).toBe(row.sha256);
    }
    // Structure never carries names or header values.
    expect(JSON.stringify(result.structure)).not.toMatch(/filename|subject|@/i);
  });

  it('decodes the encoded-word fixture in every charset', async () => {
    const { result } = await parse(read('encoded-words.eml'));
    const value = (name: string) => result.headers.find((header) => header.name === name)?.value;
    expect(result.subject).toBe('Überweisung ✓');
    expect(value('Reply-To')).toBe('André <andre@example.com>');
    expect(value('Sender')).toBe('日本語 <jp@example.jp>');
    expect(value('Cc')).toBe('Привет <ru@example.ru>');
    expect(value('In-Reply-To')).toContain('=?utf-8?Q?unterminated');
  });

  it('keeps raw UTF-8 headers', async () => {
    const { result } = await parse(read('raw-utf8-headers.eml'));
    expect(result.subject).toBe('Grüße aus Köln 👋');
    expect(result.headers.map((header) => header.name)).toEqual([
      'From',
      'To',
      'Subject',
      'Message-ID',
    ]);
  });

  it('decodes RFC 2231 continuations with charset and RFC 2047 names', async () => {
    const { result } = await parse(read('rfc2231.eml'));
    expect(result.attachments.map((attachment) => attachment.filename)).toEqual([
      'Über den Wolken ☁.pdf',
      'Résumé.txt',
    ]);
  });

  it('sanitizes the hostile filenames', async () => {
    const names = async (file: string) =>
      (await parse(read(file))).result.attachments.map((attachment) => [
        attachment.filename,
        attachment.flags,
      ]);
    expect(await names('filename-traversal.eml')).toEqual([
      ['passwd', ['filename_path_stripped']],
      ['win.ini', ['filename_path_stripped']],
      [
        'x.exe',
        [
          'filename_path_stripped',
          'filename_executable_extension',
          'content_type_mismatch',
          'executable',
        ],
      ],
    ]);
    expect(await names('filename-bidi.eml')).toEqual([
      [
        'invoicefdp.exe',
        [
          'filename_bidi_control',
          'filename_executable_extension',
          'content_type_mismatch',
          'executable',
        ],
      ],
    ]);
    expect(await names('filename-zero-width.eml')).toEqual([
      ['report.pdf', ['filename_zero_width']],
    ]);
    expect((await names('filename-double-extension.eml')).map(([, flags]) => flags)).toEqual([
      [
        'filename_executable_extension',
        'filename_double_extension',
        'content_type_mismatch',
        'executable',
      ],
      [
        'filename_whitespace_padding',
        'filename_executable_extension',
        'filename_double_extension',
        'content_type_mismatch',
        'executable',
      ],
    ]);
    expect(await names('filename-reserved.eml')).toEqual([
      ['_CON.txt', ['filename_reserved_name']],
    ]);
    const long = await names('filename-long.eml');
    expect(long[0]?.[0]).toHaveLength(200);
    expect(long[0]?.[1]).toEqual(['filename_truncated']);
    const bidi = (await parse(read('filename-bidi.eml'))).result.attachments[0];
    expect(bidi?.originalFilename).toBe('invoice\\u{202E}fdp.exe');
  });

  it('reaches part_count on the part flood once attachments are not the first limit', async () => {
    const { result } = await parse(read('part-flood.eml'), { limits: { maxAttachments: 1000 } });
    expect(result.limitsExceeded).toEqual(['part_count']);
    expect(result.structure).toHaveLength(250);
  });
});
