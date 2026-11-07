import { describe, expect, it } from 'vitest';
import { buildDocx, buildOdt, buildPptx, buildXlsx, buildZip, TINY_PNG } from '../corpus/office';
import { buildPdf } from '../corpus/pdf-writer';
import { extractFixture } from '../test-support/pipeline.test-support';
import {
  columnIndex,
  odfTables,
  officePartRole,
  sharedStrings,
  sheetTable,
  wordPartText,
} from './office';
import { extractPdfText, loadPdfjs } from './pdf';
import { ExtractionSession, extractAttachment, formatOf, textFormat } from './session';
import { capText, csvDelimiter, decodeText, delimitedToTable } from './text';
import { XmlParseError, decodeEntities, tokenizeXml, type XmlHandler } from './xml';

const collect = (): XmlHandler & { events: string[] } => {
  const events: string[] = [];
  return {
    events,
    open: (name, attrs, self) =>
      events.push(
        `<${name}${[...attrs].map(([k, v]) => ` ${k}=${v}`).join('')}${self ? '/' : ''}>`,
      ),
    close: (name) => events.push(`</${name}>`),
    text: (value) => events.push(value),
  };
};

describe('text decoding (D4)', () => {
  it('honours BOMs, valid UTF-8 and falls back to windows-1252', () => {
    expect(decodeText(Buffer.from('﻿हिंदी', 'utf8'))).toEqual({ text: 'हिंदी', encoding: 'utf-8' });
    expect(
      decodeText(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('abc', 'utf16le')])),
    ).toEqual({ text: 'abc', encoding: 'utf-16le' });
    const be = Buffer.from('abc', 'utf16le').swap16();
    expect(decodeText(Buffer.concat([Buffer.from([0xfe, 0xff]), be]))).toEqual({
      text: 'abc',
      encoding: 'utf-16be',
    });
    expect(decodeText(Buffer.from('café', 'utf8')).encoding).toBe('utf-8');
    expect(decodeText(Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x80]))).toEqual({
      text: 'café€',
      encoding: 'windows-1252',
    });
  });
  it('caps text without splitting a surrogate pair', () => {
    expect(capText('ab😀', 3)).toEqual({ text: 'ab', truncated: true });
    expect(capText('abc', 3)).toEqual({ text: 'abc', truncated: false });
  });
});

describe('CSV / TSV tables', () => {
  it('parses quoted fields into tab-separated rows with headers', () => {
    const table = delimitedToTable('name,"note, quoted",card\r\n"A ""B""",x,1\n', ',', 1000, 64);
    expect(table).toEqual({
      text: 'name\tnote, quoted\tcard\nA "B"\tx\t1',
      headers: ['name', 'note, quoted', 'card'],
      rows: 2,
      truncated: false,
    });
    expect(csvDelimiter('a;b;c\n1;2;3')).toBe(';');
    expect(delimitedToTable('a\tb\n1\t2', '\t', 1000, 1).headers).toEqual(['a']);
    expect(delimitedToTable('aaaa\nbbbb\ncccc', ',', 9, 64)).toMatchObject({
      truncated: true,
      rows: 1,
    });
  });
});

describe('XML tokenizer', () => {
  it('decodes the predefined and numeric entities only', () => {
    expect(decodeEntities('&lt;a&gt; &amp; &quot;&apos; &#65;&#x42; &unknown; &#xD800; &')).toBe(
      `<a> & "' AB &unknown; &#xD800; &`,
    );
  });
  it('emits elements, attributes, text and CDATA; skips comments and PIs', () => {
    const h = collect();
    tokenizeXml(
      '<?xml version="1.0"?><!-- c --><a x="1 &amp; 2"><b/>t&lt;<![CDATA[<raw>]]></a>',
      h,
    );
    expect(h.events).toEqual(['<a x=1 & 2>', '<b/>', '</b>', 't<', '<raw>', '</a>']);
  });
  it('refuses DOCTYPE (so billion-laughs input never expands) and malformed input', () => {
    const laughs =
      '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>';
    expect(() => tokenizeXml(laughs, collect())).toThrow(XmlParseError);
    try {
      tokenizeXml(laughs, collect());
    } catch (error) {
      expect((error as XmlParseError).reason).toBe('doctype');
    }
    expect(() => tokenizeXml('<a><!-- open', collect())).toThrow(/malformed/);
    expect(() => tokenizeXml('<a attr="x', collect())).toThrow(/malformed/);
    expect(() => tokenizeXml('<a/>', collect(), 3)).toThrow(/too_large/);
  });
  it('handles deep nesting without recursion and stays linear on 10 MB', () => {
    const deep = '<a>'.repeat(100_000) + 'x' + '</a>'.repeat(100_000);
    let opens = 0;
    tokenizeXml(deep, { open: () => (opens += 1), close: () => undefined, text: () => undefined });
    expect(opens).toBe(100_000);
    const big = `<r>${'<c t="s"><v>12345</v></c>'.repeat(400_000)}</r>`;
    expect(big.length).toBeGreaterThan(10_000_000);
    const started = performance.now();
    let texts = 0;
    tokenizeXml(big, { open: () => undefined, close: () => undefined, text: () => (texts += 1) });
    expect(texts).toBe(400_000);
    expect(performance.now() - started).toBeLessThan(10_000);
  });
});

describe('office parts', () => {
  it('selects parts by name', () => {
    expect(officePartRole('word/document.xml')).toEqual({ family: 'docx', part: 'body' });
    expect(officePartRole('word/header2.xml')).toEqual({ family: 'docx', part: 'body' });
    expect(officePartRole('word/styles.xml')).toBeNull();
    expect(officePartRole('xl/worksheets/sheet3.xml')).toEqual({
      family: 'xlsx',
      part: 'sheet',
      order: 3,
    });
    expect(officePartRole('ppt/slides/slide2.xml')).toEqual({
      family: 'pptx',
      part: 'slide',
      order: 2,
    });
    expect(officePartRole('content.xml')).toEqual({ family: 'odf', part: 'content' });
  });
  it('extracts DOCX runs, tabs and breaks', () => {
    const xml =
      '<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:tab/><w:t xml:space="preserve"> world</w:t></w:r></w:p><w:p><w:r><w:t>Two</w:t><w:br/><w:t>Three</w:t></w:r></w:p></w:body></w:document>';
    expect(wordPartText(xml, 1000)).toEqual({
      text: 'Hello\t world\nTwo\nThree',
      truncated: false,
    });
    expect(wordPartText(xml, 5)).toEqual({ text: 'Hello', truncated: true });
  });
  it('extracts XLSX shared, inline, numeric and boolean cells by column', () => {
    const shared = sharedStrings(
      '<sst><si><t>Name</t></si><si><r><t>P</t></r><r><t>AN</t></r><rPh><t>x</t></rPh></si></sst>',
    );
    expect(shared).toEqual(['Name', 'PAN']);
    const sheet =
      '<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1" t="s"><v>1</v></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>Asha</t></is></c><c r="B2"><v>42</v></c><c r="C2" t="b"><v>1</v></c></row></sheetData></worksheet>';
    expect(sheetTable(sheet, shared, 1000, 64)).toEqual({
      text: 'Name\t\tPAN\nAsha\t42\tTRUE',
      headers: ['Name', '', 'PAN'],
      rows: 2,
      truncated: false,
    });
    expect(columnIndex('AB12')).toBe(27);
  });
  it('extracts ODS tables with repeated columns', () => {
    const xml =
      '<office:document-content><table:table><table:table-row><table:table-cell><text:p>a</text:p></table:table-cell><table:table-cell table:number-columns-repeated="2"><text:p>b</text:p></table:table-cell></table:table-row></table:table></office:document-content>';
    expect(odfTables(xml, 1000, 64)).toEqual([
      { text: 'a\tb\tb', headers: ['a', 'b', 'b'], rows: 1, truncated: false },
    ]);
  });
});

describe('formats', () => {
  it('maps types and extensions to extraction formats', () => {
    expect(textFormat('text', 'csv', null)).toBe('csv');
    expect(textFormat('text', null, 'text/tab-separated-values')).toBe('tsv');
    expect(textFormat('text', 'py', null)).toBe('source');
    expect(textFormat('script_js', null, null)).toBe('source');
    expect(formatOf('png', 'png', null)).toBe('image');
    expect(formatOf('ole_office', 'doc', null)).toBe('unsupported');
    expect(formatOf('rtf', 'rtf', null)).toBe('unsupported');
    expect(formatOf('odf', null, null, 'spreadsheet')).toBe('ods');
  });
});

describe('pdfjs wrapper (pdfjs-dist 4.10.38 legacy)', () => {
  it('loads pdfjs with the pinned version', async () => {
    expect((await loadPdfjs()).version).toBe('4.10.38');
  });
  it('extracts pages, honours the page and character caps', async () => {
    const pdf = buildPdf([
      ['Page one has synthetic text'],
      ['Page two has synthetic text'],
      ['Page three text'],
    ]);
    expect(await extractPdfText(pdf, 200, 1e6)).toMatchObject({
      status: 'extracted',
      numPages: 3,
      truncated: false,
    });
    const capped = await extractPdfText(pdf, 2, 1e6);
    expect(capped).toMatchObject({ status: 'extracted', truncated: true });
    expect(capped.pages).toHaveLength(2);
    expect((await extractPdfText(pdf, 200, 30)).truncated).toBe(true);
  });
  it('maps encryption, missing text layers and parse errors', async () => {
    expect(
      await extractPdfText(buildPdf([['secret']], { userPassword: 'pw' }), 10, 1e6),
    ).toMatchObject({ status: 'not_extracted', reasons: ['encrypted'] });
    expect(await extractPdfText(buildPdf([[]], { imageOnly: true }), 10, 1e6)).toMatchObject({
      status: 'not_extracted',
      reasons: ['no_text_layer'],
    });
    expect(await extractPdfText(buildPdf([['short']]), 10, 1e6)).toMatchObject({
      reasons: ['no_text_layer'],
    });
    expect(await extractPdfText(Buffer.from('%PDF-1.4 garbage'), 10, 1e6)).toMatchObject({
      status: 'not_extracted',
      reasons: ['parse_error'],
    });
  });
  it('the RC4 encryption of the corpus writer is valid (opens with the password)', async () => {
    const pdfjs = await loadPdfjs();
    const doc = await pdfjs.getDocument({
      data: new Uint8Array(
        buildPdf([['Password protected synthetic text']], { userPassword: 'pw' }),
      ),
      password: 'pw',
      isEvalSupported: false,
      verbosity: 0,
    }).promise;
    const page = await doc.getPage(1);
    const text = (await page.getTextContent()).items.map((i) => i.str).join('');
    expect(text).toBe('Password protected synthetic text');
    await doc.destroy();
  });
});

describe('extraction session', () => {
  it('extracts text attachments, CSV tables, HTML (raw) and message/rfc822 (partial)', async () => {
    expect(
      await extractAttachment(Buffer.from('plain body'), 'text', {
        declaredContentType: null,
        filenameExt: 'txt',
      }),
    ).toMatchObject({
      status: 'extracted',
      format: 'text',
      segments: [{ path: 'attachment', kind: 'text', text: 'plain body', truncated: false }],
    });
    const csv = await extractAttachment(Buffer.from('a,b\n1,2'), 'text', {
      declaredContentType: 'text/csv',
      filenameExt: null,
    });
    expect(csv.segments[0]).toMatchObject({
      kind: 'table',
      format: 'csv',
      headers: ['a', 'b'],
      text: 'a\tb\n1\t2',
    });
    const html = await extractAttachment(Buffer.from('<html><b>x</b></html>'), 'html', {
      declaredContentType: 'text/html',
      filenameExt: 'html',
    });
    expect(html.segments[0]).toMatchObject({ kind: 'html', text: '<html><b>x</b></html>' });
    const eml = await extractAttachment(Buffer.from('Subject: hi\n\nbody'), 'eml', {
      declaredContentType: 'message/rfc822',
      filenameExt: 'eml',
    });
    expect(eml).toMatchObject({ status: 'partial', format: 'eml', reasons: ['unsupported_type'] });
    expect(
      await extractAttachment(TINY_PNG, 'png', {
        declaredContentType: 'image/png',
        filenameExt: 'png',
      }),
    ).toMatchObject({ status: 'not_extracted', reasons: ['image'], segments: [] });
    await expect(
      extractAttachment(Buffer.from('x'), 'zip', { declaredContentType: null, filenameExt: null }),
    ).rejects.toThrow(/walker/);
  });

  it('caps text per attachment and segments, marking truncation', async () => {
    const long = await new ExtractionSession(
      { declaredContentType: null, filenameExt: 'txt' },
      { maxTextChars: 5 },
    ).finish(Buffer.from('abcdefgh'), 'text');
    expect(long).toMatchObject({
      status: 'partial',
      segments: [{ text: 'abcde', truncated: true }],
    });
    const zip = await buildZip(
      Array.from({ length: 4 }, (_, i) => ({ name: `n${i}.txt`, data: `note ${i}` })),
    );
    const session = new ExtractionSession(
      { declaredContentType: null, filenameExt: 'zip' },
      { maxSegments: 2 },
    );
    const { testWalk } = await import('../test-support/walker.test-support');
    const { detected, walk } = await testWalk(zip, session.visitor);
    const result = await session.finish(zip, detected, walk);
    expect(result.segments).toHaveLength(2);
    expect(result.segments[1]!.truncated).toBe(true);
    expect(result.status).toBe('partial');
    expect(result.entriesVisited).toBe(4);
  });

  it('addresses archive entries by index path, never by name', async () => {
    const zip = await buildZip([
      { name: 'secret-plan-name.txt', data: 'first entry' },
      { name: 'dir/inner.zip', data: await buildZip([{ name: 'x.txt', data: 'nested entry' }]) },
    ]);
    const result = await extractFixture({
      bytes: zip,
      filenameExt: 'zip',
      declaredContentType: null,
    });
    expect(result.segments.map((s) => [s.path, s.text])).toEqual([
      ['0', 'first entry'],
      ['1/0', 'nested entry'],
    ]);
    expect(JSON.stringify(result)).not.toContain('secret-plan-name');
  });

  it('extracts DOCX, XLSX, PPTX and ODT from their selected parts only', async () => {
    const docx = await extractFixture({
      bytes: await buildDocx({ body: ['Body text'], header: ['Head'], footnote: ['Foot'] }),
      filenameExt: 'docx',
      declaredContentType: null,
    });
    expect(docx).toMatchObject({
      status: 'extracted',
      format: 'docx',
      segments: [{ path: 'attachment', text: 'Body text\nHead\nFoot' }],
    });
    expect(JSON.stringify(docx)).not.toContain('Synthetic Writer'); // docProps/app.xml is not a selected part
    const xlsx = await extractFixture({
      bytes: await buildXlsx({
        rows: [
          ['Name', 'Amount'],
          ['Asha', 12],
        ],
      }),
      filenameExt: 'xlsx',
      declaredContentType: null,
    });
    expect(xlsx.segments).toEqual([
      {
        path: 'attachment',
        format: 'xlsx',
        kind: 'table',
        text: 'Name\tAmount\nAsha\t12',
        headers: ['Name', 'Amount'],
        truncated: false,
      },
    ]);
    const pptx = await extractFixture({
      bytes: await buildPptx([['Slide one'], ['Slide two']], ['Notes']),
      filenameExt: 'pptx',
      declaredContentType: null,
    });
    expect(pptx.segments[0]!.text).toBe('Slide one\nSlide two\nNotes');
    const odt = await extractFixture({
      bytes: await buildOdt(['Body'], ['Footer']),
      filenameExt: 'odt',
      declaredContentType: null,
    });
    expect(odt).toMatchObject({ format: 'odt', segments: [{ text: 'Body' }, { text: 'Footer' }] });
  });

  it('a DOCTYPE inside an office part is a parse error, never expanded', async () => {
    const bad = await buildZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      {
        name: 'word/document.xml',
        data: '<!DOCTYPE x [<!ENTITY a "aaaa">]><w:document>&a;</w:document>',
      },
    ]);
    const result = await extractFixture({
      bytes: bad,
      filenameExt: 'docx',
      declaredContentType: null,
    });
    expect(result.reasons).toContain('parse_error');
    expect(result.status).not.toBe('extracted');
  });

  it('PDF attachments', async () => {
    const result = await extractAttachment(buildPdf([['A synthetic PDF attachment']]), 'pdf', {
      declaredContentType: 'application/pdf',
      filenameExt: 'pdf',
    });
    expect(result).toMatchObject({
      status: 'extracted',
      format: 'pdf',
      segments: [{ text: 'A synthetic PDF attachment' }],
    });
  });
});
