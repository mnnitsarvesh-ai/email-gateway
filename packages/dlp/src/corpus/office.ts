import { ZipFile } from 'yazl';

/**
 * Synthetic office documents and archives of the fixture corpus (step 4.5 §9): DOCX (body,
 * header, footnote), XLSX (shared strings, numeric cells, header row), PPTX (slide + notes),
 * ODT (stored `mimetype` first, content, styles), ODS, ZIP and nested ZIP, built in memory
 * with yazl 3.3.1. Minimal but well-formed OOXML/ODF packages.
 */

export interface ZipEntryInput {
  name: string;
  data: Buffer | string;
  /** Store without compression (ODF `mimetype`). */
  store?: boolean;
}

const FIXED_DATE = new Date('2026-01-01T00:00:00Z');

export function buildZip(entries: readonly ZipEntryInput[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const zip = new ZipFile();
    const chunks: Buffer[] = [];
    zip.outputStream.on('data', (chunk: Buffer) => chunks.push(chunk));
    zip.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
    zip.outputStream.on('error', reject);
    for (const entry of entries) {
      const data = typeof entry.data === 'string' ? Buffer.from(entry.data, 'utf8') : entry.data;
      zip.addBuffer(data, entry.name, { compress: entry.store !== true, mtime: FIXED_DATE });
    }
    zip.end();
  });
}

/** Sets the "encrypted" general-purpose flag on every entry (local and central headers). */
export function markZipEncrypted(zip: Buffer): Buffer {
  const out = Buffer.from(zip);
  for (let i = 0; i + 4 <= out.length; i += 1) {
    const sig = out.readUInt32LE(i);
    if (sig === 0x04034b50) out.writeUInt16LE(out.readUInt16LE(i + 6) | 1, i + 6);
    else if (sig === 0x02014b50) out.writeUInt16LE(out.readUInt16LE(i + 8) | 1, i + 8);
  }
  return out;
}

const xmlEscape = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
const paragraphs = (lines: readonly string[]) =>
  lines
    .map((l) => `<w:p><w:r><w:t xml:space="preserve">${xmlEscape(l)}</w:t></w:r></w:p>`)
    .join('');

export interface DocxInput {
  body: readonly string[];
  header?: readonly string[];
  footnote?: readonly string[];
  /** Adds `word/media/image1.png` (an embedded image). */
  image?: Buffer;
}

export function buildDocx(input: DocxInput): Promise<Buffer> {
  const overrides = [
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>',
  ];
  const entries: ZipEntryInput[] = [
    {
      name: '[Content_Types].xml',
      data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>${overrides.join('')}</Types>`,
    },
    {
      name: '_rels/.rels',
      data: '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
    },
    {
      name: 'word/document.xml',
      data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="${W}"><w:body>${paragraphs(input.body)}<w:sectPr/></w:body></w:document>`,
    },
    {
      name: 'word/styles.xml',
      data: `<?xml version="1.0"?><w:styles xmlns:w="${W}"><w:style w:styleId="Normal"><w:name w:val="Normal"/></w:style></w:styles>`,
    },
    {
      name: 'docProps/app.xml',
      data: '<?xml version="1.0"?><Properties><Application>Synthetic Writer</Application></Properties>',
    },
  ];
  if (input.header) {
    entries.push({
      name: 'word/header1.xml',
      data: `<?xml version="1.0"?><w:hdr xmlns:w="${W}">${paragraphs(input.header)}</w:hdr>`,
    });
  }
  if (input.footnote) {
    entries.push({
      name: 'word/footnotes.xml',
      data: `<?xml version="1.0"?><w:footnotes xmlns:w="${W}"><w:footnote w:id="1">${paragraphs(input.footnote)}</w:footnote></w:footnotes>`,
    });
  }
  if (input.image) entries.push({ name: 'word/media/image1.png', data: input.image });
  return buildZip(entries);
}

export interface XlsxInput {
  /** Rows of cells; numbers become numeric cells, strings shared strings. */
  rows: readonly (readonly (string | number)[])[];
}

const columnName = (index: number): string => {
  let n = index + 1;
  let out = '';
  while (n > 0) {
    const r = (n - 1) % 26;
    out = String.fromCharCode(65 + r) + out;
    n = Math.floor((n - 1) / 26);
  }
  return out;
};

export function buildXlsx(input: XlsxInput): Promise<Buffer> {
  const shared: string[] = [];
  const indexOf = (value: string) => {
    let i = shared.indexOf(value);
    if (i < 0) {
      shared.push(value);
      i = shared.length - 1;
    }
    return i;
  };
  const rows = input.rows
    .map((row, r) => {
      const cells = row
        .map((value, c) => {
          const ref = `${columnName(c)}${r + 1}`;
          return typeof value === 'number'
            ? `<c r="${ref}"><v>${value}</v></c>`
            : `<c r="${ref}" t="s"><v>${indexOf(value)}</v></c>`;
        })
        .join('');
      return `<row r="${r + 1}">${cells}</row>`;
    })
    .join('');
  const S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  return buildZip([
    {
      name: '[Content_Types].xml',
      data: '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>',
    },
    {
      name: 'xl/workbook.xml',
      data: `<?xml version="1.0"?><workbook xmlns="${S}"><sheets><sheet name="Sheet1" sheetId="1"/></sheets></workbook>`,
    },
    {
      name: 'xl/sharedStrings.xml',
      data: `<?xml version="1.0"?><sst xmlns="${S}" count="${shared.length}">${shared.map((s) => `<si><t>${xmlEscape(s)}</t></si>`).join('')}</sst>`,
    },
    {
      name: 'xl/worksheets/sheet1.xml',
      data: `<?xml version="1.0"?><worksheet xmlns="${S}"><sheetData>${rows}</sheetData></worksheet>`,
    },
  ]);
}

export function buildPptx(
  slides: readonly (readonly string[])[],
  notes: readonly string[] = [],
): Promise<Buffer> {
  const A = 'http://schemas.openxmlformats.org/drawingml/2006/main';
  const text = (lines: readonly string[]) =>
    lines.map((l) => `<a:p><a:r><a:t>${xmlEscape(l)}</a:t></a:r></a:p>`).join('');
  const entries: ZipEntryInput[] = [
    {
      name: '[Content_Types].xml',
      data: '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/></Types>',
    },
    {
      name: 'ppt/presentation.xml',
      data: '<?xml version="1.0"?><p:presentation xmlns:p="urn:p"/>',
    },
    ...slides.map((lines, i) => ({
      name: `ppt/slides/slide${i + 1}.xml`,
      data: `<?xml version="1.0"?><p:sld xmlns:p="urn:p" xmlns:a="${A}"><p:cSld><p:spTree><p:sp><p:txBody>${text(lines)}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`,
    })),
  ];
  if (notes.length > 0) {
    entries.push({
      name: 'ppt/notesSlides/notesSlide1.xml',
      data: `<?xml version="1.0"?><p:notes xmlns:p="urn:p" xmlns:a="${A}"><p:cSld><p:spTree><p:sp><p:txBody>${text(notes)}</p:txBody></p:sp></p:spTree></p:cSld></p:notes>`,
    });
  }
  return buildZip(entries);
}

const ODF_NS =
  'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"';

export function buildOdt(body: readonly string[], footer: readonly string[] = []): Promise<Buffer> {
  const p = (lines: readonly string[]) =>
    lines.map((l) => `<text:p>${xmlEscape(l)}</text:p>`).join('');
  return buildZip([
    { name: 'mimetype', data: 'application/vnd.oasis.opendocument.text', store: true },
    {
      name: 'META-INF/manifest.xml',
      data: '<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:m"/>',
    },
    {
      name: 'content.xml',
      data: `<?xml version="1.0"?><office:document-content ${ODF_NS}><office:body><office:text>${p(body)}</office:text></office:body></office:document-content>`,
    },
    {
      name: 'styles.xml',
      data: `<?xml version="1.0"?><office:document-styles ${ODF_NS}><office:master-styles><style:master-page><style:footer>${p(footer)}</style:footer></style:master-page></office:master-styles></office:document-styles>`,
    },
  ]);
}

export function buildOds(rows: readonly (readonly string[])[]): Promise<Buffer> {
  const table = rows
    .map(
      (row) =>
        `<table:table-row>${row.map((c) => `<table:table-cell><text:p>${xmlEscape(c)}</text:p></table:table-cell>`).join('')}</table:table-row>`,
    )
    .join('');
  return buildZip([
    { name: 'mimetype', data: 'application/vnd.oasis.opendocument.spreadsheet', store: true },
    {
      name: 'content.xml',
      data: `<?xml version="1.0"?><office:document-content ${ODF_NS}><office:body><office:spreadsheet><table:table table:name="Sheet1">${table}</table:table></office:spreadsheet></office:body></office:document-content>`,
    },
  ]);
}

/** A 1×1 PNG (signature + IHDR + IDAT + IEND), for image fixtures. */
export const TINY_PNG = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082',
  'hex',
);

/** An OLE compound file header (legacy .doc), for unsupported-type fixtures. */
export const OLE_HEADER = Buffer.concat([
  Buffer.from('d0cf11e0a1b11ae1', 'hex'),
  Buffer.alloc(504),
]);
