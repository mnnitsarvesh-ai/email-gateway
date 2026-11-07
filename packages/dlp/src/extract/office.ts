import { localName, tokenizeXml } from './xml';

/**
 * OOXML and ODF text extraction from XML parts (step 4.5 D4). Part selection by entry name is
 * the caller's (`officePartRole`); these functions turn one part's XML into text or a table.
 * Every output is capped (`maxChars`), and the caps are reported as `truncated`.
 */

class TextBuilder {
  private readonly parts: string[] = [];
  length = 0;
  truncated = false;
  constructor(private readonly max: number) {}

  add(value: string): void {
    if (this.truncated || value.length === 0) return;
    if (this.length + value.length > this.max) {
      this.parts.push(value.slice(0, this.max - this.length));
      this.length = this.max;
      this.truncated = true;
      return;
    }
    this.parts.push(value);
    this.length += value.length;
  }

  newline(): void {
    if (this.parts.length > 0 && this.parts[this.parts.length - 1] !== '\n') this.add('\n');
  }

  toString(): string {
    return this.parts.join('');
  }
}

export interface PartText {
  text: string;
  truncated: boolean;
}

/** DOCX parts (`w:t` runs; `w:p` paragraphs; `w:tab`, `w:br`). */
export function wordPartText(xml: string, maxChars: number): PartText {
  const out = new TextBuilder(maxChars);
  let inText = 0;
  tokenizeXml(xml, {
    open(name, _attrs, selfClosing) {
      const local = localName(name);
      if (local === 't' && !selfClosing) inText += 1;
      else if (local === 'tab') out.add('\t');
      else if (local === 'br' || local === 'cr') out.add('\n');
    },
    close(name) {
      const local = localName(name);
      if (local === 't') inText = Math.max(0, inText - 1);
      else if (local === 'p') out.newline();
    },
    text(value) {
      if (inText > 0) out.add(value);
    },
  });
  return { text: out.toString().trim(), truncated: out.truncated };
}

/** PPTX slides and notes (`a:t`; `a:p` paragraphs; `a:br`). */
export const presentationPartText = wordPartText;

/** XLSX `xl/sharedStrings.xml`: one string per `si` (rich runs concatenated, phonetic skipped). */
export function sharedStrings(xml: string, maxStrings = 1_000_000): string[] {
  const strings: string[] = [];
  let current: string[] | null = null;
  let inText = 0;
  let phonetic = 0;
  tokenizeXml(xml, {
    open(name, _attrs, selfClosing) {
      const local = localName(name);
      if (local === 'si' && !selfClosing) current = [];
      else if (local === 'si') strings.push('');
      else if (local === 'rPh' && !selfClosing) phonetic += 1;
      else if (local === 't' && !selfClosing) inText += 1;
    },
    close(name) {
      const local = localName(name);
      if (local === 'si' && current !== null) {
        if (strings.length < maxStrings) strings.push(current.join(''));
        current = null;
      } else if (local === 'rPh') phonetic = Math.max(0, phonetic - 1);
      else if (local === 't') inText = Math.max(0, inText - 1);
    },
    text(value) {
      if (current !== null && inText > 0 && phonetic === 0) current.push(value);
    },
  });
  return strings;
}

/** Column index of a cell reference (`B3` → 1). */
export function columnIndex(ref: string): number | null {
  let col = 0;
  let i = 0;
  while (i < ref.length && i < 3) {
    const c = ref.charCodeAt(i);
    if (c < 65 || c > 90) break;
    col = col * 26 + (c - 64);
    i += 1;
  }
  return i === 0 ? null : col - 1;
}

export interface TablePart {
  text: string;
  headers: string[];
  rows: number;
  truncated: boolean;
}

/** Largest column index kept in a table row (columns beyond are dropped). */
export const MAX_TABLE_COLUMN = 255;

const rowLine = (cells: Map<number, string>): string => {
  if (cells.size === 0) return '';
  const last = Math.max(...cells.keys());
  const values: string[] = [];
  for (let c = 0; c <= last; c += 1) values.push((cells.get(c) ?? '').replace(/[\t\r\n]+/g, ' '));
  return values.join('\t');
};

/** XLSX worksheet → table (shared, inline, string and numeric `<v>` values; tab/newline). */
export function sheetTable(
  xml: string,
  shared: readonly string[],
  maxChars: number,
  maxColumns: number,
): TablePart {
  const out = new TextBuilder(maxChars);
  let headers: string[] | null = null;
  let rows = 0;
  let row: Map<number, string> | null = null;
  let cell: { col: number; type: string; value: string[] } | null = null;
  let nextCol = 0;
  let inValue = 0;
  let inInline = 0;
  const flushRow = () => {
    if (row === null) return;
    const line = rowLine(row);
    if (headers === null && row.size > 0) {
      headers = line.split('\t').slice(0, maxColumns);
    }
    if (line.length > 0) {
      out.add(line);
      out.add('\n');
      rows += 1;
    }
    row = null;
  };
  tokenizeXml(xml, {
    open(name, attrs, selfClosing) {
      const local = localName(name);
      if (local === 'row') {
        flushRow();
        row = new Map();
        nextCol = 0;
        if (selfClosing) flushRow();
      } else if (local === 'c' && row !== null) {
        const ref = attrs.get('r');
        const col = (ref ? columnIndex(ref) : null) ?? nextCol;
        nextCol = col + 1;
        cell = { col, type: attrs.get('t') ?? 'n', value: [] };
        if (selfClosing) cell = null;
      } else if (local === 'v' && !selfClosing) inValue += 1;
      else if (local === 'is' && !selfClosing) inInline += 1;
    },
    close(name) {
      const local = localName(name);
      if (local === 'row') flushRow();
      else if (local === 'c' && cell !== null && row !== null) {
        const raw = cell.value.join('');
        let value = raw;
        if (cell.type === 's') value = shared[Number(raw)] ?? '';
        else if (cell.type === 'b') value = raw === '1' ? 'TRUE' : 'FALSE';
        if (cell.col <= MAX_TABLE_COLUMN && value.length > 0) row.set(cell.col, value);
        cell = null;
      } else if (local === 'v') inValue = Math.max(0, inValue - 1);
      else if (local === 'is') inInline = Math.max(0, inInline - 1);
    },
    text(value) {
      if (cell !== null && (inValue > 0 || inInline > 0)) cell.value.push(value);
    },
  });
  flushRow();
  return {
    text: out.toString().replace(/\n$/, ''),
    headers: headers ?? [],
    rows,
    truncated: out.truncated,
  };
}

/** ODF text and presentation documents (`content.xml`, `styles.xml`). */
export function odfText(xml: string, maxChars: number): PartText {
  const out = new TextBuilder(maxChars);
  let inParagraph = 0;
  tokenizeXml(xml, {
    open(name, attrs, selfClosing) {
      if (name === 'text:p' || name === 'text:h') {
        if (!selfClosing) inParagraph += 1;
      } else if (name === 'text:tab') out.add('\t');
      else if (name === 'text:s')
        out.add(' '.repeat(Math.min(64, Number(attrs.get('text:c') ?? '1') || 1)));
      else if (name === 'text:line-break') out.add('\n');
    },
    close(name) {
      if (name === 'text:p' || name === 'text:h') {
        inParagraph = Math.max(0, inParagraph - 1);
        out.newline();
      }
    },
    text(value) {
      if (inParagraph > 0) out.add(value);
    },
  });
  return { text: out.toString().trim(), truncated: out.truncated };
}

/** ODF spreadsheets (`content.xml`): one table per `table:table`. */
export function odfTables(xml: string, maxChars: number, maxColumns: number): TablePart[] {
  const tables: TablePart[] = [];
  let out: TextBuilder | null = null;
  let headers: string[] | null = null;
  let rows = 0;
  let row: Map<number, string> | null = null;
  let col = 0;
  let cell: { col: number; repeat: number; value: string[] } | null = null;
  let inParagraph = 0;
  let used = 0;
  const flushTable = () => {
    if (out === null) return;
    const text = out.toString().replace(/\n$/, '');
    used += text.length;
    if (text.length > 0)
      tables.push({ text, headers: headers ?? [], rows, truncated: out.truncated });
    out = null;
  };
  tokenizeXml(xml, {
    open(name, attrs, selfClosing) {
      if (name === 'table:table') {
        flushTable();
        out = new TextBuilder(Math.max(0, maxChars - used));
        headers = null;
        rows = 0;
      } else if (name === 'table:table-row' && out !== null) {
        row = new Map();
        col = 0;
      } else if (
        (name === 'table:table-cell' || name === 'table:covered-table-cell') &&
        row !== null
      ) {
        const repeat = Math.min(
          Math.max(Number(attrs.get('table:number-columns-repeated') ?? '1') || 1, 1),
          64,
        );
        cell = { col, repeat, value: [] };
        col += repeat;
        if (selfClosing) cell = null;
      } else if (name === 'text:p' && !selfClosing) {
        if (cell !== null && cell.value.length > 0) cell.value.push(' ');
        inParagraph += 1;
      } else if (name === 'text:s') cell?.value.push(' ');
    },
    close(name) {
      if (name === 'text:p') inParagraph = Math.max(0, inParagraph - 1);
      else if (
        (name === 'table:table-cell' || name === 'table:covered-table-cell') &&
        cell !== null
      ) {
        const value = cell.value.join('');
        if (value.length > 0 && row !== null) {
          for (let k = 0; k < cell.repeat && cell.col + k <= MAX_TABLE_COLUMN; k += 1)
            row.set(cell.col + k, value);
        }
        cell = null;
      } else if (name === 'table:table-row' && row !== null && out !== null) {
        const line = rowLine(row);
        if (line.length > 0) {
          if (headers === null) headers = line.split('\t').slice(0, maxColumns);
          out.add(line);
          out.add('\n');
          rows += 1;
        }
        row = null;
      } else if (name === 'table:table') flushTable();
    },
    text(value) {
      if (cell !== null && inParagraph > 0) cell.value.push(value);
    },
  });
  flushTable();
  return tables;
}

export type OfficeFamily = 'docx' | 'xlsx' | 'pptx' | 'odf';

/** The role of a zip entry inside an office document, by entry name (D4 part table). */
export type OfficePartRole =
  | { family: 'docx'; part: 'body' }
  | { family: 'xlsx'; part: 'shared' }
  | { family: 'xlsx'; part: 'sheet'; order: number }
  | { family: 'pptx'; part: 'slide' | 'notes'; order: number }
  | { family: 'odf'; part: 'content' | 'styles' | 'mimetype' };

const numberIn = (name: string, prefix: string): number => {
  const digits = name.slice(prefix.length).replace(/\.xml$/, '');
  const n = Number(digits);
  return Number.isInteger(n) ? n : 1_000_000;
};

export function officePartRole(name: string): OfficePartRole | null {
  if (
    name === 'word/document.xml' ||
    /^word\/(?:header|footer)[0-9]{0,4}\.xml$/.test(name) ||
    name === 'word/footnotes.xml' ||
    name === 'word/endnotes.xml' ||
    name === 'word/comments.xml'
  ) {
    return { family: 'docx', part: 'body' };
  }
  if (name === 'xl/sharedStrings.xml') return { family: 'xlsx', part: 'shared' };
  if (/^xl\/worksheets\/sheet[0-9]{1,4}\.xml$/.test(name)) {
    return { family: 'xlsx', part: 'sheet', order: numberIn(name, 'xl/worksheets/sheet') };
  }
  if (/^ppt\/slides\/slide[0-9]{1,4}\.xml$/.test(name)) {
    return { family: 'pptx', part: 'slide', order: numberIn(name, 'ppt/slides/slide') };
  }
  if (/^ppt\/notesSlides\/notesSlide[0-9]{1,4}\.xml$/.test(name)) {
    return {
      family: 'pptx',
      part: 'notes',
      order: 10_000 + numberIn(name, 'ppt/notesSlides/notesSlide'),
    };
  }
  if (name === 'content.xml') return { family: 'odf', part: 'content' };
  if (name === 'styles.xml') return { family: 'odf', part: 'styles' };
  if (name === 'mimetype') return { family: 'odf', part: 'mimetype' };
  return null;
}

/** Order of DOCX body parts: document first, then headers, footers, notes, comments. */
export function wordPartOrder(name: string): number {
  if (name === 'word/document.xml') return 0;
  if (name.startsWith('word/header')) return 100 + numberIn(name, 'word/header');
  if (name.startsWith('word/footer')) return 200 + numberIn(name, 'word/footer');
  if (name === 'word/footnotes.xml') return 300;
  if (name === 'word/endnotes.xml') return 301;
  return 302;
}
