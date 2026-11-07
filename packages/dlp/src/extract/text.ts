/**
 * Text decoding and delimited tables (step 4.5 D4): BOM (UTF-8, UTF-16LE, UTF-16BE) → valid
 * UTF-8 → windows-1252. CSV/TSV produce a table segment: cells tab-separated, rows
 * newline-separated, the first row as headers (≤ 64 columns). Linear, bounded.
 */

export interface DecodedText {
  text: string;
  encoding: 'utf-8' | 'utf-16le' | 'utf-16be' | 'windows-1252';
}

export function decodeText(bytes: Uint8Array): DecodedText {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { text: new TextDecoder('utf-8').decode(bytes.subarray(3)), encoding: 'utf-8' };
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return { text: new TextDecoder('utf-16le').decode(bytes.subarray(2)), encoding: 'utf-16le' };
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return { text: new TextDecoder('utf-16be').decode(bytes.subarray(2)), encoding: 'utf-16be' };
  }
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), encoding: 'utf-8' };
  } catch {
    return { text: new TextDecoder('windows-1252').decode(bytes), encoding: 'windows-1252' };
  }
}

/** Caps `text` at `max` code units without splitting a surrogate pair. */
export function capText(text: string, max: number): { text: string; truncated: boolean } {
  if (text.length <= max) return { text, truncated: false };
  let end = max;
  const c = text.charCodeAt(end - 1);
  if (c >= 0xd800 && c <= 0xdbff) end -= 1;
  return { text: text.slice(0, end), truncated: true };
}

export interface TableText {
  text: string;
  headers: string[];
  rows: number;
  truncated: boolean;
}

const cleanCell = (cell: string): string => cell.replace(/[\t\r\n]+/g, ' ').trim();

/**
 * Parses CSV (RFC 4180 quoting, `,` or `;`) or TSV into tab-separated rows. `maxChars` bounds
 * the output; `maxColumns` the headers.
 */
export function delimitedToTable(
  source: string,
  delimiter: ',' | '\t' | ';',
  maxChars: number,
  maxColumns: number,
): TableText {
  const rows: string[] = [];
  let headers: string[] | null = null;
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  let length = 0;
  let truncated = false;
  const endRow = () => {
    row.push(cleanCell(cell));
    cell = '';
    if (headers === null) headers = row.slice(0, maxColumns);
    const line = row.join('\t');
    if (length + line.length + 1 > maxChars) {
      truncated = true;
    } else {
      rows.push(line);
      length += line.length + 1;
    }
    row = [];
  };
  for (let i = 0; i < source.length && !truncated; i += 1) {
    const c = source[i]!;
    if (quoted) {
      if (c === '"') {
        if (source[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        cell += c;
      }
      continue;
    }
    if (c === '"' && cell.length === 0) {
      quoted = true;
    } else if (c === delimiter) {
      row.push(cleanCell(cell));
      cell = '';
    } else if (c === '\n') {
      endRow();
    } else if (c !== '\r') {
      cell += c;
    }
  }
  if (!truncated && (cell.length > 0 || row.length > 0)) endRow();
  return { text: rows.join('\n'), headers: headers ?? [], rows: rows.length, truncated };
}

/** The delimiter of a CSV sample: `;` when it is more frequent than `,` on the first line. */
export function csvDelimiter(source: string): ',' | ';' {
  const newline = source.indexOf('\n');
  const first = source.slice(
    0,
    newline < 0 ? Math.min(source.length, 4096) : Math.min(newline, 4096),
  );
  let commas = 0;
  let semicolons = 0;
  for (const c of first) {
    if (c === ',') commas += 1;
    else if (c === ';') semicolons += 1;
  }
  return semicolons > commas ? ';' : ',';
}
