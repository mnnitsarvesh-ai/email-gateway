import { inflateSync } from 'node:zlib';
import { ANALYSIS_BOUNDS, type Analysis, latin1 } from './analysis';
import { hostOfAuthority } from './generic';

/**
 * PDF analyzer (step 4.6 X4 `pdf`): a name tokenizer with `#xx` decoding over the file and over
 * the decompressed object streams (`/Type /ObjStm`, FlateDecode only, bounded inflate), counts of
 * the action/content names, `/URI` hosts. No content stream is interpreted, nothing is rendered,
 * no JavaScript is evaluated.
 */

const KEYWORDS = [
  'JavaScript',
  'JS',
  'OpenAction',
  'AA',
  'Launch',
  'EmbeddedFile',
  'EmbeddedFiles',
  'RichMedia',
  'XFA',
  'URI',
] as const;
type Keyword = (typeof KEYWORDS)[number];
const KEYWORD_SET: ReadonlySet<string> = new Set(KEYWORDS);
const NAME = /\/([^\s/<>[\](){}%]{1,127})/g;
const URI = /\/URI\s*\(((?:\\.|[^\\)]){1,2048})\)/g;
const MAX_STREAMS = 256;

export function isPdf(bytes: Buffer): boolean {
  const head = bytes.subarray(0, 1024).toString('latin1');
  return head.includes('%PDF-');
}

export interface PdfNameCounts {
  counts: Record<Keyword, number>;
  obfuscated: number;
}

/** Decodes `#xx` escapes of a PDF name; null for an invalid escape. */
export function decodePdfName(raw: string): string | null {
  if (!raw.includes('#')) return raw;
  let out = '';
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i] as string;
    if (ch !== '#') {
      out += ch;
      continue;
    }
    const hex = raw.slice(i + 1, i + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) return null;
    out += String.fromCharCode(parseInt(hex, 16));
    i += 2;
  }
  return out;
}

export function countNames(text: string, into: PdfNameCounts): void {
  for (const match of text.matchAll(NAME)) {
    const raw = match[1] as string;
    const name = decodePdfName(raw);
    if (name === null || !KEYWORD_SET.has(name)) continue;
    into.counts[name as Keyword] += 1;
    if (raw !== name) into.obfuscated += 1;
  }
}

function uriHosts(text: string, analysis: Analysis): void {
  for (const match of text.matchAll(URI)) {
    const value = (match[1] as string).replace(/\\(.)/g, '$1');
    const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#\s]+)/i.exec(value)?.[1];
    const parsed = authority ? hostOfAuthority(authority) : null;
    if (parsed?.host) analysis.host(parsed.host);
    if (parsed?.ip) analysis.ip(parsed.ip);
  }
}

/** Object streams (`/Type /ObjStm`) with only `/FlateDecode`, decompressed within the budget. */
function objectStreams(bytes: Buffer, analysis: Analysis): string[] {
  const text = latin1(bytes);
  const out: string[] = [];
  let streams = 0;
  let undecodable = 0;
  let pos = 0;
  while (streams < MAX_STREAMS) {
    const keyword = text.indexOf('stream', pos);
    if (keyword < 0) break;
    pos = keyword + 6;
    if (text.slice(Math.max(0, keyword - 3), keyword) === 'end') continue;
    let start = keyword + 6;
    if (text[start] === '\r') start += 1;
    if (text[start] !== '\n') continue;
    start += 1;
    // The stream dictionary: the text since the object header (at most 2 KiB back).
    const window = text.slice(Math.max(0, keyword - 2048), keyword);
    const header = window.lastIndexOf(' obj');
    const dict = header >= 0 ? window.slice(header) : window;
    if (
      !/\/Type\s*\/ObjStm\b/.test(dict) ||
      !/\/Filter\s*(\/FlateDecode|\[\s*\/FlateDecode\s*\])/.test(dict) ||
      /\/DecodeParms/.test(dict)
    ) {
      continue;
    }
    const end = text.indexOf('endstream', start);
    if (end < 0) break;
    pos = end + 9;
    streams += 1;
    if (!analysis.reserveInflate(Math.min(ANALYSIS_BOUNDS.inflateEntryBytes, (end - start) * 20))) {
      analysis.fact('pdf.inflateBudgetExhausted', true);
      break;
    }
    try {
      const data = inflateSync(bytes.subarray(start, end), {
        maxOutputLength: ANALYSIS_BOUNDS.inflateEntryBytes,
        finishFlush: 2, // Z_SYNC_FLUSH: tolerate a missing end marker
      });
      out.push(data.toString('latin1'));
    } catch {
      // Not inflatable or above the cap: names inside stay unseen (counted as a fact).
      undecodable += 1;
    }
  }
  analysis.fact('pdf.objectStreams', streams);
  if (undecodable > 0) analysis.fact('pdf.undecodableStreams', undecodable);
  return out;
}

export function analyzePdf(bytes: Buffer, analysis: Analysis): void {
  if (!isPdf(bytes)) {
    analysis.fact('pdf.parsed', false);
    return;
  }
  analysis.format = 'pdf';
  analysis.supported = true;
  const names: PdfNameCounts = {
    counts: Object.fromEntries(KEYWORDS.map((k) => [k, 0])) as Record<Keyword, number>,
    obfuscated: 0,
  };
  const texts = [latin1(bytes), ...objectStreams(bytes, analysis)];
  for (const text of texts) {
    countNames(text, names);
    uriHosts(text, analysis);
  }
  const c = names.counts;
  for (const k of KEYWORDS) if (c[k] > 0) analysis.fact(`pdf.${k}`, c[k]);
  const js = c.JavaScript + c.JS;
  if (js > 0) analysis.add('static.pdf_javascript', js);
  if (js > 0 && c.OpenAction + c.AA > 0)
    analysis.add('static.pdf_open_action_js', c.OpenAction + c.AA);
  if (c.Launch > 0) analysis.add('static.pdf_launch', c.Launch);
  if (c.EmbeddedFile + c.EmbeddedFiles > 0) {
    analysis.add('static.pdf_embedded_file', c.EmbeddedFile + c.EmbeddedFiles);
  }
  if (names.obfuscated > 0) analysis.add('static.pdf_obfuscated_names', names.obfuscated);
}
