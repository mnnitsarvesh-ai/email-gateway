/**
 * Identification of the reported message in a report e-mail (step API-3, design note 37 C10.2,
 * risk K6). A bounded, pure MIME walker: it reads top-level and part headers (folded), walks
 * multipart boundaries (depth ≤ 4, parts ≤ 200), and finds
 *
 * - **attachment**: the first `message/rfc822` (or `message/global`) part, or an
 *   `application/octet-stream` / `application/eml` part whose file name ends `.eml`,
 *   transfer-decoded (7bit, 8bit, binary, base64, quoted-printable) up to the original limit; its
 *   headers give Message-ID, From, Date and Subject; further attached messages are counted;
 * - **inline**: a forward separator in the first `text/plain` part (or the first `text/html` part
 *   reduced to text) followed within 20 lines by `From:` and `Subject:` (optionally `Date:` /
 *   `Sent:` and `Message-ID:`), in English, German, French and further localized variants;
 * - **unsupported**: an Outlook `.msg` attachment (`application/vnd.ms-outlook`);
 * - **none** otherwise.
 *
 * Limits exceeded give `too_large`, an unparseable structure `parse_failed`. Nothing is rendered or
 * executed; results carry codes, hashes and header values of the original only (never bodies), and
 * failures carry codes only (no address, subject or content).
 */
import { createHash } from 'node:crypto';
import {
  extractCopyHeaders,
  parseAddressList,
  parseHeaderFields,
  parseRfc5322Date,
} from '../headers';

/** Fixed bounds of the walker (C10.2). */
export const REPORT_EXTRACT_DEFAULTS = Object.freeze({
  maxDepth: 4,
  maxParts: 200,
  /** At most this many attachment hashes of an attached original (`api-report-original/1`). */
  maxAttachmentHashes: 20,
  /** The `From:`/`Subject:` lines must follow the separator within this many lines. */
  inlineHeaderWindowLines: 20,
  /** Only the first characters of the inline body text are searched. */
  maxInlineTextChars: 1_000_000,
  /** A part header block larger than this is malformed. */
  maxPartHeaderBytes: 256 * 1024,
});

export interface ReportExtractLimits {
  /** `API_MODE_REPORT_MAX_BYTES` (25 MiB): the whole report e-mail. */
  maxBytes: number;
  /** `API_MODE_MAX_MESSAGE_BYTES`: the decoded attached original. */
  maxOriginalBytes: number;
  /** Default 4. */
  maxDepth?: number;
  /** Default 200. */
  maxParts?: number;
}

/** The identifying headers of the reported original. */
export interface ReportedMessageHeaders {
  /** As written (angle brackets kept), ≤ 998 characters. */
  messageId: string | null;
  /** addr-spec (domain lower-cased). */
  from: string | null;
  date: Date | null;
  /** Decoded (RFC 2047 encoded-words), ≤ 998 characters. */
  subject: string | null;
}

export type ReportExtractFailureCode = 'too_large' | 'parse_failed';
export type ReportExtractLimitName = 'bytes' | 'original_bytes' | 'depth' | 'parts';

export type ReportExtraction =
  | {
      ok: true;
      identification: 'attachment';
      /** The decoded original message (RFC 5322 bytes). */
      original: Uint8Array;
      headers: ReportedMessageHeaders;
      /** Attached messages after the first (only the first is used). */
      extraOriginals: number;
      /** Hex SHA-256 of the original's decoded attachments (≤ 20, de-duplicated, in order). */
      attachmentSha256: string[];
      /** False when the original's own structure exceeded the bounds (hashes are partial). */
      attachmentsComplete: boolean;
    }
  | {
      ok: true;
      identification: 'inline';
      headers: ReportedMessageHeaders;
      extraOriginals: 0;
      /** Id of the separator that matched (e.g. `original_message`, `forwarded_message`). */
      separator: string;
    }
  | { ok: true; identification: 'unsupported'; extraOriginals: 0 }
  | { ok: true; identification: 'none'; extraOriginals: 0 }
  | { ok: false; code: ReportExtractFailureCode; limit?: ReportExtractLimitName };

class ExtractFailure extends Error {
  constructor(
    readonly code: ReportExtractFailureCode,
    readonly limit?: ReportExtractLimitName,
  ) {
    super(code);
  }
}

// ---------------------------------------------------------------------------------------------
// Header parameters
// ---------------------------------------------------------------------------------------------

interface ParsedHeaderValue {
  value: string;
  params: Record<string, string>;
}

/** Splits on `;` outside double quotes. */
function splitParams(value: string): string[] {
  const out: string[] = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i] as string;
    if (ch === '\\' && quoted) {
      current += ch + (value[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (ch === '"') quoted = !quoted;
    if (ch === ';' && !quoted) {
      out.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

function unquote(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
    return v.slice(1, -1).replace(/\\(.)/g, '$1');
  }
  return v;
}

function decodeBytes(bytes: Buffer, charset: string | null): string {
  const label = (charset ?? 'utf-8').trim().toLowerCase() || 'utf-8';
  try {
    return new TextDecoder(label === 'us-ascii' ? 'utf-8' : label).decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

function percentDecode(value: string): Buffer {
  const bytes: number[] = [];
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i] as string;
    if (ch === '%' && /^[0-9A-Fa-f]{2}$/.test(value.slice(i + 1, i + 3))) {
      bytes.push(parseInt(value.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(...Buffer.from(ch, 'latin1'));
    }
  }
  return Buffer.from(bytes);
}

/**
 * `type/subtype; a=b; c*=utf-8''x; d*0=..; d*1=..` (RFC 2045, RFC 2231). Values arrive as
 * latin1 (one char per byte); plain values are re-read as UTF-8, extended values with their
 * charset. Parameter names are lower-cased.
 */
function parseHeaderValue(raw: string): ParsedHeaderValue {
  const [head = '', ...rest] = splitParams(raw);
  const pieces = new Map<string, { index: number; value: string; extended: boolean }[]>();
  for (const part of rest) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    const match = /^([^*]+)(?:\*(\d{1,3}))?(\*)?$/.exec(key);
    if (!match) continue;
    const name = match[1] as string;
    const list = pieces.get(name) ?? [];
    list.push({
      index: match[2] === undefined ? 0 : Number(match[2]),
      value: match[3] === undefined ? unquote(value) : value,
      extended: match[3] !== undefined,
    });
    pieces.set(name, list);
  }
  const params: Record<string, string> = {};
  for (const [name, list] of pieces) {
    list.sort((a, b) => a.index - b.index);
    let charset: string | null = null;
    const chunks: Buffer[] = [];
    list.forEach((piece, i) => {
      if (piece.extended) {
        let text = piece.value;
        if (i === 0) {
          const ext = /^([^']*)'[^']*'(.*)$/.exec(text);
          if (ext) {
            charset = ext[1] || null;
            text = ext[2] as string;
          }
        }
        chunks.push(percentDecode(text));
      } else {
        chunks.push(Buffer.from(piece.value, 'latin1'));
      }
    });
    params[name] = decodeBytes(Buffer.concat(chunks), charset);
  }
  return { value: head.trim().toLowerCase(), params };
}

// ---------------------------------------------------------------------------------------------
// Encoded words (RFC 2047) and transfer encodings
// ---------------------------------------------------------------------------------------------

const ENCODED_WORD = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;

/** Decodes RFC 2047 encoded-words (B and Q); whitespace between adjacent words is dropped. */
export function decodeEncodedWords(value: string): string {
  const joined = value.replace(/(\?=)\s+(=\?)/g, '$1$2');
  return joined.replace(ENCODED_WORD, (whole, charset: string, enc: string, text: string) => {
    try {
      const bytes =
        enc.toUpperCase() === 'B'
          ? Buffer.from(text, 'base64')
          : Buffer.from(
              text
                .replace(/_/g, ' ')
                .replace(/=([0-9A-Fa-f]{2})/g, (_m, h: string) =>
                  String.fromCharCode(parseInt(h, 16)),
                ),
              'latin1',
            );
      return decodeBytes(bytes, charset.split('*')[0] ?? 'utf-8');
    } catch {
      return whole;
    }
  });
}

function decodeQuotedPrintable(latin1: string): Buffer {
  const text = latin1
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-Fa-f]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
  return Buffer.from(text, 'latin1');
}

/** The decoded bytes of a part body, or null for an unknown transfer encoding. */
function decodeTransfer(latin1: string, encoding: string): Buffer | null {
  switch (encoding) {
    case '':
    case '7bit':
    case '8bit':
    case 'binary':
      return Buffer.from(latin1, 'latin1');
    case 'base64':
      return Buffer.from(latin1.replace(/[^A-Za-z0-9+/]/g, ''), 'base64');
    case 'quoted-printable':
      return decodeQuotedPrintable(latin1);
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------------------------
// Entities and the bounded walk
// ---------------------------------------------------------------------------------------------

interface Entity {
  /** `type/subtype`, lower case. */
  type: string;
  params: Record<string, string>;
  encoding: string;
  disposition: string | null;
  filename: string | null;
  depth: number;
  /** Inside an attached message (attachment-hash pass only). */
  inMessage: boolean;
  /** The body (latin1, one char per byte). */
  body: string;
}

interface WalkState {
  parts: number;
  maxParts: number;
  maxDepth: number;
}

const RFC822_TYPES = new Set(['message/rfc822', 'message/global']);

/** Header block and body of an entity in `raw[start, end)`. */
function splitEntity(raw: string, start: number, end: number): { header: string; body: string } {
  let p = start;
  while (p < end) {
    let lineEnd = raw.indexOf('\n', p);
    if (lineEnd < 0 || lineEnd >= end) lineEnd = end;
    const line = raw.slice(p, lineEnd);
    if (line === '' || line === '\r') {
      return { header: raw.slice(start, p), body: raw.slice(Math.min(lineEnd + 1, end), end) };
    }
    if (p - start > REPORT_EXTRACT_DEFAULTS.maxPartHeaderBytes) {
      throw new ExtractFailure('parse_failed');
    }
    p = lineEnd + 1;
  }
  // No empty line: a header-only entity.
  return { header: raw.slice(start, end), body: '' };
}

function toEntity(
  raw: string,
  start: number,
  end: number,
  depth: number,
  inMessage: boolean,
  defaultType: string,
): Entity {
  const { header, body } = splitEntity(raw, start, end);
  const fields = parseHeaderFields(header);
  const field = (name: string) => fields.find((f) => f.name === name)?.value ?? null;
  const ct = field('content-type');
  let type = defaultType;
  let params: Record<string, string> = {};
  if (ct !== null) {
    const parsed = parseHeaderValue(ct);
    if (/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(parsed.value)) type = parsed.value;
    params = parsed.params;
  }
  const cd = field('content-disposition');
  const disposition = cd === null ? null : parseHeaderValue(cd);
  const filename = disposition?.params.filename ?? params.name ?? null;
  return {
    type,
    params,
    encoding: (field('content-transfer-encoding') ?? '').trim().toLowerCase(),
    disposition: disposition?.value || null,
    filename: filename === null ? null : decodeEncodedWords(filename).trim() || null,
    depth,
    inMessage,
    body,
  };
}

/** The child ranges of a multipart body (RFC 2046 §5.1.1). */
function multipartChildren(body: string, boundary: string): [number, number][] {
  const delimiter = `--${boundary}`;
  const children: [number, number][] = [];
  let partStart = -1;
  let pos = 0;
  while (pos <= body.length) {
    const at = body.indexOf(delimiter, pos);
    if (at < 0) break;
    pos = at + delimiter.length;
    if (at > 0 && body[at - 1] !== '\n') continue;
    const close = body.startsWith('--', pos);
    let lineEnd = body.indexOf('\n', pos);
    if (lineEnd < 0) lineEnd = body.length;
    const tail = body.slice(close ? pos + 2 : pos, lineEnd);
    if (!/^[ \t\r]*$/.test(tail)) continue;
    if (partStart >= 0) {
      let partEnd = at;
      if (partEnd > partStart && body[partEnd - 1] === '\n') partEnd -= 1;
      if (partEnd > partStart && body[partEnd - 1] === '\r') partEnd -= 1;
      children.push([partStart, Math.max(partStart, partEnd)]);
    }
    if (close) return children;
    partStart = Math.min(lineEnd + 1, body.length);
    pos = partStart;
  }
  if (partStart < 0) throw new ExtractFailure('parse_failed');
  // A missing close delimiter is tolerated: the last part runs to the end.
  children.push([partStart, body.length]);
  return children;
}

type Visit = (entity: Entity) => void;

/**
 * Depth-first, document-order walk. Multiparts are split; attached messages are walked into only
 * when `descendMessages` (the attachment-hash pass). Every entity counts towards `maxParts`.
 */
function walk(
  raw: string,
  start: number,
  end: number,
  depth: number,
  inMessage: boolean,
  defaultType: string,
  state: WalkState,
  descendMessages: boolean,
  visit: Visit,
): void {
  state.parts += 1;
  if (state.parts > state.maxParts) throw new ExtractFailure('too_large', 'parts');
  if (depth > state.maxDepth) throw new ExtractFailure('too_large', 'depth');
  const entity = toEntity(raw, start, end, depth, inMessage, defaultType);
  if (entity.type.startsWith('multipart/')) {
    const boundary = entity.params.boundary;
    if (boundary === undefined || boundary.length === 0 || boundary.length > 200) {
      throw new ExtractFailure('parse_failed');
    }
    const childDefault = entity.type === 'multipart/digest' ? 'message/rfc822' : 'text/plain';
    for (const [s, e] of multipartChildren(entity.body, boundary)) {
      walk(entity.body, s, e, depth + 1, inMessage, childDefault, state, descendMessages, visit);
    }
    return;
  }
  if (descendMessages && RFC822_TYPES.has(entity.type)) {
    const decoded = decodeTransfer(entity.body, entity.encoding);
    if (decoded === null) {
      visit(entity);
      return;
    }
    const inner = decoded.toString('latin1');
    walk(inner, 0, inner.length, depth + 1, true, 'text/plain', state, descendMessages, visit);
    return;
  }
  visit(entity);
}

// ---------------------------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------------------------

const lowerName = (e: Entity): string => (e.filename ?? '').toLowerCase();

function isOriginalCandidate(e: Entity): boolean {
  if (RFC822_TYPES.has(e.type)) return true;
  return (
    (e.type === 'application/octet-stream' || e.type === 'application/eml') &&
    lowerName(e).endsWith('.eml')
  );
}

function isOutlookMsg(e: Entity): boolean {
  return e.type === 'application/vnd.ms-outlook' || lowerName(e).endsWith('.msg');
}

/** The mime-parser body rule: not inside a message, no attachment disposition, no file name. */
function isBodyCandidate(e: Entity): boolean {
  return !e.inMessage && e.disposition !== 'attachment' && e.filename === null;
}

/**
 * Hashes of the decoded attachments of an attached original, the rule of `@email-gateway/mime-
 * parser` (and so of `email_attachments`): every leaf except the first `text/plain` and first
 * `text/html` body candidates; leaves inside a nested message are attachments. Best effort: a
 * structure beyond the bounds keeps the hashes found so far (`complete: false`).
 */
export function originalAttachmentHashes(
  original: Uint8Array,
  options: { maxDepth?: number; maxParts?: number; max?: number } = {},
): { sha256: string[]; complete: boolean } {
  const raw = Buffer.from(original).toString('latin1');
  const max = options.max ?? REPORT_EXTRACT_DEFAULTS.maxAttachmentHashes;
  const hashes: string[] = [];
  let textTaken = false;
  let htmlTaken = false;
  const state: WalkState = {
    parts: 0,
    maxParts: options.maxParts ?? REPORT_EXTRACT_DEFAULTS.maxParts,
    maxDepth: options.maxDepth ?? REPORT_EXTRACT_DEFAULTS.maxDepth,
  };
  try {
    walk(raw, 0, raw.length, 0, false, 'text/plain', state, true, (e) => {
      if (isBodyCandidate(e) && e.type === 'text/plain' && !textTaken) {
        textTaken = true;
        return;
      }
      if (isBodyCandidate(e) && e.type === 'text/html' && !htmlTaken) {
        htmlTaken = true;
        return;
      }
      if (hashes.length >= max) return;
      const bytes = decodeTransfer(e.body, e.encoding) ?? Buffer.from(e.body, 'latin1');
      const hash = createHash('sha256').update(bytes).digest('hex');
      if (!hashes.includes(hash)) hashes.push(hash);
    });
  } catch (error) {
    if (error instanceof ExtractFailure) return { sha256: hashes, complete: false };
    throw error;
  }
  return { sha256: hashes, complete: true };
}

// ---------------------------------------------------------------------------------------------
// HTML to text (bounded, linear)
// ---------------------------------------------------------------------------------------------

const ENTITIES: Readonly<Record<string, string>> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
};

function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]{2,8});/gi, (whole, name: string) => {
    if (name[0] === '#') {
      const cp =
        name[1] === 'x' || name[1] === 'X' ? parseInt(name.slice(2), 16) : Number(name.slice(1));
      return cp > 0 && cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff)
        ? String.fromCodePoint(cp === 0xa0 ? 0x20 : cp)
        : whole;
    }
    return ENTITIES[name.toLowerCase()] ?? whole;
  });
}

const BLOCK_TAGS = new Set([
  'br',
  'p',
  'div',
  'tr',
  'li',
  'table',
  'blockquote',
  'hr',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
]);

/**
 * Text of an HTML body: script/style/head removed, source white space collapsed to one space (as
 * a browser renders it), block tags as line breaks, entities decoded.
 */
export function htmlToText(html: string): string {
  const lower = html.toLowerCase();
  let out = '';
  let i = 0;
  const text = (segment: string) => segment.replace(/[ \t\r\n\f]+/g, ' ');
  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt < 0) {
      out += text(html.slice(i));
      break;
    }
    out += text(html.slice(i, lt));
    const gt = html.indexOf('>', lt + 1);
    if (gt < 0) {
      out += text(html.slice(lt));
      break;
    }
    const tag = /^<\/?([a-z][a-z0-9]*)/.exec(lower.slice(lt, Math.min(gt + 1, lt + 32)));
    const name = tag?.[1] ?? null;
    if (name === 'script' || name === 'style' || name === 'head') {
      if (lower[lt + 1] !== '/') {
        const close = lower.indexOf(`</${name}`, gt + 1);
        if (close < 0) break;
        const closeEnd = html.indexOf('>', close);
        i = closeEnd < 0 ? html.length : closeEnd + 1;
        continue;
      }
    }
    if (name !== null && BLOCK_TAGS.has(name)) out += '\n';
    i = gt + 1;
  }
  return decodeEntities(out);
}

// ---------------------------------------------------------------------------------------------
// Inline forwards
// ---------------------------------------------------------------------------------------------

/**
 * Forward separators (trimmed line, case-insensitive), English first, then German, French,
 * Spanish, Italian, Dutch and Portuguese variants of Outlook, Gmail, Apple Mail and Thunderbird.
 */
export const INLINE_FORWARD_SEPARATORS: readonly { id: string; pattern: RegExp }[] = [
  { id: 'original_message', pattern: /^-{2,}\s*original message\s*-{2,}$/iu },
  { id: 'forwarded_message', pattern: /^-{2,}\s*forwarded message\s*-{2,}$/iu },
  { id: 'begin_forwarded', pattern: /^begin forwarded message\s*:$/iu },
  { id: 'outlook_rule', pattern: /^_{10,}$/u },
  // German
  { id: 'original_message', pattern: /^-{2,}\s*urspr(?:ü|ue)ngliche nachricht\s*-{2,}$/iu },
  { id: 'forwarded_message', pattern: /^-{2,}\s*weitergeleitete nachricht\s*-{2,}$/iu },
  { id: 'begin_forwarded', pattern: /^anfang der weitergeleiteten (?:nachricht|e-mail)\s*:$/iu },
  // French
  { id: 'original_message', pattern: /^-{2,}\s*message d['’]origine\s*-{2,}$/iu },
  { id: 'original_message', pattern: /^-{2,}\s*message original\s*-{2,}$/iu },
  { id: 'forwarded_message', pattern: /^-{2,}\s*message transf[ée]r[ée]\s*-{2,}$/iu },
  {
    id: 'begin_forwarded',
    pattern: /^d[ée]but du message (?:r[ée]exp[ée]di[ée]|transf[ée]r[ée])\s*:$/iu,
  },
  // Spanish, Italian, Dutch, Portuguese
  { id: 'original_message', pattern: /^-{2,}\s*mensaje original\s*-{2,}$/iu },
  { id: 'forwarded_message', pattern: /^-{2,}\s*mensaje reenviado\s*-{2,}$/iu },
  { id: 'original_message', pattern: /^-{2,}\s*messaggio originale\s*-{2,}$/iu },
  { id: 'forwarded_message', pattern: /^-{2,}\s*messaggio inoltrato\s*-{2,}$/iu },
  { id: 'original_message', pattern: /^-{2,}\s*oorspronkelijk bericht\s*-{2,}$/iu },
  { id: 'forwarded_message', pattern: /^-{2,}\s*doorgestuurd bericht\s*-{2,}$/iu },
  { id: 'original_message', pattern: /^-{2,}\s*mensagem original\s*-{2,}$/iu },
  { id: 'forwarded_message', pattern: /^-{2,}\s*mensagem encaminhada\s*-{2,}$/iu },
];

type InlineLabel = 'from' | 'subject' | 'date' | 'messageId';

const LABELS: readonly [InlineLabel, readonly string[]][] = [
  ['from', ['from', 'von', 'de', 'da', 'van']],
  [
    'subject',
    ['subject', 'betreff', 'objet', 'sujet', 'asunto', 'oggetto', 'onderwerp', 'assunto'],
  ],
  [
    'date',
    [
      'date',
      'sent',
      'datum',
      'gesendet',
      'envoyé',
      'envoye',
      'fecha',
      'enviado',
      'enviada',
      'data',
      'inviato',
      'verzonden',
    ],
  ],
  ['messageId', ['message-id', 'message id']],
];

const LABEL_LINE = /^\*?\s*([\p{L} -]{2,20}?)\s*\*?\s*:\s*\*?\s*(.*)$/u;

function labelOf(line: string): { label: InlineLabel; value: string } | null {
  const match = LABEL_LINE.exec(line);
  if (!match) return null;
  const name = (match[1] as string).trim().toLowerCase();
  for (const [label, names] of LABELS) {
    if (names.includes(name))
      return { label, value: (match[2] as string).replace(/\*+$/, '').trim() };
  }
  return null;
}

const stripQuote = (line: string): string => line.replace(/^(?:[ \t]*>)+[ \t]?/, '');

const MONTH_NAMES: Readonly<Record<string, number>> = (() => {
  const table: Record<string, number> = {};
  const add = (month: number, ...names: string[]) => {
    for (const n of names) table[n] = month;
  };
  add(
    0,
    'january',
    'jan',
    'januar',
    'jänner',
    'janvier',
    'janv',
    'enero',
    'gennaio',
    'januari',
    'janeiro',
  );
  add(
    1,
    'february',
    'feb',
    'februar',
    'février',
    'fevrier',
    'févr',
    'fevr',
    'febrero',
    'febbraio',
    'februari',
    'fevereiro',
  );
  add(2, 'march', 'mar', 'märz', 'maerz', 'mär', 'mars', 'marzo', 'maart', 'março', 'marco');
  add(3, 'april', 'apr', 'avril', 'avr', 'abril', 'aprile');
  add(4, 'may', 'mai', 'mayo', 'maggio', 'mei', 'maio');
  add(5, 'june', 'jun', 'juni', 'juin', 'junio', 'giugno', 'junho');
  add(6, 'july', 'jul', 'juli', 'juillet', 'juil', 'julio', 'luglio', 'julho');
  add(7, 'august', 'aug', 'août', 'aout', 'agosto', 'augustus');
  add(8, 'september', 'sep', 'sept', 'septembre', 'septiembre', 'settembre', 'setembro');
  add(9, 'october', 'oct', 'oktober', 'okt', 'octobre', 'octubre', 'ottobre', 'outubro');
  add(10, 'november', 'nov', 'novembre', 'noviembre', 'novembro');
  add(
    11,
    'december',
    'dec',
    'dezember',
    'dez',
    'décembre',
    'decembre',
    'déc',
    'diciembre',
    'dicembre',
    'dezembro',
  );
  return table;
})();

function utcDate(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  offsetMinutes: number,
): Date | null {
  if (year < 1970 || year > 2100 || month < 0 || month > 11 || day < 1 || day > 31) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  const check = new Date(Date.UTC(year, month, day));
  if (check.getUTCMonth() !== month) return null;
  return new Date(Date.UTC(year, month, day, hour, minute, second) - offsetMinutes * 60_000);
}

/**
 * Dates of inline forward headers: RFC 5322, then the common client formats (`Mon, Nov 23, 2026
 * at 10:15 AM`, `Monday, November 23, 2026 10:15 AM`, `Montag, 23. November 2026 10:15`,
 * `lundi 23 novembre 2026 10:15`, `2026-11-23 10:15`, `23.11.2026 10:15`, unambiguous
 * `dd/mm/yyyy`). Without a zone the time is read as UTC (the lookup window is ±72 h).
 */
export function parseForwardDate(value: string): Date | null {
  const rfc = parseRfc5322Date(value);
  if (rfc) return rfc;
  let text = value
    .normalize('NFC')
    .toLowerCase()
    .replace(/\([^)]*\)/g, ' ');
  let hour = 0;
  let minute = 0;
  let second = 0;
  let offset = 0;
  const time = /(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(a\.?m\.?|p\.?m\.?)?/.exec(text);
  if (time) {
    hour = Number(time[1]);
    minute = Number(time[2]);
    second = time[3] === undefined ? 0 : Number(time[3]);
    const meridiem = time[4]?.replace(/\./g, '');
    if (meridiem !== undefined) {
      if (hour < 1 || hour > 12) return null;
      if (meridiem === 'pm' && hour !== 12) hour += 12;
      if (meridiem === 'am' && hour === 12) hour = 0;
    }
    const after = text.slice(time.index + time[0].length);
    const zone = /^\s*(?:utc|gmt)?\s*([+-])(\d{1,2})(?::?(\d{2}))?(?!\d)/.exec(after);
    if (zone) {
      const zoneHours = Number(zone[2]);
      const zoneMinutes = zone[3] === undefined ? 0 : Number(zone[3]);
      if (zoneHours > 14 || zoneMinutes > 59) return null;
      offset = (zone[1] === '-' ? -1 : 1) * (zoneHours * 60 + zoneMinutes);
    }
    text = `${text.slice(0, time.index)} ${after.slice(zone ? zone[0].length : 0)}`;
  }
  const iso = /\b(\d{4})-(\d{1,2})-(\d{1,2})\b/.exec(text);
  if (iso)
    return utcDate(
      Number(iso[1]),
      Number(iso[2]) - 1,
      Number(iso[3]),
      hour,
      minute,
      second,
      offset,
    );
  const dotted = /\b(\d{1,2})\.(\d{1,2})\.(\d{4})\b/.exec(text);
  if (dotted) {
    return utcDate(
      Number(dotted[3]),
      Number(dotted[2]) - 1,
      Number(dotted[1]),
      hour,
      minute,
      second,
      offset,
    );
  }
  const slash = /\b(\d{1,2})\/(\d{1,2})\/(\d{4})\b/.exec(text);
  if (slash) {
    const a = Number(slash[1]);
    const b = Number(slash[2]);
    if (a > 12 && b <= 12) return utcDate(Number(slash[3]), b - 1, a, hour, minute, second, offset);
    if (b > 12 && a <= 12) return utcDate(Number(slash[3]), a - 1, b, hour, minute, second, offset);
    return null;
  }
  let month: number | undefined;
  for (const word of text.match(/\p{L}+/gu) ?? []) {
    month = MONTH_NAMES[word.replace(/\.$/, '')];
    if (month !== undefined) break;
  }
  const year = /\b(\d{4})\b/.exec(text);
  if (month === undefined || !year) return null;
  const day = /\b(\d{1,2})(?:st|nd|rd|th|er)?\b\.?/.exec(text.replace(year[0], ' '));
  if (!day) return null;
  return utcDate(Number(year[1]), month, Number(day[1]), hour, minute, second, offset);
}

/** The addr-spec of an inline `From:` value (`Name <a@b>`, `Name [mailto:a@b]`, `a@b`). */
function inlineFromAddress(value: string): string | null {
  const normalized = value.replace(/\[mailto:([^\]]+)\]/gi, '<$1>').replace(/mailto:/gi, '');
  return parseAddressList(normalized)[0] ?? null;
}

const truncate = (value: string, max: number): string => Array.from(value).slice(0, max).join('');

/** Searches inline forward headers in body text (C10.2 "inline"). */
export function parseInlineForward(
  text: string,
): { headers: ReportedMessageHeaders; separator: string } | null {
  const lines = text.slice(0, REPORT_EXTRACT_DEFAULTS.maxInlineTextChars).split(/\r\n|\r|\n/);
  const window = REPORT_EXTRACT_DEFAULTS.inlineHeaderWindowLines;
  for (let i = 0; i < lines.length; i += 1) {
    const line = stripQuote(lines[i] as string).trim();
    if (line.length === 0 || line.length > 120) continue;
    const separator = INLINE_FORWARD_SEPARATORS.find((s) => s.pattern.test(line));
    if (!separator) continue;
    const found: Partial<Record<InlineLabel, string>> = {};
    let started = false;
    for (let j = i + 1; j <= Math.min(lines.length - 1, i + window); j += 1) {
      const candidate = stripQuote(lines[j] as string).trim();
      if (candidate.length === 0) {
        if (started) break;
        continue;
      }
      const labelled = labelOf(candidate);
      if (labelled === null) continue;
      started = true;
      found[labelled.label] ??= labelled.value;
    }
    if (found.from === undefined || found.subject === undefined) continue;
    const messageId = found.messageId?.trim() ?? '';
    return {
      separator: separator.id,
      headers: {
        messageId: messageId.length > 0 ? truncate(messageId, 998) : null,
        from: inlineFromAddress(found.from),
        date: found.date === undefined ? null : parseForwardDate(found.date),
        subject: truncate(found.subject, 998),
      },
    };
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// extractReportedMessage
// ---------------------------------------------------------------------------------------------

function bodyText(e: Entity): string | null {
  const decoded = decodeTransfer(e.body, e.encoding);
  if (decoded === null) return null;
  const text = decodeBytes(decoded, e.params.charset ?? null);
  return e.type === 'text/html'
    ? htmlToText(text.slice(0, REPORT_EXTRACT_DEFAULTS.maxInlineTextChars * 4))
    : text;
}

/** C10.2: identifies the reported original in a report e-mail. */
export function extractReportedMessage(
  bytes: Uint8Array,
  limits: ReportExtractLimits,
): ReportExtraction {
  if (bytes.length > limits.maxBytes) return { ok: false, code: 'too_large', limit: 'bytes' };
  const raw = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('latin1');
  const state: WalkState = {
    parts: 0,
    maxParts: limits.maxParts ?? REPORT_EXTRACT_DEFAULTS.maxParts,
    maxDepth: limits.maxDepth ?? REPORT_EXTRACT_DEFAULTS.maxDepth,
  };
  const originals: Entity[] = [];
  const seen: { outlookMsg: boolean; plain: Entity | null; html: Entity | null } = {
    outlookMsg: false,
    plain: null,
    html: null,
  };
  try {
    walk(raw, 0, raw.length, 0, false, 'text/plain', state, false, (e) => {
      if (isOriginalCandidate(e)) {
        originals.push(e);
        return;
      }
      if (isOutlookMsg(e)) {
        seen.outlookMsg = true;
        return;
      }
      if (isBodyCandidate(e)) {
        if (e.type === 'text/plain' && seen.plain === null) seen.plain = e;
        else if (e.type === 'text/html' && seen.html === null) seen.html = e;
      }
    });
    const first = originals[0];
    if (first !== undefined) {
      const decoded = decodeTransfer(first.body, first.encoding);
      if (decoded === null) throw new ExtractFailure('parse_failed');
      if (decoded.length > limits.maxOriginalBytes) {
        throw new ExtractFailure('too_large', 'original_bytes');
      }
      const original = new Uint8Array(decoded);
      const headers = extractCopyHeaders(original);
      const hashes = originalAttachmentHashes(original, {
        maxDepth: state.maxDepth,
        maxParts: state.maxParts,
      });
      return {
        ok: true,
        identification: 'attachment',
        original,
        headers: {
          messageId: headers.messageId,
          from: headers.from,
          date: headers.date,
          subject:
            headers.subject === null ? null : truncate(decodeEncodedWords(headers.subject), 998),
        },
        extraOriginals: originals.length - 1,
        attachmentSha256: hashes.sha256,
        attachmentsComplete: hashes.complete,
      };
    }
    const textPart = seen.plain ?? seen.html;
    const text = textPart === null ? null : bodyText(textPart);
    const inline = text === null ? null : parseInlineForward(text);
    if (inline !== null) {
      return {
        ok: true,
        identification: 'inline',
        headers: inline.headers,
        extraOriginals: 0,
        separator: inline.separator,
      };
    }
    if (seen.outlookMsg) return { ok: true, identification: 'unsupported', extraOriginals: 0 };
    return { ok: true, identification: 'none', extraOriginals: 0 };
  } catch (error) {
    if (error instanceof ExtractFailure) {
      return error.limit === undefined
        ? { ok: false, code: error.code }
        : { ok: false, code: error.code, limit: error.limit };
    }
    if (error instanceof RangeError) return { ok: false, code: 'parse_failed' };
    throw error;
  }
}

/** Headers of the report e-mail itself that the reporter checks need (C10.1). */
export interface ReportEnvelopeHeaders {
  /** addr-spec of the first `From` (domain lower-cased). */
  from: string | null;
  /** The `Auto-Submitted` value (lower case, without parameters), null when absent. */
  autoSubmitted: string | null;
  /** The `Precedence` value (lower case), null when absent. */
  precedence: string | null;
}

/** Reads `From`, `Auto-Submitted` and `Precedence` from the top-level header block. */
export function reportEnvelopeHeaders(bytes: Uint8Array): ReportEnvelopeHeaders {
  const head = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    .subarray(0, REPORT_EXTRACT_DEFAULTS.maxPartHeaderBytes)
    .toString('utf8');
  const end = /\r?\n\r?\n/.exec(head);
  const fields = parseHeaderFields(end ? head.slice(0, end.index + 1) : head);
  const value = (name: string) => fields.find((f) => f.name === name)?.value ?? null;
  const token = (v: string | null) =>
    v === null ? null : (v.split(';')[0] ?? '').trim().toLowerCase() || null;
  const from = value('from');
  return {
    from: from === null ? null : (parseAddressList(from)[0] ?? null),
    autoSubmitted: token(value('auto-submitted')),
    precedence: token(value('precedence')),
  };
}
