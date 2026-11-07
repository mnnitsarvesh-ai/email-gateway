/**
 * A bounded, linear XML tokenizer for OOXML and ODF parts (step 4.5 D4). No DTD processing:
 * `<!DOCTYPE` is refused (so entity-expansion bombs cannot exist), only the five predefined
 * entities and numeric character references are decoded (an unknown entity is kept literally),
 * no namespace resolution, no tree: events are pushed to a handler, so nesting depth costs
 * nothing but a counter. Every character is examined a bounded number of times.
 */

export class XmlParseError extends Error {
  constructor(readonly reason: 'doctype' | 'malformed' | 'too_large') {
    super(`xml ${reason}`);
    this.name = 'XmlParseError';
  }
}

export interface XmlHandler {
  open(name: string, attributes: ReadonlyMap<string, string>, selfClosing: boolean): void;
  close(name: string): void;
  text(value: string): void;
}

const PREDEFINED: Readonly<Record<string, string>> = {
  lt: '<',
  gt: '>',
  amp: '&',
  quot: '"',
  apos: "'",
};

/** Decodes the five predefined entities and numeric references; others stay literal. */
export function decodeEntities(value: string): string {
  if (!value.includes('&')) return value;
  let out = '';
  let i = 0;
  while (i < value.length) {
    const amp = value.indexOf('&', i);
    if (amp < 0) {
      out += value.slice(i);
      break;
    }
    out += value.slice(i, amp);
    const semi = value.indexOf(';', amp + 1);
    if (semi < 0 || semi - amp > 12) {
      out += '&';
      i = amp + 1;
      continue;
    }
    const name = value.slice(amp + 1, semi);
    let replacement: string | null = PREDEFINED[name] ?? null;
    if (replacement === null && name.startsWith('#')) {
      const code =
        name[1] === 'x' || name[1] === 'X'
          ? parseInt(name.slice(2), 16)
          : parseInt(name.slice(1), 10);
      const valid =
        Number.isInteger(code) &&
        code > 0 &&
        code <= 0x10ffff &&
        !(code >= 0xd800 && code <= 0xdfff) &&
        /^#(?:[0-9]{1,7}|[xX][0-9a-fA-F]{1,6})$/.test(name);
      replacement = valid ? String.fromCodePoint(code) : null;
    }
    if (replacement === null) {
      out += value.slice(amp, semi + 1);
    } else {
      out += replacement;
    }
    i = semi + 1;
  }
  return out;
}

const isNameChar = (c: number): boolean =>
  (c >= 97 && c <= 122) ||
  (c >= 65 && c <= 90) ||
  (c >= 48 && c <= 57) ||
  c === 58 || // :
  c === 95 || // _
  c === 45 || // -
  c === 46 || // .
  c > 127;

const isSpace = (c: number): boolean => c === 32 || c === 9 || c === 10 || c === 13;

function parseAttributes(source: string, from: number, to: number): Map<string, string> {
  const attributes = new Map<string, string>();
  let i = from;
  while (i < to) {
    while (i < to && isSpace(source.charCodeAt(i))) i += 1;
    const nameStart = i;
    while (i < to && isNameChar(source.charCodeAt(i))) i += 1;
    if (i === nameStart) {
      i += 1;
      continue;
    }
    const name = source.slice(nameStart, i);
    while (i < to && isSpace(source.charCodeAt(i))) i += 1;
    if (source[i] !== '=') continue;
    i += 1;
    while (i < to && isSpace(source.charCodeAt(i))) i += 1;
    const quote = source[i];
    if (quote !== '"' && quote !== "'") continue;
    const end = source.indexOf(quote, i + 1);
    if (end < 0 || end > to) break;
    attributes.set(name, decodeEntities(source.slice(i + 1, end)));
    i = end + 1;
  }
  return attributes;
}

const EMPTY_ATTRIBUTES: ReadonlyMap<string, string> = new Map();

/**
 * Tokenizes `source`, calling `handler` for elements and text. Throws `XmlParseError` on a
 * DOCTYPE, an unterminated construct or input over `maxChars`.
 */
export function tokenizeXml(source: string, handler: XmlHandler, maxChars = 26_214_400): void {
  if (source.length > maxChars) throw new XmlParseError('too_large');
  let i = 0;
  const n = source.length;
  while (i < n) {
    const lt = source.indexOf('<', i);
    if (lt < 0) {
      const tail = source.slice(i);
      if (tail.trim().length > 0) handler.text(decodeEntities(tail));
      break;
    }
    if (lt > i) handler.text(decodeEntities(source.slice(i, lt)));
    if (source.startsWith('<!--', lt)) {
      const end = source.indexOf('-->', lt + 4);
      if (end < 0) throw new XmlParseError('malformed');
      i = end + 3;
      continue;
    }
    if (source.startsWith('<![CDATA[', lt)) {
      const end = source.indexOf(']]>', lt + 9);
      if (end < 0) throw new XmlParseError('malformed');
      handler.text(source.slice(lt + 9, end));
      i = end + 3;
      continue;
    }
    if (source.startsWith('<!', lt)) {
      // DOCTYPE (and any other markup declaration): never processed.
      if (source.slice(lt + 2, lt + 9).toUpperCase() === 'DOCTYPE')
        throw new XmlParseError('doctype');
      throw new XmlParseError('malformed');
    }
    if (source.startsWith('<?', lt)) {
      const end = source.indexOf('?>', lt + 2);
      if (end < 0) throw new XmlParseError('malformed');
      i = end + 2;
      continue;
    }
    // An element tag: find its end outside quoted attribute values.
    let j = lt + 1;
    let quote = 0;
    while (j < n) {
      const c = source.charCodeAt(j);
      if (quote !== 0) {
        if (c === quote) quote = 0;
      } else if (c === 34 || c === 39) {
        quote = c;
      } else if (c === 62) {
        break;
      }
      j += 1;
    }
    if (j >= n) throw new XmlParseError('malformed');
    if (source[lt + 1] === '/') {
      let e = lt + 2;
      while (e < j && isNameChar(source.charCodeAt(e))) e += 1;
      handler.close(source.slice(lt + 2, e));
    } else {
      let e = lt + 1;
      while (e < j && isNameChar(source.charCodeAt(e))) e += 1;
      const name = source.slice(lt + 1, e);
      if (name.length === 0) throw new XmlParseError('malformed');
      const selfClosing = source[j - 1] === '/';
      const attrEnd = selfClosing ? j - 1 : j;
      const attributes = attrEnd > e ? parseAttributes(source, e, attrEnd) : EMPTY_ATTRIBUTES;
      handler.open(name, attributes, selfClosing);
      if (selfClosing) handler.close(name);
    }
    i = j + 1;
  }
}

/** Local name of a qualified name (`w:t` → `t`). */
export const localName = (name: string): string => {
  const colon = name.indexOf(':');
  return colon < 0 ? name : name.slice(colon + 1);
};
