import { parse, type DefaultTreeAdapterTypes } from 'parse5';
import { hasInnerControlChars, trimC0Space } from '../normalize/text';
import {
  DEFAULT_EXTRACTION_LIMITS,
  type ExtractionFlag,
  type ExtractionLimits,
  type MessageCode,
  type PartExtraction,
  type Range,
  type UrlOccurrence,
} from './types';

type Element = DefaultTreeAdapterTypes.Element;
type Node = DefaultTreeAdapterTypes.Node;

/**
 * HTML extraction (U4): parse5 (WHATWG tokenizer and tree builder) with source locations; the
 * document is never rendered and never re-serialized. Every listed URL attribute is read; only
 * `a[href]`/`area[href]` are rewritable. Anchor text is kept in memory for the text-mismatch rule.
 */

type SourceKind = UrlOccurrence['source'];

/** element → attribute → source kind. `srcset` and meta refresh are handled separately. */
const URL_ATTRIBUTES: Readonly<Record<string, Readonly<Record<string, SourceKind>>>> = {
  a: { href: 'html_href' },
  area: { href: 'html_href' },
  link: { href: 'html_href' },
  form: { action: 'form_action' },
  button: { formaction: 'form_action' },
  input: { formaction: 'form_action' },
  iframe: { src: 'html_src' },
  frame: { src: 'html_src' },
  img: { src: 'html_src' },
  script: { src: 'html_src' },
  embed: { src: 'html_src' },
  source: { src: 'html_src' },
  video: { src: 'html_src' },
  audio: { src: 'html_src' },
  track: { src: 'html_src' },
  object: { data: 'html_src' },
};

/** Attributes where a `data:` URL is reported (U4); data images in `img src` are ignored. */
const DATA_URI_ATTRIBUTES = new Set([
  'a/href',
  'area/href',
  'form/action',
  'iframe/src',
  'object/data',
]);
const LINK_ATTRIBUTES = new Set([
  'a/href',
  'area/href',
  'form/action',
  'button/formaction',
  'input/formaction',
  'iframe/src',
  'frame/src',
  'object/data',
  'embed/src',
]);

const MAX_ANCHOR_TEXT = 512;

interface RawAttribute {
  /** Whole attribute range in the source. */
  range: Range;
  /** The raw (not entity-decoded) value text. */
  rawValue: string;
}

/** Locates the value of `name=value` inside the attribute's source range. */
function rawAttribute(html: string, element: Element, name: string): RawAttribute | null {
  const location = element.sourceCodeLocation?.attrs?.[name];
  if (!location) return null;
  const text = html.slice(location.startOffset, location.endOffset);
  const eq = text.indexOf('=');
  let rawValue = '';
  if (eq >= 0) {
    let value = text.slice(eq + 1).replace(/^[\t\n\f\r ]+/, '');
    const quote = value[0];
    if (quote === '"' || quote === "'")
      value = value.slice(1, value.endsWith(quote) ? -1 : undefined);
    rawValue = value;
  }
  return { range: { start: location.startOffset, end: location.endOffset }, rawValue };
}

/** Lower-case scheme of a value as a browser sees it (tab/newline stripped, leading C0/space trimmed). */
export function schemeOf(value: string): string | null {
  const text = trimC0Space(value.replace(/[\t\n\r]/g, ''), 'start');
  const match = /^([a-z][a-z0-9+.-]*):/i.exec(text);
  return match ? (match[1] ?? '').toLowerCase() : null;
}

/** A UNC path (two backslashes, or a backslash and a slash, then a host). */
const isUnc = (trimmed: string): boolean => /^\\[\\/][^\\/]/.test(trimmed);

/** Entities in the scheme/host part of the raw attribute source (`&#104;ttp`, `&colon;`). */
function entityInSchemeOrHost(rawValue: string): boolean {
  if (!rawValue.includes('&')) return false;
  const slashes = rawValue.indexOf('//');
  if (slashes < 0) return /&(#\d+|#x[0-9a-f]+|[a-z][a-z0-9]*);?/i.test(rawValue.slice(0, 32));
  // A numeric entity's `#` is not a fragment delimiter: mask entities before searching.
  const after = rawValue
    .slice(slashes + 2)
    .replace(/&#x?[0-9a-f]+;?/gi, (m) => 'e'.repeat(m.length));
  const end = after.search(/[/?#]/);
  const authorityEnd = slashes + 2 + (end < 0 ? after.length : end);
  return /&(#\d+|#x[0-9a-f]+|[a-z][a-z0-9]*);?/i.test(rawValue.slice(0, authorityEnd));
}

/** Control characters inside the (trimmed) value. */
const hasControlChars = hasInnerControlChars;

/** srcset candidates (HTML "parse a srcset attribute", URL part only). */
export function srcsetUrls(value: string): string[] {
  const urls: string[] = [];
  let i = 0;
  const n = value.length;
  const isSpace = (c: string | undefined): boolean => c !== undefined && /[\t\n\f\r ]/.test(c);
  while (i < n) {
    while (i < n && (isSpace(value[i]) || value[i] === ',')) i += 1;
    if (i >= n) break;
    let start = i;
    while (i < n && !isSpace(value[i])) i += 1;
    let url = value.slice(start, i);
    let endsCandidate = false;
    if (url.endsWith(',')) {
      url = url.replace(/,+$/, '');
      endsCandidate = true;
    }
    if (url) urls.push(url);
    if (!endsCandidate) {
      // Skip descriptors up to the next comma outside parentheses.
      let depth = 0;
      while (i < n) {
        const c = value[i];
        if (c === '(') depth += 1;
        else if (c === ')') depth = Math.max(0, depth - 1);
        else if (c === ',' && depth === 0) break;
        i += 1;
      }
    }
    start = i;
  }
  return urls;
}

/** The URL of a `<meta http-equiv=refresh content="5; url=…">`, or null. */
export function metaRefreshUrl(content: string): string | null {
  const match = /^\s*[\d.]*\s*[;,]?\s*(?:url\s*=\s*)?(.*)$/is.exec(content);
  if (!match) return null;
  let url = (match[1] ?? '').trim();
  if (!url) return null;
  const quote = url[0];
  if (quote === '"' || quote === "'") {
    const end = url.indexOf(quote, 1);
    url = end > 0 ? url.slice(1, end) : url.slice(1);
  }
  return url.trim() || null;
}

function textOf(element: Element): string {
  let text = '';
  const stack: Node[] = [...element.childNodes].reverse();
  while (stack.length > 0 && text.length < MAX_ANCHOR_TEXT) {
    const node = stack.pop() as Node;
    if (node.nodeName === '#text') text += (node as DefaultTreeAdapterTypes.TextNode).value;
    else if ('childNodes' in node) stack.push(...[...node.childNodes].reverse());
  }
  return text.replace(/\s+/g, ' ').trim().slice(0, MAX_ANCHOR_TEXT);
}

const attr = (element: Element, name: string): string | undefined =>
  element.attrs.find((a) => a.name === name)?.value;

/** Elements in document order (iterative: no recursion limit on deep markup). */
function* elements(root: Node): Generator<Element> {
  const stack: Node[] = [root];
  while (stack.length > 0) {
    const node = stack.pop() as Node;
    if ('tagName' in node) yield node;
    const children: Node[] = [];
    if ('childNodes' in node) children.push(...node.childNodes);
    if (node.nodeName === 'template' && 'content' in node) {
      children.push(node.content);
    }
    for (let i = children.length - 1; i >= 0; i -= 1) stack.push(children[i] as Node);
  }
}

function resolve(value: string, base: string | null): string | null {
  const trimmed = trimC0Space(value);
  if (!trimmed) return null;
  const scheme = schemeOf(trimmed);
  if (scheme !== null) return trimmed;
  if (base === null) return null;
  try {
    return new URL(trimmed, base).href;
  } catch {
    return null;
  }
}

export function extractFromHtml(
  html: string,
  limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
): PartExtraction {
  const document = parse(html, { sourceCodeLocationInfo: true });
  const occurrences: UrlOccurrence[] = [];
  const messageCodes: Partial<Record<MessageCode, number>> = {};
  const count = (code: MessageCode): void => {
    messageCodes[code] = (messageCodes[code] ?? 0) + 1;
  };
  let limitHit = false;

  // The first base[href] with an absolute http(s) URL (only such a base is used).
  let base: string | null = null;
  for (const element of elements(document)) {
    if (element.tagName !== 'base') continue;
    const href = attr(element, 'href');
    if (href === undefined) continue;
    const trimmed = href.trim();
    if (/^https?:\/\//i.test(trimmed)) {
      try {
        base = new URL(trimmed).href;
      } catch {
        base = null;
      }
    }
    break;
  }

  const add = (
    element: Element,
    attribute: string,
    raw: string,
    source: SourceKind,
    rawAttr: RawAttribute | null,
  ): void => {
    if (limitHit) return;
    const key = `${element.tagName}/${attribute}`;
    const trimmed = trimC0Space(raw);
    if (!trimmed || trimmed.startsWith('#')) return;
    const scheme = schemeOf(trimmed);
    if (scheme === 'javascript' || scheme === 'vbscript') {
      if (LINK_ATTRIBUTES.has(key) || source === 'html_href') count('url.script_scheme');
      return;
    }
    if (scheme === 'data') {
      if (DATA_URI_ATTRIBUTES.has(key)) count('url.data_uri');
      return;
    }
    if (scheme === 'file' || scheme === 'smb' || (scheme === null && isUnc(trimmed))) {
      if (LINK_ATTRIBUTES.has(key) || source === 'html_href') count('url.unsafe_scheme');
      return;
    }
    if (scheme !== null && scheme !== 'http' && scheme !== 'https') return; // mailto:, tel:, cid:, …
    const candidate = resolve(trimmed, base);
    if (candidate === null) return;
    if (occurrences.length >= limits.maxOccurrences) {
      limitHit = true;
      return;
    }
    const flags: ExtractionFlag[] = [];
    if (rawAttr && entityInSchemeOrHost(rawAttr.rawValue)) flags.push('url.entity_obfuscation');
    if (hasControlChars(raw)) flags.push('url.control_chars');
    const rewritable =
      source === 'html_href' && (element.tagName === 'a' || element.tagName === 'area');
    occurrences.push({
      raw,
      candidate,
      source,
      element: element.tagName,
      attribute,
      range: rawAttr?.range ?? { start: -1, end: -1 },
      flags,
      anchorText: element.tagName === 'a' ? textOf(element) : null,
      rewritable: rewritable && rawAttr !== null,
    });
  };

  for (const element of elements(document)) {
    if (limitHit) break;
    const tag = element.tagName;
    const attributes = URL_ATTRIBUTES[tag];
    if (attributes) {
      for (const [name, source] of Object.entries(attributes)) {
        const value = attr(element, name);
        if (value === undefined) continue;
        add(element, name, value, source, rawAttribute(html, element, name));
      }
    }
    if (tag === 'img' || tag === 'source') {
      const srcset = attr(element, 'srcset');
      if (srcset !== undefined) {
        for (const url of srcsetUrls(srcset)) add(element, 'srcset', url, 'srcset', null);
      }
    }
    if (tag === 'meta' && (attr(element, 'http-equiv') ?? '').trim().toLowerCase() === 'refresh') {
      const content = attr(element, 'content');
      const url = content === undefined ? null : metaRefreshUrl(content);
      if (url !== null) add(element, 'content', url, 'meta_refresh', null);
    }
  }
  if (limitHit) count('limit.url_count');
  return { occurrences, messageCodes, limitHit };
}

/** The first `<meta http-equiv=refresh>` URL of a document (redirect hops, U8), or null. */
export function findMetaRefresh(html: string): string | null {
  const document = parse(html);
  for (const element of elements(document)) {
    if (element.tagName !== 'meta') continue;
    if ((attr(element, 'http-equiv') ?? '').trim().toLowerCase() !== 'refresh') continue;
    const content = attr(element, 'content');
    const url = content === undefined ? null : metaRefreshUrl(content);
    if (url !== null) return url;
  }
  return null;
}
