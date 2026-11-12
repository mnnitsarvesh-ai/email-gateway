import { parse, type DefaultTreeAdapterTypes } from 'parse5';

/**
 * HTML → plain text for the quarantine preview (step 5.3 Q11, ADR-0048). parse5 (the WHATWG
 * tokenizer and tree builder) parses the decoded HTML part; the tree is walked iteratively (no
 * recursion: deeply nested markup cannot overflow the stack) and only text comes out:
 *
 * - subtrees of `script`, `style`, `noscript`, `template`, `head`, `object`, `embed`, `iframe`,
 *   `frame`, `frameset`, `svg`, `math`, `form` (and `title`, `select`, `textarea`, `button`) are
 *   dropped; comments and processing instructions never produce text;
 * - `img`/`picture` become `[image]`, `video`/`audio` become `[media]` (no `src`, no data URI,
 *   no CSS — attributes are never copied);
 * - anchors (`a[href]`, `area[href]`) become `text [link N]`; the target goes to the link list;
 * - block elements become line breaks; entities are decoded by the parser.
 *
 * The caller sanitizes, defangs and masks the result.
 */

type Node = DefaultTreeAdapterTypes.Node;
type Element = DefaultTreeAdapterTypes.Element;

export const DROPPED_ELEMENTS: ReadonlySet<string> = new Set([
  'script',
  'style',
  'noscript',
  'template',
  'head',
  'object',
  'embed',
  'iframe',
  'frame',
  'frameset',
  'svg',
  'math',
  'form',
  'title',
  'select',
  'textarea',
  'button',
  'applet',
  'base',
  'link',
  'meta',
]);

const BLOCK = new Set([
  'address',
  'article',
  'aside',
  'blockquote',
  'body',
  'caption',
  'center',
  'dd',
  'details',
  'dialog',
  'div',
  'dl',
  'dt',
  'fieldset',
  'figcaption',
  'figure',
  'footer',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'header',
  'hr',
  'html',
  'legend',
  'li',
  'main',
  'nav',
  'ol',
  'p',
  'pre',
  'section',
  'summary',
  'table',
  'tbody',
  'tfoot',
  'thead',
  'tr',
  'ul',
]);
const CELL = new Set(['td', 'th']);
const IMAGE = new Set(['img', 'picture', 'image']);
const MEDIA = new Set(['video', 'audio']);
const PREFORMATTED = new Set(['pre', 'listing', 'plaintext', 'xmp']);

export interface HtmlToTextLimits {
  /** Stop collecting once this many characters were produced (the caller truncates). */
  maxChars: number;
  /** Nodes visited at most (bounded work on pathological documents). */
  maxNodes: number;
}

export interface HtmlToTextResult {
  text: string;
  /** Output or node budget exhausted. */
  truncated: boolean;
}

const hrefOf = (el: Element): string | null =>
  el.attrs.find((a) => a.name.toLowerCase() === 'href')?.value ?? null;

/**
 * Converts HTML to text. `onLink(href)` registers an anchor target and returns its number for
 * the `[link N]` marker.
 */
export function htmlToPreviewText(
  html: string,
  limits: HtmlToTextLimits,
  onLink: (href: string) => number,
): HtmlToTextResult {
  const document = parse(html);
  const out: string[] = [];
  let length = 0;
  let truncated = false;
  let visited = 0;
  let pre = 0;
  const emit = (s: string) => {
    if (s.length === 0 || truncated) return;
    out.push(s);
    length += s.length;
    if (length > limits.maxChars) truncated = true;
  };
  const newline = () => emit('\n');

  type Frame = { node: Node; exit: false } | { exit: true; run: () => void };
  const stack: Frame[] = [{ node: document, exit: false }];
  while (stack.length > 0 && !truncated) {
    const frame = stack.pop()!;
    if (frame.exit) {
      frame.run();
      continue;
    }
    visited += 1;
    if (visited > limits.maxNodes) {
      truncated = true;
      break;
    }
    const node = frame.node;
    if (node.nodeName === '#text') {
      const value = (node as DefaultTreeAdapterTypes.TextNode).value;
      emit(pre > 0 ? value : value.replace(/[\t\n\f\r ]+/g, ' '));
      continue;
    }
    if (node.nodeName === '#comment' || node.nodeName === '#documentType') continue;
    const children = (node as { childNodes?: Node[] }).childNodes ?? [];
    const pushChildren = () => {
      for (let i = children.length - 1; i >= 0; i -= 1) {
        stack.push({ node: children[i]!, exit: false });
      }
    };
    if (node.nodeName === '#document' || node.nodeName === '#document-fragment') {
      pushChildren();
      continue;
    }
    const el = node as Element;
    const tag = el.tagName.toLowerCase();
    if (DROPPED_ELEMENTS.has(tag)) continue;
    if (IMAGE.has(tag)) {
      emit(' [image] ');
      continue;
    }
    if (MEDIA.has(tag)) {
      emit(' [media] ');
      continue;
    }
    if (tag === 'br') {
      newline();
      continue;
    }
    if ((tag === 'a' || tag === 'area') && hrefOf(el) !== null) {
      const n = onLink(hrefOf(el)!);
      stack.push({ exit: true, run: () => emit(` [link ${n}]`) });
      pushChildren();
      continue;
    }
    if (BLOCK.has(tag)) {
      newline();
      if (tag === 'li') emit('- ');
      if (tag === 'hr') emit('----------');
      const isPre = PREFORMATTED.has(tag);
      if (isPre) pre += 1;
      stack.push({
        exit: true,
        run: () => {
          if (isPre) pre -= 1;
          // List items are separated by the next item's own line break.
          if (tag !== 'li') newline();
        },
      });
      pushChildren();
      continue;
    }
    if (CELL.has(tag)) {
      stack.push({ exit: true, run: () => emit('\t') });
      pushChildren();
      continue;
    }
    if (PREFORMATTED.has(tag)) {
      pre += 1;
      stack.push({ exit: true, run: () => (pre -= 1) });
      pushChildren();
      continue;
    }
    pushChildren();
  }
  const text = out
    .join('')
    .split('\n')
    .map((line) =>
      line
        .replace(/ {2,}/g, ' ')
        .replace(/[ \t]+$/g, '')
        .replace(/^ +/, ''),
    )
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return { text, truncated };
}
