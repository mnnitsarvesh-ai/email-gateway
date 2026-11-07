import { parse, type DefaultTreeAdapterTypes } from 'parse5';
import { Deadline } from './deadline';

type Node = DefaultTreeAdapterTypes.Node;
type ParentNode = DefaultTreeAdapterTypes.ParentNode;

/**
 * HTML → analysis text (B8): parse5 7.3.0 (WHATWG tokenizer and tree builder; entities
 * decoded), text nodes only, `script`/`style`/`head`/`template`/`noscript` skipped, block
 * elements insert a newline. At most `maxNodes` (50 000) nodes are visited; beyond that the
 * result is marked incomplete. The document is never rendered or re-serialized. Part of
 * `bec-text/1`: the produced string is the `html_text` source that evidence offsets refer to.
 */

export const MAX_HTML_NODES = 50_000;

const SKIPPED = new Set(['script', 'style', 'head', 'template', 'noscript']);
const BLOCK = new Set([
  'address',
  'article',
  'aside',
  'blockquote',
  'br',
  'dd',
  'div',
  'dl',
  'dt',
  'fieldset',
  'figcaption',
  'figure',
  'footer',
  'form',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'header',
  'hr',
  'li',
  'main',
  'nav',
  'ol',
  'p',
  'pre',
  'section',
  'table',
  'tbody',
  'td',
  'th',
  'thead',
  'tfoot',
  'title',
  'tr',
  'ul',
]);

export interface HtmlTextResult {
  text: string;
  incomplete: boolean;
  nodes: number;
}

export function htmlToText(
  html: string,
  options: { maxNodes?: number; deadline?: Deadline } = {},
): HtmlTextResult {
  const maxNodes = options.maxNodes ?? MAX_HTML_NODES;
  const deadline = options.deadline ?? Deadline.none();
  const document = parse(html);
  const parts: string[] = [];
  let nodes = 0;
  let incomplete = false;
  const newline = (): void => {
    if (parts.length > 0 && parts.at(-1) !== '\n') parts.push('\n');
  };
  // Iterative depth-first walk (no recursion on attacker-controlled depth).
  const stack: Array<{ node: Node; exit: boolean }> = [{ node: document, exit: false }];
  while (stack.length > 0) {
    const { node, exit } = stack.pop()!;
    if (exit) {
      newline();
      continue;
    }
    nodes += 1;
    deadline.check();
    if (nodes > maxNodes) {
      incomplete = true;
      break;
    }
    if (node.nodeName === '#text') {
      parts.push((node as DefaultTreeAdapterTypes.TextNode).value);
      continue;
    }
    if (node.nodeName === '#comment' || node.nodeName === '#documentType') continue;
    const tag = node.nodeName;
    if (SKIPPED.has(tag)) continue;
    const block = BLOCK.has(tag);
    if (block) {
      newline();
      stack.push({ node, exit: true });
    }
    const children = (node as ParentNode).childNodes ?? [];
    for (let i = children.length - 1; i >= 0; i -= 1)
      stack.push({ node: children[i]!, exit: false });
  }
  return { text: parts.join('').replace(/^\n+/, ''), incomplete, nodes };
}
