import { parse, type DefaultTreeAdapterTypes } from 'parse5';
import { normalizeUrl, registrableDomainOf } from '../normalize/url';

/**
 * Static landing features (U9) from at most URL_FETCH_MAX_BODY_BYTES of a final text/html page,
 * parsed with parse5 and never stored: counts, booleans, hosts and brand ids only, never text.
 */

export interface LandingFeatures {
  /** `input[type=password]` count. */
  passwordFields: number;
  forms: number;
  /** A form action whose registrable domain differs from the page's. */
  crossOriginFormAction: boolean;
  /** Hosts of absolute form actions (≤ 5, ASCII). */
  formActionHosts: string[];
  /** Ids of protected entries whose label is a word of `<title>` on a non-official page. */
  titleBrandMatches: string[];
}

export const MAX_FORM_ACTION_HOSTS = 5;
export const MAX_TITLE_BRAND_MATCHES = 5;

/** A protected entry as the title rule sees it (brands and extra domains of the ProtectedSet). */
export interface TitleBrand {
  id: string;
  label: string;
  official: ReadonlySet<string>;
}

type Node = DefaultTreeAdapterTypes.Node;
type Element = DefaultTreeAdapterTypes.Element;

function* walk(root: Node): Generator<Element> {
  const stack: Node[] = [root];
  while (stack.length > 0) {
    const node = stack.pop() as Node;
    if ('tagName' in node) yield node;
    const children: Node[] = 'childNodes' in node ? [...node.childNodes] : [];
    if (node.nodeName === 'template' && 'content' in node) {
      children.push(node.content);
    }
    for (let i = children.length - 1; i >= 0; i -= 1) stack.push(children[i] as Node);
  }
}

const attr = (element: Element, name: string): string | undefined =>
  element.attrs.find((a) => a.name === name)?.value;

function text(element: Element): string {
  let out = '';
  const stack: Node[] = [...element.childNodes].reverse();
  while (stack.length > 0 && out.length < 1024) {
    const node = stack.pop() as Node;
    if (node.nodeName === '#text') out += (node as DefaultTreeAdapterTypes.TextNode).value;
    else if ('childNodes' in node) stack.push(...[...node.childNodes].reverse());
  }
  return out;
}

export function extractLandingFeatures(
  html: string,
  pageUrl: string,
  brands: readonly TitleBrand[] = [],
  maxChars = 262_144,
): LandingFeatures {
  const document = parse(html.slice(0, maxChars));
  const page = normalizeUrl(pageUrl);
  const pageHost = page.ok ? page.url.host : null;
  const pageRegistrable = page.ok ? (page.url.registrableDomain ?? page.url.host) : null;
  let base = pageUrl;
  let passwordFields = 0;
  let forms = 0;
  let crossOriginFormAction = false;
  const formActionHosts: string[] = [];
  let title = '';

  for (const element of walk(document)) {
    if (element.tagName === 'base') {
      const href = attr(element, 'href');
      if (href && /^https?:\/\//i.test(href.trim())) base = href.trim();
    }
  }
  for (const element of walk(document)) {
    switch (element.tagName) {
      case 'title':
        if (!title) title = text(element);
        break;
      case 'input':
        if ((attr(element, 'type') ?? '').trim().toLowerCase() === 'password') passwordFields += 1;
        break;
      case 'form': {
        forms += 1;
        const action = (attr(element, 'action') ?? '').trim();
        if (!action) break;
        const resolved = normalizeUrl(action, { base });
        if (!resolved.ok) break;
        const host = resolved.url.host;
        if (
          host !== pageHost &&
          !formActionHosts.includes(host) &&
          formActionHosts.length < MAX_FORM_ACTION_HOSTS
        ) {
          formActionHosts.push(host);
        }
        const actionRegistrable = resolved.url.registrableDomain ?? host;
        if (pageRegistrable !== null && actionRegistrable !== pageRegistrable)
          crossOriginFormAction = true;
        break;
      }
      default:
        break;
    }
  }

  const words = new Set(
    title
      .toLowerCase()
      .split(/[^\p{L}\p{N}]+/u)
      .filter(Boolean),
  );
  const pageDomain = pageHost === null ? null : registrableDomainOf(pageHost);
  const titleBrandMatches: string[] = [];
  for (const brand of brands) {
    if (titleBrandMatches.length >= MAX_TITLE_BRAND_MATCHES) break;
    if (pageDomain !== null && brand.official.has(pageDomain)) continue;
    if (words.has(brand.label.toLowerCase())) titleBrandMatches.push(brand.id);
  }
  return { passwordFields, forms, crossOriginFormAction, formActionHosts, titleBrandMatches };
}
