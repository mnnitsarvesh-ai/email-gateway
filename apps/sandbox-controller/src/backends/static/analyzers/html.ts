import { type Analysis, countMatches, latin1 } from './analysis';
import { hostOfAuthority } from './generic';

/**
 * HTML / SVG analyzer (step 4.6 X4 `html`/`svg`): pattern checks on the markup only — nothing is
 * rendered and no script is executed or parsed by a JavaScript engine. HTML smuggling (Blob +
 * object URL + download, data-URI downloads), password inputs, forms posting to absolute URLs, an
 * external meta refresh and obfuscated script.
 */

const SCRIPT_BLOCK = /<script\b[^>]*>([\s\S]{0,1048576}?)<\/script\s*>/gi;
const EVAL_FAMILY = /\b(eval|atob|unescape|String\.fromCharCode|decodeURIComponent|Function)\s*\(/g;
const LONG_ENCODED = /[A-Za-z0-9+/]{400,}={0,2}/;
const HEX_ESCAPES = /(\\x[0-9a-fA-F]{2}){40,}|(\\u[0-9a-fA-F]{4}){30,}|(%[0-9a-fA-F]{2}){60,}/;

export function looksLikeMarkup(bytes: Buffer): 'html' | 'svg' | null {
  const head = bytes.subarray(0, 4096).toString('latin1').toLowerCase();
  if (head.includes('<svg')) return 'svg';
  if (/<(!doctype html|html|head|body|script|form|iframe|meta|a\s)/.test(head)) return 'html';
  return null;
}

function absoluteHost(url: string): ReturnType<typeof hostOfAuthority> {
  const authority = /^\s*(?:https?:)?\/\/([^/?#\s"'>]+)/i.exec(url)?.[1];
  return authority ? hostOfAuthority(authority) : null;
}

export function analyzeHtml(bytes: Buffer, analysis: Analysis, format: 'html' | 'svg'): void {
  const text = latin1(bytes);
  analysis.format = format;
  analysis.supported = true;
  const lower = text.toLowerCase();

  const scripts: string[] = [];
  for (const match of text.matchAll(SCRIPT_BLOCK)) {
    if (scripts.length >= 256) break;
    scripts.push(match[1] as string);
  }
  const scriptText = scripts.join('\n');
  // Inline handlers and javascript: URLs count as script too.
  const handlerText = (
    text.match(/\son[a-z]{3,20}\s*=\s*("[^"]{0,8192}"|'[^']{0,8192}')/gi) ?? []
  ).join('\n');
  const allScript = `${scriptText}\n${handlerText}`;
  analysis.fact('html.scripts', countMatches(lower, /<script\b/));

  // Smuggling: a Blob turned into an object URL and downloaded, or a data: URI download.
  const blob = /\bnew\s+Blob\s*\(|\bBlob\s*\(/.test(allScript);
  const objectUrl = /URL\.createObjectURL\s*\(/.test(allScript);
  const download =
    /\.download\s*=|setAttribute\s*\(\s*["']download["']|msSaveOrOpenBlob|msSaveBlob/.test(
      allScript,
    );
  let dataDownload = false;
  for (const match of text.matchAll(/<a\b([^>]{0,65536})>/gi)) {
    const attrs = match[1] as string;
    if (/(^|\s)download(\s|=|$)/i.test(attrs) && /\bhref\s*=\s*["']?\s*data:/i.test(attrs)) {
      dataDownload = true;
      break;
    }
  }
  if ((blob && objectUrl && download) || dataDownload) {
    analysis.add('static.html_smuggling');
    analysis.token(dataDownload ? 'data-uri-download' : 'blob-download');
  }

  const passwords = countMatches(text, /<input\b[^>]{0,2048}\btype\s*=\s*["']?password\b/i);
  if (passwords > 0) analysis.add('static.html_password_form', passwords);

  // A local file has no origin: any absolute action posts elsewhere.
  let externalForms = 0;
  for (const match of text.matchAll(/<form\b([^>]{0,4096})>/gi)) {
    const action = /\baction\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(match[1] as string);
    const url = action ? (action[2] ?? action[3] ?? action[4] ?? '') : '';
    const parsed = absoluteHost(url);
    if (parsed) {
      externalForms += 1;
      if (parsed.host) analysis.host(parsed.host);
      if (parsed.ip) analysis.ip(parsed.ip);
    }
  }
  if (externalForms > 0) analysis.add('static.html_external_form', externalForms);

  let refresh = 0;
  for (const match of text.matchAll(/<meta\b([^>]{0,4096})>/gi)) {
    const attrs = match[1] as string;
    if (!/http-equiv\s*=\s*["']?refresh/i.test(attrs)) continue;
    const content = /\bcontent\s*=\s*("([^"]*)"|'([^']*)')/i.exec(attrs);
    const value = content ? (content[2] ?? content[3] ?? '') : '';
    const url = /url\s*=\s*['"]?([^'"]+)/i.exec(value)?.[1] ?? '';
    const parsed = absoluteHost(url);
    if (parsed) {
      refresh += 1;
      if (parsed.host) analysis.host(parsed.host);
      if (parsed.ip) analysis.ip(parsed.ip);
    }
  }
  if (refresh > 0) analysis.add('static.html_meta_refresh_external', refresh);

  // Obfuscation: dense eval-family calls, long encoded blobs, long escape runs inside script.
  const evalCalls = countMatches(allScript, EVAL_FAMILY);
  const kib = Math.max(1, allScript.length / 1024);
  analysis.fact('html.evalPerKiB', evalCalls / kib);
  const encoded = LONG_ENCODED.test(allScript);
  const escapes = HEX_ESCAPES.test(allScript);
  if ((evalCalls >= 3 && evalCalls / kib >= 1) || (evalCalls >= 1 && (encoded || escapes))) {
    analysis.add('static.html_obfuscated_script', Math.max(1, evalCalls));
  }
}
