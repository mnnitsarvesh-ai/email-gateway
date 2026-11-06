import {
  DEFAULT_EXTRACTION_LIMITS,
  type ExtractionFlag,
  type ExtractionLimits,
  type MessageCode,
  type PartExtraction,
  type UrlOccurrence,
} from './types';

/**
 * Plain-text extraction (U4): only the text body and text attachments (HTML text nodes are not
 * scanned). `http://`, `https://` (any case) and `www.` (treated as `http://`); a URL ends at
 * whitespace, a control character, `<`, `>` or `"`; trailing `.,;:!?'` are dropped and a trailing
 * `)`, `]` or `}` only when unbalanced. `<URL:…>` and `<…>` wrappers end at `>`.
 */

const START = /(?:https?:\/\/|www\.)/gi;
// eslint-disable-next-line no-control-regex
const TERMINATOR = /[\s<>"\u0000-\u001f\u007f]/;
const TRAILING = new Set(['.', ',', ';', ':', '!', '?', "'"]);
const PAIRS: Readonly<Record<string, string>> = { ')': '(', ']': '[', '}': '{' };

function trimTrailing(url: string): string {
  let text = url;
  for (;;) {
    const last = text[text.length - 1];
    if (last === undefined) return text;
    if (TRAILING.has(last)) {
      text = text.slice(0, -1);
      continue;
    }
    const open = PAIRS[last];
    if (open !== undefined) {
      let opens = 0;
      let closes = 0;
      for (const c of text) {
        if (c === open) opens += 1;
        else if (c === last) closes += 1;
      }
      if (closes > opens) {
        text = text.slice(0, -1);
        continue;
      }
    }
    return text;
  }
}

export function extractFromText(
  text: string,
  limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
): PartExtraction {
  const occurrences: UrlOccurrence[] = [];
  const messageCodes: Partial<Record<MessageCode, number>> = {};
  let limitHit = false;
  START.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = START.exec(text)) !== null) {
    const start = match.index;
    const previous = start > 0 ? text[start - 1] : undefined;
    // Inside a word or a longer URL/host (`xhttp://`, `a.www.b`, `/www.`) is not a URL start.
    if (previous !== undefined && /[\p{L}\p{N}_\-.@/\\]/u.test(previous)) continue;
    let end = start + match[0].length;
    while (end < text.length && !TERMINATOR.test(text[end] as string)) end += 1;
    const raw = trimTrailing(text.slice(start, end));
    START.lastIndex = start + Math.max(raw.length, match[0].length);
    const www = /^www\./i.test(raw);
    // Nothing after the scheme or `www.` (or only a path): not a URL.
    if (!/^[^/?#\s]/.test(raw.slice(match[0].length))) continue;
    if (occurrences.length >= limits.maxOccurrences) {
      limitHit = true;
      break;
    }
    const flags: ExtractionFlag[] = [];
    occurrences.push({
      raw,
      candidate: www ? `http://${raw}` : raw,
      source: 'text',
      element: null,
      attribute: null,
      range: { start, end: start + raw.length },
      flags,
      anchorText: null,
      rewritable: true,
    });
  }
  if (limitHit) messageCodes['limit.url_count'] = 1;
  return { occurrences, messageCodes, limitHit };
}
