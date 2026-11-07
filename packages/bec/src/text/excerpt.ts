import type { LexiconCategory } from './lexicon';
import type { TextAnalysis, TextSource, TextSpan } from './analyze';

/**
 * LLM data minimization (B10): a bounded excerpt of the analysis text with redaction.
 *
 * Windows: up to 3 windows of ±200 characters around the strongest lexicon matches (category
 * weight of bec-map/1, then position; overlapping windows of one source merged), or the first
 * 600 characters of the body text when nothing matched; ≤ `maxChars` (BEC_LLM_MAX_EXCERPT_CHARS,
 * 1 500) in total after redaction; plus the subject (≤ 200, redacted). Redaction order (each
 * replacement counted): e-mail addresses → [EMAIL]; URLs and domain-like tokens → [URL];
 * IBAN/account/IFSC/SWIFT/card-like digit runs and any digit run ≥ 4 → [NUMBER]; phone numbers
 * → [PHONE]; executive / vendor profile names and aliases → [EXECUTIVE] / [VENDOR]; tenant
 * domain labels → [ORG]. The window map (segments) maps excerpt offsets back to source offsets.
 */

export const EXCERPT_WINDOW_RADIUS = 200;
export const EXCERPT_MAX_WINDOWS = 3;
export const EXCERPT_FALLBACK_CHARS = 600;
export const EXCERPT_SUBJECT_MAX = 200;
export const EXCERPT_SEPARATOR = '\n…\n';

export type RedactionKind = 'email' | 'url' | 'number' | 'phone' | 'executive' | 'vendor' | 'org';
export const REDACTION_PLACEHOLDERS: Readonly<Record<RedactionKind, string>> = {
  email: '[EMAIL]',
  url: '[URL]',
  number: '[NUMBER]',
  phone: '[PHONE]',
  executive: '[EXECUTIVE]',
  vendor: '[VENDOR]',
  org: '[ORG]',
};

export interface ExcerptSegment {
  kind: 'text' | 'placeholder' | 'separator';
  excerptStart: number;
  excerptEnd: number;
  /** null for separators. */
  source: TextSource | null;
  sourceStart: number;
  sourceEnd: number;
  window: number;
}

export interface RedactedExcerpt {
  subject: string | null;
  text: string;
  segments: ExcerptSegment[];
  redactions: Record<RedactionKind, number>;
  /** Windows were cut to respect the character budget. */
  truncated: boolean;
}

export interface RedactionContext {
  executiveNames: readonly string[];
  vendorNames: readonly string[];
  /** Tenant registrable domain labels (domain minus public suffix), e.g. `acme`. */
  tenantLabels: readonly string[];
}

/** Category strength used to pick windows (bec-map/1 weights of the C rules). */
export const CATEGORY_STRENGTH: Readonly<Record<LexiconCategory, number>> = {
  gift_card: 30,
  payroll_change: 30,
  bank_change: 25,
  invoice_change: 20,
  payment_request: 15,
  wire_transfer: 15,
  secrecy: 15,
  credential_request: 15,
  urgency: 10,
  authority: 0,
};

interface Piece {
  kind: 'text' | 'placeholder' | 'separator';
  value: string;
  source: TextSource | null;
  sourceStart: number;
  sourceEnd: number;
  window: number;
}

type Finder = (value: string) => Array<[number, number]>;

const WORD = /[\p{L}\p{M}\p{N}]/u;
const isWord = (c: string | undefined): boolean => c !== undefined && WORD.test(c);
/** Decimal digits of any script (ASCII, Devanagari ०–९, …): every digit run is redacted. */
const DIGIT = /\p{Nd}/u;
const isDigit = (c: string | undefined): boolean => c !== undefined && DIGIT.test(c);
/** Latin letters and decimal digits of any script form the tokens of digit groups. */
const isAlnum = (c: string | undefined): boolean =>
  c !== undefined && (/[A-Za-z]/.test(c) || DIGIT.test(c));

/** Non-overlapping, sorted ranges. */
const normalizeRanges = (ranges: Array<[number, number]>): Array<[number, number]> => {
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const out: Array<[number, number]> = [];
  for (const range of ranges) {
    const last = out.at(-1);
    if (last && range[0] < last[1]) {
      last[1] = Math.max(last[1], range[1]);
    } else if (range[1] > range[0]) {
      out.push([range[0], range[1]]);
    }
  }
  return out;
};

const findEmails: Finder = (value) => {
  const ranges: Array<[number, number]> = [];
  const local = /[\p{L}\p{N}._%+'-]/u;
  const domain = /[\p{L}\p{N}.-]/u;
  for (let i = value.indexOf('@'); i >= 0; i = value.indexOf('@', i + 1)) {
    let s = i;
    while (s > 0 && local.test(value[s - 1]!)) s -= 1;
    let e = i + 1;
    while (e < value.length && domain.test(value[e]!)) e += 1;
    while (e > i + 1 && (value[e - 1] === '.' || value[e - 1] === '-')) e -= 1;
    if (s < i && value.slice(i + 1, e).includes('.')) ranges.push([s, e]);
  }
  return ranges;
};

const TOKEN_BREAK = /[\s<>()"'[\]{}|]/u;
const DOMAIN_LABEL = /^[\p{L}\p{N}-]+$/u;
const TLD = /^\p{L}{2,}$/u;

const findUrls: Finder = (value) => {
  const ranges: Array<[number, number]> = [];
  let i = 0;
  while (i < value.length) {
    if (TOKEN_BREAK.test(value[i]!)) {
      i += 1;
      continue;
    }
    const start = i;
    while (i < value.length && !TOKEN_BREAK.test(value[i]!)) i += 1;
    let end = i;
    while (end > start && /[.,;:!?]/.test(value[end - 1]!)) end -= 1;
    const token = value.slice(start, end);
    const lower = token.toLowerCase();
    if (lower.includes('://') || lower.startsWith('www.')) {
      ranges.push([start, end]);
      continue;
    }
    // domain-like: label(.label)+ with an alphabetic last label of ≥ 2 letters (paths allowed)
    const host = token.split(/[/?#]/u)[0]!;
    const labels = host.split('.');
    if (
      labels.length >= 2 &&
      labels.every((l) => l.length > 0 && DOMAIN_LABEL.test(l)) &&
      TLD.test(labels.at(-1)!)
    ) {
      ranges.push([start, end]);
    }
  }
  return ranges;
};

interface DigitGroup {
  start: number;
  end: number;
  digits: number;
}

/** Groups of alphanumeric tokens holding digits, joined by 1–2 of ` -./,()`. */
function digitGroups(value: string): DigitGroup[] {
  const groups: DigitGroup[] = [];
  let i = 0;
  let current: DigitGroup | null = null;
  while (i < value.length) {
    if (!isAlnum(value[i])) {
      i += 1;
      continue;
    }
    const start = i;
    let digits = 0;
    while (i < value.length && isAlnum(value[i])) {
      if (isDigit(value[i])) digits += 1;
      i += 1;
    }
    if (digits === 0) {
      if (current) groups.push(current);
      current = null;
      continue;
    }
    const gap = current ? value.slice(current.end, start) : '';
    if (current && gap.length >= 1 && gap.length <= 2 && /^[ \-./,()]+$/.test(gap)) {
      current.end = i;
      current.digits += digits;
    } else {
      if (current) groups.push(current);
      current = { start, end: i, digits };
    }
  }
  if (current) groups.push(current);
  return groups;
}

const phonePrefix = (value: string, start: number): number => {
  let k = start - 1;
  if (value[k] === ' ') k -= 1;
  return value[k] === '+' || value[k] === '(' ? k : -1;
};

const MIN_PHONE_DIGITS = 6;

const makeNumberFinder =
  (bicContext: boolean): Finder =>
  (value) => {
    const ranges: Array<[number, number]> = [];
    for (const group of digitGroups(value)) {
      if (group.digits < 4) continue;
      if (group.digits >= MIN_PHONE_DIGITS && phonePrefix(value, group.start) >= 0) continue;
      ranges.push([group.start, group.end]);
    }
    if (bicContext) {
      // SWIFT/BIC codes are letters only (AAAABBCC[DDD]); redacted when a swift/bic word is near.
      const re = /\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;
      for (let m = re.exec(value); m; m = re.exec(value))
        ranges.push([m.index, m.index + m[0].length]);
    }
    return ranges;
  };

const findPhones: Finder = (value) => {
  const ranges: Array<[number, number]> = [];
  for (const group of digitGroups(value)) {
    if (group.digits < 4) continue;
    const prefix = phonePrefix(value, group.start);
    ranges.push([
      prefix >= 0 ? prefix : group.start,
      group.end + (value[group.end] === ')' ? 1 : 0),
    ]);
  }
  return ranges;
};

interface WordTok {
  lower: string;
  start: number;
  end: number;
}

const words = (value: string): WordTok[] => {
  const out: WordTok[] = [];
  let i = 0;
  while (i < value.length) {
    if (!isWord(value[i])) {
      i += 1;
      continue;
    }
    const start = i;
    while (i < value.length && isWord(value[i])) i += 1;
    out.push({ lower: value.slice(start, i).normalize('NFKC').toLowerCase(), start, end: i });
  }
  return out;
};

const phraseTokens = (phrase: string): string[] => words(phrase).map((w) => w.lower);

/** Whole-token phrase occurrences (case-insensitive), then each token of ≥ 3 characters. */
const makePhraseFinder =
  (phrases: readonly string[]): Finder =>
  (value) => {
    const tokens = words(value);
    const ranges: Array<[number, number]> = [];
    const lists = phrases.map(phraseTokens).filter((p) => p.length > 0);
    for (const phrase of lists) {
      for (let i = 0; i + phrase.length <= tokens.length; i += 1) {
        let ok = true;
        for (let k = 0; k < phrase.length && ok; k += 1) ok = tokens[i + k]!.lower === phrase[k];
        if (ok) ranges.push([tokens[i]!.start, tokens[i + phrase.length - 1]!.end]);
      }
    }
    const single = new Set(lists.flat().filter((t) => [...t].length >= 3));
    for (const token of tokens) if (single.has(token.lower)) ranges.push([token.start, token.end]);
    return ranges;
  };

function applyPass(
  pieces: Piece[],
  finder: Finder,
  kind: RedactionKind,
  counts: Record<RedactionKind, number>,
): Piece[] {
  const out: Piece[] = [];
  for (const piece of pieces) {
    if (piece.kind !== 'text') {
      out.push(piece);
      continue;
    }
    const ranges = normalizeRanges(finder(piece.value));
    if (ranges.length === 0) {
      out.push(piece);
      continue;
    }
    let cursor = 0;
    for (const [s, e] of ranges) {
      if (s > cursor) {
        out.push({
          ...piece,
          value: piece.value.slice(cursor, s),
          sourceStart: piece.sourceStart + cursor,
          sourceEnd: piece.sourceStart + s,
        });
      }
      out.push({
        ...piece,
        kind: 'placeholder',
        value: REDACTION_PLACEHOLDERS[kind],
        sourceStart: piece.sourceStart + s,
        sourceEnd: piece.sourceStart + e,
      });
      counts[kind] += 1;
      cursor = e;
    }
    if (cursor < piece.value.length) {
      out.push({
        ...piece,
        value: piece.value.slice(cursor),
        sourceStart: piece.sourceStart + cursor,
        sourceEnd: piece.sourceEnd,
      });
    }
  }
  return out;
}

function redactPieces(
  pieces: Piece[],
  context: RedactionContext,
  counts: Record<RedactionKind, number>,
): Piece[] {
  const joined = pieces
    .map((p) => p.value)
    .join(' ')
    .toLowerCase();
  const bicContext = /\b(swift|bic)\b/.test(joined);
  let out = applyPass(pieces, findEmails, 'email', counts);
  out = applyPass(out, findUrls, 'url', counts);
  out = applyPass(out, makeNumberFinder(bicContext), 'number', counts);
  out = applyPass(out, findPhones, 'phone', counts);
  out = applyPass(out, makePhraseFinder(context.executiveNames), 'executive', counts);
  out = applyPass(out, makePhraseFinder(context.vendorNames), 'vendor', counts);
  out = applyPass(
    out,
    makePhraseFinder(context.tenantLabels.flatMap((l) => [l, l.replace(/-/g, ' ')])),
    'org',
    counts,
  );
  return out;
}

const emptyCounts = (): Record<RedactionKind, number> => ({
  email: 0,
  url: 0,
  number: 0,
  phone: 0,
  executive: 0,
  vendor: 0,
  org: 0,
});

/** Adjusts an index so it does not split a surrogate pair. */
const safeIndex = (value: string, index: number): number => {
  const i = Math.max(0, Math.min(value.length, index));
  const code = value.charCodeAt(i);
  return i > 0 && i < value.length && code >= 0xdc00 && code <= 0xdfff ? i - 1 : i;
};

interface Window {
  source: TextSource;
  start: number;
  end: number;
}

export function buildExcerpt(
  analysis: Pick<TextAnalysis, 'sources' | 'matches'>,
  context: RedactionContext,
  maxChars: number,
): RedactedExcerpt {
  const counts = emptyCounts();
  // Subject (≤ 200, redacted; no window map: model spans refer to `text` only).
  let subject: string | null = null;
  if (analysis.sources.subject) {
    const raw = analysis.sources.subject.slice(
      0,
      safeIndex(analysis.sources.subject, EXCERPT_SUBJECT_MAX),
    );
    subject = redactPieces(
      [
        {
          kind: 'text',
          value: raw,
          source: 'subject',
          sourceStart: 0,
          sourceEnd: raw.length,
          window: -1,
        },
      ],
      context,
      counts,
    )
      .map((p) => p.value)
      .join('');
  }

  // Window selection over body sources.
  const bodyMatches = analysis.matches
    .filter((m) => m.source !== 'subject')
    .sort(
      (a, b) =>
        CATEGORY_STRENGTH[b.category] - CATEGORY_STRENGTH[a.category] ||
        (a.source < b.source ? -1 : a.source > b.source ? 1 : 0) ||
        a.start - b.start,
    );
  const windows: Window[] = [];
  for (const match of bodyMatches) {
    if (CATEGORY_STRENGTH[match.category] === 0) continue;
    const text = analysis.sources[match.source]!;
    const window: Window = {
      source: match.source,
      start: safeIndex(text, match.start - EXCERPT_WINDOW_RADIUS),
      end: safeIndex(text, match.end + EXCERPT_WINDOW_RADIUS),
    };
    const overlapping = windows.find(
      (w) => w.source === window.source && window.start <= w.end && w.start <= window.end,
    );
    if (overlapping) {
      overlapping.start = Math.min(overlapping.start, window.start);
      overlapping.end = Math.max(overlapping.end, window.end);
      continue;
    }
    if (windows.length >= EXCERPT_MAX_WINDOWS) continue;
    windows.push(window);
  }
  if (windows.length === 0) {
    const source: TextSource | null = analysis.sources.text
      ? 'text'
      : analysis.sources.html_text
        ? 'html_text'
        : null;
    if (source) {
      const text = analysis.sources[source]!;
      windows.push({ source, start: 0, end: safeIndex(text, EXCERPT_FALLBACK_CHARS) });
    }
  }
  windows.sort(
    (a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0) || a.start - b.start,
  );

  // Redact each window, then lay the pieces out within the budget.
  const segments: ExcerptSegment[] = [];
  let text = '';
  let truncated = false;
  windows.forEach((window, index) => {
    if (text.length >= maxChars) {
      truncated = true;
      return;
    }
    const sourceText = analysis.sources[window.source]!;
    const pieces = redactPieces(
      [
        {
          kind: 'text',
          value: sourceText.slice(window.start, window.end),
          source: window.source,
          sourceStart: window.start,
          sourceEnd: window.end,
          window: index,
        },
      ],
      context,
      counts,
    );
    if (segments.length > 0) {
      if (text.length + EXCERPT_SEPARATOR.length >= maxChars) {
        truncated = true;
        return;
      }
      segments.push({
        kind: 'separator',
        excerptStart: text.length,
        excerptEnd: text.length + EXCERPT_SEPARATOR.length,
        source: null,
        sourceStart: 0,
        sourceEnd: 0,
        window: -1,
      });
      text += EXCERPT_SEPARATOR;
    }
    for (const piece of pieces) {
      const room = maxChars - text.length;
      if (room <= 0) {
        truncated = true;
        break;
      }
      let value = piece.value;
      let sourceEnd = piece.sourceEnd;
      if (value.length > room) {
        truncated = true;
        if (piece.kind !== 'text') break; // never cut a placeholder
        value = value.slice(0, safeIndex(value, room));
        sourceEnd = piece.sourceStart + value.length;
        if (!value) break;
      }
      segments.push({
        kind: piece.kind,
        excerptStart: text.length,
        excerptEnd: text.length + value.length,
        source: piece.source,
        sourceStart: piece.sourceStart,
        sourceEnd,
        window: index,
      });
      text += value;
    }
  });
  return { subject, text, segments, redactions: counts, truncated };
}

/**
 * Maps an excerpt range [start, end) back to source offsets through the window map. Ranges
 * outside the excerpt, crossing windows, or starting/ending in a separator are dropped (null).
 */
export function mapExcerptSpan(
  excerpt: RedactedExcerpt,
  start: number,
  end: number,
): TextSpan | null {
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start) return null;
  if (end > excerpt.text.length) return null;
  const first = excerpt.segments.find((s) => start >= s.excerptStart && start < s.excerptEnd);
  const last = excerpt.segments.find((s) => end > s.excerptStart && end <= s.excerptEnd);
  if (!first || !last || first.kind === 'separator' || last.kind === 'separator') return null;
  if (first.window !== last.window || first.source === null) return null;
  const sourceStart =
    first.kind === 'text' ? first.sourceStart + (start - first.excerptStart) : first.sourceStart;
  const sourceEnd =
    last.kind === 'text' ? last.sourceStart + (end - last.excerptStart) : last.sourceEnd;
  if (sourceEnd <= sourceStart) return null;
  return { source: first.source, start: sourceStart, end: sourceEnd };
}
