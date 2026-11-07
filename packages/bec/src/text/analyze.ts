import { Deadline } from './deadline';
import { htmlToText, MAX_HTML_NODES } from './html';
import {
  LEXICON_CATEGORIES,
  type Lexicon,
  type LexiconCategory,
  type LexiconLanguage,
} from './lexicon';
import { normalizeForMatching, toSourceRange, wordTokens } from './normalize';
import {
  addPatternCounts,
  detectPatterns,
  emptyPatternCounts,
  type PatternCounts,
} from './patterns';

/**
 * Text analysis of one message (B8): subject, stored text body, stored HTML body converted to
 * text. Each source is matched separately (no phrase spans two sources); spans are offsets into
 * the derived source text (`subject` | `text` | `html_text`, UTF-16, reproducible with
 * `bec-text/1`). Bounds: `maxChars` code points analysed in total, ≤ 64 matches (≤ 16 per
 * category), ≤ 5 evidence spans per category; the deadline covers extraction and matching.
 */

export const TEXT_SOURCES = ['subject', 'text', 'html_text'] as const;
export type TextSource = (typeof TEXT_SOURCES)[number];

export const MAX_TEXT_MATCHES = 64;
export const MAX_MATCHES_PER_CATEGORY = 16;
export const MAX_SPANS_PER_CATEGORY = 5;

export interface TextBodyInput {
  /** UTF-8 decoded content as read (≤ BEC_TEXT_MAX_BYTES). */
  content: string;
  /** The stored part was larger than the read cap (range read). */
  truncated: boolean;
}

export interface TextInput {
  subject: string | null;
  textBody: TextBodyInput | null;
  htmlBody: TextBodyInput | null;
  /** MIME parse limits / body_size: the stored text parts are not the whole message text. */
  parseIncomplete: boolean;
}

export type TextState = 'complete' | 'incomplete' | 'absent';

export interface TextSpan {
  source: TextSource;
  start: number;
  end: number;
}

export interface TextMatch extends TextSpan {
  id: string;
  category: LexiconCategory;
  language: LexiconLanguage;
}

export interface CategorySummary {
  count: number;
  languages: LexiconLanguage[];
  /** First matches (≤ 5) per category: lexicon ids and source spans. */
  lexiconIds: string[];
  spans: TextSpan[];
}

export interface TextAnalysis {
  version: string;
  state: TextState;
  /** Why the text is incomplete (bounded list). */
  incompleteReasons: Array<'parse_limits' | 'part_truncated' | 'html_nodes' | 'max_chars'>;
  /** Derived source texts actually analysed (the excerpt is built from these). */
  sources: Record<TextSource, string | null>;
  matches: TextMatch[];
  categories: Record<LexiconCategory, CategorySummary>;
  patterns: PatternCounts;
  /** Code points analysed over all sources. */
  length: number;
}

export interface AnalyzeOptions {
  maxChars: number;
  maxHtmlNodes?: number;
  deadline?: Deadline;
}

const emptyCategories = (): Record<LexiconCategory, CategorySummary> =>
  Object.fromEntries(
    LEXICON_CATEGORIES.map((c) => [c, { count: 0, languages: [], lexiconIds: [], spans: [] }]),
  ) as unknown as Record<LexiconCategory, CategorySummary>;

const takeCodePoints = (value: string, max: number): { text: string; truncated: boolean } => {
  if (value.length <= max) return { text: value, truncated: false };
  let count = 0;
  let index = 0;
  for (const cp of value) {
    if (count >= max) return { text: value.slice(0, index), truncated: true };
    count += 1;
    index += cp.length;
  }
  return { text: value, truncated: false };
};

export function analyzeText(
  input: TextInput,
  lexicon: Lexicon,
  options: AnalyzeOptions,
): TextAnalysis {
  const deadline = options.deadline ?? Deadline.none();
  const reasons = new Set<TextAnalysis['incompleteReasons'][number]>();
  if (input.parseIncomplete) reasons.add('parse_limits');
  if (input.textBody?.truncated || input.htmlBody?.truncated) reasons.add('part_truncated');

  let htmlText: string | null = null;
  if (input.htmlBody) {
    const html = htmlToText(input.htmlBody.content, {
      maxNodes: options.maxHtmlNodes ?? MAX_HTML_NODES,
      deadline,
    });
    if (html.incomplete) reasons.add('html_nodes');
    htmlText = html.text;
  }
  const raw: Record<TextSource, string | null> = {
    subject: input.subject,
    text: input.textBody?.content ?? null,
    html_text: htmlText,
  };
  const sources: Record<TextSource, string | null> = { subject: null, text: null, html_text: null };
  let budget = options.maxChars;
  let length = 0;
  for (const source of TEXT_SOURCES) {
    const value = raw[source];
    if (value === null) continue;
    const taken = takeCodePoints(value, Math.max(0, budget));
    if (taken.truncated) reasons.add('max_chars');
    sources[source] = taken.text;
    const cps = [...taken.text].length;
    budget -= cps;
    length += cps;
  }

  const matches: TextMatch[] = [];
  const categories = emptyCategories();
  let patterns = emptyPatternCounts();
  for (const source of TEXT_SOURCES) {
    const text = sources[source];
    if (!text) continue;
    const normalized = normalizeForMatching(text, deadline);
    const tokens = wordTokens(normalized.text, deadline);
    const remaining = MAX_TEXT_MATCHES - matches.length;
    if (remaining > 0) {
      const perCategoryLeft = MAX_MATCHES_PER_CATEGORY;
      for (const match of lexicon.match(tokens, remaining, perCategoryLeft, deadline)) {
        const summary = categories[match.entry.category];
        if (summary.count >= MAX_MATCHES_PER_CATEGORY) continue;
        const range = toSourceRange(
          normalized,
          tokens[match.tokenStart]!.start,
          tokens[match.tokenEnd - 1]!.end,
        );
        const found: TextMatch = {
          source,
          start: range.start,
          end: range.end,
          id: match.entry.id,
          category: match.entry.category,
          language: match.entry.language,
        };
        matches.push(found);
        summary.count += 1;
        if (!summary.languages.includes(found.language)) summary.languages.push(found.language);
        if (
          summary.lexiconIds.length < MAX_SPANS_PER_CATEGORY &&
          !summary.lexiconIds.includes(found.id)
        ) {
          summary.lexiconIds.push(found.id);
        }
        if (summary.spans.length < MAX_SPANS_PER_CATEGORY) {
          summary.spans.push({ source, start: found.start, end: found.end });
        }
      }
    }
    patterns = addPatternCounts(patterns, detectPatterns(text, deadline));
  }
  deadline.check(true);
  const hasBody = input.textBody !== null || input.htmlBody !== null;
  const state: TextState = reasons.size > 0 ? 'incomplete' : hasBody ? 'complete' : 'absent';
  return {
    version: 'bec-text/1',
    state,
    incompleteReasons: [...reasons].sort(),
    sources,
    matches,
    categories,
    patterns,
    length,
  };
}
