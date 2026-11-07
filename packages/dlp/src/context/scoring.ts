import { DLP_DETECTORS, type DlpCategory } from '@email-gateway/security-contracts';
import type { Candidate, ContextGroup, ScoredCandidate } from '../detectors/types';
import { lineAround } from '../scan/chars';

/**
 * Context-aware confidence (step 4.5 D7):
 *
 *   confidence = base (incl. structural bonuses)
 *              + positive context (once; window or table column header)
 *              − negative context (once: −0.30 identifiers, −0.60 disclaimers for CF1)
 *              + document aggregation (+0.15 with ≥ bulkMinDistinct distinct values of the
 *                detector in the segment)
 *              − code penalty (−0.30 in a source-code segment or on a code-like line; the
 *                positive context of such a candidate is not counted: identifiers are not prose)
 *
 * clamped to [0, 1] and rounded to two decimals. Reportable iff ≥ the category threshold and,
 * for "requires context" detectors, a positive context term was found.
 */

export const NEGATIVE_PENALTY = 0.3;
export const DISCLAIMER_PENALTY = 0.6;
export const BULK_BONUS = 0.15;
export const CODE_PENALTY = 0.3;

/** Spans sorted by start; `near(lo, hi)` = some span overlaps [lo, hi). */
export class SpanIndex {
  private readonly starts: number[];
  private readonly ends: number[];
  /** Longest span (bounds the backward scan). */
  private readonly longest: number;

  constructor(spans: readonly { start: number; end: number }[]) {
    const sorted = [...spans].sort((a, b) => a.start - b.start || a.end - b.end);
    this.starts = sorted.map((s) => s.start);
    this.ends = sorted.map((s) => s.end);
    this.longest = sorted.reduce((m, s) => Math.max(m, s.end - s.start), 0);
  }

  static readonly EMPTY = new SpanIndex([]);

  get size(): number {
    return this.starts.length;
  }

  near(lo: number, hi: number): boolean {
    // First span with start >= hi; every candidate overlap is before it.
    let a = 0;
    let b = this.starts.length;
    while (a < b) {
      const m = (a + b) >>> 1;
      if (this.starts[m]! < hi) a = m + 1;
      else b = m;
    }
    for (let k = a - 1; k >= 0; k -= 1) {
      if (this.ends[k]! > lo) return true;
      if (this.starts[k]! < lo - this.longest) break;
    }
    return false;
  }
}

/** The context index of one segment, built by `detect()` from the phrase-trie matches. */
export interface SegmentContextIndex {
  positive: ReadonlyMap<ContextGroup, SpanIndex>;
  negative: SpanIndex;
  negativePhone: SpanIndex;
  disclaimer: SpanIndex;
  /** Table segments: the positive context families of each column header. */
  columns: readonly ReadonlySet<ContextGroup>[] | null;
  /** SC1 score of the segment ≥ 0.5. */
  codeSegment: boolean;
  /** CR2 candidate spans (CR3 context). */
  awsKeyIds: SpanIndex;
}

export interface ScoringSettings {
  window: number;
  bulkMinDistinct: number;
  thresholds: Readonly<Record<DlpCategory, number>>;
}

const DECLARATIONS = new Set([
  'const',
  'let',
  'var',
  'val',
  'final',
  'static',
  'private',
  'public',
  'protected',
  'def',
  'string',
  'int',
  'long',
  'char',
  'auto',
  'my',
  'our',
  'dim',
  'set',
  'export',
  'readonly',
]);

/** A code-like line around [start, end): declaration with `=`, `…=…;`, `0x`/`_` adjacency. */
export function codeLikeAt(text: string, start: number, end: number): boolean {
  if (text[start - 1] === '_' || text[end] === '_') return true;
  if (start >= 2 && text.slice(start - 2, start).toLowerCase() === '0x') return true;
  const line = lineAround(text, start);
  const content = text.slice(line.start, Math.min(line.end, line.start + 1024)).trim();
  if (!content.includes('=')) return false;
  let i = 0;
  while (i < content.length && /[A-Za-z$]/.test(content[i]!) && i < 16) i += 1;
  const word = content.slice(0, i).toLowerCase();
  if (DECLARATIONS.has(word)) return true;
  return content.endsWith(';');
}

const round2 = (value: number): number => Math.round(value * 100) / 100;

/** Column index of `offset` in its tab-separated line. */
export function columnAt(text: string, offset: number): number {
  const line = lineAround(text, offset, 1 << 16);
  let column = 0;
  for (let i = line.start; i < offset; i += 1) if (text.charCodeAt(i) === 9) column += 1;
  return column;
}

export const categoryOf = (candidate: Candidate): DlpCategory =>
  candidate.category ?? DLP_DETECTORS[candidate.detector].category ?? 'custom';

/**
 * Scores the candidates of one segment. `distinctByDetector` = distinct compact values per
 * detector key in this segment (bulk aggregation).
 */
export function scoreCandidates(
  candidates: readonly Candidate[],
  text: string,
  index: SegmentContextIndex,
  settings: ScoringSettings,
): ScoredCandidate[] {
  const distinct = new Map<string, Set<string>>();
  const key = (c: Candidate) =>
    `${c.detector}:${c.extra.customPatternId ?? c.extra.dictionaryId ?? ''}`;
  for (const c of candidates) {
    let set = distinct.get(key(c));
    if (!set) distinct.set(key(c), (set = new Set()));
    set.add(c.compact);
  }
  const { window } = settings;
  return candidates.map((c) => {
    const lo = c.start - window;
    const hi = c.end + window;
    const code = c.codePenalty && (index.codeSegment || codeLikeAt(text, c.start, c.end));
    let positive = false;
    if (!code && c.context.length > 0) {
      positive = c.context.some((g) => index.positive.get(g)?.near(lo, hi) ?? false);
      if (!positive && index.columns) {
        const groups = index.columns[columnAt(text, c.start)];
        positive = groups !== undefined && c.context.some((g) => groups.has(g));
      }
    }
    if (c.detector === 'CR3' && !positive) positive = index.awsKeyIds.near(lo, hi);
    let confidence = c.base;
    if (positive) confidence += c.contextBonus;
    if (c.negative === 'standard') {
      if (index.negative.near(lo, hi) || index.negativePhone.near(lo, hi))
        confidence -= NEGATIVE_PENALTY;
    } else if (c.negative === 'no_phone') {
      if (index.negative.near(lo, hi)) confidence -= NEGATIVE_PENALTY;
    } else if (c.negative === 'disclaimer') {
      // Disclaimers are long: twice the window on each side.
      if (index.disclaimer.near(c.start - 2 * window, c.end + 2 * window))
        confidence -= DISCLAIMER_PENALTY;
    }
    if ((distinct.get(key(c))?.size ?? 0) >= settings.bulkMinDistinct) confidence += BULK_BONUS;
    if (code) confidence -= CODE_PENALTY;
    confidence = round2(Math.min(1, Math.max(0, confidence)));
    const threshold = settings.thresholds[categoryOf(c)];
    const reportable = confidence + 1e-9 >= threshold && (!c.requiresContext || positive);
    return { ...c, confidence, reportable };
  });
}
