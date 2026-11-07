import { setImmediate as yieldToLoop } from 'node:timers/promises';
import { Deadline, htmlToText } from '@email-gateway/bec';
import {
  DLP_DETECTORS,
  type DlpCategory,
  type DlpCoverageCode,
  type DlpDetectorId,
  type DlpExtractFormat,
  type DlpSourceRef,
  type DlpTenantDisableableDetector,
} from '@email-gateway/security-contracts';
import { SpanIndex, scoreCandidates, type SegmentContextIndex } from './context/scoring';
import type { PhraseMatch } from './context/trie';
import type { LoadedPattern } from './custom';
import { findPatternMatches } from './custom';
import type { DictionaryPayload, DlpDictionarySet } from './dictionaries';
import type { DetectorContext } from './detectors/context';
import { scanDigitRuns } from './detectors/numbers';
import {
  countCurrencyAmounts,
  scanDates,
  scanMrz,
  scanPrivateKeys,
  sourceCodeScore,
} from './detectors/structure';
import { ifscTokens, scanTokens } from './detectors/tokens';
import {
  CONTEXT_GROUPS,
  type Candidate,
  type ContextGroup,
  type ScoredCandidate,
} from './detectors/types';
import { compactValue } from './validators';

/**
 * The DLP text pipeline (step 4.5 D3 steps 5–6, D5–D9): over a list of text segments (subject,
 * bodies, attachment names, extracted attachment segments), chunked by `DLP_SCAN_CHUNK_CHARS`
 * with a 512-code-unit overlap (a match belongs to the chunk where it starts, so overlapping
 * chunks never report it twice), the event loop yielded between chunks, a `Deadline` checked
 * throughout (`BecTextTimeoutError`, code `extract_timeout`). HTML segments are converted with
 * the bec `htmlToText` here, in the worker (never in the extractor child).
 */

export type DlpSegmentKind = 'text' | 'table' | 'html' | 'name';

export interface DlpTextSegment {
  source: DlpSourceRef;
  format: DlpExtractFormat;
  kind: DlpSegmentKind;
  text: string;
  headers?: readonly string[];
}

export interface DlpDetectSettings {
  thresholds: Readonly<Record<DlpCategory, number>>;
  disabledDetectors: readonly DlpTenantDisableableDetector[];
  contextWindowChars: number;
  bulkMinDistinct: number;
}

export interface DlpDetectLimits {
  chunkChars: number;
  overlap: number;
  maxMatchesPerDetector: number;
  customScanMaxChars: number;
  maxKeywordMatchesPerSegment: number;
  maxHtmlNodes: number;
}

export const DEFAULT_DETECT_LIMITS: Readonly<DlpDetectLimits> = Object.freeze({
  chunkChars: 65_536,
  overlap: 512,
  maxMatchesPerDetector: 1000,
  customScanMaxChars: 1_000_000,
  maxKeywordMatchesPerSegment: 20_000,
  maxHtmlNodes: 50_000,
});

export interface DlpDetectInput {
  segments: readonly DlpTextSegment[];
  settings: DlpDetectSettings;
  /** D17: NI2 runs only with a recorded, unexpired compliance basis. */
  aadhaarEnabled: boolean;
  dictionaries: DlpDictionarySet;
  customPatterns?: readonly LoadedPattern[];
  /** Ids of stored custom patterns that failed validation at load (`dlp.custom.pattern_invalid`). */
  invalidCustomPatterns?: readonly string[];
  /** The message's own envelope sender and recipients (PI1 does not count them). */
  envelopeAddresses?: readonly string[];
  now: Date;
  limits?: Partial<DlpDetectLimits>;
  deadline?: Deadline;
  /**
   * The clock behind `deadline` when it measures this call's own work (`WorkClock`): it is
   * paused while the call yields the event loop, so the time other messages run on the shared
   * loop never counts against this message's detection budget.
   */
  workClock?: WorkClock;
}

/**
 * Milliseconds of one detection call's own on-loop work (closer review, 2026-11-08): wall time
 * minus the time spent yielded to the event loop. A `Deadline` on this clock bounds the work a
 * message causes, independent of how many other scans share the loop; the engine's whole-call
 * timeout (SCAN_DLP_TIMEOUT_MS) still bounds wall time.
 */
export class WorkClock {
  private spent = 0;
  private since: number | null;

  constructor(private readonly source: () => number = () => performance.now()) {
    this.since = source();
  }

  readonly now = (): number => this.spent + (this.since === null ? 0 : this.source() - this.since);

  pause(): void {
    if (this.since === null) return;
    this.spent += this.source() - this.since;
    this.since = null;
  }

  resume(): void {
    if (this.since === null) this.since = this.source();
  }

  /** Yields the event loop with the clock paused. */
  async yield(): Promise<void> {
    this.pause();
    try {
      await yieldToLoop();
    } finally {
      this.resume();
    }
  }
}

/** A segment as scanned (HTML converted), the text the evidence offsets refer to. */
export interface DlpScannedSegment {
  source: DlpSourceRef;
  format: DlpExtractFormat;
  kind: 'text' | 'table' | 'name';
  text: string;
}

export interface DlpDetection {
  segments: DlpScannedSegment[];
  /** Every scored candidate (reportable or not). */
  candidates: ScoredCandidate[];
  /** Every credential candidate (CR1–CR5), for the evidence context redaction (D16 a). */
  credentialCandidates: Candidate[];
  /** Detector keys (`PC1`, `CU1:<pattern>`, `DC1:<dictionary>`) whose match cap was reached. */
  capped: ReadonlySet<string>;
  /** Coverage codes raised by detection itself. */
  coverageCodes: DlpCoverageCode[];
}

const DISCLAIMER_GROUPS = new Set(['disclaimer']);
export const CF2_MULTI_TERM_BONUS = 0.2;
export const FI1_MIN_TERMS = 2;
export const FI1_MIN_AMOUNTS = 3;
export const CUSTOM_CONTEXT_BONUS = 0.3;

export const detectorKey = (c: Pick<Candidate, 'detector' | 'extra'>): string =>
  c.detector === 'CU1'
    ? `CU1:${c.extra.customPatternId ?? ''}`
    : c.detector === 'DC1'
      ? `DC1:${c.extra.dictionaryId ?? ''}`
      : c.detector;

/** Runs the whole text pipeline. */
export async function detect(input: DlpDetectInput): Promise<DlpDetection> {
  const limits: DlpDetectLimits = { ...DEFAULT_DETECT_LIMITS, ...input.limits };
  const deadline = input.deadline ?? Deadline.none();
  const pause = (): Promise<void> => (input.workClock ? input.workClock.yield() : yieldToLoop());
  const disabled = new Set<DlpDetectorId>(input.settings.disabledDetectors);
  const window = input.settings.contextWindowChars;
  const excluded = new Set((input.envelopeAddresses ?? []).map((a) => a.toLowerCase()));
  const coverage = new Set<DlpCoverageCode>();
  const capped = new Set<string>();
  const perKey = new Map<string, number>();
  const segments: DlpScannedSegment[] = [];
  const scored: ScoredCandidate[] = [];
  const credentials: Candidate[] = [];

  if ((input.invalidCustomPatterns ?? []).length > 0) coverage.add('dlp.custom.pattern_invalid');

  const accept = (candidate: Candidate): boolean => {
    const key = detectorKey(candidate);
    const n = perKey.get(key) ?? 0;
    if (n >= limits.maxMatchesPerDetector) {
      capped.add(key);
      return false;
    }
    perKey.set(key, n + 1);
    return true;
  };

  let customBudget = limits.customScanMaxChars;
  const tenant = input.dictionaries.tenant;
  const dictionaryMatches = new Map<string, number>();

  for (let index = 0; index < input.segments.length; index += 1) {
    const raw = input.segments[index]!;
    let text = raw.text;
    const kind: DlpScannedSegment['kind'] = raw.kind === 'html' ? 'text' : raw.kind;
    if (raw.kind === 'html') {
      const converted = htmlToText(raw.text, { maxNodes: limits.maxHtmlNodes, deadline });
      text = converted.text;
      if (converted.incomplete) coverage.add('dlp.text.truncated');
    }
    segments.push({ source: raw.source, format: raw.format, kind, text });
    const segmentCandidates: Candidate[] = [];

    // Pass 1: phrase matches (context, negatives, labels, business, financial, tenant terms).
    const keyword: PhraseMatch<DictionaryPayload>[] = [];
    for (let from = 0; from < text.length; from += limits.chunkChars) {
      deadline.check(true);
      const to = Math.min(text.length, from + limits.chunkChars);
      const slice = text.slice(from, Math.min(text.length, to + limits.overlap));
      for (const match of input.dictionaries.trie.match(
        slice,
        limits.maxKeywordMatchesPerSegment - keyword.length,
        deadline,
      )) {
        if (match.start + from >= to) continue;
        keyword.push({ ...match, start: match.start + from, end: match.end + from });
      }
      if (to < text.length) await pause();
    }

    const positive = new Map<ContextGroup, { start: number; end: number }[]>();
    const negative: { start: number; end: number }[] = [];
    const negativePhone: { start: number; end: number }[] = [];
    const disclaimer: { start: number; end: number }[] = [];
    for (const m of keyword) {
      if (m.payload.kind === 'context') {
        const list = positive.get(m.payload.group) ?? [];
        list.push(m);
        positive.set(m.payload.group, list);
      } else if (m.payload.kind === 'negative') {
        const target = DISCLAIMER_GROUPS.has(m.payload.group)
          ? disclaimer
          : m.payload.group === 'negative_phone'
            ? negativePhone
            : negative;
        target.push(m);
      }
    }
    let columns: Set<ContextGroup>[] | null = null;
    if (kind === 'table') {
      const headers =
        raw.headers ??
        text.slice(0, text.indexOf('\n') < 0 ? text.length : text.indexOf('\n')).split('\t');
      columns = headers.map((header) => {
        const groups = new Set<ContextGroup>();
        for (const m of input.dictionaries.trie.match(header, 64, deadline)) {
          if (m.payload.kind === 'context') groups.add(m.payload.group);
        }
        return groups;
      });
    }
    const code = kind === 'name' ? null : sourceCodeScore(text, raw.format === 'source', deadline);

    const ctx: DetectorContext = {
      text,
      segment: index,
      window,
      now: input.now,
      aadhaarEnabled: input.aadhaarEnabled,
      disabled,
      ifsc: kind === 'name' ? [] : ifscTokens(text),
      excludedAddresses: excluded,
      sourceFile: raw.format === 'source',
      emit(candidate) {
        if (accept(candidate)) segmentCandidates.push(candidate);
      },
    };

    // Pass 2: pattern detectors (not on attachment names: keyword detectors only).
    if (kind !== 'name') {
      for (let from = 0; from < text.length; from += limits.chunkChars) {
        deadline.check(true);
        const to = Math.min(text.length, from + limits.chunkChars);
        scanDigitRuns(ctx, from, to);
        scanTokens(ctx, from, to);
        scanDates(ctx, from, to);
        if (to < text.length) await pause();
      }
      scanPrivateKeys(ctx, deadline);
      scanMrz(ctx, deadline);
    }

    // Keyword detectors: CF1, CF2, FI1, DC1.
    const contextSpans = keyword
      .filter((m) => m.payload.kind === 'context')
      .map((m) => ({ start: m.start, end: m.end }))
      .sort((a, b) => a.start - b.start);
    const businessTerms = new Set<string>();
    const financialTerms = new Map<
      string,
      { id: string; kind: string; start: number; end: number }
    >();
    for (const m of keyword) {
      const p = m.payload;
      if (p.kind === 'business') businessTerms.add(p.id);
      if (p.kind === 'financial' && !financialTerms.has(p.id)) {
        financialTerms.set(p.id, { id: p.id, kind: p.finKind, start: m.start, end: m.end });
      }
    }
    for (const m of keyword) {
      const p = m.payload;
      const common = {
        segment: index,
        start: m.start,
        end: m.end,
        value: text.slice(m.start, m.end),
        context: [] as ContextGroup[],
        contextBonus: 0,
        requiresContext: false,
        codePenalty: false,
      };
      // A label inside an identifier (`aws_secret_access_key`) is not a classification label.
      // Nor is one inside a longer context phrase ("secret" in "aws secret access key").
      const inIdentifier =
        text[m.start - 1] === '_' ||
        text[m.end] === '_' ||
        (p.kind === 'label' && insideLongerPhrase(contextSpans, m));
      if (p.kind === 'label' && !disabled.has('CF1') && !inIdentifier) {
        ctx.emit({
          ...common,
          detector: 'CF1',
          compact: p.id,
          base: 0.8,
          negative: 'disclaimer',
          extra: { termId: p.id },
        });
      } else if (p.kind === 'business' && !disabled.has('CF2')) {
        const base = businessTerms.size >= 2 ? 0.5 + CF2_MULTI_TERM_BONUS : 0.5;
        ctx.emit({
          ...common,
          detector: 'CF2',
          compact: p.id,
          base,
          negative: null,
          extra: { termId: p.id },
        });
      } else if (p.kind === 'tenant') {
        const dictionary = tenant[p.dictionary]!;
        dictionaryMatches.set(dictionary.id, (dictionaryMatches.get(dictionary.id) ?? 0) + 1);
        ctx.emit({
          ...common,
          detector: 'DC1',
          compact: `${dictionary.id}#${p.termIndex}`,
          base: dictionary.baseConfidence,
          negative: null,
          category: dictionary.category,
          severity: dictionary.severity,
          extra: { dictionaryId: dictionary.id, termIndex: p.termIndex },
        });
      }
    }
    if (kind !== 'name' && financialTerms.size >= FI1_MIN_TERMS) {
      const amounts = countCurrencyAmounts(text, FI1_MIN_AMOUNTS, deadline);
      if (amounts >= FI1_MIN_AMOUNTS) {
        const terms = [...financialTerms.values()].sort((a, b) => a.start - b.start);
        const first = terms[0]!;
        const kinds = new Map<string, number>();
        for (const t of terms) kinds.set(t.kind, (kinds.get(t.kind) ?? 0) + 1);
        const finKind = [...kinds.entries()].sort(
          (a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1),
        )[0]![0];
        ctx.emit({
          detector: 'FI1',
          segment: index,
          start: first.start,
          end: first.end,
          value: text.slice(first.start, first.end),
          compact: `FI1:${index}`,
          base: Math.min(0.9, 0.7 + 0.05 * (terms.length - FI1_MIN_TERMS)),
          context: [],
          contextBonus: 0,
          requiresContext: false,
          negative: null,
          codePenalty: false,
          extra: { termId: first.id, finKind },
        });
      }
    }
    if (code && !disabled.has('SC1') && code.score > 0) {
      const end = Math.min(text.length, 200);
      ctx.emit({
        detector: 'SC1',
        segment: index,
        start: 0,
        end,
        value: text.slice(0, end),
        compact: `SC1:${index}`,
        base: code.score,
        context: [],
        contextBonus: 0,
        requiresContext: false,
        negative: null,
        codePenalty: false,
        extra: { language: code.language },
      });
    }

    const index_: SegmentContextIndex = {
      positive: new Map(CONTEXT_GROUPS.map((g) => [g, new SpanIndex(positive.get(g) ?? [])])),
      negative: new SpanIndex(negative),
      negativePhone: new SpanIndex(negativePhone),
      disclaimer: new SpanIndex(disclaimer),
      columns,
      codeSegment: (code?.score ?? 0) >= 0.5,
      awsKeyIds: new SpanIndex(segmentCandidates.filter((c) => c.detector === 'CR2')),
    };
    for (const c of segmentCandidates) {
      if (c.detector.startsWith('CR')) credentials.push(c);
    }
    scored.push(
      ...scoreCandidates(segmentCandidates, text, index_, {
        window,
        bulkMinDistinct: input.settings.bulkMinDistinct,
        thresholds: input.settings.thresholds,
      }),
    );

    // Custom patterns (CU1) under the per-message character budget.
    const patterns = input.customPatterns ?? [];
    if (patterns.length > 0 && kind !== 'name') {
      const scanned = Math.min(text.length, customBudget);
      if (scanned < text.length) coverage.add('dlp.custom.scan_truncated');
      customBudget -= scanned;
      if (scanned > 0) {
        const part = text.slice(0, scanned);
        const lower = text.toLowerCase();
        for (const pattern of patterns) {
          const result = findPatternMatches(pattern.compiled, part, {
            maxMatches: limits.maxMatchesPerDetector,
            chunkChars: limits.chunkChars,
            overlap: limits.overlap,
            deadline,
          });
          if (result.capped) capped.add(`CU1:${pattern.id}`);
          const keywords = pattern.compiled.input.contextKeywords.map((k) => k.toLowerCase());
          for (const match of result.matches) {
            if (!match.validated) continue;
            const around = lower.slice(Math.max(0, match.start - window), match.end + window);
            const contextHit = keywords.some((k) => around.includes(k));
            const confidence =
              Math.round(
                Math.min(1, pattern.baseConfidence + (contextHit ? CUSTOM_CONTEXT_BONUS : 0)) * 100,
              ) / 100;
            const reportable =
              confidence + 1e-9 >= input.settings.thresholds.custom &&
              (!pattern.compiled.input.requireContext || contextHit);
            scored.push({
              detector: 'CU1',
              segment: index,
              start: match.start,
              end: match.end,
              value: match.value,
              compact: compactValue(match.value) || match.value,
              base: pattern.baseConfidence,
              context: [],
              contextBonus: contextHit ? CUSTOM_CONTEXT_BONUS : 0,
              requiresContext: pattern.compiled.input.requireContext,
              negative: null,
              codePenalty: false,
              category: 'custom',
              severity: pattern.severity,
              extra: { customPatternId: pattern.id, maskStyle: pattern.maskStyle },
              confidence,
              reportable,
            });
          }
        }
      }
    }
    if (index + 1 < input.segments.length) await pause();
  }

  // DC1 `minMatches`: a dictionary below its minimum is not reportable.
  for (const c of scored) {
    if (c.detector !== 'DC1') continue;
    const dictionary = tenant.find((d) => d.id === c.extra.dictionaryId);
    if (dictionary && (dictionaryMatches.get(dictionary.id) ?? 0) < dictionary.minMatches)
      c.reportable = false;
  }

  return {
    segments,
    candidates: scored,
    credentialCandidates: credentials,
    capped,
    coverageCodes: [...coverage].sort(),
  };
}

/** Longest source span of a phrase that can contain another one (bounds the backward scan). */
const MAX_PHRASE_SPAN = 1024;

/** Whether `span` lies inside a strictly longer span of the sorted `spans` (binary search). */
export function insideLongerPhrase(
  spans: readonly { start: number; end: number }[],
  span: { start: number; end: number },
): boolean {
  let lo = 0;
  let hi = spans.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (spans[mid]!.start <= span.start) lo = mid + 1;
    else hi = mid;
  }
  for (let k = lo - 1; k >= 0 && spans[k]!.start >= span.start - MAX_PHRASE_SPAN; k -= 1) {
    const o = spans[k]!;
    if (o.end >= span.end && o.end - o.start > span.end - span.start) return true;
  }
  return false;
}

/** The reason code of a candidate's detector. */
export const candidateCode = (c: Pick<Candidate, 'detector'>): string =>
  DLP_DETECTORS[c.detector].code;
