import { Deadline } from '@email-gateway/bec';
import {
  ifscTokens,
  scanDates,
  scanDigitRuns,
  scanMrz,
  scanPrivateKeys,
  scanTokens,
  type Candidate,
} from '@email-gateway/dlp';
import {
  DLP_DETECTORS,
  type DlpCategory,
  type DlpDetectorId,
} from '@email-gateway/security-contracts';

/**
 * DLP masking of preview text (step 5.3 Q11, ADR-0048). Every built-in **value** detector of
 * `@email-gateway/dlp` runs over the text, independent of the tenant's DLP configuration (no
 * disabled detectors, Aadhaar on: masking reveals nothing, so it needs no compliance basis), and
 * every candidate is masked whatever its confidence (context is not required to hide a value).
 * Payment cards keep the first 6 and last 4 digits (`maskCardEvidence` form); every other match
 * is replaced by `•`. Keyword and classification detectors (CF1, CF2, FI1, DC1, SC1) mark
 * documents, not values, and tenant patterns (CU1) are tenant configuration: neither masks text.
 */

export const MASK_CHAR = '•';
/** Masks never exceed this many characters (a 3 KiB PEM key becomes 64 bullets). */
export const MASK_MAX_CHARS = 64;
/** The context window the detectors use for their own structural checks. */
const WINDOW = 60;

type DetectorContext = Parameters<typeof scanDigitRuns>[0];

export interface MaskDlpOptions {
  /** Evaluation time for date plausibility (DOB); the caller's clock. */
  now: Date;
}

export interface MaskDlpResult {
  text: string;
  /** Number of masked spans. */
  masked: number;
  /** Categories of the masked spans, sorted, unique. */
  categories: DlpCategory[];
}

interface Span {
  start: number;
  end: number;
  detector: DlpDetectorId;
  compact: string;
}

const bullets = (n: number) => MASK_CHAR.repeat(Math.min(Math.max(n, 1), MASK_MAX_CHARS));

function maskOf(span: Span, original: string): string {
  if (span.detector === 'PC1') {
    const digits = span.compact.replace(/\D/g, '');
    if (digits.length >= 12) {
      return digits.slice(0, 6) + bullets(digits.length - 10) + digits.slice(-4);
    }
  }
  return bullets(original.length);
}

/** The candidate spans of every built-in value detector, unmerged. */
export function dlpCandidates(text: string, options: MaskDlpOptions): Candidate[] {
  const out: Candidate[] = [];
  if (text.length === 0) return out;
  const ctx: DetectorContext = {
    text,
    segment: 0,
    window: WINDOW,
    now: options.now,
    aadhaarEnabled: true,
    disabled: new Set(),
    ifsc: ifscTokens(text),
    excludedAddresses: new Set(),
    sourceFile: false,
    emit(candidate) {
      out.push(candidate);
    },
  };
  const deadline = Deadline.none();
  const CHUNK = 65_536;
  for (let from = 0; from < text.length; from += CHUNK) {
    const to = Math.min(text.length, from + CHUNK);
    scanDigitRuns(ctx, from, to);
    scanTokens(ctx, from, to);
    scanDates(ctx, from, to);
  }
  scanPrivateKeys(ctx, deadline);
  scanMrz(ctx, deadline);
  return out;
}

/** Masks every DLP value match of `text` (Q11). */
export function maskDlp(text: string, options: MaskDlpOptions): MaskDlpResult {
  const candidates = dlpCandidates(text, options)
    .filter((c) => c.end > c.start && c.start >= 0 && c.end <= text.length)
    .map((c): Span => ({ start: c.start, end: c.end, detector: c.detector, compact: c.compact }))
    .sort((a, b) => a.start - b.start || b.end - a.end);
  // Merge overlaps: the union is masked; a card wins the mask form when it covers the union.
  const merged: Span[] = [];
  const categories = new Set<DlpCategory>();
  for (const c of candidates) {
    const category = DLP_DETECTORS[c.detector].category;
    if (category !== null) categories.add(category);
    const last = merged[merged.length - 1];
    if (last !== undefined && c.start < last.end) {
      if (c.end > last.end) {
        last.end = c.end;
        if (last.detector === 'PC1') last.detector = c.detector;
      }
      continue;
    }
    merged.push({ ...c });
  }
  let result = '';
  let at = 0;
  for (const span of merged) {
    result += text.slice(at, span.start) + maskOf(span, text.slice(span.start, span.end));
    at = span.end;
  }
  result += text.slice(at);
  return {
    text: result,
    masked: merged.length,
    categories: [...categories].sort(),
  };
}
