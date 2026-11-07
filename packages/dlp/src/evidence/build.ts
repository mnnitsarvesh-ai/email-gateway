import {
  DLP_DETECTORS,
  DLP_EVIDENCE_ALGORITHM,
  DLP_EVIDENCE_CONTEXT_CHARS,
  DLP_EVIDENCE_MAX_BYTES_CEILING,
  DLP_EVIDENCE_MAX_MATCHES_CEILING,
  DLP_EVIDENCE_MAX_PER_DETECTOR,
  dlpEvidenceDocumentSchema,
  dlpSeverityRank,
  type DlpEvidenceDocument,
  type DlpEvidenceMatch,
  type DlpSourceRef,
} from '@email-gateway/security-contracts';
import { aadhaarShape } from '../detectors/numbers';
import type { Candidate, ScoredCandidate } from '../detectors/types';
import { credentialMask, isCredentialDetector, maskCardEvidence, maskLast4 } from '../mask';
import { forEachDigitRun, isDigitCode } from '../scan/chars';
import { luhnValid, verhoeffValid } from '../validators';
import { DLP_EXTRACTOR_VERSION, DLP_TEXT_DERIVATION_VERSION } from '../versions';

/**
 * Evidence content (step 4.5 D16): bounded matches with UTF-16 offsets in the extracted
 * segment text and a redacted context window. Never raw: Aadhaar values (and every
 * Verhoeff-valid Aadhaar-shaped run in any context, whether NI2 is gated on or not), credential
 * secrets (CR1 keeps only its BEGIN line, CR4 only its header, CR3/CR5 type-only), card numbers
 * (first 6 + last 4, so the evidence holds no full PAN) and card verification codes.
 */

export interface EvidenceSegment {
  source: DlpSourceRef;
  text: string;
}

export interface BuildEvidenceInput {
  /** Reportable candidates (scored). */
  matches: readonly ScoredCandidate[];
  /** Every credential candidate (CR1–CR5), reportable or not: their spans are redacted. */
  credentialCandidates: readonly Candidate[];
  segments: readonly EvidenceSegment[];
  aadhaarEnabled: boolean;
  maxMatches: number;
  maxBytes: number;
}

export interface BuiltEvidence {
  document: DlpEvidenceDocument;
  json: string;
}

interface Redaction {
  start: number;
  end: number;
  mask: string;
}

const CVV_TERMS = ['cvv2', 'cvv', 'cvc', 'csc', 'cid', 'security code'];
const CONTEXT = DLP_EVIDENCE_CONTEXT_CHARS;
/** Redactions are computed over a margin around the window so cut values are still found. */
const MARGIN = 64;

/** Redaction spans (D16 a–d) intersecting [lo, hi) of a segment. */
export function redactionsIn(
  text: string,
  lo: number,
  hi: number,
  credentials: readonly Candidate[],
): Redaction[] {
  const from = Math.max(0, lo - MARGIN);
  const to = Math.min(text.length, hi + MARGIN);
  const out: Redaction[] = [];
  // (a) every credential candidate span → its type-only mask
  for (const c of credentials) {
    if (c.end > from && c.start < to)
      out.push({ start: c.start, end: c.end, mask: credentialMask(c) });
  }
  // (b) Aadhaar-shaped Verhoeff-valid runs; (c) Luhn-valid 13–19 digit runs
  forEachDigitRun(text, from, to, (run) => {
    if (aadhaarShape(run) && verhoeffValid(run.digits)) {
      out.push({ start: run.start, end: run.end, mask: '[aadhaar]' });
    } else if (run.digits.length >= 13 && run.digits.length <= 19 && luhnValid(run.digits)) {
      out.push({ start: run.start, end: run.end, mask: maskCardEvidence(run.digits) });
    }
  });
  // (d) a 3–4 digit run within 16 code units after a CVV term
  const lower = text.slice(from, to).toLowerCase();
  for (const term of CVV_TERMS) {
    let at = lower.indexOf(term);
    while (at >= 0) {
      const termEnd = from + at + term.length;
      for (let k = termEnd; k < Math.min(text.length, termEnd + 16); k += 1) {
        if (!isDigitCode(text.charCodeAt(k))) continue;
        let e = k;
        while (e < text.length && isDigitCode(text.charCodeAt(e))) e += 1;
        if (e - k >= 3 && e - k <= 4) out.push({ start: k, end: e, mask: '***' });
        break;
      }
      at = lower.indexOf(term, at + term.length);
    }
  }
  return out.sort((a, b) => a.start - b.start || b.end - a.end);
}

/** The text of [lo, hi) with every intersecting redaction replaced by its mask (once). */
export function redactedSlice(
  text: string,
  lo: number,
  hi: number,
  redactions: readonly Redaction[],
): string {
  let out = '';
  let i = lo;
  for (const r of redactions) {
    if (r.end <= i || r.start >= hi) continue;
    if (r.start > i) out += text.slice(i, r.start);
    out += r.mask;
    i = Math.max(i, r.end);
    if (i >= hi) break;
  }
  if (i < hi) out += text.slice(i, hi);
  return out;
}

/** The value kept for a match inside the evidence (masked where D16 says so). */
export function evidenceValue(candidate: Candidate): string {
  switch (candidate.detector) {
    case 'PC1':
      return maskCardEvidence(candidate.compact);
    case 'NI2':
      return maskLast4(candidate.compact);
    case 'CR1':
      return candidate.extra.pemHeader ?? credentialMask(candidate);
    case 'CR4':
      return candidate.value.split('.')[0]!;
    case 'CR3':
    case 'CR5':
      return credentialMask(candidate);
    default:
      return candidate.value.slice(0, 1024);
  }
}

const severityOf = (c: Candidate): number =>
  dlpSeverityRank(c.severity ?? DLP_DETECTORS[c.detector].severity ?? 'medium');

/**
 * Builds the evidence document (D16 bounds): ≤ `maxMatches` (≤ 50), ≤ 5 per detector, JSON ≤
 * `maxBytes` (≤ 32 768) UTF-8; matches are dropped from the lowest severity when over. Returns
 * null when no match fits.
 */
export function buildEvidence(input: BuildEvidenceInput): BuiltEvidence | null {
  const maxMatches = Math.min(input.maxMatches, DLP_EVIDENCE_MAX_MATCHES_CEILING);
  const maxBytes = Math.min(input.maxBytes, DLP_EVIDENCE_MAX_BYTES_CEILING);
  const ordered = [...input.matches]
    .filter((m) => m.reportable)
    .sort(
      (a, b) =>
        severityOf(b) - severityOf(a) ||
        b.confidence - a.confidence ||
        a.segment - b.segment ||
        a.start - b.start,
    );
  const perDetector = new Map<string, number>();
  const picked: ScoredCandidate[] = [];
  let dropped = 0;
  for (const m of ordered) {
    const n = perDetector.get(m.detector) ?? 0;
    if (n >= DLP_EVIDENCE_MAX_PER_DETECTOR || picked.length >= maxMatches) {
      dropped += 1;
      continue;
    }
    perDetector.set(m.detector, n + 1);
    picked.push(m);
  }
  const credentialsBySegment = new Map<number, Candidate[]>();
  for (const c of input.credentialCandidates) {
    if (!isCredentialDetector(c.detector)) continue;
    const list = credentialsBySegment.get(c.segment) ?? [];
    list.push(c);
    credentialsBySegment.set(c.segment, list);
  }
  const entries: DlpEvidenceMatch[] = picked.map((m) => {
    const segment = input.segments[m.segment]!;
    const text = segment.text;
    const lo = Math.max(0, m.start - CONTEXT);
    const hi = Math.min(text.length, m.end + CONTEXT);
    const redactions = redactionsIn(text, lo, hi, credentialsBySegment.get(m.segment) ?? []);
    return {
      detector: m.detector,
      code: DLP_DETECTORS[m.detector].code,
      source: { ...segment.source, segment: m.segment },
      start: m.start,
      end: m.end,
      value: evidenceValue(m),
      context: {
        before: redactedSlice(text, lo, m.start, redactions).slice(-CONTEXT * 4),
        after: redactedSlice(text, m.end, hi, redactions).slice(0, CONTEXT * 4),
      },
    };
  });
  const make = (matches: DlpEvidenceMatch[], extra: number): DlpEvidenceDocument => ({
    format: DLP_EVIDENCE_ALGORITHM,
    textDerivationVersion: DLP_TEXT_DERIVATION_VERSION,
    extractorVersion: DLP_EXTRACTOR_VERSION,
    aadhaar: input.aadhaarEnabled ? 'enabled' : 'disabled',
    matches,
    dropped: extra,
  });
  // Drop from the lowest severity (the end of the ordered list) until the JSON fits.
  let kept = entries;
  let json = JSON.stringify(make(kept, dropped));
  while (kept.length > 0 && Buffer.byteLength(json, 'utf8') > maxBytes) {
    kept = kept.slice(0, -1);
    json = JSON.stringify(make(kept, dropped + (entries.length - kept.length)));
  }
  if (kept.length === 0) return null;
  const document = dlpEvidenceDocumentSchema.parse(JSON.parse(json));
  return { document, json };
}
