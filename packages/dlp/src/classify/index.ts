import {
  DLP_COVERAGE_CODES,
  DLP_DETECTORS,
  DLP_DETECTOR_IDS,
  DLP_MAX_COVERAGE_ENTRIES,
  DLP_MAX_FINDINGS,
  DLP_MAX_MASKED_SAMPLES,
  DLP_MAX_SOURCES_PER_FINDING,
  MAX_REASON_CODES,
  dlpNotExtractedCode,
  dlpSeverityRank,
  type DlpCategory,
  type DlpCategoryAggregate,
  type DlpCoverage,
  type DlpCoverageCode,
  type DlpCoverageEntry,
  type DlpDetectorId,
  type DlpSeverity,
  type DlpSourceRef,
  type DlpVerdict,
} from '@email-gateway/security-contracts';
import { categoryOf } from '../context/scoring';
import { detectorKey, type DlpDetection } from '../detect';
import type { ScoredCandidate } from '../detectors/types';
import type { DlpExtraction } from '../extract/types';
import { maskCandidate } from '../mask';
import type { DlpPolicyDecision, DlpPolicyFinding } from '../policy';

/**
 * Classification (step 4.5 D7, D10): reportable candidates grouped into findings (distinct
 * values, maximum confidence, ≤ 5 sources, ≤ 3 masked samples, match cap), per-category
 * aggregates, coverage composition, the verdict and the reason codes of the engine final.
 */

export interface DlpFinding {
  detector: DlpDetectorId;
  code: string;
  category: DlpCategory;
  severity: DlpSeverity;
  /** Two decimals. */
  confidence: number;
  /** Distinct normalized values. */
  count: number;
  /** Distinct values found in attachments or attachment names. */
  attachmentCount: number;
  capped: boolean;
  sources: DlpSourceRef[];
  masked: string[];
  /** Public ids (CU1 / DC1). */
  customPatternId?: string;
  dictionaryId?: string;
}

export interface DlpClassification {
  findings: DlpFinding[];
  /** Findings beyond `DLP_MAX_FINDINGS` (count only). */
  findingsDropped: number;
  categories: DlpCategoryAggregate[];
  /** Non-reportable candidates per detector (statistics only: no value, no evidence). */
  suppressed: Partial<Record<DlpDetectorId, number>>;
  matchCapped: boolean;
  findingCount: number;
}

const severityOf = (c: ScoredCandidate): DlpSeverity =>
  c.severity ?? DLP_DETECTORS[c.detector].severity ?? 'medium';

const sourceKey = (s: DlpSourceRef) => `${s.kind}|${s.partIndex ?? ''}|${s.path ?? ''}`;

/** Groups the reportable candidates of a detection into findings (D7). */
export function classifyDetection(
  detection: Pick<DlpDetection, 'candidates' | 'segments' | 'capped'>,
  maxFindings: number = DLP_MAX_FINDINGS,
): DlpClassification {
  const groups = new Map<string, ScoredCandidate[]>();
  const suppressed: Partial<Record<DlpDetectorId, number>> = {};
  for (const c of detection.candidates) {
    if (!c.reportable) {
      suppressed[c.detector] = (suppressed[c.detector] ?? 0) + 1;
      continue;
    }
    const key = detectorKey(c);
    const list = groups.get(key) ?? [];
    list.push(c);
    groups.set(key, list);
  }
  const findings: DlpFinding[] = [];
  for (const [key, list] of groups) {
    const ordered = [...list].sort((a, b) => a.segment - b.segment || a.start - b.start);
    const first = ordered[0]!;
    const values = new Set<string>();
    const attachmentValues = new Set<string>();
    const sources = new Map<string, DlpSourceRef>();
    const masked: string[] = [];
    let confidence = 0;
    for (const c of ordered) {
      values.add(c.compact);
      const source = detection.segments[c.segment]!.source;
      if (source.kind === 'attachment' || source.kind === 'attachment_name')
        attachmentValues.add(c.compact);
      if (sources.size < DLP_MAX_SOURCES_PER_FINDING && !sources.has(sourceKey(source))) {
        sources.set(sourceKey(source), { ...source });
      }
      const mask = maskCandidate(c);
      if (masked.length < DLP_MAX_MASKED_SAMPLES && !masked.includes(mask)) masked.push(mask);
      confidence = Math.max(confidence, c.confidence);
    }
    const finding: DlpFinding = {
      detector: first.detector,
      code: DLP_DETECTORS[first.detector].code,
      category: categoryOf(first),
      severity: severityOf(first),
      confidence: Math.round(confidence * 100) / 100,
      count: values.size,
      attachmentCount: attachmentValues.size,
      capped: detection.capped.has(key),
      sources: [...sources.values()],
      masked,
    };
    if (first.detector === 'CU1') finding.customPatternId = first.extra.customPatternId!;
    if (first.detector === 'DC1') finding.dictionaryId = first.extra.dictionaryId!;
    findings.push(finding);
  }
  findings.sort(
    (a, b) =>
      dlpSeverityRank(b.severity) - dlpSeverityRank(a.severity) ||
      DLP_DETECTOR_IDS.indexOf(a.detector) - DLP_DETECTOR_IDS.indexOf(b.detector) ||
      (a.customPatternId ?? a.dictionaryId ?? '').localeCompare(
        b.customPatternId ?? b.dictionaryId ?? '',
      ),
  );
  const kept = findings.slice(0, maxFindings);
  return {
    findings: kept,
    findingsDropped: findings.length - kept.length,
    categories: categoryAggregates(findings),
    suppressed,
    matchCapped: detection.capped.size > 0,
    findingCount: findings.reduce((sum, f) => sum + f.count, 0),
  };
}

/** `{ category, count, maxSeverity, maxConfidence }` per category (D7). */
export function categoryAggregates(findings: readonly DlpFinding[]): DlpCategoryAggregate[] {
  const byCategory = new Map<DlpCategory, DlpCategoryAggregate>();
  for (const f of findings) {
    const current = byCategory.get(f.category);
    if (!current) {
      byCategory.set(f.category, {
        category: f.category,
        count: f.count,
        maxSeverity: f.severity,
        maxConfidence: f.confidence,
      });
      continue;
    }
    current.count += f.count;
    if (dlpSeverityRank(f.severity) > dlpSeverityRank(current.maxSeverity))
      current.maxSeverity = f.severity;
    current.maxConfidence = Math.max(current.maxConfidence, f.confidence);
  }
  return [...byCategory.values()].sort(
    (a, b) =>
      dlpSeverityRank(b.maxSeverity) - dlpSeverityRank(a.maxSeverity) ||
      a.category.localeCompare(b.category),
  );
}

/** The policy's view of the findings (D11). */
export const policyFindings = (findings: readonly DlpFinding[]): DlpPolicyFinding[] =>
  findings.map((f) => ({
    detector: f.detector,
    category: f.category,
    severity: f.severity,
    confidence: f.confidence,
    count: f.count,
    attachmentCount: f.attachmentCount,
    ...(f.customPatternId ? { customPatternId: f.customPatternId } : {}),
    ...(f.dictionaryId ? { dictionaryId: f.dictionaryId } : {}),
  }));

// ---------------------------------------------------------------------------------------------
// Coverage (D10)
// ---------------------------------------------------------------------------------------------

/** The coverage entries of one attachment's extraction (one per extracted path + the reasons). */
export function coverageFromExtraction(
  partIndex: number,
  extraction: DlpExtraction,
): DlpCoverageEntry[] {
  const reasons = extraction.reasons.map(dlpNotExtractedCode);
  const truncated = extraction.segments.some((s) => s.truncated);
  const allReasons: DlpCoverageCode[] = [
    ...new Set([...reasons, ...(truncated ? (['dlp.text.truncated'] as const) : [])]),
  ].sort();
  const chars = extraction.segments.reduce((sum, s) => sum + s.text.length, 0);
  return [
    {
      source: 'attachment',
      partIndex,
      format: extraction.format,
      status:
        extraction.status === 'extracted'
          ? 'scanned'
          : extraction.status === 'partial'
            ? 'partial'
            : 'not_extracted',
      reasons: allReasons,
      chars: Math.min(chars, 4_000_000),
      truncated,
    },
  ];
}

/** Coverage of a message: `partial` iff any coverage code applies (D10). */
export function composeCoverage(
  entries: readonly DlpCoverageEntry[],
  extraCodes: readonly DlpCoverageCode[] = [],
): { coverage: DlpCoverage; reasons: DlpCoverageCode[]; detail: DlpCoverageEntry[] } {
  const reasons = new Set<DlpCoverageCode>(extraCodes);
  for (const entry of entries) for (const r of entry.reasons) reasons.add(r);
  const sorted = [...reasons].sort(
    (a, b) => DLP_COVERAGE_CODES.indexOf(a) - DLP_COVERAGE_CODES.indexOf(b),
  );
  // Bounded detail: entries with a reason first, so a cut never hides why coverage is partial.
  const detail = [...entries]
    .sort((a, b) => Number(b.reasons.length > 0) - Number(a.reasons.length > 0))
    .slice(0, DLP_MAX_COVERAGE_ENTRIES);
  return { coverage: sorted.length > 0 ? 'partial' : 'complete', reasons: sorted, detail };
}

/** D10: `suspicious` with a reportable finding, else `unknown` when partial, else `clean`. */
export function dlpVerdict(findingCount: number, coverage: DlpCoverage): DlpVerdict {
  if (findingCount > 0) return 'suspicious';
  return coverage === 'partial' ? 'unknown' : 'clean';
}

/**
 * Reason codes of the engine final (D10, ≤ 32): the action code first, the other policy codes,
 * detector codes by severity, `dlp.detector.match_cap`, coverage codes (+ `dlp.coverage.partial`),
 * `dlp.no_findings` for `clean`.
 */
export function dlpReasonCodes(input: {
  verdict: DlpVerdict;
  decision: Pick<DlpPolicyDecision, 'codes'> | null;
  findings: readonly DlpFinding[];
  coverageReasons: readonly DlpCoverageCode[];
  matchCapped: boolean;
}): string[] {
  const codes: string[] = [];
  const add = (code: string) => {
    if (!codes.includes(code)) codes.push(code);
  };
  for (const code of input.decision?.codes ?? []) add(code);
  for (const f of input.findings) add(f.code);
  if (input.matchCapped) add('dlp.detector.match_cap');
  if (input.coverageReasons.length > 0) add('dlp.coverage.partial');
  for (const code of input.coverageReasons) add(code);
  if (input.verdict === 'clean') add('dlp.no_findings');
  return codes.slice(0, MAX_REASON_CODES);
}
