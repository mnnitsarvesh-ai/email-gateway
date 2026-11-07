import type { BecVerdict } from '../rules/codes';
import { topLabel, type AiAssessment, type AiLayer, type AiMode } from './types';

/**
 * Aggregation of the deterministic verdict D with the AI layer (B9, ADR-0034), pure:
 *
 * 1. D = malicious → malicious.
 * 2. D = suspicious, aiMaliciousBand > 0, scoreD ≥ maliciousScore − aiMaliciousBand, identity
 *    and intent evidence, A⁺.confidence ≥ corroborateConfidence → malicious (`bec.ai.corroborated`).
 * 3. D = suspicious → suspicious.
 * 4. D ∈ {clean, unknown}, A⁺.confidence ≥ raiseConfidence → suspicious (`bec.ai.flagged`).
 * 5. otherwise D; an applied benign assessment with D ∈ {suspicious, malicious} adds
 *    `bec.ai.disagrees`; an applied provider whose status ≠ ok adds `bec.ai.unavailable`.
 *
 * A⁺ = the strongest applied (`active`) assessment with status ok and top label bec|phishing.
 * Shadow assessments are ignored (P5). Invariant P1–P6 is asserted by the unit tests.
 */

export interface CombineSettings {
  suspiciousScore: number;
  maliciousScore: number;
  /** BEC_AI_MALICIOUS_BAND (0..15). */
  aiMaliciousBand: number;
  /** BEC_AI_CORROBORATE_CONFIDENCE (0.8..0.99). */
  corroborateConfidence: number;
  /** Effective ai.raiseConfidence (0.6..0.99). */
  raiseConfidence: number;
}

export interface CombineEvidence {
  identity: boolean;
  intent: boolean;
}

export interface CombineAssessment {
  layer: AiLayer;
  mode: AiMode;
  assessment: AiAssessment;
}

export type AiEffect = 'none' | 'raised_to_suspicious' | 'corroborated_malicious';

export interface CombineResult {
  verdict: BecVerdict;
  score: number;
  /** AI codes to append to the reason codes (B6 order: after the rule and engine codes). */
  codes: string[];
  /** Effect per input entry (same order); shadow entries are always `none`. */
  effects: AiEffect[];
}

const isThreat = (a: AiAssessment): boolean => {
  const top = topLabel(a);
  return a.status === 'ok' && top !== null && (top.label === 'bec' || top.label === 'phishing');
};

export function combineVerdict(
  deterministic: BecVerdict,
  scoreD: number,
  evidence: CombineEvidence,
  assessments: readonly CombineAssessment[],
  settings: CombineSettings,
): CombineResult {
  const effects: AiEffect[] = assessments.map(() => 'none');
  const applied = assessments
    .map((entry, index) => ({ ...entry, index }))
    .filter((entry) => entry.mode === 'active');
  let strongest: (typeof applied)[number] | null = null;
  for (const entry of applied) {
    if (!isThreat(entry.assessment)) continue;
    const confidence = topLabel(entry.assessment)!.confidence;
    if (!strongest || confidence > topLabel(strongest.assessment)!.confidence) strongest = entry;
  }
  const plusConfidence = strongest ? topLabel(strongest.assessment)!.confidence : null;

  let verdict: BecVerdict = deterministic;
  let score = scoreD;
  const codes: string[] = [];
  if (deterministic === 'malicious') {
    verdict = 'malicious';
  } else if (
    deterministic === 'suspicious' &&
    settings.aiMaliciousBand > 0 &&
    scoreD >= settings.maliciousScore - settings.aiMaliciousBand &&
    evidence.identity &&
    evidence.intent &&
    plusConfidence !== null &&
    plusConfidence >= settings.corroborateConfidence
  ) {
    verdict = 'malicious';
    score = Math.max(scoreD, settings.maliciousScore);
    codes.push('bec.ai.corroborated');
    effects[strongest!.index] = 'corroborated_malicious';
  } else if (deterministic === 'suspicious') {
    verdict = 'suspicious';
  } else if (
    (deterministic === 'clean' || deterministic === 'unknown') &&
    plusConfidence !== null &&
    plusConfidence >= settings.raiseConfidence
  ) {
    verdict = 'suspicious';
    score = Math.max(scoreD, settings.suspiciousScore);
    codes.push('bec.ai.flagged');
    effects[strongest!.index] = 'raised_to_suspicious';
  }
  if (
    (deterministic === 'suspicious' || deterministic === 'malicious') &&
    applied.some((e) => e.assessment.status === 'ok' && topLabel(e.assessment)?.label === 'benign')
  ) {
    codes.push('bec.ai.disagrees');
  }
  if (applied.some((e) => e.assessment.status !== 'ok')) codes.push('bec.ai.unavailable');
  return { verdict, score: Math.min(100, score), codes, effects };
}

/** Effective mode of a layer: the tenant choice capped by the platform mode (off < shadow < active). */
export function effectiveMode(
  platformCap: AiMode,
  tenant: AiMode | undefined,
  tenantDefault: AiMode,
): AiMode {
  const rank: Record<AiMode, number> = { off: 0, shadow: 1, active: 2 };
  const chosen = tenant ?? tenantDefault;
  return rank[chosen] <= rank[platformCap] ? chosen : platformCap;
}
