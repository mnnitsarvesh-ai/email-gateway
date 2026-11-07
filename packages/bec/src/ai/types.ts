import type { TextSource } from '../text/analyze';
import type { RedactedExcerpt } from '../text/excerpt';

/**
 * The AI layer contract (docs/plan/steps/12-phishing-bec.md B9, ADR-0034). Providers return
 * labels, confidence, cited features, source spans by offset, enumerated indicators and
 * versions; never free text.
 */

export const AI_MODES = ['off', 'shadow', 'active'] as const;
export type AiMode = (typeof AI_MODES)[number];
export const AI_LAYERS = ['local', 'llm'] as const;
export type AiLayer = (typeof AI_LAYERS)[number];

export const AI_STATUSES = [
  'ok',
  'timeout',
  'error',
  'refused',
  'invalid_output',
  'budget_exceeded',
  'skipped',
  'circuit_open',
] as const;
export type AiStatus = (typeof AI_STATUSES)[number];

export const AI_LABELS = ['bec', 'phishing', 'benign', 'spam'] as const;
export type AiLabel = (typeof AI_LABELS)[number];

export interface BecAiProvider {
  readonly kind: 'local' | 'llm';
  /** 'bec-lr' | 'claude-opus-5-5' | 'fake' */
  readonly modelId: string;
  /** 'bec-lr/1@<sha256 first 12 of weights>' | provider-reported model id */
  readonly modelVersion: string;
  assess(input: AiInput, signal: AbortSignal): Promise<AiAssessment>;
}

/** Categorical identity facts sent with the features (B10); never addresses or names. */
export interface AiIdentityFacts {
  fromDomainKind: 'freemail' | 'tenant' | 'vendor' | 'lookalike' | 'external';
  replyToKind: 'none' | 'freemail' | 'tenant' | 'vendor' | 'lookalike' | 'external';
  displayNameMatch: 'executive' | 'vendor' | 'brand' | 'none';
  authenticatedAsFrom: boolean;
}

export interface AiInput {
  features: Record<string, number | boolean>;
  excerpt: RedactedExcerpt | null;
  /** B10 categorical identity facts (LLM only; optional, see §12 WP2). */
  facts?: AiIdentityFacts;
  /** Lexicon spans per lexicon category (local model: spans of its cited lexicon features). */
  lexiconSpans?: Partial<Record<string, Array<{ source: TextSource; start: number; end: number }>>>;
}

export interface AiSpan {
  source: TextSource;
  start: number;
  end: number;
  label: string;
}

export interface AiAssessment {
  status: AiStatus;
  /** ≤ 4 */
  labels: Array<{ label: AiLabel; confidence: number }>;
  /** Of the top label. */
  confidence: number | null;
  /** ≤ 8, feature ∈ AI_FEATURE_NAMES */
  citedFeatures: Array<{ feature: string; contribution: number }>;
  /** ≤ 8, mapped to source offsets */
  spans: AiSpan[];
  /** ≤ 8, from AI_INDICATORS */
  indicators: string[];
  modelId: string;
  modelVersion: string;
  /** LLM only: 'bec-llm-prompt/1' */
  promptTemplateVersion: string | null;
  /** SHA-256 of the canonical JSON of the validated output. */
  responseSha256: string | null;
  durationMs: number;
}

/** An assessment that is not `ok` (labels empty, confidence null). */
export function failedAssessment(
  status: Exclude<AiStatus, 'ok'>,
  provider: Pick<BecAiProvider, 'modelId' | 'modelVersion'>,
  durationMs: number,
  promptTemplateVersion: string | null = null,
): AiAssessment {
  return {
    status,
    labels: [],
    confidence: null,
    citedFeatures: [],
    spans: [],
    indicators: [],
    modelId: provider.modelId,
    modelVersion: provider.modelVersion,
    promptTemplateVersion,
    responseSha256: null,
    durationMs,
  };
}

/** Top label of an assessment (highest confidence; ties: list order). */
export function topLabel(assessment: AiAssessment): { label: AiLabel; confidence: number } | null {
  let best: { label: AiLabel; confidence: number } | null = null;
  for (const entry of assessment.labels)
    if (!best || entry.confidence > best.confidence) best = entry;
  return best;
}
