import type { TextAnalysis } from '../text/analyze';
import { AI_FEATURE_NAMES, AI_LEXICON_FEATURE_CATEGORIES, AI_RULE_FEATURE_IDS } from './codes';
import type { FiredRule } from './types';

/**
 * The AI feature vector (B9, `AI_FEATURE_NAMES` order): 1/0 per fired, non-suppressed rule;
 * log1p of the lexicon match count per category and of each pattern count; identity / shape
 * features. Stored with the result (`bec_scan_results.features`) for the retraining export.
 */

export const textLengthBucket = (length: number): number =>
  length < 200 ? 0 : length < 1000 ? 1 : length < 5000 ? 2 : 3;

const round6 = (value: number): number => Math.round(value * 1e6) / 1e6;

export interface FeatureInput {
  active: readonly FiredRule[];
  text: TextAnalysis | null;
  fromFreemail: boolean;
  replyToPresent: boolean;
  displayNameMatchesProfile: boolean;
  urlCount: number;
  isReply: boolean;
  authenticatedAsFrom: boolean;
}

export function buildFeatures(input: FeatureInput): Record<string, number> {
  const fired = new Set(input.active.map((r) => r.id));
  const features: Record<string, number> = {};
  for (const id of AI_RULE_FEATURE_IDS)
    features[`rule_${id.toLowerCase()}`] = fired.has(id) ? 1 : 0;
  for (const category of AI_LEXICON_FEATURE_CATEGORIES) {
    features[`lex_${category}`] = round6(Math.log1p(input.text?.categories[category].count ?? 0));
  }
  const p = input.text?.patterns;
  features.pat_iban = round6(Math.log1p(p?.iban ?? 0));
  features.pat_swift = round6(Math.log1p(p?.swift ?? 0));
  features.pat_ifsc_account = round6(Math.log1p(p?.ifscAccount ?? 0));
  features.pat_amount = round6(Math.log1p(p?.amount ?? 0));
  features.fromFreemail = input.fromFreemail ? 1 : 0;
  features.replyToPresent = input.replyToPresent ? 1 : 0;
  features.displayNameMatchesProfile = input.displayNameMatchesProfile ? 1 : 0;
  features.urlCountLog = round6(Math.log1p(input.urlCount));
  features.textLengthBucket = textLengthBucket(input.text?.length ?? 0);
  features.isReply = input.isReply ? 1 : 0;
  features.authenticatedAsFrom = input.authenticatedAsFrom ? 1 : 0;
  // Fixed order and completeness (a programming error, not an input problem).
  const keys = Object.keys(features);
  if (keys.length !== AI_FEATURE_NAMES.length || keys.some((k, i) => k !== AI_FEATURE_NAMES[i])) {
    throw new Error('bec feature vector does not match AI_FEATURE_NAMES');
  }
  return features;
}

/** Ordered numeric vector of a feature record (missing → 0). */
export const featureVector = (features: Readonly<Record<string, number | boolean>>): number[] =>
  AI_FEATURE_NAMES.map((name) => {
    const value = features[name];
    return typeof value === 'boolean' ? (value ? 1 : 0) : typeof value === 'number' ? value : 0;
  });
