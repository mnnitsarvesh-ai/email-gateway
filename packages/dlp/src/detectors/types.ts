import type { DlpCategory, DlpDetectorId, DlpSeverity } from '@email-gateway/security-contracts';

/** Positive context families of the packaged context lexicon (`data/dictionaries/context.json`). */
export const CONTEXT_GROUPS = [
  'card',
  'iban',
  'bank_account',
  'swift',
  'pan',
  'aadhaar',
  'passport',
  'mobile',
  'dob',
  'aws_secret',
] as const;
export type ContextGroup = (typeof CONTEXT_GROUPS)[number];

/**
 * Which negative lexicon applies to a candidate (D7): `standard` = the identifier negatives
 * (test, sample, order id, … and tel/phone/fax), `no_phone` = the same without tel/phone/fax
 * (the mobile detector, for which "phone" is positive context), `disclaimer` = disclaimer
 * phrases (CF1), null = none.
 */
export type NegativeKind = 'standard' | 'no_phone' | 'disclaimer' | null;

/** Detector-specific details of a candidate (never stored raw outside the evidence). */
export interface CandidateExtra {
  brand?: string;
  ifsc?: string;
  language?: string;
  alg?: string;
  tokenKind?: string;
  keyType?: string;
  termId?: string;
  finKind?: string;
  customPatternId?: string;
  dictionaryId?: string;
  termIndex?: number;
  documentNumber?: string;
  maskStyle?: 'last4' | 'full';
  /** BEGIN line of a PEM key (CR1 evidence keeps only this line). */
  pemHeader?: string;
}

/**
 * A candidate match of one detector in one segment, before scoring (D7). Offsets are UTF-16
 * units in the segment text. `value` is raw and must never leave the package except inside
 * the sealed evidence (masked there for Aadhaar, secrets and cards, D16).
 */
export interface Candidate {
  detector: DlpDetectorId;
  segment: number;
  start: number;
  end: number;
  value: string;
  /** Normalized form for distinct counting (digits / uppercase alphanumerics). */
  compact: string;
  /** Base confidence including structural bonuses (grouping, +91, expiry, …). */
  base: number;
  /** Positive context families and their bonus (applied once when one is in the window). */
  context: readonly ContextGroup[];
  contextBonus: number;
  requiresContext: boolean;
  negative: NegativeKind;
  /** Subject to the code penalty (PAN, passport, mobile, card detectors). */
  codePenalty: boolean;
  /** Category / severity overrides (DC1, CU1). */
  category?: DlpCategory;
  severity?: DlpSeverity;
  extra: CandidateExtra;
  /** Set by scoring. */
  confidence?: number;
}

/** A scored candidate (D7). */
export interface ScoredCandidate extends Candidate {
  confidence: number;
  reportable: boolean;
}
