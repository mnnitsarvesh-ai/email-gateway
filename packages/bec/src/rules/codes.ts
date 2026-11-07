/**
 * Verdict map `bec-map/1` (docs/plan/steps/12-phishing-bec.md B6): rule ids, reason codes,
 * categories, severities and weights, the structural evidence classes, the engine codes, and
 * the shared lists (BEC_MAPPER_CODES, BEC_RULE_IDS, BEC_SUPPRESSIBLE_CODES, AI_INDICATORS,
 * AI_FEATURE_NAMES) that `@email-gateway/security-contracts` holds identically (a WP3 contract
 * test asserts equality; this package deliberately does not depend on security-contracts).
 */

export const BEC_RULES_VERSION = 'bec-map/1';

export const BEC_RULE_CATEGORIES = [
  'identity',
  'auth',
  'lookalike',
  'impersonation',
  'intent',
  'link',
  'history',
  'engine',
  'ai',
] as const;
export type BecRuleCategory = (typeof BEC_RULE_CATEGORIES)[number];

export const BEC_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type BecSeverity = (typeof BEC_SEVERITIES)[number];
export const SEVERITY_RANK: Readonly<Record<BecSeverity, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const BEC_VERDICTS = ['clean', 'suspicious', 'malicious', 'unknown', 'skipped'] as const;
export type BecVerdict = (typeof BEC_VERDICTS)[number];

export interface BecRuleDefinition {
  id: string;
  code: string;
  category: BecRuleCategory;
  severity: BecSeverity;
  weight: number;
}

const rule = (
  id: string,
  code: string,
  category: BecRuleCategory,
  severity: BecSeverity,
  weight: number,
): BecRuleDefinition => ({ id, code, category, severity, weight });

/** The B6 table, in table order. */
export const BEC_RULES = [
  rule('P1', 'bec.return_path.domain_mismatch', 'identity', 'low', 5),
  rule('P2', 'bec.return_path.forged_header', 'identity', 'medium', 10),
  rule('I1', 'bec.sender.from_invalid', 'identity', 'medium', 15),
  rule('I2', 'bec.sender.sender_mismatch', 'identity', 'low', 5),
  rule('I3', 'bec.sender.not_authenticated', 'identity', 'low', 10),
  rule('D1', 'bec.display_name.embedded_address', 'identity', 'medium', 20),
  rule('D2', 'bec.display_name.brand_mismatch', 'identity', 'medium', 20),
  rule('D3', 'bec.display_name.obfuscated', 'identity', 'low', 10),
  rule('R1', 'bec.reply_to.domain_mismatch', 'identity', 'medium', 15),
  rule('R2', 'bec.reply_to.freemail', 'identity', 'medium', 20),
  rule('R3', 'bec.reply_to.lookalike', 'lookalike', 'high', 35),
  rule('A1', 'bec.auth.dmarc_fail', 'auth', 'high', 25),
  rule('A2', 'bec.auth.spf_fail', 'auth', 'medium', 10),
  rule('A3', 'bec.auth.dkim_fail', 'auth', 'medium', 10),
  rule('A4', 'bec.auth.none', 'auth', 'low', 5),
  rule('A5', 'bec.auth.temperror', 'auth', 'info', 0),
  rule('A6', 'bec.auth.tenant_domain_spoof', 'auth', 'critical', 50),
  rule('L1', 'bec.lookalike.sender_tenant', 'lookalike', 'high', 40),
  rule('L2', 'bec.lookalike.sender_vendor', 'lookalike', 'high', 40),
  rule('L3', 'bec.lookalike.sender_brand', 'lookalike', 'medium', 25),
  rule('L4', 'bec.lookalike.mixed_script_domain', 'lookalike', 'medium', 15),
  rule('X1', 'bec.impersonation.executive_name', 'impersonation', 'high', 40),
  rule('X2', 'bec.impersonation.executive_freemail', 'impersonation', 'high', 15),
  rule('X3', 'bec.impersonation.executive_reply_to', 'impersonation', 'high', 25),
  rule('V1', 'bec.impersonation.vendor_name', 'impersonation', 'medium', 25),
  rule('V2', 'bec.impersonation.vendor_unauthenticated', 'impersonation', 'medium', 20),
  rule('V3', 'bec.vendor.unknown_sender', 'impersonation', 'low', 5),
  rule('V4', 'bec.vendor.payment_change', 'intent', 'high', 35),
  rule('C1', 'bec.content.payment_request', 'intent', 'medium', 15),
  rule('C2', 'bec.content.bank_detail_change', 'intent', 'high', 25),
  rule('C3', 'bec.content.gift_card', 'intent', 'high', 30),
  rule('C4', 'bec.content.wire_transfer', 'intent', 'medium', 15),
  rule('C5', 'bec.content.invoice_change', 'intent', 'medium', 20),
  rule('C6', 'bec.content.payroll_diversion', 'intent', 'high', 30),
  rule('C7', 'bec.content.urgency', 'intent', 'low', 10),
  rule('C8', 'bec.content.secrecy', 'intent', 'medium', 15),
  rule('C9', 'bec.content.credential_request', 'intent', 'medium', 15),
  rule('C10', 'bec.content.financial_identifiers', 'intent', 'low', 5),
  rule('K1', 'bec.link.credential_harvesting', 'link', 'high', 40),
  rule('K2', 'bec.link.credential_form', 'link', 'medium', 20),
  rule('K3', 'bec.link.lookalike', 'link', 'medium', 15),
  rule('K4', 'bec.link.malicious', 'link', 'high', 30),
  rule('H1', 'bec.history.first_contact', 'history', 'low', 5),
  rule('H2', 'bec.history.first_contact_lookalike', 'history', 'high', 30),
  rule('H3', 'bec.history.reply_without_history', 'history', 'medium', 20),
  rule('H4', 'bec.history.new_infrastructure', 'history', 'medium', 20),
  rule('H5', 'bec.history.first_contact_payment', 'history', 'medium', 10),
  rule('T1', 'bec.trusted_sender', 'engine', 'info', 0),
  rule('T2', 'bec.trusted_sender_unauthenticated', 'engine', 'medium', 15),
  rule('S1', 'bec.feedback_suppressed', 'engine', 'info', 0),
] as const satisfies readonly BecRuleDefinition[];

export type BecRuleId = (typeof BEC_RULES)[number]['id'];
export type BecRuleCode = (typeof BEC_RULES)[number]['code'];

export const BEC_RULE_IDS: readonly BecRuleId[] = BEC_RULES.map((r) => r.id);
export const BEC_RULE_BY_ID: ReadonlyMap<BecRuleId, BecRuleDefinition> = new Map(
  BEC_RULES.map((r) => [r.id, r]),
);
export const BEC_RULE_BY_CODE: ReadonlyMap<string, BecRuleDefinition> = new Map(
  BEC_RULES.map((r) => [r.code, r]),
);

/** Engine-level codes (E0, E1). */
export const BEC_ENGINE_CODES = [
  'bec.not_inbound',
  'bec.input_unavailable.auth',
  'bec.input_unavailable.url',
  'bec.content_incomplete',
  'bec.history_unavailable',
] as const;
export type BecEngineCode = (typeof BEC_ENGINE_CODES)[number];

/** C0. */
export const BEC_CLEAN_CODE = 'clean.below_threshold';

/** AI codes (B9). */
export const BEC_AI_CODES = [
  'bec.ai.flagged',
  'bec.ai.corroborated',
  'bec.ai.disagrees',
  'bec.ai.unavailable',
] as const;
export type BecAiCode = (typeof BEC_AI_CODES)[number];

/** Every code the bec engine can emit (BEC_REASON_CODES in security-contracts). */
export const BEC_MAPPER_CODES: readonly string[] = [
  ...BEC_RULES.map((r) => r.code),
  ...BEC_ENGINE_CODES,
  BEC_CLEAN_CODE,
  ...BEC_AI_CODES,
];

/** B11: rules a tenant may suppress through false-positive feedback. */
export const BEC_SUPPRESSIBLE_RULE_IDS = [
  'P1',
  'P2',
  'I2',
  'I3',
  'D1',
  'D3',
  'R1',
  'R2',
  'V3',
  'C1',
  'C4',
  'C5',
  'C7',
  'C8',
  'C10',
  'H1',
  'H3',
  'H4',
  'H5',
] as const satisfies readonly BecRuleId[];
export const BEC_SUPPRESSIBLE_CODES: readonly string[] = BEC_SUPPRESSIBLE_RULE_IDS.map(
  (id) => BEC_RULE_BY_ID.get(id)!.code,
);

/** B7: rules neutralized (weight 0) by a trusted sender that authenticates as From. */
export const BEC_TRUST_NEUTRALIZED_RULE_IDS: ReadonlySet<BecRuleId> = new Set<BecRuleId>([
  'P1',
  'P2',
  'I2',
  'I3',
  'D1',
  'D2',
  'D3',
  'R1',
  'R2',
  'H1',
  'H2',
  'H3',
  'H4',
  'H5',
  'C1',
  'C2',
  'C3',
  'C4',
  'C5',
  'C6',
  'C7',
  'C8',
  'C9',
  'C10',
  'V4',
  'V1',
  'V3',
]);

/** Structural evidence classes (B6) used by the verdict and the AI invariant (B9). */
export const IDENTITY_EVIDENCE_RULE_IDS: ReadonlySet<BecRuleId> = new Set<BecRuleId>([
  'A1',
  'A6',
  'L1',
  'L2',
  'L3',
  'X1',
  'X2',
  'X3',
  'V1',
  'V2',
  'R3',
  'D1',
  'D2',
]);
export const INTENT_EVIDENCE_RULE_IDS: ReadonlySet<BecRuleId> = new Set<BecRuleId>([
  'C1',
  'C2',
  'C3',
  'C4',
  'C5',
  'C6',
  'C9',
  'K1',
  'V4',
]);

/** Category caps (points); categories not listed are uncapped. Total score ≤ 100. */
export const BEC_CATEGORY_CAPS: Readonly<Partial<Record<BecRuleCategory, number>>> = {
  intent: 50,
  history: 30,
  identity: 40,
};
export const BEC_SCORE_CAP = 100;
export const BEC_MAX_REASON_CODES = 32;
export const BEC_MAX_SIGNALS = 200;
export const BEC_MAX_EVIDENCE_PER_RULE = 5;

/** Lexicon category → content rule (authority is informational: a feature only). */
export const LEXICON_RULES = {
  payment_request: 'C1',
  bank_change: 'C2',
  gift_card: 'C3',
  wire_transfer: 'C4',
  invoice_change: 'C5',
  payroll_change: 'C6',
  urgency: 'C7',
  secrecy: 'C8',
  credential_request: 'C9',
} as const satisfies Record<string, BecRuleId>;

/** AI indicators (B10): the only enumerated "explanations" an AI provider may return. */
export const AI_INDICATORS = [
  'executive_impersonation',
  'vendor_impersonation',
  'payment_redirection',
  'gift_card_request',
  'wire_request',
  'payroll_change',
  'urgency',
  'secrecy',
  'credential_request',
  'lookalike_sender',
  'reply_to_redirection',
  'unusual_request',
  'benign_business',
  'newsletter',
  'transactional',
] as const;
export type AiIndicator = (typeof AI_INDICATORS)[number];

/** Rule ids that are AI features: every B6 rule id except S1 (B9: P1…K4, H1…H5, T1, T2). */
export const AI_RULE_FEATURE_IDS: readonly BecRuleId[] = BEC_RULE_IDS.filter((id) => id !== 'S1');

export const AI_LEXICON_FEATURE_CATEGORIES = [
  'payment_request',
  'bank_change',
  'gift_card',
  'wire_transfer',
  'invoice_change',
  'payroll_change',
  'urgency',
  'secrecy',
  'credential_request',
  'authority',
] as const;

/**
 * The AI feature vector (B9), fixed order: `rule_<id lower>` per rule id (table order, S1
 * excluded), `lex_<category>` (log1p of the match count), pattern counts (log1p), then the
 * identity / shape features.
 */
export const AI_FEATURE_NAMES: readonly string[] = [
  ...AI_RULE_FEATURE_IDS.map((id) => `rule_${id.toLowerCase()}`),
  ...AI_LEXICON_FEATURE_CATEGORIES.map((c) => `lex_${c}`),
  'pat_iban',
  'pat_swift',
  'pat_ifsc_account',
  'pat_amount',
  'fromFreemail',
  'replyToPresent',
  'displayNameMatchesProfile',
  'urlCountLog',
  'textLengthBucket',
  'isReply',
  'authenticatedAsFrom',
];
