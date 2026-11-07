import { z } from 'zod';
import { authOutcomeSchema, dmarcPolicySchema } from './results';
import type { SettingsViolation } from './settings';
import { LOOKALIKE_RULES, urlDomainSchema } from './url';

/**
 * Contracts of the phishing and BEC engine (docs/plan/steps/12-phishing-bec.md B6, B9–B11, B13,
 * B15, B18; ADR-0033–0035): the rule ids, categories and reason codes of the verdict map
 * `bec-map/1`, the suppressible codes, the AI indicator and feature vocabularies, the platform /
 * tenant settings with their pure resolver, and the strict view sub-schemas of the scans read API.
 *
 * `@email-gateway/bec` holds the same lists (`BEC_MAPPER_CODES`, its rule table, its AI
 * vocabularies); a contract test (WP3) asserts equality, so every list below is written in the
 * order of the design tables and must be copied verbatim. Codes, ids, counts, offsets and hashes
 * only: never body text, span text, excerpts or header values beyond the parsed sender identity
 * (§2.0 invariant 4).
 */

/** Mapping version of the BEC verdict map (B6); also the prefix of `settings_version` (B13). */
export const BEC_MAPPING_VERSION = 'bec-map/1';

/** Verdicts of a `bec_scan_results` row (Prisma `BecVerdict`; `skipped` = not inbound, B1). */
export const BEC_VERDICTS = ['clean', 'suspicious', 'malicious', 'unknown', 'skipped'] as const;
export type BecVerdict = (typeof BEC_VERDICTS)[number];
export const becVerdictSchema = z.enum(BEC_VERDICTS);

/** Rule categories (B6), in the order of the design. */
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
export const becRuleCategorySchema = z.enum(BEC_RULE_CATEGORIES);

/** Rule severities (B6), from the least to the most severe. */
export const BEC_RULE_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type BecRuleSeverity = (typeof BEC_RULE_SEVERITIES)[number];
export const becRuleSeveritySchema = z.enum(BEC_RULE_SEVERITIES);

/** The rule ids of the B6 table, in table order (P1 … S1). */
export const BEC_RULE_IDS = [
  'P1',
  'P2',
  'I1',
  'I2',
  'I3',
  'D1',
  'D2',
  'D3',
  'R1',
  'R2',
  'R3',
  'A1',
  'A2',
  'A3',
  'A4',
  'A5',
  'A6',
  'L1',
  'L2',
  'L3',
  'L4',
  'X1',
  'X2',
  'X3',
  'V1',
  'V2',
  'V3',
  'V4',
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
  'K1',
  'K2',
  'K3',
  'K4',
  'H1',
  'H2',
  'H3',
  'H4',
  'H5',
  'T1',
  'T2',
  'S1',
] as const;
export type BecRuleId = (typeof BEC_RULE_IDS)[number];
export const becRuleIdSchema = z.enum(BEC_RULE_IDS);

/**
 * Reason code and category of every rule id of the B6 table (weights and severities are part of
 * `bec-map/1` in `@email-gateway/bec`). Used to check that a stored or returned rule entry's code
 * and category belong to its id.
 */
export const BEC_RULES: Readonly<
  Record<BecRuleId, Readonly<{ code: string; category: BecRuleCategory }>>
> = Object.freeze({
  P1: Object.freeze({ code: 'bec.return_path.domain_mismatch', category: 'identity' }),
  P2: Object.freeze({ code: 'bec.return_path.forged_header', category: 'identity' }),
  I1: Object.freeze({ code: 'bec.sender.from_invalid', category: 'identity' }),
  I2: Object.freeze({ code: 'bec.sender.sender_mismatch', category: 'identity' }),
  I3: Object.freeze({ code: 'bec.sender.not_authenticated', category: 'identity' }),
  D1: Object.freeze({ code: 'bec.display_name.embedded_address', category: 'identity' }),
  D2: Object.freeze({ code: 'bec.display_name.brand_mismatch', category: 'identity' }),
  D3: Object.freeze({ code: 'bec.display_name.obfuscated', category: 'identity' }),
  R1: Object.freeze({ code: 'bec.reply_to.domain_mismatch', category: 'identity' }),
  R2: Object.freeze({ code: 'bec.reply_to.freemail', category: 'identity' }),
  R3: Object.freeze({ code: 'bec.reply_to.lookalike', category: 'lookalike' }),
  A1: Object.freeze({ code: 'bec.auth.dmarc_fail', category: 'auth' }),
  A2: Object.freeze({ code: 'bec.auth.spf_fail', category: 'auth' }),
  A3: Object.freeze({ code: 'bec.auth.dkim_fail', category: 'auth' }),
  A4: Object.freeze({ code: 'bec.auth.none', category: 'auth' }),
  A5: Object.freeze({ code: 'bec.auth.temperror', category: 'auth' }),
  A6: Object.freeze({ code: 'bec.auth.tenant_domain_spoof', category: 'auth' }),
  L1: Object.freeze({ code: 'bec.lookalike.sender_tenant', category: 'lookalike' }),
  L2: Object.freeze({ code: 'bec.lookalike.sender_vendor', category: 'lookalike' }),
  L3: Object.freeze({ code: 'bec.lookalike.sender_brand', category: 'lookalike' }),
  L4: Object.freeze({ code: 'bec.lookalike.mixed_script_domain', category: 'lookalike' }),
  X1: Object.freeze({ code: 'bec.impersonation.executive_name', category: 'impersonation' }),
  X2: Object.freeze({ code: 'bec.impersonation.executive_freemail', category: 'impersonation' }),
  X3: Object.freeze({ code: 'bec.impersonation.executive_reply_to', category: 'impersonation' }),
  V1: Object.freeze({ code: 'bec.impersonation.vendor_name', category: 'impersonation' }),
  V2: Object.freeze({
    code: 'bec.impersonation.vendor_unauthenticated',
    category: 'impersonation',
  }),
  V3: Object.freeze({ code: 'bec.vendor.unknown_sender', category: 'impersonation' }),
  V4: Object.freeze({ code: 'bec.vendor.payment_change', category: 'intent' }),
  C1: Object.freeze({ code: 'bec.content.payment_request', category: 'intent' }),
  C2: Object.freeze({ code: 'bec.content.bank_detail_change', category: 'intent' }),
  C3: Object.freeze({ code: 'bec.content.gift_card', category: 'intent' }),
  C4: Object.freeze({ code: 'bec.content.wire_transfer', category: 'intent' }),
  C5: Object.freeze({ code: 'bec.content.invoice_change', category: 'intent' }),
  C6: Object.freeze({ code: 'bec.content.payroll_diversion', category: 'intent' }),
  C7: Object.freeze({ code: 'bec.content.urgency', category: 'intent' }),
  C8: Object.freeze({ code: 'bec.content.secrecy', category: 'intent' }),
  C9: Object.freeze({ code: 'bec.content.credential_request', category: 'intent' }),
  C10: Object.freeze({ code: 'bec.content.financial_identifiers', category: 'intent' }),
  K1: Object.freeze({ code: 'bec.link.credential_harvesting', category: 'link' }),
  K2: Object.freeze({ code: 'bec.link.credential_form', category: 'link' }),
  K3: Object.freeze({ code: 'bec.link.lookalike', category: 'link' }),
  K4: Object.freeze({ code: 'bec.link.malicious', category: 'link' }),
  H1: Object.freeze({ code: 'bec.history.first_contact', category: 'history' }),
  H2: Object.freeze({ code: 'bec.history.first_contact_lookalike', category: 'history' }),
  H3: Object.freeze({ code: 'bec.history.reply_without_history', category: 'history' }),
  H4: Object.freeze({ code: 'bec.history.new_infrastructure', category: 'history' }),
  H5: Object.freeze({ code: 'bec.history.first_contact_payment', category: 'history' }),
  T1: Object.freeze({ code: 'bec.trusted_sender', category: 'engine' }),
  T2: Object.freeze({ code: 'bec.trusted_sender_unauthenticated', category: 'engine' }),
  S1: Object.freeze({ code: 'bec.feedback_suppressed', category: 'engine' }),
});

/**
 * Every reason code of the BEC engine (B6): the codes of the rule table in table order, the
 * engine-level codes (E0 `bec.not_inbound`; E1 inputs), `clean.below_threshold` (rule C0) and the
 * AI codes of B9. `BEC_MAPPER_CODES` of `@email-gateway/bec` is the identical list (contract test,
 * WP3). Bounded metric label set of `scan_bec_rules_total{code}`. Every code matches
 * `REASON_CODE_PATTERN` and is at most 64 characters.
 */
export const BEC_REASON_CODES = [
  // B6 rule table (P1 … S1).
  'bec.return_path.domain_mismatch',
  'bec.return_path.forged_header',
  'bec.sender.from_invalid',
  'bec.sender.sender_mismatch',
  'bec.sender.not_authenticated',
  'bec.display_name.embedded_address',
  'bec.display_name.brand_mismatch',
  'bec.display_name.obfuscated',
  'bec.reply_to.domain_mismatch',
  'bec.reply_to.freemail',
  'bec.reply_to.lookalike',
  'bec.auth.dmarc_fail',
  'bec.auth.spf_fail',
  'bec.auth.dkim_fail',
  'bec.auth.none',
  'bec.auth.temperror',
  'bec.auth.tenant_domain_spoof',
  'bec.lookalike.sender_tenant',
  'bec.lookalike.sender_vendor',
  'bec.lookalike.sender_brand',
  'bec.lookalike.mixed_script_domain',
  'bec.impersonation.executive_name',
  'bec.impersonation.executive_freemail',
  'bec.impersonation.executive_reply_to',
  'bec.impersonation.vendor_name',
  'bec.impersonation.vendor_unauthenticated',
  'bec.vendor.unknown_sender',
  'bec.vendor.payment_change',
  'bec.content.payment_request',
  'bec.content.bank_detail_change',
  'bec.content.gift_card',
  'bec.content.wire_transfer',
  'bec.content.invoice_change',
  'bec.content.payroll_diversion',
  'bec.content.urgency',
  'bec.content.secrecy',
  'bec.content.credential_request',
  'bec.content.financial_identifiers',
  'bec.link.credential_harvesting',
  'bec.link.credential_form',
  'bec.link.lookalike',
  'bec.link.malicious',
  'bec.history.first_contact',
  'bec.history.first_contact_lookalike',
  'bec.history.reply_without_history',
  'bec.history.new_infrastructure',
  'bec.history.first_contact_payment',
  'bec.trusted_sender',
  'bec.trusted_sender_unauthenticated',
  'bec.feedback_suppressed',
  // Engine level: E0 (not inbound) and E1 (inputs not available).
  'bec.not_inbound',
  'bec.input_unavailable.auth',
  'bec.input_unavailable.url',
  'bec.content_incomplete',
  'bec.history_unavailable',
  // C0: clean (every input available, score below the suspicious threshold).
  'clean.below_threshold',
  // AI layer (B9).
  'bec.ai.flagged',
  'bec.ai.corroborated',
  'bec.ai.disagrees',
  'bec.ai.unavailable',
] as const;
export type BecReasonCode = (typeof BEC_REASON_CODES)[number];
export const becReasonCodeSchema = z.enum(BEC_REASON_CODES);

export const isBecReasonCode = (value: string): value is BecReasonCode =>
  (BEC_REASON_CODES as readonly string[]).includes(value);

/** The E1 input codes (B6): any of them makes the verdict at least `unknown`, never `clean`. */
export const BEC_INPUT_UNAVAILABLE_CODES = Object.freeze([
  'bec.input_unavailable.auth',
  'bec.input_unavailable.url',
  'bec.content_incomplete',
  'bec.history_unavailable',
] as const satisfies readonly BecReasonCode[]);

/** The AI codes (B9): informational or the effect of rules 2 and 4 of the aggregation. */
export const BEC_AI_CODES = Object.freeze([
  'bec.ai.flagged',
  'bec.ai.corroborated',
  'bec.ai.disagrees',
  'bec.ai.unavailable',
] as const satisfies readonly BecReasonCode[]);

/**
 * The codes a tenant may suppress from a false-positive feedback (B11): P1, P2, I2, I3, D1, D3,
 * R1, R2, V3, C1, C4, C5, C7, C8, C10, H1, H3, H4, H5. Never A*, L*, R3, X*, V1, V2, V4, C2, C3,
 * C6, C9, K*, E*, T2 or the AI codes.
 */
export const BEC_SUPPRESSIBLE_CODES = Object.freeze([
  'bec.return_path.domain_mismatch',
  'bec.return_path.forged_header',
  'bec.sender.sender_mismatch',
  'bec.sender.not_authenticated',
  'bec.display_name.embedded_address',
  'bec.display_name.obfuscated',
  'bec.reply_to.domain_mismatch',
  'bec.reply_to.freemail',
  'bec.vendor.unknown_sender',
  'bec.content.payment_request',
  'bec.content.wire_transfer',
  'bec.content.invoice_change',
  'bec.content.urgency',
  'bec.content.secrecy',
  'bec.content.financial_identifiers',
  'bec.history.first_contact',
  'bec.history.reply_without_history',
  'bec.history.new_infrastructure',
  'bec.history.first_contact_payment',
] as const satisfies readonly BecReasonCode[]);
export type BecSuppressibleCode = (typeof BEC_SUPPRESSIBLE_CODES)[number];
export const becSuppressibleCodeSchema = z.enum(BEC_SUPPRESSIBLE_CODES);

export const isBecSuppressibleCode = (value: string): value is BecSuppressibleCode =>
  (BEC_SUPPRESSIBLE_CODES as readonly string[]).includes(value);

/** Lexicon categories of the text analysis (B8), in the order of the design. */
export const BEC_LEXICON_CATEGORIES = [
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
export type BecLexiconCategory = (typeof BEC_LEXICON_CATEGORIES)[number];

/** Lexicon languages (B8): English, Hindi (Devanagari) and Hinglish (romanized Hindi). */
export const BEC_LEXICON_LANGUAGES = ['en', 'hi', 'hi-Latn'] as const;
export type BecLexiconLanguage = (typeof BEC_LEXICON_LANGUAGES)[number];

/** Pattern detectors of rule C10 (B8): counts only. */
export const BEC_PATTERN_DETECTORS = ['iban', 'swift', 'ifsc_account', 'amount'] as const;
export type BecPatternDetector = (typeof BEC_PATTERN_DETECTORS)[number];

/** Text sources of an evidence span (B8): offsets into the derived source text (`bec-text/1`). */
export const BEC_TEXT_SOURCES = ['subject', 'text', 'html_text'] as const;
export type BecTextSource = (typeof BEC_TEXT_SOURCES)[number];

/**
 * Enumerated indicators an AI provider may return (B10). No free text: the LLM output schema and
 * the stored assessments use exactly these values.
 */
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
export const aiIndicatorSchema = z.enum(AI_INDICATORS);

/**
 * The AI feature vector (B9), in a fixed order (the local model's weights follow it): one boolean
 * per deterministic rule id P1 … K4, H1 … H5, T1, T2 (`rule_<id lower case>`; S1 is not a feature:
 * it reflects a tenant's suppression, not the message), one `log1p` match count per lexicon
 * category (`lex_<category>`), one count per pattern detector (`pat_<detector>`), then the
 * identity and structure facts.
 */
export const AI_FEATURE_NAMES = [
  'rule_p1',
  'rule_p2',
  'rule_i1',
  'rule_i2',
  'rule_i3',
  'rule_d1',
  'rule_d2',
  'rule_d3',
  'rule_r1',
  'rule_r2',
  'rule_r3',
  'rule_a1',
  'rule_a2',
  'rule_a3',
  'rule_a4',
  'rule_a5',
  'rule_a6',
  'rule_l1',
  'rule_l2',
  'rule_l3',
  'rule_l4',
  'rule_x1',
  'rule_x2',
  'rule_x3',
  'rule_v1',
  'rule_v2',
  'rule_v3',
  'rule_v4',
  'rule_c1',
  'rule_c2',
  'rule_c3',
  'rule_c4',
  'rule_c5',
  'rule_c6',
  'rule_c7',
  'rule_c8',
  'rule_c9',
  'rule_c10',
  'rule_k1',
  'rule_k2',
  'rule_k3',
  'rule_k4',
  'rule_h1',
  'rule_h2',
  'rule_h3',
  'rule_h4',
  'rule_h5',
  'rule_t1',
  'rule_t2',
  'lex_payment_request',
  'lex_bank_change',
  'lex_gift_card',
  'lex_wire_transfer',
  'lex_invoice_change',
  'lex_payroll_change',
  'lex_urgency',
  'lex_secrecy',
  'lex_credential_request',
  'lex_authority',
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
] as const;
export type AiFeatureName = (typeof AI_FEATURE_NAMES)[number];
export const aiFeatureNameSchema = z.enum(AI_FEATURE_NAMES);

/** AI layers and modes (B9). Modes are ordered `off < shadow < active` (platform caps). */
export const BEC_AI_LAYERS = ['local', 'llm'] as const;
export type BecAiLayer = (typeof BEC_AI_LAYERS)[number];
export const BEC_AI_MODES = ['off', 'shadow', 'active'] as const;
export type BecAiMode = (typeof BEC_AI_MODES)[number];
export const becAiModeSchema = z.enum(BEC_AI_MODES);
const modeRank = (mode: BecAiMode): number => BEC_AI_MODES.indexOf(mode);

/** Providers recorded with an assessment (B9, B10). `fake` is refused in production. */
export const BEC_AI_PROVIDERS = ['local', 'anthropic', 'fake'] as const;
/** Statuses of an assessment (B9). Anything but `ok` leaves the verdict deterministic (P6). */
export const BEC_AI_STATUSES = [
  'ok',
  'timeout',
  'error',
  'refused',
  'invalid_output',
  'budget_exceeded',
  'skipped',
  'circuit_open',
] as const;
export type BecAiStatus = (typeof BEC_AI_STATUSES)[number];
/** Labels an AI provider returns (B9). */
export const BEC_AI_LABELS = ['bec', 'phishing', 'benign', 'spam'] as const;
export type BecAiLabel = (typeof BEC_AI_LABELS)[number];
/** Effect of an applied assessment on the final verdict (B9 rules 2 and 4; B15). */
export const BEC_AI_EFFECTS = ['none', 'raised_to_suspicious', 'corroborated_malicious'] as const;
export type BecAiEffect = (typeof BEC_AI_EFFECTS)[number];

/** Input states recorded in `bec_scan_results.inputs` (B2). */
export const BEC_AUTH_INPUT_STATES = ['available', 'failed', 'missing', 'not_in_round'] as const;
export const BEC_URL_INPUT_STATES = ['available', 'failed', 'not_in_round'] as const;
export const BEC_TEXT_INPUT_STATES = ['complete', 'incomplete', 'absent'] as const;
export const BEC_HISTORY_INPUT_STATES = ['enabled', 'disabled', 'error'] as const;

/** Tenant data enums (§3; Prisma `BecTrustedSenderKind`, `BecFeedbackKind`, …). */
export const BEC_TRUSTED_SENDER_KINDS = ['address', 'domain'] as const;
export type BecTrustedSenderKind = (typeof BEC_TRUSTED_SENDER_KINDS)[number];
export const BEC_FEEDBACK_KINDS = ['false_positive', 'false_negative'] as const;
export type BecFeedbackKind = (typeof BEC_FEEDBACK_KINDS)[number];
export const BEC_SUPPRESSION_SCOPES = ['address', 'domain'] as const;
export type BecSuppressionScope = (typeof BEC_SUPPRESSION_SCOPES)[number];
export const BEC_CONTACT_SCOPES = ['sender', 'pair'] as const;
export type BecContactScope = (typeof BEC_CONTACT_SCOPES)[number];

// ---------------------------------------------------------------------------------------------
// Settings (B13)
// ---------------------------------------------------------------------------------------------

/** Tenant bounds of the score thresholds (B13); the platform values must lie inside them. */
export const BEC_SUSPICIOUS_SCORE_BOUNDS = Object.freeze({ min: 25, max: 60 });
export const BEC_MALICIOUS_SCORE_BOUNDS = Object.freeze({ min: 60, max: 95 });
/** Bounds of the AI raise confidence (platform and tenant, B9/B13). */
export const BEC_AI_RAISE_CONFIDENCE_BOUNDS = Object.freeze({ min: 0.6, max: 0.99 });
/** Bounds of the AI corroboration confidence (platform only, B13). */
export const BEC_AI_CORROBORATE_CONFIDENCE_BOUNDS = Object.freeze({ min: 0.8, max: 0.99 });
/** Bounds of the AI malicious band (platform only, B9 P2). */
export const BEC_AI_MALICIOUS_BAND_BOUNDS = Object.freeze({ min: 0, max: 15 });
/** History retention bounds (B12, ADR-0035: 30–730 days). */
export const BEC_HISTORY_RETENTION_BOUNDS = Object.freeze({ min: 30, max: 730 });
/** Upper bound of the platform per-tenant daily LLM call budget. */
export const BEC_LLM_DAILY_CALL_LIMIT_CEILING = 1_000_000;
/** At most this many tenant free-mail domains (B13). */
export const BEC_MAX_FREEMAIL_EXTRA_DOMAINS = 100;

const unique = (values: readonly unknown[]) => new Set(values).size === values.length;
const int = z.number().int();
const confidence = z.number().finite();

const within = (value: number, bounds: { min: number; max: number }) =>
  value >= bounds.min && value <= bounds.max;

/**
 * Platform BEC settings (B13; env `BEC_*`, read by the api and the email-worker and validated at
 * start). The thresholds and the raise confidence are tenant-tunable within fixed bounds; the
 * modes, the daily LLM call limit and the maximum history retention are caps for the tenants;
 * the corroboration confidence and the malicious band are platform only.
 */
export const becPlatformSettingsSchema = z
  .strictObject({
    suspiciousScore: int,
    maliciousScore: int,
    aiRaiseConfidence: confidence,
    aiCorroborateConfidence: confidence,
    aiMaliciousBand: int,
    localModelMode: becAiModeSchema,
    llmMode: becAiModeSchema,
    llmMaxCallsPerTenantPerDay: int.min(1).max(BEC_LLM_DAILY_CALL_LIMIT_CEILING),
    historyDefaultRetentionDays: int,
    historyMaxRetentionDays: int,
  })
  .superRefine((s, ctx) => {
    const bound = (
      path: keyof typeof s,
      value: number,
      bounds: { min: number; max: number },
    ): void => {
      if (!within(value, bounds)) {
        ctx.addIssue({
          code: 'custom',
          path: [path],
          message: `${path} must be within [${bounds.min}, ${bounds.max}]`,
        });
      }
    };
    bound('suspiciousScore', s.suspiciousScore, BEC_SUSPICIOUS_SCORE_BOUNDS);
    bound('maliciousScore', s.maliciousScore, BEC_MALICIOUS_SCORE_BOUNDS);
    bound('aiRaiseConfidence', s.aiRaiseConfidence, BEC_AI_RAISE_CONFIDENCE_BOUNDS);
    bound(
      'aiCorroborateConfidence',
      s.aiCorroborateConfidence,
      BEC_AI_CORROBORATE_CONFIDENCE_BOUNDS,
    );
    bound('aiMaliciousBand', s.aiMaliciousBand, BEC_AI_MALICIOUS_BAND_BOUNDS);
    bound('historyMaxRetentionDays', s.historyMaxRetentionDays, BEC_HISTORY_RETENTION_BOUNDS);
    bound('historyDefaultRetentionDays', s.historyDefaultRetentionDays, {
      min: BEC_HISTORY_RETENTION_BOUNDS.min,
      max: s.historyMaxRetentionDays,
    });
    if (!(s.suspiciousScore < s.maliciousScore)) {
      ctx.addIssue({
        code: 'custom',
        path: ['suspiciousScore'],
        message: 'suspiciousScore must be below maliciousScore',
      });
    }
  });
export type BecPlatformSettings = z.infer<typeof becPlatformSettingsSchema>;

/** Platform defaults (`.env.example`, §5). */
export const BEC_PLATFORM_DEFAULTS: Readonly<BecPlatformSettings> = Object.freeze({
  suspiciousScore: 40,
  maliciousScore: 80,
  aiRaiseConfidence: 0.8,
  aiCorroborateConfidence: 0.9,
  aiMaliciousBand: 10,
  localModelMode: 'shadow',
  llmMode: 'off',
  llmMaxCallsPerTenantPerDay: 1000,
  historyDefaultRetentionDays: 365,
  historyMaxRetentionDays: 730,
});

/** Environment keys of the platform settings (both the api and the email-worker read them). */
export const BEC_PLATFORM_ENV_KEYS = Object.freeze({
  suspiciousScore: 'BEC_SUSPICIOUS_SCORE',
  maliciousScore: 'BEC_MALICIOUS_SCORE',
  aiRaiseConfidence: 'BEC_AI_RAISE_CONFIDENCE',
  aiCorroborateConfidence: 'BEC_AI_CORROBORATE_CONFIDENCE',
  aiMaliciousBand: 'BEC_AI_MALICIOUS_BAND',
  localModelMode: 'BEC_LOCAL_MODEL_MODE',
  llmMode: 'BEC_LLM_MODE',
  llmMaxCallsPerTenantPerDay: 'BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY',
  historyDefaultRetentionDays: 'BEC_HISTORY_DEFAULT_RETENTION_DAYS',
  historyMaxRetentionDays: 'BEC_HISTORY_MAX_RETENTION_DAYS',
} as const satisfies Record<keyof BecPlatformSettings, string>);

const NUMERIC_KEYS = [
  'suspiciousScore',
  'maliciousScore',
  'aiRaiseConfidence',
  'aiCorroborateConfidence',
  'aiMaliciousBand',
  'llmMaxCallsPerTenantPerDay',
  'historyDefaultRetentionDays',
  'historyMaxRetentionDays',
] as const satisfies readonly (keyof BecPlatformSettings)[];

/**
 * Reads the platform settings from environment variables (unset or empty → default) and
 * validates them. Throws a `ZodError` naming the setting on invalid input, so a service refuses
 * to start with inconsistent thresholds or modes.
 */
export function becPlatformSettingsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
): BecPlatformSettings {
  const read = (key: keyof BecPlatformSettings): string | undefined => {
    const value = env[BEC_PLATFORM_ENV_KEYS[key]];
    return value === undefined || value.trim() === '' ? undefined : value.trim();
  };
  const numbers = Object.fromEntries(
    NUMERIC_KEYS.map((key) => {
      const value = read(key);
      return [key, value === undefined ? BEC_PLATFORM_DEFAULTS[key] : Number(value)];
    }),
  );
  return becPlatformSettingsSchema.parse({
    ...numbers,
    localModelMode: read('localModelMode') ?? BEC_PLATFORM_DEFAULTS.localModelMode,
    llmMode: read('llmMode') ?? BEC_PLATFORM_DEFAULTS.llmMode,
  });
}

/**
 * A tenant override (`scan_engine_settings.settings` of engine `bec`, B13): strict at every
 * level, every key optional. Bounds (including those that depend on the platform: the mode caps,
 * the daily call limit and the maximum retention) are checked by `resolveBecSettings`.
 * `freemailExtraDomains` are lower-case ASCII domains (A-labels); the api normalizes them through
 * `@email-gateway/url-security` and refuses public suffixes.
 */
export const becTenantSettingsSchema = z.strictObject({
  suspiciousScore: int.optional(),
  maliciousScore: int.optional(),
  freemailExtraDomains: z
    .array(urlDomainSchema)
    .max(BEC_MAX_FREEMAIL_EXTRA_DOMAINS)
    .refine(unique, { message: 'Duplicate domain' })
    .optional(),
  history: z
    .strictObject({
      enabled: z.boolean().optional(),
      retentionDays: int.optional(),
    })
    .optional(),
  ai: z
    .strictObject({
      localModel: becAiModeSchema.optional(),
      llm: becAiModeSchema.optional(),
      llmDailyCallLimit: int.optional(),
      raiseConfidence: confidence.optional(),
    })
    .optional(),
});
export type BecTenantSettings = z.infer<typeof becTenantSettingsSchema>;

/** The settings the BEC engine uses for one tenant (B13). */
export interface BecEffectiveSettings {
  suspiciousScore: number;
  maliciousScore: number;
  freemailExtraDomains: string[];
  history: { enabled: boolean; retentionDays: number };
  ai: {
    localModel: BecAiMode;
    llm: BecAiMode;
    llmDailyCallLimit: number;
    raiseConfidence: number;
    /** Platform only. */
    corroborateConfidence: number;
    /** Platform only. */
    maliciousBand: number;
  };
}

export type BecSettingsResolution =
  | { ok: true; settings: BecEffectiveSettings; overridden: boolean }
  | { ok: false; violations: SettingsViolation[] };

/** The bounds a tenant override must respect (the settings API returns them). */
export interface BecSettingsBounds {
  suspiciousScore: { min: number; max: number };
  maliciousScore: { min: number; max: number };
  freemailExtraDomains: { maxItems: number };
  history: { enabled: readonly boolean[]; retentionDays: { min: number; max: number } };
  ai: {
    /** Modes up to the platform cap. */
    localModel: readonly BecAiMode[];
    llm: readonly BecAiMode[];
    llmDailyCallLimit: { min: number; max: number };
    raiseConfidence: { min: number; max: number };
  };
}

const modesUpTo = (cap: BecAiMode): BecAiMode[] =>
  BEC_AI_MODES.filter((mode) => modeRank(mode) <= modeRank(cap));

/** The values a tenant may choose given the platform settings. */
export function becSettingsBounds(platform: BecPlatformSettings): BecSettingsBounds {
  return {
    suspiciousScore: { ...BEC_SUSPICIOUS_SCORE_BOUNDS },
    maliciousScore: { ...BEC_MALICIOUS_SCORE_BOUNDS },
    freemailExtraDomains: { maxItems: BEC_MAX_FREEMAIL_EXTRA_DOMAINS },
    history: {
      enabled: [false, true],
      retentionDays: {
        min: BEC_HISTORY_RETENTION_BOUNDS.min,
        max: platform.historyMaxRetentionDays,
      },
    },
    ai: {
      localModel: modesUpTo(platform.localModelMode),
      llm: modesUpTo(platform.llmMode),
      llmDailyCallLimit: { min: 1, max: platform.llmMaxCallsPerTenantPerDay },
      raiseConfidence: { ...BEC_AI_RAISE_CONFIDENCE_BOUNDS },
    },
  };
}

const platformEffective = (platform: BecPlatformSettings): BecEffectiveSettings => ({
  suspiciousScore: platform.suspiciousScore,
  maliciousScore: platform.maliciousScore,
  freemailExtraDomains: [],
  history: { enabled: false, retentionDays: platform.historyDefaultRetentionDays },
  ai: {
    // The local model defaults to the platform mode; the LLM is an explicit tenant opt-in (B9).
    localModel: platform.localModelMode,
    llm: 'off',
    llmDailyCallLimit: platform.llmMaxCallsPerTenantPerDay,
    raiseConfidence: platform.aiRaiseConfidence,
    corroborateConfidence: platform.aiCorroborateConfidence,
    maliciousBand: platform.aiMaliciousBand,
  },
});

const hasDefinedValue = (value: unknown): boolean => {
  if (value === undefined) return false;
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return Object.values(value as Record<string, unknown>).some(hasDefinedValue);
  }
  return true;
};

/**
 * Merges a tenant override (raw JSON from `scan_engine_settings.settings`, or null/undefined for
 * none) into the platform settings (B13). Pure; mirrors `resolveUrlSettings`. An invalid override
 * yields every violation found (dotted paths: `ai.llm`); the caller decides what to do (the api
 * answers 422; the engine ignores the row and applies the platform settings).
 *
 * Bounds: thresholds within their fixed bounds with `suspiciousScore < maliciousScore` after
 * merging; AI modes never above the platform cap; `ai.llmDailyCallLimit` within
 * [1, platform limit]; `ai.raiseConfidence` within [0.6, 0.99]; `history.retentionDays` within
 * [30, platform maximum]; unknown keys refused.
 */
export function resolveBecSettings(
  platform: BecPlatformSettings,
  override: unknown,
): BecSettingsResolution {
  if (override === null || override === undefined) {
    return { ok: true, settings: platformEffective(platform), overridden: false };
  }
  const parsed = becTenantSettingsSchema.safeParse(override);
  if (!parsed.success) {
    return {
      ok: false,
      violations: parsed.error.issues.flatMap((issue): SettingsViolation[] => {
        const base = issue.path.map(String);
        if (issue.code === 'unrecognized_keys') {
          return issue.keys.map((key) => ({
            path: [...base, key].join('.'),
            code: 'unknown_key',
            message: `Unknown setting: ${[...base, key].join('.')}`,
          }));
        }
        return [
          {
            path: base.length > 0 ? base.join('.') : 'settings',
            code: 'invalid',
            message: issue.message,
          },
        ];
      }),
    };
  }
  const tenant = parsed.data;
  const base = platformEffective(platform);
  const violations: SettingsViolation[] = [];
  const bound = (
    path: string,
    value: number | undefined,
    bounds: { min: number; max: number },
  ): void => {
    if (value !== undefined && !within(value, bounds)) {
      violations.push({
        path,
        code: 'out_of_bounds',
        message: `${path} must be within [${bounds.min}, ${bounds.max}]`,
      });
    }
  };
  const limits = becSettingsBounds(platform);
  bound('suspiciousScore', tenant.suspiciousScore, limits.suspiciousScore);
  bound('maliciousScore', tenant.maliciousScore, limits.maliciousScore);
  bound('history.retentionDays', tenant.history?.retentionDays, limits.history.retentionDays);
  bound('ai.llmDailyCallLimit', tenant.ai?.llmDailyCallLimit, limits.ai.llmDailyCallLimit);
  bound('ai.raiseConfidence', tenant.ai?.raiseConfidence, limits.ai.raiseConfidence);
  for (const [path, value, cap] of [
    ['ai.localModel', tenant.ai?.localModel, platform.localModelMode],
    ['ai.llm', tenant.ai?.llm, platform.llmMode],
  ] as const) {
    if (value !== undefined && modeRank(value) > modeRank(cap)) {
      violations.push({
        path,
        code: 'out_of_bounds',
        message: `${path} may not exceed the platform mode ${cap}`,
      });
    }
  }
  const suspiciousScore = tenant.suspiciousScore ?? base.suspiciousScore;
  const maliciousScore = tenant.maliciousScore ?? base.maliciousScore;
  if (!(suspiciousScore < maliciousScore)) {
    violations.push({
      path: tenant.suspiciousScore !== undefined ? 'suspiciousScore' : 'maliciousScore',
      code: 'threshold_order',
      message: `suspiciousScore (${suspiciousScore}) must be below maliciousScore (${maliciousScore})`,
    });
  }
  if (violations.length > 0) return { ok: false, violations };

  return {
    ok: true,
    overridden: hasDefinedValue(tenant),
    settings: {
      suspiciousScore,
      maliciousScore,
      freemailExtraDomains: tenant.freemailExtraDomains ?? base.freemailExtraDomains,
      history: {
        enabled: tenant.history?.enabled ?? base.history.enabled,
        retentionDays: tenant.history?.retentionDays ?? base.history.retentionDays,
      },
      ai: {
        localModel: tenant.ai?.localModel ?? base.ai.localModel,
        llm: tenant.ai?.llm ?? base.ai.llm,
        llmDailyCallLimit: tenant.ai?.llmDailyCallLimit ?? base.ai.llmDailyCallLimit,
        raiseConfidence: tenant.ai?.raiseConfidence ?? base.ai.raiseConfidence,
        corroborateConfidence: base.ai.corroborateConfidence,
        maliciousBand: base.ai.maliciousBand,
      },
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Scans read API: the `bec` section (B15)
// ---------------------------------------------------------------------------------------------

/** At most this many rule entries per result (B14, B15). */
export const BEC_MAX_RULES = 32;
/** At most this many evidence spans / lexicon ids / URL references per rule (B8, B15). */
export const BEC_MAX_EVIDENCE_ITEMS = 5;
/** Applied (≤ 2) and shadow (≤ 3) AI assessments per result (B14). */
export const BEC_MAX_AI_ASSESSMENTS = 2;
export const BEC_MAX_AI_SHADOW_ASSESSMENTS = 3;
/** Bounds of one assessment (B9). */
export const BEC_MAX_AI_LABELS = 4;
export const BEC_MAX_AI_ITEMS = 8;
/** At most this many feedback references per result in the read API. */
export const BEC_MAX_FEEDBACK_REFS = 50;
/** Largest span offset (UTF-16 code units of a derived source text, B8). */
export const BEC_MAX_SPAN_OFFSET = 1_048_576;

const offset = z.number().int().min(0).max(BEC_MAX_SPAN_OFFSET);
const publicId = z.uuid();
const score = z.number().int().min(0).max(100);
const versionText = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .regex(/^[\x21-\x7e]+$/, 'Expected a printable ASCII version');

/** A lower-case ASCII domain or host name of a parsed sender identity (A-labels). */
export const BEC_EVIDENCE_DOMAIN_PATTERN =
  /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/;
const evidenceDomain = z
  .string()
  .regex(BEC_EVIDENCE_DOMAIN_PATTERN, 'Expected a lower-case ASCII domain');

/** A lexicon entry id (`en.gift_card.003`, `hi-Latn.urgency.001`; B8). */
export const BEC_LEXICON_ID_PATTERN = /^[a-z]{2,3}(?:-[A-Z][a-z]{3})?\.[a-z_]{1,32}\.[0-9]{1,6}$/;

const span = z
  .strictObject({
    source: z.enum(BEC_TEXT_SOURCES),
    start: offset,
    end: offset,
  })
  .refine((s) => s.start < s.end, { message: 'Expected start < end', path: ['end'] });

/** Lookalike target kinds of BEC evidence: url-security's kinds plus vendor attribution (B5). */
export const BEC_LOOKALIKE_TARGET_KINDS = ['brand', 'tenant', 'vendor', 'extra'] as const;

/** Evidence headers (B15). */
export const BEC_EVIDENCE_HEADERS = [
  'From',
  'Reply-To',
  'Sender',
  'Return-Path',
  'envelope',
] as const;

/** Prior message buckets of history evidence (B15); never exact counts. */
export const BEC_PRIOR_MESSAGE_BUCKETS = ['0', '1-2', '3-9', '10+'] as const;

/**
 * Evidence of one fired rule (B15): structured, bounded, never message text. `suppressedCodes`
 * (S1: the codes a tenant suppression removed, B6) and `patterns` (C10: pattern detector counts,
 * B8) are the two keys the rule table needs beyond the B15 list.
 */
export const becRuleEvidenceSchema = z.strictObject({
  header: z.enum(BEC_EVIDENCE_HEADERS).optional(),
  address: z.string().min(1).max(320).optional(),
  displayName: z.string().min(1).max(128).optional(),
  domain: evidenceDomain.optional(),
  profile: z
    .strictObject({
      kind: z.enum(['executive', 'vendor']),
      id: publicId,
      match: z.enum(['exact', 'token_set', 'confusable']),
    })
    .optional(),
  lookalike: z
    .strictObject({
      rule: z.enum(LOOKALIKE_RULES),
      targetKind: z.enum(BEC_LOOKALIKE_TARGET_KINDS),
      targetDomain: evidenceDomain,
      score: z.number().finite().min(0).max(1),
    })
    .optional(),
  auth: z
    .strictObject({
      spf: authOutcomeSchema.nullable(),
      dkim: authOutcomeSchema.nullable(),
      dmarc: authOutcomeSchema.nullable(),
      dmarcPolicy: dmarcPolicySchema.nullable(),
      aligned: z.strictObject({ dkim: z.boolean(), spf: z.boolean() }),
    })
    .optional(),
  keywords: z
    .strictObject({
      category: z.enum(BEC_LEXICON_CATEGORIES),
      language: z.enum(BEC_LEXICON_LANGUAGES),
      lexiconIds: z
        .array(z.string().max(64).regex(BEC_LEXICON_ID_PATTERN, 'Expected a lexicon id'))
        .max(BEC_MAX_EVIDENCE_ITEMS)
        .refine(unique, { message: 'Duplicate lexicon id' }),
      spans: z.array(span).max(BEC_MAX_EVIDENCE_ITEMS),
    })
    .optional(),
  urls: z
    .array(z.number().int().min(0).max(65_535))
    .max(BEC_MAX_EVIDENCE_ITEMS)
    .refine(unique, { message: 'Duplicate url_seq' })
    .optional(),
  history: z
    .strictObject({
      firstContact: z.boolean(),
      priorMessages: z.enum(BEC_PRIOR_MESSAGE_BUCKETS),
    })
    .optional(),
  trusted: z.strictObject({ id: publicId }).optional(),
  suppression: z.strictObject({ id: publicId }).optional(),
  suppressedCodes: z
    .array(becSuppressibleCodeSchema)
    .min(1)
    .max(BEC_SUPPRESSIBLE_CODES.length)
    .refine(unique, { message: 'Duplicate reason code' })
    .optional(),
  patterns: z
    .strictObject({
      iban: z.number().int().min(0).max(64),
      swift: z.number().int().min(0).max(64),
      ifsc_account: z.number().int().min(0).max(64),
      amount: z.number().int().min(0).max(64),
    })
    .optional(),
});
export type BecRuleEvidence = z.infer<typeof becRuleEvidenceSchema>;

/** One fired rule (B14 `rules` entry, B15). Its code and category must be those of its id. */
export const becRuleEntrySchema = z
  .strictObject({
    id: becRuleIdSchema,
    code: becReasonCodeSchema,
    category: becRuleCategorySchema,
    severity: becRuleSeveritySchema,
    weight: z.number().int().min(0).max(100),
    suppressed: z.enum(['trust', 'feedback']).nullable(),
    evidence: becRuleEvidenceSchema,
  })
  .superRefine((rule, ctx) => {
    const expected = BEC_RULES[rule.id];
    if (rule.code !== expected.code) {
      ctx.addIssue({
        code: 'custom',
        path: ['code'],
        message: `${rule.id} has code ${expected.code}`,
      });
    }
    if (rule.category !== expected.category) {
      ctx.addIssue({
        code: 'custom',
        path: ['category'],
        message: `${rule.id} has category ${expected.category}`,
      });
    }
  });
export type BecRuleEntry = z.infer<typeof becRuleEntrySchema>;

/** Input states of a result (B2). */
export const becInputsSchema = z.strictObject({
  auth: z.enum(BEC_AUTH_INPUT_STATES),
  url: z.enum(BEC_URL_INPUT_STATES),
  text: z.enum(BEC_TEXT_INPUT_STATES),
  history: z.enum(BEC_HISTORY_INPUT_STATES),
});
export type BecInputs = z.infer<typeof becInputsSchema>;

const modelText = z
  .string()
  .min(1)
  .max(96)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:@/+-]*$/, 'Expected a model id or version');

const aiAssessmentViewShape = {
  layer: z.enum(BEC_AI_LAYERS),
  mode: z.enum(['active', 'shadow']),
  provider: z.enum(BEC_AI_PROVIDERS),
  modelId: modelText,
  modelVersion: modelText,
  promptTemplateVersion: versionText(32).nullable(),
  status: z.enum(BEC_AI_STATUSES),
  labels: z
    .array(
      z.strictObject({
        label: z.enum(BEC_AI_LABELS),
        confidence: z.number().finite().min(0).max(1),
      }),
    )
    .max(BEC_MAX_AI_LABELS),
  confidence: z.number().finite().min(0).max(1).nullable(),
  indicators: z
    .array(aiIndicatorSchema)
    .max(BEC_MAX_AI_ITEMS)
    .refine(unique, { message: 'Duplicate indicator' }),
  citedFeatures: z
    .array(z.strictObject({ feature: aiFeatureNameSchema, contribution: z.number().finite() }))
    .max(BEC_MAX_AI_ITEMS),
  spans: z
    .array(
      z
        .strictObject({
          source: z.enum(BEC_TEXT_SOURCES),
          start: offset,
          end: offset,
          label: z
            .string()
            .min(1)
            .max(64)
            .regex(/^[a-z][a-z0-9_]*$/, 'Expected a label token'),
        })
        .refine((s) => s.start < s.end, { message: 'Expected start < end', path: ['end'] }),
    )
    .max(BEC_MAX_AI_ITEMS),
};

const checkAssessment = (
  a: {
    layer: BecAiLayer;
    provider: string;
    status: BecAiStatus;
    labels: unknown[];
    confidence: number | null;
  },
  ctx: z.RefinementCtx,
): void => {
  if ((a.layer === 'local') !== (a.provider === 'local')) {
    ctx.addIssue({
      code: 'custom',
      path: ['provider'],
      message: 'The local layer has provider local, the llm layer anthropic or fake',
    });
  }
  if (a.status !== 'ok' && (a.labels.length > 0 || a.confidence !== null)) {
    ctx.addIssue({
      code: 'custom',
      path: ['status'],
      message: 'Only an ok assessment carries labels and a confidence',
    });
  }
};

/**
 * An applied AI assessment as the read API returns it (B15): never the response hash, the
 * duration or any text; `effect` says what it did to the verdict.
 */
export const becAiAssessmentViewSchema = z
  .strictObject({ ...aiAssessmentViewShape, effect: z.enum(BEC_AI_EFFECTS) })
  .superRefine(checkAssessment);
export type BecAiAssessmentView = z.infer<typeof becAiAssessmentViewSchema>;

/** A shadow assessment (B15): the same without `effect` (shadow never changes anything, P5). */
export const becAiShadowAssessmentViewSchema = z
  .strictObject(aiAssessmentViewShape)
  .superRefine(checkAssessment);
export type BecAiShadowAssessmentView = z.infer<typeof becAiShadowAssessmentViewSchema>;

/** A feedback reference of a result (B15). */
export const becFeedbackRefSchema = z.strictObject({
  id: publicId,
  kind: z.enum(BEC_FEEDBACK_KINDS),
  createdAt: z.iso.datetime(),
});

/** The `bec` section of an engine entry in `GET /api/v1/messages/{id}/scans` (B15). */
export const becResultViewSchema = z
  .strictObject({
    rulesVersion: versionText(16),
    engineVersion: versionText(64),
    settingsVersion: versionText(96),
    lexiconVersion: versionText(16),
    verdict: becVerdictSchema,
    deterministicVerdict: becVerdictSchema,
    score,
    deterministicScore: score,
    thresholds: z.strictObject({ suspicious: score, malicious: score }),
    inputs: becInputsSchema,
    rules: z.array(becRuleEntrySchema).max(BEC_MAX_RULES),
    ai: z.array(becAiAssessmentViewSchema).max(BEC_MAX_AI_ASSESSMENTS),
    aiShadow: z.array(becAiShadowAssessmentViewSchema).max(BEC_MAX_AI_SHADOW_ASSESSMENTS),
    feedback: z.array(becFeedbackRefSchema).max(BEC_MAX_FEEDBACK_REFS),
  })
  .superRefine((view, ctx) => {
    const ids = view.rules.map((rule) => rule.id);
    if (!unique(ids)) {
      ctx.addIssue({ code: 'custom', path: ['rules'], message: 'A rule fires at most once' });
    }
    if (!(view.thresholds.suspicious < view.thresholds.malicious)) {
      ctx.addIssue({
        code: 'custom',
        path: ['thresholds'],
        message: 'suspicious must be below malicious',
      });
    }
    // §2.0 invariant 1 / B9 P1: the AI never produces clean.
    if (view.verdict === 'clean' && view.deterministicVerdict !== 'clean') {
      ctx.addIssue({
        code: 'custom',
        path: ['verdict'],
        message: 'clean requires a clean deterministic verdict',
      });
    }
    if ((view.verdict === 'skipped') !== (view.deterministicVerdict === 'skipped')) {
      ctx.addIssue({
        code: 'custom',
        path: ['verdict'],
        message: 'skipped is a deterministic outcome (not inbound) and never changed',
      });
    }
  });
export type BecResultView = z.infer<typeof becResultViewSchema>;
